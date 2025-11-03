import json
import os
from typing import Annotated
import uuid
import re
from a2a.types import Message
from a2a.utils.message import get_message_text
from beeai_framework.backend import ChatModel, ChatModelParameters
from beeai_framework.adapters.openai import OpenAIChatModel
from beeai_framework.backend.message import AssistantMessage, UserMessage
from beeai_framework.memory import UnconstrainedMemory
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.requirements.conditional import ConditionalRequirement
from beeai_framework.middleware.trajectory import GlobalTrajectoryMiddleware
from beeai_framework.tools.think import ThinkTool
from agentstack_sdk.server import Server
from agentstack_sdk.server.context import RunContext
from beeai_framework.agents.requirement.events import RequirementAgentFinalAnswerEvent
from beeai_framework.emitter import EventMeta
from agentstack_sdk.a2a.types import AgentMessage
from agentstack_sdk.a2a.extensions import (
    LLMServiceExtensionServer,LLMServiceExtensionSpec,
    AgentDetail, AgentDetailContributor, AgentDetailTool,
    TrajectoryExtensionServer, TrajectoryExtensionSpec,
    )
from beeai_framework.agents.types import AgentExecutionConfig
from agentstack_sdk.a2a.extensions.auth.secrets import (
    SecretDemand,
    SecretsExtensionServer,
    SecretsExtensionSpec,
    SecretsServiceExtensionParams,
)
from agentstack_sdk.a2a.extensions import (
    CitationExtensionServer, CitationExtensionSpec,)
from agentstack_sdk.a2a.extensions.ui.form import (
    FormExtensionServer,FormExtensionSpec,
    FormRender,TextField,CheckboxField,
    MultiSelectField,OptionItem,
    )
from a2a.types import AgentSkill, Message, Role , TextPart
from textwrap import dedent
from fetch_dependencies_tool import GitHubUvLockReaderURLMinimal
from dependency_search_tool import OSSIndexFromContextTool
from beeai_framework.tools import Tool
from utils import ToolNotFoundError, create_repo_scoped_tool, get_tools_by_names, session_manager


server = Server()
memories = {}



def get_memory(context: RunContext) -> UnconstrainedMemory:
    """Get or create session memory"""
    context_id = getattr(context, "context_id", getattr(context, "session_id", "default"))
    return memories.setdefault(context_id, UnconstrainedMemory())

def to_framework_message(message: Message):
    """Convert A2A Message to BeeAI Framework Message format"""
    message_text = "".join(part.root.text for part in message.parts if part.root.kind == "text")
    
    if message.role == Role.agent:
        return AssistantMessage(message_text)
    elif message.role == Role.user:
        return UserMessage(message_text)
    else:
        raise ValueError(f"Invalid message role: {message.role}")
    
def extract_citations(text: str, vulnerability_results=None) -> tuple[list[dict], str]:
    """Extract citations and clean text - returns citations in the correct format"""
    citations, offset = [], 0
    pattern = r"\[([^\]]+)\]\(([^)]+)\)"
    
    for match in re.finditer(pattern, text):
        content, url = match.groups()
        start = match.start() - offset

        citations.append({
            "url": url,
            "title": url.split("/")[-1].replace("-", " ").title() or content[:50],
            "description": content[:100] + ("..." if len(content) > 100 else ""),
            "start_index": start, 
            "end_index": start + len(content)
        })
        offset += len(match.group(0)) - len(content)

    return citations, re.sub(pattern, r"\1", text)


@server.agent(
    name="Dependency Defender",
    default_input_modes=["text", "text/plain", "application/pdf", "text/csv", "application/json"],
    default_output_modes=["text", "text/plain"],
    detail=AgentDetail(
        interaction_mode="multi-turn",
        user_greeting="Let's check for known vulnerabilities in your repo's dependencies and write Github Issues to fix them!",
        input_placeholder="Ask anything...",
        programming_language="Python",
        framework="BeeAI",
        tools=[
            AgentDetailTool(
                name="Think", 
                description="An advanced reasoning pattern that encourage the agent to plan and think through how to best approach it's tasks."
            ),
            AgentDetailTool(
                name="GitHubUvLockReader",
                description="Given a giithub repo url, this tool searches for uv.lock files and returns the dependencies.",
            ),
            AgentDetailTool(
                name="OSSIndex",
                description="Given dependencies, the OSSIndex tool searches the sonatype OSS INDEX API for known vulnerabilities.",
            ),
            AgentDetailTool(
                name="Github Issue Writer",
                description="Given identified vulterabilities, this tool writes and opens github issues in pulic repos to remediate vulnerabilities.",
            ),
        ],
        author={
            "name": "Sandi Besen and Kenneth Ocheltree"
        },
        source_code_url="https://github.com/sandijean90/VulnerabilityAgent"
    ),
    skills=[
        AgentSkill(
            id="Dependency_Vulnerability_Agent",
            name="Dependency_Vulnerability_Agent",
            description=dedent(
                """\
                The agent analyzes dependencies from a given repo, determines if there are existing vulnerabilities, and writes github issues to remediate them.
                """
            ),
            tags=["Form","Github","MCP","Code Vulnerability Analysis"],
            examples=[
                "https://github.com/KenOcheltree/bad-repo"
            ]
        )
    ],
)
async def Dependency_Vulnerability_Agent(
    message: Message,
    context: RunContext,
    citation: Annotated[CitationExtensionServer, CitationExtensionSpec()],
    trajectory: Annotated[TrajectoryExtensionServer, TrajectoryExtensionSpec()],
    llm: Annotated[
        LLMServiceExtensionServer, 
        LLMServiceExtensionSpec.single_demand(
            suggested=("openai/gpt-oss-120b",
                       "openai/gpt-4.1-mini")
        )
    ],
    secrets: Annotated[
        SecretsExtensionServer,
        SecretsExtensionSpec(
            params=SecretsServiceExtensionParams(
                secret_demands={
                    # GitHub Keys
                    "GITHUB_PAT": SecretDemand(
                        name="GitHub Personal Access Token",
                        description="Personal access token for GitHub API"
                    ),
                    # OSS Index Keys
                    "OSS_INDEX_API": SecretDemand(
                        name="OSS Index API Key",
                        description="API key for Sonatype OSS Index"
                    ),
                    "OSS_INDEX_EMAIL": SecretDemand(
                        name="OSS Index Email",
                        description="Email used for OSS Index account"
                    ),
                }
            )
        ),
    ],
    form: Annotated[
        FormExtensionServer,
        FormExtensionSpec(
            params=FormRender(
                id="user_info_form",
                title="Does your Repo have Vulnerable Dependencies? Let's fix that. ",
                columns=1,
                fields=[
                    TextField(id="Repo", label="Repo URL", col_span=1),
                    MultiSelectField(
                        id="Issue_Style",
                        label="Github Issue Style",
                        options=[
                            OptionItem(id="concise", label="concise"),
                            OptionItem(id="detailed", label="detailed"),
                        ],
                        col_span=2,
                    ),
                    CheckboxField(
                        id="terms",
                        label="Terms",
                        content="I agree to the terms and conditions of this agent acting autonomously",
                        col_span=1,
                    )
                    ],
            ),
            
        ),
    ],
):
    """
    Automated dependency vulnerability scanner and GitHub issue creator.
    
    This agent performs comprehensive security analysis of Python projects by:
    
    ## Core Workflow
    
    1. **Dependency Extraction**: Scans the target GitHub repository for uv.lock files and extracts 
       all Python package dependencies with their specific versions.
    
    2. **Vulnerability Detection**: Queries the Sonatype OSS Index API to identify known security 
       vulnerabilities (CVEs) affecting the discovered dependencies.
    
    3. **Automated Remediation**: Automatically creates detailed GitHub issues in the target repository 
       for each identified vulnerability, including:
       - Vulnerability description and severity
       - Affected package and version
       - CVE references and links
       - Recommended upgrade paths
    
    ## Key Features
    
    - **Full Transparency**: Provides real-time trajectory updates showing every step of the scanning 
      process, from dependency extraction through issue creation.
    
    - **Flexible Issue Styles**: Supports both concise and detailed GitHub issue formats to match 
      your team's preferences.
    
    - **Smart Tool Orchestration**: Uses BeeAI Framework's RequirementAgent with conditional requirements 
      to ensure tools execute in the correct order (Think → Scan Dependencies → Check Vulnerabilities → 
      Create Issues).
    
    - **Citation Support**: All vulnerability references and GitHub issues are properly formatted as 
      markdown links with citation metadata for easy tracking.
    
    - **Session Persistence**: Maintains conversation context across multiple interactions using 
      UnconstrainedMemory for follow-up questions and iterative scanning.
    
    ## Required Authentication
    
    - **GitHub Personal Access Token**: For reading repository contents and creating issues 
      (requires 'repo' scope)
    - **OSS Index Credentials**: API key and email for vulnerability database access 
      (free registration at https://ossindex.sonatype.org/)
    
    ## Usage
    
    Simply provide a GitHub repository URL through the form interface. The agent will automatically:
    - Locate and parse uv.lock dependency files
    - Cross-reference all dependencies against known vulnerability databases
    - Generate and submit GitHub issues for any security concerns found
    - Provide a comprehensive summary with links to all created issues
    
    ## Technical Stack
    
    - **Framework**: BeeAI Framework with RequirementAgent for rule-based tool execution
    - **Tools**: ThinkTool (reasoning), GitHubUvLockReader (dependency extraction), 
      OSSIndexTool (vulnerability scanning), GitHub API (issue creation)
    - **Extensions**: Form input, secrets management, trajectory tracking, citation formatting, 
      LLM service integration
    
    Perfect for security-conscious development teams who want automated, proactive vulnerability 
    management in their Python projects.
    """

    # Initial setup trajectory
    yield trajectory.trajectory_metadata(
        title="Initializing",
        content="Starting Dependency Defender and parsing form data"
    )

    # Parse the form data from the initial message
    try:
        form_data = form.parse_form_response(message=message)
        repo = form_data.values['Repo'].value
        issue_style = form_data.values['Issue_Style'].value
        
        yield trajectory.trajectory_metadata(
            title="Form Parsed",
            content=f"Repository: {repo} | Issue Style: {', '.join(issue_style) if isinstance(issue_style, list) else issue_style}"
        )
    except Exception as e:
        yield trajectory.trajectory_metadata(
            title="Form Parsing Error",
            content=f"Failed to parse form data: {e}"
        )
        yield f"Error parsing form: {e}"
        return
    
    # Secret retrieval trajectory
    yield trajectory.trajectory_metadata(
        title="Retrieving Secrets",
        content="Fetching GitHub PAT and OSS Index credentials"
    )
    
    #Get secrets from platform or request them
    async def get_secret(key: str):
        """Get secret from secrets extension"""
        # Check if secret is pre-configured
        if secrets and secrets.data and secrets.data.secret_fulfillments:
            if key in secrets.data.secret_fulfillments:
                return secrets.data.secret_fulfillments[key].secret
        
        runtime_secrets = await secrets.request_secrets(
            params=SecretsServiceExtensionParams(
                secret_demands={key: SecretDemand(
                    description=f"Required {key}",
                    name=key.replace("_", " ").title()
                )}
            )
        )
        if runtime_secrets and runtime_secrets.secret_fulfillments:
            return runtime_secrets.secret_fulfillments[key].secret
        
        return None
    
    
    try:
        # Get GitHub secrets
        github_pat_key = await get_secret('GITHUB_PAT')

        # Get OSS Index secrets  
        oss_api_key = await get_secret('OSS_INDEX_API')
        oss_email_key = await get_secret('OSS_INDEX_EMAIL')

        # Check if required secrets are available
        if not github_pat_key:
            yield trajectory.trajectory_metadata(
                title="Authentication Error",
                content="GitHub Personal Access Token is missing"
            )
            yield "GitHub Personal Access Token is required"
            return

        if not all([oss_api_key, oss_email_key]):
            yield trajectory.trajectory_metadata(
                title="Authentication Error",
                content="OSS Index credentials are missing"
            )
            yield "OSS Index API key and email are required"
            return
        
        yield trajectory.trajectory_metadata(
            title="Secrets Retrieved",
            content="Successfully authenticated with GitHub and OSS Index"
        )
        
    except Exception as e:
        yield trajectory.trajectory_metadata(
            title="Secret Retrieval Error",
            content=f"Failed to retrieve secrets: {e}"
        )
        yield f"Error retrieving secrets: {e}"
        return
        
        
    #Setting up the GitHub writer tool and MCP server
    tools = await session_manager.get_tools(github_pat_key)
    try:
        
        issue_write = None
        list_issue_types = None
        list_label = None

        for tool in tools:
            if tool.name == "issue_write":
                issue_write = await create_repo_scoped_tool(tool, repo)
            elif tool.name == "list_issue_types":
                list_issue_types = await create_repo_scoped_tool(tool, repo)
            elif tool.name == "list_label":
                list_label = await create_repo_scoped_tool(tool, repo)

    except ToolNotFoundError as e:
        raise RuntimeError(f"Failed to configure the agent: {e}") from e


    dependency_tool = GitHubUvLockReaderURLMinimal()
    oss_index_tool = OSSIndexFromContextTool(api_key=oss_api_key, email=oss_email_key)


    #checks that the llm is configured in the platform and creates the llm_client instance
    try:
        if not llm or not llm.data:
            raise ValueError("LLM service extension is required but not available")
        
        llm_config = llm.data.llm_fulfillments.get("default")
        
        if not llm_config:
            raise ValueError("LLM service extension provided but no fulfillment available")
        
        yield trajectory.trajectory_metadata(
            title="LLM Configured",
            content=f"Using model: {llm_config.api_model}"
        )
                
        # Create the actual chat model instance to pass to your agent
        llm_client = OpenAIChatModel(
            model_id=llm_config.api_model,
            base_url=llm_config.api_base,
            api_key=llm_config.api_key,
            parameters=ChatModelParameters(temperature=1, stream=True),
            tool_choice_support={"auto","required"}
            )
        
    except Exception as e:
        yield trajectory.trajectory_metadata(
            title="LLM Error",
            content=f"Failed to configure LLM: {e}"
        )
        yield f"Error configuring LLM: {e}"
        return

    instructions = """
        You are an AI agent responsible for finding dependencies that have vulnerabilities and writing github issues to remediate them.
        Summarize the vulnerability scan and GitHub issues created.

        CRITICAL FORMATTING RULE - THIS IS MANDATORY:
        - EVERY SINGLE URL must be formatted as a markdown link: [descriptive text](url)
        - NEVER write plain URLs like https://example.com
        - ALWAYS wrap URLs in markdown syntax like [example](https://example.com)

        Examples of CORRECT formatting:
        - Repository: [KenOcheltree/good-repo](https://github.com/KenOcheltree/good-repo)
        - Issue: [Issue #45: Fix numpy vulnerability](https://github.com/user/repo/issues/45)
        - CVE: [CVE-2021-34141](https://ossindex.sonatype.org/vulnerability/CVE-2021-34141)
        - Package info: [anyio 4.11.0 on PyPI](https://pypi.org/project/anyio/)

        Examples of INCORRECT formatting (DO NOT DO THIS):
        - ❌ Repository: https://github.com/KenOcheltree/bad-repo
        - ❌ Check out this link: https://example.com

        If no vulnerabilities are found, still mention the repository as a markdown link and be concise about the findings.
        """
    
    memory = get_memory(context)

    # Load conversation history into memory
    history = [message async for message in context.load_history() if isinstance(message, Message) and message.parts]
    await memory.add_many(to_framework_message(item) for item in history)
    
    
    user_message = json.dumps(
        {
            "repo_url": repo,
            "issue_style": issue_style,
        }
    )
    agent = RequirementAgent(
        llm=llm_client,
        memory=memory,
        tools=[ThinkTool(), dependency_tool, oss_index_tool, issue_write],
        instructions=instructions,
        requirements=[ 
            ConditionalRequirement(ThinkTool, force_at_step=1),
            ConditionalRequirement(GitHubUvLockReaderURLMinimal, force_at_step=2),
            ConditionalRequirement(issue_write, only_after=[GitHubUvLockReaderURLMinimal,oss_index_tool]),
        ],
    )

    # Start analysis
    yield trajectory.trajectory_metadata(
        title="Starting Analysis",
        content=f"Beginning vulnerability scan for repository: {repo}"
    )

# Start analysis
    yield trajectory.trajectory_metadata(
        title="Starting Analysis",
        content=f"Beginning vulnerability scan for repository: {repo}"
    )

    try:
        response_text = ""
        
        # Define the handler function to capture response text
        def handle_final_answer_stream(data: RequirementAgentFinalAnswerEvent, meta: EventMeta) -> None:
            nonlocal response_text
            if data.delta:
                response_text += data.delta
        
        # Stream events with the handler registered
        async for event, meta in agent.run(
            user_message,
            execution=AgentExecutionConfig(max_iterations=20, max_retries_per_step=2, total_max_retries=5)
        ).on("final_answer", handle_final_answer_stream):
            
            # Stream the deltas to user in real-time
            if meta.name == "final_answer":
                if isinstance(event, RequirementAgentFinalAnswerEvent) and event.delta:
                    yield event.delta
                    continue
            
            # Check if a tool just finished
            if meta.name == "success" and event.state.steps:
                step = event.state.steps[-1]
                if not step.tool:
                    continue
                
                tool_name = step.tool.name
                
                # Skip final_answer tool
                if tool_name == "final_answer":
                    continue
                
                # Show trajectory for all other tools
                if tool_name == "think":
                    thoughts = step.input.get("thoughts", "Planning...")
                    yield trajectory.trajectory_metadata(
                        title="Thinking",
                        content=thoughts[:200]
                    )
                
                elif tool_name == "GitHubUvLockReaderURLMinimal":
                    yield trajectory.trajectory_metadata(
                        title="Scanning Dependencies",
                        content=f"Reading uv.lock files from {repo}"
                    )
                
                elif "OSSIndex" in tool_name or "oss" in tool_name.lower():
                    yield trajectory.trajectory_metadata(
                        title="Vulnerability Check",
                        content="Querying Sonatype OSS Index for known CVEs"
                    )
                
                elif tool_name == "issue_write":
                    issue_title = step.input.get("title", "Vulnerability issue")
                    yield trajectory.trajectory_metadata(
                        title="GitHub Issue Created",
                        content=f"Issue: {issue_title}"
                    )
        
        # Process citations
        citations, clean_text = extract_citations(response_text)
        
        if citations:
            yield trajectory.trajectory_metadata(
                title="Citations Found",
                content=f"Extracted {len(citations)} citation(s)"
            )
            yield citation.citation_metadata(citations=citations)
        
        yield trajectory.trajectory_metadata(
            title="Analysis Complete",
            content="Vulnerability scan finished"
        )
        
        # Store the message (content was already streamed via deltas)
        response_message = AgentMessage(text=clean_text)
        await context.store(response_message)

    except Exception as e:
        yield trajectory.trajectory_metadata(
            title="Analysis Error",
            content=f"Error: {e}"
        )
        yield f"Error during analysis: {e}"
        return


        
   


# #THIS IS NOT YIELDING A FINAL ANSWER BUT IS WORKING OTHERWISE (YIELDING R$EAL TIME TOOL CALLS WITH TRAJECTORY)
#     try:
#         response_text = ""
        
#         # Define the handler function to capture response text
#         def handle_final_answer_stream(data: RequirementAgentFinalAnswerEvent, meta: EventMeta) -> None:
#             nonlocal response_text
#             if data.delta:
#                 response_text += data.delta
        
#         # Stream events with the handler registered
#         async for event, meta in agent.run(
#             user_message,
#             execution=AgentExecutionConfig(max_iterations=20, max_retries_per_step=2, total_max_retries=5)
#         ).on("final_answer", handle_final_answer_stream):  # <-- IMPORTANT: Register the handler
            
#             # Stream the deltas to user in real-time
#             if meta.name == "final_answer":
#                 if isinstance(event, RequirementAgentFinalAnswerEvent) and event.delta:
#                     yield event.delta
#                     continue
            
#             # Check if a tool just finished
#             if meta.name == "success" and event.state.steps:
#                 step = event.state.steps[-1]
#                 if not step.tool:
#                     continue
                
#                 tool_name = step.tool.name
                
#                 # Skip final_answer tool
#                 if tool_name == "final_answer":
#                     continue
                
#                 # Show trajectory for all other tools
#                 if tool_name == "think":
#                     thoughts = step.input.get("thoughts", "Planning...")
#                     yield trajectory.trajectory_metadata(
#                         title="Thinking",
#                         content=thoughts[:200]
#                     )
                
#                 elif tool_name == "GitHubUvLockReaderURLMinimal":
#                     yield trajectory.trajectory_metadata(
#                         title="Scanning Dependencies",
#                         content=f"Reading uv.lock files from {repo}"
#                     )
                
#                 elif "OSSIndex" in tool_name or "oss" in tool_name.lower():
#                     yield trajectory.trajectory_metadata(
#                         title="Vulnerability Check",
#                         content="Querying Sonatype OSS Index for known CVEs"
#                     )
                
#                 elif tool_name == "issue_write":
#                     issue_title = step.input.get("title", "Vulnerability issue")
#                     yield trajectory.trajectory_metadata(
#                         title="GitHub Issue Created",
#                         content=f"Issue: {issue_title}"
#                     )
        
#         # Process citations
#         citations, clean_text = extract_citations(response_text)
        
#         if citations:
#             yield trajectory.trajectory_metadata(
#                 title="Citations Found",
#                 content=f"Extracted {len(citations)} citation(s)"
#             )
#             yield citation.citation_metadata(citations=citations)
        
#         yield trajectory.trajectory_metadata(
#             title="Analysis Complete",
#             content="Vulnerability scan finished"
#         )
        
#         # Store the message (DON'T yield Message at end - content was already streamed)
#         response_message = AgentMessage(text=clean_text)
#         await context.store(response_message)

#     except Exception as e:
#         yield trajectory.trajectory_metadata(
#             title="Analysis Error",
#             content=f"Error: {e}"
#         )
#         yield f"Error during analysis: {e}"
#         return


def main():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
