import json
import os
from typing import Annotated
import uuid
import re
from a2a.types import Message
from a2a.utils.message import get_message_text
from beeai_framework.backend import ChatModel, ChatModelParameters
from beeai_framework.backend.message import AssistantMessage, UserMessage
from beeai_framework.memory import UnconstrainedMemory
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.requirements.conditional import ConditionalRequirement
from beeai_framework.agents.requirement.requirements.ask_permission import AskPermissionRequirement
from beeai_framework.middleware.trajectory import GlobalTrajectoryMiddleware
from beeai_framework.tools.think import ThinkTool
from agentstack_sdk.server import Server
from agentstack_sdk.server.context import RunContext
from agentstack_sdk.a2a.types import AgentMessage
from agentstack_sdk.a2a.extensions import (
    LLMServiceExtensionServer,LLMServiceExtensionSpec,
    AgentDetail, AgentDetailContributor, AgentDetailTool,
    TrajectoryExtensionServer, TrajectoryExtensionSpec,
    )
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
    secrets: Annotated[
        SecretsExtensionServer,
        SecretsExtensionSpec(
            params=SecretsServiceExtensionParams(
                secret_demands={
                    # LLM Keys
                    "OPENAI_API_KEY": SecretDemand(
                        name="OpenAI API Key",
                        description="API key for OpenAI services"
                    ),
                    "WATSONX_PROJECT_ID": SecretDemand(
                        name="WatsonX Project ID",
                        description="Project ID for WatsonX"
                    ),
                    "WATSONX_APIKEY": SecretDemand(
                        name="WatsonX API Key",
                        description="API key for WatsonX"
                    ),
                    "WATSONX_URL": SecretDemand(
                        name="WatsonX URL",
                        description="Base URL for WatsonX instance"
                    ),
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
                    MultiSelectField(
                        id="LLM_Source",
                        label="LLM Source",
                        options=[
                            OptionItem(id="openai", label="OpenAI"),
                            OptionItem(id="watsonx", label="WatsonX"),
                            OptionItem(id="ollama", label="Ollama"),
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
    
    """Manager agent that hands off to specialty agents to complete the task"""

    print("Parsing Values From Form")
    # Parse the form data from the initial message
    form_data = form.parse_form_response(message=message)

    # Access the form values
    repo = form_data.values['Repo'].value
    issue_style = form_data.values['Issue_Style'].value
    
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
    
    llm_provider= form_data.values['LLM_Source'].value[0]

    # llm_key_from_env = form_data.values['llm_key_from_env'].value

    print("Repo: ", repo, " Issue Style: ", issue_style)
    print("LLM Provider: ", llm_provider)


    # Ollama - No parameters required
    if llm_provider == "ollama":
        model = "granite4:tiny-h"
        provider_model = llm_provider + ":" + model
        llm = ChatModel.from_name(provider_model, ChatModelParameters(temperature=0))

    # OpenAI - Place OpenAI API Key in Colab Secrets (key icon) as OPENAI_KEY
    elif llm_provider == "openai":
        model = "gpt-5-mini"
        provider_model = llm_provider + ":" + model
        yield trajectory.trajectory_metadata(title="Secret", content="Getting OpenAI API key")
        api_key = await get_secret('OPENAI_API_KEY')
        
        if not api_key:
            yield "OpenAI API key is required but not provided"
            return
        
        llm = ChatModel.from_name(
            provider_model, 
            ChatModelParameters(temperature=1), 
            api_key=api_key, 
            stream=True
        )


    # WatsonX - Place Project ID, API Key and WatsonX URL in Colab Secrets (key icon)
    elif llm_provider == "watsonx":
        model = "ibm/granite-3-8b-instruct"
        provider_model = llm_provider + ":" + model
        
        # CHANGE THESE LINES - use get_secret instead of os.getenv
        project_id = await get_secret('WATSONX_PROJECT_ID')
        api_key = await get_secret('WATSONX_APIKEY')
        base_url = await get_secret('WATSONX_URL')
        
        if not all([project_id, api_key, base_url]):
            yield "WatsonX credentials (project ID, API key, and URL) are required but not provided"
            return
        
        llm = ChatModel.from_name(
            provider_model, 
            ChatModelParameters(temperature=0), 
            project_id=project_id, 
            api_key=api_key, 
            base_url=base_url
        )
    else:
        yield f"Provider {llm_provider} undefined"
        return
    
    # Get GitHub secrets
    github_pat_key = await get_secret('GITHUB_PAT')

    # Get OSS Index secrets  
    oss_api_key = await get_secret('OSS_INDEX_API')
    oss_email_key = await get_secret('OSS_INDEX_EMAIL')

    # Check if required secrets are available
    if not github_pat_key:
        yield "GitHub Personal Access Token is required"
        return

    if not all([oss_api_key, oss_email_key]):
        yield "OSS Index API key and email are required"
        return
    
    """Create and configure the issue workflow management agent."""
    tools = await session_manager.get_tools(github_pat_key)
    try:
        tools = await get_tools_by_names(tools, ["issue_write", "list_issue_types", "list_label"])
        
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

    instructions = """
        You are an AI agent responsible for finding dependencies that have vulnerabilitites and writing github issues to remediate them.
        Summarize the vulnerability scan and GitHub issues created.

        CRITICAL: ALL URLs must be formatted as markdown links: [descriptive text](url)
        Never include plain URLs - always wrap them in markdown link syntax.

        Examples:
        - Repository: [bad-repo](https://github.com/KenOcheltree/bad-repo)
        - Issue: [Issue #45: Fix numpy vulnerability](https://github.com/user/repo/issues/45)  
        - CVE: [CVE-2021-34141](https://ossindex.sonatype.org/vulnerability/CVE-2021-34141)
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
        llm=llm,
        memory=memory,
        tools=[ThinkTool(), dependency_tool, oss_index_tool, issue_write],
        instructions=instructions,
        requirements=[ 
            ConditionalRequirement(ThinkTool, force_at_step=1),
            ConditionalRequirement(GitHubUvLockReaderURLMinimal, force_at_step=2),
            ConditionalRequirement(issue_write, only_after=[GitHubUvLockReaderURLMinimal,oss_index_tool]),
        ],
    )
    response = await agent.run(user_message).middleware(GlobalTrajectoryMiddleware(included=[Tool]))
    response_text = response.output_structured.response

    citations, clean_text = extract_citations(response_text)

    if citations:
        yield trajectory.trajectory_metadata(
            title="Citations Processed",
            content=f"Extracted {len(citations)} citation(s) from response"
        )
        yield citation.citation_metadata(citations=citations)
    
    
    yield Message(
        role="agent", 
        message_id=str(uuid.uuid4()), 
        parts=[TextPart(text=clean_text)]
    )



def main():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))



if __name__ == "__main__":
    main()
