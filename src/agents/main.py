import json
import os
from typing import Annotated
import uuid
from a2a.types import Message
from a2a.utils.message import get_message_text
from beeai_framework.backend import ChatModel, ChatModelParameters
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.requirements.conditional import ConditionalRequirement
from beeai_framework.middleware.trajectory import GlobalTrajectoryMiddleware
from beeai_framework.tools.think import ThinkTool
from agentstack_sdk.server import Server
from agentstack_sdk.a2a.types import AgentMessage
from agentstack_sdk.a2a.extensions import LLMServiceExtensionServer, LLMServiceExtensionSpec
from agentstack_sdk.a2a.extensions import AgentDetail, AgentDetailContributor, AgentDetailTool
from agentstack_sdk.a2a.extensions.ui.form import (
    FormExtensionServer,
    FormExtensionSpec,
    FormRender,
    TextField,
    CheckboxField,
    MultiSelectField,
    OptionItem,
)
from a2a.types import AgentSkill, Message, Role , TextPart
from textwrap import dedent
from fetch_dependencies_tool import GitHubUvLockReaderURLMinimal
from dependency_search_tool import OSSIndexFromContextTool
from beeai_framework.tools import Tool



server = Server()

@server.agent(
    name="Vulnerability Detection Agent",
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
                name="Tavily",
                description="internet search",
            ),
            AgentDetailTool(
                name="Think", 
                description="Advanced reasoning and analysis to provide thoughtful, well-structured responses to complex questions and topics."
            )
        ],
        author={
            "name": "Sandi Besen",
            "name": "Kenneth Olcheltree"
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
            examples=[]
        )
    ],
)
async def Dependency_Vulnerability_Agent(
    message: Message,
    form: Annotated[
        FormExtensionServer,
        FormExtensionSpec(
            params=FormRender(
                id="user_info_form",
                title="Does your Repo have Vulnerable Dependencies? Let's fix that. ",
                columns=2,
                fields=[
                    TextField(id="Repo", label="Repo URL", col_span=1),
                    TextField(id="Task", label="Additional Context?", col_span=1),
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
                        id="Terms",
                        label="Terms",
                        content="I agree to the terms and conditions.",
                        col_span=1,
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
                        id="llm_key_from_env",
                        label="LLM Key Source",
                        content="Use ENV Vars to Set Key",
                        col_span=1,
                    ),
                    TextField(id="LLM_Source_Key", label="LLM Provider Key", col_span=1),
                ],
            ),
            
        ),
    ],
):
    print("Parsing Values")
    # Parse the form data from the initial message
    form_data = form.parse_form_response(message=message)

    # Access the form values
    repo = form_data.values['Repo'].value
    task = form_data.values['Task'].value
    issue_style = form_data.values['Issue_Style'].value
    terms = form_data.values['Terms'].value

    llm_provider= form_data.values['LLM_Source'].value[0]
    llm_key_from_env = form_data.values['llm_key_from_env'].value
    llm_key_read = form_data.values['LLM_Source_Key'].value

    print("Repo: ", repo, " Task: ", task, " Issue Style: ", issue_style)
    print("LLM Provider: ", llm_provider)

    dependency_tool = GitHubUvLockReaderURLMinimal()
    oss_index_tool = OSSIndexFromContextTool()

    # Ollama - No parameters required
    if llm_provider=="ollama":
        model="granite4:tiny-h"
        #model="granite3.3"
        provider_model=llm_provider+":"+model
        #!ollama pull $model
        llm=ChatModel.from_name(provider_model, ChatModelParameters(temperature=0))
    # OpenAI - Place OpenAI API Key in Colab Secrets (key icon) as OPENAI_KEY
    elif llm_provider=="openai":
        model="gpt-5-mini"
        provider_model=llm_provider+":"+model
        if llm_key_from_env:
            api_key=llm_key_read
        else:
            api_key=os.getenv("OPENAI_API_KEY","None") #Set secret value using key in left menu

        llm=ChatModel.from_name(provider_model, ChatModelParameters(temperature=1), api_key=api_key, stream=True)
    # WatsonX - Place Project ID, API Key and WatsonX URL in Colab Secrets (key icon)
    elif llm_provider=="watsonx":
        model="ibm/granite-3-8b-instruct"
        provider_model=llm_provider+":"+model
        project_id = os.getenv('WATSONX_PROJECT_ID')  #Set secret value using key in left menu
        api_key = os.getenv('WATSONX_APIKEY')         #Set secret value using key in left menu
        base_url = os.getenv('WATSONX_URL')           #Set secret value using key in left menu
        llm=ChatModel.from_name(provider_model, ChatModelParameters(temperature=0), project_id=project_id, api_key=api_key, base_url=base_url)
    else:
        print("Provider " + llm_provider + " undefined")

    """Manager agent that hands off to specialty agents to complete the task"""
    instructions = "You are an AI agent responsible for finding dependencies that have vulnerabilitites and writing github issues to remediate them."
    user_message = json.dumps(
        {
            "repo_url": repo,
            "task_context": task,
            "issue_style": issue_style,
        }
    )
    agent = RequirementAgent(
        llm=llm,
        tools=[ThinkTool(), dependency_tool, oss_index_tool],
        instructions=instructions,
        requirements=[ 
            ConditionalRequirement(ThinkTool, force_at_step=1),
            ConditionalRequirement(GitHubUvLockReaderURLMinimal, force_at_step=2),
            ConditionalRequirement(OSSIndexFromContextTool, force_at_step=3),
        ],
    )
    response = await agent.run(user_message).middleware(GlobalTrajectoryMiddleware(included=[Tool]))
    response_text = response.output_structured.response
    
    yield Message(
        role="agent", 
        message_id=str(uuid.uuid4()), 
        parts=[TextPart(text=response_text)]
    )



def main():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))



if __name__ == "__main__":
    main()
