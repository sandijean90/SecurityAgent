import os
from typing import Annotated
import uuid
from a2a.types import Message, TextPart
from a2a.types import Message
from a2a.utils.message import get_message_text
from beeai_sdk.server import Server
from beeai_sdk.a2a.types import AgentMessage
from beeai_sdk.a2a.extensions import LLMServiceExtensionServer, LLMServiceExtensionSpec
from beeai_sdk.a2a.extensions import AgentDetail, AgentDetailContributor, AgentDetailTool
from beeai_sdk.a2a.extensions.ui.form import (
    FormExtensionServer,
    FormExtensionSpec,
    FormRender,
    TextField,
    CheckboxField,
    MultiSelectField,
    OptionItem
)
from a2a.types import AgentSkill, Message, Role
from textwrap import dedent
from beeai_framework.backend import ChatModel
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.middleware.trajectory import GlobalTrajectoryMiddleware
from beeai_framework.memory import UnconstrainedMemory
from beeai_framework.tools.think import ThinkTool


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
    input: Message,
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
                        id="multiselect_field",
                        label="Github Issue Style",
                        options=[
                            OptionItem(id="concise", label="concise"),
                            OptionItem(id="detailed", label="detailed"),
                        ],
                        col_span=2,
                    ),
                    CheckboxField(
                        id="checkbox_field",
                        label="Terms",
                        content="I agree to the terms and conditions.",
                        col_span=1,
                    ),
                ],
            ),
            
        ),
    ],
):
    """Manager agent that hands off to specialty agents to complete the task"""
    llm = os.getenv("LLM", "openai:gpt-5-mini")
    instructions = "Say hi so I know you're working"
    user_message="Hi"
    agent = RequirementAgent(
        llm=ChatModel.from_name(llm),
        tools=[ThinkTool()],
        instructions=instructions,
        requirements=[],
    )
    response = await agent.run(user_message).middleware(GlobalTrajectoryMiddleware())
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
