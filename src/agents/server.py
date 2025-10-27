import asyncio
from textwrap import dedent

from a2a.types import AgentSkill
from beeai_framework.adapters.beeai_platform.serve.server import BeeAIPlatformServer
from beeai_sdk.a2a.extensions.ui.agent_detail import AgentDetail
from dotenv import load_dotenv
from openinference.instrumentation.beeai import BeeAIInstrumentor
from beeai_sdk.a2a.types import AgentMessage
from beeai_sdk.a2a.extensions import AgentDetail, AgentDetailContributor, AgentDetailTool
from agents.agent_manager import get_agent_manager
from a2a.types import AgentSkill, Message, Role

BeeAIInstrumentor().instrument()


load_dotenv()

async def run():
    manager = await get_agent_manager()
    server = BeeAIPlatformServer(config={"configure_telemetry": True})
    server.register(
        manager,
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
            ]
    )
    await server.aserve()


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()
