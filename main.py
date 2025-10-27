import os
from typing import Annotated

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
    TextField
)


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
        ],
        homepage_url="https://github.com/sandijean90/VulnerabilityAgent",        container_image_url="ghcr.io/beeai-dev/beeai-agents:v0.0.1",
        author=AgentDetailContributor(
            name="Sandi Besen",
            email="sandi.besen@ibm.com",
        ),
    )
)
async def OperatorAgent(
    input: Message,
    form: Annotated[
        FormExtensionServer,
        FormExtensionSpec(
            params=FormRender(
                id="user_info_form",
                title="Welcome! Please tell us about yourself",
                columns=2,
                fields=[
                    TextField(id="first_name", label="First Name", col_span=1),
                    TextField(id="last_name", label="Last Name", col_span=1),
                ],
            )
        ),
    ],
    llm: Annotated[
        LLMServiceExtensionServer,
        LLMServiceExtensionSpec.single_demand(suggested=("openai/gpt-5-mini",))
    ],
):
    """Agent that uses LLM inference to respond to user input"""

    if llm:
        # Extract the user's message
        user_message = get_message_text(input)
        
        # Get LLM configuration
        # Single demand is resolved to default (unless specified otherwise)
        llm_config = llm.data.llm_fulfillments.get("default")
        
        # Use the LLM configuration with your preferred client
        # The platform provides OpenAI-compatible endpoints
        api_model = llm_config.api_model
        api_key = llm_config.api_key
        api_base = llm_config.api_base

        yield AgentMessage(text=f"LLM access configured for model: {api_model}")



def main():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))



if __name__ == "__main__":
    main()
