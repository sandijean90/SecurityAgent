import os
from typing import Optional, Any, Annotated
from agentstack_sdk.server import Server
from agentstack_sdk.server.context import RunContext
from agentstack_sdk.a2a.types import AgentMessage
from a2a.types import Message
from agentstack_sdk.a2a.extensions.auth.oauth import OAuthExtensionServer, OAuthExtensionSpec
from session_manager import MCPSessionManager
from agentstack_sdk.a2a.extensions import AgentDetail, AgentDetailContributor, AgentDetailTool
from agentstack_sdk.a2a.extensions.ui.form import (
    FormExtensionServer,
    FormExtensionSpec,
    FormRender,
    TextField
)
from agentstack_sdk.a2a.extensions import LLMServiceExtensionServer, LLMServiceExtensionSpec
from a2a.utils.message import get_message_text


async def github_mcp_agent(
    context: RunContext,
    oauth: Annotated[OAuthExtensionServer, OAuthExtensionSpec.single_demand()],
    llm: Annotated[
        LLMServiceExtensionServer,
        LLMServiceExtensionSpec.single_demand(suggested=("openai/gpt-5-mini",))]
):
    """Agent that uses GitHub MCP with OAuth authentication"""
    
    # Initialize session manager with OAuth
    session_manager = MCPSessionManager(oauth=oauth)
    
    try:
        # Get MCP tools
        tools = await session_manager.get_tools()
        
        # Use the tools...
        for tool in tools:
            yield AgentMessage(text=f"Available tool: {tool.name}")
        
        if llm:
    
            # Get LLM configuration
            # Single demand is resolved to default (unless specified otherwise)
            llm_config = llm.data.llm_fulfillments.get("default")
            
            # Use the LLM configuration with your preferred client
            # The platform provides OpenAI-compatible endpoints
            api_model = llm_config.api_model
            api_key = llm_config.api_key
            api_base = llm_config.api_base

            yield AgentMessage(text=f"LLM access configured for model: {api_model}")


        
    finally:
        await session_manager.close()
