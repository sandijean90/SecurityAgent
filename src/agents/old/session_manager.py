import os
from typing import Optional, Any, Annotated
import pydantic
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from beeai_framework.tools.mcp import MCPTool
from beeai_sdk.a2a.extensions.auth.oauth import OAuthExtensionServer, OAuthExtensionSpec

class MCPSessionManager:
    def __init__(self, oauth: Optional[OAuthExtensionServer] = None):
        """
        Initialize the session manager with optional OAuth extension.
        
        Args:
            oauth: BeeAI OAuth extension server (injected by the platform)
        """
        self._session: Optional[ClientSession] = None
        self._streams: Optional[Any] = None
        self._tools: Optional[list[MCPTool]] = None
        self._oauth = oauth
        self._mcp_url = os.getenv('MCP_SERVER_URL', 'https://api.githubcopilot.com/mcp/x/issues')

    async def connect(self):
        """Connect to the MCP server using OAuth authentication if available"""
        headers = {
            "Accept": "application/json",
        }
        
        # Create auth handler if OAuth is available
        auth = None
        if self._oauth:
            try:
                # Create HTTPX auth for the MCP endpoint
                auth = await self._oauth.create_httpx_auth(
                    resource_url=pydantic.AnyUrl(self._mcp_url)
                )
            except Exception as e:
                print(f"OAuth auth creation failed: {e}, falling back to PAT if available")
                # Fallback to PAT if OAuth fails
                if os.getenv('GITHUB_PAT'):
                    headers["Authorization"] = f"Bearer {os.getenv('GITHUB_PAT')}"
        elif os.getenv('GITHUB_PAT'):
            # Use PAT if OAuth is not available
            headers["Authorization"] = f"Bearer {os.getenv('GITHUB_PAT')}"
        
        # Connect using streamablehttp_client with auth
        self._streams = streamablehttp_client(
            url=self._mcp_url,
            headers=headers,
            auth=auth  # Pass the auth handler
        )
        
        streams = await self._streams.__aenter__()
        self._session = ClientSession(streams[0], streams[1])
        await self._session.__aenter__()
        await self._session.initialize()
        
    async def get_session(self) -> ClientSession:
        """Get or create an MCP session"""
        if self._session is None:
            await self.connect()
        return self._session

    async def get_tools(self) -> list[MCPTool]:
        """Get available MCP tools from the session"""
        if self._tools is None:
            session = await self.get_session()
            self._tools = await MCPTool.from_client(session)
        return self._tools

    async def close(self):
        """Close the session and clean up resources"""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None
        if self._streams:
            await self._streams.__aexit__(None, None, None)
            self._streams = None
        self._tools = None