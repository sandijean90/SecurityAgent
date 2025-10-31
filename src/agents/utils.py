import os
from typing import Literal, Optional

import aiohttp
from beeai_framework.backend import ChatModel
from beeai_framework.tools import Tool, tool
from dotenv import load_dotenv
from pydantic import BaseModel

from session_manager import SessionManager

load_dotenv()

#model = os.getenv("MODEL", "openai:gpt-5-mini")
#llm = ChatModel.from_name(model, {"api_key": os.getenv("API_KEY")})

# Shared singleton instance
session_manager = SessionManager()

class ToolNotFoundError(Exception):
    """Raised when required tools are not available."""

    pass


async def get_tools_by_names(tools: list[Tool], tool_names: list[str]) -> list[Tool]:
    """Get tools by names with comprehensive error handling.

    Args:
        tools: List of available tools.
        tool_names: List of required tool names.

    Returns:
        list[Tool]: List of matching tools.

    Raises:
        ToolNotFoundError: If any required tools are not found.
    """
    available_tools = []
    missing_tools = []

    for tool_name in tool_names:
        matching_tools = [tool for tool in tools if tool.name == tool_name]
        if matching_tools:
            available_tools.extend(matching_tools)
        else:
            missing_tools.append(tool_name)

    if missing_tools:
        available_tool_names = [tool.name for tool in tools]
        raise ToolNotFoundError(f"Required tools {missing_tools} not found. Available tools: {available_tool_names}")

    return available_tools


async def fetch_content(url: str) -> str:
    """Fetch content from provided URL"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    print(f"Failed to fetch content: {response.status}")
                    return ""
    except Exception as e:
        print(f"Error fetching content: {e}")
        return ""


async def create_repo_scoped_tool(original_tool: Tool) -> Tool:
    """Create a wrapper tool that hardcodes owner and repo from GITHUB_REPOSITORY env var.

    This function dynamically creates a new tool that:
    1. Takes the original tool's input schema and removes 'owner' and 'repo' fields
    2. Hardcodes owner and repo from GITHUB_REPOSITORY environment variable
    3. Creates a wrapper function that calls the original tool with the hardcoded values
    """
    repository = os.getenv("GITHUB_REPOSITORY")
    if not repository:
        raise RuntimeError("GITHUB_REPOSITORY environment variable is required")

    owner, repo = repository.split("/")

    # Create input models based on the actual schemas (removing owner/repo)
    if original_tool.name == "search_issues":

        class SearchIssuesInput(BaseModel):
            query: str  # Required
            sort: Optional[
                Literal[
                    "comments",
                    "reactions",
                    "reactions-+1",
                    "reactions--1",
                    "reactions-smile",
                    "reactions-thinking_face",
                    "reactions-heart",
                    "reactions-tada",
                    "interactions",
                    "created",
                    "updated",
                ]
            ] = None
            order: Optional[Literal["asc", "desc"]] = None
            page: Optional[int] = None  # Optional pagination
            perPage: Optional[int] = None  # Optional pagination (1-100)

        input_schema = SearchIssuesInput
    elif original_tool.name == "list_issues":

        class ListIssuesInput(BaseModel):
            state: Optional[Literal["OPEN", "CLOSED"]] = None
            labels: Optional[list[str]] = None  # Optional filter by labels
            since: Optional[str] = None  # Optional ISO 8601 timestamp
            orderBy: Optional[Literal["CREATED_AT", "UPDATED_AT", "COMMENTS"]] = None
            direction: Optional[Literal["ASC", "DESC"]] = None
            perPage: Optional[int] = None  # Optional (1-100)
            after: Optional[str] = None  # Optional cursor for pagination

        input_schema = ListIssuesInput
    elif original_tool.name == "get_issue":

        class GetIssueInput(BaseModel):
            issue_number: int  # Required

        input_schema = GetIssueInput
    elif original_tool.name == "create_issue":

        class CreateIssueInput(BaseModel):
            title: str  # Required
            body: Optional[str] = None  # Optional
            labels: Optional[list[str]] = None  # Optional
            # assignees: Optional[list[str]] = None  # Optional
            # milestone: Optional[int] = None  # Optional
            type: Optional[str] = None  # Optional

        input_schema = CreateIssueInput
    elif original_tool.name == "list_issue_types":

        class ListIssueTypesInput(BaseModel):
            pass

        input_schema = ListIssueTypesInput
    elif original_tool.name == "list_label":

        class ListLabelInput(BaseModel):
            pass

        input_schema = ListLabelInput
    else:
        # Fallback: use the original tool without wrapping
        return original_tool

    @tool(description=original_tool.description, input_schema=input_schema)
    async def wrapper_tool(**kwargs):
        """Wrapper tool with hardcoded owner and repo."""
        # Remove any owner/repo from kwargs to prevent override attempts
        filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ["owner", "repo"]}

        # Add the hardcoded owner and repo to the parameters (always programmatically set)
        if original_tool.name == "list_issue_types":
            # list_issue_types only needs owner, not repo
            params = {"owner": owner, **filtered_kwargs}
        else:
            params = {"owner": owner, "repo": repo, **filtered_kwargs}

        # Call the original tool
        result = await original_tool.run(params)
        return result

    # Set the name to match the original tool
    wrapper_tool.name = original_tool.name

    return wrapper_tool