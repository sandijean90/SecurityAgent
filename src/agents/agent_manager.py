import json
import os
from textwrap import dedent, indent

from beeai_framework.agents.experimental import RequirementAgent
from beeai_framework.agents.experimental.prompts import (
    RequirementAgentSystemPromptInput,
    RequirementAgentTaskPromptInput,
)
from beeai_framework.agents.experimental.requirements.ask_permission import AskPermissionRequirement
from beeai_framework.agents.experimental.requirements.conditional import ConditionalRequirement
from beeai_framework.middleware.trajectory import GlobalTrajectoryMiddleware
from beeai_framework.template import PromptTemplate, PromptTemplateInput
from beeai_framework.tools import Tool
from beeai_framework.tools.handoff import HandoffTool

from agents.dependency_analyst import 
from agents.utils import ToolNotFoundError, create_repo_scoped_tool, get_tools_by_names, llm, session_manager


async def get_agent_manager():
    """Create and configure the issue workflow management agent."""
    tools = await session_manager.get_tools()

    try:
        tools = await get_tools_by_names(tools, ["create_issue", "list_issue_types", "list_label"])

        create_issue = None
        list_issue_types = None
        list_label = None

        for tool in tools:
            if tool.name == "create_issue":
                create_issue = await create_repo_scoped_tool(tool)
            elif tool.name == "list_issue_types":
                list_issue_types = await create_repo_scoped_tool(tool)
            elif tool.name == "list_label":
                list_label = await create_repo_scoped_tool(tool)

    except ToolNotFoundError as e:
        raise RuntimeError(f"Failed to configure the agent: {e}") from e

    # Get issue types with fallback
    fallback_types = [{"name": "Issue", "description": "An issue about a dependency with a found vuulnerability."}]

    try:
        response = await list_issue_types.run(input={})
        issue_types_data = json.loads(response) if response else fallback_types
    except Exception:
        # Fallback to default types on any error (including 404)
        issue_types_data = fallback_types

    ######I think this was all to insert into the instructions!
    # issue_types_lines = [f"- {issue_type['name']}: {issue_type['description']}" for issue_type in issue_types_data]
    # issue_types_text = indent("\n".join(issue_types_lines), "    ")

    # # Get labels with fallback
    # fallback_labels = []

    # try:
    #     response = await list_label.run(input={})
    #     # Parse nested response structure
    #     response_data = json.loads(response.get_text_content())
    #     # Extract text from first content block
    #     text_content = response_data[0]["text"]
    #     # Parse the JSON string inside
    #     labels_response = json.loads(text_content)
    #     # Extract labels array
    #     labels_data = labels_response["labels"]
    # except Exception:
    #     # Fallback to empty list on any error (including 404, parsing errors)
    #     labels_data = fallback_labels

    # Extract only name and description from each label
    # labels_lines = [f"- {label['name']}: {label.get('description', '')}" for label in labels_data]
    # labels_text = indent("\n".join(labels_lines), "    ")

    # repository = os.getenv("GITHUB_REPOSITORY")

    role = "helpful coordinator"
    instruction = f"""PLACEHOLDER"""

    # Get the specialized agents

    #handoff agents
    # handoff_writer = HandoffTool(
    #     target=writer,
    #     name="transfer_to_writer",
    #     description="Assign to Technical Writer for drafting.",
    #     propagate_inputs=False,
    # )

    # handoff_analyst = HandoffTool(
    #     target=analyst,
    #     name="transfer_to_analyst",
    #     description="Assign to Analyst for duplicate issue search.",
    #     propagate_inputs=False,
    # )

    template = dedent(
    """\
    # Role
    Assume the role of {{role}}.

    # Instructions
    {{#instructions}}
    {{&.}}
    {{/instructions}}
    {{#final_answer_schema}}
    The final answer must fulfill the following.

    ```
    {{&final_answer_schema}}
    ```
    {{/final_answer_schema}}
    {{#final_answer_instructions}}
    {{&final_answer_instructions}}
    {{/final_answer_instructions}}

    IMPORTANT: The facts mentioned in the final answer must be backed by evidence provided by relevant tool outputs.

    # Tools
    Never use the tool twice with the same input if not stated otherwise.

    {{#tools.0}}
    {{#tools}}
    Name: {{name}}
    Description: {{description}}

    {{/tools}}
    {{/tools.0}}

    {{#notes}}
    {{&.}}
    {{/notes}}
    """,)

    return RequirementAgent(
        name="Manager",
        llm=llm,
        role=role,
        instructions=instruction,
        tools=[
            # SimpleThinkTool(),
            # handoff_writer,
            # handoff_analyst,
            create_issue,
        ],
        requirements=[],
        templates={
            "system": PromptTemplate(PromptTemplateInput(schema=RequirementAgentSystemPromptInput, template=template)),
        },
        save_intermediate_steps=False,
        middlewares=[GlobalTrajectoryMiddleware(included=[Tool])],
    )
