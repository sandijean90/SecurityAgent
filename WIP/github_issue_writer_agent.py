import os
from textwrap import dedent
from typing import Annotated

from agentstack_sdk.a2a.extensions import (
    LLMServiceExtensionServer,
    LLMServiceExtensionSpec,
)
from agentstack_sdk.a2a.types import AgentMessage
from agentstack_sdk.server import Server
from agentstack_sdk.server.context import RunContext

from a2a.types import Message
from a2a.utils.message import get_message_text

from beeai_framework.adapters.openai import OpenAIChatModel
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.prompts import (
    RequirementAgentSystemPrompt,
    RequirementAgentTaskPrompt,
)
from beeai_framework.agents.requirement.types import RequirementAgentTemplates
from beeai_framework.backend import ChatModelParameters
from beeai_framework.backend.message import UserMessage
from beeai_framework.memory import UnconstrainedMemory
from pydantic import BaseModel, Field

server = Server()

ISSUE_WRITER_INSTRUCTIONS = dedent(
    """
    You generate a single GitHub issue payload summarizing all discovered vulnerabilities.

    ## Inputs
    The caller may supply:
      - Structured JSON (preferred) that includes fields such as `repo_url`, `issue_style`, `vulnerabilities`, and `notes`.
      - Free-form prose describing the repository, desired issue style, and vulnerability findings.
    In all cases, extract the following best-effort:
      - Repository identifier and URL (if the URL is not provided, infer the owner/name when possible).
      - Desired issue style; if multiple styles are listed, use the first value.
      - Only the dependencies that actually have confirmed vulnerabilities. Ignore packages with no vulnerability data.
      - For each vulnerability: package name, installed version, severity (or qualitative description), CVE identifiers or links, and recommended remediation.

    If a field is missing or cannot be inferred, proceed with sensible defaults (e.g., treat style as "detailed", leave optional sections blank, or label CVE data as "N/A"). Never invent vulnerabilities or remediation steps.

    ## Output Contract
    Return JSON with the keys: `title` (str), `body` (str), `labels` (list[str]). The JSON must be valid and ready to pass to another tool.
    Always create exactly one issue that covers all vulnerabilities.

    ## Title Guidelines
    - Mention the repository name when available and emphasize security (e.g., "Address security issues in <repo> dependencies").

    ## Body Guidelines (all styles)
    - Begin with a short summary referencing the repository. When you know the URL, render it as a markdown link.
    - Provide a clearly labeled section enumerating each vulnerable package.
    - Every vulnerability entry should include the package, installed version, severity, CVE list (as markdown links when URLs exist), and the recommended upgrade or mitigation.
    - Close with a concise call to action.

    ## Concise Style Rules
    - Short introductory paragraph.
    - Use `"### Vulnerabilities"` followed by compact bullets (single paragraph per vulnerability).
    - Omit additional headings.

    ## Detailed Style Rules
    - Add a `"## Summary"` section with 2–3 sentences describing impact.
    - Include a `"## Affected Packages"` table with columns: Package, Installed Version, Severity, CVEs, Recommendation.
    - Finish with a `"## Next Steps"` section listing actionable bullets, including testing guidance.

    ## Labels Rules
    - Always include `"security"`.
    - Add `"dependencies"` when two or more vulnerabilities are present.
    - If any vulnerability has severity containing "high" or "critical" (case-insensitive), add `"high-priority"`.
    """
).strip()


class IssueDraft(BaseModel):
    """Structured payload returned to the calling agent."""

    title: str = Field(description="GitHub issue title")
    body: str = Field(description="GitHub issue body in markdown")
    labels: list[str] = Field(default_factory=list, description="Labels to apply to the GitHub issue")


@server.agent(name="GitHub Issue Writer")
async def github_issue_writer_agent(
    message: Message,
    context: RunContext,
    llm: Annotated[
        LLMServiceExtensionServer,
        LLMServiceExtensionSpec.single_demand(
            suggested=("openai/gpt-4.1-mini",),
        ),
    ],
):
    """
    RequirementAgent that produces a single GitHub issue payload with a fixed template
    derived from the caller's issue_style selection.
    """
    user_text = get_message_text(message)

    try:
        if not llm or not llm.data:
            raise ValueError("LLM service extension is required but not available")

        llm_config = llm.data.llm_fulfillments.get("default")
        if not llm_config:
            raise ValueError("LLM service extension provided but no fulfillment available")

        llm_client = OpenAIChatModel(
            model_id=llm_config.api_model,
            base_url=llm_config.api_base,
            api_key=llm_config.api_key,
            parameters=ChatModelParameters(temperature=0),
            tool_choice_support={"auto", "required"},
        )

        memory = UnconstrainedMemory()
        await memory.add(UserMessage(user_text))

        templates = RequirementAgentTemplates(
            system=RequirementAgentSystemPrompt.fork(
                lambda model: model.model_copy(update={"template": ISSUE_WRITER_INSTRUCTIONS})
            ),
            task=RequirementAgentTaskPrompt.fork(lambda model: model.model_copy(update={"template": "{{prompt}}"})),
        )

        agent = RequirementAgent(
            llm=llm_client,
            memory=memory,
            tools=[],
            templates=templates,
            final_answer_as_tool=False,
        )

        run_result = await agent.run(user_text, expected_output=IssueDraft)
        structured = run_result.output_structured

        if structured is None:
            raise ValueError("Issue writer failed to produce structured output.")

        yield AgentMessage(text=structured.model_dump_json())
    except Exception as exc:
        yield AgentMessage(text=f"GitHub Issue Writer Agent failed: {exc}")


def main():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
