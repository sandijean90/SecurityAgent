import os

from dotenv import load_dotenv

from agentstack_sdk.server import Server
from agentstack_sdk.server.context import RunContext
from agentstack_sdk.a2a.types import AgentMessage
from a2a.types import Message
from a2a.utils.message import get_message_text

from beeai_framework.adapters.openai import OpenAIChatModel
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.backend import ChatModel, ChatModelParameters
from beeai_framework.backend.message import UserMessage
from beeai_framework.memory import UnconstrainedMemory
from beeai_framework.middleware.trajectory import GlobalTrajectoryMiddleware
from beeai_framework.tools import Tool
from beeai_framework.tools.think import ThinkTool


load_dotenv()

server = Server()


def build_llm() -> ChatModel:
    """Create an OpenAI-backed chat model using environment configuration."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set in the environment.")

    api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    model_id = os.getenv("OPENAI_CHAT_MODEL", "openai/gpt-4.1-mini")

    return OpenAIChatModel(
        base_url=api_base,
        api_key=api_key,
        model=model_id,
        parameters=ChatModelParameters(temperature=0),
        tool_choice_support={"auto", "required"},
    )


@server.agent(name="Simple Requirement Agent")
async def simple_requirement_agent(message: Message, context: RunContext):
    """Minimal agent that only exercises the ThinkTool with gpt-5-mini."""
    user_text = get_message_text(message)

    try:
        llm_client = build_llm()
        memory = UnconstrainedMemory()
        await memory.add(UserMessage(user_text))

        agent = RequirementAgent(
            llm=llm_client,
            memory=memory,
            tools=[ThinkTool()],
            instructions=(
                "You are a diagnostic agent. Answer briefly after thinking through the task "
                "with the Think tool."
            ),
        )

        run_result = await agent.run(user_text).middleware(
            GlobalTrajectoryMiddleware(included=[Tool])
        )
        yield AgentMessage(text=run_result.output_structured.response)
    except Exception as exc:
        yield AgentMessage(text=f"Simple Requirement Agent failed: {exc}")


def main():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
