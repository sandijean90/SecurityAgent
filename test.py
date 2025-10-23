import os

from a2a.types import (
    Message,
)
from beeai_sdk.server import Server
from beeai_sdk.server.context import RunContext
from beeai_sdk.a2a.extensions import AgentDetail, AgentDetailContributor, AgentDetailTool

server = Server()

@server.agent()
async def example_agent(input: Message, context: RunContext):
    """An example agent with detailed configuration"""
    yield "Hello World!"

def run():
    server.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    run()