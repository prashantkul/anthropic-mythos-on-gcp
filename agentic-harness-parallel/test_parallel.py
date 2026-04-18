"""Quick test: does ParallelAgent + SequentialAgent work with Claude on Vertex AI?"""
import asyncio
import os

from dotenv import load_dotenv
load_dotenv()

from google.adk.agents import Agent, ParallelAgent, SequentialAgent
from google.adk.models.anthropic_llm import Claude
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


def make_agent(name: str, task: str) -> Agent:
    return Agent(
        name=name,
        model=Claude(model="claude-sonnet-4-6"),
        description=f"Agent that {task}",
        instruction=f"You are a test agent. {task}. Reply in ONE sentence.",
        output_key=f"{name}_output",
    )


async def main():
    # Three agents that will run in parallel
    agent_a = make_agent("agent_a", "Name a random color")
    agent_b = make_agent("agent_b", "Name a random animal")
    agent_c = make_agent("agent_c", "Name a random country")

    parallel = ParallelAgent(
        name="parallel_test",
        description="Runs three agents in parallel",
        sub_agents=[agent_a, agent_b, agent_c],
    )

    # Wrap in sequential: parallel first, then summary
    summary = Agent(
        name="summary",
        model=Claude(model="claude-sonnet-4-6"),
        description="Summarizes parallel results",
        instruction="Combine the outputs from agent_a, agent_b, and agent_c into one sentence.",
        output_key="summary_output",
    )

    workflow = SequentialAgent(
        name="workflow",
        description="Parallel then summary",
        sub_agents=[parallel, summary],
    )

    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="test", user_id="test", session_id="test"
    )

    runner = Runner(
        agent=workflow, app_name="test", session_service=session_service
    )

    content = types.Content(role="user", parts=[types.Part(text="Go")])

    print("Running ParallelAgent + SequentialAgent with Claude...")
    print("-" * 40)

    async for event in runner.run_async(
        new_message=content, user_id="test", session_id="test"
    ):
        author = getattr(event, 'author', 'unknown')
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    print(f"  [{author}] {part.text.strip()[:100]}")

    print("-" * 40)
    print("SUCCESS: ParallelAgent works with Claude")


if __name__ == "__main__":
    asyncio.run(main())
