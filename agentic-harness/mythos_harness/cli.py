"""CLI entry point for the Mythos harness."""
from __future__ import annotations

import argparse
import asyncio

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .agents.orchestrator import create as create_orchestrator
from .config import HarnessConfig, ModelConfig, TargetConfig
from .plugins.security_gateway import SecurityGatewayPlugin
from .sandbox import manager as sandbox


async def run_assessment(
    target: TargetConfig,
    task: str,
    harness_config: HarnessConfig,
) -> str:
    if not sandbox.image_exists(target.image_tag):
        print(f"Building image {target.image_tag} from {target.dockerfile_dir}...")
        sandbox.build(target.dockerfile_dir, target.image_tag)

    opus_agent = create_orchestrator(harness_config, target)
    gateway = SecurityGatewayPlugin(max_calls_per_session=2500)

    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="mythos_harness",
        user_id="researcher",
        session_id="assessment",
    )

    runner = Runner(
        agent=opus_agent,
        app_name="mythos_harness",
        session_service=session_service,
        plugins=[gateway],
    )

    content = types.Content(role="user", parts=[types.Part(text=task)])
    result_text = ""

    print(f"Starting assessment of {target.name}...")
    print(f"Models: finder={harness_config.models.finder}, "
          f"orchestrator={harness_config.models.orchestrator}, "
          f"analyst={harness_config.models.analyst}")
    print(f"Sandbox runtime: {harness_config.sandbox_runtime}")
    print(f"Sub-agents: mythos_finder, verifier, analyst (ADK native delegation)")
    print("-" * 60)

    async for event in runner.run_async(
        new_message=content,
        user_id="researcher",
        session_id="assessment",
    ):
        # Show agent transfers and tool calls
        author = getattr(event, 'author', None)
        actions = getattr(event, 'actions', None)
        if actions:
            transfer = getattr(actions, 'transfer_to_agent', None)
            if transfer:
                print(f"\n>>> TRANSFER TO: {transfer}")

        if event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    fc = part.function_call
                    args_str = str(dict(fc.args))[:200] if fc.args else ""
                    print(f"\n  [{author}] TOOL: {fc.name}({args_str})")
                elif hasattr(part, 'function_response') and part.function_response:
                    fr = part.function_response
                    resp_str = str(fr.response)[:200] if fr.response else ""
                    print(f"  [{author}] RESULT: {resp_str}")
                elif part.text:
                    # Show first 150 chars of text per event
                    preview = part.text.strip().replace('\n', ' ')[:150]
                    if preview:
                        print(f"  [{author}] {preview}")
                    result_text += part.text

    print("-" * 60)
    print(result_text)
    return result_text


def main():
    parser = argparse.ArgumentParser(description="Mythos Security Harness")
    parser.add_argument("target", help="Path to target directory (must contain config.yaml + Dockerfile)")
    parser.add_argument("--task", default=None, help="Assessment task (default: comprehensive assessment)")
    parser.add_argument("--finder-model", default=None)
    parser.add_argument("--orchestrator-model", default=None)
    parser.add_argument("--analyst-model", default=None)
    parser.add_argument("--runtime", default=None, choices=["kata-fc", "runsc", "runc"])
    parser.add_argument("--results-dir", default="results")

    args = parser.parse_args()
    target = TargetConfig.load(args.target)

    models = ModelConfig()
    if args.finder_model or args.orchestrator_model or args.analyst_model:
        models = ModelConfig(
            orchestrator=args.orchestrator_model or models.orchestrator,
            finder=args.finder_model or models.finder,
            verifier=args.orchestrator_model or models.verifier,
            analyst=args.analyst_model or models.analyst,
        )

    harness_config = HarnessConfig(models=models, results_dir=args.results_dir)
    if args.runtime:
        harness_config.sandbox_runtime = args.runtime

    task = args.task or (
        f"Conduct a security assessment of the {target.name} target. "
        f"Source code is at {target.source_root}, binary at {target.binary_path}. "
        f"Focus on memory safety vulnerabilities."
    )
    if target.focus_areas:
        task += f"\n\nSuggested focus areas: {', '.join(target.focus_areas)}"

    asyncio.run(run_assessment(target, task, harness_config))


if __name__ == "__main__":
    main()
