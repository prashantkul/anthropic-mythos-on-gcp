"""CLI entry point for the Mythos harness."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .agents import orchestrator
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

    opus_agent = orchestrator.create(harness_config, target)

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
          f"orchestrator={harness_config.models.orchestrator}")
    print(f"Sandbox runtime: {harness_config.sandbox_runtime}")
    print("-" * 60)

    async for event in runner.run_async(
        new_message=content,
        user_id="researcher",
        session_id="assessment",
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    result_text += part.text

    print("-" * 60)
    print(result_text)
    return result_text


def main():
    parser = argparse.ArgumentParser(description="Mythos Security Harness")
    parser.add_argument("target", help="Path to target directory (must contain config.yaml + Dockerfile)")
    parser.add_argument("--task", default=None, help="Assessment task (default: comprehensive assessment)")
    parser.add_argument("--finder-model", default="claude-mythos@latest")
    parser.add_argument("--orchestrator-model", default="claude-opus@latest")
    parser.add_argument("--runtime", default="kata-fc", choices=["kata-fc", "runsc", "runc"],
                        help="Sandbox runtime (default: kata-fc)")
    parser.add_argument("--results-dir", default="results")

    args = parser.parse_args()

    target = TargetConfig.load(args.target)

    harness_config = HarnessConfig(
        models=ModelConfig(
            orchestrator=args.orchestrator_model,
            finder=args.finder_model,
            verifier=args.orchestrator_model,
            analyst=args.orchestrator_model,
        ),
        sandbox_runtime=args.runtime,
        results_dir=args.results_dir,
    )

    task = args.task or (
        f"Conduct a comprehensive security assessment of the {target.name} target. "
        f"Source code is at {target.source_root}, binary at {target.binary_path}. "
        f"Focus on memory safety vulnerabilities: buffer overflows, use-after-free, "
        f"heap corruption, integer overflows, and format string bugs."
    )
    if target.focus_areas:
        task += f"\n\nSuggested focus areas: {', '.join(target.focus_areas)}"

    asyncio.run(run_assessment(target, task, harness_config))


if __name__ == "__main__":
    main()
