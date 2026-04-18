"""CLI entry point for the Mythos harness."""
from __future__ import annotations

import argparse
import asyncio

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .agents.orchestrator import create as create_orchestrator, get_token_counts
from .agents.orchestrator import C_RESET, C_GREEN, C_YELLOW, C_BLUE, C_CYAN, C_RED, C_DIM, C_BOLD
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
    orch_input_tokens = 0
    orch_output_tokens = 0

    print(f"\n{C_BOLD}Mythos Security Harness{C_RESET}")
    print(f"  Target:       {C_BOLD}{target.name}{C_RESET}")
    print(f"  Finder:       {harness_config.models.finder}")
    print(f"  Orchestrator: {harness_config.models.orchestrator}")
    print(f"  Analyst:      {harness_config.models.analyst}")
    print(f"  Runtime:      {harness_config.sandbox_runtime}")
    print("-" * 60)

    async for event in runner.run_async(
        new_message=content,
        user_id="researcher",
        session_id="assessment",
    ):
        author = getattr(event, 'author', None) or "unknown"

        usage = getattr(event, 'usage_metadata', None)
        if usage:
            orch_input_tokens += getattr(usage, 'prompt_token_count', 0) or 0
            orch_output_tokens += getattr(usage, 'candidates_token_count', 0) or 0

        if event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    fc = part.function_call
                    args_str = str(dict(fc.args))[:200] if fc.args else ""
                    print(f"\n  {C_CYAN}[{author}]{C_RESET} TOOL: {fc.name}({args_str})")
                elif hasattr(part, 'function_response') and part.function_response:
                    fr = part.function_response
                    resp_str = str(fr.response)[:150] if fr.response else ""
                    print(f"  {C_CYAN}[{author}]{C_RESET} {C_DIM}RESULT: {resp_str}{C_RESET}")
                elif part.text:
                    preview = part.text.strip().replace('\n', ' ')[:150]
                    if preview:
                        print(f"  {C_CYAN}[{author}]{C_RESET} {preview}")
                    result_text += part.text

    # Token summary
    print("\n" + "-" * 60)
    print(f"{C_BOLD}Token Usage{C_RESET}")
    all_tokens = {"opus_orchestrator": {"input": orch_input_tokens, "output": orch_output_tokens}}
    all_tokens.update(get_token_counts())
    total_in = 0
    total_out = 0
    for name, counts in sorted(all_tokens.items()):
        inp, out = counts["input"], counts["output"]
        total_in += inp
        total_out += out
        print(f"  {name:25s}  {inp:>8,} in  {out:>8,} out  {inp+out:>8,} total")
    print(f"  {C_BOLD}{'TOTAL':25s}  {total_in:>8,} in  {total_out:>8,} out  {total_in+total_out:>8,} total{C_RESET}")
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
