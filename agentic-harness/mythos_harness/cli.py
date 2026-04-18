"""CLI entry point for the Mythos harness."""
from __future__ import annotations

import argparse
import asyncio
import os
from datetime import datetime, timezone

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .agents.orchestrator import create as create_orchestrator, get_sub_agent_tokens
from .config import HarnessConfig, ModelConfig, TargetConfig
from .plugins.security_gateway import SecurityGatewayPlugin
from .sandbox import manager as sandbox

console = Console()


async def run_assessment(
    target: TargetConfig,
    task: str,
    harness_config: HarnessConfig,
) -> str:
    if not sandbox.image_exists(target.image_tag):
        console.print(f"[yellow]Building image {target.image_tag}...[/yellow]")
        sandbox.build(target.dockerfile_dir, target.image_tag)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(harness_config.results_dir, target.name, ts)
    os.makedirs(run_dir, exist_ok=True)

    opus_agent = create_orchestrator(harness_config, target, run_dir)
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

    # Header
    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column(style="bold")
    info.add_column()
    info.add_row("Target", target.name)
    info.add_row("Finder", harness_config.models.finder)
    info.add_row("Orchestrator", harness_config.models.orchestrator)
    info.add_row("Analyst", harness_config.models.analyst)
    info.add_row("Runtime", harness_config.sandbox_runtime)
    info.add_row("Results", run_dir)
    console.print(Panel(info, title="[bold]Mythos Security Harness[/bold]", border_style="cyan"))

    content = types.Content(role="user", parts=[types.Part(text=task)])
    result_text = ""
    total_input_tokens = 0
    total_output_tokens = 0
    agent_tokens: dict[str, dict[str, int]] = {}

    async for event in runner.run_async(
        new_message=content,
        user_id="researcher",
        session_id="assessment",
    ):
        author = getattr(event, 'author', None) or "unknown"

        # Track tokens
        usage = getattr(event, 'usage_metadata', None)
        if usage:
            inp = getattr(usage, 'prompt_token_count', 0) or 0
            out = getattr(usage, 'candidates_token_count', 0) or 0
            total_input_tokens += inp
            total_output_tokens += out
            if author not in agent_tokens:
                agent_tokens[author] = {"input": 0, "output": 0}
            agent_tokens[author]["input"] += inp
            agent_tokens[author]["output"] += out

        # Show events
        if event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    fc = part.function_call
                    args_str = str(dict(fc.args))[:200] if fc.args else ""
                    console.print(f"  [bold cyan][{author}][/bold cyan] [magenta]TOOL:[/magenta] {fc.name}({args_str})")
                elif hasattr(part, 'function_response') and part.function_response:
                    fr = part.function_response
                    resp_str = str(fr.response)[:150] if fr.response else ""
                    console.print(f"  [bold cyan][{author}][/bold cyan] [dim]RESULT: {resp_str}[/dim]")
                elif part.text:
                    preview = part.text.strip().replace('\n', ' ')[:150]
                    if preview:
                        console.print(f"  [bold cyan][{author}][/bold cyan] {preview}")
                    result_text += part.text

    console.print(f"\n[dim]Session ended. Total events processed.[/dim]")

    # Merge sub-agent tokens
    for agent_name, counts in get_sub_agent_tokens().items():
        agent_tokens[agent_name] = {
            "input": counts["input"],
            "output": counts["output"],
        }
        total_input_tokens += counts["input"]
        total_output_tokens += counts["output"]

    # Summary
    console.print()
    token_table = Table(title="Token Usage", border_style="cyan")
    token_table.add_column("Agent", style="bold")
    token_table.add_column("Input", justify="right")
    token_table.add_column("Output", justify="right")
    token_table.add_column("Total", justify="right", style="bold")

    for agent_name, counts in sorted(agent_tokens.items()):
        token_table.add_row(
            agent_name,
            f"{counts['input']:,}",
            f"{counts['output']:,}",
            f"{counts['input'] + counts['output']:,}",
        )
    token_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_input_tokens:,}[/bold]",
        f"[bold]{total_output_tokens:,}[/bold]",
        f"[bold]{total_input_tokens + total_output_tokens:,}[/bold]",
    )
    console.print(token_table)

    reports = [f for f in os.listdir(run_dir) if f.endswith('.md')]
    if reports:
        console.print(Panel(
            "\n".join(f"  {r}" for r in sorted(reports)),
            title=f"[green]Reports ({len(reports)})[/green]",
            border_style="green",
        ))

    console.print(f"\n[bold]Results directory:[/bold] {run_dir}")
    return result_text


def main():
    parser = argparse.ArgumentParser(description="Mythos Security Harness")
    parser.add_argument("target", help="Path to target directory (config.yaml + Dockerfile)")
    parser.add_argument("--task", default=None)
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
