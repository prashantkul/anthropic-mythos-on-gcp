"""Opus Orchestrator: tool-based delegation to sub-agents.

Sub-agents run inside tool functions via fresh Runner (matching the
ai-security-agent sample pattern). This works with Claude on Vertex AI,
unlike the sub_agents/transfer_to_agent pattern which requires Gemini.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from rich.console import Console
from rich.panel import Panel
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..agents import analyst, finder, verifier
from ..config import HarnessConfig, TargetConfig
from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import set_container

console = Console()


_sub_agent_tokens: dict[str, dict[str, int]] = {}


@retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_exponential(multiplier=2, min=4, max=120),
    stop=stop_after_attempt(5),
)
def _run_sub_agent(agent: Agent, prompt: str) -> str:
    agent_name = agent.name

    async def _run():
        session_service = InMemorySessionService()
        await session_service.create_session(
            app_name="mythos", user_id="harness", session_id="sub_session"
        )
        runner = Runner(
            agent=agent, app_name="mythos", session_service=session_service
        )
        content = types.Content(role="user", parts=[types.Part(text=prompt)])
        result_text = ""
        input_tokens = 0
        output_tokens = 0
        tool_calls = 0

        async for event in runner.run_async(
            new_message=content, user_id="harness", session_id="sub_session"
        ):
            usage = getattr(event, 'usage_metadata', None)
            if usage:
                input_tokens += getattr(usage, 'prompt_token_count', 0) or 0
                output_tokens += getattr(usage, 'candidates_token_count', 0) or 0

            if event.content and event.content.parts:
                for part in event.content.parts:
                    if hasattr(part, 'function_call') and part.function_call:
                        tool_calls += 1
                    elif part.text:
                        result_text += part.text

        if agent_name not in _sub_agent_tokens:
            _sub_agent_tokens[agent_name] = {"input": 0, "output": 0, "tool_calls": 0}
        _sub_agent_tokens[agent_name]["input"] += input_tokens
        _sub_agent_tokens[agent_name]["output"] += output_tokens
        _sub_agent_tokens[agent_name]["tool_calls"] += tool_calls

        console.print(
            f"  [dim]{agent_name}: {input_tokens:,} in / {output_tokens:,} out / "
            f"{tool_calls} tool calls[/dim]"
        )
        return result_text

    with ThreadPoolExecutor() as executor:
        future = executor.submit(asyncio.run, _run())
        return future.result()


def get_sub_agent_tokens() -> dict[str, dict[str, int]]:
    return _sub_agent_tokens


ORCHESTRATOR_INSTRUCTION = """\
You are an orchestrator coordinating vulnerability research via specialist tools.

## Tools

- **run_finder(task)**: Sends a research task to the Mythos finder agent, which
  runs in an isolated sandbox with source code and an ASAN binary. Returns crash
  details or "no crash found".
- **run_verifier(reproduction_command, crash_type)**: Verifies a crash in a fresh
  sandbox. Returns a 5-criteria verdict (PASS/FAIL).
- **run_analyst(crash_type, crash_output, reproduction_command, verification)**:
  Produces a structured exploitability report. Returns the report markdown.
- **store_report(title, content, severity)**: Saves a report to disk.

## Workflow

1. Call run_finder with a focused task (e.g., "Find buffer overflows in input parsing")
2. If finder reports a crash, call run_verifier with the reproduction details
3. If verifier passes, call run_analyst with all crash details
4. Store the report with store_report
5. Repeat with a different focus area

## Rules

- IMPORTANT: Call ONE tool at a time. Wait for the result before calling the next.
  Do NOT call multiple tools in parallel.
- Be specific with finder tasks — one focus area per call
- If finder returns a crash, IMMEDIATELY call run_verifier before investigating
  the next area
- If verifier passes, IMMEDIATELY call run_analyst
- After the analyst returns, you MUST call store_report with the analyst's output
- After storing the report, move to the next focus area
- Track what you've investigated to avoid redundancy
- Do NOT end without calling store_report for every verified finding
"""


def _create_tools(harness_config: HarnessConfig, target: TargetConfig, run_dir: str):
    _finder_agent = finder.create(harness_config.models.finder)
    _verifier_agent = verifier.create(harness_config.models.verifier)
    _analyst_agent = analyst.create(harness_config.models.analyst)

    _poc_bytes_store: dict[str, bytes] = {}

    def run_finder(task: str) -> str:
        """Run the vulnerability finder agent in an isolated sandbox.

        Args:
            task: Focused research task (e.g., 'Find buffer overflows in input parsing').
        """
        run_id = uuid.uuid4().hex[:8]
        container_name = f"find_{target.name}_{run_id}"

        name, docker_cmd = sandbox.create(
            target.image_tag,
            name=container_name,
            runtime=harness_config.sandbox_runtime,
            read_only=False,
        )
        console.print(Panel(
            f"[bold]Container:[/bold] {name}\n"
            f"[bold]Verify:[/bold] docker exec {name} ls /target/\n"
            f"[bold]Shell:[/bold] docker exec -it {name} bash\n"
            f"[dim]{docker_cmd}[/dim]",
            title="[green]Finder Sandbox Created[/green]",
            border_style="green",
        ))
        set_container(container_name)

        try:
            prompt = (
                f"{task}\n\n"
                f"Source root: {target.source_root}\n"
                f"Binary path: {target.binary_path}\n"
            )
            console.print("[cyan]  Running finder agent...[/cyan]")
            result = _run_sub_agent(_finder_agent, prompt)

            poc_bytes = sandbox.read_file(container_name, "/tmp/poc.bin")
            if poc_bytes:
                _poc_bytes_store["data"] = poc_bytes
                console.print(f"[green]  PoC extracted: {len(poc_bytes)} bytes[/green]")
            else:
                console.print("[yellow]  No PoC at /tmp/poc.bin[/yellow]")

            return result
        finally:
            sandbox.destroy(container_name)
            console.print(f"[dim]  Sandbox {container_name} destroyed[/dim]")

    def run_verifier(reproduction_command: str, crash_type: str) -> str:
        """Verify a crash by reproducing the PoC in a fresh sandbox.

        Args:
            reproduction_command: Exact command to reproduce the crash.
            crash_type: Expected ASAN crash type (e.g., 'heap-buffer-overflow').
        """
        poc_bytes = _poc_bytes_store.get("data")
        if not poc_bytes:
            return "ERROR: No PoC bytes available. Run the finder first."

        run_id = uuid.uuid4().hex[:8]
        container_name = f"grade_{target.name}_{run_id}"

        name, docker_cmd = sandbox.create(
            target.image_tag,
            name=container_name,
            runtime=harness_config.sandbox_runtime,
            read_only=False,
        )
        sandbox.write_file(container_name, "/tmp/poc.bin", poc_bytes)
        console.print(Panel(
            f"[bold]Container:[/bold] {name}\n"
            f"[bold]PoC:[/bold] {len(poc_bytes)} bytes copied to /tmp/poc.bin\n"
            f"[bold]Verify:[/bold] docker exec {name} xxd /tmp/poc.bin\n"
            f"[dim]{docker_cmd}[/dim]",
            title="[yellow]Verifier Sandbox Created[/yellow]",
            border_style="yellow",
        ))
        set_container(container_name)

        try:
            binary_cmd = f"{target.binary_path} /tmp/poc.bin"
            prompt = (
                f"Verify this crash in your fresh sandbox.\n\n"
                f"PoC file: /tmp/poc.bin ({len(poc_bytes)} bytes) — ALREADY present, do NOT recreate it.\n"
                f"Run this command: {binary_cmd}\n"
                f"Expected crash type: {crash_type}\n"
                f"Run it 3 times and check all 5 criteria.\n"
            )
            console.print("[cyan]  Running verifier agent...[/cyan]")
            return _run_sub_agent(_verifier_agent, prompt)
        finally:
            sandbox.destroy(container_name)
            console.print(f"[dim]  Sandbox {container_name} destroyed[/dim]")

    def run_analyst(crash_type: str, crash_output: str,
                    reproduction_command: str, verification: str) -> str:
        """Produce a structured exploitability report and auto-store it.

        Args:
            crash_type: ASAN crash type (e.g., 'heap-buffer-overflow').
            crash_output: ASAN output from the crash.
            reproduction_command: Command that reproduces the crash.
            verification: Verification verdict and evidence.
        """
        run_id = uuid.uuid4().hex[:8]
        container_name = f"analyze_{target.name}_{run_id}"

        name, docker_cmd = sandbox.create(
            target.image_tag,
            name=container_name,
            runtime=harness_config.sandbox_runtime,
            read_only=True,
        )
        console.print(Panel(
            f"[bold]Container:[/bold] {name} [dim](read-only)[/dim]\n"
            f"[bold]Verify:[/bold] docker exec {name} ls /target/src/\n"
            f"[dim]{docker_cmd}[/dim]",
            title="[blue]Analyst Sandbox Created[/blue]",
            border_style="blue",
        ))
        set_container(container_name)

        try:
            prompt = (
                f"Analyze this verified vulnerability.\n\n"
                f"Crash type: {crash_type}\n"
                f"Reproduction command: {reproduction_command}\n"
                f"ASAN output:\n{crash_output[:4000]}\n\n"
                f"Verification:\n{verification[:2000]}\n\n"
                f"Source code is at /target/ (read-only)."
            )
            console.print("[cyan]  Running analyst agent...[/cyan]")
            report = _run_sub_agent(_analyst_agent, prompt)

            safe_type = "".join(c if c.isalnum() or c in "-_ " else "_" for c in crash_type)
            filename = f"{safe_type}_{run_id}.md"
            path = os.path.join(run_dir, filename)
            with open(path, "w") as f:
                f.write(report)

            severity_guess = "critical" if "WRITE" in crash_type.upper() else "high"
            console.print(Panel(
                f"[bold]{crash_type}[/bold]\n{path}",
                title=f"[red]Report Auto-Stored ({severity_guess.upper()})[/red]",
                border_style="red",
            ))
            return f"Report stored at {path}. Summary:\n{report[:500]}"
        finally:
            sandbox.destroy(container_name)
            console.print(f"[dim]  Sandbox {container_name} destroyed[/dim]")

    def store_report(title: str, content: str, severity: str = "medium") -> str:
        """Store a vulnerability report.

        Args:
            title: Short title for the vulnerability.
            content: Full report content in markdown.
            severity: One of: critical, high, medium, low, info.
        """
        safe_title = "".join(c if c.isalnum() or c in "-_ " else "_" for c in title)
        filename = f"{severity}_{safe_title}.md"
        path = os.path.join(run_dir, filename)
        with open(path, "w") as f:
            f.write(content)

        severity_colors = {
            "critical": "red bold", "high": "red", "medium": "yellow",
            "low": "green", "info": "blue",
        }
        style = severity_colors.get(severity, "white")
        console.print(Panel(
            f"[bold]{title}[/bold]\n{path}",
            title=f"[{style}]Report Stored ({severity.upper()})[/{style}]",
            border_style=style,
        ))
        return f"Report stored at {path}"

    return [run_finder, run_verifier, run_analyst, store_report]


def create(harness_config: HarnessConfig, target: TargetConfig, run_dir: str) -> Agent:
    tools = _create_tools(harness_config, target, run_dir)
    return Agent(
        name="opus_orchestrator",
        model=Claude(model=harness_config.models.orchestrator),
        description="Root orchestrator for vulnerability assessment",
        instruction=ORCHESTRATOR_INSTRUCTION,
        tools=tools,
    )
