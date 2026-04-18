"""Opus Orchestrator: tool-based delegation to sub-agents.

Sub-agents run inside tool functions via fresh Runner (matching the
ai-security-agent sample pattern). This works with Claude on Vertex AI,
unlike the sub_agents/transfer_to_agent pattern which requires Gemini.
"""
from __future__ import annotations

import asyncio
import base64
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..agents import analyst, finder, verifier
from ..config import HarnessConfig, TargetConfig
from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import set_container


@retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_exponential(multiplier=2, min=4, max=120),
    stop=stop_after_attempt(5),
)
def _run_sub_agent(agent: Agent, prompt: str) -> str:
    """Run a sub-agent in a fresh Runner in a separate thread.

    Matches the ai-security-agent execute_sub_agent pattern:
    fresh session per call, ThreadPoolExecutor for isolation.
    """
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
        async for event in runner.run_async(
            new_message=content, user_id="harness", session_id="sub_session"
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        result_text += part.text
        return result_text

    with ThreadPoolExecutor() as executor:
        future = executor.submit(asyncio.run, _run())
        return future.result()


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

- Be specific with finder tasks — one focus area per call
- If finder returns no crash, try a different area
- Always verify before analyzing
- Track what you've investigated to avoid redundancy
"""


def _create_tools(harness_config: HarnessConfig, target: TargetConfig):
    _finder_agent = finder.create(harness_config.models.finder)
    _verifier_agent = verifier.create(harness_config.models.verifier)
    _analyst_agent = analyst.create(harness_config.models.analyst)

    _poc_bytes_store: dict[str, bytes] = {}

    def run_finder(task: str) -> str:
        """Run the vulnerability finder agent in an isolated sandbox.

        Args:
            task: Focused research task (e.g., 'Find buffer overflows in input parsing').
        """
        container_name = f"find_{target.name}"
        print(f"\n  [harness] Creating finder sandbox: {container_name}")
        sandbox.create(
            target.image_tag,
            name=container_name,
            runtime=harness_config.sandbox_runtime,
            read_only=False,
        )
        set_container(container_name)

        try:
            prompt = (
                f"{task}\n\n"
                f"Source root: {target.source_root}\n"
                f"Binary path: {target.binary_path}\n"
            )
            print(f"  [harness] Running finder agent...")
            result = _run_sub_agent(_finder_agent, prompt)

            poc_bytes = sandbox.read_file(container_name, "/tmp/poc.bin")
            if poc_bytes:
                _poc_bytes_store["data"] = poc_bytes
                print(f"  [harness] PoC extracted: {len(poc_bytes)} bytes")
            else:
                print(f"  [harness] No PoC at /tmp/poc.bin")

            return result
        finally:
            sandbox.destroy(container_name)
            print(f"  [harness] Finder sandbox destroyed")

    def run_verifier(reproduction_command: str, crash_type: str) -> str:
        """Verify a crash by reproducing the PoC in a fresh sandbox.

        Args:
            reproduction_command: Exact command to reproduce the crash.
            crash_type: Expected ASAN crash type (e.g., 'heap-buffer-overflow').
        """
        poc_bytes = _poc_bytes_store.get("data")
        if not poc_bytes:
            return "ERROR: No PoC bytes available. Run the finder first."

        container_name = f"grade_{target.name}"
        print(f"\n  [harness] Creating verifier sandbox: {container_name}")
        sandbox.create(
            target.image_tag,
            name=container_name,
            runtime=harness_config.sandbox_runtime,
            read_only=False,
        )
        sandbox.write_file(container_name, "/tmp/poc.bin", poc_bytes)
        set_container(container_name)

        try:
            adapted_cmd = reproduction_command
            prompt = (
                f"Verify this crash in your fresh sandbox.\n\n"
                f"PoC file: /tmp/poc.bin ({len(poc_bytes)} bytes)\n"
                f"Reproduction command: {adapted_cmd}\n"
                f"Expected crash type: {crash_type}\n"
            )
            print(f"  [harness] Running verifier agent...")
            return _run_sub_agent(_verifier_agent, prompt)
        finally:
            sandbox.destroy(container_name)
            print(f"  [harness] Verifier sandbox destroyed")

    def run_analyst(crash_type: str, crash_output: str,
                    reproduction_command: str, verification: str) -> str:
        """Produce a structured exploitability report for a verified crash.

        Args:
            crash_type: ASAN crash type (e.g., 'heap-buffer-overflow').
            crash_output: ASAN output from the crash.
            reproduction_command: Command that reproduces the crash.
            verification: Verification verdict and evidence.
        """
        container_name = f"analyze_{target.name}"
        print(f"\n  [harness] Creating analyst sandbox: {container_name}")
        sandbox.create(
            target.image_tag,
            name=container_name,
            runtime=harness_config.sandbox_runtime,
            read_only=True,
        )
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
            print(f"  [harness] Running analyst agent...")
            return _run_sub_agent(_analyst_agent, prompt)
        finally:
            sandbox.destroy(container_name)
            print(f"  [harness] Analyst sandbox destroyed")

    def store_report(title: str, content: str, severity: str = "medium") -> str:
        """Store a vulnerability report.

        Args:
            title: Short title for the vulnerability.
            content: Full report content in markdown.
            severity: One of: critical, high, medium, low, info.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{severity}_{title}.md"
        report_dir = os.path.join(harness_config.results_dir, target.name)
        os.makedirs(report_dir, exist_ok=True)
        path = os.path.join(report_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        print(f"\n  [harness] Report stored: {path}")
        return f"Report stored at {path}"

    return [run_finder, run_verifier, run_analyst, store_report]


def create(harness_config: HarnessConfig, target: TargetConfig) -> Agent:
    tools = _create_tools(harness_config, target)
    return Agent(
        name="opus_orchestrator",
        model=Claude(model=harness_config.models.orchestrator),
        description="Root orchestrator for vulnerability assessment",
        instruction=ORCHESTRATOR_INSTRUCTION,
        tools=tools,
    )
