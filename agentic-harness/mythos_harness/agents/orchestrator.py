"""Opus Orchestrator agent: plans investigations, delegates to specialists."""
from __future__ import annotations

import asyncio
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..agents import analyst, finder, verifier
from ..config import HarnessConfig, TargetConfig
from ..sandbox import manager as sandbox
from ..tools import sandbox_tools


def _parse_xml_tag(text: str, tag: str) -> str | None:
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


@retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_exponential(multiplier=2, min=4, max=120),
    stop=stop_after_attempt(5),
)
def _run_sub_agent(agent: LlmAgent, prompt: str) -> str:
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


def _create_tools(harness_config: HarnessConfig, target: TargetConfig):

    _finder_agent = finder.create(harness_config.models.finder)
    _verifier_agent = verifier.create(harness_config.models.verifier)
    _analyst_agent = analyst.create(harness_config.models.analyst)

    _last_poc_bytes: dict[str, bytes] = {}

    def delegate_find(task: str, focus_area: str = "", known_bugs: str = "") -> str:
        """Delegate a vulnerability research task to the Mythos finder agent.

        Args:
            task: Specific research task (e.g., 'Find buffer overflows in the JPEG parser').
            focus_area: Specific subsystem or files to focus on.
            known_bugs: Previously found bugs to avoid re-finding.
        """
        container_name = f"find_{target.name}"
        sandbox.create(
            target.image_tag,
            name=container_name,
            code_volume=None,
            runtime=harness_config.sandbox_runtime,
            read_only=False,
        )
        sandbox_tools.set_container(container_name)

        try:
            prompt_parts = [task]
            if focus_area:
                prompt_parts.append(f"\nFocus area: {focus_area}")
            if known_bugs:
                prompt_parts.append(f"\nKnown bugs (avoid re-finding):\n{known_bugs}")
            prompt_parts.append(f"\nSource root: {target.source_root}")
            prompt_parts.append(f"\nBinary path: {target.binary_path}")

            result = _run_sub_agent(_finder_agent, "\n".join(prompt_parts))

            poc_path = _parse_xml_tag(result, "poc_path")
            repro_cmd = _parse_xml_tag(result, "reproduction_command")
            crash_type = _parse_xml_tag(result, "crash_type")
            crash_output = _parse_xml_tag(result, "crash_output") or ""

            if not poc_path or not repro_cmd:
                return f"No PoC produced.\n\nAgent output:\n{result[-2000:]}"

            poc_bytes = sandbox.read_file(container_name, poc_path)
            if not poc_bytes:
                return f"PoC path claimed ({poc_path}) but file is empty or missing."

            _last_poc_bytes["data"] = poc_bytes

            finding = {
                "poc_path": poc_path,
                "reproduction_command": repro_cmd,
                "crash_type": crash_type or "unknown",
                "crash_output": crash_output[:5000],
                "poc_size": len(poc_bytes),
            }
            return json.dumps(finding, indent=2)
        finally:
            sandbox.destroy(container_name)

    def delegate_verify(
        poc_path: str,
        reproduction_command: str,
        crash_type: str,
    ) -> str:
        """Verify a vulnerability finding by reproducing the PoC in a fresh sandbox.

        Args:
            poc_path: Original PoC path from the finder.
            reproduction_command: Exact command to reproduce the crash.
            crash_type: Expected ASAN crash type.
        """
        grade_container = f"grade_{target.name}"
        sandbox.create(
            target.image_tag,
            name=grade_container,
            code_volume=None,
            runtime=harness_config.sandbox_runtime,
            read_only=False,
        )
        sandbox_tools.set_container(grade_container)

        try:
            poc_bytes = _last_poc_bytes.get("data")
            if not poc_bytes:
                return json.dumps({"verdict": "FAIL", "error": "No PoC bytes available from finder"})

            if poc_path not in reproduction_command:
                return json.dumps({"verdict": "FAIL", "error": f"poc_path '{poc_path}' not in reproduction_command"})

            sandbox.write_file(grade_container, "/tmp/poc.bin", poc_bytes)
            adapted_cmd = reproduction_command.replace(poc_path, "/tmp/poc.bin")

            prompt = (
                f"Verify this vulnerability in your fresh sandbox.\n\n"
                f"Reproduction command: {adapted_cmd}\n"
                f"Expected crash type: {crash_type}\n"
                f"PoC file is at /tmp/poc.bin ({len(poc_bytes)} bytes)\n"
                f"Source root: {target.source_root}\n\n"
                f"Run the 5-criteria verification checklist."
            )
            result = _run_sub_agent(_verifier_agent, prompt)

            overall = _parse_xml_tag(result, "overall")
            score = _parse_xml_tag(result, "score")
            evidence = _parse_xml_tag(result, "evidence") or ""

            return json.dumps({
                "verdict": overall or "UNKNOWN",
                "score": float(score) if score else 0.0,
                "evidence": evidence[:3000],
                "full_output": result[-2000:],
            }, indent=2)
        finally:
            sandbox.destroy(grade_container)

    def delegate_analyze(
        crash_type: str,
        crash_output: str,
        reproduction_command: str,
        verification_result: str,
    ) -> str:
        """Produce a detailed vulnerability report with root cause analysis.

        Args:
            crash_type: ASAN crash type (e.g., 'heap-buffer-overflow').
            crash_output: ASAN output from the crash.
            reproduction_command: Command that reproduces the crash.
            verification_result: Verification verdict and evidence.
        """
        analyze_container = f"analyze_{target.name}"
        sandbox.create(
            target.image_tag,
            name=analyze_container,
            code_volume=None,
            runtime=harness_config.sandbox_runtime,
        )
        sandbox_tools.set_container(analyze_container)

        try:
            prompt = (
                f"Analyze and document this verified vulnerability.\n\n"
                f"Crash type: {crash_type}\n"
                f"Reproduction command: {reproduction_command}\n"
                f"ASAN output:\n{crash_output}\n\n"
                f"Verification result:\n{verification_result}\n\n"
                f"Source code is at /target/ (read-only). Trace the root cause, "
                f"assess exploitability, assign CVSS, and recommend a fix."
            )
            return _run_sub_agent(_analyst_agent, prompt)
        finally:
            sandbox.destroy(analyze_container)

    def store_report(title: str, content: str, severity: str = "medium") -> str:
        """Store a vulnerability report.

        Args:
            title: Short title for the vulnerability.
            content: Full report content in markdown.
            severity: One of: critical, high, medium, low, info.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{severity}_{title}.md"
        report_dir = f"{harness_config.results_dir}/{target.name}"

        import os
        os.makedirs(report_dir, exist_ok=True)
        path = os.path.join(report_dir, filename)
        with open(path, "w") as f:
            f.write(content)

        return f"Report stored at {path}"

    return [delegate_find, delegate_verify, delegate_analyze, store_report]


ORCHESTRATOR_INSTRUCTION = """\
You are a senior security researcher orchestrating a vulnerability assessment.

You have three specialist agents:
- **delegate_find**: Sends a focused research task to the Mythos finder (runs in isolated sandbox)
- **delegate_verify**: Verifies a finding by reproducing the PoC in a fresh, independent sandbox
- **delegate_analyze**: Produces a detailed report with root cause analysis, CVSS, and remediation

Your workflow for each vulnerability:
1. Plan what area to investigate based on the target
2. Call delegate_find with a specific, focused task
3. If a PoC is found, call delegate_verify with the finding details
4. If verification passes, call delegate_analyze for the full report
5. Store the report with store_report

Strategy:
- Be specific with find tasks: "Find buffer overflows in the TIFF parser" not "find vulnerabilities"
- If a find returns no PoC, try a different focus area or refine the task
- Track known bugs to avoid re-finding the same issues
- After covering the main attack surface areas, produce a final summary

You CANNOT access the sandbox directly. All code analysis goes through your specialists.
"""


def create(harness_config: HarnessConfig, target: TargetConfig) -> LlmAgent:
    tools = _create_tools(harness_config, target)
    return LlmAgent(
        name="opus_orchestrator",
        model=harness_config.models.orchestrator,
        instruction=ORCHESTRATOR_INSTRUCTION,
        tools=tools,
        generate_content_config=types.GenerateContentConfig(temperature=0.1),
    )
