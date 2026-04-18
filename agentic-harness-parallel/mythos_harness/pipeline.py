"""Dynamic parallel pipeline.

Phase 1: Planner identifies focus areas (or from config)
Phase 2: ParallelAgent runs finders simultaneously
Phase 3: Sequential per finding: verify → analyze
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from google.adk.agents import Agent, ParallelAgent
from google.adk.models.anthropic_llm import Claude
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

import re

from .agents import analyst, finder, planner, verifier
from .config import HarnessConfig, TargetConfig
from .plugins.security_gateway import SecurityGatewayPlugin
from .sandbox import manager as sandbox

C_RESET = "\033[0m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"
C_RED = "\033[31m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_ITALIC = "\033[3m"
C_MAGENTA = "\033[35m"

# Token tracking
_token_counts: dict[str, dict[str, int]] = {}


def _track_tokens(event, agent_name: str = None):
    """Extract and accumulate token counts from an event."""
    usage = getattr(event, 'usage_metadata', None)
    if not usage:
        return
    author = agent_name or getattr(event, 'author', 'unknown')
    inp = getattr(usage, 'prompt_token_count', 0) or 0
    out = getattr(usage, 'candidates_token_count', 0) or 0
    if author not in _token_counts:
        _token_counts[author] = {"input": 0, "output": 0}
    _token_counts[author]["input"] += inp
    _token_counts[author]["output"] += out


def print_token_summary():
    """Print token usage table."""
    if not _token_counts:
        return
    print(f"\n{C_BOLD}Token Usage{C_RESET}")
    total_in = 0
    total_out = 0
    for name, counts in sorted(_token_counts.items()):
        inp, out = counts["input"], counts["output"]
        total_in += inp
        total_out += out
        print(f"  {name:35s}  {inp:>8,} in  {out:>8,} out  {inp+out:>8,} total")
    print(f"  {C_BOLD}{'TOTAL':35s}  {total_in:>8,} in  {total_out:>8,} out  {total_in+total_out:>8,} total{C_RESET}")


async def _run_single_agent(
    agent: Agent, prompt: str, plugins: list | None = None, verbose: bool = False,
) -> str:
    """Run a single agent and collect its text output."""
    session_service = InMemorySessionService()
    sid = f"session_{agent.name}"
    await session_service.create_session(
        app_name="mythos_parallel", user_id="harness", session_id=sid
    )
    runner = Runner(
        agent=agent, app_name="mythos_parallel",
        session_service=session_service, plugins=plugins or [],
    )
    content = types.Content(role="user", parts=[types.Part(text=prompt)])
    result_text = ""
    async for event in runner.run_async(
        new_message=content, user_id="harness", session_id=sid
    ):
        _track_tokens(event, agent.name)
        if event.content and event.content.parts:
            for part in event.content.parts:
                if verbose:
                    if hasattr(part, 'function_call') and part.function_call:
                        fc = part.function_call
                        args_str = str(dict(fc.args))[:150] if fc.args else ""
                        print(f"    {C_GREEN}TOOL:{C_RESET} {fc.name}({args_str})")
                    elif part.text:
                        for line in part.text.strip().split("\n")[:5]:
                            print(f"    {C_MAGENTA}{C_ITALIC}{line[:120]}{C_RESET}")
                if part.text:
                    result_text += part.text
    return result_text


async def _run_workflow(workflow_agent, prompt: str, plugins: list | None = None) -> dict:
    """Run a workflow agent and collect outputs keyed by author."""
    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="mythos_parallel", user_id="harness", session_id="workflow"
    )
    runner = Runner(
        agent=workflow_agent, app_name="mythos_parallel",
        session_service=session_service, plugins=plugins or [],
    )
    content = types.Content(role="user", parts=[types.Part(text=prompt)])
    results = {}
    async for event in runner.run_async(
        new_message=content, user_id="harness", session_id="workflow"
    ):
        _track_tokens(event)
        author = getattr(event, 'author', 'unknown')
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    preview = part.text.strip()[:100]
                    print(f"  {C_CYAN}[{author}]{C_RESET} {preview}")
                    if author not in results:
                        results[author] = ""
                    results[author] += part.text
    return results


def _parse_focus_areas(planner_output: str) -> list[str]:
    """Extract focus areas from planner output."""
    m = re.search(r"<focus_areas>(.*?)</focus_areas>", planner_output, re.DOTALL)
    if m:
        lines = m.group(1).strip().split("\n")
    else:
        lines = planner_output.strip().split("\n")

    areas = []
    for line in lines:
        line = re.sub(r"^\d+[\.\)]\s*", "", line.strip())
        if line and len(line) > 5:
            areas.append(line)
    return areas[:6]


async def run_parallel_assessment(
    target: TargetConfig,
    focus_areas: list[str] | None,
    harness_config: HarnessConfig,
    run_dir: str,
):
    if not sandbox.image_exists(target.image_tag):
        print(f"{C_YELLOW}Building image {target.image_tag}...{C_RESET}")
        sandbox.build(target.dockerfile_dir, target.image_tag)

    gateway = SecurityGatewayPlugin()

    # ── Phase 1: Planner explores source, determines focus areas ──
    if not focus_areas:
        print(f"\n{C_BOLD}Phase 1: Planning — exploring source code{C_RESET}")
        pc = f"plan_{target.name}"
        sandbox.create(target.image_tag, name=pc, runtime=harness_config.sandbox_runtime, read_only=True)
        print(f"  {C_CYAN}[planner]{C_RESET} Sandbox: {pc}")

        planner_agent = planner.create(
            model=harness_config.models.orchestrator,
            container_name=pc,
            binary_path=target.binary_path,
        )

        print(f"  {C_CYAN}[planner]{C_RESET} Analyzing codebase...\n")
        planner_output = await _run_single_agent(
            planner_agent,
            f"Explore {target.source_root} and identify focus areas for vulnerability research.",
            plugins=[gateway],
            verbose=True,
        )

        sandbox.destroy(pc)
        print(f"\n  {C_DIM}[planner] Sandbox destroyed{C_RESET}")

        focus_areas = _parse_focus_areas(planner_output)

        if not focus_areas:
            print(f"  {C_RED}[planner]{C_RESET} No focus areas identified — falling back to generic")
            focus_areas = ["memory safety vulnerabilities"]

        print(f"\n  {C_CYAN}[planner]{C_RESET} {C_BOLD}Focus areas ({len(focus_areas)}):{C_RESET}")
        for i, area in enumerate(focus_areas):
            print(f"    {C_GREEN}{i}{C_RESET}: {area}")
    else:
        print(f"\n{C_BOLD}Phase 1: Using provided focus areas ({len(focus_areas)}){C_RESET}")
        for i, area in enumerate(focus_areas):
            print(f"    {C_GREEN}{i}{C_RESET}: {area}")

    n = len(focus_areas)

    # ── Phase 2: Parallel finders only ──
    print(f"\n{C_BOLD}Phase 2: Launching {n} finders in parallel{C_RESET}")
    finder_containers = []
    finder_agents = []

    for i, area in enumerate(focus_areas):
        fc = f"find_{target.name}_{i}"
        finder_containers.append(fc)
        sandbox.create(target.image_tag, name=fc, runtime=harness_config.sandbox_runtime, read_only=False)
        print(f"  {C_GREEN}[finder_{i}]{C_RESET} Sandbox: {fc} | Focus: {area}")

        finder_agents.append(finder.create(
            model=harness_config.models.finder,
            focus_area=area,
            container_name=fc,
        ))

    parallel = ParallelAgent(
        name="parallel_finders",
        description="Run all finders simultaneously",
        sub_agents=finder_agents,
    )

    print(f"\n{C_BOLD}Running {n} finders in parallel...{C_RESET}")
    prompt = (
        f"Analyze {target.name} for memory safety vulnerabilities.\n"
        f"Source: {target.source_root}, Binary: {target.binary_path}\n"
    )
    finder_results = await _run_workflow(parallel, prompt, plugins=[gateway])

    # Extract PoC bytes from each finder container — check multiple paths
    POC_PATHS = ["/tmp/poc.bin", "/tmp/poc", "/tmp/poc.dat", "/tmp/input.bin", "/tmp/crash.bin"]
    findings = []
    for i, fc in enumerate(finder_containers):
        agent_key = f"finder_{fc}"
        finder_output = finder_results.get(agent_key, "")
        poc_bytes = None
        poc_path = None

        for path in POC_PATHS:
            poc_bytes = sandbox.read_file(fc, path)
            if poc_bytes:
                poc_path = path
                break

        # Fallback: find any .bin file in /tmp
        if not poc_bytes:
            find_result = sandbox.execute(fc, ["find", "/tmp", "-name", "*.bin", "-type", "f"], timeout=5)
            for line in find_result["stdout"].strip().split("\n"):
                line = line.strip()
                if line:
                    poc_bytes = sandbox.read_file(fc, line)
                    if poc_bytes:
                        poc_path = line
                        break

        if poc_bytes:
            print(f"  {C_GREEN}[finder_{i}]{C_RESET} PoC: {C_BOLD}{len(poc_bytes)} bytes{C_RESET} at {poc_path}")
            findings.append({
                "index": i,
                "focus_area": focus_areas[i],
                "poc_bytes": poc_bytes,
                "finder_output": finder_output,
            })
        else:
            preview = finder_output.strip()[:150] if finder_output else "no output"
            print(f"  {C_YELLOW}[finder_{i}]{C_RESET} No PoC found | {C_DIM}{preview}{C_RESET}")

    # Destroy finder containers
    for fc in finder_containers:
        sandbox.destroy(fc)
    print(f"  {C_DIM}All finder sandboxes destroyed{C_RESET}")

    # ── Phase 3: Sequential verify → analyze per finding ──
    print(f"\n{C_BOLD}Phase 3: Verify and analyze {len(findings)} findings{C_RESET}")

    for data in findings:
        i = data["index"]

        # Verify
        vc = f"grade_{target.name}_{i}"
        sandbox.create(target.image_tag, name=vc, runtime=harness_config.sandbox_runtime, read_only=False)
        sandbox.write_file(vc, "/tmp/poc.bin", data["poc_bytes"])
        print(f"\n  {C_YELLOW}[verifier_{i}]{C_RESET} Sandbox: {vc} | PoC: {len(data['poc_bytes'])} bytes")

        verifier_agent = verifier.create(
            model=harness_config.models.verifier,
            container_name=vc,
            binary_path=target.binary_path,
        )
        verifier_output = await _run_single_agent(
            verifier_agent,
            "Verify this crash. PoC is at /tmp/poc.bin.",
            plugins=[gateway],
        )
        sandbox.destroy(vc)
        print(f"  {C_DIM}[verifier_{i}] Sandbox destroyed{C_RESET}")

        # Analyze
        ac = f"analyze_{target.name}_{i}"
        sandbox.create(target.image_tag, name=ac, runtime=harness_config.sandbox_runtime, read_only=True)
        print(f"  {C_BLUE}[analyst_{i}]{C_RESET} Sandbox: {ac}")

        crash_details = (
            f"Focus area: {data['focus_area']}\n"
            f"Finder output:\n{data['finder_output'][:3000]}\n"
            f"Verifier output:\n{verifier_output[:2000]}\n"
        )
        analyst_agent = analyst.create(
            model=harness_config.models.analyst,
            container_name=ac,
            crash_details=crash_details,
        )
        report = await _run_single_agent(
            analyst_agent,
            "Analyze this vulnerability.",
            plugins=[gateway],
        )

        # Save report
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_area = "".join(c if c.isalnum() or c in "-_" else "_" for c in data["focus_area"])[:40]
        path = os.path.join(run_dir, f"{timestamp}_{safe_area}_{i}.md")
        with open(path, "w") as f:
            f.write(report)
        print(f"  {C_BLUE}[analyst_{i}]{C_RESET} Report: {C_BOLD}{path}{C_RESET}")

        sandbox.destroy(ac)
        print(f"  {C_DIM}[analyst_{i}] Sandbox destroyed{C_RESET}")

    print_token_summary()
    print(f"\n{C_BOLD}Assessment complete. {len(findings)} reports in {run_dir}{C_RESET}")
