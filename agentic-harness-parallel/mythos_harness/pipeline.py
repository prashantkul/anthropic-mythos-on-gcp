"""Dynamic parallel pipeline builder.

Phase 1: Planner identifies focus areas
Phase 2: ParallelAgent runs finder+verifier per area simultaneously
Phase 3: Analyst runs for each verified finding
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from google.adk.agents import Agent, ParallelAgent, SequentialAgent
from google.adk.models.anthropic_llm import Claude
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .agents import analyst, finder, verifier
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


async def _run_agent(agent: Agent, prompt: str, plugins: list | None = None) -> str:
    """Run a single agent and collect its text output."""
    session_service = InMemorySessionService()
    sid = f"session_{agent.name}"
    await session_service.create_session(
        app_name="mythos_parallel", user_id="harness", session_id=sid
    )
    runner = Runner(
        agent=agent,
        app_name="mythos_parallel",
        session_service=session_service,
        plugins=plugins or [],
    )
    content = types.Content(role="user", parts=[types.Part(text=prompt)])
    result_text = ""
    async for event in runner.run_async(
        new_message=content, user_id="harness", session_id=sid
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    result_text += part.text
    return result_text


async def _run_workflow(workflow_agent, prompt: str, plugins: list | None = None) -> dict:
    """Run a workflow agent (Sequential/Parallel) and collect all state."""
    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="mythos_parallel", user_id="harness", session_id="workflow"
    )
    runner = Runner(
        agent=workflow_agent,
        app_name="mythos_parallel",
        session_service=session_service,
        plugins=plugins or [],
    )
    content = types.Content(role="user", parts=[types.Part(text=prompt)])
    results = {}
    async for event in runner.run_async(
        new_message=content, user_id="harness", session_id="workflow"
    ):
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


async def run_parallel_assessment(
    target: TargetConfig,
    focus_areas: list[str],
    harness_config: HarnessConfig,
    run_dir: str,
):
    """Run the full parallel pipeline."""

    if not sandbox.image_exists(target.image_tag):
        print(f"{C_YELLOW}Building image {target.image_tag}...{C_RESET}")
        sandbox.build(target.dockerfile_dir, target.image_tag)

    gateway = SecurityGatewayPlugin()
    n = len(focus_areas)

    # --- Phase 2: Create parallel finder+verifier pipelines ---
    print(f"\n{C_BOLD}Phase 2: Launching {n} parallel finder+verifier pipelines{C_RESET}")
    pipelines = []
    finder_containers = []
    verifier_containers = []

    for i, area in enumerate(focus_areas):
        fc = f"find_{target.name}_{i}"
        vc = f"grade_{target.name}_{i}"
        finder_containers.append(fc)
        verifier_containers.append(vc)

        # Create sandboxes
        sandbox.create(target.image_tag, name=fc, runtime=harness_config.sandbox_runtime, read_only=False)
        sandbox.create(target.image_tag, name=vc, runtime=harness_config.sandbox_runtime, read_only=False)
        print(f"  {C_GREEN}[finder_{i}]{C_RESET} Sandbox: {fc} | Focus: {area}")
        print(f"  {C_YELLOW}[verifier_{i}]{C_RESET} Sandbox: {vc}")

        finder_i = finder.create(
            model=harness_config.models.finder,
            focus_area=area,
            container_name=fc,
        )
        verifier_i = verifier.create(
            model=harness_config.models.verifier,
            container_name=vc,
            binary_path=target.binary_path,
        )

        pipeline_i = SequentialAgent(
            name=f"pipeline_{i}",
            description=f"Find and verify vulnerabilities in: {area}",
            sub_agents=[finder_i, verifier_i],
        )
        pipelines.append(pipeline_i)

    parallel = ParallelAgent(
        name="parallel_finders",
        description="Run all finder+verifier pipelines simultaneously",
        sub_agents=pipelines,
    )

    # Run all pipelines in parallel
    print(f"\n{C_BOLD}Running {n} pipelines in parallel...{C_RESET}")
    prompt = (
        f"Analyze {target.name} for memory safety vulnerabilities.\n"
        f"Source: {target.source_root}, Binary: {target.binary_path}\n"
    )
    results = await _run_workflow(parallel, prompt, plugins=[gateway])

    # Extract PoC bytes from finder containers before destroying
    poc_data = []
    for i, fc in enumerate(finder_containers):
        poc_bytes = sandbox.read_file(fc, "/tmp/poc.bin")
        finder_output = results.get(f"finder_{fc}", "")
        verifier_output = results.get(f"verifier_grade_{target.name}_{i}", "")

        if poc_bytes:
            print(f"  {C_GREEN}[finder_{i}]{C_RESET} PoC: {C_BOLD}{len(poc_bytes)} bytes{C_RESET}")
            poc_data.append({
                "index": i,
                "focus_area": focus_areas[i],
                "poc_bytes": poc_bytes,
                "finder_output": finder_output,
                "verifier_output": verifier_output,
            })
        else:
            print(f"  {C_YELLOW}[finder_{i}]{C_RESET} No PoC found")

    # Copy PoC bytes to verifier containers (for verification that needs it)
    for data in poc_data:
        vc = verifier_containers[data["index"]]
        sandbox.write_file(vc, "/tmp/poc.bin", data["poc_bytes"])

    # Destroy finder and verifier containers
    for fc in finder_containers:
        sandbox.destroy(fc)
    for vc in verifier_containers:
        sandbox.destroy(vc)
    print(f"  {C_DIM}All finder/verifier sandboxes destroyed{C_RESET}")

    # --- Phase 3: Analyze verified findings ---
    verified = [d for d in poc_data if "PASS" in d.get("verifier_output", "").upper()]
    if not verified:
        verified = poc_data  # If verification info not captured, analyze all

    print(f"\n{C_BOLD}Phase 3: Analyzing {len(verified)} findings{C_RESET}")

    for data in verified:
        i = data["index"]
        ac = f"analyze_{target.name}_{i}"
        sandbox.create(target.image_tag, name=ac, runtime=harness_config.sandbox_runtime, read_only=True)
        print(f"  {C_BLUE}[analyst_{i}]{C_RESET} Sandbox: {ac}")

        crash_details = (
            f"Focus area: {data['focus_area']}\n"
            f"Finder output:\n{data['finder_output'][:3000]}\n"
            f"Verifier output:\n{data['verifier_output'][:2000]}\n"
        )
        analyst_agent = analyst.create(
            model=harness_config.models.analyst,
            container_name=ac,
            crash_details=crash_details,
        )

        report = await _run_agent(analyst_agent, "Analyze this vulnerability.", plugins=[gateway])

        # Auto-save
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_area = data["focus_area"].replace(" ", "_")[:40]
        path = os.path.join(run_dir, f"{timestamp}_{safe_area}_{i}.md")
        with open(path, "w") as f:
            f.write(report)
        print(f"  {C_BLUE}[analyst_{i}]{C_RESET} Report: {C_BOLD}{path}{C_RESET}")

        sandbox.destroy(ac)

    print(f"\n{C_BOLD}Assessment complete. {len(verified)} reports in {run_dir}{C_RESET}")
