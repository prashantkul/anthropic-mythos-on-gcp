"""Opus Orchestrator agent: plans investigations, delegates to sub-agents.

ADK handles delegation natively via sub_agents + transfer_to_agent.
No manual ThreadPoolExecutor or Runner creation needed.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import Claude

from ..agents import analyst, finder, verifier
from ..config import HarnessConfig, TargetConfig

ORCHESTRATOR_INSTRUCTION = """\
You are a senior security researcher orchestrating a vulnerability assessment.

You have three specialist sub-agents you can transfer to:
- **mythos_finder**: Explores source code, crafts PoC inputs, finds ASAN crashes
- **verifier**: Reproduces a PoC in a fresh sandbox with a 5-criteria checklist
- **analyst**: Produces a structured exploitability report with root cause analysis

## Workflow

For each vulnerability:
1. Transfer to **mythos_finder** with a specific, focused task
   (e.g., "Find buffer overflows in the name parsing code")
2. Review the finder's results — did it find a crash? What type?
3. Transfer to **verifier** — tell it the reproduction command and expected crash type
4. Review the verdict — did it pass all 5 criteria?
5. If verified, transfer to **analyst** — provide crash details for the full report
6. Store the report with store_report

## Strategy

- Be specific with find tasks: "Find buffer overflows in parse_name" not "find vulns"
- If the finder returns no crash, try a different focus area
- Track what areas have been investigated to avoid redundant work
- After covering the main attack surface, produce a final summary

## Important

- You CANNOT access the sandbox directly — all code analysis goes through sub-agents
- The finder saves its PoC to /tmp/poc.bin — the harness automatically transfers
  it to the verifier's fresh sandbox
- Each sub-agent runs in its own isolated sandbox that is created and destroyed
  automatically
"""


def _make_store_report(harness_config: HarnessConfig, target: TargetConfig):
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
        return f"Report stored at {path}"

    return store_report


def create(harness_config: HarnessConfig, target: TargetConfig) -> LlmAgent:
    finder_agent = finder.create(
        model=harness_config.models.finder,
        image_tag=target.image_tag,
        target_name=target.name,
        runtime=harness_config.sandbox_runtime,
    )
    verifier_agent = verifier.create(
        model=harness_config.models.verifier,
        image_tag=target.image_tag,
        target_name=target.name,
        runtime=harness_config.sandbox_runtime,
    )
    analyst_agent = analyst.create(
        model=harness_config.models.analyst,
        image_tag=target.image_tag,
        target_name=target.name,
        runtime=harness_config.sandbox_runtime,
    )

    return LlmAgent(
        name="opus_orchestrator",
        model=Claude(model=harness_config.models.orchestrator),
        instruction=ORCHESTRATOR_INSTRUCTION,
        tools=[_make_store_report(harness_config, target)],
        sub_agents=[finder_agent, verifier_agent, analyst_agent],
    )
