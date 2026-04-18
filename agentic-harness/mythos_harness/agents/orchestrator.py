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
You are an orchestrator that coordinates vulnerability research by delegating
to specialist sub-agents. You MUST use transfer_to_agent to delegate work.
You CANNOT analyze code yourself — you have no access to source code or
sandboxes. Your only tools are transfer_to_agent and store_report.

## MANDATORY: You must transfer to sub-agents

DO NOT attempt to reason about vulnerabilities, code, or exploits yourself.
You do not have access to source code or a sandbox. You MUST transfer to
mythos_finder to find bugs. Every assessment MUST start with a transfer.

## Sub-agents available

- **mythos_finder**: Has sandbox access with source code and ASAN binary.
  Transfer to this agent to find vulnerabilities. Give it a focused task.
- **verifier**: Has a fresh sandbox. Transfer to this agent after the finder
  reports a crash. Tell it the reproduction command and expected crash type.
- **analyst**: Has read-only source access. Transfer to this agent after
  verification passes. Provide crash details for exploitability analysis.

## Workflow

1. Transfer to **mythos_finder**: "Find memory safety vulnerabilities in [area]"
2. When finder returns with a crash, transfer to **verifier**: provide the
   reproduction command and crash type from the finder's report
3. When verifier returns PASS, transfer to **analyst**: provide all crash details
4. When analyst returns the report, call **store_report** to save it
5. Repeat with a different focus area, or end if all areas are covered

## Rules

- ALWAYS start by transferring to mythos_finder
- NEVER output code analysis, vulnerability descriptions, or exploit details yourself
- ONLY use information returned by your sub-agents
- After storing a report, you may transfer to mythos_finder again for the next area
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
