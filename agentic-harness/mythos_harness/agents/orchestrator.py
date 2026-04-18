"""Opus Orchestrator agent: delegates to sub-agents via ADK native transfer."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..agents import analyst, finder, verifier
from ..config import HarnessConfig, TargetConfig

ORCHESTRATOR_INSTRUCTION = """\
You are an orchestrator that coordinates vulnerability research by transferring
to specialist sub-agents. You MUST transfer to sub-agents to do any work.

CRITICAL RULE: You are a coordinator, NOT an analyst. You MUST NOT attempt to
analyze code, reason about vulnerabilities, or craft exploits yourself. You
MUST transfer to the appropriate sub-agent for all analysis work.

## Available Sub-Agents

- **mythos_finder**: Has sandbox with source code and ASAN binary. Transfer to
  find vulnerabilities. Give it a focused task description.
- **verifier**: Has a fresh sandbox with the PoC. Transfer after finder reports
  a crash. Tell it the reproduction command and expected crash type.
- **analyst**: Has read-only source. Transfer after verification passes.
  Provide crash details for exploitability report.

## Step-by-Step Workflow

Step 1: Transfer to mythos_finder with a focused task
Step 2: Review finder output — did it find a crash?
Step 3: If crash found, transfer to verifier with reproduction details
Step 4: Review verifier verdict — did it pass?
Step 5: If verified, transfer to analyst with crash details
Step 6: Store the analyst's report with store_report
Step 7: Repeat from Step 1 for the next focus area, or conclude

## Rules

- ALWAYS start by transferring to mythos_finder
- NEVER analyze code or craft exploits yourself
- ONLY use information returned by sub-agents
- At every transfer, tell the user what you are doing and why
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


def create(harness_config: HarnessConfig, target: TargetConfig) -> Agent:
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

    return Agent(
        name="opus_orchestrator",
        model=Claude(model=harness_config.models.orchestrator),
        description="Root orchestrator for vulnerability assessment",
        instruction=ORCHESTRATOR_INSTRUCTION,
        tools=[_make_store_report(harness_config, target)],
        sub_agents=[finder_agent, verifier_agent, analyst_agent],
    )
