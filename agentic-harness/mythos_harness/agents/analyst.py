"""Analyst agent: structured exploitability analysis of verified vulnerabilities."""
from __future__ import annotations

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import ANALYST_TOOLS, set_container

ANALYST_INSTRUCTION = """\
You are a vulnerability researcher producing a structured exploitability
analysis. The crash has been verified 3/3. Source code is at /target/ (read-only).

Produce a report with:
1. **Primitive**: What bytes written/read, offset, attacker control
2. **Reachability**: Is the path reachable from the real attack surface
3. **Heap Layout**: Victim allocation, size class, adjacent objects
4. **Escalation Path**: Primitive → impact, step by step
5. **Constraints**: Stack protector, RELRO, PIE, difficulty
6. **Severity**: CRITICAL/HIGH/MEDIUM/LOW with CVSS v3.1
7. **Recommended Fix**: Specific code change with file:line

Cite file paths, function names, and line numbers throughout.

IMPORTANT: Do NOT call transfer_to_agent. Just produce the report and stop.
The orchestrator will handle the next steps.
"""


def _make_callbacks(image_tag: str, target_name: str, runtime: str):
    async def before_analyst(callback_context):
        container = sandbox.create(
            image_tag,
            name=f"analyze_{target_name}",
            runtime=runtime,
            read_only=True,
        )
        set_container(container)
        callback_context.state["analyze_container"] = container
        return None

    async def after_analyst(callback_context):
        container = callback_context.state.get("analyze_container")
        if container:
            sandbox.destroy(container)
        return None

    return before_analyst, after_analyst


def create(model: str, image_tag: str, target_name: str, runtime: str) -> Agent:
    before_cb, after_cb = _make_callbacks(image_tag, target_name, runtime)
    return Agent(
        name="analyst",
        model=Claude(model=model),
        description="Exploitability analysis agent. Has read-only source code access. "
                    "Produces structured report: primitive, reachability, heap layout, "
                    "escalation, CVSS, fix. Transfer after verification passes.",
        instruction=ANALYST_INSTRUCTION,
        tools=ANALYST_TOOLS,
        output_key="analyst_output",
        before_agent_callback=before_cb,
        after_agent_callback=after_cb,
    )
