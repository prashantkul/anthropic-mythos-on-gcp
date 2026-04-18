"""Analyst agent: structured exploitability analysis.

Invoked via _run_sub_agent() from the orchestrator's run_analyst tool.
Has read-only sandbox access to source code.
"""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import ANALYST_TOOLS

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
Do NOT call transfer_to_agent — just produce the report and stop.
"""


def create(model: str) -> Agent:
    return Agent(
        name="analyst",
        model=Claude(model=model),
        description="Exploitability analyst with read-only source access",
        instruction=ANALYST_INSTRUCTION,
        tools=ANALYST_TOOLS,
    )
