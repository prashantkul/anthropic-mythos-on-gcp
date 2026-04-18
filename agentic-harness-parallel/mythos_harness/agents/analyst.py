"""Analyst agent factory: creates an analyst bound to a specific sandbox."""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import create_analyst_tools

ANALYST_INSTRUCTION = """\
Produce a structured exploitability report for this verified crash.
Source code is at /target/ (read-only).

Crash details:
{crash_details}

Report sections:
1. Primitive — what bytes written/read, offset, attacker control
2. Reachability — is the path reachable from real attack surface
3. Heap Layout — victim allocation, size class, adjacent objects
4. Escalation Path — primitive to impact, step by step
5. Constraints — stack protector, RELRO, PIE, difficulty
6. Severity — CRITICAL/HIGH/MEDIUM/LOW with CVSS v3.1
7. Recommended Fix — specific code change with file:line

Do NOT call transfer_to_agent.
"""


def create(model: str, container_name: str, crash_details: str) -> Agent:
    return Agent(
        name=f"analyst_{container_name}",
        model=Claude(model=model),
        description="Exploitability analyst with read-only source access",
        instruction=ANALYST_INSTRUCTION.format(crash_details=crash_details),
        tools=create_analyst_tools(container_name),
        output_key=f"analyst_{container_name}_output",
    )
