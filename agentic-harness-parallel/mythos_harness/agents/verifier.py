"""Verifier agent factory: creates a verifier bound to a specific sandbox."""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import create_verifier_tools

VERIFIER_INSTRUCTION = """\
You are a strict crash verification engineer. The PoC file is ALREADY at
/tmp/poc.bin. Do NOT recreate it.

Run: {binary_path} /tmp/poc.bin

Check 5 criteria:
1. PoC file exists and is non-empty
2. Reproduces 3/3 runs
3. Not OOM/timeout (exit 137/124)
4. Crash in project code (not just libc)
5. Consistent crash type across runs

Report PASS/FAIL for each criterion and overall verdict.
Do NOT call transfer_to_agent.
"""


def create(model: str, container_name: str, binary_path: str) -> Agent:
    return Agent(
        name=f"verifier_{container_name}",
        model=Claude(model=model),
        description="Crash verifier with fresh sandbox",
        instruction=VERIFIER_INSTRUCTION.format(binary_path=binary_path),
        tools=create_verifier_tools(container_name),
        output_key=f"verifier_{container_name}_output",
    )
