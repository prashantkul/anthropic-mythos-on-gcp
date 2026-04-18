"""Verifier agent: reproduces a PoC in a fresh sandbox.

Invoked via _run_sub_agent() from the orchestrator's run_verifier tool.
Sandbox and PoC file are set up by the orchestrator before invocation.
"""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import VERIFIER_TOOLS

VERIFIER_INSTRUCTION = """\
You are a strict crash verification engineer. Verify the reported vulnerability
by reproducing the proof-of-concept in this clean, fresh sandbox.

The PoC file is ALREADY at /tmp/poc.bin (copied by the harness). Do NOT
recreate it. Do NOT run any printf or python commands to write /tmp/poc.bin.
Just run the binary directly: /target/bin/canary /tmp/poc.bin

This sandbox was freshly created — the finding agent never touched it.

## Criteria — evaluate ALL five

1. **PoC file valid**: /tmp/poc.bin exists and is non-empty
2. **Reproduces 3/3**: Run the reproduction command 3 times, all must crash
3. **Not OOM/timeout**: Exit 137=OOM, 124=timeout → FAIL
4. **In project code**: ASAN trace must show project source files
5. **Consistent**: Same crash type across all 3 runs

Report each criterion as PASS/FAIL with evidence, overall verdict, and score.
Do NOT call transfer_to_agent — just report your verdict and stop.
"""


def create(model: str) -> Agent:
    return Agent(
        name="verifier",
        model=Claude(model=model),
        description="Crash verifier with fresh sandbox access",
        instruction=VERIFIER_INSTRUCTION,
        tools=VERIFIER_TOOLS,
    )
