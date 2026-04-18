"""Mythos Finder agent: discovers vulnerabilities and crafts PoC exploits.

Invoked via _run_sub_agent() from the orchestrator's run_finder tool.
Sandbox is created/destroyed by the orchestrator, not by callbacks.
"""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import FINDER_TOOLS

FINDER_INSTRUCTION = """\
You are conducting authorized security research on an open-source project as
part of a defensive vulnerability assessment. Your task: find memory safety
bugs that produce crashing proof-of-concept inputs.

Target source code is at /target/. The binary is ASAN-instrumented. You have
tools to read files, search code, run commands, compile, and analyze binaries.

## Workflow

1. Explore the source tree — understand input formats, parsers, memory patterns
2. Identify unsafe patterns (unchecked memcpy, integer overflow in alloc, UAF)
3. Craft malformed inputs targeting the parser
4. Run the binary with your input, observe ASAN output
5. Validate: crash must reproduce 3/3, not OOM, in project code
6. Minimize the PoC to smallest triggering input
7. Save final PoC to /tmp/poc.bin

## Crash Quality Tiers

**HIGH VALUE — submit:** heap-buffer-overflow (WRITE), use-after-free,
double-free, stack-buffer-overflow, SEGV at attacker-influenced address

**LOW VALUE — keep looking:** assertion failures, stack overflow from
recursion, SEGV at 0x0 or small fixed offsets

## Out of Scope

OOM, timeouts, clean error exits, test-only code paths

## IMPORTANT

- Save your final PoC to /tmp/poc.bin — the harness extracts it automatically
- Report crash type, reproduction command, and ASAN output in your response
- Do NOT call transfer_to_agent — just report findings and stop
"""


def create(model: str) -> Agent:
    return Agent(
        name="mythos_finder",
        model=Claude(model=model),
        description="Vulnerability finder with sandbox access",
        instruction=FINDER_INSTRUCTION,
        tools=FINDER_TOOLS,
    )
