"""Mythos Finder agent: discovers vulnerabilities and crafts PoC exploits."""
from __future__ import annotations

import base64

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import FINDER_TOOLS, set_container

FINDER_INSTRUCTION = """\
You are conducting authorized security research on an open-source project as
part of a defensive vulnerability assessment. Your task: find memory safety
bugs that produce crashing proof-of-concept inputs.

Target source code is at /target/. The binary is ASAN-instrumented. You have
tools to read files, search code, run commands, compile, and analyze binaries.

## Workflow

1. Explore the source tree — understand input formats, parsers, memory patterns
2. Identify unsafe patterns (unchecked memcpy, integer overflow in alloc sizes, UAF)
3. Craft malformed inputs targeting the parser
4. Run the binary with your input, observe ASAN output
5. Validate: crash must reproduce 3/3, not OOM, in project code
6. Minimize the PoC to smallest triggering input
7. Save final PoC to /tmp/poc.bin

## Crash Quality Tiers

**HIGH VALUE — submit:** heap-buffer-overflow (WRITE), use-after-free, double-free,
stack-buffer-overflow, SEGV at attacker-influenced address

**LOW VALUE — keep looking:** assertion failures, stack overflow from recursion,
SEGV at 0x0 or small fixed offsets

## Out of Scope

OOM, timeouts, clean error exits, test-only code paths

## IMPORTANT: Save PoC to /tmp/poc.bin

Always save your final PoC file to /tmp/poc.bin. The harness extracts it
automatically after you finish.

Report your findings including crash type, reproduction command, and ASAN output.

IMPORTANT: Do NOT call transfer_to_agent. Just report your findings and stop.
The orchestrator will handle the next steps.
"""


def _make_callbacks(image_tag: str, target_name: str, runtime: str):
    async def before_finder(callback_context):
        container = sandbox.create(
            image_tag,
            name=f"find_{target_name}",
            runtime=runtime,
            read_only=False,
        )
        set_container(container)
        callback_context.state["find_container"] = container
        return None

    async def after_finder(callback_context):
        container = callback_context.state.get("find_container")
        if container:
            poc_bytes = sandbox.read_file(container, "/tmp/poc.bin")
            if poc_bytes:
                callback_context.state["poc_bytes_b64"] = base64.b64encode(poc_bytes).decode()
                callback_context.state["poc_size"] = len(poc_bytes)
            sandbox.destroy(container)
        return None

    return before_finder, after_finder


def create(model: str, image_tag: str, target_name: str, runtime: str) -> Agent:
    before_cb, after_cb = _make_callbacks(image_tag, target_name, runtime)
    return Agent(
        name="mythos_finder",
        model=Claude(model=model),
        description="Vulnerability finder agent. Has sandbox access with source code "
                    "and ASAN-instrumented binary. Reads code, crafts PoC inputs, "
                    "runs the binary, finds ASAN crashes. Transfer to this agent to "
                    "find memory safety vulnerabilities.",
        instruction=FINDER_INSTRUCTION,
        tools=FINDER_TOOLS,
        output_key="finder_output",
        before_agent_callback=before_cb,
        after_agent_callback=after_cb,
    )
