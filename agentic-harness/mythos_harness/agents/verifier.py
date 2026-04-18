"""Verifier (Grader) agent: reproduces a PoC in a fresh sandbox."""
from __future__ import annotations

import base64

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import VERIFIER_TOOLS, set_container

VERIFIER_INSTRUCTION = """\
You are a strict crash verification engineer. Verify a reported vulnerability
by reproducing the proof-of-concept in this clean, fresh sandbox.

A PoC file has been placed at /tmp/poc.bin. This sandbox was freshly created
from the same image — the finding agent never touched it.

## Criteria — evaluate ALL five

1. **PoC file valid**: /tmp/poc.bin exists and is non-empty
2. **Reproduces 3/3**: Run the reproduction command 3 times, all must crash
3. **Not OOM/timeout**: Exit 137=OOM, 124=timeout → FAIL
4. **In project code**: ASAN trace must show project source files
5. **Consistent**: Same crash type across all 3 runs

Report each criterion as PASS/FAIL with evidence, overall verdict, and score.

IMPORTANT: Do NOT call transfer_to_agent. Just report your verdict and stop.
The orchestrator will handle the next steps.
"""


def _make_callbacks(image_tag: str, target_name: str, runtime: str):
    async def before_verifier(callback_context):
        container = sandbox.create(
            image_tag,
            name=f"grade_{target_name}",
            runtime=runtime,
            read_only=False,
        )
        poc_b64 = callback_context.state.get("poc_bytes_b64")
        if poc_b64:
            poc_bytes = base64.b64decode(poc_b64)
            sandbox.write_file(container, "/tmp/poc.bin", poc_bytes)
        set_container(container)
        callback_context.state["grade_container"] = container
        return None

    async def after_verifier(callback_context):
        container = callback_context.state.get("grade_container")
        if container:
            sandbox.destroy(container)
        return None

    return before_verifier, after_verifier


def create(model: str, image_tag: str, target_name: str, runtime: str) -> Agent:
    before_cb, after_cb = _make_callbacks(image_tag, target_name, runtime)
    return Agent(
        name="verifier",
        model=Claude(model=model),
        description="Crash verification agent. Has a fresh sandbox with the PoC file "
                    "at /tmp/poc.bin. Reproduces the crash 3/3 times and checks 5 "
                    "criteria. Transfer to this agent after the finder reports a crash.",
        instruction=VERIFIER_INSTRUCTION,
        tools=VERIFIER_TOOLS,
        output_key="verifier_output",
        before_agent_callback=before_cb,
        after_agent_callback=after_cb,
    )
