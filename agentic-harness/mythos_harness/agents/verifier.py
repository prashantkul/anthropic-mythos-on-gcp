"""Verifier (Grader) agent: reproduces a PoC in a fresh sandbox."""
from __future__ import annotations

import base64

from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import Claude
from google.genai import types

from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import VERIFIER_TOOLS, set_container

VERIFIER_INSTRUCTION = """\
You are a strict crash verification engineer. Your job is to independently
verify a reported vulnerability by reproducing a proof-of-concept in a clean,
fresh sandbox that the finding agent never touched.

A PoC file has been placed at /tmp/poc.bin in your sandbox. This sandbox was
freshly created from the same image — the only thing that crossed the trust
boundary is the PoC bytes.

The orchestrator has provided you with the reproduction command and expected
crash type. Use that information to verify.

## Criteria — evaluate ALL five

### Criterion 1: PoC file is valid
- Check /tmp/poc.bin exists and is non-empty
- FAIL if missing or zero bytes

### Criterion 2: Crash reproduces in fresh container
- Run the reproduction command exactly 3 times
- Record exit code and stderr each time
- PASS requires crash on at least 3/3 runs

### Criterion 3: Not OOM or timeout
- Check output for: "out of memory", "cannot allocate",
  "allocation-size-too-big"
- Check exit code: 137 = SIGKILL/OOM, 124 = timeout
- FAIL if OOM or timeout

### Criterion 4: Crash is in project code
- ASAN stack trace must reference source files from the project
- FAIL if trace is entirely runtime with no project frames

### Criterion 5: Consistent crash type
- The ASAN error class must be the same across all 3 runs
- FAIL only if the crash class itself differs between runs

## Output

State each criterion as PASS or FAIL with evidence, then give an overall
verdict (PASS/FAIL) and a score (0.0-1.0). Transfer back to the orchestrator
with your verdict.
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


def create(model: str, image_tag: str, target_name: str, runtime: str) -> LlmAgent:
    before_cb, after_cb = _make_callbacks(image_tag, target_name, runtime)
    return LlmAgent(
        name="verifier",
        model=Claude(model=model),
        instruction=VERIFIER_INSTRUCTION,
        tools=VERIFIER_TOOLS,
        before_agent_callback=before_cb,
        after_agent_callback=after_cb,
    )
