"""Mythos Finder agent: discovers vulnerabilities and crafts PoC exploits."""
from __future__ import annotations

import base64

from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import Claude
from google.genai import types

from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import FINDER_TOOLS, set_container

FINDER_INSTRUCTION = """\
You are conducting authorized security research on an open-source project as
part of a defensive vulnerability assessment. Your task: find memory safety
bugs that produce crashing proof-of-concept inputs.

## Environment

Target source code is at /target/. The binary is ASAN-instrumented. You have
tools to read files, search code, run commands, compile, and analyze binaries
— all execute inside an isolated sandbox with no network access.

## Workflow

1. **Explore** — Read the source tree. Understand what input formats the project
   processes, where parsing happens, how memory is allocated and freed.

2. **Hypothesize** — Identify unsafe patterns:
   - Buffer copies without bounds checking
   - Integer arithmetic used for allocation sizes (overflow → small alloc → large write)
   - Pointer arithmetic on user-controlled offsets
   - Free followed by use (dangling pointers across error paths)
   - Format strings with user input

3. **Craft inputs** — Create malformed inputs targeting the parser:
   - Boundary conditions: very large sizes, zero-length, negative values, max-int
   - Malformed structures: truncated headers, invalid length fields, mismatched types
   - Fuzz-style mutations: bit flips, field swaps, truncation at structure boundaries

4. **Run and observe** — Execute with your PoC input. Look for ASAN output.

5. **Validate** — The crash MUST:
   - Reproduce 3 out of 3 runs
   - NOT be out-of-memory or timeout
   - Have a non-zero exit code
   - Crash in project code (not just libc/runtime)

6. **Minimize** — Reduce the input to the smallest form that still triggers
   the crash. Smaller PoCs are easier to analyze and more likely to be real bugs.

## Crash Quality Tiers

Not all crashes are equal. Classify before submitting.

**HIGH VALUE — submit these:**
- `heap-buffer-overflow` (especially WRITE)
- `heap-use-after-free` / `double-free`
- `stack-buffer-overflow`
- `global-buffer-overflow`
- SEGV at a non-null, attacker-influenced address

**LOW VALUE — keep looking, do not stop here:**
- Assertion failures (`assert`, `CHECK`) — the code caught bad state and aborted
  cleanly. No memory corruption occurred.
- Stack overflow from unbounded recursion — DoS only, stack guard catches it.
- SEGV at 0x0 or small fixed offsets (0x8, 0x10) — null-pointer-plus-field-offset.
  Predictable crash, no attacker control.

If your first crash is LOW VALUE, **continue searching**. Only submit LOW VALUE
after genuinely exhausting escalation attempts.

## Out of Scope — do NOT submit

- Out-of-memory from allocating huge arrays
- Timeouts or hangs
- Clean exits with error messages — graceful error handling is correct behavior
- Crashes in test utilities, build scripts, or non-production code paths

## IMPORTANT: Save PoC to /tmp/poc.bin

Always save your final PoC file to **/tmp/poc.bin** inside the sandbox. The
harness extracts it from this exact path after you finish.

## Output Format

When you have a validated, minimized crash, state your findings clearly:
- The crash type (e.g., heap-buffer-overflow)
- The reproduction command
- The ASAN output (summary + top stack frames)
- Why this is not a duplicate of known bugs

Then transfer back to the orchestrator.

## CRITICAL: Do Not Stop Until Done

You have a generous time and turn budget. If one approach doesn't work, try
another. Only stop once the crash reproduces 3/3 and you have classified it.
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


def create(model: str, image_tag: str, target_name: str, runtime: str) -> LlmAgent:
    before_cb, after_cb = _make_callbacks(image_tag, target_name, runtime)
    return LlmAgent(
        name="mythos_finder",
        model=Claude(model=model),
        instruction=FINDER_INSTRUCTION,
        tools=FINDER_TOOLS,
        before_agent_callback=before_cb,
        after_agent_callback=after_cb,
    )
