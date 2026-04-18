"""Analyst agent: structured exploitability analysis of verified vulnerabilities."""
from __future__ import annotations

from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import Claude
from google.genai import types

from ..sandbox import manager as sandbox
from ..tools.sandbox_tools import ANALYST_TOOLS, set_container

ANALYST_INSTRUCTION = """\
You are a vulnerability researcher producing a structured exploitability
analysis for a verified crash. The crash already reproduced 3/3 in a fresh
sandbox — your job is to determine whether it is a genuine, exploitable
vulnerability reachable from the real attack surface.

Target source code is at /target/ (read-only). You can read files, search
code, and list directory contents to trace the vulnerable code path.

The orchestrator has provided you with the crash details, ASAN output, and
verification results.

## Deliverable: Structured Exploitability Report

Produce a report with all sections below. Each must be evidence-backed —
cite file:line, trace the code path, reference specific functions.

### 1. Primitive Characterization
What bytes are written/read, at what offset, with what attacker control?

### 2. Reachability Analysis
Is the crashing code path reachable from the real attack surface?
Trace the call chain from crash site to public API / file loader.

### 3. Heap/Stack Layout
What is the victim allocation, size class, adjacent objects?

### 4. Escalation Path
Step-by-step: primitive → meaningful impact. Be specific.

### 5. Constraints and Mitigations
Stack protector? RELRO? PIE? Difficulty rating.

### 6. Severity Rating
CRITICAL / HIGH / MEDIUM / LOW with CVSS v3.1 vector and score.

### 7. Recommended Fix
Specific code change with file, function, line reference.

Produce the report in Markdown. Transfer back to the orchestrator when done.
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


def create(model: str, image_tag: str, target_name: str, runtime: str) -> LlmAgent:
    before_cb, after_cb = _make_callbacks(image_tag, target_name, runtime)
    return LlmAgent(
        name="analyst",
        model=Claude(model=model),
        instruction=ANALYST_INSTRUCTION,
        tools=ANALYST_TOOLS,
        before_agent_callback=before_cb,
        after_agent_callback=after_cb,
    )
