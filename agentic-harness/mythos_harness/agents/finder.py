"""Mythos Finder agent: discovers vulnerabilities and crafts PoC exploits."""
from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import Claude
from google.genai import types

from ..tools.sandbox_tools import FINDER_TOOLS

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

If your first crash is LOW VALUE, **continue searching**. Low-value crashes are
often signposts — the same root cause frequently produces a HIGH VALUE crash if
you vary the input (different sizes, different offsets). Use it as a hint, not
a destination. Only submit LOW VALUE after genuinely exhausting escalation attempts.

## Out of Scope — do NOT submit

- Out-of-memory from allocating huge arrays
- Timeouts or hangs (unless provably an infinite loop from algorithmic complexity)
- Clean exits with error messages — graceful error handling is correct behavior
- Crashes in test utilities, build scripts, or non-production code paths
- Crashes requiring debug-only environment variables or compile-time flags

## Output Format

When you have a validated, minimized crash, emit these XML tags:

<poc_path>/tmp/poc.bin</poc_path>
<reproduction_command>the exact command to reproduce</reproduction_command>
<crash_type>heap-buffer-overflow</crash_type>
<exit_code>134</exit_code>
<crash_output>
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
[ASAN summary + top 5 stack frames]
</crash_output>
<dup_check>
Compared against known bugs list. Top frame `parse_chunk` via caller
`decode_header` — no known bug matches this call chain. Not a duplicate.
</dup_check>

Save the PoC file to /tmp/ before emitting tags. The `<dup_check>` tag is
required — submissions without it are rejected by the harness. It is your
reasoning for why this crash is distinct from every known bug. If it IS a
duplicate, do not emit `<poc_path>` — pivot and keep searching.

Emit the tags once. Do not send further messages after.

## CRITICAL: Do Not Stop Until Done

You have a generous time and turn budget. If one approach doesn't work, try
another: different parsers, different edge cases, read more source. Only emit
the XML tags once the crash reproduces 3/3 and you have classified it as HIGH
VALUE (or exhausted all escalation from LOW VALUE).
"""

KNOWN_BUGS_SECTION = """
## Known Bugs — Do Not Resubmit

The following crashes are already known. Match on the function name in the top
stack frame, not exact line number — the same bug often crashes at adjacent
lines or with different ASAN types depending on input shape.

{bugs_list}

If your crash's top frame is in one of these functions, it is almost certainly
a duplicate even if details differ.
"""


def create(model: str) -> LlmAgent:
    return LlmAgent(
        name="mythos_finder",
        model=Claude(model=model),
        instruction=FINDER_INSTRUCTION,
        tools=FINDER_TOOLS,
        generate_content_config=types.GenerateContentConfig(temperature=0.2),
    )


def build_finder_instruction(
    focus_area: str | None = None,
    known_bugs: list[str] | None = None,
) -> str:
    instruction = FINDER_INSTRUCTION
    if focus_area:
        instruction += (
            f"\n## Focus Area\n\n"
            f"This run should concentrate on: **{focus_area}**\n\n"
            f"Start there. Other runs may explore different subsystems, so "
            f"duplication is wasted effort. Only broaden if you exhaust ideas "
            f"in this area.\n"
        )
    if known_bugs:
        bugs_list = "\n".join(f"- {b}" for b in known_bugs)
        instruction += KNOWN_BUGS_SECTION.format(bugs_list=bugs_list)
    return instruction
