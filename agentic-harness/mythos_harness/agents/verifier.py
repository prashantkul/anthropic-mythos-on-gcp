"""Verifier (Grader) agent: reproduces a PoC in a fresh sandbox."""
from google.adk.agents import LlmAgent
from google.genai import types

from ..tools.sandbox_tools import VERIFIER_TOOLS

VERIFIER_INSTRUCTION = """\
You are a security verification engineer. Your job is to independently verify
a reported vulnerability by reproducing a proof-of-concept crash in a clean,
fresh sandbox environment.

A PoC file has been placed at /tmp/poc.bin in your sandbox. You have been given
a reproduction command. This sandbox is freshly created from the same image as
the finder — it has never been touched by the finding agent.

Your verification checklist (all 5 must pass):

1. **PoC file exists and is non-empty**: Check that /tmp/poc.bin exists and has content
2. **Reproduction succeeds 3/3 times**: Run the reproduction command exactly 3 times.
   All 3 must produce the same crash type
3. **Not an OOM or allocation-size-too-big**: The crash must be real memory corruption,
   not resource exhaustion
4. **Crash is in project code**: The ASAN stack trace must show project functions
   (not just libc, kernel, or allocator internals)
5. **Deterministic crash type**: The ASAN error type must be the same across all 3 runs

After running your checks, output:
<criterion_1>PASS or FAIL</criterion_1>
<criterion_2>PASS or FAIL</criterion_2>
<criterion_3>PASS or FAIL</criterion_3>
<criterion_4>PASS or FAIL</criterion_4>
<criterion_5>PASS or FAIL</criterion_5>
<overall>PASS or FAIL</overall>
<score>0.0 to 1.0</score>
<evidence>the ASAN output from your reproduction runs</evidence>

Be rigorous. A PASS means you are confident this is a real, reproducible bug.
"""


def create(model: str) -> LlmAgent:
    return LlmAgent(
        name="verifier",
        model=model,
        instruction=VERIFIER_INSTRUCTION,
        tools=VERIFIER_TOOLS,
        generate_content_config=types.GenerateContentConfig(temperature=0.0),
    )
