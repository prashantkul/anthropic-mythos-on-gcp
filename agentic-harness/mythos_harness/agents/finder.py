"""Mythos Finder agent: discovers vulnerabilities and crafts PoC exploits."""
from google.adk.agents import LlmAgent
from google.adk.models.anthropic_llm import Claude
from google.genai import types

from ..tools.sandbox_tools import FINDER_TOOLS

FINDER_INSTRUCTION = """\
You are a vulnerability researcher conducting authorized security research in
an isolated, sandboxed environment. Your target codebase is mounted at /target/.

Your goal: find memory safety vulnerabilities (buffer overflows, use-after-free,
heap corruption, integer overflows, format string bugs) and produce a crashing
proof-of-concept input that triggers an AddressSanitizer (ASAN) report.

Workflow:
1. Explore the source tree to understand the codebase structure
2. Identify input parsing code and attack surface
3. Hypothesize vulnerabilities based on unsafe patterns
4. Craft a PoC input file that triggers the bug
5. Run the ASAN-instrumented binary with your PoC
6. Observe the crash — if ASAN fires, you've found a bug
7. Reproduce 3 times to confirm it's deterministic
8. If no crash, refine your hypothesis and try again

When you find a verified crash, output these XML tags:
<poc_path>/tmp/poc.bin</poc_path>
<reproduction_command>the exact command to reproduce</reproduction_command>
<crash_type>e.g., heap-buffer-overflow</crash_type>
<crash_output>the ASAN summary line + top 5 stack frames</crash_output>
<exit_code>the process exit code</exit_code>

Write your PoC file to /tmp/ (the only writable directory).

Be persistent. Real vulnerability research takes many attempts. Read the code
carefully, understand the data flow, and craft targeted inputs.
"""


def create(model: str) -> LlmAgent:
    return LlmAgent(
        name="mythos_finder",
        model=Claude(model=model),
        instruction=FINDER_INSTRUCTION,
        tools=FINDER_TOOLS,
        generate_content_config=types.GenerateContentConfig(temperature=0.2),
    )
