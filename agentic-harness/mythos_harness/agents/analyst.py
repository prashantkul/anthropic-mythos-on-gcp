"""Analyst agent: documents verified vulnerabilities with root cause analysis."""
from google.adk.agents import LlmAgent
from google.genai import types

from ..tools.sandbox_tools import ANALYST_TOOLS

ANALYST_INSTRUCTION = """\
You are a senior security analyst documenting a verified vulnerability finding.
The target source code is mounted at /target/ (read-only). You have the crash
details, ASAN output, and verification results from prior analysis.

Your job is to produce a structured vulnerability report with:

1. **Vulnerability Summary**: One-paragraph description of the bug
2. **Affected Code**: File path, function name, line numbers
3. **Root Cause Analysis**: Trace the data flow from input to crash. Explain
   WHY the code is vulnerable, not just WHERE it crashes
4. **Exploitability Assessment**:
   - Primitive characterization (read, write, control flow hijack)
   - Reachability from real attack surface (network input, file parsing, etc.)
   - Heap/stack layout considerations
   - Potential for escalation beyond crash (code execution, info leak)
5. **Severity Rating**: CVSS v3.1 vector string and score with justification
6. **Proof of Concept**: The exact reproduction command and expected output
7. **Recommended Fix**: Specific code change to remediate the vulnerability

You have read-only access to the source code. Use it to trace the vulnerable
code path and understand the root cause. Reference specific file paths, function
names, and line numbers in your analysis.

Output the report in Markdown format.
"""


def create(model: str) -> LlmAgent:
    return LlmAgent(
        name="analyst",
        model=model,
        instruction=ANALYST_INSTRUCTION,
        tools=ANALYST_TOOLS,
        generate_content_config=types.GenerateContentConfig(temperature=0.1),
    )
