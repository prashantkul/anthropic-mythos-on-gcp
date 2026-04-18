"""Finder agent factory: creates a finder bound to a specific sandbox."""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import create_finder_tools

FINDER_INSTRUCTION = """\
You are conducting authorized security research on an open-source project.
Target source code is at /target/. The binary is ASAN-instrumented.

Focus on: {focus_area}

Workflow:
1. Explore source, identify unsafe patterns in your focus area
2. Craft malformed inputs targeting the parser
3. Run the binary, observe ASAN output
4. Validate: reproduce 3/3, not OOM, in project code
5. Minimize the PoC
6. Save final PoC to /tmp/poc.bin

Submit HIGH VALUE crashes only: heap-buffer-overflow (WRITE), use-after-free,
double-free, stack-buffer-overflow. Keep looking if you hit assertion failures
or null derefs.

Do NOT call transfer_to_agent. Report findings and stop.
"""


def create(model: str, focus_area: str, container_name: str) -> Agent:
    return Agent(
        name=f"finder_{container_name}",
        model=Claude(model=model),
        description=f"Vulnerability finder focused on: {focus_area}",
        instruction=FINDER_INSTRUCTION.format(focus_area=focus_area),
        tools=create_finder_tools(container_name),
        output_key=f"finder_{container_name}_output",
    )
