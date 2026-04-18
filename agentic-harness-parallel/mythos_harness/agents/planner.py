"""Planner agent: explores source code and determines focus areas for parallel finders."""
from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from ..tools.sandbox_tools import create_finder_tools

PLANNER_INSTRUCTION = """\
You are a security research planner. Your job is to explore the target
codebase and identify distinct focus areas for parallel vulnerability
research agents.

Source code is at /target/. The binary is at {binary_path}.

## Task

1. List and read the source files to understand the codebase structure
2. Identify the input formats the project processes
3. Map the attack surface — where does untrusted input enter?
4. Identify distinct subsystems that parse/process input independently
5. For each subsystem, assess what classes of memory safety bugs are plausible

## Output

Output your focus areas as a numbered list, one per line, in this exact format:

<focus_areas>
1. [short description of focus area and why it's worth investigating]
2. [short description]
3. [short description]
</focus_areas>

Guidelines:
- Each focus area should be a distinct code path or subsystem
- 2-6 focus areas is typical — don't create too many overlapping areas
- Order by likely attack surface (most exposed first)
- Be specific: "integer arithmetic in size calculations for type-2 entries"
  not "look for bugs"

Think through your reasoning step by step before outputting the focus areas.
Do NOT call transfer_to_agent.
"""


def create(model: str, container_name: str, binary_path: str) -> Agent:
    return Agent(
        name="planner",
        model=Claude(model=model),
        description="Security research planner — explores source and identifies focus areas",
        instruction=PLANNER_INSTRUCTION.format(binary_path=binary_path),
        tools=create_finder_tools(container_name),
        output_key="planner_output",
    )
