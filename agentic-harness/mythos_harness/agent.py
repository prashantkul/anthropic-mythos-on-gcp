"""Root agent definition — ADK convention entry point.

ADK expects agent.py at the package root with `root_agent` as the exported name.
Wires the Opus orchestrator with default target config and harness settings.
"""
from .agents.orchestrator import create as create_orchestrator
from .config import HarnessConfig, TargetConfig

_DEFAULT_TARGET = TargetConfig(
    name="default",
    dockerfile_dir=".",
    image_tag="mythos-sandbox:latest",
    source_root="/target/src",
    binary_path="/target/bin/target",
)

root_agent = create_orchestrator(
    harness_config=HarnessConfig(),
    target=_DEFAULT_TARGET,
    run_dir="results/default",
)
