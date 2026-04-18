import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SANDBOX_RUNTIME = os.environ.get("MYTHOS_SANDBOX_RUNTIME", "runsc")
SANDBOX_MEMORY = os.environ.get("MYTHOS_SANDBOX_MEMORY", "8g")
SANDBOX_NETWORK = "none"

OPUS_MODEL = os.environ.get("MYTHOS_OPUS_MODEL", "claude-opus-4-7")
FINDER_MODEL = os.environ.get("MYTHOS_FINDER_MODEL", OPUS_MODEL)


@dataclass(frozen=True)
class ModelConfig:
    orchestrator: str = OPUS_MODEL
    finder: str = FINDER_MODEL
    verifier: str = OPUS_MODEL
    analyst: str = OPUS_MODEL


@dataclass(frozen=True)
class TargetConfig:
    name: str
    dockerfile_dir: str
    image_tag: str
    source_root: str
    binary_path: str
    focus_areas: list[str] = field(default_factory=list)
    known_bugs: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, target_dir: str | Path) -> "TargetConfig":
        target_dir = Path(target_dir).resolve()
        config_path = target_dir / "config.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"No config.yaml in {target_dir}")
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cls(
            name=target_dir.name,
            dockerfile_dir=str(target_dir),
            image_tag=cfg["image_tag"],
            source_root=cfg["source_root"],
            binary_path=cfg["binary_path"],
            focus_areas=cfg.get("focus_areas") or [],
            known_bugs=cfg.get("known_bugs") or [],
        )


@dataclass
class HarnessConfig:
    models: ModelConfig = field(default_factory=ModelConfig)
    sandbox_runtime: str = SANDBOX_RUNTIME
    sandbox_memory: str = SANDBOX_MEMORY
    max_find_turns: int = 2000
    max_grade_turns: int = 50
    max_analyst_turns: int = 100
    max_delegations: int = 10
    results_dir: str = "results"
