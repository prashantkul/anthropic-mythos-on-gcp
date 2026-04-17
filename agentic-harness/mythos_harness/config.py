import os
from dataclasses import dataclass, field
from pathlib import Path

import google.auth
import yaml

_, project_id = google.auth.default()
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", project_id or "")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "us-central1")
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True")

SANDBOX_RUNTIME = os.environ.get("MYTHOS_SANDBOX_RUNTIME", "kata-fc")
SANDBOX_MEMORY = os.environ.get("MYTHOS_SANDBOX_MEMORY", "8g")
SANDBOX_NETWORK = "none"


@dataclass(frozen=True)
class ModelConfig:
    orchestrator: str = "claude-opus@latest"
    finder: str = "claude-mythos@latest"
    verifier: str = "claude-opus@latest"
    analyst: str = "claude-opus@latest"


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
