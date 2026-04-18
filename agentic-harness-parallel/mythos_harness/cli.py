"""CLI entry point for the parallel Mythos harness."""
from __future__ import annotations

import argparse
import asyncio
import os
from datetime import datetime, timezone

from .config import HarnessConfig, ModelConfig, TargetConfig
from .pipeline import run_parallel_assessment

C_BOLD = "\033[1m"
C_RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="Mythos Parallel Harness")
    parser.add_argument("target", help="Path to target directory (config.yaml + Dockerfile)")
    parser.add_argument("--focus-areas", nargs="+", default=None,
                        help="Focus areas (default: from config.yaml)")
    parser.add_argument("--finder-model", default=None)
    parser.add_argument("--orchestrator-model", default=None)
    parser.add_argument("--analyst-model", default=None)
    parser.add_argument("--runtime", default=None, choices=["kata-fc", "runsc", "runc"])
    parser.add_argument("--results-dir", default="results")

    args = parser.parse_args()
    target = TargetConfig.load(args.target)

    models = ModelConfig()
    if args.finder_model or args.orchestrator_model or args.analyst_model:
        models = ModelConfig(
            orchestrator=args.orchestrator_model or models.orchestrator,
            finder=args.finder_model or models.finder,
            verifier=args.orchestrator_model or models.verifier,
            analyst=args.analyst_model or models.analyst,
        )

    harness_config = HarnessConfig(models=models, results_dir=args.results_dir)
    if args.runtime:
        harness_config.sandbox_runtime = args.runtime

    focus_areas = args.focus_areas or target.focus_areas
    if not focus_areas:
        focus_areas = ["memory safety vulnerabilities"]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(harness_config.results_dir, target.name, ts)
    os.makedirs(run_dir, exist_ok=True)

    print(f"\n{C_BOLD}Mythos Parallel Harness{C_RESET}")
    print(f"  Target:       {C_BOLD}{target.name}{C_RESET}")
    print(f"  Finder:       {harness_config.models.finder}")
    print(f"  Analyst:      {harness_config.models.analyst}")
    print(f"  Runtime:      {harness_config.sandbox_runtime}")
    print(f"  Focus areas:  {len(focus_areas)}")
    for i, area in enumerate(focus_areas):
        print(f"    {i}: {area}")
    print(f"  Results:      {run_dir}")
    print("-" * 60)

    asyncio.run(run_parallel_assessment(target, focus_areas, harness_config, run_dir))


if __name__ == "__main__":
    main()
