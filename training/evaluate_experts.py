#!/usr/bin/env python3
"""
evaluate_experts.py — Per-expert + combined evaluation.

Runs the same benchmark script with different adapters to produce
comparison tables: base vs unified v1 vs unified v2 vs expert adapters.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


BENCHMARK_SCRIPT = Path(__file__).parent / "benchmark_mixtral_hf.py"

ADAPTER_CONFIGS = {
    "base": {
        "name": "Base Mixtral (no adapter)",
        "adapter_path": None,
    },
    "unified_v1": {
        "name": "Unified v1 (Plan A)",
        "adapter_path": "/workspace/adapters/fathom-unified-v1/lora-adapter",
    },
    "unified_v2": {
        "name": "Unified v2 (Plan B)",
        "adapter_path": "/workspace/adapters/fathom-unified-v2/lora-adapter",
    },
    "e2_dynamic": {
        "name": "E2 Dynamic Behavior Expert",
        "adapter_path": "/workspace/adapters/expert-e2-dynamic",
    },
    "e7_reports": {
        "name": "E7 Report Generation Expert",
        "adapter_path": "/workspace/adapters/expert-e7-reports",
    },
    "e1_static": {
        "name": "E1 Static Analysis Expert (stretch)",
        "adapter_path": "/workspace/adapters/expert-e1-static",
    },
    "e5_threatintel": {
        "name": "E5 Threat Intelligence Expert (stretch)",
        "adapter_path": "/workspace/adapters/expert-e5-threatintel",
    },
}


def run_eval(config_name: str, config: dict, workdir: str,
             max_new_eval: int, max_new_cyber: int, max_new_malware: int):
    """Run benchmark for a single adapter configuration."""
    print(f"\n{'=' * 60}")
    print(f"  Evaluating: {config['name']}")
    print(f"{'=' * 60}")

    cmd = [
        sys.executable, str(BENCHMARK_SCRIPT),
        "--workdir", workdir,
        "--out-tag", config_name,
        "--max-new-eval", str(max_new_eval),
        "--max-new-cyber", str(max_new_cyber),
        "--max-new-malware", str(max_new_malware),
    ]

    if config["adapter_path"]:
        if not Path(config["adapter_path"]).exists():
            print(f"  [SKIP] Adapter not found: {config['adapter_path']}")
            return None
        cmd.extend(["--adapter-path", config["adapter_path"]])

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print(f"  [FAIL] {e}")
        return None

    # Find the output directory
    import glob
    pattern = os.path.join(workdir, "baseline_outputs", f"{config_name}_*")
    dirs = sorted(glob.glob(pattern))
    if dirs:
        metrics_file = os.path.join(dirs[-1], "aggregate_metrics.json")
        if os.path.exists(metrics_file):
            with open(metrics_file) as f:
                return json.load(f)

    return None


def build_comparison_table(results: dict) -> str:
    """Build a markdown comparison table from results."""
    rows = []
    header = "| Configuration | CyberMetric Acc | Structure | ATT&CK | Reasoning | Evidence | Usefulness |"
    separator = "|---|---|---|---|---|---|---|"
    rows.append(header)
    rows.append(separator)

    for name, metrics in results.items():
        if metrics is None:
            rows.append(f"| {name} | SKIPPED | - | - | - | - | - |")
            continue

        cyber = metrics.get("cybermetric_80", {}).get("accuracy", "?")
        rubric = metrics.get("malware_eval_25", {}).get("rubric_means", {})

        rows.append(
            f"| {name} | {cyber} | "
            f"{rubric.get('structure', '?')} | "
            f"{rubric.get('attck_correctness', '?')} | "
            f"{rubric.get('malware_reasoning', '?')} | "
            f"{rubric.get('evidence_awareness', '?')} | "
            f"{rubric.get('analyst_usefulness', '?')} |"
        )

    return "\n".join(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", default="/workspace")
    parser.add_argument("--configs", nargs="+",
                        default=["base", "unified_v2", "e2_dynamic", "e7_reports"],
                        help="Which configs to evaluate")
    parser.add_argument("--max-new-eval", type=int, default=64)
    parser.add_argument("--max-new-cyber", type=int, default=48)
    parser.add_argument("--max-new-malware", type=int, default=256)
    args = parser.parse_args()

    results = {}
    for config_name in args.configs:
        if config_name not in ADAPTER_CONFIGS:
            print(f"Unknown config: {config_name}")
            continue
        config = ADAPTER_CONFIGS[config_name]
        metrics = run_eval(config_name, config, args.workdir,
                          args.max_new_eval, args.max_new_cyber, args.max_new_malware)
        results[config["name"]] = metrics

    # Build and save comparison
    table = build_comparison_table(results)
    print(f"\n{'=' * 60}")
    print("  COMPARISON TABLE")
    print(f"{'=' * 60}")
    print(table)

    output_path = os.path.join(args.workdir, "expert_comparison.md")
    with open(output_path, "w") as f:
        f.write("# Fathom Expert Adapter Evaluation\n\n")
        f.write(table)
        f.write("\n")

    # Also save raw results
    raw_path = os.path.join(args.workdir, "expert_comparison_raw.json")
    with open(raw_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
