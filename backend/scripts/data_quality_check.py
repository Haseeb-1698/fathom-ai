#!/usr/bin/env python3
"""
data_quality_check.py — Validate all expert training datasets before upload.

Checks:
  - Valid JSON on every line
  - Required fields: instruction, output (input optional)
  - Minimum lengths (instruction > 10 chars, output > 20 chars)
  - No empty fields
  - Length distribution stats
  - Duplicate detection
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def check_file(path: Path) -> dict:
    """Validate a single JSONL file. Returns stats dict."""
    stats = {
        "file": path.name,
        "total": 0,
        "valid": 0,
        "errors": [],
        "short_instruction": 0,
        "short_output": 0,
        "empty_instruction": 0,
        "empty_output": 0,
        "missing_instruction": 0,
        "missing_output": 0,
        "json_errors": 0,
        "instruction_lengths": [],
        "output_lengths": [],
        "duplicates": 0,
    }

    seen_hashes = set()

    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            stats["total"] += 1
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                stats["json_errors"] += 1
                if len(stats["errors"]) < 5:
                    stats["errors"].append(f"Line {i}: JSON error: {e}")
                continue

            # Check required fields
            instruction = row.get("instruction", "")
            output_text = row.get("output", "")

            if not instruction:
                if "instruction" not in row:
                    stats["missing_instruction"] += 1
                else:
                    stats["empty_instruction"] += 1
                continue

            if not output_text:
                if "output" not in row:
                    stats["missing_output"] += 1
                else:
                    stats["empty_output"] += 1
                continue

            # Length checks
            if len(instruction) < 10:
                stats["short_instruction"] += 1
            if len(output_text) < 20:
                stats["short_output"] += 1

            stats["instruction_lengths"].append(len(instruction))
            stats["output_lengths"].append(len(output_text))

            # Duplicate check (hash of instruction + output)
            h = hash(instruction + output_text)
            if h in seen_hashes:
                stats["duplicates"] += 1
            else:
                seen_hashes.add(h)

            stats["valid"] += 1

    return stats


def print_report(stats: dict):
    """Print a formatted quality report."""
    print(f"\n{'=' * 60}")
    print(f"  {stats['file']}")
    print(f"{'=' * 60}")
    print(f"  Total lines:          {stats['total']:,}")
    print(f"  Valid examples:       {stats['valid']:,}")
    print(f"  JSON errors:          {stats['json_errors']}")
    print(f"  Missing instruction:  {stats['missing_instruction']}")
    print(f"  Missing output:       {stats['missing_output']}")
    print(f"  Empty instruction:    {stats['empty_instruction']}")
    print(f"  Empty output:         {stats['empty_output']}")
    print(f"  Short instruction:    {stats['short_instruction']}")
    print(f"  Short output:         {stats['short_output']}")
    print(f"  Duplicates:           {stats['duplicates']}")

    if stats["instruction_lengths"]:
        lens = stats["instruction_lengths"]
        print(f"  Instruction len:      min={min(lens)}, "
              f"median={sorted(lens)[len(lens)//2]}, "
              f"max={max(lens)}, mean={sum(lens)/len(lens):.0f}")

    if stats["output_lengths"]:
        lens = stats["output_lengths"]
        print(f"  Output len:           min={min(lens)}, "
              f"median={sorted(lens)[len(lens)//2]}, "
              f"max={max(lens)}, mean={sum(lens)/len(lens):.0f}")

    if stats["errors"]:
        print(f"\n  Sample errors:")
        for e in stats["errors"]:
            print(f"    {e}")

    # Pass/fail
    issues = (stats["json_errors"] + stats["missing_instruction"] +
              stats["missing_output"] + stats["empty_instruction"] +
              stats["empty_output"])
    pct_issues = issues / max(stats["total"], 1) * 100
    verdict = "PASS" if pct_issues < 5 else "WARN" if pct_issues < 15 else "FAIL"
    print(f"\n  Issue rate: {pct_issues:.1f}% → {verdict}")

    return verdict


def main():
    parser = argparse.ArgumentParser(description="Validate expert training data")
    parser.add_argument("data_dir", type=str, help="Directory containing JSONL files")
    parser.add_argument("--output", type=str, default=None,
                        help="Save stats JSON to this path")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"Error: {data_dir} does not exist")
        sys.exit(1)

    jsonl_files = sorted(data_dir.glob("*.jsonl"))
    if not jsonl_files:
        print(f"No .jsonl files found in {data_dir}")
        sys.exit(1)

    all_stats = []
    overall_pass = True

    for path in jsonl_files:
        stats = check_file(path)
        verdict = print_report(stats)
        if verdict == "FAIL":
            overall_pass = False

        # Remove raw lists from saved stats (too large)
        save_stats = {k: v for k, v in stats.items()
                      if k not in ("instruction_lengths", "output_lengths", "errors")}
        all_stats.append(save_stats)

    print(f"\n{'=' * 60}")
    print(f"  OVERALL: {'PASS ✓' if overall_pass else 'ISSUES FOUND ⚠'}")
    print(f"  Files checked: {len(jsonl_files)}")
    total = sum(s["total"] for s in all_stats)
    valid = sum(s["valid"] for s in all_stats)
    print(f"  Total examples: {total:,} ({valid:,} valid)")
    print(f"{'=' * 60}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_stats, f, indent=2)
        print(f"\nStats saved to {args.output}")


if __name__ == "__main__":
    main()
