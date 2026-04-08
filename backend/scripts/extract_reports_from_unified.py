#!/usr/bin/env python3
"""
extract_reports_from_unified.py — Extract report-style examples from Plan A's
fathom_train_combined.jsonl to supplement E7 Report Generation training data.

Filters by keywords: analysis report, malware report, executive summary,
incident response, ATT&CK mapping, threat assessment, etc.

Targets ~15-20K high-quality report-oriented examples from the 127K unified set.

Output: data/processed/e7_unified_supplement.jsonl
"""

import argparse
import json
import random
from pathlib import Path

REPORT_KEYWORDS = {
    # Strong signal — these are almost certainly report-relevant
    "analysis report", "malware report", "executive summary",
    "incident report", "threat assessment", "security report",
    "findings", "recommendations", "investigation report",

    # Medium signal — report-adjacent
    "att&ck", "mitre", "technique", "tactic",
    "indicator of compromise", "ioc",
    "threat actor", "campaign",
    "remediation", "containment", "eradication",
    "detection rule", "yara", "sigma",

    # Weaker signal — still useful for report generation style
    "malware analysis", "behavioral analysis", "static analysis",
    "dynamic analysis", "sandbox", "reverse engineer",
    "vulnerability", "exploit", "cve-",
    "phishing", "ransomware", "trojan", "backdoor",
    "command and control", "c2", "lateral movement",
    "persistence", "privilege escalation", "defense evasion",
    "exfiltration", "credential",
}

# These indicate the output is report-structured (has sections/headers)
STRUCTURE_MARKERS = {
    "##", "###", "**finding", "**recommendation",
    "executive summary", "technical detail",
    "1.", "2.", "3.",  # numbered lists
    "- ", "* ",        # bullet lists
}


def score_row(row: dict) -> float:
    """Score a row for report-relevance. Higher = more relevant."""
    instruction = (row.get("instruction", "") or "").lower()
    output_text = (row.get("output", "") or "").lower()
    input_text = (row.get("input", "") or "").lower()
    combined = instruction + " " + output_text + " " + input_text

    score = 0.0

    # Keyword matches
    for kw in REPORT_KEYWORDS:
        if kw in combined:
            score += 1.0

    # Bonus for structured output (has markdown headers, lists)
    for marker in STRUCTURE_MARKERS:
        if marker in output_text:
            score += 0.3

    # Bonus for longer, more detailed outputs (reports are detailed)
    output_len = len(output_text)
    if output_len > 500:
        score += 1.0
    if output_len > 1000:
        score += 1.0
    if output_len > 2000:
        score += 0.5

    # Penalty for very short outputs (not report-like)
    if output_len < 100:
        score -= 2.0

    # Bonus if instruction explicitly asks for a report
    report_ask_keywords = ["write a report", "generate a report", "create a report",
                           "produce a report", "draft a report", "summarize",
                           "provide an analysis", "analyze and report"]
    for kw in report_ask_keywords:
        if kw in instruction:
            score += 3.0

    return score


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, required=True,
                        help="Path to fathom_train_combined.jsonl (Plan A)")
    parser.add_argument("--output", type=str, required=True,
                        help="Output JSONL path")
    parser.add_argument("--min-score", type=float, default=2.0,
                        help="Minimum relevance score to include")
    parser.add_argument("--max-rows", type=int, default=20000,
                        help="Maximum rows to extract")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        print(f"Error: {input_path} does not exist")
        return

    print(f"Scanning {input_path} for report-style examples...")
    print(f"Min score: {args.min_score}, Max rows: {args.max_rows}")

    # Score all rows
    scored = []
    total = 0
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            total += 1
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            s = score_row(row)
            if s >= args.min_score:
                scored.append((s, row))

    print(f"Scanned {total:,} rows, {len(scored):,} above min score {args.min_score}")

    # Sort by score descending, take top N
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = scored[:args.max_rows]

    # Shuffle to avoid clustering by source
    random.seed(42)
    random.shuffle(selected)

    # Write output
    count = 0
    with open(output_path, "w", encoding="utf-8") as out:
        for score, row in selected:
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1

    print(f"Extracted {count:,} report-style examples → {output_path}")

    # Score distribution
    if scored:
        scores = [s for s, _ in scored]
        print(f"Score range: {min(scores):.1f} — {max(scores):.1f}")
        print(f"Mean score: {sum(scores)/len(scores):.1f}")

        # Breakdown by score bucket
        buckets = {}
        for s, _ in scored:
            bucket = int(s)
            buckets[bucket] = buckets.get(bucket, 0) + 1
        print("Score distribution:")
        for b in sorted(buckets.keys()):
            print(f"  score {b}-{b+1}: {buckets[b]:,} rows")


if __name__ == "__main__":
    main()
