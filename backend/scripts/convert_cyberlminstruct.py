#!/usr/bin/env python3
"""
convert_cyberlminstruct.py — Convert cybersecurity instruction datasets to Alpaca JSONL
for E7 Report Generation expert.

Sources:
  - Tiamz/CybersecurityInstructions (HF) — cybersec Q&A pairs
  - MalwareTextDB — annotated malware reports
  - APTnotes — APT report text (if available)
  - Plan A training data (report-relevant subset)

Output: data/processed/e7_reports.jsonl (~65K)
"""

import argparse
import json
import os
import random
import re
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
PLAN_A_DATA = Path(__file__).resolve().parent.parent.parent.parent / "data" / "processed"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

REPORT_INSTRUCTIONS = [
    "Write a structured malware analysis report based on the following information.",
    "Generate a comprehensive security analysis report with ATT&CK technique mappings.",
    "Create an executive summary and technical findings report for this malware sample.",
    "Produce a formal incident analysis report including IOCs, TTPs, and recommendations.",
    "Draft a threat analysis report documenting the behaviors, techniques, and mitigations.",
]

ATTCK_MAPPING_INSTRUCTIONS = [
    "Map the following malware behaviors to MITRE ATT&CK techniques and provide analysis.",
    "Identify the ATT&CK techniques demonstrated in this analysis and explain each mapping.",
    "Given this behavioral summary, produce ATT&CK technique mappings with confidence ratings.",
]


def convert_tiamz(input_path: Path, output_path: Path) -> int:
    """Convert Tiamz CybersecurityInstructions to report-focused JSONL."""
    if not input_path.exists():
        print(f"[SKIP] Tiamz not found at {input_path}")
        return 0

    count = 0
    with open(input_path, "r", encoding="utf-8") as f, \
         open(output_path, "a", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)

            # Tiamz schema: instruction + answer
            instruction = row.get("instruction", "")
            input_text = ""
            output_text = row.get("answer", row.get("output", ""))

            if not instruction or not output_text:
                continue

            # Filter: keep only report/analysis/ATT&CK related entries
            combined = (instruction + " " + output_text).lower()
            report_keywords = ["report", "analysis", "technique", "att&ck", "mitre",
                              "summary", "finding", "malware", "threat", "incident",
                              "vulnerability", "exploit", "ioc", "ttp"]
            if not any(kw in combined for kw in report_keywords):
                # Keep anyway but with lower probability (general cybersec is still useful)
                if random.random() > 0.5:
                    continue

            record = {
                "instruction": instruction.strip(),
                "input": input_text.strip(),
                "output": output_text.strip(),
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} Tiamz rows → {output_path.name}")
    return count


def convert_malware_textdb(input_path: Path, output_path: Path) -> int:
    """Convert naorm/malware-text-db — annotated malware report texts.

    Schema: text (long annotated malware report paragraphs)
    """
    if not input_path.exists():
        print(f"[SKIP] MalwareTextDB not found at {input_path}")
        return 0

    count = 0
    with open(input_path, "r", encoding="utf-8") as f, \
         open(output_path, "a", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            text = row.get("text", "")
            if not text or len(text) < 100:
                continue

            # These are real malware analysis report texts — high quality
            instruction = random.choice(REPORT_INSTRUCTIONS)
            # Use the text as both context and as a model for what good reports look like
            record = {
                "instruction": instruction,
                "input": f"Source material:\n{text[:1500]}",
                "output": (
                    f"## Malware Analysis Report\n\n"
                    f"{text[:2000]}\n\n"
                    f"### Summary\n\n"
                    f"This report documents malware behaviors observed during analysis. "
                    f"Refer to the ATT&CK framework for technique classification."
                ),
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} MalwareTextDB rows → {output_path.name}")
    return count


def convert_apt_notes(input_path: Path, output_path: Path) -> int:
    """Convert clydeiii/cybersecurity — APT notes and cybersecurity reports."""
    if not input_path.exists():
        print(f"[SKIP] APT Notes not found at {input_path}")
        return 0

    count = 0
    with open(input_path, "r", encoding="utf-8") as f, \
         open(output_path, "a", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Try common column names
            text = row.get("text", row.get("content", row.get("body", "")))
            title = row.get("title", row.get("name", ""))

            if not text or len(text) < 100:
                continue

            instruction = random.choice(REPORT_INSTRUCTIONS)
            input_text = title + "\n\n" + text[:1500] if title else text[:1500]

            record = {
                "instruction": instruction,
                "input": input_text,
                "output": (
                    f"## Analysis Report" + (f": {title}" if title else "") + "\n\n"
                    f"{text[:2000]}\n\n"
                    f"### Recommendations\n\n"
                    f"1. Review indicators mentioned in the report\n"
                    f"2. Update detection signatures\n"
                    f"3. Brief relevant security teams"
                ),
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} APT Notes rows → {output_path.name}")
    return count


def extract_plan_a_reports(plan_a_path: Path, output_path: Path,
                           max_rows: int = 20000) -> int:
    """Extract report-relevant entries from Plan A training data."""
    # Accept either a direct file path or a directory containing the file
    if plan_a_path.is_file():
        train_file = plan_a_path
    else:
        train_file = plan_a_path / "fathom_train_combined.jsonl"
    if not train_file.exists():
        print(f"[SKIP] Plan A data not found at {train_file}")
        return 0

    report_keywords = {"report", "analysis", "summary", "att&ck", "mitre",
                       "technique", "finding", "threat", "incident"}

    candidates = []
    with open(train_file, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line.strip())
            instruction = row.get("instruction", "").lower()
            output_text = row.get("output", "").lower()
            combined = instruction + " " + output_text

            if any(kw in combined for kw in report_keywords):
                candidates.append(row)

    random.seed(42)
    if len(candidates) > max_rows:
        candidates = random.sample(candidates, max_rows)

    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for row in candidates:
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1

    print(f"Extracted {count} report-relevant Plan A rows → {output_path.name}")
    return count


def generate_report_templates(output_path: Path, n: int = 5000) -> int:
    """Generate structured report template examples."""
    families = ["Emotet", "TrickBot", "Cobalt Strike", "Qakbot", "IcedID",
                "AgentTesla", "Remcos", "AsyncRAT", "NjRAT", "RedLine",
                "WinosStager", "LockBit", "Conti", "REvil", "BlackCat"]
    techniques = [
        ("T1055", "Process Injection"),
        ("T1059.001", "PowerShell"),
        ("T1547.001", "Registry Run Keys"),
        ("T1053.005", "Scheduled Task"),
        ("T1071.001", "Web Protocols"),
        ("T1027", "Obfuscated Files"),
        ("T1036", "Masquerading"),
        ("T1082", "System Information Discovery"),
        ("T1083", "File and Directory Discovery"),
        ("T1005", "Data from Local System"),
    ]

    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for i in range(n):
            family = random.choice(families)
            num_techniques = random.randint(2, 5)
            selected_techs = random.sample(techniques, min(num_techniques, len(techniques)))

            tech_lines = "\n".join(
                f"- **{tid}** ({tname}): Observed in execution trace"
                for tid, tname in selected_techs
            )

            instruction = random.choice(REPORT_INSTRUCTIONS)
            input_text = (
                f"Malware Family: {family}\n"
                f"Observed Techniques: {', '.join(t[0] for t in selected_techs)}\n"
                f"Sample Type: PE32 executable\n"
                f"Analysis Environment: Windows 10 sandbox"
            )
            output_text = (
                f"# Malware Analysis Report: {family}\n\n"
                f"## Executive Summary\n\n"
                f"This report documents the analysis of a {family} sample. "
                f"The sample demonstrates {num_techniques} distinct ATT&CK techniques "
                f"and poses a significant threat to enterprise environments.\n\n"
                f"## MITRE ATT&CK Mapping\n\n{tech_lines}\n\n"
                f"## Recommendations\n\n"
                f"1. Update endpoint detection signatures for {family} variants\n"
                f"2. Monitor for the identified behavioral indicators\n"
                f"3. Implement network-level detection for C2 communication patterns\n"
                f"4. Review and harden endpoint configurations"
            )

            record = {
                "instruction": instruction,
                "input": input_text,
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Generated {count} report templates → {output_path.name}")
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--plan-a-data", type=str, default=None,
                        help="Path to directory containing fathom_train_combined.jsonl")
    args = parser.parse_args()

    out_path = Path(args.output) if args.output else OUT_DIR / "e7_reports.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0

    # Truncate output file first so all appends are clean
    out_path.write_text("")

    # Tiamz cybersec instructions (13,190 rows)
    total += convert_tiamz(RAW_DIR / "tiamz_cybersec.jsonl", out_path)

    # MalwareTextDB (38 annotated reports — small but high-quality)
    total += convert_malware_textdb(RAW_DIR / "malware_textdb.jsonl", out_path)

    # APT Notes / cybersecurity reports (clydeiii/cybersecurity)
    total += convert_apt_notes(RAW_DIR / "apt_notes_cybersec.jsonl", out_path)

    # Plan A report-relevant subset
    plan_a_dir = Path(args.plan_a_data) if args.plan_a_data else PLAN_A_DATA
    total += extract_plan_a_reports(plan_a_dir, out_path)

    # Generated report templates (supplement)
    total += generate_report_templates(out_path, n=5000)

    print(f"\nTotal E7 Report Generation examples: {total}")


if __name__ == "__main__":
    main()
