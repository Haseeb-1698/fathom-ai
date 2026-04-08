#!/usr/bin/env python3
"""
convert_static_to_instruct.py — Convert static analysis datasets to Alpaca JSONL
for E1 Static Analysis expert.

Sources:
  - joyce8/EMBER2024 (HF) — PE feature vectors
  - joyce8/EMBER2024-capa (HF) — CAPA capability extractions
  - rr4433/Powershell_Malware_Detection_Dataset (HF) — PowerShell malware scripts

Output: data/processed/e1_static.jsonl
"""

import argparse
import json
import random
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

STATIC_INSTRUCTIONS = [
    "Analyze the following PE file features and determine if this executable is malicious. Explain your reasoning.",
    "Given these static analysis features from a PE binary, classify it and identify suspicious indicators.",
    "Review the following PE header information and import table data. Is this file benign or malicious?",
    "Examine these extracted PE features and provide a static analysis assessment.",
    "Based on the PE metadata below, determine the likely nature of this executable.",
]

CAPA_INSTRUCTIONS = [
    "Analyze the following CAPA capability extraction results and identify what this executable can do.",
    "Review these CAPA-detected capabilities and assess the threat level of this binary.",
    "Given these automated capability detections, determine if this sample is malicious and what its purpose is.",
]

POWERSHELL_INSTRUCTIONS = [
    "Analyze this PowerShell script for malicious behavior. Identify obfuscation, suspicious commands, and potential impact.",
    "Review this PowerShell code and determine if it is malicious. Explain the indicators.",
    "Examine this PowerShell script for signs of malware. What techniques does it use?",
]

LABEL_MAP = {0: "benign", 1: "malicious", -1: "unknown"}


def convert_ember2024(input_path: Path, output_path: Path, max_rows: int = 100000) -> int:
    """Convert EMBER2024 PE feature dataset."""
    if not input_path.exists():
        print(f"[SKIP] EMBER2024 not found at {input_path}")
        return 0

    rows = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    random.seed(42)
    if len(rows) > max_rows:
        rows = random.sample(rows, max_rows)

    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for row in rows:
            # Build feature summary from whatever columns are present
            feature_parts = []
            for key in ["sha256", "md5", "size", "virtual_size", "machine",
                        "entry_point", "has_debug", "has_signature", "has_tls",
                        "exports", "imports", "sections"]:
                if key in row and key != "label":
                    val = row[key]
                    if isinstance(val, (list, dict)):
                        val = json.dumps(val)[:200]
                    feature_parts.append(f"{key}: {val}")

            if not feature_parts:
                # Fallback: dump all non-label fields
                for k, v in list(row.items())[:15]:
                    if k != "label":
                        feature_parts.append(f"{k}: {str(v)[:200]}")

            if not feature_parts:
                continue

            features_text = "\n".join(feature_parts)
            label = row.get("label", -1)
            if isinstance(label, str):
                label = {"malicious": 1, "benign": 0, "malware": 1}.get(label.lower(), -1)

            verdict = LABEL_MAP.get(label, "unknown")
            instruction = random.choice(STATIC_INSTRUCTIONS)

            output_text = (
                f"## Static Analysis Verdict: {verdict.upper()}\n\n"
                f"{'This executable exhibits characteristics consistent with malware.' if verdict == 'malicious' else 'This executable appears to be legitimate software.' if verdict == 'benign' else 'Insufficient features for a definitive determination.'}\n\n"
                f"### Key Indicators\n\n"
                f"{features_text[:500]}\n\n"
                f"### Recommendation\n\n"
                f"{'Quarantine and proceed with dynamic analysis.' if verdict == 'malicious' else 'No immediate action required. Monitor during execution.' if verdict == 'benign' else 'Proceed with dynamic analysis for complete assessment.'}"
            )

            record = {
                "instruction": instruction,
                "input": features_text[:2000],
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} EMBER2024 rows → {output_path.name}")
    return count


def convert_ember_capa(input_path: Path, output_path: Path, max_rows: int = 50000) -> int:
    """Convert EMBER2024-CAPA capability extractions."""
    if not input_path.exists():
        print(f"[SKIP] EMBER2024-CAPA not found at {input_path}")
        return 0

    rows = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    random.seed(43)
    if len(rows) > max_rows:
        rows = random.sample(rows, max_rows)

    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for row in rows:
            # CAPA output typically has capabilities/rules matched
            capa_parts = []
            for k, v in row.items():
                if k in ("label", "sha256", "md5"):
                    continue
                capa_parts.append(f"{k}: {str(v)[:300]}")

            if not capa_parts:
                continue

            capa_text = "\n".join(capa_parts[:20])
            instruction = random.choice(CAPA_INSTRUCTIONS)

            output_text = (
                f"## CAPA Capability Analysis\n\n"
                f"The following capabilities were detected in this binary:\n\n"
                f"{capa_text[:800]}\n\n"
                f"### Threat Assessment\n\n"
                f"Based on the detected capabilities, this binary should be treated as potentially malicious.\n\n"
                f"### Recommendation\n\n"
                f"1. Correlate CAPA findings with behavioral analysis\n"
                f"2. Check for matching YARA signatures\n"
                f"3. Submit to sandbox for dynamic analysis"
            )

            record = {
                "instruction": instruction,
                "input": capa_text[:2000],
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} EMBER2024-CAPA rows → {output_path.name}")
    return count


def convert_powershell(input_path: Path, output_path: Path) -> int:
    """Convert PowerShell malware detection dataset."""
    if not input_path.exists():
        print(f"[SKIP] PowerShell malware not found at {input_path}")
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

            # Schema varies — look for code/script + label
            code = row.get("code", row.get("script", row.get("text", row.get("content", ""))))
            label = row.get("label", row.get("class", row.get("is_malicious", "")))

            if not code or len(code) < 20:
                continue

            is_malicious = str(label).lower() in ("1", "true", "malicious", "malware", "yes")

            instruction = random.choice(POWERSHELL_INSTRUCTIONS)
            verdict = "MALICIOUS" if is_malicious else "BENIGN"

            output_text = (
                f"## PowerShell Analysis Verdict: {verdict}\n\n"
                f"{'This PowerShell script contains malicious behavior.' if is_malicious else 'This PowerShell script appears to be benign.'}\n\n"
                f"### Script Analysis\n\n"
                f"The script {'uses obfuscation and suspicious cmdlets' if is_malicious else 'performs standard administrative tasks'}.\n\n"
                f"### Recommendation\n\n"
                f"{'Block execution, investigate source, and check for persistence.' if is_malicious else 'No action required.'}"
            )

            record = {
                "instruction": instruction,
                "input": f"PowerShell Script:\n```powershell\n{code[:2000]}\n```",
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} PowerShell malware rows → {output_path.name}")
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-ember-rows", type=int, default=100000)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    out_path = Path(args.output) if args.output else OUT_DIR / "e1_static.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("")  # truncate

    total = 0
    total += convert_ember2024(RAW_DIR / "ember2024.jsonl", out_path, args.max_ember_rows)
    total += convert_ember_capa(RAW_DIR / "ember2024_capa.jsonl", out_path)
    total += convert_powershell(RAW_DIR / "powershell_malware.jsonl", out_path)

    print(f"\nTotal E1 Static examples: {total}")


if __name__ == "__main__":
    main()
