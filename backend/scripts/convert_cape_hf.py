#!/usr/bin/env python3
"""
convert_cape_hf.py — Download real CAPE sandbox reports from HuggingFace and
convert them to Alpaca instruction pairs using cape_extraction_layer_v3.

Source:
  unileon-robotics/malware-samples — real CAPEv2 sandbox JSON reports
  (~1K-10K samples with full behavioral data, process trees, signatures, network)

Also downloads supplementary CTI datasets:
  reloading0101/threat-intelligence-dataset — 52K ATT&CK-mapped instruction pairs
  Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset — 53K security Q&A pairs

Output:
  data/processed/cape_hf_reports.jsonl      — behavioral analysis pairs from CAPE reports
  data/processed/cti_supplement.jsonl       — CTI instruction pairs (filtered for quality)

Usage:
  python3 convert_cape_hf.py --hf-token hf_xxx --output-dir data/processed/
  python3 convert_cape_hf.py  # uses HF_TOKEN env var or anonymous access
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

try:
    from datasets import load_dataset
    from huggingface_hub import hf_hub_download, snapshot_download
except ImportError:
    print("ERROR: pip install datasets huggingface_hub")
    sys.exit(1)

SCRIPTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPTS_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

RAW_DIR = BACKEND_DIR.parent / "data" / "raw"
OUT_DIR = BACKEND_DIR.parent / "data" / "processed"

INSTRUCTION_ANALYZE = [
    "Analyze this CAPE sandbox execution report and produce a detailed malware analysis with ATT&CK technique mapping.",
    "You are a malware analyst. Given the following sandbox behavioral evidence, write a comprehensive analysis report.",
    "Review this CAPEv2 sandbox report and identify the malware family, behaviors, and MITRE ATT&CK techniques.",
    "Analyze the following dynamic analysis evidence and produce a structured malware report with IOCs and technique mappings.",
    "Given this sandbox execution data, classify the malware, explain its behavior, and map techniques to MITRE ATT&CK.",
    "Examine this behavioral sandbox report and produce a threat analysis with kill chain and detection recommendations.",
    "Based on the following CAPE sandbox execution evidence, identify malware type, persistence mechanisms, and C2 indicators.",
]

INSTRUCTION_ATTCK = [
    "Map the observed behaviors in this sandbox report to MITRE ATT&CK techniques with evidence for each mapping.",
    "Identify all MITRE ATT&CK techniques in this malware execution. Justify each mapping with behavioral evidence.",
    "Given this behavioral evidence, produce a structured ATT&CK technique mapping with confidence ratings.",
]

INSTRUCTION_SUMMARY = [
    "Write an executive summary of this malware analysis for a security operations team.",
    "Produce a concise threat assessment and executive summary from this sandbox analysis.",
    "Summarize the key findings for an incident response team.",
]


def build_output_from_cape_dict(report: dict) -> tuple[str, str, str]:
    """Extract evidence and build output strings from a CAPE report dict."""
    # Try to use the v3 extractor if available
    try:
        from evidence.cape_extractor import extract_from_cape_dict, format_evidence_text
        brief = extract_from_cape_dict(report)
        evidence_text = format_evidence_text(brief)
        family = brief.detections[0]["family"] if brief.detections else "Unknown"
        score = getattr(brief, "threat_score", 0) or 0
    except Exception:
        # Fallback: manual extraction
        evidence_text, family, score = _manual_extract(report)

    if not evidence_text or len(evidence_text) < 50:
        return "", "", ""

    # Build analysis output
    behavior = report.get("behavior", {})
    signatures = report.get("signatures", []) or []
    network = report.get("network", {}) or {}
    processes = behavior.get("processes", behavior.get("processtree", [])) or []

    # Signatures
    sig_lines = []
    for s in signatures[:8]:
        if isinstance(s, dict):
            sev = s.get("severity", "")
            name = s.get("name", "")
            desc = s.get("description", "")[:200]
            if name:
                sig_lines.append(f"- **[{sev}] {name}**: {desc}")

    # ATT&CK from signatures
    techniques = {}
    for s in signatures:
        if isinstance(s, dict):
            for att in s.get("attck", s.get("ttp", [])) or []:
                if isinstance(att, dict):
                    tid = att.get("id", att.get("technique_id", ""))
                    tname = att.get("name", att.get("technique_name", ""))
                    tactic = att.get("tactic", "")
                    if tid:
                        techniques[tid] = (tname, tactic)

    # Network IOCs
    dns = network.get("dns", []) or []
    dns_domains = [d.get("request", d.get("domain", "")) for d in dns[:8] if isinstance(d, dict)]
    hosts = network.get("hosts", []) or []
    host_ips = [h.get("ip", h) if isinstance(h, dict) else h for h in hosts[:8]]

    # Full analysis output
    tech_text = "\n".join(
        f"- **{tid}** {name}" + (f" (Tactic: {tac})" if tac else "")
        for tid, (name, tac) in list(techniques.items())[:10]
    ) or "- Technique mapping requires further analysis"

    ioc_lines = []
    if dns_domains:
        ioc_lines.extend([f"  Domain: {d}" for d in dns_domains[:5] if d])
    if host_ips:
        ioc_lines.extend([f"  IP: {ip}" for ip in host_ips[:5] if ip])
    ioc_text = "\n".join(ioc_lines) or "  None captured"

    sig_text = "\n".join(sig_lines[:6]) or "- General malicious behavior detected"

    analysis_out = (
        f"## Malware Analysis Report\n\n"
        f"**Classification:** {family}\n"
        f"**Threat Score:** {score}/10\n\n"
        f"## Executive Summary\n\n"
        f"CAPEv2 sandbox analysis of this sample confirms {family} behavior. "
        f"The sample triggered {len(signatures)} behavioral signature(s) during execution.\n\n"
        f"## Behavioral Observations\n\n{sig_text}\n\n"
        f"## MITRE ATT&CK Mapping\n\n{tech_text}\n\n"
        f"## Indicators of Compromise\n\n{ioc_text}\n\n"
        f"## Recommendations\n\n"
        f"1. Isolate affected endpoint and collect forensic evidence\n"
        f"2. Block identified network IOCs at perimeter\n"
        f"3. Hunt for similar samples using the behavioral signatures\n"
        f"4. Update detection rules based on observed TTPs"
    )

    attck_out = ""
    if techniques:
        tech_lines = [
            f"**{tid}** — {name}" + (f" (Tactic: {tac})" if tac else "")
            for tid, (name, tac) in list(techniques.items())[:12]
        ]
        attck_out = (
            f"## ATT&CK Technique Analysis — {family}\n\n"
            + "\n".join(f"- {l}" for l in tech_lines) +
            f"\n\n## Summary\n\n{len(techniques)} technique(s) mapped from behavioral evidence."
        )

    summary_out = (
        f"## Executive Summary\n\n"
        f"**Threat:** {family} | **Risk:** {'High' if score >= 7 else 'Medium' if score >= 4 else 'Low'}\n\n"
        f"CAPE sandbox analysis confirms {family} malware with {len(signatures)} behavioral signatures. "
        f"{'Network activity detected.' if dns_domains or host_ips else ''}\n\n"
        f"**Key Findings:**\n"
        f"- {len(techniques)} ATT&CK techniques mapped\n"
        f"- {len(signatures)} behavioral signatures triggered\n"
        f"- {len(processes)} processes spawned\n\n"
        f"**Action Required:** Isolate, block IOCs, initiate IR procedures."
    )

    return analysis_out, attck_out, summary_out


def _manual_extract(report: dict) -> tuple[str, str, int]:
    """Fallback manual extraction when cape_extractor v3 unavailable."""
    behavior = report.get("behavior", {})
    info = report.get("info", {})
    target = report.get("target", {}).get("file", {})

    family = (
        info.get("cape_type", "")
        or report.get("malfamily", "")
        or target.get("name", "Unknown")
    )
    score = info.get("score", 0)

    parts = []
    if target.get("name"):
        parts.append(f"Sample: {target['name']}")
    if score:
        parts.append(f"Score: {score}/10")

    processes = behavior.get("processes", []) or []
    if processes:
        proc_names = [p.get("process_name", p.get("name", "")) for p in processes[:5] if isinstance(p, dict)]
        parts.append(f"Processes: {', '.join(n for n in proc_names if n)}")

    signatures = report.get("signatures", []) or []
    if signatures:
        sig_names = [s.get("name", "") for s in signatures[:5] if isinstance(s, dict)]
        parts.append(f"Signatures: {', '.join(n for n in sig_names if n)}")

    return "\n".join(parts), family, score


def process_cape_dataset() -> int:
    """Download and convert CAPE reports from HuggingFace."""
    out_path = OUT_DIR / "cape_hf_reports.jsonl"
    print(f"\n[1/3] Loading unileon-robotics/malware-samples from HuggingFace...")

    try:
        ds = load_dataset(
            "unileon-robotics/malware-samples",
            split="train",
            trust_remote_code=False,
            download_mode="force_redownload",
        )
        print(f"  Loaded {len(ds)} samples")
    except Exception as e:
        print(f"  [WARN] Dataset load failed: {e}")
        return 0

    random.seed(42)
    count = 0

    with open(out_path, "a", encoding="utf-8") as out:
        for i, sample in enumerate(ds):
            # The dataset may have a 'report' field with JSON or a file path
            report_data = None

            # Try different field names
            for field in ["report", "cape_report", "analysis", "json_report"]:
                val = sample.get(field)
                if val:
                    if isinstance(val, dict):
                        report_data = val
                    elif isinstance(val, str):
                        try:
                            report_data = json.loads(val)
                        except Exception:
                            pass
                    break

            if not report_data:
                # Try to construct from individual fields
                report_data = {k: v for k, v in sample.items() if v is not None}

            if not report_data:
                continue

            try:
                analysis_out, attck_out, summary_out = build_output_from_cape_dict(report_data)
            except Exception as e:
                continue

            if not analysis_out:
                continue

            # Format evidence text for input
            try:
                from evidence.cape_extractor import extract_from_cape_dict, format_evidence_text
                brief = extract_from_cape_dict(report_data)
                evidence_text = format_evidence_text(brief)
            except Exception:
                evidence_text, _, _ = _manual_extract(report_data)

            if len(evidence_text.strip()) < 50:
                continue

            # Write pairs
            out.write(json.dumps({
                "instruction": random.choice(INSTRUCTION_ANALYZE),
                "input": evidence_text[:2500],
                "output": analysis_out,
            }, ensure_ascii=False) + "\n")
            count += 1

            if attck_out:
                out.write(json.dumps({
                    "instruction": random.choice(INSTRUCTION_ATTCK),
                    "input": evidence_text[:2500],
                    "output": attck_out,
                }, ensure_ascii=False) + "\n")
                count += 1

            out.write(json.dumps({
                "instruction": random.choice(INSTRUCTION_SUMMARY),
                "input": evidence_text[:2500],
                "output": summary_out,
            }, ensure_ascii=False) + "\n")
            count += 1

            if (i + 1) % 100 == 0:
                print(f"  Processed {i+1} samples → {count} pairs so far")

    print(f"  Total CAPE pairs: {count} → {out_path}")
    return count


def process_cti_dataset() -> int:
    """Download and filter reloading0101/threat-intelligence-dataset."""
    out_path = OUT_DIR / "cti_supplement.jsonl"
    print(f"\n[2/3] Loading reloading0101/threat-intelligence-dataset...")

    try:
        ds = load_dataset(
            "reloading0101/threat-intelligence-dataset",
            split="train",
            trust_remote_code=False,
        )
        print(f"  Loaded {len(ds)} samples")
    except Exception as e:
        print(f"  [WARN] CTI dataset load failed: {e}")
        return 0

    # Filter for malware analysis and ATT&CK relevant entries
    malware_keywords = {
        "malware", "att&ck", "mitre", "technique", "indicator", "ioc",
        "ransomware", "trojan", "backdoor", "c2", "persistence", "sandbox",
        "analysis", "threat", "incident", "forensic", "detection"
    }

    count = 0
    with open(out_path, "a", encoding="utf-8") as out:
        for sample in ds:
            # Normalize fields — dataset may use instruction/response or question/answer
            instruction = (
                sample.get("instruction", "") or
                sample.get("question", "") or
                sample.get("input", "") or ""
            ).strip()

            response = (
                sample.get("response", "") or
                sample.get("output", "") or
                sample.get("answer", "") or ""
            ).strip()

            if not instruction or not response:
                continue

            # Quality filter: must be related to malware/threat intel
            combined = (instruction + " " + response).lower()
            if not any(kw in combined for kw in malware_keywords):
                continue

            # Length filter: skip very short responses
            if len(response) < 100:
                continue

            context = sample.get("context", sample.get("system", "")).strip()

            record = {
                "instruction": instruction[:500],
                "input": context[:500] if context else "",
                "output": response[:3000],
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"  Filtered CTI pairs: {count} → {out_path}")
    return count


def process_trendyol_dataset() -> int:
    """Download Trendyol cybersecurity instruction dataset."""
    out_path = OUT_DIR / "cti_supplement.jsonl"
    print(f"\n[3/3] Loading Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset...")

    try:
        ds = load_dataset(
            "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset",
            split="train",
            trust_remote_code=False,
        )
        print(f"  Loaded {len(ds)} samples")
    except Exception as e:
        print(f"  [WARN] Trendyol dataset load failed: {e}")
        return 0

    malware_keywords = {
        "malware", "att&ck", "mitre", "ransomware", "trojan", "backdoor",
        "incident response", "forensic", "threat intel", "ioc", "sandbox",
        "c2", "lateral movement", "persistence", "privilege escalation",
        "detection", "threat hunt"
    }

    count = 0
    with open(out_path, "a", encoding="utf-8") as out:
        for sample in ds:
            # Trendyol uses system/user/assistant format
            system = (sample.get("system") or "").strip()
            user = (sample.get("user") or sample.get("instruction") or "").strip()
            assistant = (sample.get("assistant") or sample.get("output") or "").strip()

            if not user or not assistant:
                continue

            combined = (user + " " + assistant).lower()
            if not any(kw in combined for kw in malware_keywords):
                continue

            if len(assistant) < 100:
                continue

            instruction = user[:500]
            context = system[:300] if system else ""

            record = {
                "instruction": instruction,
                "input": context,
                "output": assistant[:3000],
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"  Trendyol filtered pairs appended: {count} → {out_path}")
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hf-token", type=str, default=os.environ.get("HF_TOKEN"),
                        help="HuggingFace token (or set HF_TOKEN env)")
    parser.add_argument("--output-dir", type=str, default=None)
    parser.add_argument("--skip-cape", action="store_true")
    parser.add_argument("--skip-cti", action="store_true")
    args = parser.parse_args()

    if args.output_dir:
        global OUT_DIR
        OUT_DIR = Path(args.output_dir)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.hf_token:
        from huggingface_hub import login
        login(token=args.hf_token)
        print(f"Logged in to HuggingFace")

    total = 0

    if not args.skip_cape:
        total += process_cape_dataset()

    if not args.skip_cti:
        total += process_cti_dataset()
        total += process_trendyol_dataset()

    print(f"\n{'='*60}")
    print(f"Total instruction pairs generated: {total}")
    for f in [OUT_DIR / "cape_hf_reports.jsonl", OUT_DIR / "cti_supplement.jsonl"]:
        if f.exists():
            lines = sum(1 for _ in open(f))
            size_mb = f.stat().st_size / 1e6
            print(f"  {f.name}: {lines:,} lines, {size_mb:.1f} MB")
    print("="*60)


if __name__ == "__main__":
    main()
