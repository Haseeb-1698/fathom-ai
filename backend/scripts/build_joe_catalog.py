#!/usr/bin/env python3
"""
build_joe_catalog.py — Parse Joe Sandbox JSONL files into a structured catalog.

Reads:
  joe sandbox/joe_dynamic_reports_raw.jsonl  — raw report data with executive text
  joe sandbox/joe_training.jsonl             — structured Q&A training data

Outputs:
  joe sandbox/catalog.json  — list of report objects ready for the frontend

Usage:
  python backend/scripts/build_joe_catalog.py
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
JOE_DIR = ROOT / "joe sandbox"
OUTPUT = JOE_DIR / "catalog.json"


def parse_techniques(text: str) -> list[str]:
    """Extract ATT&CK technique IDs from text."""
    return list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", text)))


def parse_iocs_from_text(text: str) -> dict:
    """Extract IOCs from executive text."""
    domains = list(dict.fromkeys(re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:xyz|com|net|org|io|ru|cn|info|biz)\b",
        text, re.IGNORECASE
    )))
    ips = list(dict.fromkeys(re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        text
    )))
    hashes_sha256 = list(dict.fromkeys(re.findall(r"\b[0-9a-fA-F]{64}\b", text)))
    hashes_md5 = list(dict.fromkeys(re.findall(r"\b[0-9a-fA-F]{32}\b", text)))
    return {
        "domains": domains[:20],
        "ips": [ip for ip in ips[:20] if not ip.startswith(("192.168.", "10.", "127."))],
        "sha256": hashes_sha256[:5],
        "md5": hashes_md5[:5],
    }


def parse_signatures(text: str) -> list[str]:
    """Extract signature names from executive text."""
    sigs = []
    # Common Joe Sandbox signature patterns
    patterns = [
        r"Yara detected [\w\s/]+",
        r"Found malware configuration",
        r"Multi AV Scanner detection[^\n]+",
        r"Suricata IDS alerts[^\n]+",
        r"Contains functionality to[^\n]+",
        r"Injects a PE file[^\n]+",
        r"Allocates memory in foreign[^\n]+",
        r"Tries to harvest[^\n]+",
        r"Sample uses string decryption[^\n]+",
    ]
    for p in patterns:
        matches = re.findall(p, text)
        sigs.extend(m.strip() for m in matches[:3])
    return list(dict.fromkeys(sigs))[:15]


def score_to_verdict(score: float) -> str:
    if score >= 7:
        return "malicious"
    elif score >= 4:
        return "suspicious"
    return "benign"


def build_catalog():
    catalog = []
    seen_ids = set()

    # Load raw reports
    raw_path = JOE_DIR / "joe_dynamic_reports_raw.jsonl"
    if raw_path.exists():
        print(f"Processing {raw_path.name}...")
        with open(raw_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                analysis_id = str(entry.get("analysis_id", ""))
                if not analysis_id or analysis_id in seen_ids:
                    continue
                seen_ids.add(analysis_id)

                text = entry.get("executive_text", "")
                score = float(entry.get("quality_score", 0))
                family = entry.get("threatname", "Unknown")

                # Extract file name from text
                fname_match = re.search(r"Sample name:\s*([^\n]+)", text)
                file_name = fname_match.group(1).strip() if fname_match else f"sample_{analysis_id}"

                # Extract MD5/SHA256
                md5_match = re.search(r"MD5:\s*([0-9a-fA-F]{32})", text)
                sha256_match = re.search(r"SHA256:\s*([0-9a-fA-F]{64})", text)

                techniques = parse_techniques(text)
                iocs = parse_iocs_from_text(text)
                signatures = parse_signatures(text)
                verdict = score_to_verdict(score)

                # Build executive summary (first 1500 chars of meaningful text)
                exec_summary = re.sub(r"\s+", " ", text[:3000]).strip()

                catalog.append({
                    "analysis_id": analysis_id,
                    "file_name": file_name,
                    "family": family,
                    "verdict": verdict,
                    "score": score,
                    "md5": md5_match.group(1) if md5_match else "",
                    "sha256": sha256_match.group(1) if sha256_match else "",
                    "techniques": techniques[:12],
                    "iocs": iocs,
                    "signatures": signatures,
                    "executive_summary": exec_summary[:2000],
                    "source": "joe_sandbox",
                    "has_executive_html": (JOE_DIR / "executive" / f"{analysis_id}_executive.html").exists(),
                    "has_full_html": (JOE_DIR / "html" / f"{analysis_id}_full.html").exists(),
                    "has_ioc_html": (JOE_DIR / "iochtml" / f"{analysis_id}_iochtml.html").exists(),
                })

    # Load by_category HTML reports (extract metadata from filenames)
    by_cat = JOE_DIR / "by_category"
    if by_cat.exists():
        for cat_dir in sorted(by_cat.iterdir()):
            if not cat_dir.is_dir():
                continue
            category = cat_dir.name
            for html_file in sorted(cat_dir.glob("*.html")):
                # Filename: 01_score8.1_Formbook_info_stealer.html
                parts = html_file.stem.split("_", 3)
                if len(parts) < 3:
                    continue
                try:
                    score = float(parts[1].replace("score", ""))
                except ValueError:
                    score = 0.0
                family = parts[2] if len(parts) > 2 else "Unknown"
                desc = parts[3].replace("_", " ") if len(parts) > 3 else ""
                fake_id = f"cat_{category}_{html_file.stem}"
                if fake_id in seen_ids:
                    continue
                seen_ids.add(fake_id)
                catalog.append({
                    "analysis_id": fake_id,
                    "file_name": f"{family}.exe",
                    "family": family,
                    "verdict": score_to_verdict(score),
                    "score": score,
                    "md5": "",
                    "sha256": "",
                    "techniques": [],
                    "iocs": {"domains": [], "ips": [], "sha256": [], "md5": []},
                    "signatures": [],
                    "executive_summary": f"{family} — {desc}. Category: {category}. Score: {score}/10.",
                    "source": "joe_sandbox_category",
                    "category": category,
                    "html_path": str(html_file.relative_to(ROOT)),
                    "has_executive_html": False,
                    "has_full_html": True,
                    "has_ioc_html": False,
                })

    # Sort by score descending
    catalog.sort(key=lambda x: x.get("score", 0), reverse=True)

    OUTPUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n✅ Catalog built: {len(catalog)} reports → {OUTPUT}")
    print(f"   Malicious: {sum(1 for r in catalog if r['verdict'] == 'malicious')}")
    print(f"   Suspicious: {sum(1 for r in catalog if r['verdict'] == 'suspicious')}")
    print(f"   Benign: {sum(1 for r in catalog if r['verdict'] == 'benign')}")
    return catalog


if __name__ == "__main__":
    build_catalog()
