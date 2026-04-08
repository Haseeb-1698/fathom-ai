#!/usr/bin/env python3
"""
download_extended_v5.py — Download all expert-training datasets for Fathom Plan B.

Run on Vultr CPU instance. Outputs raw data to ../data/raw/.

Expert mapping:
  E1 Static:      EMBER2024, EMBER2024-CAPA, PowerShell Malware
  E2 Dynamic:     Mal-API-2019 (GitHub), Avast-CTU CAPE Dataset (GitHub)
  E5 ThreatIntel: MITRE CTI, LOLBAS, Atomic Red Team, CTI reports (HF)
  E7 Reports:     Tiamz cybersec instructions, MalwareTextDB, APT Notes (HF)
  + MITRE ATT&CK STIX JSON (for RAG)
  + Plan A data already preprocessed (127K)
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"


def run(cmd: str, cwd: str | None = None):
    print(f"\n>>> {cmd}")
    subprocess.check_call(cmd, shell=True, cwd=cwd)


def ensure_pip_deps():
    """Install minimal deps for downloading."""
    run(f"{sys.executable} -m pip install -q datasets huggingface_hub requests tqdm")


def download_hf_dataset(repo_id: str, out_name: str, subset: str | None = None,
                         split: str = "train", max_rows: int | None = None):
    """Download a HuggingFace dataset and save as JSONL."""
    from datasets import load_dataset

    out_path = RAW_DIR / f"{out_name}.jsonl"
    if out_path.exists():
        lines = sum(1 for _ in open(out_path))
        print(f"[SKIP] {out_path.name} already exists ({lines} lines)")
        return

    print(f"[DL] {repo_id} (subset={subset}, split={split})")
    kwargs = {}
    if subset:
        kwargs["name"] = subset
    ds = load_dataset(repo_id, split=split, trust_remote_code=True, **kwargs)

    if max_rows and len(ds) > max_rows:
        ds = ds.shuffle(seed=42).select(range(max_rows))
        print(f"  Subsampled to {max_rows} rows")

    with open(out_path, "w", encoding="utf-8") as f:
        for row in ds:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"  Saved {len(ds)} rows → {out_path.name}")


def download_github_file(url: str, out_name: str):
    """Download a single file from GitHub."""
    import requests

    out_path = RAW_DIR / out_name
    if out_path.exists():
        print(f"[SKIP] {out_name} already exists")
        return

    print(f"[DL] {url}")
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    out_path.write_bytes(resp.content)
    print(f"  Saved → {out_name} ({len(resp.content)} bytes)")


def download_github_repo(repo_url: str, dirname: str, depth: int = 1):
    """Shallow-clone a GitHub repo."""
    dest = RAW_DIR / dirname
    if dest.exists():
        print(f"[SKIP] {dirname}/ already exists")
        return
    print(f"[CLONE] {repo_url}")
    run(f"git clone --depth {depth} {repo_url} {dest}")


def main():
    parser = argparse.ArgumentParser(description="Download Fathom Plan B datasets")
    parser.add_argument("--skip-large", action="store_true",
                        help="Skip EMBER (large) downloads")
    parser.add_argument("--experts", nargs="+",
                        default=["e1", "e2", "e5", "e7", "rag"],
                        help="Which expert datasets to download (e1 e2 e5 e7 rag)")
    args = parser.parse_args()

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    ensure_pip_deps()

    # ═══════════════════════════════════════════════════════════════════
    # E1: Static Analysis
    # ═══════════════════════════════════════════════════════════════════
    if "e1" in args.experts:
        print("\n" + "=" * 60)
        print("  E1: Static Analysis datasets")
        print("=" * 60)

        if not args.skip_large:
            # EMBER2024 — PE feature vectors with labels
            download_hf_dataset(
                "joyce8/EMBER2024",
                "ember2024",
                split="train",
                max_rows=100_000,
            )

            # EMBER2024-CAPA — CAPA capability extractions
            download_hf_dataset(
                "joyce8/EMBER2024-capa",
                "ember2024_capa",
                split="train",
                max_rows=100_000,
            )

        # PowerShell Malware Detection
        download_hf_dataset(
            "rr4433/Powershell_Malware_Detection_Dataset",
            "powershell_malware",
            split="train",
        )

    # ═══════════════════════════════════════════════════════════════════
    # E2: Dynamic Behavior Analysis
    # ═══════════════════════════════════════════════════════════════════
    if "e2" in args.experts:
        print("\n" + "=" * 60)
        print("  E2: Dynamic Behavior datasets")
        print("=" * 60)

        # Mal-API-2019 — API call sequences labeled by malware family
        download_github_repo(
            "https://github.com/ocatak/malware_api_class",
            "mal-api-2019",
        )

        # Avast-CTU CAPE Dataset — real CAPE sandbox reports
        download_github_repo(
            "https://github.com/avast/avast-ctu-cape-dataset.git",
            "avast-cape",
            depth=2,
        )

    # ═══════════════════════════════════════════════════════════════════
    # E5: Threat Intelligence
    # ═══════════════════════════════════════════════════════════════════
    if "e5" in args.experts:
        print("\n" + "=" * 60)
        print("  E5: Threat Intelligence datasets")
        print("=" * 60)

        # MITRE CTI — STIX objects for all ATT&CK techniques
        download_github_repo(
            "https://github.com/mitre/cti",
            "mitre-cti",
        )

        # LOLBAS — Living Off The Land Binaries
        download_github_repo(
            "https://github.com/LOLBAS-Project/LOLBAS",
            "lolbas",
        )

        # Atomic Red Team — atomics for ATT&CK techniques
        download_github_repo(
            "https://github.com/redcanaryco/atomic-red-team",
            "atomic-red-team",
        )

        # CTI annotated reports (HF) — 9,732 annotated CTI texts
        download_hf_dataset(
            "mrmoor/cyber-threat-intelligence",
            "cti_reports",
            split="train",
        )

    # ═══════════════════════════════════════════════════════════════════
    # E7: Report Generation
    # ═══════════════════════════════════════════════════════════════════
    if "e7" in args.experts:
        print("\n" + "=" * 60)
        print("  E7: Report Generation datasets")
        print("=" * 60)

        # Tiamz CyberSec Instructions — 13,190 instruction/answer pairs
        download_hf_dataset(
            "Tiamz/cybersecurity-instruction-dataset",
            "tiamz_cybersec",
            split="train",
        )

        # MalwareTextDB — 38 annotated malware report texts
        download_hf_dataset(
            "naorm/malware-text-db",
            "malware_textdb",
            split="train",
        )

        # APT Notes — cybersecurity report collection (HF)
        download_hf_dataset(
            "clydeiii/cybersecurity",
            "apt_notes_cybersec",
            split="train",
        )

    # ═══════════════════════════════════════════════════════════════════
    # RAG: MITRE ATT&CK STIX JSON (for FAISS index)
    # ═══════════════════════════════════════════════════════════════════
    if "rag" in args.experts:
        print("\n" + "=" * 60)
        print("  RAG: MITRE ATT&CK STIX JSON")
        print("=" * 60)

        download_github_file(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            "enterprise-attack.json",
        )

    # ═══════════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 60)
    print("  Download Summary")
    print("=" * 60)

    total_files = 0
    total_bytes = 0
    for f in sorted(RAW_DIR.glob("*.jsonl")):
        lines = sum(1 for _ in open(f, encoding="utf-8"))
        size = f.stat().st_size
        total_files += 1
        total_bytes += size
        print(f"  {f.name}: {lines:,} rows ({size / 1e6:.1f} MB)")

    for d in sorted(RAW_DIR.iterdir()):
        if d.is_dir():
            total_files += 1
            print(f"  {d.name}/ (git repo)")

    print(f"\n  Total: {total_files} items, {total_bytes / 1e6:.1f} MB JSONL")
    print(f"  Raw data in: {RAW_DIR}")


if __name__ == "__main__":
    main()
