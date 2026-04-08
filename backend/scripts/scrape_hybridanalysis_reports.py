#!/usr/bin/env python3
"""
scrape_hybridanalysis_reports.py — Scrape Hybrid Analysis public sandbox reports
and convert to Alpaca instruction pairs for E2 Dynamic Behavior training.

Hybrid Analysis (https://www.hybrid-analysis.com) provides a FREE public API
that returns full JSON behavioral reports including process trees, network
activity, ATT&CK mappings, and signatures — no subscription required.

Free tier limits: 200 requests/minute, no daily cap for public report reads.

Usage:
  # Search by malware family (no API key needed for public reports):
  python3 scrape_hybridanalysis_reports.py \
      --families Emotet AgentTesla RedLine AsyncRAT Remcos \
      --count 60 \
      --output data/processed/hybridanalysis_reports.jsonl

  # With API key for higher rate limits (free signup):
  python3 scrape_hybridanalysis_reports.py --api-key YOUR_KEY --families ...

Get free API key: https://www.hybrid-analysis.com/signup

Output: data/processed/hybridanalysis_reports.jsonl (~3 pairs per report)
"""

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path

import requests

# ── Constants ─────────────────────────────────────────────────────────────────

API_BASE = "https://www.hybrid-analysis.com/api/v2"
PUBLIC_BASE = "https://www.hybrid-analysis.com"

# Environments: 120=Windows 7 32-bit, 160=Windows 10 64-bit
WINDOWS_ENVS = [120, 160]

INSTRUCTION_ANALYZE = [
    "Analyze this sandbox execution report and produce a detailed malware analysis with ATT&CK technique mapping.",
    "You are a malware analyst. Given the following sandbox behavioral evidence, write a comprehensive analysis report.",
    "Review this Hybrid Analysis sandbox report and identify the malware family, behaviors, and MITRE ATT&CK techniques.",
    "Analyze the following dynamic analysis evidence and produce a structured malware report with IOCs and technique mappings.",
    "Given this sandbox execution data, classify the malware, explain its behavior, and map techniques to MITRE ATT&CK.",
    "Examine this behavioral sandbox report and produce a threat analysis with kill chain and detection recommendations.",
    "Based on the following sandbox execution evidence, identify the malware type, persistence mechanisms, and C2 indicators.",
]

INSTRUCTION_ATTCK = [
    "Map the observed behaviors in this sandbox report to MITRE ATT&CK techniques with evidence for each mapping.",
    "Identify all MITRE ATT&CK techniques in this malware execution trace. Justify each mapping with behavioral evidence.",
    "Given this behavioral evidence, produce a structured ATT&CK technique mapping with confidence ratings.",
    "Analyze this malware report and produce an ATT&CK Navigator-style breakdown of all observed techniques.",
]

INSTRUCTION_SUMMARY = [
    "Write an executive summary of this malware analysis for a security operations team.",
    "Produce a concise threat assessment and executive summary from this sandbox analysis report.",
    "Summarize the key findings from this malware sandbox analysis for an incident response team.",
    "Create a one-page threat briefing from this sandbox report for distribution to stakeholders.",
]

RATE_LIMIT_DELAY = 1.2  # seconds between requests (well within free tier)


# ── Hybrid Analysis API client ────────────────────────────────────────────────

class HybridAnalysisClient:
    def __init__(self, api_key: str | None = None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        })
        if api_key:
            self.session.headers["api-key"] = api_key

    def search_by_family(self, family: str, limit: int = 50) -> list[dict]:
        """Search for public reports by malware family/threat name."""
        results = []
        try:
            resp = self.session.post(
                f"{API_BASE}/search/terms",
                data={
                    "verdict": "malicious",
                    "threat_name": family,
                    "av_detect": "1",
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("result", [])[:limit]
        except Exception as e:
            print(f"  [WARN] Search failed for {family}: {e}")

        if not results:
            # Fallback: search by tag
            try:
                resp = self.session.post(
                    f"{API_BASE}/search/terms",
                    data={"verdict": "malicious", "tag": family.lower()},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
                results = data.get("result", [])[:limit]
            except Exception:
                pass

        return results

    def get_report_summary(self, sha256: str, environment_id: int = 160) -> dict | None:
        """Fetch full report summary for a sample."""
        try:
            resp = self.session.get(
                f"{API_BASE}/report/{sha256}:{environment_id}/summary",
                timeout=30,
            )
            if resp.status_code == 404:
                # Try other environments
                for env in WINDOWS_ENVS:
                    if env == environment_id:
                        continue
                    resp = self.session.get(
                        f"{API_BASE}/report/{sha256}:{env}/summary",
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        break
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"  [WARN] Report fetch failed for {sha256[:16]}...: {e}")
            return None

    def get_report_state(self, sha256: str, environment_id: int = 160) -> dict | None:
        """Fetch report state (alternative endpoint with ATT&CK data)."""
        try:
            resp = self.session.get(
                f"{API_BASE}/report/{sha256}:{environment_id}/state",
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def search_recent_malicious(self, limit: int = 100) -> list[dict]:
        """Get recent malicious public submissions."""
        try:
            resp = self.session.get(
                f"{API_BASE}/feed/latest",
                params={"_limit": limit},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return [r for r in data.get("data", []) if r.get("verdict") == "malicious"]
        except Exception as e:
            print(f"  [WARN] Feed fetch failed: {e}")
            return []


# ── Evidence extraction ───────────────────────────────────────────────────────

def extract_evidence(report: dict) -> dict:
    """Extract structured behavioral evidence from a Hybrid Analysis report."""
    ev = {
        "sha256": report.get("sha256", ""),
        "md5": report.get("md5", ""),
        "filename": report.get("submit_name", report.get("sample_name", "unknown")),
        "family": "",
        "threat_score": report.get("threat_score", 0),
        "verdict": report.get("verdict", ""),
        "av_detect": report.get("av_detect", 0),
        "type_short": report.get("type_short", ""),
        "processes": [],
        "network": {"hosts": [], "domains": [], "http": [], "connections": []},
        "files_created": [],
        "registry": [],
        "attck_techniques": [],
        "signatures": [],
        "tags": [],
        "mitre_attcks": [],
    }

    # Family detection
    ev["family"] = (
        report.get("vx_family", "") or
        report.get("threat_name", "") or
        ""
    )
    if not ev["family"] and report.get("classification_tags"):
        ev["family"] = report["classification_tags"][0] if report["classification_tags"] else ""

    # Tags
    ev["tags"] = report.get("tags", [])[:10]

    # Process list
    processes = report.get("processes", [])
    if isinstance(processes, list):
        for proc in processes[:15]:
            if isinstance(proc, dict):
                name = proc.get("name", proc.get("filename", ""))
                uid = proc.get("uid", proc.get("pid", ""))
                cmd = proc.get("command_line", proc.get("cmd", ""))[:200]
                normalized = proc.get("normalized_path", "")
                if name:
                    ev["processes"].append({
                        "name": name,
                        "pid": uid,
                        "cmd": cmd,
                        "path": normalized,
                    })

    # Network
    hosts = report.get("hosts", [])
    if isinstance(hosts, list):
        ev["network"]["hosts"] = [h if isinstance(h, str) else h.get("ip", "") for h in hosts[:15]]

    domains = report.get("domains", [])
    if isinstance(domains, list):
        ev["network"]["domains"] = [d if isinstance(d, str) else d.get("domain", "") for d in domains[:15]]

    http_reqs = report.get("http_requests", report.get("compromised_hosts", []))
    if isinstance(http_reqs, list):
        for r in http_reqs[:10]:
            if isinstance(r, dict):
                url = r.get("request_url", r.get("url", ""))
                method = r.get("request_method", r.get("method", "GET"))
                if url:
                    ev["network"]["http"].append(f"{method} {url[:120]}")

    # Files
    files = report.get("file_metadata", report.get("extracted_files", []))
    if not files:
        files = report.get("dropped_files", [])
    if isinstance(files, list):
        for f in files[:10]:
            if isinstance(f, dict):
                name = f.get("filename", f.get("file_name", f.get("name", "")))
                if name:
                    ev["files_created"].append(name[:100])

    # Registry
    reg = report.get("registry_keys_created", []) + report.get("registry_keys_modified", [])
    if isinstance(reg, list):
        for r in reg[:10]:
            if isinstance(r, str):
                ev["registry"].append(f"Modified: {r[:120]}")
            elif isinstance(r, dict):
                key = r.get("key", r.get("name", ""))
                op = "Modified"
                if key:
                    ev["registry"].append(f"{op}: {key[:120]}")

    # ATT&CK techniques (mitre_attcks field)
    mitre = report.get("mitre_attcks", [])
    if isinstance(mitre, list):
        for t in mitre:
            if isinstance(t, dict):
                tid = t.get("attck_id", t.get("id", ""))
                tname = t.get("technique", t.get("name", ""))
                tactic = t.get("tactic", "")
                parent_id = t.get("attck_id_wiki", "")
                if tid:
                    ev["attck_techniques"].append({
                        "id": tid,
                        "name": tname,
                        "tactic": tactic,
                    })

    # Signatures
    sigs = report.get("signatures", [])
    if isinstance(sigs, list):
        for s in sigs[:15]:
            if isinstance(s, dict):
                name = s.get("name", s.get("threat_level_human", ""))
                desc = s.get("description", s.get("desc", ""))[:250]
                threat_level = s.get("threat_level", 0)
                if name:
                    ev["signatures"].append({
                        "name": name,
                        "description": desc,
                        "threat_level": threat_level,
                    })

    return ev


def format_evidence_text(ev: dict) -> str:
    """Format extracted evidence into readable input text."""
    parts = []

    if ev["filename"]:
        parts.append(f"Sample: {ev['filename']}")
    if ev["sha256"]:
        parts.append(f"SHA256: {ev['sha256'][:16]}...")
    if ev["family"]:
        parts.append(f"Detected Family: {ev['family']}")
    if ev["threat_score"]:
        parts.append(f"Threat Score: {ev['threat_score']}/100")
    if ev["type_short"]:
        parts.append(f"File Type: {ev['type_short']}")
    if ev["tags"]:
        parts.append(f"Tags: {', '.join(ev['tags'][:6])}")

    if ev["processes"]:
        parts.append("\nProcess Execution:")
        for p in ev["processes"][:8]:
            line = f"  {p['name']}"
            if p["cmd"]:
                line += f"\n    CMD: {p['cmd'][:150]}"
            parts.append(line)

    if ev["signatures"]:
        parts.append("\nBehavioral Signatures:")
        for s in ev["signatures"][:8]:
            lvl = f"[Level {s['threat_level']}] " if s["threat_level"] else ""
            desc = f": {s['description']}" if s["description"] else ""
            parts.append(f"  {lvl}{s['name']}{desc[:200]}")

    net = ev["network"]
    if net["hosts"]:
        parts.append(f"\nC2/Network Hosts: {', '.join(str(h) for h in net['hosts'][:8] if h)}")
    if net["domains"]:
        parts.append(f"DNS Queries: {', '.join(str(d) for d in net['domains'][:8] if d)}")
    if net["http"]:
        parts.append("\nHTTP Requests:")
        for r in net["http"][:5]:
            parts.append(f"  {r}")

    if ev["files_created"]:
        parts.append(f"\nDropped Files: {', '.join(ev['files_created'][:5])}")

    if ev["registry"]:
        parts.append("\nRegistry Operations:")
        for r in ev["registry"][:4]:
            parts.append(f"  {r}")

    if ev["attck_techniques"]:
        parts.append("\nATT&CK Techniques:")
        for t in ev["attck_techniques"][:10]:
            tact = f" [{t['tactic']}]" if t["tactic"] else ""
            parts.append(f"  {t['id']} {t['name']}{tact}")

    return "\n".join(parts)


# ── Output builders ───────────────────────────────────────────────────────────

def build_analysis_output(ev: dict) -> str:
    family = ev["family"] or "Unknown"
    score = ev["threat_score"]
    net = ev["network"]

    # Behavioral observation section
    obs_lines = []
    for s in ev["signatures"][:6]:
        lvl = s.get("threat_level", 0)
        desc = s["description"] if s["description"] else ""
        obs_lines.append(f"- **{s['name']}**{': ' + desc[:200] if desc else ''}")

    obs_section = "\n".join(obs_lines) if obs_lines else "- General malicious behavior observed"

    # ATT&CK section
    tech_lines = []
    for t in ev["attck_techniques"]:
        tact = f" (Tactic: {t['tactic']})" if t["tactic"] else ""
        tech_lines.append(f"- **{t['id']}** {t['name']}{tact}")
    tech_section = "\n".join(tech_lines) if tech_lines else "- Technique mapping requires further analysis"

    # IOC section
    ioc_lines = []
    if net["hosts"]:
        ioc_lines.extend([f"  C2 IP: {h}" for h in net["hosts"][:5] if h])
    if net["domains"]:
        ioc_lines.extend([f"  Domain: {d}" for d in net["domains"][:5] if d])
    if ev["files_created"]:
        ioc_lines.extend([f"  File: {f}" for f in ev["files_created"][:3]])
    ioc_section = "\n".join(ioc_lines) if ioc_lines else "  No network IOCs captured"

    proc_count = len(ev["processes"])
    spawned = ", ".join(p["name"] for p in ev["processes"][:4] if p["name"])

    return (
        f"## Malware Analysis Report\n\n"
        f"**Classification:** {family}\n"
        f"**Threat Score:** {score}/100\n"
        f"**AV Detection:** {ev['av_detect']}%\n\n"
        f"## Executive Summary\n\n"
        f"Analysis of **{ev['filename']}** confirms {family} malware behavior with a threat "
        f"score of {score}/100. The sample spawned {proc_count} process(es)"
        + (f" ({spawned})" if spawned else "") +
        f" and triggered {len(ev['signatures'])} behavioral signatures.\n\n"
        f"## Behavioral Observations\n\n"
        f"{obs_section}\n\n"
        f"## MITRE ATT&CK Mapping\n\n"
        f"{tech_section}\n\n"
        f"## Indicators of Compromise\n\n"
        f"{ioc_section}\n\n"
        f"## Recommendations\n\n"
        f"1. Isolate affected endpoint and preserve forensic evidence\n"
        f"2. Block identified C2 hosts and domains at the network perimeter\n"
        f"3. Hunt for related samples using the SHA256 and behavioral signatures\n"
        f"4. Update EDR detection rules based on the observed TTPs"
    )


def build_attck_output(ev: dict) -> str:
    if not ev["attck_techniques"]:
        return ""
    family = ev["family"] or "the sample"
    lines = []
    for t in ev["attck_techniques"]:
        tact = f"\n  Tactic: {t['tactic']}" if t["tactic"] else ""
        lines.append(f"**{t['id']}** — {t['name']}{tact}\n")
    return (
        f"## ATT&CK Technique Analysis — {family}\n\n"
        f"Mapped {len(ev['attck_techniques'])} technique(s) from behavioral evidence:\n\n"
        + "\n".join(lines) +
        f"\n## Coverage Summary\n\n"
        f"Total: {len(ev['attck_techniques'])} technique(s) across "
        f"{len(set(t['tactic'] for t in ev['attck_techniques'] if t['tactic']))} tactic(s)."
    )


def build_summary_output(ev: dict) -> str:
    family = ev["family"] or "Unknown"
    score = ev["threat_score"]
    net = ev["network"]
    has_c2 = bool(net["hosts"] or net["domains"] or net["http"])

    return (
        f"## Executive Summary\n\n"
        f"**Threat:** {family} | **Risk:** {'Critical' if score >= 80 else 'High' if score >= 60 else 'Medium'}\n\n"
        f"Dynamic analysis of **{ev['filename']}** confirms malicious behavior consistent with "
        f"**{family}**. Threat score: {score}/100, AV detection: {ev['av_detect']}%.\n\n"
        f"**Key Findings:**\n"
        f"- {len(ev['attck_techniques'])} ATT&CK techniques identified\n"
        f"- {len(ev['signatures'])} behavioral signatures triggered\n"
        + (f"- Active C2 communication detected to {len(net['hosts'])+len(net['domains'])} host(s)\n" if has_c2 else "")
        + f"- {len(ev['processes'])} processes spawned during execution\n\n"
        f"**Immediate Response:**\n"
        f"1. Quarantine affected host immediately\n"
        f"2. Block IOCs at network layer\n"
        f"3. Initiate IR procedures for {family} per playbook"
    )


def report_to_pairs(ev: dict) -> list[dict]:
    """Convert evidence to 1-3 instruction pairs."""
    evidence_text = format_evidence_text(ev)
    if len(evidence_text.strip()) < 80:
        return []

    pairs = []
    random.seed(None)  # Different each run for variety

    output1 = build_analysis_output(ev)
    if len(output1) > 100:
        pairs.append({
            "instruction": random.choice(INSTRUCTION_ANALYZE),
            "input": evidence_text[:2500],
            "output": output1,
        })

    if ev["attck_techniques"]:
        output2 = build_attck_output(ev)
        if output2:
            pairs.append({
                "instruction": random.choice(INSTRUCTION_ATTCK),
                "input": evidence_text[:2500],
                "output": output2,
            })

    output3 = build_summary_output(ev)
    if len(output3) > 100:
        pairs.append({
            "instruction": random.choice(INSTRUCTION_SUMMARY),
            "input": evidence_text[:2500],
            "output": output3,
        })

    return pairs


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scrape Hybrid Analysis reports for training data")
    parser.add_argument("--api-key", type=str, default=None,
                        help="Hybrid Analysis API key (free: https://www.hybrid-analysis.com/signup)")
    parser.add_argument("--families", nargs="+",
                        default=["Emotet", "AgentTesla", "RedLine", "AsyncRAT", "Remcos",
                                 "Qakbot", "IcedID", "Formbook", "NjRAT", "LockBit",
                                 "Dridex", "Ursnif", "TrickBot", "Raccoon", "Vidar"],
                        help="Malware families to search")
    parser.add_argument("--count", type=int, default=60,
                        help="Reports per family (default 60)")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--hashes", type=str, default=None,
                        help="File with SHA256 hashes (one per line) to fetch directly")
    parser.add_argument("--delay", type=float, default=RATE_LIMIT_DELAY)
    args = parser.parse_args()

    out_dir = Path(__file__).resolve().parent.parent.parent / "data" / "processed"
    out_path = Path(args.output) if args.output else out_dir / "hybridanalysis_reports.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    client = HybridAnalysisClient(api_key=args.api_key)
    random.seed(42)

    sha256_list = []

    # Source 1: From hash file
    if args.hashes:
        hash_path = Path(args.hashes)
        if hash_path.exists():
            sha256_list = [l.strip() for l in hash_path.read_text().strip().split("\n")
                          if l.strip() and len(l.strip()) == 64]
            print(f"Loaded {len(sha256_list)} hashes from {args.hashes}")

    # Source 2: Search by family name
    if not sha256_list:
        print(f"Searching {len(args.families)} malware families...")
        seen_hashes = set()
        for family in args.families:
            print(f"  Searching: {family}...")
            results = client.search_by_family(family, limit=args.count)
            for r in results:
                h = r.get("sha256", "")
                if h and h not in seen_hashes:
                    seen_hashes.add(h)
                    sha256_list.append(h)
            print(f"    Got {len(results)} results")
            time.sleep(args.delay)

        # Also grab recent feed for diversity
        print("  Fetching recent malicious submissions...")
        feed = client.search_recent_malicious(limit=100)
        for r in feed:
            h = r.get("sha256", "")
            if h and h not in seen_hashes:
                seen_hashes.add(h)
                sha256_list.append(h)
        print(f"  Feed added {len(feed)} samples")

    print(f"\nTotal unique samples to fetch: {len(sha256_list)}")

    total_pairs = 0
    skipped = 0
    written = 0

    with open(out_path, "a", encoding="utf-8") as out:
        for i, sha256 in enumerate(sha256_list, 1):
            print(f"[{i}/{len(sha256_list)}] {sha256[:16]}...", end=" ")
            report = client.get_report_summary(sha256)

            if not report:
                print("SKIP (no report)")
                skipped += 1
                time.sleep(args.delay)
                continue

            ev = extract_evidence(report)
            pairs = report_to_pairs(ev)

            if not pairs:
                print("SKIP (insufficient evidence)")
                skipped += 1
                time.sleep(args.delay)
                continue

            family = ev["family"] or "unknown"
            for pair in pairs:
                out.write(json.dumps(pair, ensure_ascii=False) + "\n")
                total_pairs += 1
            written += 1

            print(f"OK ({family}, {len(pairs)} pairs, score={ev['threat_score']}, "
                  f"{len(ev['attck_techniques'])} ATT&CK)")
            time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"Fetched: {written} reports, Skipped: {skipped}")
    print(f"Total instruction pairs: {total_pairs}")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
