#!/usr/bin/env python3
"""
scrape_anyrun_reports.py — Scrape ANY.RUN public sandbox reports and convert
to Alpaca instruction pairs for E2 Dynamic Behavior training.

Usage:
  # Search by family and scrape (requires free API key):
  python3 scrape_anyrun_reports.py --families Emotet AgentTesla RedLine AsyncRAT Remcos \
      --count 100 --api-key YOUR_ANYRUN_KEY --output data/processed/anyrun_reports.jsonl

  # From a file of task IDs:
  python3 scrape_anyrun_reports.py --task-ids task_ids.txt --api-key YOUR_KEY

  # From a file of ANY.RUN task URLs:
  python3 scrape_anyrun_reports.py --urls urls.txt --api-key YOUR_KEY

Sign up for free API key at: https://app.any.run/signup
Free tier: 100 requests/day, access to all public reports.

Output: data/processed/anyrun_reports.jsonl (~3 instruction pairs per report)
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

API_BASE = "https://api.any.run/v1"
REPORT_URL = "https://app.any.run/tasks/{task_id}"

INSTRUCTION_ANALYZE = [
    "Analyze this sandbox execution report and produce a detailed malware analysis with ATT&CK technique mapping.",
    "You are a malware analyst. Given the following sandbox behavioral evidence, write a comprehensive analysis report.",
    "Review this ANY.RUN sandbox report and identify the malware family, behaviors, and MITRE ATT&CK techniques.",
    "Analyze the following dynamic analysis evidence and produce a structured malware report with IOCs and technique mappings.",
    "Given this sandbox execution data, classify the malware, explain its behavior, and map techniques to MITRE ATT&CK.",
]

INSTRUCTION_ATTCK = [
    "Map the observed behaviors in this sandbox report to MITRE ATT&CK techniques. Explain each mapping with evidence.",
    "Identify all MITRE ATT&CK techniques demonstrated in this malware execution trace and provide justification.",
    "Given this behavioral evidence, produce a structured ATT&CK technique mapping with confidence ratings.",
]

INSTRUCTION_SUMMARY = [
    "Write an executive summary of this malware analysis for a security operations team.",
    "Produce a concise threat assessment and executive summary from this sandbox analysis report.",
    "Summarize the key findings from this malware sandbox analysis for an incident response team.",
]

RATE_LIMIT_DELAY = 1.5  # seconds between API calls (free tier safe)


# ── ANY.RUN API client ────────────────────────────────────────────────────────

class AnyRunClient:
    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"API-Key {api_key}",
            "Accept": "application/json",
        })

    def search_public_tasks(self, family: str, skip: int = 0, limit: int = 100) -> list[dict]:
        """Search public submissions by malware family name."""
        try:
            resp = self.session.get(
                f"{API_BASE}/analysis",
                params={
                    "skip": skip,
                    "limit": limit,
                    "verdict": "Malicious",
                    "tag": family.lower(),
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("tasks", [])
        except Exception as e:
            print(f"  [WARN] Search failed for {family}: {e}")
            return []

    def get_task(self, task_id: str) -> dict | None:
        """Fetch detailed task report by ID."""
        try:
            resp = self.session.get(
                f"{API_BASE}/analysis/{task_id}",
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("data", {})
        except Exception as e:
            print(f"  [WARN] Task fetch failed for {task_id}: {e}")
            return None

    def search_by_threat_name(self, threat_name: str, limit: int = 50) -> list[dict]:
        """Alternative search by threat name field."""
        try:
            resp = self.session.get(
                f"{API_BASE}/analysis",
                params={
                    "limit": limit,
                    "verdict": "Malicious",
                    "threatName": threat_name,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("tasks", [])
        except Exception as e:
            print(f"  [WARN] Threat name search failed for {threat_name}: {e}")
            return []


def extract_task_id_from_url(url: str) -> str | None:
    """Extract task ID from ANY.RUN task URL."""
    patterns = [
        r"app\.any\.run/tasks/([a-f0-9-]{36})",
        r"any\.run/report/[^/]+/([a-f0-9-]{36})",
        r"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
    ]
    for pattern in patterns:
        m = re.search(pattern, url)
        if m:
            return m.group(1)
    return None


# ── Evidence extraction ───────────────────────────────────────────────────────

def extract_evidence(task: dict) -> dict:
    """Extract structured behavioral evidence from ANY.RUN task data."""
    ev = {
        "task_id": task.get("taskid", ""),
        "sha256": "",
        "filename": "",
        "family": "",
        "verdict": "",
        "score": 0,
        "processes": [],
        "network": {
            "http": [],
            "dns": [],
            "connections": [],
        },
        "files_created": [],
        "registry": [],
        "attck_techniques": [],
        "signatures": [],
        "summary": "",
    }

    # Top-level fields
    ev["sha256"] = task.get("sha256", task.get("hash", ""))
    ev["verdict"] = task.get("verdict", "")
    ev["score"] = task.get("scores", {}).get("verdict", {}).get("score", 0)

    # File info
    file_info = task.get("file", {})
    if not file_info:
        file_info = task.get("target", {}).get("file", {})
    ev["filename"] = file_info.get("name", file_info.get("filename", "unknown"))
    ev["sha256"] = ev["sha256"] or file_info.get("sha256", "")

    # Family detection
    threat = task.get("mainObject", {})
    ev["family"] = (
        threat.get("threatName", "") or
        task.get("threat", "") or
        task.get("family", "")
    )

    # Process tree
    processes = task.get("processes", []) or task.get("process", [])
    if isinstance(processes, list):
        for proc in processes[:15]:
            if isinstance(proc, dict):
                name = proc.get("name", proc.get("processName", ""))
                pid = proc.get("pid", "")
                cmd = proc.get("commandLine", proc.get("cmd", ""))[:150]
                if name:
                    ev["processes"].append({
                        "name": name,
                        "pid": pid,
                        "cmd": cmd,
                    })

    # Network activity
    network = task.get("network", {})
    if isinstance(network, dict):
        http_reqs = network.get("http", network.get("httpRequests", []))
        if isinstance(http_reqs, list):
            for r in http_reqs[:10]:
                if isinstance(r, dict):
                    ev["network"]["http"].append(
                        f"{r.get('method', 'GET')} {r.get('url', r.get('uri', ''))[:100]}"
                    )

        dns_reqs = network.get("dns", network.get("dnsRequests", []))
        if isinstance(dns_reqs, list):
            for r in dns_reqs[:10]:
                if isinstance(r, dict):
                    domain = r.get("domain", r.get("request", r.get("host", "")))
                    if domain:
                        ev["network"]["dns"].append(domain)

        conns = network.get("connections", [])
        if isinstance(conns, list):
            for c in conns[:10]:
                if isinstance(c, dict):
                    ip = c.get("ip", c.get("destinationIp", ""))
                    port = c.get("port", c.get("destinationPort", ""))
                    if ip:
                        ev["network"]["connections"].append(f"{ip}:{port}")

    # Files dropped
    files = task.get("files", task.get("droppedFiles", []))
    if isinstance(files, list):
        for f in files[:10]:
            if isinstance(f, dict):
                name = f.get("name", f.get("filename", f.get("path", "")))
                if name:
                    ev["files_created"].append(name[:100])

    # Registry
    reg = task.get("registry", task.get("registryKeys", []))
    if isinstance(reg, list):
        for r in reg[:10]:
            if isinstance(r, dict):
                key = r.get("key", r.get("path", ""))
                op = r.get("operation", r.get("type", ""))
                if key:
                    ev["registry"].append(f"{op}: {key[:120]}")

    # ATT&CK techniques
    techniques = (
        task.get("mitre", []) or
        task.get("attck", []) or
        task.get("techniques", [])
    )
    if isinstance(techniques, list):
        for t in techniques:
            if isinstance(t, dict):
                tid = t.get("id", t.get("technique_id", ""))
                tname = t.get("name", t.get("technique_name", ""))
                tactic = t.get("tactic", t.get("tactics", [""])[0] if isinstance(t.get("tactics"), list) else "")
                evidence = t.get("evidence", t.get("description", ""))[:200]
                if tid:
                    ev["attck_techniques"].append({
                        "id": tid,
                        "name": tname,
                        "tactic": tactic,
                        "evidence": evidence,
                    })

    # Signatures / behavioral indicators
    sigs = task.get("signatures", task.get("behaviorSummary", []))
    if isinstance(sigs, list):
        for s in sigs[:15]:
            if isinstance(s, dict):
                sname = s.get("name", s.get("title", ""))
                sdesc = s.get("description", s.get("desc", ""))[:200]
                severity = s.get("severity", s.get("score", ""))
                if sname:
                    ev["signatures"].append({
                        "name": sname,
                        "description": sdesc,
                        "severity": severity,
                    })

    # Summary text
    ev["summary"] = task.get("summary", task.get("description", ""))[:1000]

    return ev


def format_evidence_text(ev: dict) -> str:
    """Format extracted evidence as readable input text."""
    parts = []

    if ev["filename"]:
        parts.append(f"Sample: {ev['filename']}")
    if ev["sha256"]:
        parts.append(f"SHA256: {ev['sha256'][:16]}...")
    if ev["family"]:
        parts.append(f"Detected Family: {ev['family']}")
    if ev["score"]:
        parts.append(f"Threat Score: {ev['score']}/100")

    if ev["processes"]:
        parts.append("\nProcess Execution:")
        for p in ev["processes"][:8]:
            line = f"  {p['name']} (PID {p['pid']})"
            if p["cmd"]:
                line += f"\n    CMD: {p['cmd']}"
            parts.append(line)

    if ev["signatures"]:
        parts.append("\nBehavioral Signatures:")
        for s in ev["signatures"][:8]:
            sev = f"[{s['severity']}] " if s["severity"] else ""
            desc = f": {s['description']}" if s["description"] else ""
            parts.append(f"  {sev}{s['name']}{desc}")

    net = ev["network"]
    if net["http"]:
        parts.append("\nHTTP Requests:")
        for r in net["http"][:5]:
            parts.append(f"  {r}")
    if net["dns"]:
        parts.append("\nDNS Queries:")
        parts.append(f"  {', '.join(net['dns'][:8])}")
    if net["connections"]:
        parts.append("\nNetwork Connections:")
        parts.append(f"  {', '.join(net['connections'][:6])}")

    if ev["files_created"]:
        parts.append("\nDropped/Created Files:")
        for f in ev["files_created"][:5]:
            parts.append(f"  {f}")

    if ev["registry"]:
        parts.append("\nRegistry Operations:")
        for r in ev["registry"][:5]:
            parts.append(f"  {r}")

    if ev["attck_techniques"]:
        parts.append("\nDetected ATT&CK Techniques:")
        for t in ev["attck_techniques"][:10]:
            tact = f" [{t['tactic']}]" if t["tactic"] else ""
            parts.append(f"  {t['id']} {t['name']}{tact}")

    return "\n".join(parts)


# ── Output builders ───────────────────────────────────────────────────────────

def build_analysis_output(ev: dict) -> str:
    """Build the full analysis report output."""
    family = ev["family"] or "Unknown"
    score = ev["score"]
    verdict = "MALICIOUS" if score > 30 else "SUSPICIOUS"

    # Build technique section
    tech_lines = []
    for t in ev["attck_techniques"]:
        tact = f" (Tactic: {t['tactic']})" if t["tactic"] else ""
        evid = f"\n    Evidence: {t['evidence']}" if t["evidence"] else ""
        tech_lines.append(f"- **{t['id']}** {t['name']}{tact}{evid}")

    tech_section = "\n".join(tech_lines) if tech_lines else (
        "- Further analysis required to map specific techniques"
    )

    # Build IOC section
    iocs = []
    net = ev["network"]
    if net["dns"]:
        iocs.extend([f"  Domain: {d}" for d in net["dns"][:5]])
    if net["connections"]:
        iocs.extend([f"  IP: {c}" for c in net["connections"][:5]])
    if net["http"]:
        iocs.extend([f"  URL: {r}" for r in net["http"][:3]])
    if ev["files_created"]:
        iocs.extend([f"  File: {f}" for f in ev["files_created"][:3]])
    ioc_section = "\n".join(iocs) if iocs else "  None extracted from sandbox execution"

    # Process summary
    proc_count = len(ev["processes"])
    spawned = ", ".join(p["name"] for p in ev["processes"][:5])

    return (
        f"## Malware Analysis Report\n\n"
        f"**Classification:** {family}\n"
        f"**Verdict:** {verdict}\n"
        f"**Threat Score:** {score}/100\n\n"
        f"## Executive Summary\n\n"
        f"This sandbox execution of **{ev['filename'] or 'the sample'}** reveals "
        f"behavior consistent with **{family}** malware. The sample scored {score}/100 "
        f"on the threat scale with {len(ev['signatures'])} behavioral signatures triggered. "
        f"{'The malware established network connections to external infrastructure.' if net['connections'] or net['http'] else ''}\n\n"
        f"## Behavioral Analysis\n\n"
        f"**Process Activity:** {proc_count} processes observed"
        + (f" ({spawned})" if spawned else "") + "\n\n"
        + (
            "**Behavioral Indicators:**\n"
            + "\n".join(f"- {s['name']}: {s['description']}" if s['description'] else f"- {s['name']}"
                       for s in ev["signatures"][:6])
            + "\n\n"
            if ev["signatures"] else ""
        )
        + f"## MITRE ATT&CK Mapping\n\n"
        f"{tech_section}\n\n"
        f"## Indicators of Compromise\n\n"
        f"{ioc_section}\n\n"
        f"## Recommendations\n\n"
        f"1. Isolate affected endpoint and collect memory forensic image\n"
        f"2. Hunt for IOCs across the environment using the extracted indicators\n"
        f"3. Update detection rules based on the observed behavioral signatures\n"
        f"4. Review the ATT&CK mappings to assess detection coverage gaps"
    )


def build_attck_output(ev: dict) -> str:
    """Build ATT&CK-focused output."""
    if not ev["attck_techniques"]:
        return ""

    lines = []
    for t in ev["attck_techniques"]:
        tact = f"\n  Tactic: {t['tactic']}" if t["tactic"] else ""
        evid = f"\n  Evidence: {t['evidence']}" if t["evidence"] else ""
        lines.append(f"**{t['id']}** — {t['name']}{tact}{evid}\n")

    return (
        f"## ATT&CK Technique Analysis\n\n"
        f"The following MITRE ATT&CK techniques were identified in this "
        f"{ev['family'] or 'malware'} sample:\n\n"
        + "\n".join(lines) +
        f"\n## Coverage Assessment\n\n"
        f"{len(ev['attck_techniques'])} technique(s) mapped across "
        f"{len(set(t['tactic'] for t in ev['attck_techniques'] if t['tactic']))} tactic(s). "
        f"Refer to the ATT&CK Navigator layer for full coverage visualization."
    )


def build_summary_output(ev: dict) -> str:
    """Build executive summary output."""
    family = ev["family"] or "Unknown"
    net = ev["network"]
    has_network = bool(net["connections"] or net["http"] or net["dns"])
    has_persistence = any(
        "persist" in s["name"].lower() or "autorun" in s["name"].lower() or "registry" in s["name"].lower()
        for s in ev["signatures"]
    )

    return (
        f"## Executive Summary\n\n"
        f"**Threat:** {family} | **Risk:** {'High' if ev['score'] > 70 else 'Medium' if ev['score'] > 40 else 'Low'}\n\n"
        f"Analysis of **{ev['filename'] or 'the submitted sample'}** confirms this is a "
        f"{'known ' if ev['family'] else ''}{family} sample with a threat score of {ev['score']}/100.\n\n"
        f"**Key Findings:**\n"
        f"- {len(ev['attck_techniques'])} MITRE ATT&CK techniques identified\n"
        f"- {len(ev['signatures'])} behavioral signatures triggered\n"
        f"{'- Network communication to external C2 infrastructure observed' + chr(10) if has_network else ''}"
        f"{'- Persistence mechanisms detected' + chr(10) if has_persistence else ''}"
        f"- {len(ev['processes'])} process(es) spawned during execution\n\n"
        f"**Immediate Actions Required:**\n"
        f"1. Quarantine the affected host(s)\n"
        f"2. Block the identified network IOCs at the perimeter\n"
        f"3. Initiate incident response procedures\n"
        f"4. Notify relevant stakeholders per IR playbook"
    )


def task_to_pairs(ev: dict) -> list[dict]:
    """Convert extracted evidence to 1-3 Alpaca instruction pairs."""
    evidence_text = format_evidence_text(ev)
    if len(evidence_text.strip()) < 50:
        return []

    pairs = []

    # Pair 1: Full analysis report
    output1 = build_analysis_output(ev)
    if len(output1) > 100:
        pairs.append({
            "instruction": random.choice(INSTRUCTION_ANALYZE),
            "input": evidence_text[:2500],
            "output": output1,
        })

    # Pair 2: ATT&CK mapping (only if techniques exist)
    if ev["attck_techniques"]:
        output2 = build_attck_output(ev)
        if output2:
            pairs.append({
                "instruction": random.choice(INSTRUCTION_ATTCK),
                "input": evidence_text[:2500],
                "output": output2,
            })

    # Pair 3: Executive summary
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
    parser = argparse.ArgumentParser(description="Scrape ANY.RUN reports for training data")
    parser.add_argument("--api-key", type=str, required=True,
                        help="ANY.RUN API key (free: https://app.any.run/signup)")
    parser.add_argument("--families", nargs="+",
                        default=["Emotet", "AgentTesla", "RedLine", "AsyncRAT", "Remcos",
                                 "Qakbot", "IcedID", "Formbook", "NjRAT", "LockBit"],
                        help="Malware families to search")
    parser.add_argument("--count", type=int, default=50,
                        help="Reports per family to fetch (default 50)")
    parser.add_argument("--task-ids", type=str, default=None,
                        help="File containing one task ID per line")
    parser.add_argument("--urls", type=str, default=None,
                        help="File containing one ANY.RUN URL per line")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--delay", type=float, default=RATE_LIMIT_DELAY,
                        help="Delay between API calls in seconds (default 1.5)")
    args = parser.parse_args()

    out_dir = Path(__file__).resolve().parent.parent.parent / "data" / "processed"
    out_path = Path(args.output) if args.output else out_dir / "anyrun_reports.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    client = AnyRunClient(args.api_key)
    random.seed(42)

    task_ids = []

    # Source 1: From explicit task ID file
    if args.task_ids:
        id_file = Path(args.task_ids)
        if id_file.exists():
            task_ids.extend([l.strip() for l in id_file.read_text().strip().split("\n") if l.strip()])
            print(f"Loaded {len(task_ids)} task IDs from {args.task_ids}")

    # Source 2: From URL file
    if args.urls:
        url_file = Path(args.urls)
        if url_file.exists():
            for url in url_file.read_text().strip().split("\n"):
                url = url.strip()
                if url:
                    tid = extract_task_id_from_url(url)
                    if tid:
                        task_ids.append(tid)
                    else:
                        print(f"  [WARN] Could not parse task ID from: {url}")
            print(f"Loaded {len(task_ids)} task IDs from URLs")

    # Source 3: Search by family name
    if not task_ids:
        print(f"Searching {len(args.families)} malware families...")
        for family in args.families:
            print(f"  Searching: {family}...")
            tasks = client.search_public_tasks(family, limit=args.count)
            if not tasks:
                # Try threat name search as fallback
                tasks = client.search_by_threat_name(family, limit=args.count)

            new_ids = [t.get("taskid", t.get("id", "")) for t in tasks if t]
            task_ids.extend([tid for tid in new_ids if tid])
            print(f"    Found {len(new_ids)} tasks for {family}")
            time.sleep(args.delay)

    # Deduplicate
    task_ids = list(dict.fromkeys(task_ids))
    print(f"\nTotal unique task IDs to fetch: {len(task_ids)}")

    # Fetch and convert
    total_pairs = 0
    skipped = 0
    written = 0

    with open(out_path, "a", encoding="utf-8") as out:
        for i, task_id in enumerate(task_ids, 1):
            if not task_id:
                continue

            print(f"[{i}/{len(task_ids)}] Fetching {task_id}...", end=" ")
            task = client.get_task(task_id)

            if not task:
                print("SKIP (no data)")
                skipped += 1
                time.sleep(args.delay)
                continue

            ev = extract_evidence(task)
            pairs = task_to_pairs(ev)

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

            print(f"OK ({family}, {len(pairs)} pairs, score={ev['score']})")
            time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"Fetched: {written} reports, Skipped: {skipped}")
    print(f"Total instruction pairs written: {total_pairs}")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
