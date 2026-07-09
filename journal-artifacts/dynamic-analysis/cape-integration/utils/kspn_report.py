#!/usr/bin/env python3
"""Generate a polished host-side post-analysis malware report from CAPE artifacts."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import html
import io
import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ANALYSES_DIR = ROOT / "storage" / "analyses"


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def path_ref(path: Path) -> str:
    try:
        return str(path.resolve())
    except FileNotFoundError:
        return str(path)


def rel_to_root(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except Exception:
        return str(path)


def uniq(values: Iterable[Any]) -> list[Any]:
    seen = set()
    result = []
    for item in values:
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def shorten(text: Any, limit: int = 120) -> str:
    value = str(text or "")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def format_bytes(value: Any) -> str:
    if value in (None, ""):
        return "Unknown"
    try:
        size = float(value)
    except Exception:
        return str(value)
    units = ["B", "KB", "MB", "GB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.2f} {units[idx]}"


def bullet_list(title: str, items: list[str], empty_note: str) -> list[str]:
    lines = [f"### {title}", ""]
    if not items:
        lines.append(empty_note)
        lines.append("")
        return lines
    for item in items:
        lines.append(f"- {item}")
    lines.append("")
    return lines


def count_non_empty(values: Iterable[Any]) -> int:
    return sum(1 for value in values if value)


def safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def top_strings(strings: list[str], limit: int = 12) -> list[str]:
    filtered = [s for s in strings if isinstance(s, str) and len(s) >= 6]
    filtered.sort(key=lambda item: (-len(item), item))
    return uniq(filtered[:limit])


def normalize_family_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "", str(name or ""))
    return clean or str(name or "").strip()


def family_and_confidence(target_file: dict[str, Any], payloads: list[dict[str, Any]], signatures: list[dict[str, Any]]) -> tuple[str, int, list[str], list[dict[str, Any]]]:
    weights: Counter[str] = Counter()
    evidence_items: list[dict[str, Any]] = []

    def add_name(name: str, weight: int, reason: str, source: str) -> None:
        clean = normalize_family_name(name)
        if not clean:
            return
        weights[clean] += weight
        evidence_items.append({"family": clean, "weight": weight, "reason": reason, "source": source})

    for hit in safe_list(target_file.get("cape_yara")) + safe_list(target_file.get("yara")):
        if isinstance(hit, dict):
            add_name(
                hit.get("name", ""),
                5 if hit in safe_list(target_file.get("cape_yara")) else 3,
                "Target-file YARA match",
                "target_file",
            )
    for payload in payloads:
        for hit in safe_list(payload.get("cape_yara")) + safe_list(payload.get("yara")):
            if isinstance(hit, dict):
                add_name(hit.get("name", ""), 4, "Payload YARA match", "payload")
        cape_type = payload.get("cape_type")
        if cape_type:
            evidence_items.append(
                {
                    "family": None,
                    "weight": 1,
                    "reason": f"CAPE classified payload as {cape_type}",
                    "source": payload.get("name", "payload"),
                }
            )
    for sig in signatures:
        if isinstance(sig, dict):
            add_name(sig.get("name", ""), 2, "Behavior signature name", "signature")

    if not weights:
        return ("Unknown", 15, [], [])

    ranked = weights.most_common()
    family, score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    support_count = sum(1 for item in evidence_items if item.get("family") == family)
    margin = score - runner_up
    confidence = 25 + min(30, score * 6) + min(20, support_count * 4) + min(15, margin * 4)
    if runner_up and margin <= 2:
        confidence -= 10
    confidence = max(20, min(90, confidence))
    evidence_lines = [
        f"{item['family']}: {item['reason']} via {item['source']}"
        for item in evidence_items
        if item.get("family") == family
    ]
    top_evidence = sorted(
        [item for item in evidence_items if item.get("family") == family],
        key=lambda item: (-item["weight"], item["reason"]),
    )[:5]
    return (family, confidence, uniq(evidence_lines), top_evidence)


def infer_classification(family: str, target_file: dict[str, Any], payloads: list[dict[str, Any]], behavior_summary: dict[str, Any]) -> tuple[str, list[str]]:
    text_blob = " ".join(
        [
            family.lower(),
            str(target_file.get("type", "")).lower(),
            " ".join(str(s).lower() for s in safe_list(target_file.get("strings"))[:80]),
            " ".join(str(payload.get("cape_type", "")).lower() for payload in payloads),
            " ".join(str(path).lower() for path in safe_list(behavior_summary.get("files"))[:100]),
        ]
    )
    reasons = []
    if "agenttesla" in text_blob or "opera stable" in text_blob or "browser" in text_blob:
        reasons.append("Observed AgentTesla-oriented YARA hits and browser/profile path access")
        return ("Credential theft / infostealer", reasons)
    if ".net" in text_blob or "mono/.net" in text_blob:
        reasons.append("Observed .NET executable metadata in the target sample")
    if "powershell.exe" in text_blob:
        reasons.append("Observed PowerShell execution during detonation")
    return ("Suspicious .NET malware", reasons or ["Classification inferred from executable type and CAPE payload behavior"])


def infer_capabilities(behavior_summary: dict[str, Any], network: dict[str, Any], payloads: list[dict[str, Any]], family: str) -> list[dict[str, str]]:
    caps: list[dict[str, str]] = []
    files = " ".join(str(v).lower() for v in safe_list(behavior_summary.get("files")))
    reg_write = safe_list(behavior_summary.get("write_keys"))
    reg_delete = safe_list(behavior_summary.get("delete_keys"))
    hosts = [host.get("ip") for host in safe_list(network.get("hosts")) if isinstance(host, dict) and host.get("ip")]
    if family != "Unknown":
        caps.append({"name": "Family-aligned malware execution", "confidence": "High", "evidence": f"Family inference: {family}"})
    if any(token in files for token in ("opera", "chrome", "edge", "firefox", "wallet", "login data")):
        caps.append({"name": "Credential or browser data access", "confidence": "Medium", "evidence": "Behavior summary references browser- and profile-related file paths"})
    if reg_write or reg_delete:
        caps.append({"name": "Registry modification", "confidence": "High", "evidence": f"Observed {len(reg_write)} registry writes and {len(reg_delete)} registry deletes in behavior summary"})
    if payloads:
        caps.append({"name": "In-memory unpacking / secondary payload material", "confidence": "High", "evidence": f"CAPE extracted {len(payloads)} payload artifact(s)"})
    if hosts:
        caps.append({"name": "Outbound network activity", "confidence": "Medium", "evidence": f"Observed network hosts: {', '.join(hosts[:5])}"})
    return caps


def infer_objective(classification: str, behavior_summary: dict[str, Any], network: dict[str, Any]) -> tuple[str, list[str]]:
    files_blob = " ".join(str(v).lower() for v in safe_list(behavior_summary.get("files")))
    reasons = []
    if "credential" in classification.lower() or "infostealer" in classification.lower():
        reasons.append("Family and string evidence align with credential or browser-data theft")
        return ("Credential theft and data collection", reasons)
    if any(token in files_blob for token in ("opera", "chrome", "firefox", "wallet", "cookies")):
        reasons.append("Observed file paths reference browser profiles or credential stores")
        return ("Browser data collection", reasons)
    if safe_list(network.get("hosts")):
        reasons.append("Observed outbound network communications suggest remote collection or staging")
        return ("Outbound beaconing or data staging", reasons)
    return ("Malware execution with uncertain objective", ["Available evidence does not support a narrower mission assessment"])


def infer_mitre(behavior_summary: dict[str, Any], network: dict[str, Any], payloads: list[dict[str, Any]], processes: list[dict[str, Any]]) -> list[dict[str, str]]:
    mappings: list[dict[str, str]] = []
    files = safe_list(behavior_summary.get("files"))
    read_keys = safe_list(behavior_summary.get("read_keys"))
    write_keys = safe_list(behavior_summary.get("write_keys"))
    delete_keys = safe_list(behavior_summary.get("delete_keys"))
    process_names = {str(proc.get("process_name", "")).lower() for proc in processes if isinstance(proc, dict)}
    if payloads:
        mappings.append({"technique": "T1055", "name": "Process Injection", "confidence": "Medium", "evidence": "CAPE memory payload extraction indicates runtime code staging or injected material"})
    if write_keys or delete_keys:
        mappings.append({"technique": "T1112", "name": "Modify Registry", "confidence": "High", "evidence": f"Behavior summary shows {len(write_keys)} write key(s) and {len(delete_keys)} delete key(s)"})
    if any("run" in str(key).lower() or "startup" in str(key).lower() for key in write_keys):
        mappings.append({"technique": "T1547.001", "name": "Registry Run Keys / Startup Folder", "confidence": "Medium", "evidence": "Persistence-oriented registry path observed in write activity"})
    if "powershell.exe" in process_names:
        mappings.append({"technique": "T1059.001", "name": "PowerShell", "confidence": "High", "evidence": "PowerShell spawned during execution"})
    hosts = [host.get("ip") for host in safe_list(network.get("hosts")) if isinstance(host, dict)]
    if hosts:
        mappings.append({"technique": "T1071", "name": "Application Layer Protocol", "confidence": "Medium", "evidence": f"Outbound communications observed toward {', '.join(hosts[:3])}"})
    if any(port == 53 for entry in safe_list(network.get("udp")) for port in [entry.get("dport")] if isinstance(entry, dict)):
        mappings.append({"technique": "T1071.004", "name": "DNS", "confidence": "Medium", "evidence": "UDP/53 traffic observed in network telemetry"})
    if read_keys:
        mappings.append({"technique": "T1012", "name": "Query Registry", "confidence": "High", "evidence": f"Observed {len(read_keys)} registry read key(s) in behavior summary"})
    if files:
        mappings.append({"technique": "T1083", "name": "File and Directory Discovery", "confidence": "Medium", "evidence": "Behavior summary contains filesystem enumeration and access traces"})
    return uniq(mappings)


def risk_rating(
    classification: str,
    objective: str,
    payload_count: int,
    network_count: int,
    reg_write_count: int,
    screenshot_count: int,
    capabilities: list[dict[str, str]],
    ioc_counts: dict[str, int],
    family_confidence: int,
) -> tuple[str, int, list[str]]:
    score = 10
    reasons = []
    class_lower = classification.lower()
    objective_lower = objective.lower()
    if "credential" in class_lower or "infostealer" in class_lower:
        score += 26
        reasons.append("Credential-theft behavior materially increases business impact")
    elif "loader" in class_lower or "trojan" in class_lower:
        score += 18
        reasons.append("Generic malware execution with follow-on payload potential")

    if "data collection" in objective_lower or "credential" in objective_lower:
        score += 10
        reasons.append("Likely objective involves collection of user or browser data")
    if payload_count:
        score += min(14, 4 + payload_count * 4)
        reasons.append(f"CAPE extracted {payload_count} in-memory or unpacked payload artifact(s)")
    if reg_write_count:
        score += min(12, reg_write_count * 2)
        reasons.append("Registry modifications elevate persistence or tampering risk")
    if network_count:
        score += min(12, 4 + network_count // 3)
        reasons.append("Observed external network indicators suggest outbound communications")
    if screenshot_count >= 10:
        score += 4
        reasons.append("Repeated screenshots indicate extended interactive execution coverage")
    if ioc_counts.get("urls", 0) or ioc_counts.get("domains", 0):
        score += 6
        reasons.append("Higher-confidence network identifiers were extracted")
    if ioc_counts.get("ips", 0) > 15:
        score += 4
        reasons.append("Large IOC surface increases containment effort")
    if any("Registry modification" in cap["name"] for cap in capabilities):
        score += 6
    if any("Outbound network activity" in cap["name"] for cap in capabilities):
        score += 6
    if any("secondary payload" in cap["name"].lower() for cap in capabilities):
        score += 8
    if family_confidence >= 70:
        score += 4
        reasons.append("Family attribution is supported by multiple local evidence points")

    score = min(95, score)
    if score >= 75:
        return ("High", score, reasons)
    if score >= 45:
        return ("Medium", score, reasons)
    return ("Low", score, reasons)


def prioritize_iocs(
    target_file: dict[str, Any],
    ips: list[str],
    domains: list[str],
    urls: list[str],
    smtp: list[str],
    notable_reg: list[str],
    notable_files: list[str],
    mutexes: list[str],
    process_names: list[str],
) -> dict[str, dict[str, list[str]]]:
    def score_registry(value: str) -> int:
        v = value.lower()
        score = 1
        if any(token in v for token in ("run", "runonce", "policies", "services", "shell", "winlogon", "startup")):
            score += 3
        if "software\\" in v or "currentversion" in v:
            score += 1
        return score

    def score_file(value: str) -> int:
        v = value.lower()
        score = 1
        if any(token in v for token in ("appdata", "temp\\test_sample", "\\startup", "opera", "chrome", "firefox", "wallet", "login data")):
            score += 3
        if v.endswith((".exe", ".dll", ".dat", ".config")):
            score += 1
        return score

    def score_process(value: str) -> int:
        v = value.lower()
        score = 1
        if any(token in v for token in ("powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32", "test_sample.exe")):
            score += 3
        return score

    def split_conf(items: list[str], scorer) -> dict[str, list[str]]:
        deduped = uniq([item for item in items if item])
        ranked = sorted(deduped, key=lambda item: (-scorer(item), item))
        high = [item for item in ranked if scorer(item) >= 4]
        medium = [item for item in ranked if scorer(item) == 3]
        low = [item for item in ranked if scorer(item) <= 2]
        return {"high": high[:15], "medium": medium[:15], "low": low[:15]}

    net_high = uniq(domains[:15] + urls[:15])
    ip_groups = {"high": uniq(ips[:15]), "medium": [], "low": []}
    grouped = {
        "files": split_conf([target_file.get("sha256"), target_file.get("md5"), *notable_files], score_file),
        "registry": split_conf(notable_reg, score_registry),
        "processes": split_conf(process_names, score_process),
        "domains": {"high": net_high[:15], "medium": [], "low": []},
        "ips": ip_groups,
        "urls": {"high": uniq(urls[:15]), "medium": [], "low": []},
        "emails": {"high": uniq(smtp[:15]), "medium": [], "low": []},
        "mutexes": {"high": uniq(mutexes[:15]), "medium": [], "low": []},
    }
    return grouped


def clean_artifact_refs(artifact_refs: dict[str, Any]) -> list[str]:
    preferred_order = ["report_json", "analysis_log", "cuckoo_log", "dump_pcap", "files_json", "digisig_json"]
    labels = {
        "report_json": "report.json",
        "analysis_log": "analysis.log",
        "cuckoo_log": "cuckoo.log",
        "dump_pcap": "dump.pcap",
        "files_json": "files.json",
        "digisig_json": "aux/DigiSig.json",
    }
    lines = []
    for key in preferred_order:
        value = artifact_refs.get(key)
        if value:
            lines.append(f"{labels.get(key, key)} -> `{value}`")
    return lines


def summarize_process_tree(tree: list[dict[str, Any]], depth: int = 0) -> list[str]:
    lines: list[str] = []
    for node in tree:
        if not isinstance(node, dict):
            continue
        name = node.get("name") or node.get("process_name") or "unknown"
        pid = node.get("pid") or node.get("process_id") or "?"
        path = node.get("command_line") or node.get("module_path") or ""
        lines.append(f"{'  ' * depth}- {name} (PID {pid}) {shorten(path, 110)}".rstrip())
        lines.extend(summarize_process_tree(safe_list(node.get("children")), depth + 1))
    return lines


def sample_events_from_bson(log_dir: Path) -> dict[str, list[dict[str, Any]]]:
    samples = {"registry": [], "filesystem": [], "process": []}
    if not log_dir.exists():
        return samples

    sys.path.insert(0, str(ROOT))
    try:
        logging.disable(logging.CRITICAL)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            from modules.processing.behavior import ParseProcessLog
    except Exception:
        return samples
    finally:
        logging.disable(logging.NOTSET)

    opts = SimpleNamespace(ram_mmap=False, ram_boost=False, analysis_call_limit=0, replace_patterns=False)
    seen: set[tuple[str, str, str]] = set()
    try:
        for bson_path in sorted(log_dir.glob("*.bson")):
            parser = ParseProcessLog(str(bson_path), opts)
            try:
                for call in parser:
                    category = str(call.get("category", "")).lower()
                    bucket = None
                    if category == "registry":
                        bucket = "registry"
                    elif category == "filesystem":
                        bucket = "filesystem"
                    elif category == "process":
                        bucket = "process"
                    if not bucket or len(samples[bucket]) >= 8:
                        continue
                    api = str(call.get("api", ""))
                    args = safe_list(call.get("arguments"))
                    arg_preview = ", ".join(f"{arg.get('name')}={arg.get('value')}" for arg in args[:4])
                    dedupe_key = (bucket, api, arg_preview)
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    samples[bucket].append(
                        {
                            "api": api,
                            "status": call.get("status"),
                            "arguments": arg_preview,
                            "timestamp": call.get("timestamp"),
                        }
                    )
            finally:
                parser.close()
    finally:
        if sys.path and sys.path[0] == str(ROOT):
            sys.path.pop(0)
    return samples


def collect_analysis(analysis_id: int, include_all_artifacts: bool) -> dict[str, Any]:
    analysis_dir = ANALYSES_DIR / str(analysis_id)
    reports_dir = analysis_dir / "reports"
    report_path = reports_dir / "report.json"
    report = safe_dict(load_json(report_path))
    target = safe_dict(report.get("target"))
    target_file = safe_dict(target.get("file"))
    info = safe_dict(report.get("info"))
    behavior = safe_dict(report.get("behavior"))
    behavior_summary = safe_dict(behavior.get("summary"))
    network = safe_dict(report.get("network"))
    cape = safe_dict(report.get("CAPE"))
    payloads = safe_list(cape.get("payloads"))
    signatures = safe_list(report.get("signatures"))
    pe = safe_dict(target_file.get("pe"))
    digi_sig = safe_dict(load_json(analysis_dir / "aux" / "DigiSig.json"))
    files_json = load_jsonl(analysis_dir / "files.json")
    analysis_log = (analysis_dir / "analysis.log").read_text(encoding="utf-8", errors="ignore") if (analysis_dir / "analysis.log").exists() else ""
    cuckoo_log = (analysis_dir / "cuckoo.log").read_text(encoding="utf-8", errors="ignore") if (analysis_dir / "cuckoo.log").exists() else ""
    dropped = safe_list(report.get("dropped"))
    procdump = safe_list(report.get("procdump"))
    procmemory = safe_list(report.get("procmemory"))
    screenshots = sorted((analysis_dir / "shots").glob("*")) if (analysis_dir / "shots").exists() else []
    tlsdump_files = sorted((analysis_dir / "tlsdump").glob("*")) if (analysis_dir / "tlsdump").exists() else []
    cape_files = sorted((analysis_dir / "CAPE").glob("*")) if (analysis_dir / "CAPE").exists() else []
    selfextracted = sorted((analysis_dir / "selfextracted").glob("*")) if (analysis_dir / "selfextracted").exists() else []
    files_dir = sorted((analysis_dir / "files").glob("*")) if (analysis_dir / "files").exists() else []
    logs_dir = analysis_dir / "logs"
    bson_samples = sample_events_from_bson(logs_dir)

    family, family_confidence, family_evidence, family_top_evidence = family_and_confidence(target_file, payloads, signatures)
    classification, classification_reasons = infer_classification(family, target_file, payloads, behavior_summary)
    objective, objective_reasons = infer_objective(classification, behavior_summary, network)
    capabilities = infer_capabilities(behavior_summary, network, payloads, family)
    mitre = infer_mitre(behavior_summary, network, payloads, safe_list(behavior.get("processes")))

    yara_hits = uniq(
        [hit.get("name") for hit in safe_list(target_file.get("yara")) if isinstance(hit, dict)]
        + [hit.get("name") for hit in safe_list(target_file.get("cape_yara")) if isinstance(hit, dict)]
        + [hit.get("name") for payload in payloads for hit in safe_list(payload.get("cape_yara")) if isinstance(hit, dict)]
    )
    clamav_hits = uniq(
        [hit for hit in safe_list(target_file.get("clamav"))]
        + [hit for payload in payloads for hit in safe_list(payload.get("clamav"))]
    )

    process_tree_lines = summarize_process_tree(safe_list(behavior.get("processtree")))
    process_names = uniq(
        [f"{proc.get('process_name')} (PID {proc.get('process_id')})" for proc in safe_list(behavior.get("processes")) if isinstance(proc, dict)]
    )
    command_lines = []
    for proc in safe_list(behavior.get("processes")):
        if not isinstance(proc, dict):
            continue
        module_path = proc.get("module_path")
        if module_path:
            command_lines.append(f"{proc.get('process_name')} -> {module_path}")
    command_lines = uniq(command_lines)

    reg_reads = uniq([str(v) for v in safe_list(behavior_summary.get("read_keys")) if v])[:30]
    reg_writes = uniq([str(v) for v in safe_list(behavior_summary.get("write_keys")) if v])[:30]
    reg_deletes = uniq([str(v) for v in safe_list(behavior_summary.get("delete_keys")) if v])[:30]
    notable_reg = uniq((reg_writes + reg_deletes + reg_reads)[:25])
    notable_files = uniq(
        [str(v) for v in safe_list(behavior_summary.get("files")) if v][:40]
        + [entry.get("filepath") for entry in files_json if isinstance(entry, dict) and entry.get("filepath")]
        + [item.get("path") for item in dropped if isinstance(item, dict) and item.get("path")]
        + [item.get("path") for item in payloads if isinstance(item, dict) and item.get("path")]
    )[:40]
    mutexes = uniq([str(v) for v in safe_list(behavior_summary.get("mutexes")) if v])[:25]

    domains = []
    for item in safe_list(network.get("domains")):
        if isinstance(item, dict):
            value = item.get("domain") or item.get("hostname")
            if value:
                domains.append(value)
    urls = []
    for item in safe_list(network.get("http")):
        if isinstance(item, dict):
            uri = item.get("uri") or item.get("url")
            if uri:
                urls.append(uri)
    ips = []
    for item in safe_list(network.get("hosts")):
        if isinstance(item, dict) and item.get("ip"):
            ips.append(item["ip"])
    for row in safe_list(network.get("dead_hosts")):
        if isinstance(row, list) and row:
            ips.append(str(row[0]))
    ips = [ip for ip in uniq(ips) if not ip.startswith("192.168.122.")]
    smtp = []
    for item in safe_list(network.get("smtp")):
        if isinstance(item, dict):
            for key in ("mail_from", "mail_to", "hostname"):
                if item.get(key):
                    smtp.append(f"{key}={item.get(key)}")
    dns_queries = []
    for item in safe_list(network.get("dns")):
        if isinstance(item, dict):
            request = item.get("request")
            if request:
                dns_queries.append(request)
    if not dns_queries and any(isinstance(item, dict) and item.get("dport") == 53 for item in safe_list(network.get("udp"))):
        dns_queries.append("UDP/53 traffic observed, but no parsed DNS requests were produced in report.json")

    inetsim_evidence = []
    if info.get("route") == "inetsim":
        inetsim_evidence.append("Task route recorded as inetsim")
    if "inetsim" in analysis_log.lower() or "inetsim" in cuckoo_log.lower():
        inetsim_evidence.append("Log output references inetsim routing")

    artifact_refs = {
        "report_json": path_ref(report_path),
        "analysis_log": path_ref(analysis_dir / "analysis.log"),
        "cuckoo_log": path_ref(analysis_dir / "cuckoo.log"),
        "dump_pcap": path_ref(analysis_dir / "dump.pcap") if (analysis_dir / "dump.pcap").exists() else None,
        "files_json": path_ref(analysis_dir / "files.json") if (analysis_dir / "files.json").exists() else None,
        "digisig_json": path_ref(analysis_dir / "aux" / "DigiSig.json") if (analysis_dir / "aux" / "DigiSig.json").exists() else None,
    }

    all_artifacts = []
    if include_all_artifacts:
        for child in sorted(analysis_dir.rglob("*")):
            if child.is_file():
                all_artifacts.append(rel_to_root(child))

    technical_limitations = []
    if not report:
        technical_limitations.append("report.json is missing, so the report relies only on raw artifacts.")
    if not safe_dict(report.get("static")):
        technical_limitations.append("The CAPE static section is absent for this analysis; PE metadata was taken from target.file.pe instead.")
    if not safe_list(network.get("http")):
        technical_limitations.append("No parsed HTTP transactions were present in report.json.")
    if not safe_list(network.get("dns")):
        technical_limitations.append("Parsed DNS records were absent; only packet-level UDP/53 evidence may be available.")
    if not tlsdump_files:
        technical_limitations.append("No tlsdump artifacts were present in the analysis directory.")

    ioc_groups = prioritize_iocs(target_file, ips, domains, urls, smtp, notable_reg, notable_files, mutexes, process_names)
    ioc_counts = {
        "ips": len(ips),
        "domains": len(domains),
        "urls": len(urls),
        "registry_keys": len(notable_reg),
        "files": len(notable_files),
        "mutexes": len(mutexes),
    }
    risk_label, risk_score, risk_reasons = risk_rating(
        classification,
        objective,
        len(payloads),
        len(safe_list(network.get("hosts"))),
        len(safe_list(behavior_summary.get("write_keys"))),
        len(screenshots),
        capabilities,
        ioc_counts,
        family_confidence,
    )

    json_summary = {
        "analysis_id": analysis_id,
        "family_guess": family,
        "family_confidence": family_confidence,
        "classification": classification,
        "objective": objective,
        "risk_rating": risk_label,
        "risk_score": risk_score,
        "ioc_counts": ioc_counts,
        "artifacts": {
            "payloads": len(payloads),
            "dropped": len(dropped),
            "procdump": len(procdump),
            "procmemory": len(procmemory),
            "screenshots": len(screenshots),
            "pcap": artifact_refs["dump_pcap"] is not None,
        },
        "mitre": mitre,
        "capabilities": capabilities,
        "family_top_evidence": family_top_evidence,
        "risk_reasons": risk_reasons,
    }

    return {
        "analysis_id": analysis_id,
        "analysis_dir": analysis_dir,
        "reports_dir": reports_dir,
        "report_path": report_path,
        "report": report,
        "target_file": target_file,
        "pe": pe,
        "info": info,
        "behavior": behavior,
        "behavior_summary": behavior_summary,
        "network": network,
        "payloads": payloads,
        "signatures": signatures,
        "dropped": dropped,
        "procdump": procdump,
        "procmemory": procmemory,
        "digi_sig": digi_sig,
        "files_json": files_json,
        "cape_files": cape_files,
        "selfextracted": selfextracted,
        "files_dir": files_dir,
        "screenshots": screenshots,
        "tlsdump_files": tlsdump_files,
        "family": family,
        "family_confidence": family_confidence,
        "family_evidence": family_evidence,
        "family_top_evidence": family_top_evidence,
        "classification": classification,
        "classification_reasons": classification_reasons,
        "objective": objective,
        "objective_reasons": objective_reasons,
        "capabilities": capabilities,
        "mitre": mitre,
        "risk_label": risk_label,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "yara_hits": yara_hits,
        "clamav_hits": clamav_hits,
        "process_tree_lines": process_tree_lines,
        "process_names": process_names,
        "command_lines": command_lines[:25],
        "reg_reads": reg_reads,
        "reg_writes": reg_writes,
        "reg_deletes": reg_deletes,
        "notable_reg": notable_reg,
        "notable_files": notable_files,
        "mutexes": mutexes,
        "domains": domains[:40],
        "urls": urls[:40],
        "ips": ips[:40],
        "smtp": smtp[:20],
        "dns_queries": dns_queries[:25],
        "inetsim_evidence": inetsim_evidence,
        "artifact_refs": artifact_refs,
        "artifact_ref_lines": clean_artifact_refs(artifact_refs),
        "all_artifacts": all_artifacts,
        "ioc_groups": ioc_groups,
        "analysis_log": analysis_log,
        "cuckoo_log": cuckoo_log,
        "bson_samples": bson_samples,
        "json_summary": json_summary,
        "technical_limitations": technical_limitations,
    }


def render_markdown(ctx: dict[str, Any], title: str, analyst: str, org: str, include_all_artifacts: bool) -> str:
    target = ctx["target_file"]
    pe = ctx["pe"]
    digi_sig = ctx["digi_sig"]
    info = ctx["info"]
    behavior_summary = ctx["behavior_summary"]

    lines = [
        f"# {title}",
        "",
        f"- **Analysis ID:** {ctx['analysis_id']}",
        f"- **Prepared for:** {org}",
        f"- **Analyst:** {analyst}",
        f"- **Generated:** {dt.datetime.now().isoformat(timespec='seconds')}",
        f"- **Source report:** `{path_ref(ctx['report_path'])}`",
        "",
        "## Executive Summary",
        "",
        (
            f"**Observed:** Analysis **#{ctx['analysis_id']}** executed as a **{ctx['classification']}**-aligned sample with "
            f"**{len(ctx['payloads'])} extracted payload artifact(s)**, **{len(ctx['ips'])} external IP indicator(s)**, and "
            f"**{len(ctx['process_names'])} observed process(es)**."
        ),
        "",
        (
            f"**Inferred:** The likely objective is **{ctx['objective']}**, and the business severity is **{ctx['risk_label']} "
            f"({ctx['risk_score']}/100)** based on the observed evidence preserved by CAPE."
        ),
        "",
        (
            f"**Family assessment:** The strongest local family hypothesis is **{ctx['family']}** with a conservative confidence score of "
            f"**{ctx['family_confidence']}%**. Where telemetry is absent, the report states that absence rather than inferring unsupported behavior."
        ),
        "",
    ]

    lines.extend(bullet_list("IOC Summary", [
        f"**Observed sample hash:** `{target.get('sha256', 'Unknown')}`",
        f"**Observed external IPs:** {', '.join(ctx['ips'][:8]) if ctx['ips'] else 'None confirmed'}",
        f"**Observed domains:** {', '.join(ctx['domains'][:8]) if ctx['domains'] else 'None confirmed'}",
        f"**Observed URLs:** {', '.join(ctx['urls'][:5]) if ctx['urls'] else 'None confirmed'}",
        f"**Observed notable registry keys:** {len(ctx['notable_reg'])}",
        f"**Observed notable file paths:** {len(ctx['notable_files'])}",
        f"**Observed mutexes:** {len(ctx['mutexes'])}",
        f"**Observed artifact count:** payloads={len(ctx['payloads'])}, dropped={len(ctx['dropped'])}, procdump={len(ctx['procdump'])}",
    ], "No IOC material was available for a top-level summary."))

    lines.extend(bullet_list("Classification Assessment", [
        f"**Observed family indicators:** {ctx['family']}",
        f"**Inferred family confidence score:** {ctx['family_confidence']}%",
        f"**Inferred malware class:** {ctx['classification']}",
        f"**Inferred likely objective:** {ctx['objective']}",
        f"**Risk rating:** {ctx['risk_label']} ({ctx['risk_score']}/100)",
        *[f"**Observed evidence:** {reason}" for reason in ctx["family_evidence"][:6]],
        *[f"**Top confidence driver:** {item['reason']} ({item['source']}, weight {item['weight']})" for item in ctx["family_top_evidence"][:4]],
        *[f"**Inference rationale:** {reason}" for reason in ctx["classification_reasons"][:4]],
        *[f"**Objective rationale:** {reason}" for reason in ctx["objective_reasons"][:3]],
    ], "No classification indicators were strong enough to support a family or type assessment."))

    lines.extend(bullet_list("Sample Overview", [
        f"**File name:** {target.get('name', 'Unknown')}",
        f"**Category:** {info.get('category', 'Unknown')}",
        f"**Package:** {info.get('package', 'Unknown')}",
        f"**Route:** {info.get('route', 'Unknown')}",
        f"**Original path / binary path:** {target.get('path', 'Unknown')}",
        f"**Guest paths:** {target.get('guest_paths') or 'Not recorded'}",
        f"**File size:** {format_bytes(target.get('size'))} ({target.get('size', 'Unknown')} bytes)",
        f"**File type:** {target.get('type', 'Unknown')}",
        f"**MD5:** `{target.get('md5', 'Unknown')}`",
        f"**SHA1:** `{target.get('sha1', 'Unknown')}`",
        f"**SHA256:** `{target.get('sha256', 'Unknown')}`",
        f"**SHA512:** `{target.get('sha512', 'Unknown')}`",
        f"**TLSH / SSDEEP:** `{target.get('tlsh') or 'n/a'}` / `{target.get('ssdeep') or 'n/a'}`",
        f"**Compile timestamp:** {pe.get('timestamp') or 'Not available'}",
        f"**Imphash:** `{pe.get('imphash') or 'n/a'}`",
        f"**Machine type:** {pe.get('machine_type') or 'Unknown'}",
    ], "Sample metadata was not available."))

    lines.extend(bullet_list("Digital Signature and Trust", [
        f"**Valid signature reported:** {digi_sig.get('valid') if digi_sig else pe.get('guest_signers', {}).get('aux_valid', 'Unknown')}",
        f"**Signature timestamp:** {digi_sig.get('timestamp') or pe.get('guest_signers', {}).get('aux_timestamp') or 'Not available'}",
        f"**Signature error detail:** {digi_sig.get('error_desc') or pe.get('guest_signers', {}).get('aux_error_desc') or 'No signature error recorded'}",
    ] + [
        f"**Signer chain:** {entry.get('Issued to')} issued by {entry.get('Issued by')} (expires {entry.get('Expires')})"
        for entry in safe_list(pe.get('guest_signers', {}).get('aux_signers'))[:6]
        if isinstance(entry, dict)
    ], "No digital signature metadata was present."))

    static_points = [
        f"**PE entry point:** {pe.get('entrypoint') or 'Unknown'}",
        f"**Image base:** {pe.get('imagebase') or 'Unknown'}",
        f"**Imported DLL count:** {pe.get('imported_dll_count') or len(safe_dict(pe.get('imports')))}",
        f"**Sections observed:** {len(safe_list(pe.get('sections')))}",
        f"**Resource entries:** {len(safe_list(pe.get('resources')))}",
        f"**Version info keys:** {len(safe_list(pe.get('versioninfo')))}",
    ]
    static_points.extend(f"**YARA hit:** {hit}" for hit in ctx["yara_hits"][:10])
    static_points.extend(f"**ClamAV hit:** {hit}" for hit in ctx["clamav_hits"][:5])
    static_points.extend(f"**Suspicious string:** `{shorten(s, 140)}`" for s in top_strings(safe_list(target.get("strings")), 10))
    static_points.extend(
        f"**Import indicator:** {dll} -> {', '.join(entry.get('name', '<?>') for entry in safe_list(details.get('imports'))[:5])}"
        for dll, details in list(safe_dict(pe.get("imports")).items())[:8]
        if isinstance(details, dict)
    )
    static_points.extend(
        f"**Section:** {sec.get('name')} | entropy {sec.get('entropy')} | perms {sec.get('characteristics')}"
        for sec in safe_list(pe.get("sections"))[:8]
        if isinstance(sec, dict)
    )
    lines.extend(bullet_list("Static Analysis", static_points, "Static analysis details were minimal or absent in the available artifacts."))

    lines.extend(bullet_list("Behavioral Analysis", [
        "**Observed vs Inferred note:** Process, registry, file, and network entries below are observed artifacts unless explicitly marked as inferred.",
        f"**Observed processes:** {len(ctx['process_names'])}",
        f"**Dropped files:** {len(ctx['dropped'])}",
        f"**Registry read / write / delete counts:** {len(ctx['reg_reads'])} / {len(ctx['reg_writes'])} / {len(ctx['reg_deletes'])}",
        f"**Notable files in summary:** {len(ctx['notable_files'])}",
        f"**Mutexes recorded:** {len(ctx['mutexes'])}",
        *[f"**Inferred capability:** {cap['name']} ({cap['confidence']}) - {cap['evidence']}" for cap in ctx["capabilities"][:8]],
    ], "Behavioral findings were not available."))

    lines.extend(bullet_list("Process and Memory Activity", [
        *ctx["process_tree_lines"][:20],
        *[f"Spawned process: {entry}" for entry in ctx["process_names"][:15]],
        *[f"Execution path: {entry}" for entry in ctx["command_lines"][:12]],
        *[
            f"Raw process event: {item['api']} | success={item['status']} | {item['arguments']}"
            for item in ctx["bson_samples"]["process"][:8]
        ],
        f"**CAPE payloads extracted:** {len(ctx['payloads'])}",
        f"**Procdump artifacts:** {len(ctx['procdump'])}",
        f"**Process memory artifacts:** {len(ctx['procmemory'])}",
    ], "No process or memory behavior was available."))

    lines.extend(bullet_list("Registry Activity", [
        *[f"Registry write: `{key}`" for key in ctx["reg_writes"][:15]],
        *[f"Registry delete: `{key}`" for key in ctx["reg_deletes"][:10]],
        *[f"Registry read: `{key}`" for key in ctx["reg_reads"][:15]],
        *[
            f"Raw registry event: {item['api']} | success={item['status']} | {item['arguments']}"
            for item in ctx["bson_samples"]["registry"][:8]
        ],
    ], "No registry activity was recorded in the processed outputs or raw behavior samples."))

    lines.extend(bullet_list("File System Activity", [
        *[f"Notable path: `{path}`" for path in ctx["notable_files"][:20]],
        *[f"Dropped file: `{item.get('name')}` -> {item.get('path') or item.get('filepath') or 'path unavailable'}" for item in ctx["dropped"][:10] if isinstance(item, dict)],
        *[
            f"Raw filesystem event: {item['api']} | success={item['status']} | {item['arguments']}"
            for item in ctx["bson_samples"]["filesystem"][:8]
        ],
        f"**files.json entries:** {len(ctx['files_json'])}",
    ], "No notable file-system activity was extracted from the available artifacts."))

    network_points = [
        f"**PCAP available:** {'yes' if ctx['artifact_refs']['dump_pcap'] else 'no'}",
        f"**External IPs:** {', '.join(ctx['ips'][:10]) if ctx['ips'] else 'None observed'}",
        f"**Domains:** {', '.join(ctx['domains'][:10]) if ctx['domains'] else 'None observed'}",
        f"**URLs:** {', '.join(ctx['urls'][:6]) if ctx['urls'] else 'None observed'}",
        f"**SMTP evidence:** {', '.join(ctx['smtp'][:4]) if ctx['smtp'] else 'None observed'}",
        f"**DNS evidence:** {', '.join(ctx['dns_queries'][:6]) if ctx['dns_queries'] else 'None observed'}",
        f"**HTTP transactions parsed:** {len(safe_list(ctx['network'].get('http')))}",
        f"**UDP events parsed:** {len(safe_list(ctx['network'].get('udp')))}",
        f"**INetSim / sinkhole evidence:** {', '.join(ctx['inetsim_evidence']) if ctx['inetsim_evidence'] else 'No direct inetsim indicator preserved in local artifacts'}",
        f"**TLS artifacts:** {len(ctx['tlsdump_files'])} tlsdump file(s)",
    ]
    lines.extend(bullet_list("Network Activity", network_points, "No network evidence was present."))

    lines.extend(bullet_list("Persistence and Evasion", [
        *[f"Persistence-related registry path: `{key}`" for key in ctx["reg_writes"] if any(token in key.lower() for token in ('run', 'runonce', 'startup', 'services', 'scheduled tasks'))][:10],
        *[f"Execution via PowerShell observed: {entry}" for entry in ctx["process_names"] if "powershell" in entry.lower()][:5],
        *[f"Behavioral limitation: {item}" for item in ctx["technical_limitations"][:6]],
    ], "No persistence-specific telemetry was confirmed in the local artifacts."))

    lines.extend(bullet_list("Extracted Payloads and Artifacts", [
        *[
            f"Payload: `{payload.get('name')}` | type={payload.get('cape_type') or payload.get('type')} | size={payload.get('size')} | path={payload.get('path')}"
            for payload in ctx["payloads"][:12]
            if isinstance(payload, dict)
        ],
        *[f"Self-extracted artifact: `{path_ref(item)}`" for item in ctx["selfextracted"][:10]],
        *[f"Process dump: `{item.get('path') or item.get('filepath') or item.get('sha256')}`" for item in ctx["procdump"][:10] if isinstance(item, dict)],
        *[f"Screenshot: `{path_ref(item)}`" for item in ctx["screenshots"][:8]],
        f"**CAPE file count on disk:** {len(ctx['cape_files'])}",
        f"**Dropped-file count on disk:** {len(ctx['files_dir'])}",
    ], "No extracted payloads or auxiliary artifacts were found."))

    lines.extend(bullet_list("Indicators of Compromise", [
        f"**High-confidence file IOCs:** {', '.join(f'`{v}`' for v in ctx['ioc_groups']['files']['high'][:6]) if ctx['ioc_groups']['files']['high'] else 'None'}",
        f"**High-confidence registry IOCs:** {', '.join(f'`{v}`' for v in ctx['ioc_groups']['registry']['high'][:6]) if ctx['ioc_groups']['registry']['high'] else 'None'}",
        f"**High-confidence domains/URLs:** {', '.join(f'`{v}`' for v in (ctx['ioc_groups']['domains']['high'][:4] + ctx['ioc_groups']['urls']['high'][:4])) if (ctx['ioc_groups']['domains']['high'] or ctx['ioc_groups']['urls']['high']) else 'None'}",
        f"**High-confidence IPs:** {', '.join(f'`{v}`' for v in ctx['ioc_groups']['ips']['high'][:8]) if ctx['ioc_groups']['ips']['high'] else 'None'}",
        f"**High-confidence process IOCs:** {', '.join(f'`{v}`' for v in ctx['ioc_groups']['processes']['high'][:6]) if ctx['ioc_groups']['processes']['high'] else 'None'}",
        f"**Sample SHA256:** `{target.get('sha256', 'Unknown')}`",
        *[f"File IOC: `{value}`" for value in ctx["ioc_groups"]["files"]["medium"][:10]],
        *[f"Registry IOC: `{value}`" for value in ctx["ioc_groups"]["registry"]["medium"][:10]],
        *[f"IP IOC: `{value}`" for value in ctx["ioc_groups"]["ips"]["high"][:15]],
        *[f"Domain IOC: `{value}`" for value in ctx["ioc_groups"]["domains"]["high"][:15]],
        *[f"URL IOC: `{value}`" for value in ctx["ioc_groups"]["urls"]["high"][:10]],
        *[f"Email IOC: `{value}`" for value in ctx["ioc_groups"]["emails"]["high"][:10]],
        *[f"Mutex IOC: `{value}`" for value in ctx["ioc_groups"]["mutexes"]["high"][:10]],
        *[f"Process IOC: `{value}`" for value in ctx["ioc_groups"]["processes"]["medium"][:10]],
    ], "No IOC material could be extracted from the available artifacts."))

    lines.extend(bullet_list("MITRE ATT&CK Mapping", [
        f"**Inferred {item['technique']} {item['name']}** ({item['confidence']}) - {item['evidence']}"
        for item in ctx["mitre"]
    ], "No ATT&CK mappings met the threshold for evidence-backed inclusion."))

    lines.extend(bullet_list("Risk Assessment", [
        f"**Overall risk:** {ctx['risk_label']} ({ctx['risk_score']}/100)",
        f"**Primary concern:** {ctx['classification']}",
        f"**Likely objective:** {ctx['objective']}",
        f"**Network exposure:** {'Outbound activity observed' if ctx['ips'] else 'No external destinations confirmed'}",
        f"**Registry modification risk:** {'Observed' if ctx['reg_writes'] or ctx['reg_deletes'] else 'Not confirmed'}",
        f"**Payload staging risk:** {'Observed' if ctx['payloads'] else 'Not confirmed'}",
        *[f"**Scoring factor:** {reason}" for reason in ctx["risk_reasons"][:6]],
    ], "Risk could not be assessed."))

    lines.extend(bullet_list("Analyst Notes / Limitations", [
        *ctx["technical_limitations"],
        "This report uses only local CAPE host artifacts and does not rely on external enrichment services.",
        "Inference sections are intentionally conservative and limited to evidence preserved by CAPE in this workspace.",
    ], "No additional analyst limitations were identified."))

    lines.extend(bullet_list("Appendix: Raw Artifact References", [
        *ctx["artifact_ref_lines"],
    ], "No artifact references were available."))

    if include_all_artifacts:
        lines.extend(bullet_list("Appendix: Full Artifact Listing", [f"`{item}`" for item in ctx["all_artifacts"]], "No artifact files were found."))

    return "\n".join(lines).rstrip() + "\n"


def inline_markup(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def markdown_to_html(markdown_text: str, title: str) -> str:
    body: list[str] = []
    in_list = False
    in_code = False

    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if line.startswith("```"):
            if not in_code:
                body.append("<pre><code>")
                in_code = True
            else:
                body.append("</code></pre>")
                in_code = False
            continue
        if in_code:
            body.append(html.escape(line))
            continue
        if not line:
            if in_list:
                body.append("</ul>")
                in_list = False
            continue
        if line.startswith("### "):
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<h3>{inline_markup(line[4:])}</h3>")
            continue
        if line.startswith("## "):
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<h2>{inline_markup(line[3:])}</h2>")
            continue
        if line.startswith("# "):
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<h1>{inline_markup(line[2:])}</h1>")
            continue
        if line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{inline_markup(line[2:])}</li>")
            continue
        if in_list:
            body.append("</ul>")
            in_list = False
        body.append(f"<p>{inline_markup(line)}</p>")
    if in_list:
        body.append("</ul>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #f3efe4;
      --paper: #fffdf8;
      --ink: #16212d;
      --muted: #5b6670;
      --accent: #9b1d20;
      --line: #d8d1c1;
      --code: #f4f0e7;
    }}
    body {{
      margin: 0;
      font-family: "Source Serif 4", Georgia, serif;
      background: linear-gradient(180deg, #efe8d8 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1000px;
      margin: 32px auto;
      padding: 40px 48px;
      background: var(--paper);
      border: 1px solid var(--line);
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08);
    }}
    h1, h2, h3 {{
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      letter-spacing: 0.01em;
    }}
    h1 {{
      margin-top: 0;
      font-size: 2.2rem;
      border-bottom: 3px solid var(--accent);
      padding-bottom: 12px;
    }}
    h2 {{
      margin-top: 2.2rem;
      color: var(--accent);
      border-top: 1px solid var(--line);
      padding-top: 18px;
    }}
    h3 {{
      margin-bottom: 0.4rem;
    }}
    p, li {{
      line-height: 1.6;
      font-size: 1rem;
    }}
    ul {{
      margin-top: 0.4rem;
      padding-left: 1.2rem;
    }}
    code {{
      background: var(--code);
      padding: 0.08rem 0.3rem;
      border-radius: 4px;
      font-family: "IBM Plex Mono", Consolas, monospace;
      font-size: 0.92em;
    }}
    pre {{
      background: var(--code);
      padding: 16px;
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--line);
    }}
  </style>
</head>
<body>
  <main>
    {''.join(body)}
  </main>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a professional CAPE post-analysis report.")
    parser.add_argument("--id", type=int, required=True, help="CAPE analysis ID")
    parser.add_argument("--output", type=str, help="Output markdown path")
    parser.add_argument("--title", type=str, help="Custom report title")
    parser.add_argument("--analyst", type=str, default="Unknown Analyst", help="Analyst name")
    parser.add_argument("--org", type=str, default="KSPN", help="Organization name")
    parser.add_argument("--all-artifacts", action="store_true", help="Include a full artifact appendix")
    parser.add_argument("--json-summary", action="store_true", help="Emit a machine-readable summary next to the report")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    analysis_dir = ANALYSES_DIR / str(args.id)
    if not analysis_dir.exists():
        print(f"Analysis directory not found: {analysis_dir}", file=sys.stderr)
        return 1

    ctx = collect_analysis(args.id, args.all_artifacts)
    title = args.title or f"{args.org} Malware Analysis Report - Analysis #{args.id}"
    reports_dir = analysis_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    md_path = Path(args.output).resolve() if args.output else reports_dir / "kspn_report.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    html_path = md_path.with_suffix(".html")
    summary_path = md_path.with_name(md_path.stem + "_summary.json")

    print(f"Generating KSPN-style report for analysis {args.id} from {analysis_dir}")

    markdown_text = render_markdown(ctx, title, args.analyst, args.org, args.all_artifacts)
    md_path.write_text(markdown_text, encoding="utf-8")

    if not args.no_html:
        html_text = markdown_to_html(markdown_text, title)
        html_path.write_text(html_text, encoding="utf-8")

    if args.json_summary:
        summary_path.write_text(json.dumps(ctx["json_summary"], indent=2), encoding="utf-8")

    ioc_count = sum(ctx["json_summary"]["ioc_counts"].values())
    key_flags = []
    if ctx["payloads"]:
        key_flags.append(f"{len(ctx['payloads'])} payload(s)")
    if ctx["reg_writes"]:
        key_flags.append(f"{len(ctx['reg_writes'])} registry write key(s)")
    if ctx["ips"]:
        key_flags.append(f"{len(ctx['ips'])} external IP(s)")
    if ctx["screenshots"]:
        key_flags.append(f"{len(ctx['screenshots'])} screenshot(s)")

    print("Report generated")
    print(f"Markdown: {md_path}")
    if not args.no_html:
        print(f"HTML: {html_path}")
    if args.json_summary:
        print(f"JSON summary: {summary_path}")
    print(f"Family guess: {ctx['family']} ({ctx['family_confidence']}% confidence)")
    print(f"Risk rating: {ctx['risk_label']} ({ctx['risk_score']}/100)")
    print(f"IOC count: {ioc_count}")
    print(f"Key risk flags: {', '.join(key_flags) if key_flags else 'No major risk flags extracted'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
