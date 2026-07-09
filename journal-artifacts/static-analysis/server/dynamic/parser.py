from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dedupe_dict_items(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for item in items:
        fingerprint = tuple(sorted((str(key), str(value)) for key, value in item.items()))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(item)
    return deduped


def _infer_file_type(target_type: str, package: str) -> str:
    target_type_lower = (target_type or "").lower()
    package_lower = (package or "").lower()

    if "dll" in package_lower or "(dll)" in target_type_lower:
        return "dll"
    if "pe32" in target_type_lower or package_lower == "exe":
        return "pe"
    if "pdf" in target_type_lower:
        return "pdf"
    if "html" in target_type_lower:
        return "html"
    if "word" in target_type_lower or "excel" in target_type_lower or "powerpoint" in target_type_lower:
        return "office"
    return package_lower or "unknown"


def _flatten_process_tree(nodes: Iterable[Dict[str, Any]], parent_name: Optional[str] = None) -> List[Dict[str, Any]]:
    flattened: List[Dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        item = {
            "name": node.get("name"),
            "pid": node.get("pid"),
            "parent_pid": node.get("parent_id"),
            "parent_name": parent_name,
            "path": node.get("module_path"),
            "command_line": _safe_dict(node.get("environ")).get("CommandLine"),
            "bitness": _safe_dict(node.get("environ")).get("Bitness"),
            "child_count": len(_safe_list(node.get("children"))),
        }
        flattened.append({key: value for key, value in item.items() if value not in (None, "", [])})
        flattened.extend(_flatten_process_tree(_safe_list(node.get("children")), parent_name=node.get("name")))
    return flattened


def _parse_file_activity(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = _safe_dict(_safe_dict(report.get("behavior")).get("summary"))
    activity: List[Dict[str, Any]] = []

    for path in _safe_list(summary.get("files")):
        activity.append({"kind": "observed_path", "path": path})

    for dropped in _safe_list(report.get("dropped")):
        if not isinstance(dropped, dict):
            continue
        activity.append(
            {
                "kind": "dropped_file",
                "name": ",".join(_safe_list(dropped.get("name"))) or dropped.get("path"),
                "path": dropped.get("path"),
                "guest_paths": _safe_list(dropped.get("guest_paths")),
                "sha256": dropped.get("sha256"),
                "type": dropped.get("type"),
                "size": dropped.get("size"),
            }
        )

    for procdump in _safe_list(report.get("procdump")):
        if not isinstance(procdump, dict):
            continue
        activity.append(
            {
                "kind": "procdump",
                "path": procdump.get("path"),
                "sha256": procdump.get("sha256"),
                "process_name": procdump.get("process_name"),
                "process_path": procdump.get("process_path"),
                "cape_type": procdump.get("cape_type"),
            }
        )

    for payload in _safe_list(_safe_dict(report.get("CAPE")).get("payloads")):
        if not isinstance(payload, dict):
            continue
        activity.append(
            {
                "kind": "cape_payload",
                "path": payload.get("path"),
                "sha256": payload.get("sha256"),
                "process_name": payload.get("process_name"),
                "process_path": payload.get("process_path"),
                "cape_type": payload.get("cape_type"),
                "pid": payload.get("pid"),
                "virtual_address": payload.get("virtual_address"),
            }
        )

    return _dedupe_dict_items(activity)


def _parse_registry_activity(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = _safe_dict(_safe_dict(report.get("behavior")).get("summary"))
    activity: List[Dict[str, Any]] = []

    for key in _safe_list(summary.get("read_keys")):
        activity.append({"operation": "read", "key": key})
    for key in _safe_list(summary.get("write_keys")):
        activity.append({"operation": "write", "key": key})
    for key in _safe_list(summary.get("delete_keys")):
        activity.append({"operation": "delete", "key": key})

    return _dedupe_dict_items(activity)


def _parse_network_activity(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    network = _safe_dict(report.get("network"))
    activity: List[Dict[str, Any]] = []

    for entry in _safe_list(network.get("dns")):
        if not isinstance(entry, dict):
            continue
        activity.append(
            {
                "protocol": "dns",
                "request": entry.get("request"),
                "record_type": entry.get("type"),
                "answers": [answer.get("data") for answer in _safe_list(entry.get("answers")) if isinstance(answer, dict)],
            }
        )

    for entry in _safe_list(network.get("http")):
        if not isinstance(entry, dict):
            continue
        activity.append(
            {
                "protocol": "http",
                "host": entry.get("host"),
                "uri": entry.get("uri"),
                "method": entry.get("method"),
                "user_agent": entry.get("user-agent") or entry.get("user_agent"),
            }
        )

    for proto in ("tcp", "udp"):
        for entry in _safe_list(network.get(proto)):
            if not isinstance(entry, dict):
                continue
            activity.append(
                {
                    "protocol": proto,
                    "src": entry.get("src"),
                    "sport": entry.get("sport"),
                    "dst": entry.get("dst"),
                    "dport": entry.get("dport"),
                }
            )

    return _dedupe_dict_items(activity)


def _parse_iocs(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    iocs: List[Dict[str, Any]] = []
    target_file = _safe_dict(_safe_dict(report.get("target")).get("file"))
    summary = _safe_dict(_safe_dict(report.get("behavior")).get("summary"))
    network = _safe_dict(report.get("network"))

    for hash_name in ("md5", "sha1", "sha256", "sha512"):
        if target_file.get(hash_name):
            iocs.append({"type": hash_name, "value": target_file[hash_name], "source": "target_file"})

    for host in _safe_list(network.get("hosts")):
        if not isinstance(host, dict):
            continue
        if host.get("ip"):
            iocs.append({"type": "ip", "value": host["ip"], "source": "network.hosts"})
        if host.get("hostname"):
            iocs.append({"type": "domain", "value": host["hostname"], "source": "network.hosts"})

    for dns in _safe_list(network.get("dns")):
        if not isinstance(dns, dict):
            continue
        if dns.get("request"):
            iocs.append({"type": "domain", "value": dns["request"], "source": "network.dns"})
        for answer in _safe_list(dns.get("answers")):
            if isinstance(answer, dict) and answer.get("type") == "A" and answer.get("data"):
                iocs.append({"type": "ip", "value": answer["data"], "source": "network.dns"})

    for mutex in _safe_list(summary.get("mutexes")):
        iocs.append({"type": "mutex", "value": mutex, "source": "behavior.summary"})

    for command in _safe_list(summary.get("executed_commands")):
        iocs.append({"type": "command", "value": command, "source": "behavior.summary"})

    return _dedupe_dict_items(iocs)


def parse_cape_dynamic_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the CAPE behaviors needed by the Fathom dynamic pipeline."""

    info = _safe_dict(report.get("info"))
    target = _safe_dict(report.get("target"))
    target_file = _safe_dict(target.get("file"))
    behavior = _safe_dict(report.get("behavior"))

    target_type = str(target_file.get("type", ""))
    package = str(info.get("package", ""))

    parsed = {
        "analysis_id": info.get("id"),
        "file_name": target_file.get("name"),
        "file_type": _infer_file_type(target_type, package),
        "submission_mode": "manual_cape",
        "cape_task_id": info.get("id"),
        "sandbox_status": "completed" if not info.get("timeout") else "timeout",
        "execution_profile": package or "unknown",
        "process_activity": _dedupe_dict_items(_flatten_process_tree(_safe_list(behavior.get("processtree")))),
        "file_activity": _parse_file_activity(report),
        "registry_activity": _parse_registry_activity(report),
        "network_activity": _parse_network_activity(report),
        "iocs": _parse_iocs(report),
        "raw_context": {
            "package": package,
            "category": target.get("category"),
            "duration": info.get("duration"),
            "machine": _safe_dict(info.get("machine")).get("name"),
        },
    }
    return parsed
