from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


BASE = Path(__file__).parent
OUT = BASE / "out"

CAPE_ROOT = Path(os.environ.get("FATHOM_CAPE_ROOT", "~/CAPEv2")).expanduser()
CAPE_PYTHON = Path(os.environ.get("FATHOM_CAPE_PYTHON", str(CAPE_ROOT / "venv/bin/python3"))).expanduser()
CAPE_SUBMIT = Path(os.environ.get("FATHOM_CAPE_SUBMIT", str(CAPE_ROOT / "utils/submit.py"))).expanduser()
CAPE_ANALYSES = Path(os.environ.get("FATHOM_CAPE_ANALYSES", str(CAPE_ROOT / "storage/analyses"))).expanduser()
CAPE_ARCHIVE_PASSWORD = os.environ.get("FATHOM_CAPE_ZIP_PASSWORD", "infected")
CAPE_WAIT_TIMEOUT = int(os.environ.get("FATHOM_CAPE_WAIT_TIMEOUT", "3600"))
CAPE_POLL_INTERVAL = int(os.environ.get("FATHOM_CAPE_POLL_INTERVAL", "10"))
CALLBACK_TIMEOUT = int(os.environ.get("FATHOM_CALLBACK_TIMEOUT", "15"))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def dynamic_state_path(sha256: str) -> Path:
    return OUT / f"{sha256}.dynamic.json"


def load_dynamic_state(sha256: str) -> Dict[str, Any]:
    path = dynamic_state_path(sha256)
    if not path.exists():
        return {"sha256": sha256, "status": "missing", "error": "Dynamic analysis has not been started"}
    return json.loads(path.read_text(encoding="utf-8"))


def save_dynamic_state(state: Dict[str, Any]) -> Dict[str, Any]:
    OUT.mkdir(exist_ok=True)
    state["updated_at"] = utc_now()
    path = dynamic_state_path(state["sha256"])
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp_path.replace(path)
    return state


def is_http_callback_url(callback_url: str) -> bool:
    return callback_url.startswith(("http://", "https://"))


def post_analysis_callback(
    callback_url: Optional[str],
    event: str,
    sha256: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Best-effort JSON callback delivery for external LLM/orchestrator services."""
    if not callback_url:
        return {"enabled": False, "event": event}
    if not is_http_callback_url(callback_url):
        return {
            "enabled": True,
            "event": event,
            "status": "failed",
            "error": "callback_url must start with http:// or https://",
            "sent_at": utc_now(),
        }

    body = {
        "event": event,
        "sha256": sha256,
        "sent_at": utc_now(),
        "data": payload,
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        callback_url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Fathom-Callback/1.0"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=CALLBACK_TIMEOUT) as response:
            response.read(1024)
            return {
                "enabled": True,
                "event": event,
                "status": "delivered",
                "status_code": response.status,
                "sent_at": body["sent_at"],
            }
    except Exception as exc:
        return {
            "enabled": True,
            "event": event,
            "status": "failed",
            "error": str(exc),
            "sent_at": body["sent_at"],
        }


def record_callback_delivery(state: Dict[str, Any], delivery: Dict[str, Any]) -> Dict[str, Any]:
    if not delivery.get("enabled"):
        return state
    history = state.setdefault("callback_deliveries", [])
    history.append(delivery)
    state["last_callback_delivery"] = delivery
    return save_dynamic_state(state)


def create_dynamic_state(
    sha256: str,
    sample_path: Path,
    filename: Optional[str],
    callback_url: Optional[str] = None,
) -> Dict[str, Any]:
    state = {
        "sha256": sha256,
        "filename": filename or sample_path.name,
        "sample_path": str(sample_path),
        "callback_url": callback_url,
        "callback_deliveries": [],
        "status": "queued",
        "cape_task_id": None,
        "submitted_at": None,
        "completed_at": None,
        "analysis_dir": None,
        "report_json_path": None,
        "report_html_path": None,
        "report_json_available": False,
        "report_html_available": False,
        "summary": {},
        "error": None,
        "created_at": utc_now(),
    }
    return save_dynamic_state(state)


def submit_to_cape(sample_path: Path) -> int:
    if not CAPE_PYTHON.exists():
        raise RuntimeError(f"CAPE Python not found: {CAPE_PYTHON}")
    if not CAPE_SUBMIT.exists():
        raise RuntimeError(f"CAPE submit.py not found: {CAPE_SUBMIT}")
    if not sample_path.exists():
        raise RuntimeError(f"Sample path does not exist: {sample_path}")

    command = [str(CAPE_PYTHON), str(CAPE_SUBMIT)]
    if sample_path.suffix.lower() == ".zip":
        command.extend(["--package", "archive", "--options", f"password={CAPE_ARCHIVE_PASSWORD}"])
    command.append(str(sample_path))

    result = subprocess.run(
        command,
        cwd=str(CAPE_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if result.returncode != 0:
        raise RuntimeError(output.strip() or f"CAPE submit failed with exit code {result.returncode}")

    task_ids = [int(value) for value in re.findall(r"task with ID\s+(\d+)", output, flags=re.IGNORECASE)]
    if not task_ids:
        task_ids = [int(value) for value in re.findall(r"task(?:s)?(?: with)? ID(?:s)?[:\s]+(\d+)", output, flags=re.IGNORECASE)]
    if not task_ids:
        raise RuntimeError(f"Could not parse CAPE task ID from submit output: {output.strip()}")

    return task_ids[0]


def find_cape_reports(task_id: int) -> Dict[str, Optional[Path]]:
    analysis_dir = CAPE_ANALYSES / str(task_id)
    reports_dir = analysis_dir / "reports"

    json_candidates = [
        reports_dir / "report.json",
        reports_dir / "reports.json",
        analysis_dir / "report.json",
        analysis_dir / "reports.json",
    ]
    html_candidates = [
        reports_dir / "report.html",
        reports_dir / "reports.html",
        reports_dir / "kspn_report.html",
        analysis_dir / "report.html",
        analysis_dir / "reports.html",
        analysis_dir / "kspn_report.html",
    ]

    return {
        "analysis_dir": analysis_dir if analysis_dir.exists() else None,
        "json": next((path for path in json_candidates if path.exists()), None),
        "html": next((path for path in html_candidates if path.exists()), None),
    }


def summarize_cape_report(report: Dict[str, Any]) -> Dict[str, Any]:
    signatures = report.get("signatures") or []
    network = report.get("network") or {}
    dropped = report.get("dropped") or []
    cape = report.get("CAPE") or report.get("cape") or {}
    target = report.get("target") or {}
    info = report.get("info") or {}

    hosts = network.get("hosts") or []
    dns = network.get("dns") or []
    http = network.get("http") or []
    tcp = network.get("tcp") or []
    udp = network.get("udp") or []

    return {
        "task_id": info.get("id"),
        "target_file": (target.get("file") or {}).get("name") or target.get("target"),
        "malscore": report.get("malscore"),
        "malstatus": report.get("malstatus"),
        "detections": report.get("detections"),
        "signatures_count": len(signatures) if isinstance(signatures, list) else 0,
        "network_hosts_count": len(hosts) if isinstance(hosts, list) else 0,
        "dns_count": len(dns) if isinstance(dns, list) else 0,
        "http_count": len(http) if isinstance(http, list) else 0,
        "tcp_count": len(tcp) if isinstance(tcp, list) else 0,
        "udp_count": len(udp) if isinstance(udp, list) else 0,
        "dropped_count": len(dropped) if isinstance(dropped, list) else 0,
        "cape_payload_count": len(cape.get("payloads") or []) if isinstance(cape, dict) else 0,
        "cape_config_count": len(cape.get("configs") or []) if isinstance(cape, dict) else 0,
    }


def is_safe_cape_report_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(CAPE_ANALYSES.resolve())
        return True
    except ValueError:
        return False


def load_cape_json_for_sha(sha256: str) -> Dict[str, Any]:
    state = load_dynamic_state(sha256)
    report_path = state.get("report_json_path")
    if not report_path:
        raise FileNotFoundError("CAPE JSON report is not available yet")

    path = Path(report_path)
    if not path.exists() or not is_safe_cape_report_path(path):
        raise FileNotFoundError("CAPE JSON report path is missing or unsafe")
    return json.loads(path.read_text(encoding="utf-8"))


def load_cape_json_for_task(task_id: int) -> Dict[str, Any]:
    reports = find_cape_reports(task_id)
    report_path = reports["json"]
    if not report_path:
        raise FileNotFoundError(f"CAPE JSON report is not available for task {task_id}")
    if not report_path.exists() or not is_safe_cape_report_path(report_path):
        raise FileNotFoundError("CAPE JSON report path is missing or unsafe")
    return json.loads(report_path.read_text(encoding="utf-8"))


def html_report_path_for_sha(sha256: str) -> Path:
    state = load_dynamic_state(sha256)
    report_path = state.get("report_html_path")
    if not report_path:
        raise FileNotFoundError("CAPE HTML report is not available")

    path = Path(report_path)
    if not path.exists() or not is_safe_cape_report_path(path):
        raise FileNotFoundError("CAPE HTML report path is missing or unsafe")
    return path


def html_report_path_for_task(task_id: int) -> Path:
    reports = find_cape_reports(task_id)
    report_path = reports["html"]
    if not report_path:
        raise FileNotFoundError(f"CAPE HTML report is not available for task {task_id}")
    if not report_path.exists() or not is_safe_cape_report_path(report_path):
        raise FileNotFoundError("CAPE HTML report path is missing or unsafe")
    return report_path


def report_matches_hash(report: Dict[str, Any], query: str) -> bool:
    needle = query.lower()
    target_file = (report.get("target") or {}).get("file") or {}
    hash_fields = [
        target_file.get("sha256"),
        target_file.get("sha1"),
        target_file.get("md5"),
        target_file.get("sha512"),
        target_file.get("tlsh"),
        target_file.get("ssdeep"),
    ]
    cape = report.get("CAPE") or report.get("cape") or {}
    for artifact in (cape.get("payloads") or []) + (report.get("dropped") or []) + (report.get("procmemory") or []):
        if isinstance(artifact, dict):
            hash_fields.extend(
                [
                    artifact.get("sha256"),
                    artifact.get("sha1"),
                    artifact.get("md5"),
                    artifact.get("sha512"),
                ]
            )

    return any(value and needle in str(value).lower() for value in hash_fields)


def lookup_cape_analysis(query: str) -> Dict[str, Any]:
    cleaned = query.strip()
    if not cleaned:
        raise FileNotFoundError("Provide a CAPE analysis number or file hash")

    if cleaned.isdigit():
        task_id = int(cleaned)
        reports = find_cape_reports(task_id)
        if not reports["json"]:
            raise FileNotFoundError(f"No CAPE JSON report found for analysis {task_id}")
        report = load_cape_json_for_task(task_id)
        return build_lookup_response(task_id, reports, report, "analysis_id", cleaned)

    for report_path in sorted(CAPE_ANALYSES.glob("*/reports/report*.json"), reverse=True):
        try:
            task_id = int(report_path.parents[1].name)
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if report_matches_hash(report, cleaned):
            reports = find_cape_reports(task_id)
            return build_lookup_response(task_id, reports, report, "hash", cleaned)

    raise FileNotFoundError(f"No CAPE report matched: {cleaned}")


def build_lookup_response(
    task_id: int,
    reports: Dict[str, Optional[Path]],
    report: Dict[str, Any],
    lookup_type: str,
    query: str,
) -> Dict[str, Any]:
    target_file = ((report.get("target") or {}).get("file") or {})
    sha256 = target_file.get("sha256") or f"cape-task-{task_id}"
    report_json = reports["json"]
    report_html = reports["html"]
    state = {
        "sha256": sha256,
        "filename": target_file.get("name") or f"CAPE analysis {task_id}",
        "sample_path": target_file.get("path"),
        "status": "completed",
        "cape_task_id": task_id,
        "submitted_at": (report.get("info") or {}).get("started"),
        "completed_at": (report.get("info") or {}).get("ended"),
        "analysis_dir": str(reports["analysis_dir"]) if reports["analysis_dir"] else None,
        "report_json_path": str(report_json) if report_json else None,
        "report_html_path": str(report_html) if report_html else None,
        "report_json_available": bool(report_json),
        "report_html_available": bool(report_html),
        "summary": summarize_cape_report(report),
        "error": None,
        "lookup": {"type": lookup_type, "query": query},
    }
    return {
        "state": state,
        "report": report,
        "html_url": f"/api/dynamic/task/{task_id}/report-html" if report_html else None,
    }


def run_dynamic_analysis(sha256: str, sample_path_str: str, filename: Optional[str] = None) -> None:
    sample_path = Path(sample_path_str)
    state = load_dynamic_state(sha256)
    if state.get("status") in {"running", "submitted"}:
        return

    try:
        state.update({"status": "submitting", "error": None})
        save_dynamic_state(state)

        task_id = submit_to_cape(sample_path)
        state.update(
            {
                "status": "running",
                "cape_task_id": task_id,
                "submitted_at": utc_now(),
                "filename": filename or state.get("filename") or sample_path.name,
            }
        )
        save_dynamic_state(state)

        deadline = time.time() + CAPE_WAIT_TIMEOUT
        while time.time() < deadline:
            reports = find_cape_reports(task_id)
            report_json = reports["json"]
            report_html = reports["html"]
            if report_json:
                report = json.loads(report_json.read_text(encoding="utf-8"))
                state.update(
                    {
                        "status": "completed",
                        "completed_at": utc_now(),
                        "analysis_dir": str(reports["analysis_dir"]) if reports["analysis_dir"] else None,
                        "report_json_path": str(report_json),
                        "report_html_path": str(report_html) if report_html else None,
                        "report_json_available": True,
                        "report_html_available": bool(report_html),
                        "summary": summarize_cape_report(report),
                        "error": None,
                    }
                )
                save_dynamic_state(state)
                delivery = post_analysis_callback(
                    state.get("callback_url"),
                    "dynamic_completed",
                    sha256,
                    {"state": state, "cape_report": report},
                )
                record_callback_delivery(state, delivery)
                return

            state.update(
                {
                    "status": "running",
                    "analysis_dir": str(reports["analysis_dir"]) if reports["analysis_dir"] else state.get("analysis_dir"),
                    "report_html_path": str(report_html) if report_html else state.get("report_html_path"),
                    "report_html_available": bool(report_html) or state.get("report_html_available", False),
                }
            )
            save_dynamic_state(state)
            time.sleep(CAPE_POLL_INTERVAL)

        state.update({"status": "timeout", "error": f"Timed out waiting for CAPE task {task_id} report"})
        save_dynamic_state(state)
        delivery = post_analysis_callback(
            state.get("callback_url"),
            "dynamic_timeout",
            sha256,
            {"state": state},
        )
        record_callback_delivery(state, delivery)
    except Exception as exc:
        state = load_dynamic_state(sha256)
        state.update({"status": "failed", "error": str(exc)})
        save_dynamic_state(state)
        delivery = post_analysis_callback(
            state.get("callback_url"),
            "dynamic_failed",
            sha256,
            {"state": state},
        )
        record_callback_delivery(state, delivery)
