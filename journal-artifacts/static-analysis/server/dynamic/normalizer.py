from __future__ import annotations

from typing import Any, Dict, List


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _derive_verdict(parsed: Dict[str, Any]) -> str:
    indicator_count = (
        len(_safe_list(parsed.get("process_activity")))
        + len(_safe_list(parsed.get("file_activity")))
        + len(_safe_list(parsed.get("registry_activity")))
        + len(_safe_list(parsed.get("network_activity")))
    )
    if indicator_count >= 50:
        return "suspicious"
    if indicator_count >= 15:
        return "review"
    return "observed"


def normalize_dynamic_analysis(parsed: Dict[str, Any], *, report_path: str | None = None) -> Dict[str, Any]:
    """
    Normalize parsed CAPE output into the stable schema expected by Fathom.

    Tasks 13 and 14 will enrich the placeholder `mitre_mapping`, `risk_score`,
    and `verdict` fields later. For Task 10 we keep the shape stable now.
    """

    normalized = {
        "analysis_id": parsed.get("analysis_id"),
        "file_name": parsed.get("file_name"),
        "file_type": parsed.get("file_type"),
        "submission_mode": parsed.get("submission_mode", "manual_cape"),
        "cape_task_id": parsed.get("cape_task_id"),
        "sandbox_status": parsed.get("sandbox_status", "unknown"),
        "execution_profile": parsed.get("execution_profile", "unknown"),
        "process_activity": _safe_list(parsed.get("process_activity")),
        "file_activity": _safe_list(parsed.get("file_activity")),
        "registry_activity": _safe_list(parsed.get("registry_activity")),
        "network_activity": _safe_list(parsed.get("network_activity")),
        "iocs": _safe_list(parsed.get("iocs")),
        "mitre_mapping": [],
        "risk_score": None,
        "verdict": _derive_verdict(parsed),
        "source": {
            "engine": "cape",
            "report_path": report_path,
            "submission_mode": parsed.get("submission_mode", "manual_cape"),
        },
        "raw_context": parsed.get("raw_context", {}),
    }
    return normalized
