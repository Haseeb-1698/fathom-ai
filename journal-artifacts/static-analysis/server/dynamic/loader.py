from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CAPE_ROOT = Path(os.environ.get("FATHOM_CAPE_ROOT", "~/CAPEv2")).expanduser()


def _default_analyses_root() -> Path:
    return DEFAULT_CAPE_ROOT / "storage" / "analyses"


def resolve_cape_report_path(
    *,
    task_id: Optional[int] = None,
    report_path: Optional[str | Path] = None,
    analyses_root: Optional[str | Path] = None,
) -> Path:
    """Resolve a CAPE report.json path from either a task id or a direct path."""

    if report_path:
        resolved = Path(report_path).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"CAPE report path does not exist: {resolved}")
        return resolved

    if task_id is None:
        raise ValueError("Either task_id or report_path must be provided")

    base = Path(analyses_root).expanduser().resolve() if analyses_root else _default_analyses_root()
    resolved = base / str(task_id) / "reports" / "report.json"
    if not resolved.exists():
        raise FileNotFoundError(f"CAPE report for task {task_id} not found: {resolved}")
    return resolved


def _validate_report_sections(report: Dict[str, Any]) -> None:
    required_top_level = ("info", "target", "behavior", "network")
    missing = [key for key in required_top_level if key not in report]
    if missing:
        raise ValueError(f"CAPE report missing required section(s): {', '.join(missing)}")


def collect_cape_report(
    *,
    task_id: Optional[int] = None,
    report_path: Optional[str | Path] = None,
    analyses_root: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Load a CAPE report for a task or direct path and return a bundle for the parser.

    The returned object contains the raw CAPE report plus a small amount of locator
    metadata so downstream stages can retain provenance.
    """

    resolved_path = resolve_cape_report_path(task_id=task_id, report_path=report_path, analyses_root=analyses_root)
    raw_report = json.loads(resolved_path.read_text(encoding="utf-8"))
    _validate_report_sections(raw_report)

    inferred_task_id = raw_report.get("info", {}).get("id")
    analysis_path = resolved_path.parents[1]

    return {
        "task_id": inferred_task_id if inferred_task_id is not None else task_id,
        "report_path": str(resolved_path),
        "analysis_path": str(analysis_path),
        "report": raw_report,
    }
