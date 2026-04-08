"""
audit/logger.py — Structured audit logging for Fathom.

Uses structlog for machine-readable, queryable audit trails.
Every security-relevant action is logged with:
  - timestamp (ISO 8601)
  - event type
  - actor (IP address, user_id if available)
  - resource (sha256, session_id, endpoint)
  - outcome (success / failure)
  - metadata (file size, verdict, technique count, etc.)

Log output goes to:
  - stdout (JSON, picked up by Docker logging)
  - /var/log/fathom/audit.jsonl (append-only file)

Usage:
    from audit.logger import audit

    audit.log_upload(request, sha256="abc...", filename="malware.exe", size=102400)
    audit.log_analysis(request, sha256="abc...", verdict="malicious", techniques=["T1055"])
    audit.log_chat(request, session_id="...", query="What C2 domains?")
    audit.log_auth(request, event="login", provider="google", user_id="uid123")
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

# ── structlog setup ───────────────────────────────────────────────────────────
try:
    import structlog

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
    _structlog_available = True
except ImportError:
    _structlog_available = False

_std_logger = logging.getLogger("fathom.audit")

# Audit log file (append-only)
AUDIT_LOG_DIR = Path(os.environ.get("FATHOM_AUDIT_DIR", "/var/log/fathom"))
AUDIT_LOG_FILE = AUDIT_LOG_DIR / "audit.jsonl"


def _ensure_log_dir():
    try:
        AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _write_to_file(record: dict):
    """Append audit record to the JSONL file."""
    try:
        _ensure_log_dir()
        import json
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass  # Never let audit logging break the main flow


def _get_client_ip(request) -> str:
    """Extract client IP from FastAPI request, respecting X-Forwarded-For."""
    if request is None:
        return "unknown"
    try:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


class AuditLogger:
    """Structured audit logger for all security-relevant events."""

    def _emit(self, event: str, request=None, **kwargs):
        """Core emit — writes to structlog + file."""
        record = {
            "ts": time.time(),
            "event": event,
            "client_ip": _get_client_ip(request),
            **kwargs,
        }

        if _structlog_available:
            log = structlog.get_logger("fathom.audit")
            log.info(event, **{k: v for k, v in record.items() if k != "event"})
        else:
            _std_logger.info("%s %s", event, record)

        _write_to_file(record)

    # ── Upload events ─────────────────────────────────────────────────────

    def log_upload(
        self,
        request,
        sha256: str,
        filename: str,
        size: int,
        file_type: str,
        ioc_count: int = 0,
        behavior_count: int = 0,
        stored_in_minio: bool = False,
    ):
        self._emit(
            "file_upload",
            request=request,
            sha256=sha256[:16] + "...",
            filename=filename,
            size_bytes=size,
            file_type=file_type,
            ioc_count=ioc_count,
            behavior_count=behavior_count,
            stored_in_minio=stored_in_minio,
            outcome="success",
        )

    def log_upload_rejected(self, request, reason: str, filename: str = "", size: int = 0):
        self._emit(
            "file_upload_rejected",
            request=request,
            filename=filename,
            size_bytes=size,
            reason=reason,
            outcome="rejected",
        )

    # ── Analysis events ───────────────────────────────────────────────────

    def log_analysis_start(self, request, sha256: str, enable_enrichment: bool):
        self._emit(
            "analysis_start",
            request=request,
            sha256=sha256[:16] + "...",
            enable_enrichment=enable_enrichment,
        )

    def log_analysis_complete(
        self,
        request,
        sha256: str,
        verdict: str,
        confidence: int,
        technique_count: int,
        ioc_count: int,
        enrichment_used: bool,
        duration_ms: int,
        adapter_used: str = "",
    ):
        self._emit(
            "analysis_complete",
            request=request,
            sha256=sha256[:16] + "...",
            verdict=verdict,
            confidence=confidence,
            technique_count=technique_count,
            ioc_count=ioc_count,
            enrichment_used=enrichment_used,
            duration_ms=duration_ms,
            adapter_used=adapter_used,
            outcome="success",
        )

    def log_analysis_failed(self, request, sha256: str, error: str):
        self._emit(
            "analysis_failed",
            request=request,
            sha256=sha256[:16] + "..." if sha256 else "unknown",
            error=error[:200],
            outcome="failure",
        )

    # ── Chat events ───────────────────────────────────────────────────────

    def log_chat(
        self,
        request,
        session_id: str,
        query_len: int,
        cache_hit: bool,
        response_len: int = 0,
    ):
        self._emit(
            "chat_query",
            request=request,
            session_id=session_id[:16] + "...",
            query_len=query_len,
            cache_hit=cache_hit,
            response_len=response_len,
            outcome="success",
        )

    # ── Auth events ───────────────────────────────────────────────────────

    def log_auth(
        self,
        request,
        event: str,  # "login" | "logout" | "token_rejected"
        provider: str = "",
        user_id: str = "",
        outcome: str = "success",
    ):
        self._emit(
            f"auth_{event}",
            request=request,
            provider=provider,
            user_id=user_id[:16] + "..." if len(user_id) > 16 else user_id,
            outcome=outcome,
        )

    # ── Rate limit / security events ──────────────────────────────────────

    def log_rate_limited(self, request, endpoint: str):
        self._emit(
            "rate_limited",
            request=request,
            endpoint=endpoint,
            outcome="blocked",
        )

    def log_injection_detected(self, request, pattern: str, endpoint: str):
        self._emit(
            "injection_attempt",
            request=request,
            pattern=pattern[:100],
            endpoint=endpoint,
            outcome="blocked",
        )

    # ── Graph / storage events ────────────────────────────────────────────

    def log_graph_query(self, request, query_name: str, sample_hash: str = ""):
        self._emit(
            "graph_query",
            request=request,
            query_name=query_name,
            sample_hash=sample_hash[:16] + "..." if sample_hash else "",
            outcome="success",
        )


# Singleton
audit = AuditLogger()
