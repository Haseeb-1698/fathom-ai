"""
cape_extractor.py — Thin wrapper around cape_extraction_layer_v3.py.

All extraction logic lives in the v3 module (1,934 lines of battle-tested code
including KSPN enrichment, API n-grams, process tree reconstruction, AMSI
payload extraction, CVE-2025-61301 resilience, and IOC deduplication).

This module re-exports the public API so downstream consumers
(routes.py, tools.py, module1_adapter.py, ingest_cape.py) can do:

    from evidence.cape_extractor import extract_from_cape_json, EvidenceBrief
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Import everything from v3 — the single source of truth
from evidence.cape_extraction_layer_v3 import (
    CAPEEvidenceExtractor,
    EvidenceBrief,
    ExtractorConfig,
    IOC,
    IOCType,
    BehaviorIndicator,
    Severity,
)

# Module-level singleton extractor (default config)
_extractor = CAPEEvidenceExtractor()


def extract_from_cape_json(report_path: str | Path) -> EvidenceBrief:
    """Extract an EvidenceBrief from a CAPE JSON report file.

    Delegates to CAPEEvidenceExtractor.from_report_file() which handles:
    - orjson fast-path for large reports
    - Size guard against oversized/adversarial payloads
    - Full extraction pipeline (static, dynamic, network, signatures, etc.)
    """
    return _extractor.from_report_file(str(report_path))


def extract_from_cape_dict(report: dict) -> EvidenceBrief:
    """Extract an EvidenceBrief from an already-loaded CAPE report dict.

    Delegates to CAPEEvidenceExtractor.from_report_dict() which runs the
    full 13-stage extraction pipeline with deduplication and cap enforcement.
    """
    return _extractor.from_report_dict(report)


def format_evidence_text(brief: EvidenceBrief) -> str:
    """Produce a human-readable evidence summary for LLM context.

    This is the to_text() equivalent — calls the v3 extractor's
    _format_evidence() which produces the full structured brief.
    """
    return _extractor._format_evidence(brief)


def enrich_from_kspn(brief: EvidenceBrief, kspn: dict) -> None:
    """Enrich an EvidenceBrief with KSPN sidecar data.

    Adds MITRE mappings, risk scores, PCAP IPs, and family confidence
    from the KSPN report summary.
    """
    _extractor.enrich_from_kspn(brief, kspn)


def build_expert_prompt(brief: EvidenceBrief, task: str = "full_report") -> str:
    """Build a task-specific expert prompt from an EvidenceBrief.

    Tasks: full_report, attck_mapping, risk_assessment, executive_summary, ioc_report
    """
    return _extractor.build_expert_prompt(brief, task=task)
