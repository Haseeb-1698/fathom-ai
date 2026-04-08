"""
context_retriever.py — Query Neo4j for behavioral context during LLM inference.

Called BEFORE the LLM generates a report. Enriches the prompt with:
  1. Related samples sharing the same IOCs or techniques (cross-sample correlation)
  2. Known technique details from previously analyzed samples
  3. IOC reputation from the graph (how many samples used this IOC)

This is Step 14b from the architecture diagram:
  "Malware behavior relationships (Neo4j) → injected into LLM context"
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_graph_context(
    sha256: str = "",
    techniques: list[str] | None = None,
    ioc_values: list[str] | None = None,
    max_related: int = 5,
) -> str:
    """
    Query Neo4j for behavioral relationships and return formatted context text.

    Args:
        sha256: SHA256 of the current sample (to exclude self from results).
        techniques: ATT&CK technique IDs extracted from the current sample.
        ioc_values: IOC values (IPs, domains, hashes) from the current sample.
        max_related: Max number of related samples to include.

    Returns:
        Formatted context string ready for LLM prompt injection.
        Empty string if Neo4j is unavailable or no relationships found.
    """
    try:
        from graph.neo4j_client import Neo4jClient
        client = Neo4jClient()
    except Exception as e:
        logger.debug("Neo4j unavailable for context retrieval: %s", e)
        return ""

    sections: list[str] = []

    # ── 1. Samples sharing the same techniques ────────────────────────────
    if techniques:
        try:
            rows = client.run("""
                UNWIND $tids AS tid
                MATCH (t:Technique {technique_id: tid})<-[:USES_TECHNIQUE]-(s:Sample)
                WHERE s.sha256 <> $sha256
                WITH s, collect(DISTINCT tid) AS shared_tids
                ORDER BY size(shared_tids) DESC
                LIMIT $limit
                RETURN s.sha256 AS hash, s.name AS name, s.family AS family,
                       s.score AS score, shared_tids
            """, {
                "tids": techniques[:10],
                "sha256": sha256 or "",
                "limit": max_related,
            })

            if rows:
                lines = ["=== RELATED SAMPLES (shared ATT&CK techniques) ==="]
                for r in rows:
                    name = r.get("name") or r.get("hash", "?")[:16]
                    family = r.get("family") or "unknown"
                    score = r.get("score") or 0
                    shared = ", ".join(r.get("shared_tids", [])[:5])
                    lines.append(
                        f"• {name} ({family}) score={score} | shared TTPs: {shared}"
                    )
                sections.append("\n".join(lines))
        except Exception as e:
            logger.debug("Technique correlation query failed: %s", e)

    # ── 2. Samples sharing the same IOCs ─────────────────────────────────
    if ioc_values:
        try:
            rows = client.run("""
                UNWIND $iocs AS ioc_val
                MATCH (i:IOC {value: ioc_val})<-[:HAS_IOC]-(s:Sample)
                WHERE s.sha256 <> $sha256
                WITH s, collect(DISTINCT ioc_val) AS shared_iocs
                ORDER BY size(shared_iocs) DESC
                LIMIT $limit
                RETURN s.sha256 AS hash, s.name AS name, s.family AS family,
                       s.score AS score, shared_iocs
            """, {
                "iocs": ioc_values[:15],
                "sha256": sha256 or "",
                "limit": max_related,
            })

            if rows:
                lines = ["=== RELATED SAMPLES (shared IOCs) ==="]
                for r in rows:
                    name = r.get("name") or r.get("hash", "?")[:16]
                    family = r.get("family") or "unknown"
                    score = r.get("score") or 0
                    shared = ", ".join(r.get("shared_iocs", [])[:3])
                    lines.append(
                        f"• {name} ({family}) score={score} | shared IOCs: {shared}"
                    )
                sections.append("\n".join(lines))
        except Exception as e:
            logger.debug("IOC correlation query failed: %s", e)

    # ── 3. IOC reputation (how many samples used each IOC) ────────────────
    if ioc_values:
        try:
            rows = client.run("""
                UNWIND $iocs AS ioc_val
                MATCH (i:IOC {value: ioc_val})<-[:HAS_IOC]-(s:Sample)
                WITH i.value AS ioc, i.type AS ioc_type,
                     count(s) AS sample_count,
                     collect(DISTINCT s.family)[..3] AS families
                WHERE sample_count > 1
                ORDER BY sample_count DESC
                LIMIT 8
                RETURN ioc, ioc_type, sample_count, families
            """, {"iocs": ioc_values[:15]})

            if rows:
                lines = ["=== IOC REPUTATION (from graph) ==="]
                for r in rows:
                    ioc = r.get("ioc", "")
                    itype = r.get("ioc_type", "")
                    count = r.get("sample_count", 0)
                    fams = ", ".join(f for f in (r.get("families") or []) if f)
                    lines.append(
                        f"• [{itype}] {ioc} — seen in {count} samples"
                        + (f" ({fams})" if fams else "")
                    )
                sections.append("\n".join(lines))
        except Exception as e:
            logger.debug("IOC reputation query failed: %s", e)

    # ── 4. Technique co-occurrence (which techniques appear together) ──────
    if techniques and len(techniques) >= 2:
        try:
            rows = client.run("""
                UNWIND $tids AS tid
                MATCH (t:Technique {technique_id: tid})<-[:USES_TECHNIQUE]-(s:Sample)
                      -[:USES_TECHNIQUE]->(t2:Technique)
                WHERE t2.technique_id <> tid
                  AND NOT t2.technique_id IN $tids
                WITH t2.technique_id AS co_tid, count(DISTINCT s) AS freq
                ORDER BY freq DESC
                LIMIT 5
                RETURN co_tid, freq
            """, {"tids": techniques[:8]})

            if rows:
                co_tids = [r["co_tid"] for r in rows if r.get("co_tid")]
                if co_tids:
                    sections.append(
                        f"=== COMMONLY CO-OCCURRING TECHNIQUES ===\n"
                        f"Samples with {', '.join(techniques[:3])} also frequently use: "
                        f"{', '.join(co_tids)}"
                    )
        except Exception as e:
            logger.debug("Technique co-occurrence query failed: %s", e)

    if not sections:
        return ""

    return "\n\n".join(sections)


def extract_techniques_from_brief(brief) -> list[str]:
    """Extract ATT&CK technique IDs from an EvidenceBrief."""
    techniques: set[str] = set()
    for behavior in getattr(brief, "behaviors", []):
        techniques.update(getattr(behavior, "attack_techniques", []))
    return list(techniques)[:15]


def extract_iocs_from_brief(brief) -> list[str]:
    """Extract IOC values from an EvidenceBrief (non-private IPs + domains)."""
    import re
    values: list[str] = []
    for ioc in getattr(brief, "iocs", [])[:30]:
        val = getattr(ioc, "value", "")
        if not val:
            continue
        # Skip private IPs
        if re.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", val):
            continue
        values.append(val)
    return values[:20]
