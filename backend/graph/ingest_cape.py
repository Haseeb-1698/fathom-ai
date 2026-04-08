"""
ingest_cape.py — Ingest EvidenceBrief data into Neo4j graph + FAISS sample index.
"""

from __future__ import annotations

import logging
from datetime import datetime

from evidence.cape_extractor import EvidenceBrief
from graph.neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)


def ingest_evidence(client: Neo4jClient, brief: EvidenceBrief):
    """Ingest a single EvidenceBrief into the Neo4j graph."""

    sample_hash = brief.hashes.get("sha256", brief.hashes.get("md5", brief.sample_id))
    family = brief.detections[0]["family"] if brief.detections else ""

    # Create Sample node
    client.run("""
        MERGE (s:Sample {sha256: $hash})
        SET s.name = $name, s.family = $family, s.score = $score,
            s.analyzed_at = $ts
    """, {
        "hash": sample_hash,
        "name": brief.file_name,
        "family": family,
        "score": brief.meta.malscore if brief.meta else 0,
        "ts": datetime.utcnow().isoformat(),
    })

    # Create processes from process_tree (v3 uses ProcessNode objects)
    for node in brief.process_tree:
        uid = f"{sample_hash}_{node.pid}"
        client.run("""
            MERGE (p:Process {uid: $uid})
            SET p.pid = $pid, p.name = $name, p.ppid = $ppid
            WITH p
            MATCH (s:Sample {sha256: $hash})
            MERGE (s)-[:SPAWNED]->(p)
        """, {
            "uid": uid,
            "pid": node.pid,
            "name": node.name,
            "ppid": node.ppid,
            "hash": sample_hash,
        })

    # Create IOC nodes (v3 IOC objects have .type, .value, .confidence)
    for ioc in brief.iocs:
        client.run("""
            MERGE (i:IOC {value: $value})
            SET i.type = $type, i.confidence = $conf, i.source = $source
            WITH i
            MATCH (s:Sample {sha256: $hash})
            MERGE (s)-[:HAS_IOC]->(i)
        """, {
            "value": ioc.value,
            "type": ioc.type.value,
            "conf": ioc.confidence,
            "source": ioc.source,
            "hash": sample_hash,
        })

    # Create Technique nodes from behaviors (v3 stores ATT&CK in behaviors)
    seen_techniques = set()
    for behavior in brief.behaviors:
        for tid in behavior.attack_techniques:
            if tid in seen_techniques:
                continue
            seen_techniques.add(tid)
            client.run("""
                MERGE (t:Technique {technique_id: $tid})
                WITH t
                MATCH (s:Sample {sha256: $hash})
                MERGE (s)-[:USES_TECHNIQUE]->(t)
            """, {
                "tid": tid,
                "hash": sample_hash,
            })

    # Create Behavior nodes (v3 BehaviorIndicator has severity, description, evidence)
    for behavior in brief.behaviors:
        client.run("""
            MERGE (b:Behavior {description: $desc})
            SET b.severity = $sev, b.source = $source
            WITH b
            MATCH (s:Sample {sha256: $hash})
            MERGE (s)-[:EXHIBITED]->(b)
        """, {
            "desc": behavior.description[:500],
            "sev": behavior.severity.value,
            "source": behavior.source,
            "hash": sample_hash,
        })

    # Create network connections (v3 uses network_flows: list of dicts)
    for flow in brief.network_flows:
        ip = flow.get("dst", "")
        port = flow.get("port", flow.get("dport", 0))
        proto = flow.get("protocol", flow.get("proto", "tcp")).upper()

        client.run("""
            MERGE (n:NetworkConn {dst_ip: $ip, dst_port: $port})
            SET n.protocol = $proto
            WITH n
            MATCH (s:Sample {sha256: $hash})
            MERGE (s)-[:HAS_NETWORK]->(n)
        """, {
            "ip": ip,
            "port": port,
            "proto": proto,
            "hash": sample_hash,
        })


async def ingest_evidence_brief(brief: EvidenceBrief) -> None:
    """Async wrapper: ingest into Neo4j + FAISS sample index. Logs errors, never raises."""
    try:
        client = Neo4jClient()
        ingest_evidence(client, brief)
        logger.info("Neo4j ingestion complete for %s", brief.sha256)
    except Exception as exc:
        logger.error("Neo4j ingestion failed for %s: %s", brief.sha256, exc)

    # Also index in FAISS sample_kb for cross-sample similarity
    try:
        from rag.sample_similarity import index_sample
        index_sample(brief)
    except Exception as exc:
        logger.warning("FAISS sample indexing failed for %s: %s", brief.sha256, exc)
