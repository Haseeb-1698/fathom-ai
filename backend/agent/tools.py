"""
tools.py — Tool functions used by the Azure swarm agents and copilot.

These are plain Python functions (no LangChain dependency) that wrap
Fathom's FAISS, Neo4j, and evidence extraction components.
They are also registered as SWARM_TOOLS in azure_swarm.py.
"""

from __future__ import annotations


def fathom_analyze(query: str) -> str:
    """Analyze a malware sample or behavior using Fathom's expert pipeline."""
    from llm.inference import generate
    result = generate(query=query, max_new_tokens=512)
    return (
        f"[Domain: {result.domain_name} | Adapter: {result.adapter_used} | "
        f"Confidence: {result.confidence:.2f}]\n\n{result.text}"
    )


def attack_map(query: str) -> str:
    """Map behaviors to MITRE ATT&CK techniques via FAISS index."""
    try:
        from rag.retriever import RAGRetriever
        return RAGRetriever("attack_kb").query_to_text(query, top_k=5)
    except Exception as e:
        return f"ATT&CK lookup failed: {e}"


def knowledge_search(query: str) -> str:
    """Search the cybersecurity knowledge base."""
    try:
        from rag.retriever import RAGRetriever
        return RAGRetriever("attack_kb").query_to_text(query, top_k=3)
    except Exception as e:
        return f"Knowledge search unavailable: {e}"


def ioc_lookup(ioc_value: str) -> str:
    """Look up an IOC in the Neo4j behavior graph."""
    try:
        from graph.neo4j_client import Neo4jClient
        results = Neo4jClient().run(
            "MATCH (i:IOC {value: $value})<-[:HAS_IOC]-(s:Sample) "
            "RETURN s.sha256 AS hash, s.name AS name, s.family AS family, s.score AS score",
            {"value": ioc_value},
        )
        if not results:
            return f"IOC '{ioc_value}' not found in graph database."
        lines = [f"IOC '{ioc_value}' found in {len(results)} sample(s):"]
        for r in results:
            lines.append(
                f"  - {r.get('name','?')} ({r.get('family','unknown')}) "
                f"hash={str(r.get('hash','?'))[:16]}... score={r.get('score','?')}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"IOC lookup failed: {e}"


def evidence_extract(cape_json_path: str) -> str:
    """Extract structured evidence from a CAPE sandbox report file."""
    import os
    from pathlib import Path

    allowed_dirs = [Path(os.getenv("FATHOM_REPORTS_DIR", "/workspace/reports"))]
    resolved = Path(cape_json_path).resolve()
    if not any(str(resolved).startswith(str(d.resolve())) for d in allowed_dirs):
        return "Access denied: path must be within the reports directory"

    try:
        from evidence.cape_extractor import extract_from_cape_json, format_evidence_text
        return format_evidence_text(extract_from_cape_json(str(resolved)))
    except FileNotFoundError:
        return f"File not found: {cape_json_path}"
    except Exception as e:
        return f"Evidence extraction failed: {e}"


# Kept for any code that imports ALL_TOOLS by name
ALL_TOOLS = [fathom_analyze, attack_map, knowledge_search, ioc_lookup, evidence_extract]
