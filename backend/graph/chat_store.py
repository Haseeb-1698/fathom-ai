"""
chat_store.py — Persistent chat session storage in Neo4j + FAISS semantic cache.

Architecture:
  Neo4j  — stores ChatSession → ChatTurn nodes with technique/IOC tags.
            Enables: session replay, cross-sample Q&A analytics, graph traversal.

  FAISS  — chat_kb index stores embeddings of (query, response) pairs.
            Enables: semantic cache — similar future queries return cached answers
            in <200ms instead of calling the model.

Public API:
  save_turn(session_id, sample_sha256, role, content, ...)
  get_session_history(session_id) -> list[dict]
  cache_lookup(query, sample_sha256, threshold) -> str | None
  cache_store(query, response, sample_sha256)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Optional

import numpy as np

from config import FAISS_INDEX_DIR

logger = logging.getLogger(__name__)

# ── FAISS chat cache ──────────────────────────────────────────────────────────

CHAT_INDEX_DIR = FAISS_INDEX_DIR / "chat_kb"
CHAT_INDEX_DIR.mkdir(parents=True, exist_ok=True)

_chat_index = None
_chat_meta: list[dict] = []
_chat_dirty = False   # True when in-memory index has unsaved additions

CACHE_SIMILARITY_THRESHOLD = 0.88   # cosine similarity to consider a cache hit
MAX_CACHE_ENTRIES = 10_000


def _get_embed_model():
    from rag.indexer import _get_embed_model as _base
    return _base()


def _load_chat_index():
    """Load or create the chat FAISS index."""
    global _chat_index, _chat_meta
    if _chat_index is not None:
        return _chat_index, _chat_meta

    import faiss

    idx_path = CHAT_INDEX_DIR / "index.faiss"
    meta_path = CHAT_INDEX_DIR / "metadata.json"

    if idx_path.exists() and meta_path.exists():
        try:
            _chat_index = faiss.read_index(str(idx_path))
            with open(meta_path, encoding="utf-8") as f:
                _chat_meta = json.load(f)
            logger.info("Loaded chat_kb FAISS index: %d entries", len(_chat_meta))
            return _chat_index, _chat_meta
        except Exception as e:
            logger.warning("Failed to load chat_kb index: %s — creating fresh", e)

    # Create empty index (768-dim, same as attack_kb)
    dim = 768
    _chat_index = faiss.IndexFlatIP(dim)
    _chat_meta = []
    logger.info("Created fresh chat_kb FAISS index")
    return _chat_index, _chat_meta


def _save_chat_index():
    """Persist the chat FAISS index to disk."""
    global _chat_dirty
    if not _chat_dirty or _chat_index is None:
        return
    import faiss
    try:
        faiss.write_index(_chat_index, str(CHAT_INDEX_DIR / "index.faiss"))
        with open(CHAT_INDEX_DIR / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(_chat_meta, f, ensure_ascii=False)
        _chat_dirty = False
        logger.debug("chat_kb FAISS index saved (%d entries)", len(_chat_meta))
    except Exception as e:
        logger.warning("Failed to save chat_kb index: %s", e)


def cache_lookup(
    query: str,
    sample_sha256: str = "",
    threshold: float = CACHE_SIMILARITY_THRESHOLD,
) -> Optional[str]:
    """
    Semantic cache lookup. Returns cached response if a similar query exists.

    Args:
        query: The user's question.
        sample_sha256: Filter to entries for this sample (empty = global search).
        threshold: Cosine similarity threshold (0.88 = very similar).

    Returns:
        Cached response string, or None on miss.
    """
    try:
        index, meta = _load_chat_index()
        if index.ntotal == 0:
            return None

        model = _get_embed_model()
        emb = model.encode(query, normalize_embeddings=True)
        emb = np.array([emb], dtype=np.float32)

        k = min(5, index.ntotal)
        scores, indices = index.search(emb, k)

        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(meta):
                continue
            if float(score) < threshold:
                break  # sorted descending, no point continuing

            entry = meta[idx]
            # If sample filter is set, only return hits for that sample
            # (or entries with no sample association)
            if sample_sha256 and entry.get("sample_sha256") not in ("", sample_sha256):
                continue

            logger.info(
                "Cache HIT (score=%.3f) for query: %s...",
                score, query[:60]
            )
            # Bump hit count in Neo4j asynchronously
            _bump_cache_hit_async(entry.get("cache_id", ""))
            return entry.get("response_text", "")

    except Exception as e:
        logger.warning("Cache lookup error: %s", e)
    return None


def cache_store(
    query: str,
    response: str,
    sample_sha256: str = "",
    tags: list[str] | None = None,
) -> str:
    """
    Store a query→response pair in the FAISS cache and Neo4j.

    Returns the cache_id.
    """
    global _chat_dirty

    if not query.strip() or not response.strip():
        return ""

    cache_id = hashlib.sha256(f"{query}|{sample_sha256}".encode()).hexdigest()[:16]

    try:
        index, meta = _load_chat_index()

        # Don't store duplicates
        for entry in meta:
            if entry.get("cache_id") == cache_id:
                return cache_id

        # Enforce max size (evict oldest)
        if len(meta) >= MAX_CACHE_ENTRIES:
            meta.pop(0)
            # Rebuild index without the evicted entry
            _rebuild_chat_index(meta)

        model = _get_embed_model()
        emb = model.encode(query, normalize_embeddings=True)
        emb = np.array([emb], dtype=np.float32)
        index.add(emb)

        meta.append({
            "cache_id": cache_id,
            "query_text": query[:500],
            "response_text": response[:4000],
            "sample_sha256": sample_sha256,
            "tags": tags or [],
            "created_at": time.time(),
            "hit_count": 0,
        })
        _chat_dirty = True
        _save_chat_index()

        # Persist to Neo4j asynchronously
        _store_cache_neo4j_async(cache_id, query, response, sample_sha256)

        logger.debug("Cache stored: %s (query: %s...)", cache_id, query[:40])
        return cache_id

    except Exception as e:
        logger.warning("Cache store error: %s", e)
        return ""


def _rebuild_chat_index(meta: list[dict]):
    """Rebuild FAISS index from metadata (used after eviction)."""
    global _chat_index
    import faiss
    model = _get_embed_model()
    dim = 768
    _chat_index = faiss.IndexFlatIP(dim)
    if not meta:
        return
    texts = [m.get("query_text", "") for m in meta]
    embs = model.encode(texts, normalize_embeddings=True, batch_size=64)
    _chat_index.add(np.array(embs, dtype=np.float32))


# ── Neo4j chat session storage ────────────────────────────────────────────────

def save_turn(
    session_id: str,
    role: str,
    content: str,
    sample_sha256: str = "",
    tags: list[str] | None = None,
) -> str:
    """
    Persist a single chat turn to Neo4j.

    Creates ChatSession if it doesn't exist, links to Sample if sha256 provided.
    Extracts technique IDs and IOC values from content for graph linking.

    Returns turn_id.
    """
    turn_id = str(uuid.uuid4())
    ts = time.time()
    tags = tags or []

    # Auto-extract ATT&CK technique IDs and IOC-like values from content
    techniques = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", content)))
    iocs = list(dict.fromkeys(re.findall(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"          # IPs
        r"|\b[0-9a-fA-F]{32}\b"                         # MD5
        r"|\b[0-9a-fA-F]{64}\b"                         # SHA256
        r"|\b(?:[a-z0-9\-]+\.)+(?:xyz|com|net|org|io|ru|cn)\b",  # domains
        content, re.IGNORECASE
    )))[:10]

    try:
        from graph.neo4j_client import Neo4jClient
        client = Neo4jClient()

        # Upsert ChatSession
        client.run("""
            MERGE (sess:ChatSession {session_id: $sid})
            ON CREATE SET sess.created_at = $ts, sess.turn_count = 0,
                          sess.sample_sha256 = $sha256
            SET sess.turn_count = sess.turn_count + 1,
                sess.last_active = $ts
        """, {"sid": session_id, "ts": ts, "sha256": sample_sha256})

        # Link session to Sample if sha256 provided
        if sample_sha256:
            client.run("""
                MATCH (sess:ChatSession {session_id: $sid})
                MERGE (s:Sample {sha256: $sha256})
                MERGE (sess)-[:ABOUT]->(s)
            """, {"sid": session_id, "sha256": sample_sha256})

        # Create ChatTurn
        client.run("""
            CREATE (t:ChatTurn {
                turn_id: $turn_id,
                role: $role,
                content: $content,
                ts: $ts,
                tags: $tags,
                techniques_mentioned: $techniques,
                iocs_mentioned: $iocs
            })
            WITH t
            MATCH (sess:ChatSession {session_id: $sid})
            MERGE (sess)-[:HAS_TURN]->(t)
        """, {
            "turn_id": turn_id,
            "role": role,
            "content": content[:2000],
            "ts": ts,
            "tags": tags,
            "techniques": techniques,
            "iocs": iocs,
            "sid": session_id,
        })

        # Link turn to mentioned Techniques
        for tid in techniques[:8]:
            client.run("""
                MATCH (t:ChatTurn {turn_id: $turn_id})
                MERGE (tech:Technique {technique_id: $tid})
                MERGE (t)-[:MENTIONS_TECHNIQUE]->(tech)
            """, {"turn_id": turn_id, "tid": tid})

        # Link turn to mentioned IOCs
        for ioc_val in iocs[:5]:
            client.run("""
                MATCH (t:ChatTurn {turn_id: $turn_id})
                MERGE (i:IOC {value: $val})
                MERGE (t)-[:MENTIONS_IOC]->(i)
            """, {"turn_id": turn_id, "val": ioc_val})

    except Exception as e:
        logger.warning("Neo4j chat turn save failed: %s", e)

    return turn_id


def get_session_history(session_id: str, limit: int = 20) -> list[dict]:
    """
    Retrieve conversation history for a session from Neo4j.

    Returns list of {role, content, ts, tags, techniques, iocs} dicts.
    """
    try:
        from graph.neo4j_client import Neo4jClient
        from graph.queries import SESSION_TURNS
        client = Neo4jClient()
        rows = client.run(SESSION_TURNS, {"session_id": session_id})
        return [
            {
                "role": r.get("role", "user"),
                "content": r.get("content", ""),
                "ts": r.get("ts", 0),
                "tags": r.get("tags", []),
                "techniques": r.get("techniques", []),
                "iocs": r.get("iocs", []),
            }
            for r in rows[-limit:]
        ]
    except Exception as e:
        logger.warning("Neo4j session history fetch failed: %s", e)
        return []


def get_history_as_turns(session_id: str) -> list[dict[str, str]]:
    """
    Return history in orchestrator format: [{user: ..., bot: ...}]
    """
    rows = get_session_history(session_id)
    turns: list[dict[str, str]] = []
    i = 0
    while i < len(rows):
        if rows[i]["role"] == "user":
            bot = rows[i + 1]["content"] if i + 1 < len(rows) and rows[i + 1]["role"] == "assistant" else ""
            turns.append({"user": rows[i]["content"], "bot": bot})
            i += 2
        else:
            i += 1
    return turns


# ── Async helpers (fire-and-forget) ──────────────────────────────────────────

def _bump_cache_hit_async(cache_id: str):
    """Increment hit_count on a cache entry in Neo4j (best-effort)."""
    if not cache_id:
        return
    try:
        from graph.neo4j_client import Neo4jClient
        from graph.queries import CACHE_LOOKUP
        Neo4jClient().run(CACHE_LOOKUP, {
            "query_hash": cache_id,
            "now": time.time(),
        })
    except Exception:
        pass


def _store_cache_neo4j_async(
    cache_id: str, query: str, response: str, sample_sha256: str
):
    """Persist cache entry to Neo4j (best-effort)."""
    try:
        from graph.neo4j_client import Neo4jClient
        from graph.queries import CACHE_STORE
        Neo4jClient().run(CACHE_STORE, {
            "cache_id": cache_id,
            "query_hash": cache_id,
            "query_text": query[:500],
            "response_text": response[:4000],
            "now": time.time(),
            "sample_sha256": sample_sha256,
        })
    except Exception:
        pass
