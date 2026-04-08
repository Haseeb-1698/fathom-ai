"""
sample_similarity.py — Cross-sample FAISS similarity search.

Embeds EvidenceBrief summaries into a dedicated FAISS index (sample_kb).
On each new upload, finds the top-k most similar previously analyzed samples
and returns their SHA256, family, score, and shared techniques/IOCs.

This enables:
  - "This sample is 94% similar to Emotet (sha256: abc...)"
  - Shared IOC correlation across samples
  - Cluster detection (campaign attribution)
  - Context injection into LLM prompts
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

import numpy as np

from config import FAISS_INDEX_DIR

logger = logging.getLogger(__name__)

SAMPLE_INDEX_DIR = FAISS_INDEX_DIR / "sample_kb"
SAMPLE_INDEX_DIR.mkdir(parents=True, exist_ok=True)

MAX_SAMPLE_ENTRIES = 50_000
SIMILARITY_THRESHOLD = 0.75   # cosine similarity to consider "similar"

_sample_index = None
_sample_meta: list[dict] = []
_sample_dirty = False


def _get_embed_model():
    from rag.indexer import _get_embed_model as _base
    return _base()


def _load_sample_index():
    """Load or create the sample FAISS index."""
    global _sample_index, _sample_meta
    if _sample_index is not None:
        return _sample_index, _sample_meta

    import faiss

    idx_path = SAMPLE_INDEX_DIR / "index.faiss"
    meta_path = SAMPLE_INDEX_DIR / "metadata.json"

    if idx_path.exists() and meta_path.exists():
        try:
            _sample_index = faiss.read_index(str(idx_path))
            with open(meta_path, encoding="utf-8") as f:
                _sample_meta = json.load(f)
            logger.info("Loaded sample_kb FAISS index: %d samples", len(_sample_meta))
            return _sample_index, _sample_meta
        except Exception as e:
            logger.warning("Failed to load sample_kb: %s — creating fresh", e)

    dim = 768
    _sample_index = faiss.IndexFlatIP(dim)
    _sample_meta = []
    logger.info("Created fresh sample_kb FAISS index")
    return _sample_index, _sample_meta


def _save_sample_index():
    global _sample_dirty
    if not _sample_dirty or _sample_index is None:
        return
    import faiss
    try:
        faiss.write_index(_sample_index, str(SAMPLE_INDEX_DIR / "index.faiss"))
        with open(SAMPLE_INDEX_DIR / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(_sample_meta, f, ensure_ascii=False)
        _sample_dirty = False
        logger.debug("sample_kb saved (%d entries)", len(_sample_meta))
    except Exception as e:
        logger.warning("Failed to save sample_kb: %s", e)


def _brief_to_text(brief) -> str:
    """
    Convert an EvidenceBrief to a dense text representation for embedding.
    Captures: family, behaviors, techniques, IOC types, API categories, risk signals.
    """
    parts = []

    # Family / detection
    if brief.detections:
        families = [d.get("family", "") for d in brief.detections if d.get("family")]
        if families:
            parts.append(f"Family: {' '.join(families)}")

    # YARA matches
    if brief.yara_matches:
        parts.append(f"YARA: {' '.join(brief.yara_matches[:10])}")

    # Behaviors (category + techniques)
    behavior_cats = set()
    all_techniques = set()
    for b in brief.behaviors[:50]:
        behavior_cats.add(b.category)
        all_techniques.update(b.attack_techniques)
    if behavior_cats:
        parts.append(f"Behaviors: {' '.join(sorted(behavior_cats))}")
    if all_techniques:
        parts.append(f"Techniques: {' '.join(sorted(all_techniques))}")

    # IOC types
    ioc_types = set()
    ioc_domains = []
    ioc_ips = []
    for ioc in brief.iocs[:30]:
        ioc_types.add(ioc.type.value)
        if ioc.type.value == "domain":
            ioc_domains.append(ioc.value)
        elif ioc.type.value == "ip":
            ioc_ips.append(ioc.value)
    if ioc_types:
        parts.append(f"IOC types: {' '.join(sorted(ioc_types))}")

    # API categories
    if brief.api_category_counts:
        top_cats = sorted(brief.api_category_counts.items(), key=lambda x: -x[1])[:8]
        parts.append(f"API categories: {' '.join(c for c, _ in top_cats)}")

    # Suspicious APIs
    if brief.suspicious_apis_seen:
        parts.append(f"Suspicious APIs: {' '.join(brief.suspicious_apis_seen[:15])}")

    # Risk signals
    if brief.risk_signals:
        parts.append(f"Risk: {' '.join(brief.risk_signals[:5])}")

    # PE characteristics
    if brief.packed:
        parts.append("packed obfuscated")
    if brief.pe_signed:
        parts.append("signed certificate")

    # Network
    if brief.network_dns:
        parts.append(f"DNS: {' '.join(brief.network_dns[:5])}")

    return " | ".join(parts) if parts else "unknown sample"


def index_sample(brief) -> str:
    """
    Embed and store an EvidenceBrief in the sample_kb FAISS index.
    Returns the sha256 of the indexed sample.
    Idempotent — won't add duplicates.
    """
    global _sample_dirty

    sha256 = brief.hashes.get("sha256", brief.sample_id or "")
    if not sha256:
        return ""

    index, meta = _load_sample_index()

    # Check for duplicate
    for entry in meta:
        if entry.get("sha256") == sha256:
            logger.debug("Sample %s already in sample_kb", sha256[:16])
            return sha256

    # Enforce max size
    if len(meta) >= MAX_SAMPLE_ENTRIES:
        meta.pop(0)
        _rebuild_sample_index(meta)

    text = _brief_to_text(brief)
    model = _get_embed_model()
    emb = model.encode(text, normalize_embeddings=True)
    emb = np.array([emb], dtype=np.float32)
    index.add(emb)

    # Extract techniques and IOCs for metadata
    techniques = list({t for b in brief.behaviors for t in b.attack_techniques})[:15]
    ioc_values = [i.value for i in brief.iocs[:20]]
    families = [d.get("family", "") for d in brief.detections if d.get("family")]

    meta.append({
        "sha256": sha256,
        "file_name": brief.file_name or "",
        "family": families[0] if families else "",
        "malscore": brief.meta.malscore if brief.meta else 0,
        "techniques": techniques,
        "ioc_values": ioc_values,
        "indexed_at": time.time(),
        "_text": text[:300],
    })
    _sample_dirty = True
    _save_sample_index()

    logger.info("Indexed sample %s (%s) in sample_kb", sha256[:16], families[0] if families else "unknown")
    return sha256


def find_similar_samples(
    brief,
    top_k: int = 5,
    threshold: float = SIMILARITY_THRESHOLD,
) -> list[dict]:
    """
    Find the top-k most similar previously analyzed samples.

    Returns list of:
        {sha256, file_name, family, malscore, similarity, shared_techniques, shared_iocs}
    """
    try:
        index, meta = _load_sample_index()
        if index.ntotal == 0:
            return []

        text = _brief_to_text(brief)
        model = _get_embed_model()
        emb = model.encode(text, normalize_embeddings=True)
        emb = np.array([emb], dtype=np.float32)

        k = min(top_k + 1, index.ntotal)  # +1 to skip self
        scores, indices = index.search(emb, k)

        current_sha256 = brief.hashes.get("sha256", "")
        current_techniques = set(t for b in brief.behaviors for t in b.attack_techniques)
        current_iocs = set(i.value for i in brief.iocs)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(meta):
                continue
            if float(score) < threshold:
                continue

            entry = meta[idx]
            if entry.get("sha256") == current_sha256:
                continue  # skip self

            shared_techniques = list(current_techniques & set(entry.get("techniques", [])))
            shared_iocs = list(current_iocs & set(entry.get("ioc_values", [])))

            results.append({
                "sha256": entry["sha256"],
                "file_name": entry.get("file_name", ""),
                "family": entry.get("family", ""),
                "malscore": entry.get("malscore", 0),
                "similarity": round(float(score), 3),
                "shared_techniques": shared_techniques[:8],
                "shared_iocs": shared_iocs[:5],
            })

            if len(results) >= top_k:
                break

        return results

    except Exception as e:
        logger.warning("find_similar_samples error: %s", e)
        return []


def format_similar_context(similar: list[dict]) -> str:
    """Format similar samples as context text for LLM injection."""
    if not similar:
        return ""
    lines = ["=== SIMILAR SAMPLES FROM KNOWLEDGE BASE ==="]
    for s in similar:
        line = f"• {s['file_name'] or s['sha256'][:16]} ({s['family'] or 'unknown'}) — similarity {s['similarity']:.0%}"
        if s["shared_techniques"]:
            line += f" | shared TTPs: {', '.join(s['shared_techniques'][:4])}"
        if s["shared_iocs"]:
            line += f" | shared IOCs: {', '.join(s['shared_iocs'][:3])}"
        lines.append(line)
    return "\n".join(lines)


def _rebuild_sample_index(meta: list[dict]):
    """Rebuild FAISS index from metadata (used after eviction)."""
    global _sample_index
    import faiss
    model = _get_embed_model()
    dim = 768
    _sample_index = faiss.IndexFlatIP(dim)
    if not meta:
        return
    texts = [m.get("_text", "") for m in meta]
    embs = model.encode(texts, normalize_embeddings=True, batch_size=64)
    _sample_index.add(np.array(embs, dtype=np.float32))
