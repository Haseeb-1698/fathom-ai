"""
indexer.py — Build FAISS index from ATT&CK KB + custom knowledge base.

Uses sentence-transformers embeddings and FAISS IndexFlatIP (inner product
on L2-normalized vectors = cosine similarity).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np

from config import EMBEDDING_MODEL_ID, FAISS_INDEX_DIR

# Lazy imports for heavy deps
_faiss = None
_embed_model = None


def _get_faiss():
    global _faiss
    if _faiss is None:
        import faiss
        _faiss = faiss
    return _faiss


def _get_embed_model():
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer(EMBEDDING_MODEL_ID)
    return _embed_model


def build_index(
    documents: list[dict],
    text_key: str = "text",
    index_name: str = "attack_kb",
) -> Path:
    """
    Build a FAISS index from a list of documents.

    Args:
        documents: List of dicts, each must have `text_key` field.
        text_key: Key in each dict containing the text to embed.
        index_name: Name for the saved index files.

    Returns:
        Path to the index directory.
    """
    faiss = _get_faiss()
    model = _get_embed_model()

    texts = [doc[text_key] for doc in documents]
    print(f"Embedding {len(texts)} documents...")
    embeddings = model.encode(texts, normalize_embeddings=True,
                              show_progress_bar=True, batch_size=64)
    embeddings = np.array(embeddings, dtype=np.float32)

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)  # cosine similarity on normalized vectors
    index.add(embeddings)

    # Save
    index_dir = FAISS_INDEX_DIR / index_name
    index_dir.mkdir(parents=True, exist_ok=True)

    faiss.write_index(index, str(index_dir / "index.faiss"))

    # Save metadata alongside
    metadata = []
    for doc in documents:
        meta = {k: v for k, v in doc.items() if k != text_key}
        meta["_text_preview"] = doc[text_key][:200]
        metadata.append(meta)

    with open(index_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Index saved: {index_dir} ({len(documents)} vectors, dim={dim})")
    return index_dir


def load_index(index_name: str = "attack_kb"):
    """Load a FAISS index and its metadata. Tries multiple path layouts."""
    faiss = _get_faiss()

    # Primary path: FAISS_INDEX_DIR / index_name
    index_dir = FAISS_INDEX_DIR / index_name

    # Fallback: infra/rag_index subdirectory (legacy layout)
    if not (index_dir / "index.faiss").exists():
        alt = index_dir / "infra" / "rag_index"
        if (alt / "index.faiss").exists():
            index_dir = alt

    if not (index_dir / "index.faiss").exists():
        raise FileNotFoundError(
            f"FAISS index not found at {index_dir}. "
            "Run: python scripts/build_faiss_index.py"
        )

    index = faiss.read_index(str(index_dir / "index.faiss"))

    with open(index_dir / "metadata.json", "r", encoding="utf-8") as f:
        metadata = json.load(f)

    return index, metadata
