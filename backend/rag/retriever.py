"""
retriever.py — Query FAISS index for relevant ATT&CK techniques and KB chunks.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from rag.indexer import load_index, _get_embed_model


class RAGRetriever:
    """Retrieve relevant context from FAISS indexes."""

    def __init__(self, index_name: str = "attack_kb"):
        self.index, self.metadata = load_index(index_name)
        self.model = _get_embed_model()

    def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """
        Query the index and return top-K results with scores.

        Returns list of:
            {"score": float, "technique_id": str, "name": str, ...}
        """
        query_emb = self.model.encode(text, normalize_embeddings=True)
        query_emb = np.array([query_emb], dtype=np.float32)

        scores, indices = self.index.search(query_emb, top_k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.metadata):
                continue
            result = dict(self.metadata[idx])
            result["score"] = float(score)
            results.append(result)

        return results

    def query_to_text(self, text: str, top_k: int = 5) -> str:
        """Query and format results as text context for LLM."""
        results = self.query(text, top_k)
        if not results:
            return ""

        lines = []
        for r in results:
            tid = r.get("technique_id", "?")
            name = r.get("name", "?")
            preview = r.get("_text_preview", "")
            score = r.get("score", 0)
            lines.append(f"[{tid}] {name} (relevance: {score:.2f})\n{preview}")

        return "\n\n".join(lines)
