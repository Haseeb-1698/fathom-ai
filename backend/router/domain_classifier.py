"""
domain_classifier.py — Route queries to the correct expert domain.

Uses sentence-transformers embeddings + cosine similarity to 8 domain centroids.
Falls back to keyword matching if embeddings aren't available.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import numpy as np

from config import DOMAINS, EMBEDDING_MODEL_ID

CENTROID_PATH = Path(__file__).parent / "centroid_data.json"

# Lazy-loaded model
_embed_model = None


def _get_embed_model():
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer(EMBEDDING_MODEL_ID)
    return _embed_model


def embed_text(text: str) -> np.ndarray:
    """Embed a single text string."""
    model = _get_embed_model()
    return model.encode(text, normalize_embeddings=True)


def load_centroids() -> dict[str, np.ndarray]:
    """Load precomputed domain centroids from JSON."""
    if not CENTROID_PATH.exists():
        return {}

    with open(CENTROID_PATH, "r") as f:
        data = json.load(f)

    return {k: np.array(v) for k, v in data.items()}


def save_centroids(centroids: dict[str, np.ndarray]):
    """Save domain centroids to JSON."""
    data = {k: v.tolist() for k, v in centroids.items()}
    with open(CENTROID_PATH, "w") as f:
        json.dump(data, f)


def keyword_classify(text: str) -> tuple[str, float]:
    """Simple keyword-based classification as fallback."""
    text_lower = text.lower()
    scores = {}

    for domain_id, domain_def in DOMAINS.items():
        score = sum(1 for kw in domain_def["keywords"] if kw.lower() in text_lower)
        scores[domain_id] = score

    if not scores or max(scores.values()) == 0:
        return "E7_reports", 0.0  # default to report generation

    best = max(scores, key=scores.get)
    total = sum(scores.values()) or 1
    confidence = scores[best] / total
    return best, confidence


def classify(text: str, centroids: dict[str, np.ndarray] | None = None,
             threshold: float = 0.3) -> tuple[str, float, dict[str, float]]:
    """
    Classify text into one of 8 expert domains.

    Returns:
        (domain_id, confidence, all_scores)
    """
    # Try embedding-based classification first
    if centroids is None:
        centroids = load_centroids()

    if centroids:
        try:
            query_emb = embed_text(text)
            scores = {}
            for domain_id, centroid in centroids.items():
                similarity = float(np.dot(query_emb, centroid))
                scores[domain_id] = similarity

            best = max(scores, key=scores.get)
            confidence = scores[best]

            if confidence < threshold:
                # Below threshold → fall back to unified
                return best, confidence, scores

            return best, confidence, scores
        except Exception:
            pass  # fall through to keyword

    # Keyword fallback
    domain_id, confidence = keyword_classify(text)
    return domain_id, confidence, {domain_id: confidence}


class DomainRouter:
    """Stateful router with cached centroids."""

    def __init__(self):
        self.centroids = load_centroids()

    def route(self, text: str) -> tuple[str, float, dict[str, float]]:
        return classify(text, self.centroids)

    def get_adapter_name(self, domain_id: str) -> Optional[str]:
        """Return adapter name for a domain, or None if using unified."""
        domain = DOMAINS.get(domain_id, {})
        if domain.get("has_trained_adapter") and domain.get("adapter"):
            return domain["adapter"]
        return None  # use unified
