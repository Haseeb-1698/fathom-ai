#!/usr/bin/env python3
"""
build_centroids.py — Build domain centroids for the expert router.

Classifies training JSONL by keyword patterns, embeds each domain's examples,
averages to produce centroid vectors, and saves to router/centroid_data.json.

Usage: python scripts/build_centroids.py --train-file path/to/train.jsonl
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import DOMAINS
from router.domain_classifier import embed_text, save_centroids


def classify_by_keywords(text: str) -> str:
    """Assign a text to a domain based on keyword overlap."""
    text_lower = text.lower()
    best_domain = "E7_reports"
    best_score = 0

    for domain_id, domain_def in DOMAINS.items():
        score = sum(1 for kw in domain_def["keywords"] if kw.lower() in text_lower)
        if score > best_score:
            best_score = score
            best_domain = domain_id

    return best_domain


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-file", type=str, required=True)
    parser.add_argument("--max-per-domain", type=int, default=500,
                        help="Max examples per domain to embed (for speed)")
    args = parser.parse_args()

    print(f"Reading {args.train_file}...")
    domain_texts = defaultdict(list)

    skipped = 0
    with open(args.train_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line.strip())
            except json.JSONDecodeError:
                skipped += 1
                continue
            text = row.get("instruction", "") + " " + row.get("input", "")
            domain = classify_by_keywords(text)
            if len(domain_texts[domain]) < args.max_per_domain:
                domain_texts[domain].append(text)
    if skipped:
        print(f"  Skipped {skipped} malformed lines")

    print(f"Domain distribution:")
    for d, texts in sorted(domain_texts.items()):
        print(f"  {d}: {len(texts)} examples")

    print("\nEmbedding domain texts...")
    centroids = {}
    for domain_id, texts in domain_texts.items():
        if not texts:
            continue
        embeddings = [embed_text(t) for t in texts]
        centroid = np.mean(embeddings, axis=0)
        centroid = centroid / np.linalg.norm(centroid)  # normalize
        centroids[domain_id] = centroid
        print(f"  {domain_id}: centroid from {len(texts)} examples")

    save_centroids(centroids)
    print(f"\nSaved {len(centroids)} centroids to centroid_data.json")


if __name__ == "__main__":
    main()
