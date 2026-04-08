#!/usr/bin/env python3
"""
build_faiss_index.py — Build FAISS index from ATT&CK KB.

Usage: python scripts/build_faiss_index.py [--stix-path path/to/enterprise-attack.json]
"""

import argparse
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rag.attack_kb import load_attack_kb
from rag.indexer import build_index


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stix-path", type=str, default=None)
    parser.add_argument("--index-name", type=str, default="attack_kb")
    args = parser.parse_args()

    print("Loading ATT&CK knowledge base...")
    techniques = load_attack_kb(args.stix_path)
    print(f"Parsed {len(techniques)} techniques")

    print("Building FAISS index...")
    index_dir = build_index(techniques, text_key="text", index_name=args.index_name)
    print(f"Done! Index at: {index_dir}")


if __name__ == "__main__":
    main()
