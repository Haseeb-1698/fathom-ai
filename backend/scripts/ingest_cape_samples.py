#!/usr/bin/env python3
"""
ingest_cape_samples.py — Ingest CAPE JSON reports into Neo4j graph.

Usage: python scripts/ingest_cape_samples.py --reports-dir path/to/cape/reports/
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evidence.cape_extractor import extract_from_cape_json
from graph.neo4j_client import Neo4jClient
from graph.ingest_cape import ingest_evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", type=str, required=True,
                        help="Directory containing CAPE JSON report files")
    parser.add_argument("--init-schema", action="store_true",
                        help="Initialize Neo4j schema before ingestion")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    if not reports_dir.exists():
        print(f"Error: {reports_dir} does not exist")
        sys.exit(1)

    client = Neo4jClient()

    if args.init_schema:
        print("Initializing Neo4j schema...")
        client.init_schema()

    report_files = list(reports_dir.glob("*.json"))
    print(f"Found {len(report_files)} CAPE reports to ingest")

    for i, report_path in enumerate(report_files, 1):
        print(f"[{i}/{len(report_files)}] Ingesting {report_path.name}...")
        try:
            brief = extract_from_cape_json(report_path)
            ingest_evidence(client, brief)
            family = brief.detections[0]["family"] if brief.detections else "unknown"
            print(f"  OK: {brief.file_name} ({family})")
        except Exception as e:
            print(f"  ERROR: {e}")

    print(f"\nIngested {len(report_files)} reports into Neo4j")
    client.close()


if __name__ == "__main__":
    main()
