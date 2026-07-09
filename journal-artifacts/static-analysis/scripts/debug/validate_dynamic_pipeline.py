#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = ROOT / "server"
sys.path.insert(0, str(SERVER_DIR))

from dynamic.loader import collect_cape_report
from dynamic.normalizer import normalize_dynamic_analysis
from dynamic.parser import parse_cape_dynamic_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Fathom dynamic Tasks 8-10 against a CAPE report.")
    parser.add_argument("--task-id", type=int, help="CAPE task id under CAPEv2/storage/analyses/<id>/reports/report.json")
    parser.add_argument("--report-path", help="Direct path to a CAPE report.json")
    parser.add_argument("--summary-only", action="store_true", help="Print a compact summary instead of full normalized JSON")
    args = parser.parse_args()

    bundle = collect_cape_report(task_id=args.task_id, report_path=args.report_path)
    parsed = parse_cape_dynamic_report(bundle["report"])
    normalized = normalize_dynamic_analysis(parsed, report_path=bundle["report_path"])

    if args.summary_only:
        output = {
            "analysis_id": normalized["analysis_id"],
            "file_name": normalized["file_name"],
            "file_type": normalized["file_type"],
            "sandbox_status": normalized["sandbox_status"],
            "execution_profile": normalized["execution_profile"],
            "counts": {
                "process_activity": len(normalized["process_activity"]),
                "file_activity": len(normalized["file_activity"]),
                "registry_activity": len(normalized["registry_activity"]),
                "network_activity": len(normalized["network_activity"]),
                "iocs": len(normalized["iocs"]),
            },
            "verdict": normalized["verdict"],
        }
    else:
        output = normalized

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
