import os
import sys
from pathlib import Path

import pytest


SERVER_DIR = os.path.join(os.path.dirname(__file__), "..", "server")
sys.path.insert(0, SERVER_DIR)

from dynamic.loader import collect_cape_report, resolve_cape_report_path
from dynamic.normalizer import normalize_dynamic_analysis
from dynamic.parser import parse_cape_dynamic_report


DEFAULT_CAPE_REPORT = Path(
    os.environ.get(
        "FATHOM_TEST_CAPE_REPORT",
        "<CAPEv2_ROOT>/storage/analyses/15/reports/report.json",
    )
)


@pytest.mark.skipif(not DEFAULT_CAPE_REPORT.exists(), reason="CAPE validation report not available")
class TestDynamicPipeline:
    def test_loader_resolves_report_from_direct_path(self):
        path = resolve_cape_report_path(report_path=DEFAULT_CAPE_REPORT)
        assert path == DEFAULT_CAPE_REPORT.resolve()

    def test_loader_collects_report_bundle(self):
        bundle = collect_cape_report(report_path=DEFAULT_CAPE_REPORT)
        assert bundle["task_id"] == 15
        assert bundle["report_path"].endswith("report.json")
        assert isinstance(bundle["report"], dict)
        assert "behavior" in bundle["report"]

    def test_parser_extracts_required_categories(self):
        bundle = collect_cape_report(report_path=DEFAULT_CAPE_REPORT)
        parsed = parse_cape_dynamic_report(bundle["report"])

        assert parsed["analysis_id"] == 15
        assert parsed["file_type"] in {"pe", "dll"}
        assert parsed["submission_mode"] == "manual_cape"
        assert len(parsed["process_activity"]) >= 1
        assert len(parsed["file_activity"]) >= 1
        assert len(parsed["registry_activity"]) >= 1
        assert len(parsed["network_activity"]) >= 1
        assert len(parsed["iocs"]) >= 1

    def test_normalizer_stabilizes_schema(self):
        bundle = collect_cape_report(report_path=DEFAULT_CAPE_REPORT)
        parsed = parse_cape_dynamic_report(bundle["report"])
        normalized = normalize_dynamic_analysis(parsed, report_path=bundle["report_path"])

        required_fields = {
            "analysis_id",
            "file_name",
            "file_type",
            "submission_mode",
            "cape_task_id",
            "sandbox_status",
            "execution_profile",
            "process_activity",
            "file_activity",
            "registry_activity",
            "network_activity",
            "iocs",
            "mitre_mapping",
            "risk_score",
            "verdict",
        }
        assert required_fields.issubset(normalized.keys())
        assert normalized["analysis_id"] == 15
        assert normalized["cape_task_id"] == 15
        assert isinstance(normalized["process_activity"], list)
        assert isinstance(normalized["file_activity"], list)
        assert isinstance(normalized["registry_activity"], list)
        assert isinstance(normalized["network_activity"], list)
        assert isinstance(normalized["iocs"], list)
