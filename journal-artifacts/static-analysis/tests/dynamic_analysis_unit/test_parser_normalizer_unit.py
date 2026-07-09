import pytest

from dynamic.normalizer import normalize_dynamic_analysis
from dynamic.parser import parse_cape_dynamic_report


@pytest.mark.parametrize(
    ("target_type", "package", "expected"),
    [
        ("PE32 executable", "exe", "pe"),
        ("PE32 executable (DLL)", "dll", "dll"),
        ("PDF document", "", "pdf"),
        ("HTML document", "", "html"),
        ("Microsoft Word 2007+", "", "office"),
        ("Unknown", "archive", "archive"),
        ("Unknown", "", "unknown"),
    ],
)
def test_file_type_inference(report_copy, target_type, package, expected):
    report_copy["target"]["file"]["type"] = target_type
    report_copy["info"]["package"] = package

    parsed = parse_cape_dynamic_report(report_copy)

    assert parsed["file_type"] == expected


def test_parser_extracts_process_tree_and_parent_context(report_copy):
    parsed = parse_cape_dynamic_report(report_copy)

    assert parsed["analysis_id"] == 42
    assert parsed["sandbox_status"] == "completed"
    assert parsed["execution_profile"] == "exe"
    assert parsed["process_activity"][0]["name"] == "sample.exe"
    assert parsed["process_activity"][0]["child_count"] == 1
    assert parsed["process_activity"][1]["name"] == "cmd.exe"
    assert parsed["process_activity"][1]["parent_name"] == "sample.exe"
    assert parsed["process_activity"][1]["command_line"] == "cmd.exe /c whoami"


def test_parser_marks_timeout_when_cape_info_times_out(report_copy):
    report_copy["info"]["timeout"] = True

    parsed = parse_cape_dynamic_report(report_copy)

    assert parsed["sandbox_status"] == "timeout"


def test_parser_extracts_file_registry_network_and_iocs(report_copy):
    parsed = parse_cape_dynamic_report(report_copy)

    file_kinds = {item["kind"] for item in parsed["file_activity"]}
    registry_ops = {item["operation"] for item in parsed["registry_activity"]}
    network_protocols = {item["protocol"] for item in parsed["network_activity"]}
    ioc_pairs = {(item["type"], item["value"]) for item in parsed["iocs"]}

    assert {"observed_path", "dropped_file", "procdump", "cape_payload"}.issubset(file_kinds)
    assert registry_ops == {"read", "write", "delete"}
    assert {"dns", "http", "tcp", "udp"}.issubset(network_protocols)
    assert ("sha256", "sha256-value") in ioc_pairs
    assert ("ip", "203.0.113.10") in ioc_pairs
    assert ("domain", "c2.example.test") in ioc_pairs
    assert ("mutex", "Global/TestMutex") in ioc_pairs
    assert ("command", "cmd.exe /c whoami") in ioc_pairs


def test_parser_deduplicates_repeated_activity(report_copy):
    report_copy["network"]["http"].append(dict(report_copy["network"]["http"][0]))

    parsed = parse_cape_dynamic_report(report_copy)

    observed_paths = [
        item for item in parsed["file_activity"] if item["kind"] == "observed_path" and item["path"] == "C:/Users/Public/a.tmp"
    ]
    http_events = [item for item in parsed["network_activity"] if item["protocol"] == "http"]
    assert len(observed_paths) == 1
    assert len(http_events) == 1


def test_parser_tolerates_malformed_optional_sections(report_copy):
    report_copy["behavior"]["processtree"] = "not-a-list"
    report_copy["behavior"]["summary"]["files"] = "not-a-list"
    report_copy["network"]["dns"] = {"not": "a-list"}
    report_copy["dropped"] = "not-a-list"
    report_copy["procdump"] = None
    report_copy["CAPE"]["payloads"] = "not-a-list"

    parsed = parse_cape_dynamic_report(report_copy)

    assert parsed["process_activity"] == []
    assert parsed["file_activity"] == []
    assert parsed["network_activity"]
    assert all(item["protocol"] != "dns" for item in parsed["network_activity"])


@pytest.mark.parametrize(
    ("process_count", "file_count", "registry_count", "network_count", "expected"),
    [
        (1, 1, 1, 1, "observed"),
        (5, 5, 3, 2, "review"),
        (20, 20, 5, 5, "suspicious"),
    ],
)
def test_normalizer_verdict_thresholds(process_count, file_count, registry_count, network_count, expected):
    parsed = {
        "analysis_id": 7,
        "file_name": "sample.exe",
        "file_type": "pe",
        "cape_task_id": 7,
        "process_activity": [{"i": i} for i in range(process_count)],
        "file_activity": [{"i": i} for i in range(file_count)],
        "registry_activity": [{"i": i} for i in range(registry_count)],
        "network_activity": [{"i": i} for i in range(network_count)],
    }

    normalized = normalize_dynamic_analysis(parsed, report_path="/tmp/report.json")

    assert normalized["verdict"] == expected
    assert normalized["source"] == {
        "engine": "cape",
        "report_path": "/tmp/report.json",
        "submission_mode": "manual_cape",
    }
    assert normalized["mitre_mapping"] == []
    assert normalized["risk_score"] is None


def test_normalizer_keeps_schema_stable_when_lists_are_missing():
    normalized = normalize_dynamic_analysis({"analysis_id": 1})

    for key in ("process_activity", "file_activity", "registry_activity", "network_activity", "iocs"):
        assert normalized[key] == []
    assert normalized["sandbox_status"] == "unknown"
    assert normalized["execution_profile"] == "unknown"
    assert normalized["verdict"] == "observed"

