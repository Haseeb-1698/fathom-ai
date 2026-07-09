import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import cape_integration as cape


def test_dynamic_state_roundtrip_uses_atomic_json(monkeypatch, tmp_path):
    monkeypatch.setattr(cape, "OUT", tmp_path)

    state = cape.create_dynamic_state(
        "a" * 64,
        tmp_path / "sample.exe",
        filename="sample.exe",
        callback_url="http://callback.test/hook",
    )
    state["status"] = "completed"
    cape.save_dynamic_state(state)

    loaded = cape.load_dynamic_state("a" * 64)
    assert loaded["status"] == "completed"
    assert loaded["filename"] == "sample.exe"
    assert loaded["callback_url"] == "http://callback.test/hook"
    assert loaded["updated_at"].endswith("Z")


def test_load_dynamic_state_missing_returns_placeholder(monkeypatch, tmp_path):
    monkeypatch.setattr(cape, "OUT", tmp_path)

    state = cape.load_dynamic_state("missing-sha")

    assert state["sha256"] == "missing-sha"
    assert state["status"] == "missing"
    assert "not been started" in state["error"]


def test_summarize_cape_report_counts_core_sections(minimal_cape_report):
    summary = cape.summarize_cape_report(minimal_cape_report)

    assert summary["task_id"] == 42
    assert summary["target_file"] == "sample.exe"
    assert summary["malscore"] == 10.0
    assert summary["malstatus"] == "Malicious"
    assert summary["signatures_count"] == 1
    assert summary["network_hosts_count"] == 1
    assert summary["dns_count"] == 1
    assert summary["http_count"] == 1
    assert summary["tcp_count"] == 1
    assert summary["udp_count"] == 1
    assert summary["dropped_count"] == 1
    assert summary["cape_payload_count"] == 1
    assert summary["cape_config_count"] == 1


def test_find_cape_reports_discovers_json_and_html(monkeypatch, tmp_path):
    analyses = tmp_path / "analyses"
    reports = analyses / "123" / "reports"
    reports.mkdir(parents=True)
    (reports / "report.json").write_text("{}", encoding="utf-8")
    (reports / "kspn_report.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setattr(cape, "CAPE_ANALYSES", analyses)

    found = cape.find_cape_reports(123)

    assert found["analysis_dir"] == analyses / "123"
    assert found["json"] == reports / "report.json"
    assert found["html"] == reports / "kspn_report.html"


def test_safe_cape_report_path_rejects_paths_outside_analysis_root(monkeypatch, tmp_path):
    analyses = tmp_path / "analyses"
    safe_path = analyses / "1" / "reports" / "report.json"
    unsafe_path = tmp_path / "outside" / "report.json"
    safe_path.parent.mkdir(parents=True)
    unsafe_path.parent.mkdir()
    safe_path.write_text("{}", encoding="utf-8")
    unsafe_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cape, "CAPE_ANALYSES", analyses)

    assert cape.is_safe_cape_report_path(safe_path)
    assert not cape.is_safe_cape_report_path(unsafe_path)


def test_report_matches_hash_checks_target_and_artifact_hashes(report_copy):
    assert cape.report_matches_hash(report_copy, "sha256-value")
    assert cape.report_matches_hash(report_copy, "payload-sha256")
    assert cape.report_matches_hash(report_copy, "dropped-sha256")
    assert not cape.report_matches_hash(report_copy, "not-present")


def test_lookup_cape_analysis_by_task_id(monkeypatch, tmp_path, minimal_cape_report):
    analyses = tmp_path / "analyses"
    reports = analyses / "42" / "reports"
    reports.mkdir(parents=True)
    report_path = reports / "report.json"
    report_path.write_text(json.dumps(minimal_cape_report), encoding="utf-8")
    monkeypatch.setattr(cape, "CAPE_ANALYSES", analyses)

    result = cape.lookup_cape_analysis("42")

    assert result["state"]["status"] == "completed"
    assert result["state"]["cape_task_id"] == 42
    assert result["state"]["summary"]["target_file"] == "sample.exe"
    assert result["html_url"] is None


def test_lookup_cape_analysis_by_hash(monkeypatch, tmp_path, minimal_cape_report):
    analyses = tmp_path / "analyses"
    reports = analyses / "42" / "reports"
    reports.mkdir(parents=True)
    (reports / "report.json").write_text(json.dumps(minimal_cape_report), encoding="utf-8")
    monkeypatch.setattr(cape, "CAPE_ANALYSES", analyses)

    result = cape.lookup_cape_analysis("sha256-value")

    assert result["state"]["lookup"] == {"type": "hash", "query": "sha256-value"}
    assert result["report"]["target"]["file"]["sha256"] == "sha256-value"


def test_lookup_cape_analysis_rejects_blank_query():
    with pytest.raises(FileNotFoundError, match="Provide a CAPE analysis number"):
        cape.lookup_cape_analysis("   ")


def test_submit_to_cape_builds_archive_command_and_parses_task_id(monkeypatch, tmp_path):
    cape_root = tmp_path / "cape"
    cape_python = cape_root / "venv" / "bin" / "python3"
    cape_submit = cape_root / "utils" / "submit.py"
    sample = tmp_path / "sample.zip"
    cape_python.parent.mkdir(parents=True)
    cape_submit.parent.mkdir(parents=True)
    cape_python.write_text("#!/bin/sh\n", encoding="utf-8")
    cape_submit.write_text("# submit", encoding="utf-8")
    sample.write_bytes(b"PK")
    monkeypatch.setattr(cape, "CAPE_ROOT", cape_root)
    monkeypatch.setattr(cape, "CAPE_PYTHON", cape_python)
    monkeypatch.setattr(cape, "CAPE_SUBMIT", cape_submit)
    monkeypatch.setattr(cape, "CAPE_ARCHIVE_PASSWORD", "infected")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="Success: task with ID 777", stderr="")

    monkeypatch.setattr(cape.subprocess, "run", fake_run)

    assert cape.submit_to_cape(sample) == 777
    command = calls[0][0]
    assert command[:2] == [str(cape_python), str(cape_submit)]
    assert "--package" in command
    assert "archive" in command
    assert "--options" in command
    assert "password=infected" in command
    assert str(sample) == command[-1]


def test_submit_to_cape_surfaces_submit_failure(monkeypatch, tmp_path):
    cape_root = tmp_path / "cape"
    cape_python = cape_root / "venv" / "bin" / "python3"
    cape_submit = cape_root / "utils" / "submit.py"
    sample = tmp_path / "sample.exe"
    cape_python.parent.mkdir(parents=True)
    cape_submit.parent.mkdir(parents=True)
    cape_python.write_text("#!/bin/sh\n", encoding="utf-8")
    cape_submit.write_text("# submit", encoding="utf-8")
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(cape, "CAPE_ROOT", cape_root)
    monkeypatch.setattr(cape, "CAPE_PYTHON", cape_python)
    monkeypatch.setattr(cape, "CAPE_SUBMIT", cape_submit)
    monkeypatch.setattr(
        cape.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="submit failed"),
    )

    with pytest.raises(RuntimeError, match="submit failed"):
        cape.submit_to_cape(sample)


def test_post_callback_no_url_and_invalid_url_do_not_perform_network():
    assert cape.post_analysis_callback(None, "event", "sha", {}) == {"enabled": False, "event": "event"}

    result = cape.post_analysis_callback("ftp://callback", "event", "sha", {})
    assert result["enabled"] is True
    assert result["status"] == "failed"
    assert "http://" in result["error"]


def test_run_dynamic_analysis_completes_when_report_is_found(monkeypatch, tmp_path, minimal_cape_report):
    monkeypatch.setattr(cape, "OUT", tmp_path / "out")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    report_path = tmp_path / "analyses" / "321" / "reports" / "report.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text(json.dumps(minimal_cape_report), encoding="utf-8")
    cape.create_dynamic_state("b" * 64, sample, "sample.exe")
    monkeypatch.setattr(cape, "submit_to_cape", lambda path: 321)
    monkeypatch.setattr(
        cape,
        "find_cape_reports",
        lambda task_id: {
            "analysis_dir": report_path.parents[1],
            "json": report_path,
            "html": None,
        },
    )
    monkeypatch.setattr(cape, "post_analysis_callback", lambda *args, **kwargs: {"enabled": False, "event": args[1]})

    cape.run_dynamic_analysis("b" * 64, str(sample), "sample.exe")

    state = cape.load_dynamic_state("b" * 64)
    assert state["status"] == "completed"
    assert state["cape_task_id"] == 321
    assert state["report_json_available"] is True
    assert state["summary"]["target_file"] == "sample.exe"


def test_run_dynamic_analysis_records_submit_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(cape, "OUT", tmp_path / "out")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    cape.create_dynamic_state("c" * 64, sample, "sample.exe")
    monkeypatch.setattr(cape, "submit_to_cape", lambda path: (_ for _ in ()).throw(RuntimeError("submit boom")))
    monkeypatch.setattr(cape, "post_analysis_callback", lambda *args, **kwargs: {"enabled": False, "event": args[1]})

    cape.run_dynamic_analysis("c" * 64, str(sample), "sample.exe")

    state = cape.load_dynamic_state("c" * 64)
    assert state["status"] == "failed"
    assert "submit boom" in state["error"]

