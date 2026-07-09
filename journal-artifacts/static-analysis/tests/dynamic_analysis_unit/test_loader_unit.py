import json

import pytest

from dynamic.loader import collect_cape_report, resolve_cape_report_path


def test_resolve_direct_report_path(cape_report_file):
    assert resolve_cape_report_path(report_path=cape_report_file) == cape_report_file.resolve()


def test_resolve_task_id_from_custom_analyses_root(cape_report_file):
    analyses_root = cape_report_file.parents[2]

    resolved = resolve_cape_report_path(task_id=42, analyses_root=analyses_root)

    assert resolved == cape_report_file.resolve()


def test_resolve_requires_task_id_or_report_path():
    with pytest.raises(ValueError, match="Either task_id or report_path"):
        resolve_cape_report_path()


def test_resolve_missing_direct_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="does not exist"):
        resolve_cape_report_path(report_path=tmp_path / "missing.json")


def test_resolve_missing_task_report_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="CAPE report for task 99"):
        resolve_cape_report_path(task_id=99, analyses_root=tmp_path)


def test_collect_report_returns_provenance(cape_report_file):
    bundle = collect_cape_report(report_path=cape_report_file)

    assert bundle["task_id"] == 42
    assert bundle["report_path"] == str(cape_report_file.resolve())
    assert bundle["analysis_path"] == str(cape_report_file.parents[1].resolve())
    assert bundle["report"]["target"]["file"]["name"] == "sample.exe"


def test_collect_report_rejects_missing_required_sections(tmp_path, minimal_cape_report):
    del minimal_cape_report["behavior"]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(minimal_cape_report), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required section"):
        collect_cape_report(report_path=path)


def test_collect_report_surfaces_invalid_json(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        collect_cape_report(report_path=path)

