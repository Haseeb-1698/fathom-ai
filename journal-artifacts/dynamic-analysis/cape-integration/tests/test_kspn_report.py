import json
import sys
from pathlib import Path
from types import SimpleNamespace

import utils.kspn_report as kspn_report
from modules.reporting.kspnreport import Kspnreport


def test_reporting_module_invokes_generator_with_expected_flags(monkeypatch):
    calls = {}

    def fake_run(command, cwd, capture_output, text, check):
        calls["command"] = command
        calls["cwd"] = cwd
        calls["capture_output"] = capture_output
        calls["text"] = text
        calls["check"] = check
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("modules.reporting.kspnreport.subprocess.run", fake_run)

    reporter = Kspnreport()
    reporter.set_task({"id": 42})
    reporter.set_options(
        {
            "analyst": "Analyst One",
            "org": "KSPN",
            "all_artifacts": True,
            "json_summary": True,
            "html": False,
        }
    )

    reporter.run({})

    assert calls["cwd"] == kspn_report.ROOT.as_posix()
    assert calls["capture_output"] is True
    assert calls["text"] is True
    assert calls["check"] is False
    assert calls["command"] == [
        sys.executable,
        str(kspn_report.ROOT / "utils" / "kspn_report.py"),
        "--id",
        "42",
        "--analyst",
        "Analyst One",
        "--org",
        "KSPN",
        "--all-artifacts",
        "--json-summary",
        "--no-html",
    ]


def test_main_generates_markdown_html_and_summary_for_minimal_analysis(tmp_path, monkeypatch):
    analysis_id = 77
    root = tmp_path
    analysis_dir = root / "storage" / "analyses" / str(analysis_id)
    reports_dir = analysis_dir / "reports"
    reports_dir.mkdir(parents=True)

    report = {
        "info": {"category": "file", "package": "exe", "route": "inetsim"},
        "target": {
            "file": {
                "name": "sample.exe",
                "path": "C:\\Temp\\sample.exe",
                "size": 123456,
                "type": "PE32 executable",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "1111111111111111111111111111111111111111",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha512": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "strings": ["AgentTesla", "Opera Stable", "Login Data"],
                "yara": [{"name": "AgentTesla"}],
                "pe": {"imports": {}, "sections": [], "guest_signers": {}},
            }
        },
        "behavior": {
            "summary": {
                "files": [r"C:\Users\user\AppData\Roaming\Opera Software\Opera Stable\Login Data"],
                "write_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BadValue"],
                "read_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer"],
                "delete_keys": [],
                "mutexes": ["Global\\BadMutex"],
            },
            "processes": [
                {
                    "process_name": "powershell.exe",
                    "process_id": 31337,
                    "module_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                }
            ],
            "processtree": [{"name": "powershell.exe", "pid": 31337, "children": []}],
        },
        "network": {
            "hosts": [{"ip": "8.8.8.8"}],
            "domains": [{"domain": "bad.example"}],
            "http": [{"uri": "http://bad.example/submit"}],
            "udp": [{"dport": 53}],
            "dns": [{"request": "bad.example"}],
            "smtp": [],
        },
        "CAPE": {
            "payloads": [
                {
                    "name": "payload.bin",
                    "cape_type": "extracted_pe",
                    "size": 128,
                    "path": r"C:\Temp\payload.bin",
                    "cape_yara": [{"name": "AgentTesla"}],
                }
            ]
        },
        "signatures": [{"name": "agenttesla"}],
        "dropped": [{"name": "dropped.dat", "path": r"C:\Temp\dropped.dat"}],
        "procdump": [],
        "procmemory": [],
        "statistics": {},
    }
    (reports_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (analysis_dir / "analysis.log").write_text("route=inetsim", encoding="utf-8")
    (analysis_dir / "cuckoo.log").write_text("using inetsim route", encoding="utf-8")
    (analysis_dir / "dump.pcap").write_bytes(b"pcap")

    output_path = root / "custom" / "reports" / "case-77.md"
    monkeypatch.setattr(kspn_report, "ROOT", root)
    monkeypatch.setattr(kspn_report, "ANALYSES_DIR", root / "storage" / "analyses")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kspn_report.py",
            "--id",
            str(analysis_id),
            "--output",
            str(output_path),
            "--analyst",
            "Case Analyst",
            "--org",
            "Example Org",
            "--json-summary",
        ],
    )

    rc = kspn_report.main()

    assert rc == 0
    assert output_path.exists()
    assert output_path.with_suffix(".html").exists()
    assert output_path.with_name("case-77_summary.json").exists()

    markdown = output_path.read_text(encoding="utf-8")
    summary = json.loads(output_path.with_name("case-77_summary.json").read_text(encoding="utf-8"))

    assert "Example Org Malware Analysis Report - Analysis #77" in markdown
    assert "Credential theft / infostealer" in markdown
    assert summary["analysis_id"] == analysis_id
    assert summary["family_guess"] == "AgentTesla"
    assert summary["risk_rating"] in {"Medium", "High"}
