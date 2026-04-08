"""
conftest.py — Shared pytest fixtures for Fathom backend tests.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure backend/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Minimal CAPE report fixtures ─────────────────────────────────────────────

@pytest.fixture
def minimal_cape_report():
    """Bare-minimum CAPE report — only required top-level keys."""
    return {"info": {"id": 1}, "behavior": {}}


@pytest.fixture
def basic_cape_report():
    """CAPE report with common fields populated."""
    return {
        "info": {"id": 42, "score": 7.5, "duration": 120},
        "target": {
            "file": {
                "name": "malware.exe",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "size": 102400,
                "type": "PE32",
            }
        },
        "signatures": [
            {"name": "injection", "description": "Process injection detected", "severity": 3,
             "ttps": [{"ttp": "T1055"}]},
            {"name": "persistence", "description": "Registry run key", "severity": 2,
             "ttps": [{"ttp": "T1547.001"}]},
        ],
        "behavior": {
            "processes": [
                {
                    "process_name": "malware.exe",
                    "process_id": 1234,
                    "parent_id": 4,
                    "calls": [
                        {"api": "NtCreateProcess", "status": 1, "arguments": []},
                        {"api": "WriteProcessMemory", "status": 1, "arguments": []},
                        {"api": "CreateRemoteThread", "status": 1, "arguments": []},
                    ],
                }
            ]
        },
        "network": {
            "hosts": ["185.1.2.3", "10.0.0.1"],
            "domains": [{"domain": "evil.example.com", "ip": "185.1.2.3"}],
            "http": [],
            "dns": [],
        },
        "strings": ["http://evil.example.com/payload", "cmd.exe", "powershell"],
    }


@pytest.fixture
def large_cape_report(basic_cape_report):
    """CAPE report with 500+ IOCs and 200+ behaviors to test cap enforcement."""
    report = dict(basic_cape_report)
    # Inflate network hosts to 500+
    report["network"] = {
        "hosts": [f"10.0.{i // 256}.{i % 256}" for i in range(600)],
        "domains": [{"domain": f"evil{i}.example.com"} for i in range(300)],
        "http": [],
        "dns": [],
    }
    # Inflate signatures to 200+
    report["signatures"] = [
        {"name": f"sig_{i}", "description": f"Behavior {i}", "severity": 2, "ttps": []}
        for i in range(250)
    ]
    return report


@pytest.fixture
def duplicate_ioc_report(basic_cape_report):
    """CAPE report with duplicate IOC entries."""
    report = dict(basic_cape_report)
    report["network"] = {
        "hosts": ["185.1.2.3", "185.1.2.3", "185.1.2.3"],  # tripled
        "domains": [
            {"domain": "evil.example.com"},
            {"domain": "evil.example.com"},
        ],
        "http": [],
        "dns": [],
    }
    return report
