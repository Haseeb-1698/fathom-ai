import copy
import json
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = PROJECT_ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


@pytest.fixture
def minimal_cape_report():
    return {
        "info": {
            "id": 42,
            "package": "exe",
            "duration": 120,
            "machine": {"name": "win10-test"},
            "started": "2026-05-14T01:00:00Z",
            "ended": "2026-05-14T01:02:00Z",
        },
        "target": {
            "category": "file",
            "file": {
                "name": "sample.exe",
                "path": "C:/samples/sample.exe",
                "type": "PE32 executable",
                "md5": "md5-value",
                "sha1": "sha1-value",
                "sha256": "sha256-value",
                "sha512": "sha512-value",
            },
        },
        "behavior": {
            "processtree": [
                {
                    "name": "sample.exe",
                    "pid": 100,
                    "parent_id": 4,
                    "module_path": "C:/samples/sample.exe",
                    "environ": {"CommandLine": "sample.exe -run", "Bitness": "32-bit"},
                    "children": [
                        {
                            "name": "cmd.exe",
                            "pid": 101,
                            "parent_id": 100,
                            "module_path": "C:/Windows/System32/cmd.exe",
                            "environ": {"CommandLine": "cmd.exe /c whoami", "Bitness": "64-bit"},
                            "children": [],
                        }
                    ],
                }
            ],
            "summary": {
                "files": ["C:/Users/Public/a.tmp", "C:/Users/Public/a.tmp"],
                "read_keys": ["HKCU/Software/Test"],
                "write_keys": ["HKCU/Software/Microsoft/Windows/CurrentVersion/Run/Test"],
                "delete_keys": ["HKCU/Software/Old"],
                "mutexes": ["Global/TestMutex"],
                "executed_commands": ["cmd.exe /c whoami"],
            },
        },
        "network": {
            "hosts": [{"ip": "203.0.113.10", "hostname": "c2.example.test"}],
            "dns": [
                {
                    "request": "c2.example.test",
                    "type": "A",
                    "answers": [{"type": "A", "data": "203.0.113.10"}],
                }
            ],
            "http": [
                {
                    "host": "c2.example.test",
                    "uri": "/gate.php",
                    "method": "POST",
                    "user-agent": "UnitTestAgent/1.0",
                }
            ],
            "tcp": [{"src": "10.0.2.15", "sport": 49152, "dst": "203.0.113.10", "dport": 443}],
            "udp": [{"src": "10.0.2.15", "sport": 5353, "dst": "224.0.0.251", "dport": 5353}],
        },
        "dropped": [
            {
                "name": ["payload.bin"],
                "path": "C:/Users/Public/payload.bin",
                "guest_paths": ["C:/Users/Public/payload.bin"],
                "sha256": "dropped-sha256",
                "type": "PE32 executable",
                "size": 1234,
            }
        ],
        "procdump": [
            {
                "path": "C:/dumps/sample.dmp",
                "sha256": "dump-sha256",
                "process_name": "sample.exe",
                "process_path": "C:/samples/sample.exe",
                "cape_type": "process_dump",
            }
        ],
        "CAPE": {
            "payloads": [
                {
                    "path": "C:/payloads/unpacked.exe",
                    "sha256": "payload-sha256",
                    "process_name": "sample.exe",
                    "process_path": "C:/samples/sample.exe",
                    "cape_type": "unpacked",
                    "pid": 100,
                    "virtual_address": "0x401000",
                }
            ],
            "configs": [{"family": "UnitTest"}],
        },
        "signatures": [{"name": "unit_signature"}],
        "malscore": 10.0,
        "malstatus": "Malicious",
        "detections": [{"family": "UnitTest"}],
    }


@pytest.fixture
def cape_report_file(tmp_path, minimal_cape_report):
    report_path = tmp_path / "analyses" / "42" / "reports" / "report.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text(json.dumps(minimal_cape_report), encoding="utf-8")
    return report_path


@pytest.fixture
def report_copy(minimal_cape_report):
    return copy.deepcopy(minimal_cape_report)

