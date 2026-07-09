import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from detector import pe_full

try:
    from server.app import app, OUT, QUAR
    _APP_AVAILABLE = True
except ModuleNotFoundError:
    app = OUT = QUAR = None
    _APP_AVAILABLE = False

try:
    from fastapi.testclient import TestClient
    _FASTAPI_AVAILABLE = True
except ModuleNotFoundError:
    TestClient = None
    _FASTAPI_AVAILABLE = False


def build_fake_pefile_module(state):
    directory_entry = {
        "IMAGE_DIRECTORY_ENTRY_IMPORT": 1,
        "IMAGE_DIRECTORY_ENTRY_EXPORT": 2,
        "IMAGE_DIRECTORY_ENTRY_RESOURCE": 3,
        "IMAGE_DIRECTORY_ENTRY_TLS": 4,
        "IMAGE_DIRECTORY_ENTRY_SECURITY": 5,
    }

    class FakeSection:
        def __init__(self, name, virtual_size, raw_size, virtual_address, raw_pointer, data, characteristics=0x60000020):
            padded = name.encode("latin-1", errors="ignore")[:8]
            self.Name = padded + b"\x00" * (8 - len(padded))
            self.Misc_VirtualSize = virtual_size
            self.SizeOfRawData = raw_size
            self.VirtualAddress = virtual_address
            self.PointerToRawData = raw_pointer
            self.Characteristics = characteristics
            self._data = data

        def get_data(self):
            return self._data

        def get_entropy(self):
            return pe_full.shannon_entropy(self._data)

    class FakeImportEntry:
        def __init__(self, dll, functions):
            self.dll = dll.encode("latin-1", errors="ignore")
            self.imports = []
            for func in functions:
                if func.startswith("ord_"):
                    self.imports.append(SimpleNamespace(name=None, ordinal=int(func.split("_", 1)[1])))
                else:
                    self.imports.append(SimpleNamespace(name=func.encode("latin-1"), ordinal=None))

    class FakeExportSymbol:
        def __init__(self, name=None, ordinal=None, rva=None):
            self.name = name.encode("latin-1") if name else None
            self.ordinal = ordinal
            self.address = rva

    class FakePE:
        def __init__(self, data=None, fast_load=False):
            if isinstance(data, (bytes, bytearray)):
                raw = bytes(data)
            elif isinstance(data, str):
                raw = Path(data).read_bytes()
            else:
                raw = b""
            self._raw = raw
            self.fast_load = fast_load
            self.sections = [
                FakeSection(**section)
                for section in state["sections"]
            ]
            self.FILE_HEADER = SimpleNamespace(
                Machine=state["machine"],
                TimeDateStamp=state["timestamp"],
                Characteristics=state["characteristics"],
                NumberOfSections=len(state["sections"]),
            )
            self.OPTIONAL_HEADER = SimpleNamespace(
                Magic=state["magic"],
                AddressOfEntryPoint=state["entry_rva"],
                ImageBase=state["image_base"],
                CheckSum=state["checksum"],
            )
            if state["imports"]:
                self.DIRECTORY_ENTRY_IMPORT = [
                    FakeImportEntry(**imp) for imp in state["imports"]
                ]
            if state["exports"]:
                self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(
                    symbols=[FakeExportSymbol(**ex) for ex in state["exports"]]
                )
            if state["resources"]:
                self.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(entries=[])
            if state["tls_callbacks"]:
                self.DIRECTORY_ENTRY_TLS = SimpleNamespace(callbacks=state["tls_callbacks"])

        def parse_data_directories(self, directories):
            return

        def is_dll(self):
            return state.get("is_dll", False)

        def is_exe(self):
            return not state.get("is_dll", False)

        def generate_checksum(self):
            return state["calc_checksum"]

        def get_offset_from_rva(self, rva):
            return state["entry_offset"] + (rva - state["entry_rva"])

    module = SimpleNamespace(
        OPTIONAL_HEADER_MAGIC_PE=0x10B,
        OPTIONAL_HEADER_MAGIC_PE_PLUS=0x20B,
        DIRECTORY_ENTRY=directory_entry,
        PE=FakePE,
    )
    return module


@pytest.fixture
def fake_state():
    return {
        "machine": 0x014C,
        "timestamp": 1_600_000_000,
        "characteristics": 0x2102,
        "magic": 0x10B,
        "entry_rva": 0x1000,
        "entry_offset": 0x200,
        "image_base": 0x400000,
        "checksum": 0x12345678,
        "calc_checksum": 0x12345678,
        "sections": [],
        "imports": [],
        "exports": [],
        "resources": [],
        "tls_callbacks": [],
        "is_dll": False,
    }


@pytest.fixture
def fake_environment(monkeypatch, fake_state):
    module = build_fake_pefile_module(fake_state)
    monkeypatch.setattr(pe_full, "pefile", module, raising=False)
    monkeypatch.setattr(pe_full, "Cs", None, raising=False)
    monkeypatch.setattr(pe_full, "CS_ARCH_X86", None, raising=False)
    monkeypatch.setattr(pe_full, "CS_MODE_32", None, raising=False)
    monkeypatch.setattr(pe_full, "CS_MODE_64", None, raising=False)
    monkeypatch.setattr(pe_full, "yara", None, raising=False)
    monkeypatch.setattr(
        pe_full,
        "_authenticode_info",
        lambda path, errors, anomalies: {"present": False, "valid": None, "signer": None},
        raising=False,
    )
    return fake_state


def test_basic_pe_analysis(tmp_path, fake_environment):
    fake_environment["sections"] = [
        {
            "name": "UPX0",
            "virtual_size": 0x1000,
            "raw_size": 0x400,
            "virtual_address": 0x1000,
            "raw_pointer": 0x200,
            "data": os.urandom(0x400),
        },
        {
            "name": ".rdata",
            "virtual_size": 0x800,
            "raw_size": 0x200,
            "virtual_address": 0x2000,
            "raw_pointer": 0x600,
            "data": b"\x00" * 0x200,
        },
    ]
    fake_environment["imports"] = [
        {"dll": "KERNEL32.dll", "functions": ["CreateProcessA", "GetProcAddress"]},
        {"dll": "ADVAPI32.dll", "functions": ["RegOpenKeyA"]},
    ]
    fake_environment["exports"] = [{"name": "TestFunc", "ordinal": 1, "rva": 0x3000}]
    fake_environment["tls_callbacks"] = [0x401000]

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + os.urandom(2048))

    result = pe_full.analyze_pe_full(str(sample))
    pe_static = result["static"]["pe"]

    assert pe_static["file_info"]["file_type"] == "PE32"
    assert pe_static["file_info"]["has_tls_callbacks"] is True
    assert pe_static["suspicious_imports"], "expected suspicious imports to be detected"
    assert "packed_suspected" in pe_static["anomalies"]
    assert result["counts"]["sections_total"] == 2
    assert result["counts"]["imports_total"] >= 3
    assert result["counts"]["suspicious_imports_total"] >= 1
    if result["counts"]["suspicious_imports_total"] > 0:
        assert "suspicious_imports_detected" in pe_static["anomalies"]
    else:
        assert "suspicious_imports_detected" not in pe_static["anomalies"]


def test_strings_extraction(tmp_path, fake_environment):
    payload = (
        b"MZ"
        + b"A" * 64
        + b"http://example.com/malware"
        + b" powershell -nop"
        + "cmd.exe /c calc".encode("utf-16le")
    )
    sample = tmp_path / "strings.exe"
    sample.write_bytes(payload)

    result = pe_full.analyze_pe_full(str(sample))
    strings_info = result["static"]["pe"]["strings"]

    assert strings_info["total"] >= strings_info["unique"] >= len(strings_info.get("sample_strings", []))
    assert result["counts"]["strings_total"] == strings_info["total"]
    for url in strings_info.get("ioc_urls", []):
        assert url.lower().startswith("http")


def test_authenticode_fallback(tmp_path, fake_environment, monkeypatch):
    fake_environment["sections"] = []

    def fake_auth(path, errors, anomalies):
        anomalies.append("authenticode_parse_partial")
        return {"present": True, "valid": None, "signer": "unknown"}

    monkeypatch.setattr(pe_full, "_authenticode_info", fake_auth, raising=False)

    sample = tmp_path / "signed.exe"
    sample.write_bytes(b"MZ" + os.urandom(1024))

    result = pe_full.analyze_pe_full(str(sample))
    auth = result["static"]["pe"]["signatures"]["authenticode"]
    assert auth["present"] is True
    assert auth["valid"] is None
    assert auth["signer"] in ("unknown", None) or isinstance(auth["signer"], str)
    assert all("lief_signature_error" not in str(e) for e in result["errors"])


def test_fail_soft_without_pefile(tmp_path, monkeypatch):
    monkeypatch.setattr(pe_full, "pefile", None, raising=False)
    monkeypatch.setattr(pe_full, "yara", None, raising=False)
    monkeypatch.setattr(pe_full, "Cs", None, raising=False)
    monkeypatch.setattr(
        pe_full,
        "_authenticode_info",
        lambda path, errors, anomalies: {"present": False, "valid": None, "signer": None},
        raising=False,
    )
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 512)

    result = pe_full.analyze_pe_full(str(sample))
    assert "pefile_unavailable" in result["errors"]
    assert "static" in result and "pe" in result["static"]


def test_api_static_pe_endpoint(tmp_path, fake_environment, monkeypatch):
    if not (_FASTAPI_AVAILABLE and _APP_AVAILABLE):
        pytest.skip("FastAPI app not available in this environment")
    fake_environment["sections"] = [
        {
            "name": ".text",
            "virtual_size": 0x1000,
            "raw_size": 0x400,
            "virtual_address": 0x1000,
            "raw_pointer": 0x200,
            "data": os.urandom(0x400),
        }
    ]
    fake_environment["imports"] = [{"dll": "KERNEL32.dll", "functions": ["LoadLibraryA"]}]
    monkeypatch.setattr(pe_full, "pefile", build_fake_pefile_module(fake_environment), raising=False)
    monkeypatch.setattr(pe_full, "Cs", None, raising=False)
    monkeypatch.setattr(pe_full, "CS_ARCH_X86", None, raising=False)
    monkeypatch.setattr(pe_full, "yara", None, raising=False)
    monkeypatch.setattr(
        pe_full,
        "_authenticode_info",
        lambda path, errors, anomalies: {"present": False, "valid": None, "signer": None},
        raising=False,
    )

    client = TestClient(app)

    sample = tmp_path / "api.exe"
    payload = b"MZ" + os.urandom(1024)
    sample.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()

    files = {"file": ("api.exe", payload, "application/octet-stream")}
    resp = client.post("/api/static/pe/analyze", files=files)
    assert resp.status_code == 200
    body = resp.json()
    assert body["sha256"] == sha
    assert "static" in body and "pe" in body["static"]

    saved_path = OUT / f"{sha}.json"
    assert saved_path.exists(), "expected merged report to be written"
    saved = saved_path.read_text(encoding="utf-8")
    assert '"pe"' in saved

    # cleanup artifacts
    saved_path.unlink(missing_ok=True)
    quarantine_file = QUAR / f"{sha}.exe"
    if quarantine_file.exists():
        quarantine_file.unlink()
