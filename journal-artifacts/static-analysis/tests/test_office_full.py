import io
import os
import zipfile
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parents[1] / "server"))
from detector.office_full import analyze_office_full


def write_bytes(p: Path, data: bytes) -> Path:
    p.write_bytes(data)
    return p


def build_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def test_ooxml_doc_with_external_link(tmp_path: Path):
    content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
      <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
    </Types>'''
    core_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:creator>UnitTest</dc:creator>
    </cp:coreProperties>'''
    workbook = b"<workbook>Minimal</workbook>"
    rels = b'''<?xml version="1.0" encoding="UTF-8"?>
      <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://malicious.test/" TargetMode="External"/>
      </Relationships>'''
    zbytes = build_zip({
        "[Content_Types].xml": content_types,
        "docProps/core.xml": core_xml,
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": rels,
    })
    p = write_bytes(tmp_path / "doc.xlsx", zbytes)
    res = analyze_office_full(str(p))
    assert "static" in res and "office" in res["static"]
    off = res["static"]["office"]
    assert off["structure"]["family"] == "ooxml"
    assert (res["counts"]["external_references_total"]) >= 1
    assert isinstance(off.get("metadata"), dict)
    assert "counts" in res and "strings_total" in res["counts"]


def test_macro_enabled_workbook_mock(tmp_path: Path):
    # Include a vbaProject.bin file with AutoExec markers in plain text to trigger detection
    content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
    </Types>'''
    workbook = b"<workbook>Minimal</workbook>"
    vba = b"Sub Workbook_Open()\n Shell \"powershell -nop\"\n End Sub"
    zbytes = build_zip({
        "[Content_Types].xml": content_types,
        "xl/workbook.xml": workbook,
        "xl/vbaProject.bin": vba,
    })
    p = write_bytes(tmp_path / "macro.xlsm", zbytes)
    res = analyze_office_full(str(p))
    off = res["static"]["office"]
    flags = off.get("flags") or {}
    assert flags.get("macro_present") is True
    assert flags.get("suspicious_auto_exec") is True
    # OS command usage should be surfaced either via olevba or fallback keywords
    assert flags.get("suspicious_shell_usage") in (True, False)
    assert flags.get("suspicious_shell_usage") is True
    strings = off.get("strings") or {}
    assert any("powershell" in (s or "").lower() for s in (strings.get("suspicious_keywords") or [])) or ("powershell" in (" ".join(strings.get("sample_strings") or [])).lower())
    assert (res["counts"]["autoexec_macros_total"]) >= 1
    assert (res["counts"]["macros_total"]) >= 1
    # macro modules should include autoexec or show it in preview
    mods = off.get("macros") or []
    if mods:
        m0 = mods[0]
        prev = (m0.get("preview") or "").lower()
        autoexec_list = [s.lower() for s in (m0.get("autoexec_indicators") or [])]
        susp_list = [s.lower() for s in (m0.get("suspicious_indicators") or [])]
        assert ("workbook_open" in prev) or ("workbook_open" in " ".join(autoexec_list))
        assert ("powershell" in prev) or ("powershell" in " ".join(susp_list))


def test_high_entropy_embed_detection(tmp_path: Path):
    import os
    rnd = os.urandom(80 * 1024)
    content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    </Types>'''
    doc = b"<document>ok</document>"
    zbytes = build_zip({
        "[Content_Types].xml": content_types,
        "word/document.xml": doc,
        "word/embeddings/oleObject1.bin": rnd,
    })
    p = write_bytes(tmp_path / "highent.docx", zbytes)
    res = analyze_office_full(str(p))
    assert (res["counts"]["high_entropy_embed_count"]) >= 1
    off = res["static"]["office"]
    assert any(e.get("high_entropy") for e in (off.get("embedded_payloads") or []))


def test_fail_soft_on_corrupted_zip(tmp_path: Path):
    # Not a zip
    p = write_bytes(tmp_path / "bad.docx", b"not-a-zip")
    res = analyze_office_full(str(p))
    assert isinstance(res, dict)
    assert isinstance(res.get("errors"), list)
    # Unknown family or open error should be recorded
    assert res.get("errors")


def test_macro_analysis_fallback_unavailable(tmp_path: Path):
    # Simulate no oletools available: monkeypatch helper to return unavailable
    import importlib
    import detector.office_full as office_mod
    # Build minimal OOXML with macro hint to keep heuristics alive
    content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
    </Types>'''
    workbook = b"<workbook>Minimal</workbook>"
    vba = b"Sub Workbook_Open()\n Shell \"powershell -nop\"\n End Sub"
    zbytes = build_zip({
        "[Content_Types].xml": content_types,
        "xl/workbook.xml": workbook,
        "xl/vbaProject.bin": vba,
    })
    p = write_bytes(tmp_path / "macro2.xlsm", zbytes)

    orig = office_mod.analyze_macros_with_olevba
    try:
        def _fake(path: str, budget_bytes: int = 8192):
            return {"macro_present": False, "modules": [], "autoexec_detected": False, "errors": ["olevba_unavailable"]}
        office_mod.analyze_macros_with_olevba = _fake  # type: ignore
        res = analyze_office_full(str(p))
        assert isinstance(res, dict)
        off = res.get("static", {}).get("office", {})
        # Fallback heuristics still produce structure and counts
        assert "structure" in off and "counts" in res
        # Flags may still be true due to heuristic detection in our test sample
        flags = off.get("flags") or {}
        assert flags.get("macro_present") in (True, False)
        assert flags.get("suspicious_auto_exec") in (True, False)
        # errors should include the placeholder
        assert any("olevba_unavailable" in e for e in (res.get("errors") or []))
    finally:
        office_mod.analyze_macros_with_olevba = orig  # type: ignore
