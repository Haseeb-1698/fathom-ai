import hashlib
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parents[1] / "server"))
from detector.pdf_full import analyze_pdf_full


def write(tmpdir: Path, name: str, data: bytes) -> Path:
    p = tmpdir / name
    p.write_bytes(data)
    return p


def test_benign_small_pdf(tmp_path: Path):
    # Minimal well-formed PDF 1.4 with one object
    pdf = (b"%PDF-1.4\n"
           b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
           b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
           b"trailer\n<< /Root 1 0 R >>\nstartxref\n60\n%%EOF\n")
    p = write(tmp_path, "benign.pdf", pdf)
    res = analyze_pdf_full(str(p))
    assert "static" in res and "pdf" in res["static"]
    assert res["counts"]["revisions_total"] >= 1
    assert "pdf_header_missing" not in (res.get("errors") or [])
    # counts for strings/entropy should exist (even if zero)
    assert "strings_total" in res["counts"]
    assert "ioc_urls_total" in res["counts"]
    assert "high_entropy_stream_count" in res["counts"]
    ent = res["static"]["pdf"].get("entropy") or {}
    assert isinstance(ent.get("overall", 0.0), (int, float))
    # schema presence
    pdfs = res["static"]["pdf"]
    assert "metadata" in pdfs and set(["Producer","Creator"]).issubset(pdfs["metadata"].keys())
    assert "encryption" in pdfs and set(["Filter","Length"]).issubset(pdfs["encryption"].keys())
    assert isinstance(pdfs.get("actions"), list)
    assert isinstance(pdfs.get("names"), list)
    assert isinstance(pdfs.get("anomalies"), list)
    assert "revisions_total" in res["counts"] and "xref_streams_total" in res["counts"] and "objstm_total" in res["counts"]


def test_openaction_js(tmp_path: Path):
    # Catalog with OpenAction -> JS object
    pdf = (b"%PDF-1.5\n"
           b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
           b"2 0 obj\n<< /S /JavaScript /JS (app.alert('hi')) >>\nendobj\n"
           b"xref\n0 3\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n"
           b"trailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n")
    p = write(tmp_path, "openaction.pdf", pdf)
    res = analyze_pdf_full(str(p))
    counts = res["counts"]
    assert counts["js_objects_total"] >= 1
    assert counts["auto_actions_total"] >= 1


def test_incremental_updates_two_trailers(tmp_path: Path):
    # Initial revision + incremental update appended
    rev1 = (b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
            b"trailer\n<< /Root 1 0 R >>\nstartxref\n60\n%%EOF\n")
    # Append a second trailer with a bogus xref offset, still detectable via startxref occurrences
    rev2 = (b"\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 1\n0000000000 65535 f \n"
            b"trailer\n<< /Root 1 0 R >>\nstartxref\n120\n%%EOF\n")
    p = write(tmp_path, "incr.pdf", rev1 + rev2)
    res = analyze_pdf_full(str(p))
    assert res["counts"]["revisions_total"] >= 2


def test_decompression_budget_exceeded(tmp_path: Path):
    # Create an object with a flate stream that would expand a lot; here we mimic by many 'A's compressed
    payload = b"A" * (200 * 1024)  # 200KB
    comp = __import__("zlib").compress(payload)
    stream = (b"3 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp)) + comp + b"\nendstream\nendobj\n"
    pdf = (b"%PDF-1.7\n"
           b"1 0 obj\n<< /Type /Catalog >>\nendobj\n" + stream +
           b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000000 00000 f \n0000000000 00000 f \n"
           b"trailer\n<< /Root 1 0 R >>\nstartxref\n200\n%%EOF\n")
    p = write(tmp_path, "budget.pdf", pdf)
    res = analyze_pdf_full(str(p), config={"MAX_STREAM_PREVIEW": 1024, "MAX_DECOMPRESSED_TOTAL": 2048})
    # With a very small total budget, decoding should stop and raise budget exceeded
    assert any("decompression_budget_exceeded" in e for e in (res.get("errors") or []))


def test_strings_and_entropy_detection(tmp_path: Path):
    # PDF with URL and suspicious keyword
    body = (b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"2 0 obj\n<< /Length 36 >>\nstream\n"
            b"http://example.com powershell\n"
            b"endstream\nendobj\n"
            b"xref\n0 3\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n"
            b"trailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n")
    p = write(tmp_path, "ioc.pdf", body)
    res = analyze_pdf_full(str(p))
    strings = (res.get("static") or {}).get("pdf", {}).get("strings") or {}
    assert (strings.get("total") or 0) >= 1
    assert any(u.startswith("http") for u in (strings.get("ioc_urls") or []))


def test_high_entropy_stream_flag(tmp_path: Path):
    import os, zlib as _z
    rnd = os.urandom(80 * 1024)
    comp = _z.compress(rnd)
    stream = (b"3 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp)) + comp + b"\nendstream\nendobj\n"
    pdf = (b"%PDF-1.7\n"
           b"1 0 obj\n<< /Type /Catalog >>\nendobj\n" + stream +
           b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000000 00000 f \n0000000000 00000 f \n"
           b"trailer\n<< /Root 1 0 R >>\nstartxref\n200\n%%EOF\n")
    p = write(tmp_path, "highent.pdf", pdf)
    res = analyze_pdf_full(str(p))
    ent = (res.get("static") or {}).get("pdf", {}).get("entropy") or {}
    assert (ent.get("high_entropy_stream_count") or 0) >= 1


def test_frontend_shape_snapshot(tmp_path: Path):
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
           b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
           b"trailer\n<< /Root 1 0 R >>\nstartxref\n60\n%%EOF\n")
    p = write(tmp_path, "shape.pdf", pdf)
    res = analyze_pdf_full(str(p))
    record = {"static": res["static"], "counts": res["counts"], "errors": res["errors"]}
    # minimal shape consumed by StaticView.jsx
    pdfs = record["static"]["pdf"]
    assert isinstance(pdfs.get("metadata"), dict)
    assert isinstance(pdfs.get("encryption"), dict)
    assert isinstance(pdfs.get("actions"), list)
    assert isinstance(pdfs.get("trailers"), list)
    assert isinstance(pdfs.get("embedded_files"), list)
    assert isinstance(record.get("errors"), list)
