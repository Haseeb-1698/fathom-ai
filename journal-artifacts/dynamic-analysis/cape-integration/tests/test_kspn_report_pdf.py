import sys
from pathlib import Path
from types import SimpleNamespace

import utils.kspn_report_pdf as kspn_report_pdf


def test_render_with_browser_invokes_chrome_and_writes_pdf(tmp_path, monkeypatch):
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    html_path.write_text("<html><body><h1>Report</h1></body></html>", encoding="utf-8")

    monkeypatch.setattr(kspn_report_pdf, "find_browser", lambda: "/usr/bin/google-chrome")

    calls = {}

    def fake_run(command, capture_output, text, check):
        calls["command"] = command
        pdf_path.write_bytes(b"%PDF-1.4\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("utils.kspn_report_pdf.subprocess.run", fake_run)

    ok, detail = kspn_report_pdf.render_with_browser(html_path, pdf_path)

    assert ok is True
    assert detail == "/usr/bin/google-chrome"
    assert calls["command"][0] == "/usr/bin/google-chrome"
    assert any(str(pdf_path) in item for item in calls["command"])
    assert html_path.resolve().as_uri() == calls["command"][-1]


def test_main_falls_back_to_builtin_pdf_when_browser_render_fails(tmp_path, monkeypatch):
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    html_path.write_text("<html><body><h1>Title</h1><p>Body text</p></body></html>", encoding="utf-8")

    monkeypatch.setattr(kspn_report_pdf, "render_with_browser", lambda *_args, **_kwargs: (False, "no browser"))
    monkeypatch.setattr(sys, "argv", ["kspn_report_pdf.py", "--html", str(html_path), "--output", str(pdf_path)])

    rc = kspn_report_pdf.main()

    assert rc == 0
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF-")
