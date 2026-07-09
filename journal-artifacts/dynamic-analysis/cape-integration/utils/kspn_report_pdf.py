#!/usr/bin/env python3
"""Generate a PDF version of the KSPN report for a CAPE analysis."""

from __future__ import annotations

import argparse
import html
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYSES_DIR = ROOT / "storage" / "analyses"
CHROME_CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a PDF from a KSPN HTML report.")
    parser.add_argument("--id", type=int, help="CAPE analysis ID")
    parser.add_argument("--html", type=str, help="Path to an existing KSPN HTML report")
    parser.add_argument("--output", type=str, help="Output PDF path")
    parser.add_argument("--analyst", type=str, default="Unknown Analyst", help="Analyst name when regenerating HTML")
    parser.add_argument("--org", type=str, default="KSPN", help="Organization name when regenerating HTML")
    parser.add_argument("--all-artifacts", action="store_true", help="Include full artifact appendix when regenerating HTML")
    parser.add_argument("--json-summary", action="store_true", help="Emit JSON summary when regenerating HTML")
    return parser.parse_args()


def ensure_html_report(args: argparse.Namespace) -> Path:
    if args.html:
        html_path = Path(args.html).expanduser().resolve()
        if not html_path.exists():
            raise FileNotFoundError(f"HTML report not found: {html_path}")
        return html_path

    if args.id is None:
        raise ValueError("Either --id or --html must be provided")

    analysis_dir = ANALYSES_DIR / str(args.id)
    reports_dir = analysis_dir / "reports"
    html_path = reports_dir / "kspn_report.html"
    if html_path.exists():
        return html_path

    script_path = ROOT / "utils" / "kspn_report.py"
    command = [sys.executable, str(script_path), "--id", str(args.id), "--analyst", args.analyst, "--org", args.org]
    if args.all_artifacts:
        command.append("--all-artifacts")
    if args.json_summary:
        command.append("--json-summary")

    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise RuntimeError(f"Failed to generate HTML report: {detail}")
    if not html_path.exists():
        raise FileNotFoundError(f"Expected HTML report was not created: {html_path}")
    return html_path


def find_browser() -> str | None:
    for candidate in CHROME_CANDIDATES:
        path = shutil.which(candidate)
        if path:
            return path
    return None


def render_with_browser(html_path: Path, pdf_path: Path) -> tuple[bool, str]:
    browser = find_browser()
    if not browser:
        return False, "No Chrome/Chromium executable found"

    command = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--allow-file-access-from-files",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}",
        html_path.resolve().as_uri(),
    ]
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0:
        command.insert(1, "--no-sandbox")

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode == 0 and pdf_path.exists() and pdf_path.stat().st_size > 0:
        return True, browser

    detail = completed.stderr.strip() or completed.stdout.strip() or "browser render failed"
    return False, detail


def html_to_text(html_text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", "", html_text)
    text = re.sub(r"(?i)</?(h1|h2|h3|p|div|section|article|main|header|footer|li|ul|ol|pre|br)[^>]*>", "\n", text)
    text = re.sub(r"(?i)</?code[^>]*>", "", text)
    text = re.sub(r"(?s)<[^>]+>", "", text)
    text = html.unescape(text)
    text = text.replace("\r", "")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


def wrap_line(text: str, width: int = 92) -> list[str]:
    if not text:
        return [""]
    words = text.split()
    if not words:
        return [""]
    lines = [words[0]]
    for word in words[1:]:
        candidate = f"{lines[-1]} {word}"
        if len(candidate) <= width:
            lines[-1] = candidate
        else:
            lines.append(word)
    return lines


def pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_text_pdf(text: str) -> bytes:
    lines: list[str] = []
    for block in text.splitlines():
        wrapped = wrap_line(block)
        lines.extend(wrapped)
    if not lines:
        lines = ["Empty report"]

    page_height = 792
    page_width = 612
    left = 54
    top = 742
    line_height = 12
    lines_per_page = 56

    objects: list[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    font_obj = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    pages_obj = add_object(b"<< /Type /Pages /Kids [] /Count 0 >>")

    page_ids: list[int] = []
    content_ids: list[int] = []
    for idx in range(0, len(lines), lines_per_page):
        chunk = lines[idx : idx + lines_per_page]
        content_lines = [b"BT", b"/F1 10 Tf"]
        y = top
        for line in chunk:
            content_lines.append(f"1 0 0 1 {left} {y} Tm ({pdf_escape(line)}) Tj".encode("latin-1", errors="ignore"))
            y -= line_height
        content_lines.append(b"ET")
        stream = b"\n".join(content_lines) + b"\n"
        content_obj = add_object(b"<< /Length %d >>\nstream\n%sendstream" % (len(stream), stream))
        page_obj = add_object(
            (
                f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 {page_width} {page_height}] "
                f"/Contents {content_obj} 0 R /Resources << /Font << /F1 {font_obj} 0 R >> >> >>"
            ).encode("ascii")
        )
        content_ids.append(content_obj)
        page_ids.append(page_obj)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_obj - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    catalog_obj = add_object(f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode("ascii"))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{index} 0 obj\n".encode("ascii"))
        out.extend(payload)
        out.extend(b"\nendobj\n")

    xref_offset = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(out)


def render_fallback_pdf(html_path: Path, pdf_path: Path) -> str:
    html_text = html_path.read_text(encoding="utf-8")
    pdf_path.write_bytes(build_text_pdf(html_to_text(html_text)))
    return "built-in text fallback"


def main() -> int:
    args = parse_args()
    try:
        html_path = ensure_html_report(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    pdf_path = Path(args.output).expanduser().resolve() if args.output else html_path.with_suffix(".pdf")
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    ok, detail = render_with_browser(html_path, pdf_path)
    backend = detail
    if not ok:
        backend = render_fallback_pdf(html_path, pdf_path)

    print(f"PDF: {pdf_path}")
    print(f"Source HTML: {html_path}")
    print(f"Backend: {backend}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
