#!/usr/bin/env python3
"""
scrape_cisa_mars.py — Download CISA Malware Analysis Reports (MARs), extract
structured content, and convert to Alpaca instruction pairs.

Usage:
  # Download and process all available CISA MARs:
  python3 scrape_cisa_mars.py --output data/processed/cisa_mars.jsonl

  # Process pre-downloaded PDFs from a directory:
  python3 scrape_cisa_mars.py --pdf-dir data/raw/cisa_mars/ --output data/processed/cisa_mars.jsonl

  # Limit to recent N reports:
  python3 scrape_cisa_mars.py --max-reports 30

Requirements:
  pip install pdfplumber requests beautifulsoup4 lxml

Each MAR produces 2-3 instruction pairs:
  1. Full analyst report (instruction + findings + ATT&CK)
  2. ATT&CK mapping only
  3. Executive summary

Output: data/processed/cisa_mars.jsonl
"""

import argparse
import io
import json
import random
import re
import sys
import time
from pathlib import Path

try:
    import pdfplumber
except ImportError:
    print("ERROR: pdfplumber not installed. Run: pip install pdfplumber")
    sys.exit(1)

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: requests/bs4 not installed. Run: pip install requests beautifulsoup4")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────

CISA_BASE = "https://www.cisa.gov"

# CISA blocks automated downloads with Cloudflare (403).
# Strategy: use Wayback Machine CDX API to find all archived MAR PDFs,
# then download from archive.org which has no bot protection.
WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"
WAYBACK_BASE = "https://web.archive.org/web"

# Seed original CISA MAR URLs — used to query Wayback for archived copies
CISA_MAR_ORIGINAL_URLS = [
    # APT/Nation-state
    "https://www.cisa.gov/sites/default/files/publications/MAR-10310246-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10310246-2.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10316564-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10316564-2.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10271944-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10271944-2.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10288834-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10295134-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10327841-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10330097-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10330097-2.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10330097-3.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10319053-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10319053-2.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10319053-3.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10381583-1.v2.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10135536-8.v4.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10135536-9.v4.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10135536-11.v4.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10135536-12.v4.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10135536-15.v4.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10135536-17.v4.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10322463-1.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10322463-2.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10322463-3.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10322463-4.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10322463-5.v1.WHITE.pdf",
    "https://www.cisa.gov/sites/default/files/publications/MAR-10365227-1.v1.WHITE.pdf",
    # Newer paths (post-2022 CISA site reorganisation)
    "https://www.cisa.gov/sites/default/files/2023-06/MAR-10448362.r1.v1.CLEAR.pdf",
    "https://www.cisa.gov/sites/default/files/2023-05/aa23-131a_mar_v2.pdf",
    "https://www.cisa.gov/sites/default/files/2024-02/aa24-038a-prc-state-sponsored-actors.pdf",
]

INSTRUCTION_FULL_REPORT = [
    "You are a senior malware analyst. Write a comprehensive malware analysis report based on the following evidence and findings.",
    "Produce a CISA-style malware analysis report from the following technical findings, including ATT&CK mapping and recommendations.",
    "Given the following malware analysis findings, produce a structured analysis report with executive summary, technical details, ATT&CK mapping, and IOCs.",
    "Write a formal malware analysis report in the style of a CISA MAR for the following sample evidence.",
    "You are a government malware analyst. Analyze the following findings and produce a complete threat report with ATT&CK mapping.",
]

INSTRUCTION_ATTCK = [
    "Map the following malware behaviors to MITRE ATT&CK techniques. Provide justification for each mapping.",
    "Produce a MITRE ATT&CK technique mapping with evidence citations from this malware analysis.",
    "Identify and explain the ATT&CK techniques observed in this malware sample based on the following findings.",
    "Given these malware analysis findings, provide a structured ATT&CK mapping with tactic, technique, and evidence for each entry.",
]

INSTRUCTION_SUMMARY = [
    "Write an executive summary of this malware analysis report suitable for non-technical leadership.",
    "Produce a concise executive summary and threat assessment from this CISA malware analysis.",
    "Summarize the key findings, threat actor attribution, and recommended mitigations from this malware analysis.",
]

# Section header patterns in CISA MARs
SECTION_PATTERNS = {
    "executive_summary": re.compile(
        r"(?:executive\s+summary|summary)[\s\n:]+(.+?)(?=(?:findings|technical\s+findings|description|malware\s+details|indicators|recommendations|att[&]?ck|mitre)|\Z)",
        re.IGNORECASE | re.DOTALL,
    ),
    "findings": re.compile(
        r"(?:findings|technical\s+findings|technical\s+details|malware\s+description|description)[\s\n:]+(.+?)(?=(?:executive\s+summary|indicators|recommendations|att[&]?ck|mitre|caveats|\Z))",
        re.IGNORECASE | re.DOTALL,
    ),
    "attck": re.compile(
        r"(?:att[&]?ck\s+techniques?|mitre\s+att[&]?ck|att[&]?ck\s+mapping)[\s\n:]+(.+?)(?=(?:indicators|iocs?|recommendations|caveats|\Z))",
        re.IGNORECASE | re.DOTALL,
    ),
    "iocs": re.compile(
        r"(?:indicators?\s+of\s+compromise|iocs?|network\s+indicators|host\s+indicators)[\s\n:]+(.+?)(?=(?:recommendations?|mitigations?|caveats?|att[&]?ck|\Z))",
        re.IGNORECASE | re.DOTALL,
    ),
    "recommendations": re.compile(
        r"(?:recommendations?|mitigations?|recommended\s+actions?)[\s\n:]+(.+?)(?=\Z)",
        re.IGNORECASE | re.DOTALL,
    ),
}

# ATT&CK ID pattern
ATTCK_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# IOC patterns
IOC_PATTERNS = {
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|gov|io|ru|cn|info|biz|onion)\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
}


# ── Scraping ──────────────────────────────────────────────────────────────────

def get_wayback_url(session: requests.Session, original_url: str) -> str | None:
    """Find the best archived copy of a URL in the Wayback Machine."""
    try:
        resp = session.get(
            WAYBACK_CDX_URL,
            params={
                "url": original_url,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "filter2": "mimetype:application/pdf",
                "limit": "1",
                "from": "20200101",
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        if len(data) > 1:  # first row is header
            row = data[1]
            timestamp, orig_url = row[0], row[1]
            return f"{WAYBACK_BASE}/{timestamp}if_/{orig_url}"
    except Exception as e:
        pass
    return None


def discover_mar_urls_via_wayback(session: requests.Session) -> list[tuple[str, str]]:
    """Use Wayback Machine CDX bulk search to find all archived CISA MARs."""
    print("Querying Wayback Machine CDX API for CISA MAR PDFs...")
    archived = []
    try:
        # Bulk wildcard query for all MAR PDFs ever on cisa.gov
        for url_pattern in [
            "cisa.gov/sites/default/files/publications/MAR-*.pdf",
            "cisa.gov/sites/default/files/*/MAR-*.pdf",
            "us-cert.gov/sites/default/files/publications/MAR-*.pdf",
        ]:
            resp = session.get(
                WAYBACK_CDX_URL,
                params={
                    "url": url_pattern,
                    "matchType": "glob",
                    "output": "json",
                    "fl": "timestamp,original",
                    "filter": "statuscode:200",
                    "collapse": "original",  # one entry per unique URL
                    "limit": "200",
                },
                timeout=30,
            )
            resp.raise_for_status()
            rows = resp.json()
            for row in rows[1:]:  # skip header
                timestamp, orig_url = row[0], row[1]
                if "MAR-" in orig_url and orig_url.endswith(".pdf"):
                    wayback_url = f"{WAYBACK_BASE}/{timestamp}if_/{orig_url}"
                    name = Path(orig_url).stem
                    archived.append((wayback_url, name))

        print(f"  Found {len(archived)} archived MAR PDFs via CDX")
    except Exception as e:
        print(f"  [WARN] CDX bulk query failed: {e}")

    return archived


def get_mar_pdf_urls(session: requests.Session) -> list[tuple[str, str]]:
    """Get MAR PDF download URLs via Wayback Machine (bypasses CISA Cloudflare)."""
    # Try CDX bulk discovery first
    urls = discover_mar_urls_via_wayback(session)

    if not urls:
        # Fall back: resolve each known URL individually via Wayback
        print(f"  CDX bulk query returned nothing. Resolving {len(CISA_MAR_ORIGINAL_URLS)} known URLs...")
        for orig_url in CISA_MAR_ORIGINAL_URLS:
            archived = get_wayback_url(session, orig_url)
            if archived:
                urls.append((archived, Path(orig_url).stem))
            time.sleep(0.3)

    if not urls:
        # Last resort: try original CISA URLs with browser-like headers
        print("  Wayback lookup failed. Trying direct CISA download with browser headers...")
        urls = [(url, Path(url).stem) for url in CISA_MAR_ORIGINAL_URLS]

    return urls


def download_pdf(session: requests.Session, url: str) -> bytes | None:
    """Download a PDF from Wayback Machine or direct URL."""
    try:
        resp = session.get(url, timeout=90, stream=False,
                           headers={"Referer": "https://web.archive.org/"})
        resp.raise_for_status()
        # Wayback sometimes returns HTML error pages — check content type
        ct = resp.headers.get("Content-Type", "")
        if "pdf" not in ct and len(resp.content) < 500:
            return None
        return resp.content
    except Exception as e:
        print(f"  [WARN] Download failed ({url[:80]}...): {e}")
        return None


# ── PDF parsing ───────────────────────────────────────────────────────────────

def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract full text from PDF bytes using pdfplumber."""
    text_parts = []
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
    except Exception as e:
        print(f"  [WARN] PDF extraction error: {e}")
    return "\n".join(text_parts)


def extract_text_from_pdf_file(pdf_path: Path) -> str:
    """Extract full text from a PDF file."""
    text_parts = []
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
    except Exception as e:
        print(f"  [WARN] PDF extraction error: {e}")
    return "\n".join(text_parts)


def clean_text(text: str) -> str:
    """Clean extracted PDF text."""
    # Remove excessive whitespace and control chars
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    # Remove page headers/footers (common CISA patterns)
    text = re.sub(r"TLP:\s*WHITE[^\n]*\n", "", text, flags=re.IGNORECASE)
    text = re.sub(r"Page\s+\d+\s+of\s+\d+[^\n]*\n", "", text, flags=re.IGNORECASE)
    text = re.sub(r"(?:UNCLASSIFIED|FOR OFFICIAL USE ONLY)[^\n]*\n", "", text, flags=re.IGNORECASE)
    return text.strip()


def parse_mar_sections(text: str) -> dict:
    """Parse a CISA MAR text into structured sections."""
    sections = {
        "executive_summary": "",
        "findings": "",
        "attck": "",
        "iocs": "",
        "recommendations": "",
        "attck_ids": [],
        "ioc_data": {},
        "malware_name": "",
        "mar_id": "",
        "full_text": text[:8000],
    }

    # Extract MAR ID
    mar_id_match = re.search(r"MAR[-–]\d{8}[-–]\d+\.v\d+", text, re.IGNORECASE)
    if mar_id_match:
        sections["mar_id"] = mar_id_match.group()

    # Extract malware name from title lines
    title_match = re.search(
        r"(?:malware\s+analysis\s+report[:\s]+|mar[:\s]+)([^\n]{5,80})",
        text[:2000], re.IGNORECASE
    )
    if title_match:
        sections["malware_name"] = title_match.group(1).strip()[:80]

    # Extract each section
    for section_name, pattern in SECTION_PATTERNS.items():
        m = pattern.search(text)
        if m:
            content = m.group(1).strip()
            # Limit to reasonable length
            sections[section_name] = content[:3000]

    # Extract ATT&CK technique IDs from full text
    sections["attck_ids"] = list(dict.fromkeys(ATTCK_PATTERN.findall(text)))

    # Extract IOCs
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(dict.fromkeys(pattern.findall(text)))
        if matches:
            # Filter out common false positives
            if ioc_type in ("sha256", "sha1", "md5"):
                # Only include if they look like real hashes
                matches = [m for m in matches if len(m) in (32, 40, 64)]
            sections["ioc_data"][ioc_type] = matches[:20]

    return sections


# ── Output builders ───────────────────────────────────────────────────────────

def build_full_report_input(sections: dict) -> str:
    """Build the input text for full report pair."""
    parts = []

    if sections["malware_name"]:
        parts.append(f"Malware: {sections['malware_name']}")
    if sections["mar_id"]:
        parts.append(f"Report ID: {sections['mar_id']}")

    if sections["executive_summary"]:
        parts.append(f"\nExecutive Summary:\n{sections['executive_summary'][:600]}")

    if sections["findings"]:
        parts.append(f"\nKey Findings:\n{sections['findings'][:800]}")

    if sections["attck_ids"]:
        parts.append(f"\nATT&CK Techniques Identified: {', '.join(sections['attck_ids'][:15])}")

    ioc_data = sections["ioc_data"]
    if ioc_data:
        ioc_parts = []
        if ioc_data.get("sha256"):
            ioc_parts.append(f"SHA256: {', '.join(ioc_data['sha256'][:3])}")
        if ioc_data.get("ip"):
            ioc_parts.append(f"IPs: {', '.join(ioc_data['ip'][:5])}")
        if ioc_data.get("domain"):
            ioc_parts.append(f"Domains: {', '.join(ioc_data['domain'][:5])}")
        if ioc_parts:
            parts.append(f"\nIndicators:\n" + "\n".join(ioc_parts))

    return "\n".join(parts)


def build_full_report_output(sections: dict) -> str:
    """Build the full analysis report output."""
    malware = sections["malware_name"] or "Malware Sample"

    tech_section = ""
    if sections["attck"]:
        tech_section = f"## ATT&CK Technique Mapping\n\n{sections['attck'][:2000]}\n\n"
    elif sections["attck_ids"]:
        tech_list = "\n".join(f"- **{tid}**" for tid in sections["attck_ids"][:15])
        tech_section = f"## ATT&CK Technique Mapping\n\n{tech_list}\n\n"

    ioc_section = ""
    ioc_data = sections["ioc_data"]
    if ioc_data:
        ioc_lines = []
        for ioc_type, values in ioc_data.items():
            if values:
                ioc_lines.extend([f"  {ioc_type.upper()}: {v}" for v in values[:5]])
        if ioc_lines:
            ioc_section = f"## Indicators of Compromise\n\n" + "\n".join(ioc_lines) + "\n\n"

    rec_section = ""
    if sections["recommendations"]:
        rec_section = f"## Recommendations\n\n{sections['recommendations'][:800]}\n\n"
    else:
        rec_section = (
            "## Recommendations\n\n"
            "1. Implement the ATT&CK-based detection recommendations\n"
            "2. Block the identified IOCs at network and endpoint controls\n"
            "3. Review logs for evidence of the observed TTPs\n"
            "4. Patch any vulnerabilities exploited by this malware\n\n"
        )

    exec_summary = sections["executive_summary"] or (
        f"This malware analysis report documents behavioral analysis of {malware}."
    )
    findings = sections["findings"] or sections["full_text"][:1500]

    return (
        f"## Malware Analysis Report: {malware}\n\n"
        f"## Executive Summary\n\n{exec_summary[:600]}\n\n"
        f"## Technical Findings\n\n{findings[:1500]}\n\n"
        f"{tech_section}"
        f"{ioc_section}"
        f"{rec_section}"
    )


def build_attck_output(sections: dict) -> str:
    """Build ATT&CK-focused output."""
    if not sections["attck_ids"] and not sections["attck"]:
        return ""

    malware = sections["malware_name"] or "the sample"

    if sections["attck"]:
        attck_detail = sections["attck"][:2500]
    elif sections["attck_ids"]:
        attck_detail = "\n".join(
            f"**{tid}** — identified in the analysis of {malware}"
            for tid in sections["attck_ids"]
        )
    else:
        return ""

    return (
        f"## MITRE ATT&CK Mapping — {malware}\n\n"
        f"The following ATT&CK techniques were identified during analysis:\n\n"
        f"{attck_detail}\n\n"
        f"## Coverage Summary\n\n"
        f"{len(sections['attck_ids'])} technique(s) mapped. "
        f"Defenders should prioritize detection coverage for the highest-confidence mappings "
        f"where direct behavioral evidence is available.\n"
    )


def build_summary_output(sections: dict) -> str:
    """Build executive summary output."""
    malware = sections["malware_name"] or "the analyzed sample"
    exec_summary = sections["executive_summary"]

    if not exec_summary or len(exec_summary) < 50:
        # Synthesize from findings
        exec_summary = sections["findings"][:400] if sections["findings"] else sections["full_text"][:400]

    return (
        f"## Executive Summary\n\n"
        f"**Subject:** {malware}\n\n"
        f"{exec_summary[:800]}\n\n"
        f"**Key Indicators:**\n"
        + (
            "\n".join(f"- ATT&CK: {tid}" for tid in sections["attck_ids"][:5])
            if sections["attck_ids"] else "- See full report for complete indicator list"
        )
        + "\n\n"
        f"**Recommended Actions:**\n"
        + (
            f"{sections['recommendations'][:400]}"
            if sections["recommendations"]
            else
            "- Block identified IOCs\n"
            "- Implement detection for identified ATT&CK techniques\n"
            "- Apply recommended patches and mitigations"
        )
    )


def mar_to_pairs(sections: dict) -> list[dict]:
    """Convert a parsed MAR into 2-3 Alpaca instruction pairs."""
    pairs = []

    input_text = build_full_report_input(sections)
    if len(input_text.strip()) < 100:
        return []

    # Pair 1: Full analysis report
    output1 = build_full_report_output(sections)
    if len(output1) > 200:
        pairs.append({
            "instruction": random.choice(INSTRUCTION_FULL_REPORT),
            "input": input_text[:2500],
            "output": output1,
        })

    # Pair 2: ATT&CK mapping (only if ATT&CK content exists)
    if sections["attck_ids"] or sections["attck"]:
        output2 = build_attck_output(sections)
        if output2:
            pairs.append({
                "instruction": random.choice(INSTRUCTION_ATTCK),
                "input": input_text[:2500],
                "output": output2,
            })

    # Pair 3: Executive summary
    output3 = build_summary_output(sections)
    if len(output3) > 100:
        pairs.append({
            "instruction": random.choice(INSTRUCTION_SUMMARY),
            "input": input_text[:2500],
            "output": output3,
        })

    return pairs


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scrape CISA MARs for training data")
    parser.add_argument("--output", type=str, default=None,
                        help="Output JSONL path")
    parser.add_argument("--pdf-dir", type=str, default=None,
                        help="Directory containing pre-downloaded MAR PDFs")
    parser.add_argument("--save-pdfs", type=str, default=None,
                        help="Directory to save downloaded PDFs for reuse")
    parser.add_argument("--max-reports", type=int, default=None,
                        help="Max number of MARs to process")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Delay between downloads in seconds")
    args = parser.parse_args()

    out_dir = Path(__file__).resolve().parent.parent.parent / "data" / "processed"
    out_path = Path(args.output) if args.output else out_dir / "cisa_mars.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    raw_dir = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
    save_dir = Path(args.save_pdfs) if args.save_pdfs else raw_dir / "cisa_mars"
    save_dir.mkdir(parents=True, exist_ok=True)

    random.seed(42)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (research; malware analysis training data)"
    })

    total_pairs = 0
    processed = 0
    skipped = 0

    with open(out_path, "a", encoding="utf-8") as out:
        # Source 1: Pre-downloaded PDFs
        if args.pdf_dir:
            pdf_dir = Path(args.pdf_dir)
            pdf_files = sorted(pdf_dir.glob("*.pdf"))
            if args.max_reports:
                pdf_files = pdf_files[:args.max_reports]

            print(f"Processing {len(pdf_files)} pre-downloaded PDFs from {pdf_dir}...")
            for i, pdf_path in enumerate(pdf_files, 1):
                print(f"[{i}/{len(pdf_files)}] {pdf_path.name}...", end=" ")
                text = extract_text_from_pdf_file(pdf_path)
                if len(text) < 200:
                    print("SKIP (too short)")
                    skipped += 1
                    continue

                text = clean_text(text)
                sections = parse_mar_sections(text)
                pairs = mar_to_pairs(sections)

                if not pairs:
                    print("SKIP (no usable sections)")
                    skipped += 1
                    continue

                for pair in pairs:
                    out.write(json.dumps(pair, ensure_ascii=False) + "\n")
                    total_pairs += 1
                processed += 1
                print(f"OK ({len(pairs)} pairs, {len(sections['attck_ids'])} ATT&CK IDs)")

        else:
            # Source 2: Download from CISA website
            mar_urls = get_mar_pdf_urls(session)
            if args.max_reports:
                mar_urls = mar_urls[:args.max_reports]

            print(f"\nDownloading and processing {len(mar_urls)} MARs...")
            for i, (url, title) in enumerate(mar_urls, 1):
                pdf_name = Path(url).name
                local_path = save_dir / pdf_name

                print(f"[{i}/{len(mar_urls)}] {pdf_name}...", end=" ")

                # Check if already downloaded
                if local_path.exists() and local_path.stat().st_size > 1000:
                    pdf_bytes = local_path.read_bytes()
                    print("(cached)", end=" ")
                else:
                    pdf_bytes = download_pdf(session, url)
                    if not pdf_bytes:
                        print("SKIP (download failed)")
                        skipped += 1
                        time.sleep(args.delay)
                        continue
                    local_path.write_bytes(pdf_bytes)
                    time.sleep(args.delay)

                text = extract_text_from_pdf(pdf_bytes)
                if len(text) < 200:
                    print("SKIP (too short)")
                    skipped += 1
                    continue

                text = clean_text(text)
                sections = parse_mar_sections(text)
                pairs = mar_to_pairs(sections)

                if not pairs:
                    print("SKIP (no usable sections)")
                    skipped += 1
                    continue

                for pair in pairs:
                    out.write(json.dumps(pair, ensure_ascii=False) + "\n")
                    total_pairs += 1
                processed += 1
                print(f"OK ({len(pairs)} pairs, {len(sections['attck_ids'])} ATT&CK IDs, "
                      f"{sections['mar_id'] or 'no ID found'})")

    print(f"\n{'='*60}")
    print(f"Processed: {processed} MARs, Skipped: {skipped}")
    print(f"Total instruction pairs written: {total_pairs}")
    print(f"PDFs saved to: {save_dir}")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
