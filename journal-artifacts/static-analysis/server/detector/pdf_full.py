"""PDF structural analysis for Fathom (self-contained).

Import path expectation: when you run `uvicorn app:app --reload` from the
`server` folder, this module is importable as `detector.pdf_full`.

No top-level execution. All work is inside helpers and analyze_pdf_full().
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import base64
import binascii
import io
import re
import time
import zlib
import hashlib

# --------------------------
# Configuration (constants)
# --------------------------
MAX_INPUT_SIZE = 64 * 1024 * 1024          # 64 MB
MAX_DECOMPRESSED_TOTAL = 8 * 1024 * 1024   # 8 MB total across all streams
MAX_STREAM_PREVIEW = 8 * 1024              # 8 KB per-stream preview
MAX_OBJECT_GRAPH_DEPTH = 50                # reserved (not deeply used)
DECOMPRESS_TIMEOUT_SEC = 1.0               # per-decode time budget

# --------------------------
# Regex helpers
# --------------------------
_OBJ_HDR_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_OBJ_REF_RE = re.compile(rb"(\d+)\s+(\d+)\s+R\b")
_PDF_HEADER_RE = re.compile(rb"%PDF-(\d\.\d)")
_EOF_RE = re.compile(rb"%%EOF")

# --------------------------
# Utility helpers
# --------------------------

def _now() -> float:
    return time.monotonic()


def _within_budget(start: float, timeout: float) -> bool:
    return (time.monotonic() - start) <= timeout


def _safe_slice(b: bytes, start: int, end: int) -> bytes:
    start = max(0, start)
    end = max(start, end)
    return b[start:end]


def _findall(buf: bytes, pat: bytes) -> List[int]:
    out: List[int] = []
    idx = 0
    while True:
        j = buf.find(pat, idx)
        if j == -1:
            break
        out.append(j)
        idx = j + 1
    return out


def _trim_ascii(b: bytes, limit: int = 200) -> str:
    s = b.decode("latin-1", errors="ignore")
    return s if len(s) <= limit else s[:limit] + "…"


def _parse_simple_dict(blob: bytes) -> Dict[str, Any]:
    """Very shallow parser for << /Key value /Key2 value2 ... >> dictionaries.
    Supports names, numbers, arrays, strings (no escape handling), and refs (n n R).
    """
    res: Dict[str, Any] = {}
    l = blob.find(b"<<")
    r = blob.find(b">>", l + 2)
    if l == -1 or r == -1:
        return res
    body = blob[l + 2 : r]
    toks = re.findall(rb"/[^\s\[/\(\)<>%]+|\[|\]|\(|\)|<<?|>>?|true|false|null|\d+\.?\d*|R", body)
    i = 0
    key: Optional[str] = None
    arr_stack: List[List[Any]] = []

    def push(v: Any) -> None:
        nonlocal key
        if arr_stack:
            arr_stack[-1].append(v)
        elif key is not None:
            res[key] = v
            key = None

    while i < len(toks):
        t = toks[i]
        if t.startswith(b"/"):
            name = t[1:].decode("latin-1", errors="ignore")
            if key is None:
                key = name
            else:
                push(name)
        elif t == b"[":
            arr_stack.append([])
        elif t == b"]":
            v = arr_stack.pop() if arr_stack else []
            push(v)
        elif re.fullmatch(rb"\d+", t):
            if i + 2 < len(toks) and re.fullmatch(rb"\d+", toks[i + 1]) and toks[i + 2] == b"R":
                try:
                    o = int(t)
                    g = int(toks[i + 1])
                except Exception:
                    o = g = 0
                push({"ref": f"{o} {g} R"})
                i += 2
            else:
                try:
                    push(int(t))
                except Exception:
                    push(0)
        elif t in (b"true", b"false", b"null"):
            push(True if t == b"true" else False if t == b"false" else None)
        elif t == b"(":
            j = body.find(b")", body.find(t))
            s = b"" if j == -1 else body[body.find(t) + 1 : j]
            push(_trim_ascii(s, 400))
        i += 1
    return res

def _parse_info_kv(blob: bytes) -> Dict[str, str]:
    """Best-effort parse for PDF Info dictionary literal strings.
    Looks for keys like /Producer (..), /Creator (..), /CreationDate (..), /ModDate (..).
    Returns ascii-trimmed values without executing or resolving nested structures.
    """
    keys = ("Producer","Creator","CreationDate","ModDate","Title","Author","Subject","Keywords")
    out: Dict[str, str] = {}
    
    # Date fields need special handling
    date_fields = {"CreationDate", "ModDate"}
    
    for k in keys:
        try:
            # Pattern 1: literal string in parentheses: /Producer (Adobe Acrobat) or /CreationDate (D:20240101120000)
            pat1 = re.compile(rb"/" + k.encode("ascii") + rb"\s*\((.*?)\)", re.S)
            m1 = pat1.search(blob)
            if m1:
                # Handle escaped characters in PDF strings
                raw_value = m1.group(1)
                # Basic unescape for common PDF string escapes
                unescaped = raw_value.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
                
                # Special handling for date fields
                if k in date_fields:
                    date_str = _trim_ascii(unescaped, 400)
                    # Only accept if it looks like a PDF date (starts with D: or looks like a date)
                    if (date_str.startswith('D:') or 
                        re.match(r'\d{4}[-/]\d{2}[-/]\d{2}', date_str) or
                        re.match(r'D:\d{8,14}', date_str)):
                        out[k] = date_str
                else:
                    out[k] = _trim_ascii(unescaped, 400)
                continue
            
            # Pattern 2: hex string: /Producer <48656C6C6F>
            pat2 = re.compile(rb"/" + k.encode("ascii") + rb"\s*<([0-9A-Fa-f]+)>")
            m2 = pat2.search(blob)
            if m2:
                try:
                    hex_data = m2.group(1)
                    decoded = bytes.fromhex(hex_data.decode('ascii'))
                    decoded_str = _trim_ascii(decoded, 400)
                    
                    # Special handling for date fields
                    if k in date_fields:
                        if (decoded_str.startswith('D:') or 
                            re.match(r'\d{4}[-/]\d{2}[-/]\d{2}', decoded_str) or
                            re.match(r'D:\d{8,14}', decoded_str)):
                            out[k] = decoded_str
                    else:
                        out[k] = decoded_str
                    continue
                except Exception:
                    pass
            
            # For date fields, don't try name objects or unquoted strings as they're unlikely to be dates
            if k in date_fields:
                continue
            
            # Pattern 3: name object: /Producer /Chromium (not for dates)
            pat3 = re.compile(rb"/" + k.encode("ascii") + rb"\s*/([^\s<>\[\]\(\)/]+)")
            m3 = pat3.search(blob)
            if m3:
                out[k] = _trim_ascii(m3.group(1), 400)
                continue
                
            # Pattern 4: string without parentheses (some malformed PDFs, not for dates)
            pat4 = re.compile(rb"/" + k.encode("ascii") + rb"\s+([^\s<>\[\]/]+)")
            m4 = pat4.search(blob)
            if m4:
                value = m4.group(1)
                # Skip if it looks like another PDF keyword
                if not value.startswith(b'/') and not value.isdigit():
                    out[k] = _trim_ascii(value, 400)
                    
        except Exception:
            continue
    return out

# --------------------------
# Global string + IOC extraction
# --------------------------
def extract_global_strings(file_bytes: bytes, min_len: int = 6) -> Dict[str, Any]:
    """Extract ASCII and UTF-16LE strings + IOC hints. Fail-soft."""
    out: Dict[str, Any] = {
        "total": 0,
        "unique": 0,
        "ioc_urls": [],
        "suspicious_keywords": [],
        "sample_strings": [],
    }
    try:
        if not file_bytes:
            return out
        # ASCII printable strings
        ascii_strings: List[str] = []
        try:
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, file_bytes):
                s = m.group(0).decode("latin-1", errors="ignore")
                if s:
                    ascii_strings.append(s)
        except Exception:
            pass

        # UTF-16LE strings: look for printable bytes interleaved with \x00
        utf16_strings: List[str] = []
        try:
            # Heuristic: decode as UTF-16LE ignoring errors, then look for printable runs
            dec = file_bytes.decode("utf-16le", errors="ignore")
            for m in re.finditer(r"[\x20-\x7e]{%d,}" % min_len, dec):
                s = m.group(0)
                if s:
                    utf16_strings.append(s)
        except Exception:
            pass

        all_strings = ascii_strings + utf16_strings
        out["total"] = len(all_strings)
        # Deduplicate
        uniq = []
        seen = set()
        for s in all_strings:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        out["unique"] = len(uniq)

        # IOC: URLs
        url_re = re.compile(r"https?://[\w\-\.\/?#%&=:+,@~]+", re.I)
        ioc_urls: List[str] = []
        for s in uniq:
            for u in url_re.findall(s):
                if len(ioc_urls) >= 200:
                    break
                ioc_urls.append(u)
            if len(ioc_urls) >= 200:
                break
        out["ioc_urls"] = ioc_urls

        # Suspicious keywords
        suspects = (
            "powershell", "cmd.exe", "rundll32", "WScript.Shell",
            "ActiveXObject", "shell32.dll", "AutoOpen",
        )
        found = []
        for kw in suspects:
            for s in uniq:
                if kw.lower() in s.lower():
                    found.append(kw)
                    break
        out["suspicious_keywords"] = found[:20]

        # Sample strings (first ~10, truncated)
        out["sample_strings"] = [ (s if len(s) <= 120 else s[:120] + "…") for s in uniq[:10] ]
        return out
    except Exception:
        # Fail-soft handled by caller via errors list
        return out

# --------------------------
# Stream decoding (bounded)
# --------------------------

@dataclass
class DecompressBudget:
    total_used: int = 0
    max_total: int = MAX_DECOMPRESSED_TOTAL

    def request(self, need: int) -> bool:
        return (self.total_used + need) <= self.max_total

    def add(self, used: int) -> None:
        self.total_used = min(self.max_total, self.total_used + int(max(0, used)))

    def remaining(self) -> int:
        return max(0, self.max_total - self.total_used)


def _decode_asciihex(d: bytes) -> bytes:
    d = re.sub(rb"\s+", b"", d)
    if d.endswith(b">"):
        d = d[:-1]
    if len(d) % 2 == 1:
        d += b"0"
    try:
        return binascii.unhexlify(d)
    except Exception:
        return b""


def _decode_ascii85(d: bytes) -> bytes:
    try:
        return base64.a85decode(d, adobe=True)
    except Exception:
        return b""


def _decode_runlength(d: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(d)
    while i < n:
        L = d[i]
        i += 1
        if L == 128:
            break
        if L < 128:
            run = L + 1
            out.extend(d[i : i + run])
            i += run
        else:
            run = 257 - L
            if i >= n:
                break
            out.extend(d[i : i + 1] * run)
            i += 1
    return bytes(out)


def _try_flate(d: bytes) -> bytes:
    try:
        return zlib.decompress(d)
    except Exception:
        return b""


def _decode_stream(
    raw: bytes,
    filters: List[str],
    budget: DecompressBudget,
    errors: List[str],
    max_preview: int,
    timeout_sec: float,
) -> Tuple[bytes, bool]:
    dec = raw
    truncated = False
    st = _now()
    for f in (filters or []):
        if not _within_budget(st, timeout_sec):
            errors.append("decompress_timeout")
            return b"", False
        fn = f.lower()
        if fn in ("flatedecode", "flate"):
            dec = _try_flate(dec)
        elif fn in ("lzw", "lzwdecode"):
            errors.append("lzw_unsupported")
            return b"", False
        elif fn in ("asciihexdecode", "ahx"):
            dec = _decode_asciihex(dec)
        elif fn in ("ascii85decode", "a85"):
            dec = _decode_ascii85(dec)
        elif fn in ("runlengthdecode", "rld"):
            dec = _decode_runlength(dec)
        elif fn in ("jbig2decode", "jbig2"):
            errors.append("jbig2_unsupported")
            return b"", False
        elif fn in ("dctdecode", "dct"):
            # DCTDecode is JPEG compression - we can't decode it without PIL/Pillow
            # but we can pass it through as-is since it's already compressed data
            # This is common in PDFs with embedded images
            pass  # Keep the data as-is
        elif fn in ("jpxdecode", "jpx"):
            # JPEG2000 compression - similar to DCT, pass through
            pass  # Keep the data as-is
        elif fn in ("ccittfaxdecode", "ccf"):
            # CCITT Fax compression - pass through
            pass  # Keep the data as-is
        else:
            errors.append(f"unknown_filter:{f}")
            return b"", False
        if not dec:
            break
        available = budget.remaining()
        if available <= 0 or len(dec) > available:
            errors.append("decompression_budget_exceeded")
            return b"", False
        if not budget.request(min(len(dec), max_preview)):
            errors.append("decompression_budget_exceeded")
            return b"", False
    preview = dec[:max_preview]
    budget.add(len(preview))
    truncated = len(dec) > len(preview)
    return preview, truncated


def _apply_png_predictor(decoded: bytes, columns: int) -> Tuple[bytes, bool]:
    """Minimal PNG predictor handling (filter type 0 only)."""
    try:
        out = bytearray()
        i = 0
        row = 1 + columns
        if row <= 1 or len(decoded) < row or len(decoded) % row != 0:
            return decoded, False
        while i < len(decoded):
            f = decoded[i]
            r = decoded[i + 1 : i + row]
            if f == 0:
                out.extend(r)
            else:
                return decoded, False
            i += row
        return bytes(out), True
    except Exception:
        return decoded, False

# --------------------------
# Entropy helper
# --------------------------
# Import professional entropy calculation
try:
    from .entropy_utils import calculate_shannon_entropy as shannon_entropy
except ImportError:
    # Fallback if scipy not available
    def shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy of bytes. Returns 0.0 for empty input."""
        if not data:
            return 0.0
        from collections import Counter
        import math
        total = len(data)
        counts = Counter(data)
        return float(-sum((c/total) * math.log2(c/total) for c in counts.values()))

# --------------------------
# Main entrypoint
# --------------------------

def analyze_pdf_full(path: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = config or {}
    max_input = int(cfg.get("MAX_INPUT_SIZE", MAX_INPUT_SIZE))
    max_dec_total = int(cfg.get("MAX_DECOMPRESSED_TOTAL", MAX_DECOMPRESSED_TOTAL))
    max_preview = int(cfg.get("MAX_STREAM_PREVIEW", MAX_STREAM_PREVIEW))
    dec_timeout = float(cfg.get("DECOMPRESS_TIMEOUT_SEC", DECOMPRESS_TIMEOUT_SEC))

    p = Path(path)
    errors: List[str] = []
    static_pdf: Dict[str, Any] = {
        "versions": [],
        "headers": [],
        "trailers": [],
        "objects": [],
        "names": [],
        "embedded_files": [],
        "actions": [],
        "anomalies": [],
        "metadata": {
            "Producer": None, "Creator": None, "CreationDate": None, "ModDate": None,
            "Title": None, "Author": None, "Subject": None, "Keywords": None,
        },
        "encryption": {
            "Filter": None, "V": None, "R": None, "Length": None, "P": None,
            "CF": None, "StmF": None, "StrF": None,
        },
        "object_offsets": {"total": 0, "sample": []},
    }
    counts: Dict[str, int] = {
        "objects_total": 0, "streams_total": 0, "js_objects_total": 0, "auto_actions_total": 0,
        "embedded_files_total": 0, "urls_total": 0, "revisions_total": 0,
        "xref_streams_total": 0, "objstm_total": 0,
    }

    try:
        data = p.read_bytes()
    except Exception as e:
        return {"static": {"pdf": static_pdf}, "counts": counts, "errors": [f"read_error:{e}"]}

    if len(data) > max_input:
        errors.append("input_over_limit")
        return {"static": {"pdf": static_pdf}, "counts": counts, "errors": errors}

    # Header / versions
    head = data[: min(len(data), 4096)]
    vers = _PDF_HEADER_RE.findall(head)
    if vers:
        static_pdf["versions"] = [v.decode("ascii", errors="ignore") for v in vers]
        static_pdf["headers"] = [m.start() for m in _PDF_HEADER_RE.finditer(head)]
    else:
        errors.append("pdf_header_missing")

    # Revisions by startxref
    sx = _findall(data, b"startxref")
    revs: List[Tuple[int, int]] = []
    for pos in sx:
        m = re.search(rb"startxref\s+(\d+)", data[pos : pos + 64])
        if m:
            try:
                revs.append((pos, int(m.group(1))))
            except Exception:
                pass
    counts["revisions_total"] = len(revs)

    # EOF anomalies
    eof_positions = [m.start() for m in _EOF_RE.finditer(data)]
    if not eof_positions:
        static_pdf["anomalies"].append("missing_eof")
    elif len(eof_positions) > 1:
        static_pdf["anomalies"].append(f"multiple_eof_markers:{len(eof_positions)}")

    # Global decompression budget
    budget = DecompressBudget(0, max_dec_total)

    # Global strings/IOC sweep
    try:
        strings_info = extract_global_strings(data, min_len=6)
        static_pdf["strings"] = strings_info
        counts["strings_total"] = int(strings_info.get("total") or 0)
        counts["ioc_urls_total"] = len(strings_info.get("ioc_urls") or [])
    except Exception:
        static_pdf["strings"] = {}
        errors.append("global_string_extraction_failed")

    # Build object offset map from xref tables and xref streams
    obj_off: Dict[Tuple[int, int], int] = {}
    dup: List[str] = []

    def add_x(o: int, g: int, off: int) -> None:
        k = (o, g)
        if k in obj_off:
            dup.append(f"duplicate_xref:{o} {g}")
        obj_off[k] = off

    def parse_xref_table(xoff: int) -> List[str]:
        an: List[str] = []
        if not (0 <= xoff < len(data)) or not data[xoff : xoff + 4].startswith(b"xref"):
            return an
        buf = data[xoff : min(len(data), xoff + 8192)]
        nl = buf.find(b"\n")
        if nl == -1:
            return an
        cur = nl + 1
        last = -1
        while cur < len(buf):
            nl2 = buf.find(b"\n", cur)
            if nl2 == -1:
                break
            line = buf[cur:nl2].strip()
            cur = nl2 + 1
            if not line:
                continue
            if line.startswith(b"trailer"):
                break
            parts = line.split()
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                break
            start_obj = int(parts[0])
            cnt = int(parts[1])
            if start_obj < last:
                an.append("non_monotonic_xref_subsection")
            last = start_obj
            for i in range(cnt):
                nl3 = buf.find(b"\n", cur)
                if nl3 == -1:
                    break
                e = buf[cur:nl3]
                cur = nl3 + 1
                try:
                    off = int(e[:10])
                    g = int(e[11:16])
                    fl = e[17:18]
                except Exception:
                    continue
                if fl == b"n":
                    add_x(start_obj + i, g, off)
        return an

    def parse_xref_stream(xoff: int) -> List[str]:
        s = max(0, xoff - 1024)
        win = data[s : min(len(data), xoff + 1024)]
        m = _OBJ_HDR_RE.search(win)
        if not m:
            return []
        abs_off = s + m.start()
        end = data.find(b"endobj", abs_off)
        if end == -1:
            end = min(abs_off + 8192, len(data))
        blob = data[abs_off : min(end + 6, len(data))]
        d = _parse_simple_dict(blob)
        if (d.get("Type") or "") != "XRef":
            return []
        p = blob.find(b"stream")
        q = blob.find(b"endstream", p)
        raw = b""
        if p != -1 and q != -1:
            raw = blob[p + len(b"stream") : q].lstrip(b"\r\n")
        fv = d.get("Filter")
        filters = fv if isinstance(fv, list) else [fv] if isinstance(fv, str) else []
        if not budget.request(1):
            errors.append("decompression_budget_exceeded_global")
            return []
        prev, _ = _decode_stream(raw, [str(x).strip("/") for x in filters], budget, errors, MAX_STREAM_PREVIEW, DECOMPRESS_TIMEOUT_SEC)
        if not prev:
            return []
        W = d.get("W") if isinstance(d.get("W"), list) else None
        if not W or not all(isinstance(x, int) for x in W):
            return []
        Index = d.get("Index") if isinstance(d.get("Index"), list) else None
        if not Index:
            sz = int(d.get("Size") or 0)
            Index = [0, sz]
        bts = prev if isinstance(prev, (bytes, bytearray)) else prev.encode("latin-1", errors="ignore")
        ptr = 0
        for i in range(0, len(Index), 2):
            start_obj = int(Index[i])
            cnt = int(Index[i + 1])
            for j in range(cnt):
                f0, f1, f2 = W
                if ptr + f0 + f1 + f2 > len(bts):
                    break
                t = int.from_bytes(bts[ptr : ptr + f0] or b"\x00", "big"); ptr += f0
                a = int.from_bytes(bts[ptr : ptr + f1] or b"\x00", "big"); ptr += f1
                b_ = int.from_bytes(bts[ptr : ptr + f2] or b"\x00", "big"); ptr += f2
                if t == 1:
                    add_x(start_obj + j, b_, a)
        return []

    for _, xoff in revs:
        if 0 <= xoff < len(data) and data[xoff : xoff + 4] == b"xref":
            static_pdf["anomalies"].extend(parse_xref_table(xoff))
        elif 0 <= xoff < len(data):
            static_pdf["anomalies"].extend(parse_xref_stream(xoff))

    for (o, g), off in obj_off.items():
        if not (0 <= off < len(data)):
            static_pdf["anomalies"].append(f"xref_offset_oob:{o} {g}")
    for dmsg in dup:
        static_pdf["anomalies"].append(dmsg)

    # Enumerate objects (prefer xref offsets)
    objects: Dict[Tuple[int, int], Dict[str, Any]] = {}
    # Track suspicious streams by entropy
    suspicious_streams: List[Dict[str, Any]] = []
    for m in _OBJ_HDR_RE.finditer(data):
        o = int(m.group(1)); g = int(m.group(2))
        start_off = obj_off.get((o, g), m.start())
        end = data.find(b"endobj", start_off)
        if end == -1:
            end = min(start_off + 8192, len(data))
        blob = data[start_off : min(end + 6, len(data))]
        ent: Dict[str, Any] = {
            "obj_id": f"{o} {g} R",
            "offset": start_off,
            "type_hint": "unknown",
            "dict_keys": [],
            "references": [],
            "annotations": [],
        }
        d = _parse_simple_dict(blob)
        if d:
            ent["dict_keys"] = sorted(list(d.keys()))
        if (d.get("Type") or "") == "ObjStm":
            counts["objstm_total"] += 1
        sp = blob.find(b"stream")
        if sp != -1:
            ent["type_hint"] = "stream"
            counts["streams_total"] += 1
            ep = blob.find(b"endstream", sp)
            raw = b""
            if ep != -1:
                raw = blob[sp + len(b"stream") : ep].lstrip(b"\r\n")
            fv = d.get("Filter")
            filters = fv if isinstance(fv, list) else [fv] if isinstance(fv, str) else []
            si: Dict[str, Any] = {"filters": [str(x).strip("/") for x in filters], "raw_stream_len": len(raw)}
            if not budget.request(1):
                errors.append("decompression_budget_exceeded_global")
            else:
                if any(str(f).lower() in ("lzw", "lzwdecode") for f in filters):
                    ent["annotations"].append("lzw_unsupported")
                    si["decoded_preview"] = None
                    si["decoded_truncated"] = False
                else:
                    try:
                        prev, tr = _decode_stream(raw, si["filters"], budget, errors, max_preview, dec_timeout)
                        if prev and isinstance(d.get("DecodeParms"), dict):
                            pred = d["DecodeParms"].get("Predictor")
                            if isinstance(pred, int) and pred >= 10:
                                cols = int(d["DecodeParms"].get("Columns") or 0)
                                if cols > 0 and isinstance(prev, (bytes, bytearray)):
                                    adj, ok = _apply_png_predictor(prev, cols)
                                    if ok:
                                        prev = adj
                                    else:
                                        errors.append("predictor_parse_failed")
                        if prev:
                            si["decoded_preview"] = _trim_ascii(prev, max_preview)
                            si["decoded_truncated"] = bool(tr)
                    except Exception as e:
                        errors.append(f"stream_decode_error:{e}")
            ent["stream"] = si

            # Entropy on raw/decoded (bounded)
            try:
                # raw entropy (cap to 64KB)
                raw_slice = raw[: 64 * 1024] if isinstance(raw, (bytes, bytearray)) else b""
                eraw = shannon_entropy(raw_slice) if raw_slice else 0.0
                # decoded entropy uses preview bytes if available
                dprev = None
                if isinstance(ent.get("stream", {}).get("decoded_preview"), str):
                    dprev = ent["stream"]["decoded_preview"].encode("latin-1", errors="ignore")
                edec = shannon_entropy(dprev) if dprev else 0.0
                if eraw > 7.5 or edec > 7.5:
                    suspicious_streams.append({
                        "obj_ref": ent["obj_id"],
                        "entropy_raw": round(eraw, 2),
                        "entropy_decoded": round(edec, 2),
                        "reason": "high_entropy_stream",
                    })
            except Exception:
                pass
        else:
            ent["type_hint"] = "dict"
        refs = [f"{int(a)} {int(b)} R" for (a, b) in _OBJ_REF_RE.findall(blob)]
        if refs:
            ent["references"] = refs[:50]
        ks = set(ent.get("dict_keys") or [])
        if any(k in ks for k in ("JS", "JavaScript")):
            ent["annotations"].append("/JS")
            counts["js_objects_total"] += 1
        if "OpenAction" in ks or "AA" in ks:
            ent["annotations"].append("/OpenAction")
            counts["auto_actions_total"] += 1
        if d.get("Type") == "EmbeddedFile" or "EmbeddedFile" in ks:
            ent["annotations"].append("embedded_file")
        objects[(o, g)] = ent

    static_pdf["objects"] = list(objects.values())[:5000]
    counts["objects_total"] = len(objects)
    static_pdf["object_offsets"] = {
        "total": len(obj_off),
        "sample": [{"obj_id": f"{o} {g} R", "offset": obj_off[(o, g)]} for (o, g) in list(obj_off.keys())[:20]],
    }

    # Overall entropy (cap to 4MB)
    try:
        cap = min(len(data), 4 * 1024 * 1024)
        overall = shannon_entropy(data[:cap]) if cap > 0 else 0.0
    except Exception:
        overall = 0.0
        errors.append("entropy_calc_failed")
    static_pdf["entropy"] = {
        "overall": round(float(overall), 2),
        "suspicious_streams": suspicious_streams,
        "high_entropy_stream_count": len(suspicious_streams),
    }
    counts["high_entropy_stream_count"] = len(suspicious_streams)

    # Trailers summary
    for _, xoff in revs:
        tr: Dict[str, Any] = {
            "startxref": xoff,
            "xref_type": "table",
            "root_obj": None,
            "info_obj": None,
            "encrypt_obj": None,
            "raw": "",
        }
        if 0 <= xoff < len(data):
            kind = data[xoff : xoff + 8]
            if kind.startswith(b"xref"):
                tpos = data.find(b"trailer", xoff)
                if tpos != -1:
                    raw = _safe_slice(data, tpos, tpos + 1024)
                    tr["raw"] = _trim_ascii(raw)
                    dt = _parse_simple_dict(raw)
                    tr["root_obj"] = (dt.get("Root") or {}).get("ref") if isinstance(dt.get("Root"), dict) else None
                    tr["info_obj"] = (dt.get("Info") or {}).get("ref") if isinstance(dt.get("Info"), dict) else None
                    tr["encrypt_obj"] = (dt.get("Encrypt") or {}).get("ref") if isinstance(dt.get("Encrypt"), dict) else None
            else:
                tr["xref_type"] = "stream"
                counts["xref_streams_total"] += 1
                raw = _safe_slice(data, xoff, min(xoff + 1024, len(data)))
                tr["raw"] = _trim_ascii(raw)
                dt = _parse_simple_dict(raw)
                tr["root_obj"] = (dt.get("Root") or {}).get("ref") if isinstance(dt.get("Root"), dict) else None
                tr["info_obj"] = (dt.get("Info") or {}).get("ref") if isinstance(dt.get("Info"), dict) else None
                tr["encrypt_obj"] = (dt.get("Encrypt") or {}).get("ref") if isinstance(dt.get("Encrypt"), dict) else None
        static_pdf["trailers"].append(tr)

    # Catalog and basic action resolution
    cat: Optional[Tuple[int, int]] = None
    for ref, v in objects.items():
        ks = set(v.get("dict_keys") or [])
        if "Type" in ks and "Catalog" in ks:
            cat = ref
            break

    def get_blob(refs: str) -> Optional[bytes]:
        try:
            n, g, _ = refs.split()
            off = obj_off.get((int(n), int(g)))
            if off is None:
                return None
            end = data.find(b"endobj", off)
            if end == -1:
                end = min(off + 8192, len(data))
            return data[off : min(end + 6, len(data))]
        except Exception:
            return None

    def deref_dict(refs: Optional[str]) -> Dict[str, Any]:
        if not refs:
            return {}
        b = get_blob(refs)
        return _parse_simple_dict(b) if b else {}

    acts: List[Dict[str, Any]] = []
    if cat is not None:
        b = get_blob(f"{cat[0]} {cat[1]} R")
        if b:
            d = _parse_simple_dict(b)
            oa = d.get("OpenAction")
            if isinstance(oa, dict) and "ref" in oa:
                tgt = oa["ref"]
                tb = get_blob(tgt)
                if tb:
                    td = _parse_simple_dict(tb)
                    acts.append({
                        "source_obj": f"{cat[0]} {cat[1]} R",
                        "action_type": "OpenAction",
                        "target_obj": tgt,
                        "uri": td.get("URI") if isinstance(td.get("URI"), str) else None,
                        "js_preview": td.get("JS") if isinstance(td.get("JS"), str) else None,
                        "notes": ["auto-exec on open"],
                    })
            aa = d.get("AA")
            if isinstance(aa, dict):
                for k, v in list(aa.items()):
                    if isinstance(v, dict) and "ref" in v:
                        tgt = v["ref"]
                        tb = get_blob(tgt)
                        if tb:
                            td = _parse_simple_dict(tb)
                            acts.append({
                                "source_obj": f"{cat[0]} {cat[1]} R",
                                "action_type": "AA",
                                "target_obj": tgt,
                                "uri": td.get("URI") if isinstance(td.get("URI"), str) else None,
                                "js_preview": td.get("JS") if isinstance(td.get("JS"), str) else None,
                                "notes": [f"AA event {k}"],
                            })
    static_pdf["actions"] = acts

    # Names trees (EmbeddedFiles / JavaScript) — simplified
    if cat is not None:
        b = get_blob(f"{cat[0]} {cat[1]} R")
        if b:
            d = _parse_simple_dict(b)
            names_ref = d.get("Names")
            names_dict: Dict[str, Any] = {}
            if isinstance(names_ref, dict) and "ref" in names_ref:
                names_dict = deref_dict(names_ref["ref"]) or {}
            elif isinstance(names_ref, dict):
                names_dict = names_ref
            for catk in ("EmbeddedFiles", "JavaScript"):
                sub = names_dict.get(catk)
                subd: Dict[str, Any] = {}
                if isinstance(sub, dict) and "ref" in sub:
                    subd = deref_dict(sub["ref"]) or {}
                elif isinstance(sub, dict):
                    subd = sub
                arr = subd.get("Names") if isinstance(subd, dict) else None
                if isinstance(arr, list):
                    for i in range(0, len(arr), 2):
                        nm = arr[i] if i < len(arr) else None
                        rf = arr[i + 1] if i + 1 < len(arr) else None
                        if isinstance(nm, str) and isinstance(rf, dict) and "ref" in rf:
                            entry = {"category": catk, "name": nm, "obj_ref": rf["ref"]}
                            if catk == "EmbeddedFiles":
                                entry["size_hint"] = None
                            static_pdf["names"].append(entry)

    # Embedded files — hash raw stream bytes and preview
    for (o, g), v in objects.items():
        if "embedded_file" in (v.get("annotations") or []):
            desc = {
                "name": None,
                "obj_ref": f"{o} {g} R",
                "size_hint": (v.get("stream") or {}).get("raw_stream_len"),
                "sha256_raw": None,
                "preview_first_bytes": None,
                "preview_truncated": False,
            }
            off = obj_off.get((o, g))
            if off is not None:
                end = data.find(b"endobj", off)
                bts = data[off : min(end + 6, len(data))]
                sp = bts.find(b"stream")
                ep = bts.find(b"endstream", sp)
                if sp != -1 and ep != -1:
                    raw = bts[sp + len(b"stream") : ep].lstrip(b"\r\n")
                    desc["sha256_raw"] = hashlib.sha256(raw).hexdigest()
                    pb = raw[:64]
                    desc["preview_first_bytes"] = _trim_ascii(pb, 120)
                    desc["preview_truncated"] = len(raw) > len(pb)
            static_pdf["embedded_files"].append(desc)
    counts["embedded_files_total"] = len(static_pdf["embedded_files"])

    # JavaScript detection and analysis
    js_objects = []
    js_keywords = ["javascript", "js", "eval", "unescape", "fromcharcode", "activexobject", "wscript"]
    
    # Check for JavaScript in actions
    for action in acts:
        if action.get("js_preview"):
            js_objects.append({
                "type": "action",
                "source": action.get("source_obj"),
                "content": action["js_preview"][:500]  # Truncate for safety
            })
    
    # Check for JavaScript in Names tree
    for name_entry in static_pdf["names"]:
        if name_entry.get("category") == "JavaScript":
            # Try to get the JavaScript content
            ref = name_entry.get("obj_ref")
            if ref:
                blob = get_blob(ref)
                if blob:
                    # Look for /JS key in the object
                    js_match = re.search(rb"/JS\s*\((.*?)\)", blob, re.DOTALL)
                    if js_match:
                        js_content = js_match.group(1).decode('latin-1', errors='ignore')
                        js_objects.append({
                            "type": "named_js",
                            "name": name_entry.get("name"),
                            "source": ref,
                            "content": js_content[:500]  # Truncate for safety
                        })
    
    # Check for JavaScript patterns in decoded streams
    for (o, g), v in objects.items():
        prev = (v.get("stream") or {}).get("decoded_preview")
        if isinstance(prev, str):
            # Look for JavaScript keywords
            prev_lower = prev.lower()
            for keyword in js_keywords:
                if keyword in prev_lower:
                    # Check if it looks like actual JavaScript code
                    if any(pattern in prev_lower for pattern in ["function", "var ", "app.", "console.", "alert("]):
                        js_objects.append({
                            "type": "stream_js",
                            "source": f"{o} {g} R",
                            "content": prev[:500],  # Truncate for safety
                            "detected_keywords": [kw for kw in js_keywords if kw in prev_lower]
                        })
                        break
    
    # Check for JavaScript in object dictionaries
    for (o, g), v in objects.items():
        dict_keys = v.get("dict_keys", [])
        if "JS" in dict_keys or "JavaScript" in dict_keys:
            # This object likely contains JavaScript
            off = obj_off.get((o, g))
            if off is not None:
                end = data.find(b"endobj", off)
                obj_data = data[off:end] if end != -1 else data[off:off+2048]
                
                # Look for JavaScript content
                js_match = re.search(rb"/JS\s*\((.*?)\)", obj_data, re.DOTALL)
                if js_match:
                    js_content = js_match.group(1).decode('latin-1', errors='ignore')
                    js_objects.append({
                        "type": "object_js",
                        "source": f"{o} {g} R",
                        "content": js_content[:500]  # Truncate for safety
                    })
    
    # Set JavaScript detection results
    static_pdf["javascript"] = {
        "present": len(js_objects) > 0,
        "objects": js_objects
    }
    counts["js_objects_total"] = len(js_objects)
    counts["auto_actions_total"] = len([a for a in acts if "auto-exec" in str(a.get("notes", []))])

    # URLs from decoded previews
    url_re = re.compile(r"https?://[\w\-\./?#%&=:+,@~]+", re.I)
    urls: List[str] = []
    for v in objects.values():
        prev = (v.get("stream") or {}).get("decoded_preview")
        if isinstance(prev, str):
            urls += url_re.findall(prev)
    counts["urls_total"] = len(set(urls))
    counts["ioc_urls_total"] = len(set(urls))

    # Metadata / encryption (last trailer)
    last = static_pdf["trailers"][-1] if static_pdf["trailers"] else None
    if last:
        try:
            info_ref = last.get("info_obj")
            blob = get_blob(info_ref) if info_ref else None
            if blob:
                # Try regex-based parsing first
                info_kv = _parse_info_kv(blob)
                if info_kv:
                    for k, v in info_kv.items():
                        if v and v.strip():  # Only set non-empty values
                            static_pdf["metadata"][k] = v
                
                # Always try the generic dict parser as well (may catch different formats)
                try:
                    info = deref_dict(info_ref)
                    if info:
                        date_fields = {"CreationDate", "ModDate"}
                        for k in ("Producer", "Creator", "CreationDate", "ModDate", "Title", "Author", "Subject", "Keywords"):
                            v = info.get(k)
                            if isinstance(v, str) and v.strip():
                                # Special validation for date fields
                                if k in date_fields:
                                    # Only accept if it looks like a valid PDF date
                                    if (v.startswith('D:') or 
                                        re.match(r'\d{4}[-/]\d{2}[-/]\d{2}', v) or
                                        re.match(r'D:\d{8,14}', v)):
                                        # Only override if we don't have a date or this one is better
                                        if not static_pdf["metadata"].get(k):
                                            static_pdf["metadata"][k] = v
                                else:
                                    # For non-date fields, use length-based preference
                                    if (not static_pdf["metadata"].get(k) or len(v) > len(static_pdf["metadata"].get(k, ""))):
                                        static_pdf["metadata"][k] = v
                            elif v is None and k not in static_pdf["metadata"]:
                                static_pdf["metadata"][k] = None
                except Exception:
                    pass
                    
            # If we still don't have metadata, try to find Info dictionary manually
            if not any(static_pdf["metadata"].values()):
                try:
                    # Look for Info dictionary patterns in the raw data
                    info_pattern = re.compile(rb"/Info\s+(\d+\s+\d+\s+R)", re.I)
                    info_matches = info_pattern.findall(data)
                    for match in info_matches:
                        ref = match.decode('ascii', errors='ignore')
                        blob = get_blob(ref)
                        if blob:
                            info_kv = _parse_info_kv(blob)
                            date_fields = {"CreationDate", "ModDate"}
                            for k, v in info_kv.items():
                                if v and v.strip() and not static_pdf["metadata"].get(k):
                                    # Extra validation for date fields
                                    if k in date_fields:
                                        if (v.startswith('D:') or 
                                            re.match(r'\d{4}[-/]\d{2}[-/]\d{2}', v) or
                                            re.match(r'D:\d{8,14}', v)):
                                            static_pdf["metadata"][k] = v
                                    else:
                                        static_pdf["metadata"][k] = v
                            break
                except Exception:
                    pass
                    
        except Exception as e:
            errors.append(f"info_deref_error:{e}")
        try:
            enc = deref_dict(last.get("encrypt_obj"))
            if enc:
                for k in ("Filter", "V", "R", "Length", "P", "CF", "StmF", "StrF"):
                    static_pdf["encryption"][k] = enc.get(k)
        except Exception as e:
            errors.append(f"encrypt_deref_error:{e}")

    return {"static": {"pdf": static_pdf}, "counts": counts, "errors": errors}
