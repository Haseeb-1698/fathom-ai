import argparse
import hashlib
import json
import os
import struct
import sys
import time
import zipfile
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# --- YARA support ---
try:
    import yara  # pip install yara-python
except Exception:
    yara = None

# Import YARA loader utilities
try:
    from .yara_loader import (
        YaraConfig,
        DEFAULT_YARA_EXTERNALS,
        compile_yara_rules,
        discover_yara_rules,
        get_yara_externals_for_path,
        load_yara_denylist,
    )
except ImportError:
    try:
        # Try absolute import for CLI usage
        from yara_loader import (
            YaraConfig,
            DEFAULT_YARA_EXTERNALS,
            compile_yara_rules,
            discover_yara_rules,
            get_yara_externals_for_path,
            load_yara_denylist,
        )
    except ImportError:
        # Fallback if yara_loader not available
        YaraConfig = None
        DEFAULT_YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": ""}
        discover_yara_rules = None
        compile_yara_rules = None
        get_yara_externals_for_path = None
        load_yara_denylist = None

# =========================
# Config / Limits
# =========================
TINY_FILE_MIN_BYTES = 64           # early reject for impossible headers
READ_CHUNK = 1 << 20               # 1MB hashing chunk
PDF_TAIL_SCAN = 8192               # scan tail for EOF/startxref
PDF_HEADER_WINDOW = 1024           # allow header within first 1KB (per spec)
HEAD_SCAN_MAX = 131072             # 128KB for quick PDF obj hints
ZIP_MAX_ENTRIES = 5000             # guard vs. zip-bombs
ZIP_MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024  # 500MB total
PROBE_TIMEOUT_S = 1.5              # soft timeout per ZIP/PDF probe thread
DETECTOR_SIZE_LIMIT = 64 * 1024 * 1024  # align with API cap (64MB)

# =========================
# YARA (paths / limits)
# =========================
# Default to your Windows folder; you can override with --yara-dir
YARA_DIR_DEFAULT = Path(r"D:\FYP - Research Material\File Scan\server\detector\rules\yara")
YARA_TIMEOUT_S_DEFAULT = 1

# These globals get set in main() so detect() can see them
YARA_DIR = YARA_DIR_DEFAULT
YARA_TIMEOUT_S = YARA_TIMEOUT_S_DEFAULT

# Global for pre-compiled YARA rules (new multi-directory system)
YARA_COMPILED_RULES = None
YARA_RULE_MAPPING = {}  # Maps rule names to their categories and source files

# Initialize YARA rules at module import (for API usage)
def _initialize_yara_rules():
    """Initialize YARA rules when module is imported (for API usage)"""
    global YARA_COMPILED_RULES, YARA_RULE_MAPPING
    
    if YaraConfig and discover_yara_rules and compile_yara_rules and yara:
        try:
            import logging
            logger = logging.getLogger(__name__)
            
            # Create default configuration
            config = YaraConfig.default()
            
            # Discover rules
            logger.info("Initializing YARA rules from multiple directories...")
            denylisted_rules = load_yara_denylist(config.denylist_path) if load_yara_denylist else set()
            rule_files = discover_yara_rules(config.rule_directories, config.enabled_categories, denylisted_rules)
            logger.info(f"Found {len(rule_files)} YARA rule files")
            
            # Compile rules
            compiled_rules, errors = compile_yara_rules(rule_files, timeout=config.compile_timeout, externals=DEFAULT_YARA_EXTERNALS)
            
            if compiled_rules:
                YARA_COMPILED_RULES = compiled_rules
                YARA_RULE_MAPPING = rule_files
                logger.info(f"Successfully compiled YARA rules for API usage")
                if errors:
                    logger.warning(f"{len(errors)} rules failed to compile")
            else:
                logger.warning("Failed to compile YARA rules, YARA scanning will use legacy mode")
                
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to initialize YARA rules: {e}")

# Auto-initialize when imported (for API usage)
_initialize_yara_rules()

# =========================
# Helpers
# =========================
def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(READ_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def file_size(path: Path) -> int:
    return path.stat().st_size

def read_at(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as f:
        f.seek(offset)
        return f.read(size)

def read_head(path: Path, size: int) -> bytes:
    with path.open("rb") as f:
        return f.read(size)

def safe_decode_ascii(b: bytes) -> str:
    return b.decode("ascii", errors="ignore")

def run_with_timeout(fn, timeout_s: float) -> Tuple[bool, Any, Optional[str]]:
    """
    Run fn() in a thread; return (ok, result, error_msg_or_none).
    ok=False if thread exceeded timeout or raised.
    """
    result_holder = {"ok": False, "result": None, "err": None}

    def _runner():
        try:
            result_holder["result"] = fn()
            result_holder["ok"] = True
        except Exception as e:
            result_holder["err"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        return (False, None, f"timeout>{timeout_s}s")
    if not result_holder["ok"]:
        return (False, None, result_holder["err"])
    return (True, result_holder["result"], None)

# =========================
# Constants (signatures)
# =========================
CFB_MAGIC = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")  # OLE Compound File
ZIP_LOCAL_MAGIC = b"PK\x03\x04"
ZIP_CENTRAL_MAGIC = b"PK\x01\x02"
ZIP_END_MAGIC = b"PK\x05\x06"
PDF_MAGIC_PREFIX = b"%PDF-"
MZ_MAGIC = b"MZ"
PE_MAGIC = b"PE\0\0"

# =========================
# PE / DLL detection (hardened)
# =========================
def parse_pe_headers(path: Path, fsize: int) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "is_pe": False,
        "pe_offset": None,
        "pe_signature_ok": None,
        "machine": None,
        "number_of_sections": None,
        "timedatestamp": None,
        "size_of_optional_header": None,
        "characteristics_hex": None,
        "is_dll": None,
        "errors": []
    }

    # Need at least DOS header + e_lfanew
    if fsize < 64:
        info["errors"].append("too_small_for_pe")
        return info

    try:
        head = read_head(path, 64)
        if not head.startswith(MZ_MAGIC):
            return info  # not PE
    except Exception as e:
        info["errors"].append(f"read_head_error:{e}")
        return info

    # e_lfanew at 0x3C (DWORD)
    try:
        e_lfanew_bytes = head[0x3C:0x40]
        if len(e_lfanew_bytes) != 4:
            info["errors"].append("e_lfanew_missing")
            return info
        pe_offset = struct.unpack("<I", e_lfanew_bytes)[0]
        info["pe_offset"] = pe_offset

        # bounds checks: signature + file header (24 bytes total)
        if pe_offset > fsize - 24:
            info["errors"].append("e_lfanew_out_of_bounds")
            return info

        pe_sig = read_at(path, pe_offset, 4)
        if pe_sig != PE_MAGIC:
            info["pe_signature_ok"] = False
            return info
        info["pe_signature_ok"] = True
        info["is_pe"] = True

        file_header = read_at(path, pe_offset + 4, 20)
        if len(file_header) != 20:
            info["errors"].append("file_header_truncated")
            return info

        machine, nsect, tstamp, ptrsym, numsym, sz_opt, ch = struct.unpack("<HHLLLHH", file_header)
        info["machine"] = f"0x{machine:04X}"
        info["number_of_sections"] = nsect
        info["timedatestamp"] = tstamp
        info["size_of_optional_header"] = sz_opt
        info["characteristics_hex"] = f"0x{ch:04X}"
        info["is_dll"] = bool(ch & 0x2000)  # IMAGE_FILE_DLL
    except Exception as e:
        info["errors"].append(f"parse_error:{e}")

    return info

# =========================
# PDF detection (hardened)
# =========================
def detect_pdf(path: Path, fsize: int) -> Dict[str, Any]:
    result = {"is_pdf": False, "version": None, "has_eof": None, "has_startxref": None, "obj_count_hint": None, "is_encrypted": None, "errors": []}
    if fsize < len(PDF_MAGIC_PREFIX):
        return result

    # Search for %PDF- within first 1KB to be robust to leading bytes
    try:
        window = min(max(PDF_HEADER_WINDOW, 16), fsize)
        head = read_head(path, window)
        off = head.find(PDF_MAGIC_PREFIX)
        if off == -1:
            return result
        result["is_pdf"] = True
        header_slice = head[off:off+8]
        header_txt = safe_decode_ascii(header_slice)
        version = header_txt[5:8] if header_txt.startswith("%PDF-") else None
        result["version"] = version
    except Exception as e:
        result["errors"].append(f"head_error:{e}")
        return result

    # Tail scan for %%EOF and startxref
    try:
        tail_read = min(fsize, PDF_TAIL_SCAN)
        if tail_read > 0:
            tail = read_at(path, fsize - tail_read, tail_read)
            result["has_eof"] = (b"%%EOF" in tail)
            result["has_startxref"] = (b"startxref" in tail)
            # quick encrypt token hint in tail
            tail_has_encrypt = (b"/Encrypt" in tail) or (b"/Encrypt" in head)
            result["is_encrypted"] = bool(tail_has_encrypt)
        else:
            result["has_eof"] = False
            result["has_startxref"] = False
    except Exception as e:
        result["errors"].append(f"tail_error:{e}")

    # obj count hint (first 128KB)
    try:
        head_scan = read_head(path, min(HEAD_SCAN_MAX, fsize))
        result["obj_count_hint"] = head_scan.count(b" obj")
        if result.get("is_encrypted") is None:
            result["is_encrypted"] = bool(b"/Encrypt" in head_scan)
    except Exception as e:
        result["errors"].append(f"obj_hint_error:{e}")
        result["obj_count_hint"] = None

    return result

def detect_pdf_with_timeout(path: Path, fsize: int) -> Dict[str, Any]:
    def _work():
        return detect_pdf(path, fsize)
    ok, res, err = run_with_timeout(_work, PROBE_TIMEOUT_S)
    if not ok:
        return {"is_pdf": False, "errors": [err], "version": None, "has_eof": None, "has_startxref": None, "obj_count_hint": None}
    return res

# =========================
# OOXML (ZIP) detection (hardened)
# =========================
def detect_ooxml_zip(path: Path, fsize: int) -> Dict[str, Any]:
    out = {
        "is_ooxml": False,
        "zip_open_ok": None,
        "has_content_types": None,
        "families": [],
        "has_vba_project": None,
        "has_encryption": None,
        "entry_count": None,
        "total_uncompressed": None,
        "errors": []
    }

    # Quick ZIP signature check
    try:
        head4 = read_head(path, 4)
        if not (head4.startswith(ZIP_LOCAL_MAGIC) or head4.startswith(ZIP_CENTRAL_MAGIC) or head4.startswith(ZIP_END_MAGIC)):
            return out
    except Exception as e:
        out["errors"].append(f"head_error:{e}")
        return out

    try:
        with zipfile.ZipFile(path, "r") as z:
            # Corruption test
            bad = z.testzip()
            if bad is not None:
                out["zip_open_ok"] = False
                out["errors"].append(f"zip_corrupt_entry:{bad}")
                return out
            out["zip_open_ok"] = True

            infos = z.infolist()
            entry_count = len(infos)
            out["entry_count"] = entry_count

            if entry_count > ZIP_MAX_ENTRIES:
                out["errors"].append("zip_too_many_entries")
                # Still proceed to gather minimal info, but will not mark as OOXML

            total_uncompressed = sum(i.file_size for i in infos)
            out["total_uncompressed"] = int(total_uncompressed)
            if total_uncompressed > ZIP_MAX_TOTAL_UNCOMPRESSED:
                out["errors"].append("zip_total_uncompressed_cap")

            names = set(i.filename for i in infos)
            has_content_types = "[Content_Types].xml" in names
            out["has_content_types"] = has_content_types

            fams = []
            if any(n.startswith("word/") for n in names): fams.append("word")
            if any(n.startswith("xl/") for n in names):   fams.append("xl")
            if any(n.startswith("ppt/") for n in names):  fams.append("ppt")
            out["families"] = fams

            vba_present = any(n.lower().endswith("vbaproject.bin") for n in names)
            out["has_vba_project"] = vba_present

            # OOXML encryption is indicated by these entries
            enc = any(n.endswith("EncryptionInfo") for n in names) and any(n.endswith("EncryptedPackage") for n in names)
            out["has_encryption"] = bool(enc)

            # OOXML must have content types + at least one family, and must not violate bomb caps
            if has_content_types and fams and entry_count <= ZIP_MAX_ENTRIES and total_uncompressed <= ZIP_MAX_TOTAL_UNCOMPRESSED:
                out["is_ooxml"] = True
    except Exception as e:
        out["zip_open_ok"] = False
        out["errors"].append(f"zip_open_error:{e}")

    return out

def detect_ooxml_with_timeout(path: Path, fsize: int) -> Dict[str, Any]:
    def _work():
        return detect_ooxml_zip(path, fsize)
    ok, res, err = run_with_timeout(_work, PROBE_TIMEOUT_S)
    if not ok:
        return {
            "is_ooxml": False, "zip_open_ok": False, "errors": [err],
            "has_content_types": None, "families": [], "has_vba_project": None,
            "entry_count": None, "total_uncompressed": None
        }
    return res

# =========================
# OLE (CFB) detection (hardened)
# =========================
def detect_ole_cfb(path: Path, fsize: int) -> Dict[str, Any]:
    out = {"is_ole": False, "sector_shift": None, "mini_sector_shift": None, "has_vba_project": None, "errors": []}
    if fsize < 512:
        return out
    try:
        hdr = read_head(path, 512)
    except Exception as e:
        out["errors"].append(f"read_error:{e}")
        return out

    if hdr[:8] != CFB_MAGIC:
        return out

    # Basic header sanity (per MS-CFB): sector shifts at 0x1E (2 bytes) and 0x20 (2 bytes)
    try:
        sector_shift = struct.unpack("<H", hdr[0x1E:0x20])[0]  # typically 0x0009 (512) or 0x000C (4096)
        mini_sector_shift = struct.unpack("<H", hdr[0x20:0x22])[0]  # typically 0x0006 (64)
        # Valid shifts are powers-of-two exponents in a small set
        valid_sector = sector_shift in (9, 12)        # 2^9=512, 2^12=4096
        valid_mini = mini_sector_shift == 6           # 2^6=64
        if not (valid_sector and valid_mini):
            out["errors"].append("cfb_sector_shift_invalid")
        out["sector_shift"] = sector_shift
        out["mini_sector_shift"] = mini_sector_shift
    except Exception as e:
        out["errors"].append(f"cfb_parse_error:{e}")

    out["is_ole"] = True

    # Heuristic macro flag: search early bytes for common UTF-16LE stream names
    try:
        scan_n = min(64 * 1024, fsize)
        blob = read_head(path, scan_n)
        # UTF-16LE names as found in directory entries
        pat_vba = b"V\x00B\x00A\x00"
        pat_proj = b"P\x00R\x00O\x00J\x00E\x00C\x00T\x00"
        pat_dir = b"d\x00i\x00r\x00"
        found = any(p in blob for p in (pat_vba, pat_proj, pat_dir))
        out["has_vba_project"] = bool(found)
    except Exception as e:
        out["errors"].append(f"macro_probe_error:{e}")
        out["has_vba_project"] = None
    return out

# =========================
# YARA scan (helper)
# =========================
def yara_scan_file(path: Path, yara_dir: Path, timeout_s: float, compiled_rules=None, rule_mapping=None) -> Dict[str, Any]:
    """
    Run YARA on `path` using pre-compiled rules or rules from `yara_dir`.
    
    Args:
        path: Path to file to scan
        yara_dir: Directory containing .yar rules (legacy mode, used if compiled_rules is None)
        timeout_s: Scan timeout in seconds
        compiled_rules: Pre-compiled yara.Rules object (new multi-directory system)
        rule_mapping: Dictionary mapping rule IDs to categories and source files
    
    Returns: {"matches":[{rule,tags,meta,category,source_file}], "errors":[...], "stats":{...}}
    """
    out: Dict[str, Any] = {"matches": [], "errors": [], "stats": {}}

    if yara is None:
        out["errors"].append("yara_module_not_available")
        return out

    # Use pre-compiled rules if available (new system)
    if compiled_rules is not None:
        try:
            match_externals = get_yara_externals_for_path(path) if get_yara_externals_for_path else {"filename": path.name, "filepath": str(path), "extension": path.suffix.lower()}
            results = compiled_rules.match(str(path), timeout=int(timeout_s), externals=match_externals)
            
            for m in results:
                match_info = {
                    "rule": m.rule,
                    "tags": list(m.tags) if hasattr(m, "tags") else [],
                    "meta": dict(m.meta) if hasattr(m, "meta") and m.meta else {}
                }
                
                # Add category and source file information if available
                if rule_mapping:
                    # Try to find the rule in the mapping
                    # The namespace in YARA matches corresponds to the rule_id we used
                    rule_namespace = m.namespace if hasattr(m, "namespace") else None
                    if rule_namespace and rule_namespace in rule_mapping:
                        category = rule_namespace.split('/')[0] if '/' in rule_namespace else "unknown"
                        match_info["category"] = category
                        match_info["source_file"] = rule_mapping[rule_namespace]
                    else:
                        # Fallback: try to infer from rule name
                        match_info["category"] = "unknown"
                        match_info["source_file"] = "unknown"
                else:
                    match_info["category"] = "unknown"
                    match_info["source_file"] = "unknown"
                
                out["matches"].append(match_info)
            
            # Add stats
            out["stats"]["rules_used"] = "multi_directory"
            
        except yara.TimeoutError:
            out["errors"].append("yara_timeout")
        except Exception as e:
            out["errors"].append(f"yara_error:{type(e).__name__}:{e}")
        
        return out
    
    # Legacy mode: compile rules from single directory
    try:
        if not yara_dir.exists():
            out["errors"].append(f"yara_dir_missing:{yara_dir}")
            return out

        rule_files = {p.stem: str(p) for p in yara_dir.glob("*.yar")}
        if not rule_files:
            out["errors"].append(f"no_yara_rules_in:{yara_dir}")
            return out

        rules = yara.compile(filepaths=rule_files, externals=DEFAULT_YARA_EXTERNALS)
        match_externals = get_yara_externals_for_path(path) if get_yara_externals_for_path else {"filename": path.name, "filepath": str(path), "extension": path.suffix.lower()}
        results = rules.match(str(path), timeout=int(timeout_s), externals=match_externals)

        for m in results:
            out["matches"].append({
                "rule": m.rule,
                "tags": list(m.tags) if hasattr(m, "tags") else [],
                "meta": dict(m.meta) if hasattr(m, "meta") and m.meta else {},
                "category": "legacy",
                "source_file": yara_dir.name
            })
        
        # Add stats
        out["stats"]["rules_used"] = "legacy_single_directory"

    except yara.TimeoutError:
        out["errors"].append("yara_timeout")
    except Exception as e:
        out["errors"].append(f"yara_error:{type(e).__name__}:{e}")

    return out

# =========================
# Main detector
# =========================
def detect_signatures_and_headers(path: Path) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "filename": path.name,
        "path": str(path),
        "size_bytes": None,
        "sha256": None,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signatures": {},
        "final_guess": {"type": "unknown", "reasons": []}
    }

    try:
        fsize = file_size(path)
        record["size_bytes"] = fsize
        record["sha256"] = sha256_of_file(path)
    except Exception as e:
        record["final_guess"]["reasons"].append(f"meta_error:{e}")
        return record

    # Size cap guard to keep analysis safe in CLI mode too
    if fsize > DETECTOR_SIZE_LIMIT:
        record["final_guess"]["type"] = "unknown"
        record["final_guess"]["reasons"].append("size_over_limit")
        # Still attach minimal signatures/yara if desired, but we bail early to satisfy policy
        record["confidence"] = 0
        record["confidence_level"] = "low"
        return record

    # Tiny/truncated guard
    if fsize < TINY_FILE_MIN_BYTES:
        record["final_guess"]["type"] = "unknown"
        record["final_guess"]["reasons"].append("too_small_for_headers")
        return record

    # Run probes (with timeouts for PDF/ZIP)
    pe_info = parse_pe_headers(path, fsize)
    pdf_info = detect_pdf_with_timeout(path, fsize)
    ooxml_info = detect_ooxml_with_timeout(path, fsize)
    ole_info = detect_ole_cfb(path, fsize)

    record["signatures"]["pe"] = pe_info
    record["signatures"]["pdf"] = pdf_info
    record["signatures"]["office_ooxml"] = ooxml_info
    record["signatures"]["office_ole"] = ole_info

    # --- Heuristics: YARA (using configured globals from main) ---
    try:
        heur_yara = yara_scan_file(path, YARA_DIR, YARA_TIMEOUT_S, YARA_COMPILED_RULES, YARA_RULE_MAPPING)
    except Exception as e:
        heur_yara = {"matches": [], "errors": [f"yara_wrapper_error:{e}"], "stats": {}}

    record.setdefault("heuristics", {})
    record["heuristics"]["yara"] = heur_yara

    # Decision priority: PE/DLL → PDF → OOXML → OLE
    if pe_info.get("is_pe") and pe_info.get("pe_signature_ok"):
        if pe_info.get("is_dll"):
            record["final_guess"]["type"] = "dll"
            record["final_guess"]["reasons"].extend(["MZ", "PE signature", "DLL flag"])
        else:
            record["final_guess"]["type"] = "pe"
            record["final_guess"]["reasons"].extend(["MZ", "PE signature"])
        # proceed to post-processing (extension, confidence, entropy)
    elif pdf_info.get("is_pdf"):
        record["final_guess"]["type"] = "pdf"
        r = ["%PDF- header"]
        if pdf_info.get("has_eof") is True:
            r.append("%%EOF in tail")
        elif pdf_info.get("has_startxref") is True:
            r.append("startxref in tail")
        record["final_guess"]["reasons"].extend(r)
    elif ooxml_info.get("zip_open_ok") and ooxml_info.get("is_ooxml"):
        fams = ooxml_info.get("families") or []
        reason = "OOXML container"
        if fams:
            reason += f" ({','.join(fams)})"
        record["final_guess"]["type"] = "office_ooxml"
        record["final_guess"]["reasons"].append(reason)
    elif ole_info.get("is_ole"):
        record["final_guess"]["type"] = "office_ole"
        reasons = ["OLE/CFB magic"]
        if "cfb_sector_shift_invalid" in (ole_info.get("errors") or []):
            reasons.append("header_suspicious")
        record["final_guess"]["reasons"].extend(reasons)
    else:
        # Fallback
        record["final_guess"]["type"] = "unknown"
        record["final_guess"]["reasons"].append("no known signature/header matched")

    # Post-processing enrichments
    _post_enrich_record(record)
    # Optional: deep static enrich (currently PDF only)
    try:
        _enrich_static(record)
    except Exception:
        pass
    return record

def _post_enrich_record(record: Dict[str, Any]) -> None:
    """Enrich record with extension-mismatch, entropy (PE), and confidence score.
    Safe: never raises; appends to errors/reasons where applicable.
    """
    try:
        # 1) Extension consistency check
        ext = _safe_ext(record.get("filename"))
        final_type = (record.get("final_guess") or {}).get("type")
        mismatch = _is_extension_mismatch(final_type, ext)
        if mismatch:
            record["final_guess"]["reasons"].append("extension_mismatch")

        # 2) Entropy summary for PE
        try:
            if final_type in ("pe", "dll") and (record.get("signatures", {}).get("pe") or {}).get("is_pe"):
                ent = _entropy_summary_for_pe(Path(record.get("path")))
                record.setdefault("heuristics", {})
                record["heuristics"]["entropy"] = ent
        except Exception as e:
            record.setdefault("heuristics", {})
            record["heuristics"].setdefault("errors", [])
            record["heuristics"]["errors"].append(f"entropy_error:{e}")

        # 3) Confidence
        conf = compute_confidence(record)
        record.update(conf)
    except Exception:
        # Hard safeguard; do not let enrich fail the call
        pass

def _safe_ext(name: Optional[str]) -> Optional[str]:
    if not name or not isinstance(name, str):
        return None
    if "." not in name:
        return None
    return name.rsplit(".", 1)[-1].lower()

def _is_extension_mismatch(final_type: Optional[str], ext: Optional[str]) -> bool:
    if not ext or not final_type:
        return False
    mapping = {
        "pdf": {"pdf"},
        "pe": {"exe"},
        "dll": {"dll"},
        "office_ooxml": {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm"},
        "office_ole": {"doc", "xls", "ppt"},
    }
    allowed = mapping.get(final_type)
    if not allowed:
        return False
    return ext not in allowed

# Import professional entropy calculation
try:
    from .entropy_utils import calculate_shannon_entropy
except ImportError:
    # Fallback if scipy not available
    def calculate_shannon_entropy(data: bytes) -> float:
        import math
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        h = 0.0
        total = len(data)
        for c in counts:
            if c:
                p = c / total
                h -= p * math.log(p, 2)
        return float(h)

def _entropy_summary_for_pe(path: Path) -> Dict[str, Any]:
    """Compute overall file entropy and max section entropy for a PE.
    Best-effort; reads sections from COFF table if present. Returns
    {"overall": float, "max_section": Optional[float]}.
    """
    out: Dict[str, Any] = {"overall": None, "max_section": None}
    try:
        # overall entropy (read up to 4MB for calculation)
        try:
            with path.open("rb") as f:
                data = f.read(4 * 1024 * 1024)  # Read up to 4MB
            out["overall"] = calculate_shannon_entropy(data)
        except Exception:
            out["overall"] = None
    except Exception:
        out["overall"] = None

    # section max (lightweight PE table parse)
    try:
        with path.open("rb") as f:
            head = f.read(0x100)
            if head[:2] != b"MZ":
                return out
            e_lfanew = struct.unpack("<I", head[0x3C:0x40])[0]
            f.seek(e_lfanew)
            if f.read(4) != PE_MAGIC:
                return out
            file_hdr = f.read(20)
            _, nsect, _, _, _, sz_opt, _ = struct.unpack("<HHLLLHH", file_hdr)
            f.seek(e_lfanew + 4 + 20 + sz_opt)
            max_h = None
            for _i in range(int(nsect)):
                sh = f.read(40)
                if len(sh) < 40:
                    break
                # section header fields
                raw_size = struct.unpack("<I", sh[16:20])[0]
                raw_ptr = struct.unpack("<I", sh[20:24])[0]
                if raw_size == 0:
                    continue
                try:
                    with path.open("rb") as sf:
                        sf.seek(raw_ptr)
                        data = sf.read(min(raw_size, 512 * 1024))  # cap
                    if data:
                        h = calculate_shannon_entropy(data)
                        max_h = h if max_h is None else max(max_h, h)
                except Exception:
                    continue
            out["max_section"] = max_h
    except Exception:
        pass
    return out

def compute_confidence(record: Dict[str, Any]) -> Dict[str, Any]:
    """Fuse signals into a numeric score [0,100] and qualitative level.
    Scoring (approx):
      +45 magic/header verified
      +45 structural probe success
      +10 extension match
      +8 each YARA "strong"
      +2 each YARA "hint"
      -10 extension mismatch
      +5 macro flag (OOXML/OLE)
    """
    score = 0
    final_type = (record.get("final_guess") or {}).get("type")
    sig = record.get("signatures", {})
    reasons = (record.get("final_guess") or {}).get("reasons", [])

    # Magic/header + structural
    if final_type in ("pe", "dll"):
        pe = sig.get("pe", {})
        if pe.get("is_pe") and pe.get("pe_signature_ok"):
            score += 45
        if pe.get("number_of_sections"):
            score += 45
    elif final_type == "pdf":
        pdf = sig.get("pdf", {})
        if pdf.get("is_pdf"):
            score += 45
        if pdf.get("has_eof") or pdf.get("has_startxref"):
            score += 45
    elif final_type == "office_ooxml":
        oox = sig.get("office_ooxml", {})
        if oox.get("zip_open_ok"):
            score += 45
        if oox.get("is_ooxml"):
            score += 45
        if oox.get("has_vba_project"):
            score += 5
    elif final_type == "office_ole":
        ole = sig.get("office_ole", {})
        if ole.get("is_ole"):
            score += 45
        if not ("cfb_sector_shift_invalid" in (ole.get("errors") or [])):
            score += 45
        if ole.get("has_vba_project"):
            score += 5

    # Extension match/mismatch
    ext = _safe_ext(record.get("filename"))
    if _is_extension_mismatch(final_type, ext):
        score -= 10
    else:
        # Only reward when we have an expected mapping
        mapping_known = final_type in {"pdf", "pe", "dll", "office_ooxml", "office_ole"}
        if mapping_known and ext is not None:
            score += 10

    # YARA tags
    matches = (((record.get("heuristics") or {}).get("yara") or {}).get("matches")) or []
    strong = sum(1 for m in matches if "strong" in (m.get("tags") or []))
    hint = sum(1 for m in matches if "hint" in (m.get("tags") or []))
    score += strong * 8 + hint * 2

    # Bound and label
    score = int(max(0, min(100, score)))
    if score >= 85:
        level = "high"
    elif score >= 60:
        level = "medium"
    else:
        level = "low"

    return {"confidence": score, "confidence_level": level}

# =========================
# Static enrich (PDF full)
# =========================
def _enrich_static(record: Dict[str, Any]) -> None:
    """Add static details per family. Fail-soft.

    Supports PDF via detector.pdf_full.analyze_pdf_full, Office via
    detector.office_full.analyze_office_full, and PE via
    detector.pe_full.analyze_pe_full.
    """
    final_type = (record.get("final_guess") or {}).get("type")
    path = record.get("path")
    if not path:
        return

    # PDF
    if final_type == "pdf":
        try:
            from .pdf_full import analyze_pdf_full  # deferred import
        except Exception:
            return
        try:
            res = analyze_pdf_full(path)
        except Exception as e:
            record.setdefault("errors", [])
            record["errors"].append(f"static_enrich_failed:{e}")
            return
        if not isinstance(res, dict):
            return
        static_pdf = ((res.get("static") or {}).get("pdf"))
        if static_pdf is not None:
            record.setdefault("static", {})
            record["static"]["pdf"] = static_pdf
        counts = res.get("counts") or {}
        if counts:
            record.setdefault("counts", {})
            for k, v in counts.items():
                if k not in record["counts"]:
                    record["counts"][k] = v
        errs = res.get("errors") or []
        if errs:
            record.setdefault("errors", [])
            record["errors"].extend(errs)

    # Office (OOXML / OLE)
    elif final_type in ("office_ooxml", "office_ole"):
        try:
            from .office_full import analyze_office_full  # deferred import
        except Exception:
            return
        try:
            res = analyze_office_full(path)
        except Exception as e:
            record.setdefault("errors", [])
            record["errors"].append(f"office_static_enrich_failed:{e}")
            return
        if not isinstance(res, dict):
            return
        static_office = ((res.get("static") or {}).get("office"))
        if static_office is not None:
            record.setdefault("static", {})
            record["static"]["office"] = static_office
        counts = res.get("counts") or {}
        if counts:
            record.setdefault("counts", {})
            for k, v in counts.items():
                if k not in record["counts"]:
                    record["counts"][k] = v
        errs = res.get("errors") or []
        if errs:
            record.setdefault("errors", [])
            record["errors"].extend(errs)

    # PE / DLL
    elif final_type in ("pe", "dll"):
        try:
            from .pe_full import analyze_pe_full  # deferred import
        except Exception:
            return
        try:
            res = analyze_pe_full(path)
        except Exception as e:
            record.setdefault("errors", [])
            record["errors"].append(f"pe_static_enrich_failed:{e}")
            return
        if not isinstance(res, dict):
            return
        static_pe = ((res.get("static") or {}).get("pe"))
        if static_pe is not None:
            record.setdefault("static", {})
            record["static"]["pe"] = static_pe
        counts = res.get("counts") or {}
        if counts:
            record.setdefault("counts", {})
            for k, v in counts.items():
                if k not in record["counts"]:
                    record["counts"][k] = v
        errs = res.get("errors") or []
        if errs:
            record.setdefault("errors", [])
            record["errors"].extend(errs)

# =========================
# CLI
# =========================
def main() -> None:
    p = argparse.ArgumentParser(description="Hardened header/signature detector for PE/DLL, PDF, and Office (OOXML/OLE).")
    p.add_argument("input", help="Path to the file to analyze")
    p.add_argument("--out", help="Output JSON path (default: <input>.sig.json)")
    p.add_argument("--yara-dir", help="Directory containing .yar rules (legacy mode: single directory only)")
    p.add_argument("--yara-timeout", type=float, help="YARA match timeout in seconds (default: 1.0)")
    p.add_argument("--yara-categories", help="Comma-separated list of categories to enable (e.g., 'filetype,capability')")
    args = p.parse_args()

    # YARA config (override defaults if provided)
    global YARA_DIR, YARA_TIMEOUT_S, YARA_COMPILED_RULES, YARA_RULE_MAPPING
    YARA_TIMEOUT_S = float(args.yara_timeout) if args.yara_timeout else YARA_TIMEOUT_S_DEFAULT
    
    # If --yara-dir is specified, use legacy single-directory mode
    if args.yara_dir:
        YARA_DIR = Path(args.yara_dir)
        YARA_COMPILED_RULES = None
        YARA_RULE_MAPPING = {}
        print(f"Using legacy YARA mode with directory: {YARA_DIR}")
    else:
        # Use new multi-directory system
        if YaraConfig and discover_yara_rules and compile_yara_rules:
            try:
                # Create configuration
                config = YaraConfig.default()
                config.scan_timeout = YARA_TIMEOUT_S
                
                # Parse category filter if provided
                if args.yara_categories:
                    categories = set(c.strip() for c in args.yara_categories.split(','))
                    config.enabled_categories = categories
                    print(f"Enabled YARA categories: {', '.join(sorted(categories))}")
                
                # Discover rules
                print("Discovering YARA rules from multiple directories...")
                denylisted_rules = load_yara_denylist(config.denylist_path) if load_yara_denylist else set()
                rule_files = discover_yara_rules(config.rule_directories, config.enabled_categories, denylisted_rules)
                print(f"Found {len(rule_files)} YARA rule files")
                
                # Compile rules
                print("Compiling YARA rules...")
                compiled_rules, errors = compile_yara_rules(rule_files, timeout=config.compile_timeout, externals=DEFAULT_YARA_EXTERNALS)
                
                if compiled_rules:
                    YARA_COMPILED_RULES = compiled_rules
                    YARA_RULE_MAPPING = rule_files
                    print(f"Successfully compiled YARA rules")
                    if errors:
                        print(f"Warning: {len(errors)} rules failed to compile")
                else:
                    print("Warning: Failed to compile YARA rules, YARA scanning disabled")
                    if errors:
                        print(f"Errors: {errors[:3]}")
                
            except Exception as e:
                print(f"Warning: Failed to initialize multi-directory YARA system: {e}")
                print("Falling back to legacy mode")
                YARA_DIR = YARA_DIR_DEFAULT
                YARA_COMPILED_RULES = None
                YARA_RULE_MAPPING = {}
        else:
            # Fallback to legacy mode if yara_loader not available
            print("YARA loader module not available, using legacy mode")
            YARA_DIR = YARA_DIR_DEFAULT
            YARA_COMPILED_RULES = None
            YARA_RULE_MAPPING = {}

    in_path = Path(args.input)
    if not in_path.exists() or not in_path.is_file():
        print(f"ERROR: input path not found or not a file: {in_path}", file=sys.stderr)
        sys.exit(1)

    try:
        record = detect_signatures_and_headers(in_path)
    except Exception as e:
        record = {"filename": in_path.name, "path": str(in_path), "error": f"unexpected_error:{e}"}

    out_path = Path(args.out) if args.out else in_path.with_suffix(in_path.suffix + ".sig.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)
        print(f"Wrote JSON report to: {out_path}")
    except Exception as e:
        print(f"ERROR: failed to write JSON output: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
