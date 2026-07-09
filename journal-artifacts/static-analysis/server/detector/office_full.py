"""
Office static analyzer (OOXML + legacy OLE/CFB) for Fathom.

Fail-soft, offline-only, 64MB safety cap. Mirrors the overall shape of
detector/pdf_full.py outputs but under static.office.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import io
import json
import re
import struct
import zipfile

# Import professional entropy calculation
try:
    from .entropy_utils import calculate_shannon_entropy as shannon_entropy
except ImportError:
    # Fallback if scipy not available
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        from collections import Counter
        import math
        total = len(data)
        counts = Counter(data)
        return float(-sum((c/total) * math.log2(c/total) for c in counts.values()))

# Import helpers from PDF analyzer to avoid code duplication
try:
    from .pdf_full import extract_global_strings  # type: ignore
except Exception:

    def extract_global_strings(file_bytes: bytes, min_len: int = 6) -> Dict[str, Any]:
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
            ascii_strings: List[str] = []
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, file_bytes):
                s = m.group(0).decode("latin-1", errors="ignore")
                if s:
                    ascii_strings.append(s)
            # UTF-16LE strings
            utf16_strings: List[str] = []
            try:
                dec = file_bytes.decode("utf-16le", errors="ignore")
                for m in re.finditer(r"[\x20-\x7e]{%d,}" % min_len, dec):
                    s = m.group(0)
                    if s:
                        utf16_strings.append(s)
            except Exception:
                pass
            all_strings = ascii_strings + utf16_strings
            out["total"] = len(all_strings)
            uniq, seen = [], set()
            for s in all_strings:
                if s not in seen:
                    seen.add(s)
                    uniq.append(s)
            out["unique"] = len(uniq)
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
            suspects = (
                "powershell", "cmd.exe", "rundll32", "WScript.Shell",
                "ActiveXObject", "shell32.dll", "AutoOpen",
                "Workbook_Open", "Document_Open",
            )
            found = []
            for kw in suspects:
                for s in uniq:
                    if kw.lower() in s.lower():
                        found.append(kw)
                        break
            out["suspicious_keywords"] = found[:20]
            out["sample_strings"] = [(s if len(s) <= 120 else s[:120] + "…") for s in uniq[:10]]
            return out
        except Exception:
            return out


# Configuration
MAX_INPUT_SIZE = 64 * 1024 * 1024          # 64 MB
ZIP_MAX_ENTRIES = 5000
ZIP_MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024
ZIP_MAX_RATIO = 500.0                       # simple compression ratio cap
MAX_EMBED_PREVIEW = 128 * 1024              # cap bytes read for entropy/hash (per embed)
SHELL_INDICATORS = (
    "powershell",
    "cmd.exe",
    "rundll32",
    "wscript.shell",
    "createobject",
    "adodb.stream",
)


def _safe_read(path: Path, max_bytes: int = MAX_INPUT_SIZE) -> bytes:
    try:
        data = path.read_bytes()
        if len(data) > max_bytes:
            return b""
        return data
    except Exception:
        return b""


def _is_ooxml_zip(p: Path) -> bool:
    try:
        if not zipfile.is_zipfile(p):
            return False
        with zipfile.ZipFile(p, "r") as z:
            names = set(i.filename for i in z.infolist())
            return "[Content_Types].xml" in names
    except Exception:
        return False


def _is_ole_cfb(path: Path) -> bool:
    try:
        head = path.read_bytes()[:8]
        return head == bytes.fromhex("D0CF11E0A1B11AE1")
    except Exception:
        return False


def _read_zip_safely(p: Path) -> Tuple[Optional[zipfile.ZipFile], List[str], Dict[str, Any]]:
    errors: List[str] = []
    info: Dict[str, Any] = {}
    try:
        z = zipfile.ZipFile(p, "r")
    except Exception as e:
        errors.append(f"zip_open_error:{e}")
        return None, errors, info
    try:
        entries = z.infolist()
        info["entry_count"] = len(entries)
        if len(entries) > ZIP_MAX_ENTRIES:
            errors.append("zip_too_many_entries")
        total_uncompressed = sum(i.file_size for i in entries)
        info["total_uncompressed"] = int(total_uncompressed)
        if total_uncompressed > ZIP_MAX_TOTAL_UNCOMPRESSED:
            errors.append("zip_total_uncompressed_cap")
        for i in entries:
            name = i.filename
            if name.startswith("/") or ".." in name.replace("\\", "/"):
                errors.append("zip_path_suspicious")
                break
            try:
                if i.compress_size and i.file_size:
                    ratio = max(1.0, i.file_size / max(1, i.compress_size))
                    if ratio > ZIP_MAX_RATIO:
                        errors.append("zip_entry_compression_ratio_insane")
                        break
            except Exception:
                pass
        return z, errors, info
    except Exception as e:
        errors.append(f"zip_scan_error:{e}")
        try:
            z.close()
        except Exception:
            pass
        return None, errors, info


def _parse_content_types(z: zipfile.ZipFile) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    try:
        with z.open("[Content_Types].xml") as f:
            xml = f.read()
    except Exception:
        return mapping
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
        ns = {"ct": "http://schemas.openxmlformats.org/package/2006/content-types"}
        for el in root.findall("ct:Override", ns):
            part = el.attrib.get("PartName") or ""
            ctype = el.attrib.get("ContentType") or ""
            if part.startswith("/"):
                part = part[1:]
            mapping[part] = ctype
        # Defaults by extension (not used for explicit map but could be fallback)
        # We'll skip default extension mapping for brevity; explicit overrides suffice for our purposes.
    except Exception:
        pass
    return mapping


def _parse_rels_xml(blob: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(blob)
        # Relationships use a namespace, but tags may be unprefixed after parsing
        for rel in root.iter():
            if rel.tag.endswith("Relationship"):
                typ = rel.attrib.get("Type") or ""
                tgt = rel.attrib.get("Target") or ""
                ext = (rel.attrib.get("TargetMode") or "").lower() == "external"
                kind = "unknown"
                if "/hyperlink" in typ:
                    kind = "hyperlink"
                elif "/attachedTemplate" in typ:
                    kind = "linkedTemplate"
                elif "/externalLink" in typ:
                    kind = "externalWorkbook"
                elif "/video" in typ or "/audio" in typ:
                    kind = "remoteMedia"
                out.append({"type": kind, "target": tgt, "external": ext})
    except Exception:
        pass
    return out


def _gather_ooxml_structure(z: zipfile.ZipFile) -> Tuple[Dict[str, Any], List[str]]:
    errors: List[str] = []
    parts: List[Dict[str, Any]] = []
    external_refs: List[Dict[str, Any]] = []
    try:
        ctm = _parse_content_types(z)
        names = [i.filename for i in z.infolist()]
        main_part = None
        if "word/document.xml" in names:
            main_part = "word/document.xml"
        elif "xl/workbook.xml" in names:
            main_part = "xl/workbook.xml"
        elif "ppt/presentation.xml" in names:
            main_part = "ppt/presentation.xml"

        for info in z.infolist():
            p = info.filename
            ctype = ctm.get(p)
            rels_path = None
            if "/" in p:
                base, fname = p.rsplit("/", 1)
                rels_path = f"{base}/_rels/{fname}.rels"
            else:
                rels_path = f"_rels/{p}.rels"
            rels: List[Dict[str, Any]] = []
            try:
                if rels_path in z.namelist():
                    with z.open(rels_path) as rf:
                        rels = _parse_rels_xml(rf.read())
                        for r in rels:
                            if r.get("external") or re.match(r"^(https?|\\\\)", r.get("target") or "", re.I):
                                external_refs.append({
                                    "type": r.get("type") or "unknown",
                                    "target": r.get("target") or "",
                                    "where": rels_path,
                                })
            except Exception:
                errors.append("rels_parse_failed")
            parts.append({
                "path": p,
                "content_type": ctype,
                "size_hint": int(info.file_size),
                "relationships": rels,
            })
        structure = {
            "family": "ooxml",
            "main_part": main_part,
            "parts": parts[:1000],
            "external_references": external_refs[:1000],
        }
        return structure, errors
    except Exception as e:
        errors.append(f"ooxml_structure_error:{e}")
        return {"family": "ooxml", "main_part": None, "parts": [], "external_references": []}, errors


def _collect_ooxml_embeds_and_macros(z: zipfile.ZipFile) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], bool, bool, List[str], List[str]]:
    embeds: List[Dict[str, Any]] = []
    macros: List[Dict[str, Any]] = []
    macro_present = False
    suspicious_auto_exec = False
    errors: List[str] = []
    shell_hits: Set[str] = set()
    autoexec_markers = ("AutoOpen", "Document_Open", "AutoExec", "Workbook_Open", "Auto_Open", "PresentationOpen")
    try:
        names = [i.filename for i in z.infolist()]
        for name in names:
            lname = name.lower()
            if lname.endswith("vbaProject.bin".lower()):
                macro_present = True
                try:
                    with z.open(name) as f:
                        vb = f.read()
                    text = vb.decode("latin-1", errors="ignore")
                    lower_text = text.lower()
                    am = [m for m in autoexec_markers if m in text]
                    suspicious_auto_exec = suspicious_auto_exec or (len(am) > 0)
                    shell_list = [kw for kw in SHELL_INDICATORS if kw in lower_text]
                    shell_hits.update(shell_list)
                    prev = text[:8192]
                    macros.append({
                        "module_name": None,
                        "autoexec_indicators": am[:10],
                        "suspicious_indicators": shell_list[:10],
                        "preview": prev,
                        "preview_truncated": len(text) > len(prev),
                    })
                except Exception as e:
                    errors.append(f"macro_extract_error:{e}")
            # Embedded payloads
            if any(lname.startswith(prefix) for prefix in ("word/embeddings/", "xl/embeddings/", "ppt/embeddings/", "word/media/", "xl/media/", "ppt/media/")):
                try:
                    with z.open(name) as f:
                        raw = f.read(MAX_EMBED_PREVIEW)
                    import hashlib
                    sha = hashlib.sha256(raw).hexdigest() if raw else None
                    embeds.append({
                        "name": name.split("/")[-1] or name,
                        "path": name,
                        "size_hint": int(z.getinfo(name).file_size),
                        "sha256_raw": sha,
                        "type_hint": "ole-object" if "/embeddings/" in lname else ("media" if "/media/" in lname else "embedded-file"),
                        "high_entropy": (shannon_entropy(raw) > 7.5) if raw else False,
                    })
                except Exception as e:
                    errors.append(f"embed_extract_error:{e}")
    except Exception as e:
        errors.append(f"ooxml_embed_macro_error:{e}")
    return embeds[:2000], macros[:200], macro_present, suspicious_auto_exec, sorted(shell_hits), errors


def _analyze_ooxml(path: Path) -> Tuple[Dict[str, Any], Dict[str, int], List[str]]:
    errors: List[str] = []
    counts: Dict[str, int] = {
        "parts_total": 0,
        "embedded_payloads_total": 0,
        "external_references_total": 0,
        "macros_total": 0,
        "autoexec_macros_total": 0,
        "ioc_urls_total": 0,
        "strings_total": 0,
        "high_entropy_embed_count": 0,
    }

    z, errs, zinfo = _read_zip_safely(path)
    errors.extend(errs)
    if z is None:
        return {"structure": {"family": "ooxml", "main_part": None, "parts": [], "external_references": []},
                "macros": [], "embedded_payloads": [],
                "metadata": {"Creator": None, "LastModifiedBy": None, "Created": None, "Modified": None, "Application": None, "Company": None},
                "strings": {}, "entropy": {"overall": 0.0, "suspicious_embeds": [], "high_entropy_embed_count": 0},
                "flags": {"macro_present": False, "suspicious_auto_exec": False, "has_external_links": False},
                "anomalies": []}, counts, errors
    try:
        structure, struct_errs = _gather_ooxml_structure(z)
        errors.extend(struct_errs)
        parts = structure.get("parts") or []
        external_refs = structure.get("external_references") or []
        counts["parts_total"] = len(parts)
        counts["external_references_total"] = len(external_refs)

        embeds, macros, macro_present, suspicious_auto_exec, shell_hits, m_errs = _collect_ooxml_embeds_and_macros(z)
        errors.extend(m_errs)
        counts["embedded_payloads_total"] = len(embeds)
        counts["macros_total"] = len(macros)
        counts["autoexec_macros_total"] = sum(1 for m in macros if (m.get("autoexec_indicators") or []))
        suspicious_embeds = [
            {"name": e.get("name"), "entropy_raw": round(float(shannon_entropy(b"")), 2), "reason": "high_entropy_payload"}
            for e in embeds if e.get("high_entropy")
        ]
        counts["high_entropy_embed_count"] = sum(1 for e in embeds if e.get("high_entropy"))

        # Metadata (best-effort)
        metadata = {"Creator": None, "LastModifiedBy": None, "Created": None, "Modified": None, "Application": None, "Company": None}
        try:
            import xml.etree.ElementTree as ET
            if "docProps/core.xml" in z.namelist():
                with z.open("docProps/core.xml") as f:
                    core = f.read()
                try:
                    root = ET.fromstring(core)
                    # Namespaced, but we can match by localname endings
                    def find_text(tag_ends: Tuple[str, ...]) -> Optional[str]:
                        for el in root.iter():
                            if any(el.tag.endswith(te) for te in tag_ends):
                                t = (el.text or "").strip()
                                if t:
                                    return t
                        return None
                    metadata["Creator"] = find_text(("creator",))
                    metadata["LastModifiedBy"] = find_text(("lastModifiedBy",))
                    metadata["Created"] = find_text(("created",))
                    metadata["Modified"] = find_text(("modified",))
                except Exception:
                    errors.append("core_props_parse_failed")
            if "docProps/app.xml" in z.namelist():
                with z.open("docProps/app.xml") as f:
                    appx = f.read()
                try:
                    root = ET.fromstring(appx)
                    def find_text_local(name: str) -> Optional[str]:
                        for el in root.iter():
                            if el.tag.endswith(name):
                                t = (el.text or "").strip()
                                if t:
                                    return t
                        return None
                    metadata["Application"] = find_text_local("Application")
                    metadata["Company"] = find_text_local("Company")
                except Exception:
                    errors.append("app_props_parse_failed")
        except Exception:
            errors.append("metadata_parse_failed")

        # Strings / IOC
        data = _safe_read(path, MAX_INPUT_SIZE)
        strings_info: Dict[str, Any] = {}
        try:
            strings_info = extract_global_strings(data, min_len=6) if data else {}
        except Exception:
            errors.append("string_extraction_failed")
            strings_info = {}
        if not isinstance(strings_info, dict):
            strings_info = {}
        # Merge macro-derived shell indicators into string results.
        if shell_hits:
            existing = strings_info.setdefault("suspicious_keywords", [])
            if not isinstance(existing, list):
                existing = []
            existing_lower = {str(k).lower() for k in existing if isinstance(k, str)}
            for kw in shell_hits:
                if kw not in existing_lower:
                    existing.append(kw)
                    existing_lower.add(kw)
            strings_info["suspicious_keywords"] = existing
            samples = strings_info.setdefault("sample_strings", [])
            if not isinstance(samples, list):
                samples = []
            for m in macros:
                prev = str(m.get("preview") or "")
                if not prev:
                    continue
                lower_prev = prev.lower()
                for kw in shell_hits:
                    idx = lower_prev.find(kw)
                    if idx == -1:
                        continue
                    start = max(0, idx - 20)
                    end = min(len(prev), idx + len(kw) + 40)
                    snippet = prev[start:end]
                    if len(snippet) > 120:
                        snippet = snippet[:120] + "…"
                    if snippet not in samples:
                        samples.append(snippet)
                    break
                if len(samples) >= 10:
                    break
            strings_info["sample_strings"] = samples
        counts["strings_total"] = int((strings_info or {}).get("total") or 0)
        counts["ioc_urls_total"] = len((strings_info or {}).get("ioc_urls") or [])

        # Entropy
        try:
            cap = min(len(data or b""), 4 * 1024 * 1024)
            overall = shannon_entropy((data or b"")[:cap]) if cap > 0 else 0.0
        except Exception:
            overall = 0.0
            errors.append("entropy_calc_failed")
        # recompute suspicious_embeds with actual names and entropy numbers if we have raw bytes (we used 'high_entropy' flag earlier)
        sus_list = []
        for e in embeds:
            if e.get("high_entropy"):
                sus_list.append({"name": e.get("name"), "entropy_raw": None, "reason": "high_entropy_payload"})

        flags = {
            "macro_present": macro_present,
            "suspicious_auto_exec": suspicious_auto_exec,
            "has_external_links": counts["external_references_total"] > 0,
        }
        anomalies: List[str] = []
        if suspicious_auto_exec:
            anomalies.append("macro_autoexec_detected")
        if counts["high_entropy_embed_count"] > 0:
            anomalies.append("suspicious_high_entropy_payload")
        if "zip_entry_compression_ratio_insane" in errors:
            anomalies.append("zip_entry_compression_ratio_insane")
        if "zip_total_uncompressed_cap" in errors:
            anomalies.append("office_file_too_large_for_deep_scan")

        static_office = {
            "structure": structure,
            "macros": macros,
            "embedded_payloads": embeds,
            "metadata": metadata,
            "strings": strings_info or {},
            "entropy": {"overall": round(float(overall), 2), "suspicious_embeds": sus_list, "high_entropy_embed_count": counts["high_entropy_embed_count"]},
            "flags": flags,
            "anomalies": anomalies,
        }
        return static_office, counts, errors
    finally:
        try:
            z.close()
        except Exception:
            pass


def _analyze_ole(path: Path) -> Tuple[Dict[str, Any], Dict[str, int], List[str]]:
    errors: List[str] = []
    counts: Dict[str, int] = {
        "parts_total": 0,
        "embedded_payloads_total": 0,
        "external_references_total": 0,
        "macros_total": 0,
        "autoexec_macros_total": 0,
        "ioc_urls_total": 0,
        "strings_total": 0,
        "high_entropy_embed_count": 0,
    }
    data = _safe_read(path, MAX_INPUT_SIZE)
    strings_info = {}
    try:
        strings_info = extract_global_strings(data, min_len=6) if data else {}
    except Exception:
        errors.append("string_extraction_failed")
        strings_info = {}
    counts["strings_total"] = int((strings_info or {}).get("total") or 0)
    counts["ioc_urls_total"] = len((strings_info or {}).get("ioc_urls") or [])
    try:
        cap = min(len(data or b""), 4 * 1024 * 1024)
        overall = shannon_entropy((data or b"")[:cap]) if cap > 0 else 0.0
    except Exception:
        overall = 0.0
        errors.append("entropy_calc_failed")

    # Heuristic macro presence by UTF-16LE stream name hints
    macro_present = False
    suspicious_auto_exec = False
    macros: List[Dict[str, Any]] = []
    try:
        text_latin = (data or b"").decode("latin-1", errors="ignore")
        markers = ("VBA", "_VBA_PROJECT", "ThisDocument", "Workbook", "Module1")
        autoexec_markers = ("AutoOpen", "Document_Open", "AutoExec", "Workbook_Open", "Auto_Open", "PresentationOpen")
        macro_present = any(m in text_latin for m in markers)
        am = [m for m in autoexec_markers if m in text_latin]
        suspicious_auto_exec = len(am) > 0
        if macro_present:
            prev = text_latin[:8192]
            macros.append({
                "module_name": None,
                "autoexec_indicators": am[:10],
                "preview": prev,
                "preview_truncated": len(text_latin) > len(prev),
            })
    except Exception:
        pass
    counts["macros_total"] = len(macros)
    counts["autoexec_macros_total"] = sum(1 for m in macros if (m.get("autoexec_indicators") or []))

    static_office = {
        "structure": {"family": "ole", "main_part": None, "parts": [], "external_references": []},
        "macros": macros,
        "embedded_payloads": [],
        "metadata": {"Creator": None, "LastModifiedBy": None, "Created": None, "Modified": None, "Application": None, "Company": None},
        "strings": strings_info or {},
        "entropy": {"overall": round(float(overall), 2), "suspicious_embeds": [], "high_entropy_embed_count": 0},
        "flags": {"macro_present": macro_present, "suspicious_auto_exec": suspicious_auto_exec, "has_external_links": False},
        "anomalies": ["ole_vba_stream_unexpected_layout"] if macro_present and not suspicious_auto_exec else [],
    }
    return static_office, counts, errors


# ==============================================
# Macro intelligence via oletools.olevba (optional)
# ==============================================

def analyze_macros_with_olevba(path: str, budget_bytes: int = 8192) -> dict:
    """
    Try to use oletools.olevba.VBA_Parser to extract macro modules.
    Returns:
    {
        "macro_present": bool,
        "modules": [
            {
                "module_name": str,
                "autoexec_indicators": [str, ...],
                "suspicious_indicators": [str, ...],
                "preview": str,
                "preview_truncated": bool
            },
            ...
        ],
        "autoexec_detected": bool,
        "errors": [ "...", ...]
    }

    Fail-soft: never raise; append errors and return.
    """
    result: Dict[str, Any] = {
        "macro_present": False,
        "modules": [],
        "autoexec_detected": False,
        "errors": [],
    }

    # Auto-exec and suspicious indicators
    autoexec_markers = [
        "AutoOpen", "Auto_Open", "Document_Open", "DocumentOpen",
        "Workbook_Open", "WorkbookOpen", "AutoExec", "PresentationOpen",
    ]
    suspicious_markers = [
        "powershell", "cmd.exe", "WScript.Shell", "CreateObject",
        "Shell(", "rundll32", "URLDownloadToFile", "Msxml2.XMLHTTP", "ADODB.Stream",
    ]

    try:
        try:
            from oletools.olevba import VBA_Parser  # type: ignore
        except Exception as e:  # pragma: no cover
            result["errors"].append("olevba_unavailable")
            return result

        try:
            vp = VBA_Parser(path)
        except Exception as e:
            result["errors"].append(f"olevba_init_failed: {e}")
            return result

        try:
            macro_present = bool(vp.detect_vba_macros())
            result["macro_present"] = macro_present
            autoexec_any = False
            modules: List[Dict[str, Any]] = []

            if macro_present:
                for (filename, stream_path, vba_filename, vba_code) in vp.extract_all_macros():
                    try:
                        text = vba_code or ""
                        prev = text[:budget_bytes]
                        truncated = len(text) > budget_bytes
                        low = prev.lower()
                        # find indicators
                        autoexec = [m for m in autoexec_markers if m.lower() in low]
                        susp = [s for s in suspicious_markers if s.lower() in low]
                        if autoexec:
                            autoexec_any = True
                        modules.append({
                            "module_name": vba_filename or filename or stream_path,
                            "autoexec_indicators": autoexec,
                            "suspicious_indicators": susp,
                            "preview": prev,
                            "preview_truncated": truncated,
                        })
                    except Exception as ie:
                        result["errors"].append(f"olevba_extract_failed: {ie}")

            result["modules"] = modules
            result["autoexec_detected"] = bool(autoexec_any)
        finally:
            try:
                vp.close()
            except Exception:
                pass
    except Exception as e:  # pragma: no cover
        result["errors"].append(f"olevba_unexpected: {e}")

    return result


def analyze_office_full(path: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = config or {}
    p = Path(path)
    errors: List[str] = []
    static_office: Dict[str, Any] = {
        "structure": {"family": None, "main_part": None, "parts": [], "external_references": []},
        "macros": [],
        "embedded_payloads": [],
        "metadata": {"Creator": None, "LastModifiedBy": None, "Created": None, "Modified": None, "Application": None, "Company": None},
        "strings": {},
        "entropy": {"overall": 0.0, "suspicious_embeds": [], "high_entropy_embed_count": 0},
        "flags": {"macro_present": False, "suspicious_auto_exec": False, "has_external_links": False},
        "anomalies": [],
    }
    counts: Dict[str, int] = {
        "parts_total": 0,
        "embedded_payloads_total": 0,
        "external_references_total": 0,
        "macros_total": 0,
        "autoexec_macros_total": 0,
        "ioc_urls_total": 0,
        "strings_total": 0,
        "high_entropy_embed_count": 0,
    }
    try:
        size = p.stat().st_size
    except Exception as e:
        return {"static": {"office": static_office}, "counts": counts, "errors": [f"stat_error:{e}"]}
    if size > MAX_INPUT_SIZE:
        errors.append("input_over_limit")
        return {"static": {"office": static_office}, "counts": counts, "errors": errors}

    try:
        if _is_ooxml_zip(p):
            static_office, counts, errs = _analyze_ooxml(p)
            errors.extend(errs)
        elif _is_ole_cfb(p):
            static_office, counts, errs = _analyze_ole(p)
            errors.extend(errs)
        else:
            errors.append("unknown_office_family")
    except Exception as e:
        errors.append(f"unexpected_office_error:{e}")

    # Integrate olevba macro extraction (optional; fail-soft)
    try:
        macro_info = analyze_macros_with_olevba(str(p))
        # merge modules: concatenate existing + olevba
        try:
            existing = list(static_office.get("macros") or [])
            merged = existing + list(macro_info.get("modules") or [])
            static_office["macros"] = merged[:200]  # bound
        except Exception:
            pass

        # flags OR
        try:
            flags = static_office.setdefault("flags", {})
            if bool(macro_info.get("macro_present")):
                flags["macro_present"] = True
            if bool(macro_info.get("autoexec_detected")):
                flags["suspicious_auto_exec"] = True
        except Exception:
            pass

        # suspicious shell usage flag
        try:
            sus = False
            for m in (static_office.get("macros") or []):
                # prefer explicit indicators when available
                for tok in (m.get("suspicious_indicators") or []):
                    t = str(tok).lower()
                    if any(x in t for x in SHELL_INDICATORS):
                        sus = True
                        break
                if sus:
                    break
                # fallback: scan preview text for tokens (heuristic macros)
                prev = str(m.get("preview") or "").lower()
                if any(x in prev for x in SHELL_INDICATORS):
                    sus = True
                    break
            if not sus:
                # fallback to global strings keywords if oletools unavailable
                try:
                    kws = (static_office.get("strings") or {}).get("suspicious_keywords") or []
                    lower = [str(k).lower() for k in kws]
                    if any(any(sig in k for sig in SHELL_INDICATORS) for k in lower):
                        sus = True
                except Exception:
                    pass
            static_office.setdefault("flags", {})["suspicious_shell_usage"] = bool(sus)
        except Exception:
            pass

        # counts
        try:
            total = len(static_office.get("macros") or [])
            autoexec_count = sum(1 for m in (static_office.get("macros") or []) if m.get("autoexec_indicators"))
            counts["macros_total"] = total
            counts["autoexec_macros_total"] = autoexec_count
        except Exception:
            pass

        # errors and anomalies
        try:
            for e in (macro_info.get("errors") or []):
                errors.append(e)
                if isinstance(e, str) and e.startswith("olevba_") and e != "olevba_unavailable":
                    static_office.setdefault("anomalies", []).append(f"engine_warning:{e}")
        except Exception:
            pass
    except Exception as e:
        errors.append(f"olevba_integration_failed: {e}")

    return {"static": {"office": static_office}, "counts": counts, "errors": errors}
