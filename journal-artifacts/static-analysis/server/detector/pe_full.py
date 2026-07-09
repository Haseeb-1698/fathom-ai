"""
PE static analyzer for Fathom.

Fail-soft, offline-only, bounded resource usage.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import math
import re

try:
    import pefile  # type: ignore
except Exception:
    pefile = None  # type: ignore

try:
    import lief  # type: ignore
except Exception:
    lief = None  # type: ignore

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore
except Exception:
    Cs = None  # type: ignore
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = None  # type: ignore

try:
    import yara  # type: ignore
except Exception:
    yara = None  # type: ignore

# Optional reuse of string utilities from the PDF analyzer if available
DEFAULT_CONFIG: Dict[str, Any] = {
    "max_input_size": 64 * 1024 * 1024,
    "entropy_threshold": 7.5,
    "strings_min_len": 6,
    "preview_bytes": 8192,
    "max_disasm_bytes": 256,
}

SUSPICIOUS_IMPORT_NAMES = {
    "createprocess",
    "winexec",
    "shellexecute",
    "urldownloadtofile",
    "internetopenurl",
    "virtualalloc",
    "virtualprotect",
    "loadlibrary",
    "getprocaddress",
    "httpsendrequest",
    "rtlcreateuserthread",
    "ntcreatethreadex",
}

SUSPICIOUS_KEYWORDS = (
    "cmd.exe",
    "powershell",
    "rundll32",
    "regsvr32",
    "wscript",
    "mshta",
    "certutil",
    "bitsadmin",
    "schtasks",
    "vssadmin",
)

MACHINE_MAP = {
    0x014c: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x01c0: "IMAGE_FILE_MACHINE_ARM",
    0x01c4: "IMAGE_FILE_MACHINE_ARMNT",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

CHARACTERISTICS_FLAGS = {
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x2000: "DLL",
}


# Import professional entropy calculation
try:
    from .entropy_utils import calculate_shannon_entropy as shannon_entropy
except ImportError:
    # Fallback if scipy not available
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        total = len(data)
        for c in counts:
            if c == 0:
                continue
            p = c / total
            entropy -= p * math.log(p, 2)
        return float(entropy)


def _safe_hex(val: Optional[int]) -> Optional[str]:
    if val is None:
        return None
    try:
        return hex(int(val))
    except Exception:
        return None


def _normalize_time(timestamp: Optional[int]) -> Optional[str]:
    if not timestamp:
        return None
    try:
        dt = datetime.utcfromtimestamp(int(timestamp))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _load_yara_rules(rule_dir: Path, errors: List[str]) -> Optional["yara.Rules"]:
    if yara is None:
        errors.append("yara_unavailable")
        return None
    try:
        rule_files = {p.stem: str(p) for p in rule_dir.glob("*.yar")}
        if not rule_files:
            errors.append("yara_rules_missing")
            return None
        return yara.compile(filepaths=rule_files)
    except yara.TimeoutError:
        errors.append("yara_compile_timeout")
    except Exception as e:
        errors.append(f"yara_compile_error:{e}")
    return None


def extract_strings_full(
    data: bytes,
    min_len: int = 6,
    max_samples: int = 50,
    max_preview_len: int = 120,
) -> Dict[str, Any]:
    """Extract ASCII/UTF-16LE strings, prioritising IOC-rich content."""
    result: Dict[str, Any] = {
        "total": 0,
        "unique": 0,
        "ioc_urls": [],
        "suspicious_keywords": [],
        "sample_strings": [],
    }
    if not data:
        return result

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_len))
    utf16_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % max(1, min_len)))
    try:
        candidates: List[Tuple[int, str]] = []
        for match in ascii_re.finditer(data):
            try:
                s = match.group(0).decode("latin-1", errors="ignore")
            except Exception:
                continue
            candidates.append((match.start(), s))
        for match in utf16_re.finditer(data):
            try:
                s = match.group(0).decode("utf-16le", errors="ignore")
            except Exception:
                continue
            candidates.append((match.start(), s))
        candidates.sort(key=lambda t: t[0])

        dedup: List[str] = []
        seen: Set[str] = set()
        for _, s in candidates:
            cleaned = s.strip()
            if not cleaned:
                continue
            if cleaned not in seen:
                seen.add(cleaned)
                dedup.append(cleaned)

        result["total"] = len(candidates)
        result["unique"] = len(dedup)

        suspicious_terms = [
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "wscript",
            "mshta",
            "shellexecute",
            "loadlibrary",
            "getprocaddress",
            "virtualalloc",
            "http://",
            "https://",
        ]
        suspicious_hits: List[str] = []
        lower_terms = [t.lower() for t in suspicious_terms]
        for s in dedup:
            l = s.lower()
            for original, lowered in zip(suspicious_terms, lower_terms):
                if lowered in l and original not in suspicious_hits:
                    suspicious_hits.append(original)
        result["suspicious_keywords"] = suspicious_hits[:50]

        url_re = re.compile(r"https?://[^\s\"'<>]+", re.I)
        urls: List[str] = []
        for s in dedup:
            for url in url_re.findall(s):
                if url not in urls:
                    urls.append(url)
                if len(urls) >= 20:
                    break
            if len(urls) >= 20:
                break
        result["ioc_urls"] = urls

        interesting_terms = {term.lower() for term in suspicious_terms}
        interesting: List[str] = []
        general: List[str] = []
        for s in dedup:
            l = s.lower()
            if any(term in l for term in interesting_terms) or any(url in s for url in urls):
                interesting.append(s)
            else:
                general.append(s)

        def truncate(items: Iterable[str], limit: int) -> List[str]:
            out: List[str] = []
            for item in items:
                if len(out) >= limit:
                    break
                if len(item) > max_preview_len:
                    out.append(item[:max_preview_len] + "…")
                else:
                    out.append(item)
            return out

        samples = truncate(interesting, max_samples)
        if len(samples) < max_samples:
            samples.extend(truncate(general, max_samples - len(samples)))
        result["sample_strings"] = samples
        return result
    except Exception:
        return result


def _run_yara(data: bytes, rules: Optional["yara.Rules"], errors: List[str]) -> List[Dict[str, Any]]:
    if not data or rules is None:
        return []
    out: List[Dict[str, Any]] = []
    try:
        matches = rules.match(data=data)
        for m in matches:
            meta = dict(m.meta) if getattr(m, "meta", None) else {}
            out.append(
                {
                    "rule": m.rule,
                    "namespace": getattr(m, "namespace", ""),
                    "meta": meta,
                }
            )
    except yara.TimeoutError:
        errors.append("yara_match_timeout")
    except Exception as e:
        errors.append(f"yara_match_error:{e}")
    return out


def _disassemble_entry(
    pe_obj: Any,
    data: bytes,
    max_bytes: int,
    errors: List[str],
) -> List[Dict[str, Any]]:
    if Cs is None or CS_ARCH_X86 is None:
        errors.append("capstone_unavailable")
        return []
    try:
        entry_rva = int(pe_obj.OPTIONAL_HEADER.AddressOfEntryPoint)
        entry_offset = pe_obj.get_offset_from_rva(entry_rva)
    except Exception:
        return []

    try:
        if pe_obj.FILE_HEADER.Machine == 0x8664:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
    except Exception as e:
        errors.append(f"capstone_init_failed:{e}")
        return []

    try:
        snippet = data[entry_offset : entry_offset + max_bytes]
    except Exception:
        return []

    disasm: List[Dict[str, Any]] = []
    consumed = 0
    try:
        for insn in md.disasm(snippet, entry_rva):
            bytes_hex = " ".join(f"{b:02X}" for b in insn.bytes)
            disasm.append(
                {
                    "rva": int(insn.address),
                    "bytes": bytes_hex,
                    "mnemonics": f"{insn.mnemonic} {insn.op_str}".strip(),
                }
            )
            consumed += len(insn.bytes)
            if consumed >= max_bytes:
                break
    except Exception as e:
        errors.append(f"capstone_disasm_error:{e}")
    return disasm[:40]


def _authenticode_info(path: Path, errors: List[str], anomalies: List[str]) -> Dict[str, Any]:
    info = {"present": False, "valid": None, "signer": None}
    if pefile is None:
        return info
    try:
        pe = pefile.PE(str(path), fast_load=True)
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if not (security_dir.VirtualAddress and security_dir.Size):
            return info
        info["present"] = True
        if lief is None:
            return info
        try:
            binary = lief.parse(str(path))
            if not binary or not getattr(binary, "has_signatures", False):
                return info
            sig = binary.signatures[0]
            signer = None
            try:
                signer = getattr(sig.signer_info, "program_name", None)
            except Exception:
                signer = None
            info["signer"] = signer or "unknown"
            if signer is None:
                anomalies.append("authenticode_parse_partial")
        except Exception:
            info["signer"] = "unknown"
            anomalies.append("authenticode_parse_partial")
        return info
    except Exception:
        errors.append("authenticode_check_failed")
        return info


def analyze_pe_full(path: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if config:
        cfg.update(config)

    p = Path(path)
    errors: List[str] = []

    static_pe: Dict[str, Any] = {
        "file_info": {
            "file_type": None,
            "machine": None,
            "compile_time": None,
            "entrypoint_rva": None,
            "image_base": None,
            "is_dll": None,
            "is_exe": None,
            "has_tls_callbacks": False,
        },
        "headers": {},
        "sections": [],
        "imports": [],
        "exports": [],
        "resources": [],
        "suspicious_imports": [],
        "yara_matches": [],
        "disasm": [],
        "strings": {},
        "signatures": {"authenticode": {"present": False, "valid": None, "signer": None}},
        "anomalies": [],
        "notes": [],
        "overlay": {"present": False, "size": 0},
    }

    counts: Dict[str, int] = {
        "sections_total": 0,
        "imports_total": 0,
        "exports_total": 0,
        "resources_total": 0,
        "strings_total": 0,
        "yara_matches_total": 0,
        "high_entropy_section_count": 0,
        "suspicious_imports_total": 0,
    }

    try:
        data = p.read_bytes()
    except Exception as e:
        errors.append(f"read_error:{e}")
        return {"static": {"pe": static_pe}, "counts": counts, "errors": errors}

    file_size = len(data)
    max_size = int(cfg.get("max_input_size", 64 * 1024 * 1024))
    light_mode = False
    if file_size > max_size:
        light_mode = True
        static_pe["anomalies"].append("file_too_large_for_full_scan")

    pe_obj: Optional[Any] = None
    if pefile is None:
        errors.append("pefile_unavailable")
    else:
        try:
            pe_obj = pefile.PE(data=data, fast_load=light_mode)
            if pe_obj and not light_mode:
                pe_obj.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                    ]
                )
        except Exception as e:
            errors.append(f"pefile_parse_error:{e}")
            pe_obj = None

    # File info
    if pe_obj is not None:
        try:
            magic = getattr(pe_obj.OPTIONAL_HEADER, "Magic", None)
            if magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
                static_pe["file_info"]["file_type"] = "PE32+"
            elif magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
                static_pe["file_info"]["file_type"] = "PE32"
            static_pe["file_info"]["machine"] = MACHINE_MAP.get(
                pe_obj.FILE_HEADER.Machine, hex(pe_obj.FILE_HEADER.Machine)
            )
            static_pe["file_info"]["compile_time"] = _normalize_time(pe_obj.FILE_HEADER.TimeDateStamp)
            static_pe["file_info"]["entrypoint_rva"] = int(pe_obj.OPTIONAL_HEADER.AddressOfEntryPoint)
            static_pe["file_info"]["image_base"] = int(pe_obj.OPTIONAL_HEADER.ImageBase)
            static_pe["file_info"]["is_dll"] = bool(pe_obj.is_dll())
            static_pe["file_info"]["is_exe"] = bool(pe_obj.is_exe())
            if hasattr(pe_obj, "DIRECTORY_ENTRY_TLS"):
                tls_dir = pe_obj.DIRECTORY_ENTRY_TLS
                callbacks = getattr(tls_dir, "callbacks", None)
                static_pe["file_info"]["has_tls_callbacks"] = bool(callbacks)
                if callbacks:
                    static_pe["anomalies"].append("tls_callbacks_present")
        except Exception as e:
            errors.append(f"file_info_error:{e}")

        # Headers
        try:
            checksum = getattr(pe_obj.OPTIONAL_HEADER, "CheckSum", None)
            calc_checksum = None
            try:
                calc_checksum = pe_obj.generate_checksum()
            except Exception:
                pass
            static_pe["headers"] = {
                "characteristics": [
                    name
                    for flag, name in CHARACTERISTICS_FLAGS.items()
                    if pe_obj.FILE_HEADER.Characteristics & flag
                ],
                "checksum": checksum,
                "calculated_checksum": calc_checksum,
                "checksum_valid": (checksum == calc_checksum) if (checksum and calc_checksum) else None,
                "number_of_sections": int(pe_obj.FILE_HEADER.NumberOfSections),
            }
            if checksum and calc_checksum and checksum != calc_checksum:
                static_pe["anomalies"].append("checksum_mismatch")
        except Exception as e:
            errors.append(f"header_error:{e}")

        # Sections
        entropy_threshold = float(cfg.get("entropy_threshold", 7.5))
        try:
            sections_out: List[Dict[str, Any]] = []
            last_section_end = 0
            for section in pe_obj.sections:
                name = section.Name.rstrip(b"\x00").decode("latin-1", errors="ignore") or "__unnamed__"
                raw_data = section.get_data() or b""
                ent = section.get_entropy() if hasattr(section, "get_entropy") else shannon_entropy(raw_data)
                va = int(section.VirtualAddress)
                raw_ptr = int(section.PointerToRawData)
                raw_size = int(section.SizeOfRawData)
                virt_size = int(section.Misc_VirtualSize)
                characteristics = []
                flags = getattr(section, "Characteristics", 0)
                for flag, label in CHARACTERISTICS_FLAGS.items():
                    if flags & flag:
                        characteristics.append(label)
                suspect = ent >= entropy_threshold or name.upper().startswith(("UPX", ".UPX", ".ASPACK"))
                sections_out.append(
                    {
                        "name": name,
                        "virtual_size": virt_size,
                        "raw_size": raw_size,
                        "virtual_address": va,
                        "raw_pointer": raw_ptr,
                        "entropy": round(float(ent), 3),
                        "characteristics": characteristics,
                        "suspect": bool(suspect),
                    }
                )
                if suspect:
                    static_pe["anomalies"].append("high_entropy_section")
                if raw_ptr + raw_size > last_section_end:
                    last_section_end = raw_ptr + raw_size
                if ent >= entropy_threshold:
                    counts["high_entropy_section_count"] += 1
            static_pe["sections"] = sections_out
            counts["sections_total"] = len(sections_out)
            if file_size > last_section_end:
                static_pe["overlay"] = {"present": True, "size": file_size - last_section_end}
                static_pe["anomalies"].append("overlay_present")
        except Exception as e:
            errors.append(f"sections_error:{e}")

        # Imports
        suspicious_imports: List[str] = []
        try:
            if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
                imports_out: List[Dict[str, Any]] = []
                for entry in pe_obj.DIRECTORY_ENTRY_IMPORT[:200]:
                    dll = entry.dll.decode("latin-1", errors="ignore") if entry.dll else "unknown.dll"
                    funcs: List[str] = []
                    for imp in entry.imports[:500]:
                        name = None
                        if imp.name:
                            name = imp.name.decode("latin-1", errors="ignore")
                        elif imp.ordinal is not None:
                            name = f"ord_{imp.ordinal}"
                        if name:
                            funcs.append(name)
                            norm = name.lower()
                            for risk in SUSPICIOUS_IMPORT_NAMES:
                                if risk in norm:
                                    suspicious_imports.append(f"{dll}:{name}")
                                    break
                    imports_out.append({"dll": dll, "functions": funcs})
                static_pe["imports"] = imports_out
                counts["imports_total"] = sum(len(i["functions"]) for i in imports_out)
        except Exception as e:
            errors.append(f"imports_error:{e}")

        # Exports
        try:
            exports_out: List[Dict[str, Any]] = []
            if hasattr(pe_obj, "DIRECTORY_ENTRY_EXPORT"):
                for sym in pe_obj.DIRECTORY_ENTRY_EXPORT.symbols[:500]:
                    name = sym.name.decode("latin-1", errors="ignore") if sym.name else None
                    exports_out.append(
                        {
                            "name": name,
                            "ordinal": getattr(sym, "ordinal", None),
                            "rva": getattr(sym, "address", None),
                        }
                    )
            static_pe["exports"] = exports_out
            counts["exports_total"] = len(exports_out)
        except Exception as e:
            errors.append(f"exports_error:{e}")

        # Resources
        try:
            resources_out: List[Dict[str, Any]] = []
            if hasattr(pe_obj, "DIRECTORY_ENTRY_RESOURCE"):
                for entry in pe_obj.DIRECTORY_ENTRY_RESOURCE.entries[:200]:
                    try:
                        res_type = entry.name.string if entry.name else entry.struct.Id
                    except Exception:
                        res_type = entry.struct.Id
                    if isinstance(res_type, bytes):
                        res_type = res_type.decode("latin-1", errors="ignore")
                    if hasattr(entry, "directory"):
                        for lang_entry in entry.directory.entries[:100]:
                            lang = lang_entry.name.string if lang_entry.name else lang_entry.struct.Id
                            if isinstance(lang, bytes):
                                lang = lang.decode("latin-1", errors="ignore")
                            data_entry = lang_entry.data.struct if hasattr(lang_entry, "data") else None
                            size = getattr(data_entry, "Size", None)
                            resources_out.append(
                                {
                                    "type": res_type,
                                    "lang": lang,
                                    "size": size,
                                }
                            )
            static_pe["resources"] = resources_out
            counts["resources_total"] = len(resources_out)
        except Exception as e:
            errors.append(f"resources_error:{e}")

        # Suspicious imports summary
        static_pe["suspicious_imports"] = suspicious_imports[:50]
        counts["suspicious_imports_total"] = len(suspicious_imports)
        if suspicious_imports and "suspicious_imports_detected" not in static_pe["anomalies"]:
            static_pe["anomalies"].append("suspicious_imports_detected")

        # TLS callbacks flagged as suspicious
        if static_pe["file_info"]["has_tls_callbacks"] and "suspicious_tls_callback" not in static_pe["anomalies"]:
            static_pe["anomalies"].append("suspicious_tls_callback")

        # Packed heuristic
        if (
            counts["high_entropy_section_count"] >= 2
            or any(s["name"].upper().startswith(("UPX", ".UPX", ".ASPACK")) for s in static_pe["sections"])
        ) and "packed_suspected" not in static_pe["anomalies"]:
            static_pe["anomalies"].append("packed_suspected")

        # Disassembly (entrypoint)
        if not light_mode:
            static_pe["disasm"] = _disassemble_entry(pe_obj, data, int(cfg.get("max_disasm_bytes", 256)), errors)

    # Strings
    try:
        strings_info = extract_strings_full(
            data,
            min_len=int(cfg.get("strings_min_len", 6)),
            max_samples=50,
            max_preview_len=120,
        )
        static_pe["strings"] = strings_info
        counts["strings_total"] = int(strings_info.get("total") or 0)
    except Exception as e:
        errors.append(f"strings_error:{e}")
        static_pe["anomalies"].append("string_extraction_failed")
        static_pe["strings"] = {}
        counts["strings_total"] = 0

    # Global entropy note
    try:
        overall_entropy = shannon_entropy(data[: 4 * 1024 * 1024])
        static_pe.setdefault("notes", []).append(f"overall_entropy:{overall_entropy:.3f}")
    except Exception:
        pass

    # YARA
    try:
        rules = _load_yara_rules(Path(__file__).parent / "rules" / "yara", errors)
        matches = _run_yara(data if not light_mode else data[: 2 * 1024 * 1024], rules, errors)
        static_pe["yara_matches"] = matches
        counts["yara_matches_total"] = len(matches)
        if matches:
            static_pe["anomalies"].append("yara_matches_present")
    except Exception as e:
        errors.append(f"yara_runtime_error:{e}")

    # Signatures
    static_pe["signatures"]["authenticode"] = _authenticode_info(p, errors, static_pe["anomalies"])

    if static_pe["signatures"]["authenticode"]["present"]:
        static_pe["notes"].append("authenticode_present")

    return {"static": {"pe": static_pe}, "counts": counts, "errors": errors}


__all__ = ["analyze_pe_full"]
