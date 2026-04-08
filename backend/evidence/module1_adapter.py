"""
module1_adapter.py — Convert Module 1 (static analysis) JSON output to EvidenceBrief.

Module 1 produces static analysis results (PE headers, imports, strings, etc.).
This adapter normalizes that into the same EvidenceBrief format used by the
rest of the pipeline (v3 EvidenceBrief from cape_extraction_layer_v3).
"""

from __future__ import annotations

from typing import Any

from evidence.cape_extractor import EvidenceBrief, IOC, IOCType, BehaviorIndicator, Severity


class Module1Adapter:
    """Adapter class for Module 1 static analysis."""

    def from_module1_output(self, data: dict[str, Any]) -> EvidenceBrief:
        """Convert Module 1 static analysis JSON to EvidenceBrief (instance method)."""
        return from_module1_output(data)

    def analyze_pe_binary(self, path: str) -> EvidenceBrief:
        """Perform basic static analysis on a PE binary and return an EvidenceBrief."""
        import hashlib
        import os

        brief = EvidenceBrief()
        brief.file_name = os.path.basename(path)
        brief.file_type = "PE32"

        with open(path, "rb") as fh:
            data = fh.read()

        brief.file_size = len(data)

        # Compute hashes
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        brief.sha256 = sha256
        brief.sample_id = sha256
        brief.hashes = {"sha256": sha256, "md5": md5, "sha1": sha1}

        # Try pefile for richer static info
        try:
            import pefile  # type: ignore
            pe = pefile.PE(data=data)

            # Imports
            brief.pe_imports = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode(errors="replace")
                    funcs = []
                    for imp in entry.imports:
                        name = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                        funcs.append(name)
                    brief.pe_imports[dll_name] = funcs[:50]

            # Sections + entropy
            for sec in pe.sections:
                name = sec.Name.decode(errors="replace").rstrip("\x00")
                entropy = sec.get_entropy()
                brief.pe_sections.append({
                    "name": name,
                    "entropy": round(entropy, 4),
                    "characteristics": hex(sec.Characteristics),
                })
                if entropy > 7.0:
                    brief.behaviors.append(BehaviorIndicator(
                        description=f"Section {name} has entropy {entropy:.2f} (packed/encrypted)",
                        severity=Severity.MEDIUM,
                        attack_techniques=["T1027"],
                        evidence=[f"PE section {name} entropy={entropy:.2f}"],
                        source="pe_binary_static",
                    ))

            # Compile timestamp
            brief.pe_compile_ts = str(pe.FILE_HEADER.TimeDateStamp)

            pe.close()
        except Exception:
            pass  # pefile not available or not a valid PE — continue with hash-only brief

        # Extract printable strings for IOC hints
        import re
        printable = re.findall(rb"[\x20-\x7e]{6,}", data)
        for s in printable[:200]:
            s_str = s.decode(errors="replace")
            if "http" in s_str.lower() or "://" in s_str:
                brief.iocs.append(IOC(
                    type=IOCType.URL, value=s_str[:200],
                    confidence=0.5, source="pe_binary_strings", context="extracted from binary strings"
                ))
            elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s_str):
                brief.iocs.append(IOC(
                    type=IOCType.IP, value=s_str,
                    confidence=0.4, source="pe_binary_strings", context="IP from binary strings"
                ))

        return brief


def from_module1_output(static: dict[str, Any]) -> EvidenceBrief:
    """Convert Module 1 static analysis JSON to EvidenceBrief."""
    brief = EvidenceBrief()

    # File identity
    brief.sample_id = static.get("sha256", static.get("md5", ""))
    brief.file_name = static.get("filename", static.get("name", ""))
    brief.file_type = static.get("file_type", "PE32")
    brief.file_size = static.get("file_size", static.get("size", 0))
    brief.hashes = {
        k: static[k] for k in ("sha256", "md5", "sha1") if k in static
    }

    # PE info
    pe = static.get("pe_info", static.get("pe", {}))
    if pe:
        brief.processes = [f"{brief.file_name} (PID 0)"]
        brief.pe_imphash = pe.get("imphash", "")
        brief.pe_compile_ts = pe.get("timestamp", pe.get("compile_ts", ""))
        brief.pe_entrypoint = str(pe.get("entrypoint", ""))
        brief.pe_signed = bool(pe.get("signature", pe.get("signed", False)))

    # Imports → suspicious API detection
    imports = static.get("imports", {})
    if isinstance(imports, dict):
        brief.pe_imports = {}
        for dll, funcs in imports.items():
            if isinstance(funcs, list):
                brief.pe_imports[dll] = [str(f) for f in funcs[:50]]
    elif isinstance(imports, list):
        brief.pe_imports = {"unknown": [str(i)[:100] for i in imports[:50]]}

    # Strings of interest → IOCs
    strings = static.get("strings", static.get("interesting_strings", []))
    if isinstance(strings, list):
        for s in strings[:50]:
            s_str = str(s).strip()
            if "http" in s_str.lower() or "://" in s_str:
                brief.iocs.append(IOC(
                    type=IOCType.URL, value=s_str[:200],
                    confidence=0.5, source="module1_static", context="extracted from strings"
                ))
            elif any(ind in s_str.lower() for ind in [".exe", ".dll", ".bat", "cmd", "powershell"]):
                brief.iocs.append(IOC(
                    type=IOCType.FILE_PATH, value=s_str[:200],
                    confidence=0.4, source="module1_static", context="suspicious string"
                ))

    # Sections → behavioral indicators (high entropy = packed/encrypted)
    sections = static.get("sections", pe.get("sections", []))
    if isinstance(sections, list):
        for sec in sections:
            if isinstance(sec, dict):
                entropy = sec.get("entropy", 0)
                name = sec.get("name", "?")
                brief.pe_sections.append({
                    "name": name,
                    "entropy": float(entropy) if isinstance(entropy, (int, float)) else 0.0,
                    "characteristics": sec.get("characteristics", ""),
                })
                if isinstance(entropy, (int, float)) and entropy > 7.0:
                    brief.behaviors.append(BehaviorIndicator(
                        description=f"Section {name} has entropy {entropy:.2f} (packed/encrypted)",
                        severity=Severity.MEDIUM,
                        attack_techniques=["T1027"],
                        evidence=[f"PE section {name} entropy={entropy:.2f}"],
                        source="module1_static",
                    ))

    # Packer detection
    packer = static.get("packer", static.get("packers", []))
    if packer:
        brief.packed = True
        packers = packer if isinstance(packer, list) else [packer]
        for p in packers:
            brief.behaviors.append(BehaviorIndicator(
                description=f"Packed with {p}",
                severity=Severity.MEDIUM,
                attack_techniques=["T1027.002"],
                evidence=[f"Packer detected: {p}"],
                source="module1_static",
            ))

    # YARA matches from static scan
    yara = static.get("yara", static.get("yara_matches", []))
    if isinstance(yara, list):
        for y in yara:
            if isinstance(y, dict):
                brief.yara_matches.append(y.get("name", y.get("rule", "")))
            elif isinstance(y, str):
                brief.yara_matches.append(y)

    # Score
    score = static.get("score", static.get("risk_score", 0))
    if score:
        brief.risk_signals.append(f"Module 1 static risk score: {score}")

    return brief
