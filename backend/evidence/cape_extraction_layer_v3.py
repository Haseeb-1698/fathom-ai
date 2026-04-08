#!/usr/bin/env python3
"""
Fathom CAPE Extraction Layer v3.0
===================================
Improved from v2.0 with:
  1. KSPN enrichment bolt-on (enrich_from_kspn)
  2. Resilience guards (depth/size limits for malformed or adversarial reports)
  3. orjson fast-path for large report loading
  4. IOC deduplication at extraction time (not just at format time)
  5. BehaviorIndicator deduplication to prevent duplicate entries
  6. API call n-gram extraction for sequence-aware analysis
  7. Process tree reconstruction with parent-child relationships
  8. Temporal event ordering for behavioral timeline
  9. Configurable extraction limits via ExtractorConfig
 10. Private IP validation fix (172.16-31 range was incomplete)
 11. AMSI payload extraction (CAPEv2 2021+ feature)
 12. Proper entropy calculation on the full binary when sections unavailable
 13. Source tagging on all evidence items for provenance tracking

Architecture
------------
report.json (always present)
    │
    ├── CAPEEvidenceExtractor.from_report_dict(report)
    │       ├── _extract_static()
    │       ├── _extract_api_calls()          + n-gram sequences
    │       ├── _extract_behavior_summary()
    │       ├── _extract_enhanced_events()
    │       ├── _extract_cape_payloads()      + AMSI payloads
    │       ├── _extract_dropped_files()
    │       ├── _extract_network()
    │       ├── _extract_signatures_ttps()
    │       ├── _extract_analysis_meta()
    │       ├── _compute_risk_signals()
    │       └── _compute_known_gaps()
    │
    └── kspn_report_summary.json (when present)
            │
            └── enrich_from_kspn(kspn_summary)
                    ├── MITRE mappings → behaviors (source="kspn")
                    ├── Risk score + reasons → risk_signals
                    ├── PCAP IPs → iocs (source="kspn")
                    └── Family confidence → detections
    │
    ▼
EvidenceBrief (complete, serialisable)
    │
    ▼
build_expert_prompt(brief, task=...)
    │
    ▼
Fathom LLM (Mixtral + LoRA adapter)

Field quirks from real data
---------------------------
- target.file.pe.imports  : dict {dll_name → {dll:str, imports:[{address,name}]}}
- target.file.pe.sections : list of dicts {name,entropy,characteristics,...}
- dropped[i].name         : LIST not string (e.g. ['StartupProfileData-NonInteractive'])
- behavior.processes[].calls[i].arguments : list of {name, value} dicts
- enhanced events: (load/library), (read/registry), (execute/file), (write/file), etc.
- network.udp[i]          : {src, sport, dst, dport, offset, time}
- CAPE.payloads[i].data   : None for large payloads (metadata still present)
- signatures[], ttps[]    : frequently empty [] — always guard
- Resilience guards: deeply nested process trees or oversized reports can cause
  reports may arrive truncated — guard all nested traversals with depth limits.

Usage
-----
    from cape_extraction_layer_v3 import CAPEEvidenceExtractor, ExtractorConfig

    # Default extraction
    extractor = CAPEEvidenceExtractor()
    brief = extractor.from_report_file("/path/to/report.json")

    # With KSPN enrichment
    import json
    kspn = json.load(open("kspn_report_summary.json"))
    extractor.enrich_from_kspn(brief, kspn)

    # Custom limits for resource-constrained environments
    config = ExtractorConfig(max_api_calls_per_process=5000, max_dropped_files=50)
    extractor = CAPEEvidenceExtractor(config=config)
    brief = extractor.from_report_file("/path/to/report.json")

    # Build LLM prompt
    prompt = extractor.build_expert_prompt(brief, task="full_report")
"""

from __future__ import annotations

import re
import json
import hashlib
import ipaddress          # ← FIX #10: proper RFC1918 validation
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
from pathlib import Path

# Optional fast JSON — graceful fallback
try:
    import orjson
    _HAVE_ORJSON = True
except ImportError:
    _HAVE_ORJSON = False

logger = logging.getLogger("fathom.extraction")


# ════════════════════════════════════════════════════════════════
# CONFIGURATION (Improvement #9)
# ════════════════════════════════════════════════════════════════

@dataclass
class ExtractorConfig:
    """
    Tuneable limits that protect against malformed or adversarial report payloads.
    oversized/deeply-nested reports while letting normal reports
    through unmodified.
    """
    # API extraction
    max_api_calls_per_process: int = 10_000  # skip tail if exceeded
    max_suspicious_evidence_per_cat: int = 8

    # File / network caps
    max_dropped_files: int = 100
    max_network_flows: int = 500
    max_iocs: int = 200
    max_behaviors: int = 150

    # String scanning
    max_strings_to_scan: int = 5_000
    max_string_length: int = 500

    # Process tree depth guard (adversarial report resilience)
    max_process_depth: int = 50

    # N-gram window for API sequence extraction
    api_ngram_window: int = 3
    top_ngrams: int = 20

    # Report size guard (bytes) — skip loading if bigger
    max_report_size_bytes: int = 500_000_000  # 500MB


# ════════════════════════════════════════════════════════════════
# ENUMS & BASE DATA STRUCTURES
# ════════════════════════════════════════════════════════════════

class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class IOCType(Enum):
    IP           = "ip"
    DOMAIN       = "domain"
    URL          = "url"
    HASH_MD5     = "hash_md5"
    HASH_SHA1    = "hash_sha1"
    HASH_SHA256  = "hash_sha256"
    EMAIL        = "email"
    FILE_PATH    = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX        = "mutex"
    USER_AGENT   = "user_agent"


@dataclass
class IOC:
    type: IOCType
    value: str
    context: str = ""
    confidence: float = 0.0
    source: str = "report.json"     # ← FIX #13: provenance tag

    def to_dict(self):
        return {
            "type": self.type.value,
            "value": self.value,
            "context": self.context,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class BehaviorIndicator:
    category: str
    description: str
    evidence: List[str]         = field(default_factory=list)
    severity: Severity          = Severity.MEDIUM
    attack_techniques: List[str]= field(default_factory=list)
    source: str = "report.json"  # ← FIX #13: provenance tag

    def to_dict(self):
        return {
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "attack_techniques": self.attack_techniques,
            "source": self.source,
        }


@dataclass
class Capability:
    name: str
    description: str
    source: str          # yara / cape / heuristic / capa / kspn
    confidence: float = 0.0

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "confidence": self.confidence,
        }


@dataclass
class AnalysisMeta:
    """CAPE-specific analysis metadata."""
    analysis_id: int        = 0
    machine: str            = ""
    package: str            = ""
    duration: int           = 0     # seconds
    started: str            = ""
    ended: str              = ""    # ← NEW: capture end time for duration calc
    malscore: float         = 0.0
    malstatus: str          = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ProcessNode:
    """Reconstructed process tree node (Improvement #7)."""
    pid: int
    ppid: int
    name: str
    path: str = ""
    cmd: str = ""
    children: List[int] = field(default_factory=list)

    def to_dict(self):
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "path": self.path,
            "cmd": self.cmd,
            "children": self.children,
        }


@dataclass
class EvidenceBrief:
    """
    Structured evidence package fed to the expert LLM.
    Every field is populated deterministically — no inference by the extractor.
    """
    # Identity
    sample_id: str       = ""
    file_name: str       = ""
    file_type: str       = ""
    file_size: int       = 0
    hashes: Dict[str,str]= field(default_factory=dict)

    # Analysis context
    meta: AnalysisMeta   = field(default_factory=AnalysisMeta)

    # Static PE
    pe_sections: List[Dict]     = field(default_factory=list)
    pe_imports: Dict[str,List]  = field(default_factory=dict)   # dll → [fn, ...]
    pe_imphash: str             = ""
    pe_timestamp: str           = ""
    pe_compile_ts: str          = ""
    pe_entrypoint: str          = ""
    pe_signed: bool             = False
    pe_signers: List[str]       = field(default_factory=list)
    pe_versioninfo: List[Dict]  = field(default_factory=list)
    pe_entropy_sections: List[Dict] = field(default_factory=list)  # {name, entropy}

    # Evidence extracted
    iocs: List[IOC]                      = field(default_factory=list)
    behaviors: List[BehaviorIndicator]   = field(default_factory=list)
    capabilities: List[Capability]       = field(default_factory=list)

    # Confidence signals
    yara_matches: List[str]              = field(default_factory=list)
    cape_yara_matches: List[str]         = field(default_factory=list)
    detections: List[Dict]               = field(default_factory=list)   # [{family, source}]
    entropy: float                       = 0.0
    packed: bool                         = False

    # Dynamic — network
    network_hosts: List[Dict]            = field(default_factory=list)
    network_flows: List[Dict]            = field(default_factory=list)   # {dst,port,proto}
    network_dns: List[str]               = field(default_factory=list)
    network_http: List[Dict]             = field(default_factory=list)

    # Dynamic — behavior
    processes: List[str]                 = field(default_factory=list)   # [name (pid)]
    process_tree: List[ProcessNode]      = field(default_factory=list)   # ← NEW #7
    commands_executed: List[str]         = field(default_factory=list)
    files_written: List[str]             = field(default_factory=list)
    files_deleted: List[str]             = field(default_factory=list)
    registry_reads: List[str]            = field(default_factory=list)
    registry_writes: List[str]           = field(default_factory=list)
    mutexes: List[str]                   = field(default_factory=list)
    services_created: List[str]          = field(default_factory=list)

    # Extracted artifacts
    cape_payloads: List[Dict]            = field(default_factory=list)
    cape_configs: List[Dict]             = field(default_factory=list)
    dropped_files: List[Dict]            = field(default_factory=list)
    amsi_payloads: List[Dict]            = field(default_factory=list)   # ← NEW #11

    # API call summary (unique APIs seen, category counts)
    api_unique_count: int                = 0
    api_category_counts: Dict[str,int]   = field(default_factory=dict)
    suspicious_apis_seen: List[str]      = field(default_factory=list)
    api_ngrams: List[Tuple[str,...]]     = field(default_factory=list)   # ← NEW #6

    # Strings of interest (from target + payloads)
    suspicious_strings: List[str]        = field(default_factory=list)

    # Risk assessment
    risk_signals: List[str]              = field(default_factory=list)
    benign_signals: List[str]            = field(default_factory=list)

    # Anti-hallucination: what the sandbox did NOT produce
    known_gaps: List[str]                = field(default_factory=list)

    # Temporal ordering (Improvement #8)
    event_timeline: List[Dict]           = field(default_factory=list)  # [{time, event, detail}]

    def to_dict(self) -> dict:
        d = {
            "sample_id":       self.sample_id,
            "file_name":       self.file_name,
            "file_type":       self.file_type,
            "file_size":       self.file_size,
            "hashes":          self.hashes,
            "meta":            self.meta.to_dict(),
            "pe_sections":     self.pe_sections,
            "pe_imports":      self.pe_imports,
            "pe_imphash":      self.pe_imphash,
            "pe_compile_ts":   self.pe_compile_ts,
            "pe_entrypoint":   self.pe_entrypoint,
            "pe_signed":       self.pe_signed,
            "pe_signers":      self.pe_signers,
            "pe_versioninfo":  self.pe_versioninfo,
            "iocs":            [i.to_dict() for i in self.iocs],
            "behaviors":       [b.to_dict() for b in self.behaviors],
            "capabilities":    [c.to_dict() for c in self.capabilities],
            "yara_matches":    self.yara_matches,
            "cape_yara_matches": self.cape_yara_matches,
            "detections":      self.detections,
            "entropy":         self.entropy,
            "packed":          self.packed,
            "network_hosts":   self.network_hosts,
            "network_flows":   self.network_flows,
            "network_dns":     self.network_dns,
            "network_http":    self.network_http,
            "processes":       self.processes,
            "process_tree":    [p.to_dict() for p in self.process_tree],
            "commands_executed": self.commands_executed,
            "files_written":   self.files_written,
            "files_deleted":   self.files_deleted,
            "registry_reads":  self.registry_reads,
            "registry_writes": self.registry_writes,
            "mutexes":         self.mutexes,
            "services_created": self.services_created,
            "cape_payloads":   self.cape_payloads,
            "cape_configs":    self.cape_configs,
            "dropped_files":   self.dropped_files,
            "amsi_payloads":   self.amsi_payloads,
            "api_unique_count": self.api_unique_count,
            "api_category_counts": self.api_category_counts,
            "suspicious_apis_seen": self.suspicious_apis_seen,
            "api_ngrams":      [list(ng) for ng in self.api_ngrams],
            "suspicious_strings": self.suspicious_strings,
            "risk_signals":    self.risk_signals,
            "benign_signals":  self.benign_signals,
            "known_gaps":      self.known_gaps,
            "event_timeline":  self.event_timeline,
        }
        return d


# ════════════════════════════════════════════════════════════════
# DETECTION KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════════

# API name → (category, ATT&CK techniques, severity)
SUSPICIOUS_API_MAP: Dict[str, tuple] = {
    # Process injection
    "CreateRemoteThread":          ("process_injection",  ["T1055.003"], Severity.HIGH),
    "CreateRemoteThreadEx":        ("process_injection",  ["T1055.003"], Severity.HIGH),
    "VirtualAllocEx":              ("process_injection",  ["T1055"],     Severity.HIGH),
    "WriteProcessMemory":          ("process_injection",  ["T1055"],     Severity.HIGH),
    "NtMapViewOfSection":          ("process_injection",  ["T1055.001"], Severity.HIGH),
    "NtUnmapViewOfSection":        ("process_injection",  ["T1055.001"], Severity.HIGH),
    "QueueUserAPC":                ("process_injection",  ["T1055.004"], Severity.HIGH),
    "SetThreadContext":            ("process_injection",  ["T1055.003"], Severity.HIGH),
    "NtCreateThreadEx":            ("process_injection",  ["T1055"],     Severity.HIGH),
    "RtlCreateUserThread":         ("process_injection",  ["T1055"],     Severity.HIGH),
    "NtWriteVirtualMemory":        ("process_injection",  ["T1055"],     Severity.HIGH),
    "NtAllocateVirtualMemory":     ("process_injection",  ["T1055"],     Severity.MEDIUM),

    # Persistence
    "RegSetValueExA":              ("persistence",        ["T1547.001"], Severity.HIGH),
    "RegSetValueExW":              ("persistence",        ["T1547.001"], Severity.HIGH),
    "RegCreateKeyExA":             ("persistence",        ["T1547.001"], Severity.MEDIUM),
    "RegCreateKeyExW":             ("persistence",        ["T1547.001"], Severity.MEDIUM),
    "CreateServiceA":              ("persistence",        ["T1543.003"], Severity.HIGH),
    "CreateServiceW":              ("persistence",        ["T1543.003"], Severity.HIGH),
    "SetWindowsHookExA":           ("persistence",        ["T1546.011"], Severity.HIGH),
    "SetWindowsHookExW":           ("persistence",        ["T1546.011"], Severity.HIGH),

    # Credential theft
    "CredEnumerateA":              ("credential_theft",   ["T1555"],     Severity.CRITICAL),
    "CredEnumerateW":              ("credential_theft",   ["T1555"],     Severity.CRITICAL),
    "LsaRetrievePrivateData":      ("credential_theft",   ["T1003"],     Severity.CRITICAL),
    "CryptUnprotectData":          ("credential_theft",   ["T1555"],     Severity.HIGH),
    "SamQueryInformationUser":     ("credential_theft",   ["T1003.002"], Severity.CRITICAL),
    "NtCreateFile":                ("credential_theft",   ["T1003"],     Severity.INFO),

    # Defense evasion / anti-analysis
    "IsDebuggerPresent":           ("defense_evasion",    ["T1622"],     Severity.MEDIUM),
    "CheckRemoteDebuggerPresent":  ("defense_evasion",    ["T1622"],     Severity.MEDIUM),
    "NtQueryInformationProcess":   ("defense_evasion",    ["T1622"],     Severity.MEDIUM),
    "GetTickCount":                ("defense_evasion",    ["T1497.003"], Severity.LOW),
    "OutputDebugStringA":          ("defense_evasion",    ["T1622"],     Severity.LOW),
    "FindWindowA":                 ("defense_evasion",    ["T1497.001"], Severity.LOW),
    "FindWindowW":                 ("defense_evasion",    ["T1497.001"], Severity.LOW),
    "NtQuerySystemInformation":    ("defense_evasion",    ["T1497"],     Severity.MEDIUM),
    "EnumWindows":                 ("defense_evasion",    ["T1497.001"], Severity.LOW),
    # NEW: Additional evasion APIs seen in modern malware
    "NtDelayExecution":            ("defense_evasion",    ["T1497.003"], Severity.MEDIUM),
    "NtQueryAttributesFile":       ("defense_evasion",    ["T1083"],     Severity.LOW),

    # Keylogging / input capture
    "GetAsyncKeyState":            ("keylogging",         ["T1056.001"], Severity.HIGH),
    "GetKeyState":                 ("keylogging",         ["T1056.001"], Severity.HIGH),
    "GetForegroundWindow":         ("keylogging",         ["T1056.001"], Severity.MEDIUM),
    "GetWindowTextA":              ("keylogging",         ["T1056.001"], Severity.MEDIUM),
    "GetWindowTextW":              ("keylogging",         ["T1056.001"], Severity.MEDIUM),

    # Screen / clipboard capture
    "BitBlt":                      ("screen_capture",     ["T1113"],     Severity.MEDIUM),
    "GetDC":                       ("screen_capture",     ["T1113"],     Severity.LOW),
    "CreateCompatibleBitmap":      ("screen_capture",     ["T1113"],     Severity.MEDIUM),
    "GetClipboardData":            ("clipboard_capture",  ["T1115"],     Severity.HIGH),
    "OpenClipboard":               ("clipboard_capture",  ["T1115"],     Severity.MEDIUM),

    # Network communication
    "InternetOpenA":               ("network_c2",         ["T1071"],     Severity.MEDIUM),
    "InternetOpenW":               ("network_c2",         ["T1071"],     Severity.MEDIUM),
    "HttpSendRequestA":            ("network_c2",         ["T1071.001"], Severity.MEDIUM),
    "HttpSendRequestW":            ("network_c2",         ["T1071.001"], Severity.MEDIUM),
    "WinHttpOpen":                 ("network_c2",         ["T1071.001"], Severity.MEDIUM),
    "WinHttpSendRequest":          ("network_c2",         ["T1071.001"], Severity.MEDIUM),
    "URLDownloadToFileA":          ("download_execution", ["T1105"],     Severity.HIGH),
    "URLDownloadToFileW":          ("download_execution", ["T1105"],     Severity.HIGH),
    "WSAConnect":                  ("network_c2",         ["T1071"],     Severity.MEDIUM),
    "connect":                     ("network_c2",         ["T1071"],     Severity.MEDIUM),

    # Process manipulation
    "ShellExecuteA":               ("execution",          ["T1059"],     Severity.MEDIUM),
    "ShellExecuteW":               ("execution",          ["T1059"],     Severity.MEDIUM),
    "ShellExecuteExA":             ("execution",          ["T1059"],     Severity.MEDIUM),
    "ShellExecuteExW":             ("execution",          ["T1059"],     Severity.MEDIUM),
    "CreateProcessA":              ("execution",          ["T1059"],     Severity.MEDIUM),
    "CreateProcessW":              ("execution",          ["T1059"],     Severity.MEDIUM),
    "WinExec":                     ("execution",          ["T1059"],     Severity.HIGH),
    # NEW: CreateProcessInternalW often used as lower-level process creation
    "CreateProcessInternalW":      ("execution",          ["T1106"],     Severity.HIGH),

    # Privilege escalation
    "AdjustTokenPrivileges":       ("privilege_escalation", ["T1134"],   Severity.HIGH),
    "ImpersonateLoggedOnUser":     ("privilege_escalation", ["T1134.001"],Severity.HIGH),
    "OpenProcessToken":            ("privilege_escalation", ["T1134"],   Severity.MEDIUM),

    # Memory operations
    "VirtualProtect":              ("memory_manipulation", ["T1055"],    Severity.MEDIUM),
    "VirtualProtectEx":            ("memory_manipulation", ["T1055"],    Severity.HIGH),

    # NEW: WMI-based execution (increasingly common in modern malware)
    "CoCreateInstance":            ("wmi_execution",      ["T1047"],     Severity.MEDIUM),
    "IWbemServices_ExecMethod":    ("wmi_execution",      ["T1047"],     Severity.HIGH),
}

# Command-line pattern matching
COMMAND_PATTERNS = [
    (r'powershell[^\s]* +-[Ee][Nn][Cc]',                    "Encoded PowerShell (T1059.001 + T1027)", Severity.HIGH,   ["T1059.001", "T1027"]),
    (r'powershell[^\s]* +-[Ee][Xx][Ee][Cc][Uu][Tt][Ii]',   "PS ExecutionPolicy bypass (T1059.001)",  Severity.HIGH,   ["T1059.001"]),
    (r'powershell[^\s]* +-[Nn][Oo][Pp]',                    "PS -NoProfile execution",                Severity.MEDIUM, ["T1059.001"]),
    (r'cmd\.exe\s+/[cC]',                                   "Cmd shell execution (T1059.003)",        Severity.MEDIUM, ["T1059.003"]),
    (r'certutil.*-urlcache',                                 "Certutil download (T1105)",              Severity.HIGH,   ["T1105"]),
    (r'bitsadmin.*transfer',                                 "BITS download (T1197)",                  Severity.HIGH,   ["T1197"]),
    (r'mshta\s+https?://',                                   "MSHTA remote execution (T1218.005)",     Severity.HIGH,   ["T1218.005"]),
    (r'regsvr32\s+/[sS].*https?://',                        "Regsvr32 remote load (T1218.010)",       Severity.HIGH,   ["T1218.010"]),
    (r'schtasks\s+/[cC][rR][eE][aA][tT][eE]',               "Scheduled task creation (T1053.005)",    Severity.HIGH,   ["T1053.005"]),
    (r'sc\s+create',                                        "Service creation (T1543.003)",            Severity.HIGH,   ["T1543.003"]),
    (r'wmic[^\s]* .*process.*call.*create',                 "WMIC process creation (T1047)",          Severity.HIGH,   ["T1047"]),
    (r'ShowWindow[^\s]*;\s*\$consolePtr',                   "Console window hidden (T1564.003)",      Severity.MEDIUM, ["T1564.003"]),
    (r'\.NET\\Framework.*csc\.exe',                         ".NET on-the-fly compilation (T1027)",   Severity.MEDIUM, ["T1027"]),
    # NEW patterns
    (r'rundll32.*javascript:',                               "Rundll32 JS execution (T1218.011)",     Severity.HIGH,   ["T1218.011"]),
    (r'cscript|wscript.*\.js|\.vbs',                        "Script host execution (T1059.005/7)",   Severity.MEDIUM, ["T1059.005"]),
    (r'reg\s+add.*\\Run',                                    "Reg.exe Run key persistence (T1547.001)",Severity.HIGH,  ["T1547.001"]),
]

# File path patterns that indicate suspicious destinations
SUSPICIOUS_FILE_PATHS = [
    (r'\\Temp\\.*\.(exe|dll|bat|ps1|vbs|js)',   "Executable dropped to Temp (T1204)",          Severity.HIGH,   ["T1204"]),
    (r'\\AppData\\.*\.(exe|dll)',               "Executable in AppData (T1547)",               Severity.HIGH,   ["T1547"]),
    (r'\\Start\s*Menu\\Programs\\Startup\\',   "Startup folder persistence (T1547.001)",       Severity.HIGH,   ["T1547.001"]),
    (r'\\System32\\.*\.(exe|dll)',             "File written to System32",                     Severity.HIGH,   ["T1036.005"]),
    (r'\\Roaming\\Microsoft\\Windows\\',       "Roaming profile persistence path",             Severity.MEDIUM, ["T1547"]),
    (r'\\CONOUT\$|\\CONIN\$',                  "Console handle access",                        Severity.INFO,   []),
]

# Registry key patterns
SUSPICIOUS_REGISTRY_KEYS = [
    (r'CurrentVersion\\Run',                   "Run key persistence (T1547.001)",              Severity.HIGH,   ["T1547.001"]),
    (r'CurrentVersion\\RunOnce',               "RunOnce persistence (T1547.001)",              Severity.HIGH,   ["T1547.001"]),
    (r'Lsa\\FipsAlgorithmPolicy',              "FIPS policy query",                            Severity.INFO,   []),
    (r'Lsa\\Secrets',                          "LSA secrets access (T1003.004)",               Severity.CRITICAL, ["T1003.004"]),
    (r'SAM\\Domains',                          "SAM database access (T1003.002)",              Severity.CRITICAL, ["T1003.002"]),
    (r'WinLogon\\.*Userinit',                  "Winlogon hijack (T1547.004)",                  Severity.HIGH,   ["T1547.004"]),
    (r'Policies.*DisableTaskMgr',              "Task manager disabled (T1562.001)",            Severity.HIGH,   ["T1562.001"]),
    # NEW
    (r'Image\s*File\s*Execution\s*Options',    "IFEO debugger hijack (T1546.012)",             Severity.HIGH,   ["T1546.012"]),
    (r'DisableRealtimeMonitoring',             "Defender disabled (T1562.001)",                 Severity.CRITICAL,["T1562.001"]),
]

# Strings in static/payload content
STATIC_STRING_PATTERNS = [
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',      "IP-based URL (possible C2)",        Severity.HIGH),
    (r'powershell\s*-[Ee][Nn][Cc]',                         "Encoded PowerShell command",        Severity.HIGH),
    (r'VirtualBox|VMware|QEMU|Hyper-V|vbox',                "VM detection string",               Severity.MEDIUM),
    (r'Wireshark|Fiddler|x64dbg|OllyDbg|Procmon',          "Analysis tool detection",           Severity.MEDIUM),
    (r'sbiedll\.dll|dbghelp\.dll|SbieDll',                  "Sandbox detection DLL",             Severity.MEDIUM),
    (r'-----BEGIN (RSA|EC|DSA|DH|X942)',                    "Embedded cryptographic material",   Severity.MEDIUM),
    (r'[0-9A-Fa-f]{64}',                                    "Possible embedded SHA-256 / key",   Severity.LOW),
    (r'(SELECT|INSERT|UPDATE|DELETE)\s+\w+\s+FROM',         "Embedded SQL query",                Severity.MEDIUM),
]

# Known packer section names
PACKER_SECTION_NAMES = [
    "UPX", "ASPack", "PECompact", "Themida", "VMProtect",
    "Enigma", "ExeStealth", "MEW", "MPRESS", "Petite", ".MPRESS", ".vmp",
]

# Benign DNS resolvers / CDNs that are noise
BENIGN_HOSTS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "208.67.220.220",
}

# Benign DNS suffixes to filter out
BENIGN_DNS_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com",
    "google.com", "gstatic.com", "googleapis.com",
    "digicert.com", "verisign.com",          # certificate infra
    "msftconnecttest.com",                    # Windows connectivity check
    "msftncsi.com",                           # Network status indicator
)


def _is_private(ip: str) -> bool:
    """
    FIX #10: Use stdlib ipaddress for correct RFC1918/link-local checks.
    The v2 code used string prefix matching which missed 172.20-31.x.x
    and could false-positive on e.g. "10.0.0.1" embedded in strings.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return False


def _normalise_name(name_field) -> str:
    """CAPE stores dropped file names as lists. Return first element as string."""
    if isinstance(name_field, list):
        return str(name_field[0]) if name_field else ""
    return str(name_field) if name_field else ""


# ════════════════════════════════════════════════════════════════
# CAPE EVIDENCE EXTRACTOR
# ════════════════════════════════════════════════════════════════

class CAPEEvidenceExtractor:
    """
    Deterministic extraction of structured evidence from a CAPEv2 report.json.
    No LLM calls. No inference. Every output field traces to a specific
    artifact in the report.
    """

    def __init__(self, config: Optional[ExtractorConfig] = None):
        self.config = config or ExtractorConfig()

    # ── Entry points ──────────────────────────────────────────

    def from_report_file(self, path: str) -> EvidenceBrief:
        """
        Load report.json from disk and extract.
        Uses orjson if available for ~3x faster parsing on large reports.
        Includes size guard against oversized or adversarial report payloads.
        """
        file_path = Path(path)
        file_size = file_path.stat().st_size

        # FIX #2: Size guard
        if file_size > self.config.max_report_size_bytes:
            logger.warning(
                "Report %s is %d bytes (limit %d) — skipping to avoid OOM.",
                path, file_size, self.config.max_report_size_bytes,
            )
            brief = EvidenceBrief()
            brief.known_gaps.append(
                f"Report file too large ({file_size:,} bytes) — extraction skipped."
            )
            return brief

        # FIX #3: orjson fast-path
        raw = file_path.read_bytes()
        if _HAVE_ORJSON:
            try:
                report = orjson.loads(raw)
            except orjson.JSONDecodeError as e:
                logger.error("orjson failed on %s: %s — falling back to json", path, e)
                report = json.loads(raw)
        else:
            report = json.loads(raw)

        return self.from_report_dict(report)

    def from_report_dict(self, report: dict) -> EvidenceBrief:
        """Extract evidence from an already-loaded CAPEv2 report dict."""
        # Reset per-analysis dedup state
        self._seen_file_behaviors: Set[str] = set()
        self._seen_ioc_values: Set[str] = set()          # FIX #4: IOC dedup at extraction
        self._seen_behavior_keys: Set[str] = set()        # FIX #5: behavior dedup

        brief = EvidenceBrief()
        self._extract_static(report, brief)
        self._extract_detections(report, brief)
        self._extract_api_calls(report, brief)
        self._extract_behavior_summary(report, brief)
        self._extract_enhanced_events(report, brief)
        self._extract_cape_payloads(report, brief)
        self._extract_amsi_payloads(report, brief)        # NEW #11
        self._extract_dropped_files(report, brief)
        self._extract_network(report, brief)
        self._extract_signatures_ttps(report, brief)
        self._extract_analysis_meta(report, brief)
        self._extract_process_tree(report, brief)         # NEW #7
        self._compute_risk_signals(brief)
        self._compute_known_gaps(report, brief)

        # Enforce global caps (FIX #2: adversarial report resilience)
        brief.iocs = brief.iocs[:self.config.max_iocs]
        brief.behaviors = brief.behaviors[:self.config.max_behaviors]
        brief.network_flows = brief.network_flows[:self.config.max_network_flows]

        return brief

    # ── KSPN ENRICHMENT (Improvement #1) ──────────────────────

    def enrich_from_kspn(self, brief: EvidenceBrief, kspn: dict) -> None:
        """
        Bolt-on enrichment from kspn_report_summary.json.
        Additive only — if kspn is absent, the extractor works fine from
        report.json alone. Every item injected is tagged source="kspn".

        Real kspn_report_summary.json schema (verified from actual output):
            analysis_id:       int
            family_guess:      str          ← NOT "family"
            family_confidence: int (0-100)  ← NOT float 0-1; divide by 100
            classification:    str
            objective:         str
            risk_rating:       str
            risk_score:        int (0-100)
            risk_reasons:      [str]
            ioc_counts:        {ips, domains, urls, registry_keys, files, mutexes}
            artifacts:         {payloads, dropped, procdump, procmemory, screenshots, pcap}
            mitre:             [{technique, name, confidence, evidence}]
                               ← keys are "technique" and "name", NOT "technique_id"/"technique_name"
            capabilities:      [{name, confidence, evidence}]
                               ← confidence is str "High"/"Medium"/"Low", NOT float
            family_top_evidence: [{family, weight, reason, source}]

        Note: pcap_ips is NOT a field in kspn_report_summary.json.
        Full PCAP-parsed IPs appear only in kspn_report.md (text). This
        enrichment uses ioc_counts.ips as a count signal only.
        """
        if not kspn:
            return

        # String confidence labels → float (for Capability.confidence field)
        CONF_MAP = {"High": 0.9, "Medium": 0.6, "Low": 0.3}

        # MITRE ATT&CK mappings → behaviors with high confidence
        # Real field names: "technique" and "name" (not "technique_id"/"technique_name")
        for tech in kspn.get("mitre", []):
            tech_id   = tech.get("technique", "")
            tech_name = tech.get("name", "")
            evidence  = tech.get("evidence", "")
            if tech_id:
                bkey = f"kspn_ttp|{tech_id}"
                if bkey not in self._seen_behavior_keys:
                    self._seen_behavior_keys.add(bkey)
                    brief.behaviors.append(BehaviorIndicator(
                        category="ttp_match",
                        description=f"KSPN-mapped TTP: {tech_id} — {tech_name}",
                        evidence=[evidence] if evidence else [f"KSPN pre-mapped: {tech_id}"],
                        severity=Severity.HIGH,
                        attack_techniques=[tech_id] if tech_id.startswith("T") else [],
                        source="kspn",
                    ))

        # Family detection with confidence
        # Real field is "family_guess"; confidence is int 0-100, convert to 0.0-1.0
        family      = kspn.get("family_guess", "")
        family_conf = kspn.get("family_confidence", 0) / 100.0
        if family:
            brief.detections.append({
                "family":  family,
                "sources": [f"kspn (confidence: {family_conf:.0%})"],
            })
            brief.capabilities.append(Capability(
                name=f"{family} family match (KSPN)",
                description=f"KSPN identified sample as {family} with {family_conf:.0%} confidence",
                source="kspn",
                confidence=family_conf,
            ))

        # Risk score and reasons → risk_signals
        risk_score = kspn.get("risk_score")
        risk_rating = kspn.get("risk_rating", "")
        if risk_score is not None:
            brief.risk_signals.append(
                f"KSPN risk score: {risk_score}/100 ({risk_rating})" if risk_rating
                else f"KSPN risk score: {risk_score}/100"
            )
        for reason in kspn.get("risk_reasons", []):
            brief.risk_signals.append(f"[kspn] {reason}")

        # Capabilities — confidence is "High"/"Medium"/"Low" string, map to float
        for cap in kspn.get("capabilities", []):
            cap_name = cap.get("name", "")
            cap_conf = CONF_MAP.get(str(cap.get("confidence", "Medium")), 0.5)
            if cap_name:
                brief.capabilities.append(Capability(
                    name=cap_name,
                    description=f"KSPN-inferred capability: {cap_name}",
                    source="kspn",
                    confidence=cap_conf,
                ))

        # IOC count signal — kspn_report_summary has counts but not the IPs themselves
        # Full IPs are in kspn_report.md; use count as a risk signal only
        ioc_counts = kspn.get("ioc_counts", {})
        ip_count = ioc_counts.get("ips", 0)
        if ip_count > 1:
            brief.risk_signals.append(
                f"[kspn] {ip_count} external IP indicator(s) observed (full list in kspn_report.md)"
            )

    # ── Static / PE extraction ────────────────────────────────

    def _extract_static(self, report: dict, brief: EvidenceBrief):
        tf = report.get("target", {}).get("file", {})

        brief.sample_id = tf.get("sha256", tf.get("md5", "unknown"))
        brief.file_name = tf.get("name", "")
        brief.file_type = tf.get("type", "")
        brief.file_size = tf.get("size", 0)
        brief.hashes = {
            "md5":    tf.get("md5", ""),
            "sha1":   tf.get("sha1", ""),
            "sha256": tf.get("sha256", ""),
            "ssdeep": tf.get("ssdeep", ""),
            "tlsh":   tf.get("tlsh", ""),
        }

        # YARA on the sample itself
        for y in tf.get("yara", []):
            name = y.get("name", "") if isinstance(y, dict) else str(y)
            if name:
                brief.yara_matches.append(name)

        for y in tf.get("cape_yara", []):
            name = y.get("name", "") if isinstance(y, dict) else str(y)
            if name:
                brief.cape_yara_matches.append(name)

        # Static strings of interest
        strings = tf.get("strings", [])
        if strings:
            self._scan_strings(
                strings[:self.config.max_strings_to_scan],
                brief, source="static_strings",
            )

        # PE metadata (only present when CAPE's static analyser ran)
        pe = tf.get("pe", {})
        if pe:
            self._extract_pe(pe, brief)

    def _extract_pe(self, pe: dict, brief: EvidenceBrief):
        brief.pe_imphash   = pe.get("imphash", "")
        brief.pe_entrypoint= pe.get("entrypoint", "")
        brief.pe_compile_ts= pe.get("timestamp", "")

        # Imports: dict {dll_name → {dll:str, imports:[{address,name}]}}
        imports_raw = pe.get("imports", {})
        if isinstance(imports_raw, dict):
            for dll_key, dll_data in imports_raw.items():
                if isinstance(dll_data, dict):
                    dll_name = dll_data.get("dll", dll_key)
                    fn_names = [fn.get("name", "") for fn in dll_data.get("imports", []) if fn.get("name")]
                    brief.pe_imports[dll_name] = fn_names

        # Sections: list of dicts
        total_high_entropy = 0
        for sec in pe.get("sections", []):
            brief.pe_sections.append({
                "name":           sec.get("name", ""),
                "entropy":        float(sec.get("entropy", 0)),
                "virtual_address":sec.get("virtual_address", ""),
                "size":           sec.get("size_of_data", ""),
                "characteristics":sec.get("characteristics", ""),
            })
            brief.pe_entropy_sections.append({
                "name":    sec.get("name", ""),
                "entropy": float(sec.get("entropy", 0)),
            })
            # Packer detection via section name
            sec_name = sec.get("name", "")
            for packer in PACKER_SECTION_NAMES:
                if packer.lower() in sec_name.lower():
                    brief.packed = True
                    self._add_behavior(brief,
                        category="packing",
                        description=f"Packer section detected: {packer}",
                        evidence=[f"Section: {sec_name}"],
                        severity=Severity.MEDIUM,
                        attack_techniques=["T1027.002"],
                    )
            # High-entropy section
            sec_entropy = float(sec.get("entropy", 0))
            if sec_entropy > 7.2:
                total_high_entropy += 1
                brief.packed = True
                # Only add behavior for first 3 high-entropy sections to reduce noise
                if total_high_entropy <= 3:
                    self._add_behavior(brief,
                        category="packing",
                        description=f"High-entropy section {sec_name} ({sec_entropy:.2f}) — packed or encrypted",
                        evidence=[f"Section {sec_name} entropy={sec_entropy:.2f}"],
                        severity=Severity.MEDIUM,
                        attack_techniques=["T1027.002"],
                    )

        # FIX #12: If all sections are high-entropy, report aggregate
        if total_high_entropy > 3:
            self._add_behavior(brief,
                category="packing",
                description=f"{total_high_entropy} sections with entropy > 7.2 — likely fully packed binary",
                evidence=[f"Total high-entropy sections: {total_high_entropy}"],
                severity=Severity.HIGH,
                attack_techniques=["T1027.002"],
            )

        # Digital signature
        signers = pe.get("digital_signers", []) or pe.get("guest_signers", [])
        if signers:
            brief.pe_signed  = True
            brief.pe_signers = [str(s) for s in signers]

        # Version info
        brief.pe_versioninfo = pe.get("versioninfo", []) or []

    # ── Detection / malscore ──────────────────────────────────

    def _extract_detections(self, report: dict, brief: EvidenceBrief):
        brief.meta.malscore   = float(report.get("malscore", 0))
        brief.meta.malstatus  = str(report.get("malstatus", ""))

        for det in report.get("detections", []):
            family = det.get("family", "")
            if not family:
                continue
            sources = []
            for detail in det.get("details", []):
                if isinstance(detail, dict):
                    for k, v in detail.items():
                        sources.append(f"{k}: {v}")
            brief.detections.append({"family": family, "sources": sources})
            # Family detection = capability
            brief.capabilities.append(Capability(
                name=f"{family} family match",
                description=f"CAPE identified sample as {family}",
                source="detection",
                confidence=0.85,
            ))

    # ── API call extraction ───────────────────────────────────

    def _extract_api_calls(self, report: dict, brief: EvidenceBrief):
        """
        Build a unique API set across all processes — O(n) single pass.
        We don't store all 10K+ raw calls; we store the semantic summary.

        NEW in v3: Also extracts API call n-grams for sequence-aware analysis.
        """
        all_apis: Set[str]      = set()
        category_counts: Dict[str, int] = {}
        suspicious_seen: Dict[str, dict]= {}  # api → {category, techniques, severity, evidence}
        api_sequences: List[str] = []  # Ordered API names for n-gram extraction

        for proc in report.get("behavior", {}).get("processes", []):
            proc_name = proc.get("process_name", "?")
            pid       = proc.get("process_id", "?")
            proc_api_seq: List[str] = []  # Per-process sequence

            calls = proc.get("calls", [])
            # Resilience guard — cap calls per process to prevent OOM on large reports
            if len(calls) > self.config.max_api_calls_per_process:
                logger.warning(
                    "Process %s (PID %s) has %d calls — capping at %d",
                    proc_name, pid, len(calls), self.config.max_api_calls_per_process,
                )
                calls = calls[:self.config.max_api_calls_per_process]

            for call in calls:
                api      = call.get("api", "")
                if not api:
                    continue
                all_apis.add(api)
                proc_api_seq.append(api)

                # Count by CAPE category
                cat = call.get("category", "misc")
                category_counts[cat] = category_counts.get(cat, 0) + 1

                # Map to suspicious API knowledge base
                if api in SUSPICIOUS_API_MAP:
                    ev_category, techniques, severity = SUSPICIOUS_API_MAP[api]
                    if api not in suspicious_seen:
                        # Capture first-seen argument context
                        args = call.get("arguments", [])
                        arg_str = ""
                        if args:
                            arg_str = ", ".join(
                                f"{a['name']}={str(a.get('value',''))[:60]}"
                                for a in args[:3] if isinstance(a, dict)
                            )
                        suspicious_seen[api] = {
                            "category": ev_category,
                            "techniques": techniques,
                            "severity": severity,
                            "evidence": f"{api} called by {proc_name} (PID {pid})" +
                                        (f" [{arg_str}]" if arg_str else ""),
                        }

                        # Timeline event (Improvement #8)
                        ts = call.get("time", "")
                        if ts:
                            brief.event_timeline.append({
                                "time": ts,
                                "event": f"Suspicious API: {api}",
                                "detail": f"{proc_name} (PID {pid})",
                            })

            # Accumulate for n-gram extraction
            api_sequences.extend(proc_api_seq)

        brief.api_unique_count    = len(all_apis)
        brief.api_category_counts = category_counts
        brief.suspicious_apis_seen= list(suspicious_seen.keys())

        # NEW #6: Extract API n-grams
        self._extract_api_ngrams(api_sequences, brief)

        # Group suspicious APIs into BehaviorIndicators by category
        grouped: Dict[str, dict] = {}
        for api, info in suspicious_seen.items():
            cat = info["category"]
            if cat not in grouped:
                grouped[cat] = {
                    "techniques": list(info["techniques"]),
                    "severity":   info["severity"],
                    "evidence":   [],
                }
            grouped[cat]["evidence"].append(info["evidence"])
            # Merge techniques (union)
            for t in info["techniques"]:
                if t not in grouped[cat]["techniques"]:
                    grouped[cat]["techniques"].append(t)
            # Escalate severity if needed
            if info["severity"].value == "critical":
                grouped[cat]["severity"] = Severity.CRITICAL
            elif info["severity"].value == "high" and grouped[cat]["severity"] != Severity.CRITICAL:
                grouped[cat]["severity"] = Severity.HIGH

        for cat, data in grouped.items():
            self._add_behavior(brief,
                category=cat,
                description=f"Suspicious API behaviour: {cat.replace('_', ' ')}",
                evidence=data["evidence"][:self.config.max_suspicious_evidence_per_cat],
                severity=data["severity"],
                attack_techniques=data["techniques"],
            )

    def _extract_api_ngrams(self, api_seq: List[str], brief: EvidenceBrief):
        """
        NEW #6: Extract top-k most frequent API call n-grams.
        These capture behavioral patterns like:
          (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) → process injection
          (RegOpenKeyExA, RegSetValueExA, RegCloseKey) → persistence
        """
        if len(api_seq) < self.config.api_ngram_window:
            return

        window = self.config.api_ngram_window
        ngram_counts: Counter = Counter()

        for i in range(len(api_seq) - window + 1):
            ngram = tuple(api_seq[i:i + window])
            ngram_counts[ngram] += 1

        # Keep only n-grams seen more than once (noise filter)
        brief.api_ngrams = [
            ng for ng, count in ngram_counts.most_common(self.config.top_ngrams)
            if count > 1
        ]

    # ── Behavior summary extraction ───────────────────────────

    def _extract_behavior_summary(self, report: dict, brief: EvidenceBrief):
        summary = report.get("behavior", {}).get("summary", {})

        # Process list
        for proc in report.get("behavior", {}).get("processes", []):
            name = proc.get("process_name", "")
            pid  = proc.get("process_id", "")
            path = proc.get("module_path", "")
            brief.processes.append(f"{name} (PID {pid}) — {path}" if path else f"{name} (PID {pid})")

        # Executed commands
        for cmd in summary.get("executed_commands", []):
            cmd_str = str(cmd)[:500]
            brief.commands_executed.append(cmd_str)
            self._scan_command(cmd_str, brief)

        # File writes
        for f in summary.get("write_files", []):
            f_str = str(f)[:300]
            brief.files_written.append(f_str)
            self._scan_file_path(f_str, "write", brief)

        # File deletes
        for f in summary.get("delete_files", []):
            brief.files_deleted.append(str(f)[:300])

        # Registry
        for k in summary.get("write_keys", []):
            k_str = str(k)[:300]
            brief.registry_writes.append(k_str)
            self._scan_registry_key(k_str, brief)

        for k in summary.get("read_keys", [])[:30]:
            brief.registry_reads.append(str(k)[:300])

        # Mutexes
        for m in summary.get("mutexes", []):
            m_str = str(m)
            brief.mutexes.append(m_str)
            if not m_str.startswith(("Local\\SM0:", "Global\\SM0:")):
                self._add_ioc(brief, IOCType.MUTEX, m_str, "Mutex created/opened", 0.7)

        # Services
        for s in summary.get("created_services", []):
            s_str = str(s)
            brief.services_created.append(s_str)
            self._add_behavior(brief,
                category="persistence",
                description=f"Service created: {s_str}",
                evidence=[f"created_services: {s_str}"],
                severity=Severity.HIGH,
                attack_techniques=["T1543.003"],
            )

    # ── Enhanced event extraction ─────────────────────────────

    def _extract_enhanced_events(self, report: dict, brief: EvidenceBrief):
        for ev in report.get("behavior", {}).get("enhanced", []):
            event  = ev.get("event", "")
            obj    = ev.get("object", "")
            data   = ev.get("data", {}) or {}

            if event == "execute" and obj == "file":
                cmd = data.get("file", "")
                if cmd:
                    self._scan_command(str(cmd)[:500], brief)

            elif event == "write" and obj == "file":
                path = data.get("pathtofile", "") or data.get("file", "")
                if path:
                    self._scan_file_path(str(path)[:300], "enhanced_write", brief)

            elif event == "read" and obj == "registry":
                key = data.get("regkey", "") or data.get("key", "")
                if key:
                    self._scan_registry_key(str(key)[:300], brief)

    # ── CAPE payloads extraction ──────────────────────────────

    def _extract_cape_payloads(self, report: dict, brief: EvidenceBrief):
        cape = report.get("CAPE", {})

        for payload in cape.get("payloads", []):
            cape_type  = payload.get("cape_type", "Unknown payload")
            size       = payload.get("size", 0)
            sha256     = payload.get("sha256", "")
            proc_name  = payload.get("process_name", "")
            pid        = payload.get("pid", "")
            virt_addr  = payload.get("virtual_address", "")

            p_yara     = [y.get("name", "") for y in payload.get("yara", []) if y.get("name")]
            p_cape_yara= [y.get("name", "") for y in payload.get("cape_yara", []) if y.get("name")]

            brief.cape_payloads.append({
                "cape_type":   cape_type,
                "size":        size,
                "sha256":      sha256,
                "process":     f"{proc_name} (PID {pid})",
                "virtual_addr": virt_addr,
                "yara":        p_yara,
                "cape_yara":   p_cape_yara,
            })

            for y in p_cape_yara:
                brief.cape_yara_matches.append(f"{y} [from payload]")
                brief.capabilities.append(Capability(
                    name=f"{y} payload",
                    description=f"YARA rule {y} matched on extracted payload ({cape_type})",
                    source="cape_payload_yara",
                    confidence=0.92,
                ))

            payload_strings = payload.get("strings", [])
            if payload_strings:
                self._scan_strings(
                    payload_strings[:self.config.max_strings_to_scan],
                    brief, source=f"payload_{cape_type[:30]}",
                )

        # Extracted configs (highest confidence)
        for cfg in cape.get("configs", []):
            brief.cape_configs.append(cfg)
            brief.capabilities.append(Capability(
                name="Configuration extracted",
                description=f"CAPE extracted a config block: {str(cfg)[:200]}",
                source="cape_config",
                confidence=0.98,
            ))

    # ── AMSI payloads extraction (NEW #11) ────────────────────

    def _extract_amsi_payloads(self, report: dict, brief: EvidenceBrief):
        """
        CAPEv2 (2021+) captures AMSI (Anti-Malware Scan Interface) payloads
        from PowerShell, .NET, VBA, and JScript. These are found under
        CAPE.payloads with cape_type containing "AMSI" or in a separate
        "amsi" key in newer report versions.
        """
        # Check top-level AMSI key (newer CAPE versions)
        for payload in report.get("amsi", []):
            content = payload.get("content", "")
            source  = payload.get("source", "")
            if content:
                brief.amsi_payloads.append({
                    "content": content[:2000],
                    "source": source,
                })
                self._scan_strings([content], brief, source="amsi_payload")
                self._add_behavior(brief,
                    category="script_execution",
                    description=f"AMSI captured script content from {source}",
                    evidence=[f"AMSI payload ({len(content)} chars) from {source}"],
                    severity=Severity.HIGH,
                    attack_techniques=["T1059"],
                )

        # Also scan CAPE payloads for AMSI-type entries
        for payload in report.get("CAPE", {}).get("payloads", []):
            cape_type = payload.get("cape_type", "")
            if "AMSI" in cape_type.upper():
                content = payload.get("data", "")
                if content and isinstance(content, str):
                    brief.amsi_payloads.append({
                        "content": content[:2000],
                        "source": f"CAPE/{cape_type}",
                    })

    # ── Dropped files extraction ──────────────────────────────

    def _extract_dropped_files(self, report: dict, brief: EvidenceBrief):
        dropped_list = report.get("dropped", [])
        # FIX #2: Cap dropped files
        if len(dropped_list) > self.config.max_dropped_files:
            logger.warning("Capping dropped files from %d to %d",
                           len(dropped_list), self.config.max_dropped_files)
            dropped_list = dropped_list[:self.config.max_dropped_files]

        for dropped in dropped_list:
            name     = _normalise_name(dropped.get("name", ""))
            size     = dropped.get("size", 0)
            sha256   = dropped.get("sha256", "")
            ftype    = dropped.get("type", "")
            pid      = dropped.get("pid", "")
            d_yara   = [y.get("name", "") for y in dropped.get("yara", []) if y.get("name")]
            d_cape_y = [y.get("name", "") for y in dropped.get("cape_yara", []) if y.get("name")]

            brief.dropped_files.append({
                "name":      name,
                "size":      size,
                "sha256":    sha256,
                "type":      ftype,
                "pid":       pid,
                "yara":      d_yara,
                "cape_yara": d_cape_y,
            })

            if re.search(r'\.(exe|dll|bat|ps1|vbs|js|scr|com)$', name, re.I):
                self._add_behavior(brief,
                    category="file_drop",
                    description=f"Executable/script dropped: {name}",
                    evidence=[f"Dropped file: {name} ({size} bytes) SHA256:{sha256[:16]}"],
                    severity=Severity.HIGH,
                    attack_techniques=["T1204.002"],
                )
                self._add_ioc(brief, IOCType.FILE_PATH, name, "Dropped during execution", 0.85)

            if sha256:
                self._add_ioc(brief, IOCType.HASH_SHA256, sha256, f"Dropped file: {name}", 0.9)

            if dropped.get("strings"):
                self._scan_strings(
                    dropped["strings"][:self.config.max_strings_to_scan],
                    brief, source=f"dropped_{name[:30]}",
                )

            data = dropped.get("data", "")
            if data and isinstance(data, str) and len(data) < 2000:
                self._scan_strings([data], brief, source=f"dropped_data_{name[:20]}")

    # ── Network extraction ────────────────────────────────────

    def _extract_network(self, report: dict, brief: EvidenceBrief):
        net = report.get("network", {})

        seen_ips: Set[str] = set()
        for host in net.get("hosts", []):
            ip   = host.get("ip", "")
            ports= host.get("ports", [])
            if ip and not _is_private(ip):
                seen_ips.add(ip)
                brief.network_hosts.append({"ip": ip, "ports": ports})
                confidence = 0.6 if ip in BENIGN_HOSTS else 0.85
                self._add_ioc(brief, IOCType.IP, ip, f"Observed host (ports: {ports})", confidence)

        # TCP flows
        flow_count = 0
        for flow in net.get("tcp", []):
            if flow_count >= self.config.max_network_flows:
                break
            dst = flow.get("dst", "")
            dport = flow.get("dport", 0)
            if dst and not _is_private(dst) and dst not in seen_ips:
                seen_ips.add(dst)
                self._add_ioc(brief, IOCType.IP, dst, f"TCP flow to port {dport}", 0.75)
            brief.network_flows.append({
                "protocol": "tcp", "dst": dst, "port": dport, "src": flow.get("src",""),
            })
            flow_count += 1

        # UDP flows (often DNS)
        for flow in net.get("udp", []):
            if flow_count >= self.config.max_network_flows:
                break
            dst   = flow.get("dst", "")
            dport = flow.get("dport", 0)
            if dst and not _is_private(dst):
                if dport == 53:
                    if dst not in BENIGN_HOSTS:
                        self._add_ioc(brief, IOCType.IP, dst, "DNS resolver contacted", 0.4)
                elif dst not in seen_ips:
                    seen_ips.add(dst)
                    self._add_ioc(brief, IOCType.IP, dst, f"UDP flow to port {dport}", 0.7)
            brief.network_flows.append({
                "protocol": "udp", "dst": dst, "port": dport, "src": flow.get("src",""),
            })
            flow_count += 1

        # DNS queries
        for entry in net.get("dns", []):
            domain = entry.get("request", "") or entry.get("domain", "")
            if domain:
                brief.network_dns.append(domain)
                if not any(domain.endswith(d) for d in BENIGN_DNS_SUFFIXES):
                    self._add_ioc(brief, IOCType.DOMAIN, domain, "DNS query during execution", 0.9)

        # HTTP transactions
        for req in net.get("http", []):
            url = req.get("uri", "") or req.get("url", "")
            if url:
                brief.network_http.append({
                    "method": req.get("method", "GET"),
                    "url":    url[:300],
                    "host":   req.get("host", ""),
                    "ua":     req.get("user-agent", "")[:100],
                })
                self._add_ioc(brief, IOCType.URL, url[:300], "HTTP request during execution", 0.9)
                if req.get("method","").upper() == "POST":
                    self._add_behavior(brief,
                        category="c2_communication",
                        description=f"HTTP POST to {url[:80]}",
                        evidence=[f"POST {url[:200]}"],
                        severity=Severity.HIGH,
                        attack_techniques=["T1071.001"],
                    )

                # NEW: Extract User-Agent as IOC if non-standard
                ua = req.get("user-agent", "")
                if ua and len(ua) > 5 and "Mozilla" not in ua:
                    self._add_ioc(brief, IOCType.USER_AGENT, ua[:100],
                                  "Non-standard User-Agent in HTTP request", 0.7)

        if net.get("udp") and not net.get("dns"):
            brief.known_gaps.append(
                "UDP/53 (DNS) traffic observed in PCAP but no domain names were parsed — "
                "DNS resolution targets are unknown from report.json alone."
            )

    # ── Signatures and TTPs ───────────────────────────────────

    def _extract_signatures_ttps(self, report: dict, brief: EvidenceBrief):
        for sig in report.get("signatures", []):
            name  = sig.get("name", "")
            desc  = sig.get("description", "")
            sev   = sig.get("severity", 2)
            self._add_behavior(brief,
                category="cape_signature",
                description=f"{name}: {desc}",
                evidence=[f"CAPE signature match: {name}"],
                severity=Severity.HIGH if sev >= 3 else Severity.MEDIUM,
                attack_techniques=[],
            )

        for ttp in report.get("ttps", []):
            ttp_id  = ttp.get("ttp", "") if isinstance(ttp, dict) else str(ttp)
            ttp_desc= ttp.get("description", "") if isinstance(ttp, dict) else ""
            self._add_behavior(brief,
                category="ttp_match",
                description=f"TTP detected: {ttp_id} {ttp_desc}".strip(),
                evidence=[f"CAPE TTP mapping: {ttp_id}"],
                severity=Severity.HIGH,
                attack_techniques=[ttp_id] if ttp_id.startswith("T") else [],
            )

    # ── Process tree reconstruction (NEW #7) ──────────────────

    def _extract_process_tree(self, report: dict, brief: EvidenceBrief):
        """
        Reconstruct parent-child process relationships.
        This gives the LLM structural context like:
          explorer.exe → cmd.exe → powershell.exe → malware.exe
        """
        nodes: Dict[int, ProcessNode] = {}
        for proc in report.get("behavior", {}).get("processes", []):
            pid  = proc.get("process_id", 0)
            ppid = proc.get("parent_id", proc.get("ppid", 0))
            name = proc.get("process_name", "")
            path = proc.get("module_path", "")
            cmd  = proc.get("command_line", "")

            nodes[pid] = ProcessNode(
                pid=pid, ppid=ppid, name=name,
                path=path, cmd=str(cmd)[:300],
            )

        # Wire up children
        for pid, node in nodes.items():
            if node.ppid in nodes:
                nodes[node.ppid].children.append(pid)

        brief.process_tree = list(nodes.values())

    # ── Analysis metadata ─────────────────────────────────────

    def _extract_analysis_meta(self, report: dict, brief: EvidenceBrief):
        info = report.get("info", {})
        machine = info.get("machine", {})
        brief.meta.analysis_id = info.get("id", 0)
        brief.meta.package     = info.get("package", "")
        brief.meta.duration    = info.get("duration", 0)
        brief.meta.started     = info.get("started", "")
        brief.meta.ended       = info.get("ended", "")
        brief.meta.machine     = (
            machine.get("name", "") if isinstance(machine, dict) else str(machine)
        )

    # ── Deduplicated add helpers (FIX #4, #5) ─────────────────

    def _add_ioc(self, brief: EvidenceBrief, ioc_type: IOCType,
                 value: str, context: str, confidence: float,
                 source: str = "report.json"):
        """Add IOC only if not already seen (by value). Higher confidence wins."""
        if value in self._seen_ioc_values:
            # Update confidence if new is higher
            for existing in brief.iocs:
                if existing.value == value and confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.context = context
            return
        self._seen_ioc_values.add(value)
        brief.iocs.append(IOC(ioc_type, value, context, confidence, source))

    def _add_behavior(self, brief: EvidenceBrief, category: str,
                      description: str, evidence: List[str],
                      severity: Severity, attack_techniques: List[str],
                      source: str = "report.json"):
        """Add behavior only if not already seen (by category+description key)."""
        key = f"{category}|{description[:100]}"
        if key in self._seen_behavior_keys:
            return
        self._seen_behavior_keys.add(key)
        brief.behaviors.append(BehaviorIndicator(
            category=category,
            description=description,
            evidence=evidence,
            severity=severity,
            attack_techniques=attack_techniques,
            source=source,
        ))

    # ── Pattern scanners (reused by multiple extractors) ──────

    def _scan_strings(self, strings: list, brief: EvidenceBrief, source: str):
        """Scan a list of strings for suspicious patterns and IOCs."""
        blob = "\n".join(
            str(s)[:self.config.max_string_length]
            for s in strings[:self.config.max_strings_to_scan]
        )

        for pattern, desc, severity in STATIC_STRING_PATTERNS:
            matches = re.findall(pattern, blob, re.IGNORECASE)
            for m in matches[:3]:
                m_str = str(m)[:120]
                if m_str not in brief.suspicious_strings:
                    brief.suspicious_strings.append(m_str)
                self._add_behavior(brief,
                    category="suspicious_string",
                    description=desc,
                    evidence=[f"[{source}] String: {m_str}"],
                    severity=severity,
                    attack_techniques=[],
                )

        # Extract IPs
        for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', blob):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                continue
            # From static strings: OIDs and version numbers flood the IP regex.
            parts = ip.split('.')
            if source == "static_strings":
                if sum(1 for p in parts if int(p) > 10) < 2:
                    continue
            self._add_ioc(brief, IOCType.IP, ip, source, 0.65)

        # Extract URLs
        if source == "static_strings":
            for url in re.findall(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s"\'<>]*', blob):
                if len(url) < 300:
                    self._add_ioc(brief, IOCType.URL, url, source, 0.75)
        else:
            for url in re.findall(r'https?://[^\s"\'<>{}\[\]]{4,}', blob):
                if len(url) < 300:
                    self._add_ioc(brief, IOCType.URL, url, source, 0.8)

    def _scan_command(self, cmd: str, brief: EvidenceBrief):
        for pattern, desc, severity, techniques in COMMAND_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                self._add_behavior(brief,
                    category="command_execution",
                    description=desc,
                    evidence=[f"Command: {cmd[:200]}"],
                    severity=severity,
                    attack_techniques=techniques,
                )

    def _scan_file_path(self, path: str, ctx: str, brief: EvidenceBrief):
        for pattern, desc, severity, techniques in SUSPICIOUS_FILE_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                key = f"{desc}|{path[:200]}"
                if key in self._seen_file_behaviors:
                    continue
                self._seen_file_behaviors.add(key)
                self._add_behavior(brief,
                    category="suspicious_file_write",
                    description=desc,
                    evidence=[f"[{ctx}] Path: {path[:200]}"],
                    severity=severity,
                    attack_techniques=techniques,
                )

    def _scan_registry_key(self, key: str, brief: EvidenceBrief):
        for pattern, desc, severity, techniques in SUSPICIOUS_REGISTRY_KEYS:
            if re.search(pattern, key, re.IGNORECASE):
                self._add_behavior(brief,
                    category="registry",
                    description=desc,
                    evidence=[f"Registry key: {key[:200]}"],
                    severity=severity,
                    attack_techniques=techniques,
                )
                if severity in (Severity.HIGH, Severity.CRITICAL):
                    self._add_ioc(brief, IOCType.REGISTRY_KEY, key[:200], "Registry access", 0.75)

    # ── Risk signals ──────────────────────────────────────────

    def _compute_risk_signals(self, brief: EvidenceBrief):
        critical_behaviors = [b for b in brief.behaviors if b.severity == Severity.CRITICAL]
        high_behaviors     = [b for b in brief.behaviors if b.severity == Severity.HIGH]

        if critical_behaviors:
            brief.risk_signals.append(
                f"CRITICAL: {len(critical_behaviors)} critical-severity behavior(s) detected "
                f"({', '.join(b.category for b in critical_behaviors[:3])})"
            )
        if len(high_behaviors) >= 3:
            brief.risk_signals.append(
                f"HIGH: {len(high_behaviors)} high-severity behavioral indicators"
            )
        if brief.packed:
            brief.risk_signals.append("MEDIUM: Binary packed/encrypted — active evasion (T1027.002)")
        if any("process_injection" in b.category for b in brief.behaviors):
            brief.risk_signals.append("HIGH: Process injection capability confirmed (T1055)")
        if any("c2_communication" in b.category for b in brief.behaviors):
            brief.risk_signals.append("HIGH: Active C2 communication observed")
        if brief.commands_executed:
            ps_cmds = [c for c in brief.commands_executed if "powershell" in c.lower()]
            if ps_cmds:
                brief.risk_signals.append(f"HIGH: {len(ps_cmds)} PowerShell command(s) executed")
        if brief.cape_payloads:
            brief.risk_signals.append(
                f"HIGH: {len(brief.cape_payloads)} CAPE payload(s) extracted "
                f"(types: {', '.join(set(p['cape_type'] for p in brief.cape_payloads))})"
            )
        if brief.cape_configs:
            brief.risk_signals.append("CRITICAL: Malware configuration block extracted by CAPE")
        if brief.detections:
            families = [d["family"] for d in brief.detections]
            brief.risk_signals.append(f"HIGH: Family detection — {', '.join(families)}")
        if len(brief.iocs) >= 5:
            brief.risk_signals.append(f"HIGH: {len(brief.iocs)} IOCs extracted")
        if brief.meta.malscore >= 8.0:
            brief.risk_signals.append(f"HIGH: CAPE malscore {brief.meta.malscore:.1f}/10")
        # NEW: AMSI captures = high-value signal
        if brief.amsi_payloads:
            brief.risk_signals.append(
                f"HIGH: {len(brief.amsi_payloads)} AMSI payload(s) captured — script-layer evidence"
            )

        # Benign signals
        if brief.pe_signed and brief.pe_signers:
            brief.benign_signals.append(f"Digitally signed by: {', '.join(brief.pe_signers[:2])}")
        if not brief.behaviors:
            brief.benign_signals.append("No suspicious behavioral indicators identified")
        if brief.meta.malscore < 3.0:
            brief.benign_signals.append(f"Low CAPE malscore ({brief.meta.malscore:.1f}/10)")

    # ── Known gaps (anti-hallucination) ───────────────────────

    def _compute_known_gaps(self, report: dict, brief: EvidenceBrief):
        net = report.get("network", {})
        if not net.get("http"):
            brief.known_gaps.append("No HTTP transactions were parsed — HTTP-level C2 details unavailable.")
        if not net.get("dns"):
            brief.known_gaps.append("No DNS request records parsed — domain resolution targets unknown.")
        if not report.get("signatures"):
            brief.known_gaps.append("No CAPE behavioral signatures triggered — manual API correlation required.")
        if not report.get("ttps"):
            brief.known_gaps.append("No automated CAPE TTP mappings — ATT&CK mapping is heuristic only.")
        if not report.get("CAPE", {}).get("payloads"):
            brief.known_gaps.append("No CAPE payloads extracted — binary may be packed, staged, or non-extractable.")
        if not report.get("dropped"):
            brief.known_gaps.append("No files were dropped during sandbox execution.")
        tf = report.get("target", {}).get("file", {})
        if not tf.get("pe") or not tf.get("pe", {}).get("imports"):
            brief.known_gaps.append("PE import table not parsed — static import analysis unavailable (likely packed).")
        pcap_hash = report.get("network", {}).get("pcap_sha256", "")
        if pcap_hash and not net.get("hosts"):
            brief.known_gaps.append("PCAP present but no hosts parsed — network IOCs may be incomplete.")
        # NEW: Short execution duration gap
        if brief.meta.duration and brief.meta.duration < 30:
            brief.known_gaps.append(
                f"Short sandbox execution ({brief.meta.duration}s) — "
                "time-delayed or interactive behaviors may not have triggered."
            )

    # ════════════════════════════════════════════════════════════
    # PROMPT BUILDER
    # ════════════════════════════════════════════════════════════

    def build_expert_prompt(self, brief: EvidenceBrief, task: str = "full_report") -> str:
        evidence_text = self._format_evidence(brief)

        TASK_INSTRUCTIONS = {
            "full_report": (
                "You are a senior malware analyst at a Security Operations Center. "
                "You have received a structured evidence brief produced by CAPEv2 dynamic analysis. "
                "Produce a comprehensive malware analysis report.\n\n"
                "RULES:\n"
                "1. Every claim MUST reference specific evidence from the brief.\n"
                "2. Do NOT mention techniques, capabilities, or IOCs absent from the brief.\n"
                "3. Where evidence is missing, state that explicitly — do NOT infer.\n"
                "4. Use MITRE ATT&CK IDs (e.g. T1055.003) for every technique reference.\n"
                "5. Provide a risk score 0–100 with justification tied to specific evidence items.\n"
                "6. Items marked source='kspn' are pre-mapped with higher confidence — prioritize them."
            ),
            "attck_mapping": (
                "You are a threat intelligence analyst. "
                "Map ONLY the evidence below to MITRE ATT&CK techniques. "
                "For every mapping, cite the specific evidence field that supports it. "
                "Do not map techniques you have no direct evidence for. "
                "If a technique is commonly associated with this family but NOT evidenced here, "
                "list it separately as 'unconfirmed by this analysis'.\n"
                "NOTE: Items with source='kspn' are pre-validated MITRE mappings — include them with HIGH confidence."
            ),
            "risk_assessment": (
                "You are a SOC analyst performing risk triage. "
                "Based strictly on the evidence brief, provide:\n"
                "1. Risk score 0–100 with per-factor breakdown.\n"
                "2. Confidence level (high / medium / low) reflecting evidence completeness.\n"
                "3. Recommended immediate containment actions.\n"
                "Every score factor must cite a specific evidence field."
            ),
            "executive_summary": (
                "You are preparing an executive summary for the CISO. "
                "Translate the technical evidence below into business-impact language. "
                "No jargon. Focus on: what the malware does, what data or systems are at risk, "
                "and what must happen in the next 24 hours. Keep it under 200 words."
            ),
            "ioc_report": (
                "You are a threat intelligence analyst producing an IOC report for the network defense team. "
                "List every actionable indicator from the brief below, grouped by type. "
                "Assign confidence levels based on the source stated for each IOC. "
                "Include detection recommendations for each indicator type."
            ),
        }

        instruction = TASK_INSTRUCTIONS.get(task, "Analyze the malware evidence brief below and provide your expert assessment.")

        return (
            f"### Instruction:\n{instruction}\n\n"
            f"### Input:\n{evidence_text}\n\n"
            f"### Response:\n"
        )

    def _format_evidence(self, brief: EvidenceBrief) -> str:
        lines = []
        lines.append("═══ FATHOM EVIDENCE BRIEF ═══")
        lines.append(f"Sample : {brief.file_name or brief.sample_id}")
        lines.append(f"SHA256 : {brief.hashes.get('sha256', 'N/A')}")
        lines.append(f"MD5    : {brief.hashes.get('md5', 'N/A')}")
        lines.append(f"Type   : {brief.file_type}  |  Size: {brief.file_size:,} bytes")
        lines.append(f"Packed : {brief.packed}  |  Signed: {brief.pe_signed}")
        if brief.meta.malscore:
            lines.append(f"CAPE malscore : {brief.meta.malscore:.1f}/10  |  Status: {brief.meta.malstatus}")
        if brief.meta.machine:
            lines.append(f"Sandbox machine: {brief.meta.machine}  |  Duration: {brief.meta.duration}s")

        # Detections
        if brief.detections:
            lines.append(f"\n── DETECTIONS ──")
            for d in brief.detections:
                lines.append(f"  • Family: {d['family']}")
                for s in d.get("sources", [])[:2]:
                    lines.append(f"    Source: {s}")

        # YARA
        all_yara = list(dict.fromkeys(brief.yara_matches + brief.cape_yara_matches))
        if all_yara:
            lines.append(f"\n── YARA / CAPE-YARA MATCHES ({len(all_yara)}) ──")
            for y in all_yara[:10]:
                lines.append(f"  • {y}")

        # Behavioral indicators
        if brief.behaviors:
            high_crit = [b for b in brief.behaviors if b.severity in (Severity.HIGH, Severity.CRITICAL)]
            others    = [b for b in brief.behaviors if b.severity not in (Severity.HIGH, Severity.CRITICAL)]
            lines.append(f"\n── BEHAVIORAL INDICATORS ({len(brief.behaviors)} total, "
                         f"{len(high_crit)} HIGH/CRITICAL) ──")
            for b in (high_crit + others)[:20]:
                src_tag = f" [{b.source}]" if b.source != "report.json" else ""
                lines.append(f"  [{b.severity.value.upper()}]{src_tag} {b.description}")
                for e in b.evidence[:2]:
                    lines.append(f"    Evidence: {e}")
                if b.attack_techniques:
                    lines.append(f"    ATT&CK: {', '.join(b.attack_techniques)}")

        # Capabilities
        if brief.capabilities:
            lines.append(f"\n── CAPABILITIES ({len(brief.capabilities)}) ──")
            for c in brief.capabilities[:10]:
                lines.append(f"  • [{c.source}] {c.name} (conf: {c.confidence:.0%})")

        # IOCs
        if brief.iocs:
            lines.append(f"\n── IOCs ({len(brief.iocs)} total) ──")
            for ioc in sorted(brief.iocs, key=lambda x: -x.confidence)[:20]:
                src_tag = f" [{ioc.source}]" if ioc.source != "report.json" else ""
                lines.append(f"  [{ioc.type.value}]{src_tag} {ioc.value} "
                             f"(conf: {ioc.confidence:.0%}) — {ioc.context}")

        # Network
        if brief.network_hosts or brief.network_flows:
            lines.append(f"\n── NETWORK ──")
            if brief.network_hosts:
                lines.append(f"  Hosts observed: {', '.join(h['ip'] for h in brief.network_hosts[:10])}")
            tcp_flows = [f for f in brief.network_flows if f["protocol"]=="tcp"]
            udp_flows = [f for f in brief.network_flows if f["protocol"]=="udp"]
            lines.append(f"  TCP flows: {len(tcp_flows)}  |  UDP flows: {len(udp_flows)}")
            if brief.network_dns:
                lines.append(f"  DNS queries: {', '.join(brief.network_dns[:8])}")
            for req in brief.network_http[:5]:
                lines.append(f"  HTTP {req['method']} {req['url'][:80]}")

        # Process tree (NEW #7)
        if brief.process_tree:
            roots = [p for p in brief.process_tree if p.ppid not in
                     {n.pid for n in brief.process_tree}]
            lines.append(f"\n── PROCESS TREE ({len(brief.process_tree)} processes) ──")
            for root in roots[:5]:
                self._format_tree_node(root, brief.process_tree, lines, depth=0, max_depth=4)

        # Commands
        if brief.commands_executed:
            lines.append(f"\n── EXECUTED COMMANDS ({len(brief.commands_executed)}) ──")
            for c in brief.commands_executed[:4]:
                lines.append(f"  • {c[:200]}")

        # File system
        if brief.files_written or brief.files_deleted:
            lines.append(f"\n── FILE SYSTEM ──")
            for f in brief.files_written[:5]:
                lines.append(f"  [WRITE] {f[:180]}")
            for f in brief.files_deleted[:5]:
                lines.append(f"  [DEL]   {f[:180]}")

        # Registry
        if brief.registry_writes:
            lines.append(f"\n── REGISTRY WRITES ({len(brief.registry_writes)}) ──")
            for r in brief.registry_writes[:5]:
                lines.append(f"  • {r[:180]}")

        # Mutexes
        if brief.mutexes:
            lines.append(f"\n── MUTEXES ──")
            for m in brief.mutexes[:5]:
                lines.append(f"  • {m}")

        # CAPE payloads
        if brief.cape_payloads:
            lines.append(f"\n── CAPE EXTRACTED PAYLOADS ({len(brief.cape_payloads)}) ──")
            for p in brief.cape_payloads:
                lines.append(f"  • {p['cape_type']}  {p['size']:,}B  process:{p['process']}")
                if p["cape_yara"]:
                    lines.append(f"    CAPE-YARA: {', '.join(p['cape_yara'])}")

        # AMSI payloads (NEW #11)
        if brief.amsi_payloads:
            lines.append(f"\n── AMSI PAYLOADS ({len(brief.amsi_payloads)}) ──")
            for a in brief.amsi_payloads[:3]:
                lines.append(f"  • Source: {a['source']}  ({len(a['content'])} chars)")
                lines.append(f"    Preview: {a['content'][:150]}...")

        # Dropped files
        if brief.dropped_files:
            lines.append(f"\n── DROPPED FILES ({len(brief.dropped_files)}) ──")
            for d in brief.dropped_files[:6]:
                lines.append(f"  • {d['name']}  ({d['size']:,}B)  {d['type'][:40]}")
                if d["yara"]: lines.append(f"    YARA: {', '.join(d['yara'])}")

        # PE static
        if brief.pe_sections:
            lines.append(f"\n── STATIC PE ──")
            lines.append(f"  Imphash : {brief.pe_imphash}")
            lines.append(f"  Compiled: {brief.pe_compile_ts}")
            for s in brief.pe_sections[:7]:
                lines.append(f"  Section {s['name']:10s} entropy={s['entropy']:.2f}  {s['characteristics'][:60]}")
            if brief.pe_imports:
                total_imports = sum(len(v) for v in brief.pe_imports.values())
                lines.append(f"  Imports: {len(brief.pe_imports)} DLLs, {total_imports} functions")

        # API summary
        lines.append(f"\n── API CALL SUMMARY ──")
        lines.append(f"  Unique APIs observed: {brief.api_unique_count}")
        if brief.api_category_counts:
            top_cats = sorted(brief.api_category_counts.items(), key=lambda x: -x[1])[:6]
            lines.append(f"  Top categories: {', '.join(f'{k}:{v}' for k,v in top_cats)}")
        if brief.suspicious_apis_seen:
            lines.append(f"  Suspicious APIs ({len(brief.suspicious_apis_seen)}): "
                         f"{', '.join(brief.suspicious_apis_seen[:12])}")

        # API N-grams (NEW #6)
        if brief.api_ngrams:
            lines.append(f"\n── API SEQUENCE PATTERNS (top {len(brief.api_ngrams)} n-grams) ──")
            for ng in brief.api_ngrams[:10]:
                lines.append(f"  • {' → '.join(ng)}")

        # Suspicious strings
        if brief.suspicious_strings:
            lines.append(f"\n── SUSPICIOUS STRINGS ({len(brief.suspicious_strings)}) ──")
            for s in brief.suspicious_strings[:6]:
                lines.append(f"  • {s[:120]}")

        # Risk signals
        if brief.risk_signals:
            lines.append(f"\n── RISK SIGNALS ──")
            for s in brief.risk_signals:
                lines.append(f"  ⚠ {s}")
        if brief.benign_signals:
            lines.append(f"\n── MITIGATING FACTORS ──")
            for s in brief.benign_signals:
                lines.append(f"  ✓ {s}")

        # Known gaps
        if brief.known_gaps:
            lines.append(f"\n── KNOWN GAPS (do NOT infer or hallucinate these) ──")
            for g in brief.known_gaps:
                lines.append(f"  ✗ {g}")

        lines.append("\n═══ END EVIDENCE BRIEF ═══")
        return "\n".join(lines)

    def _format_tree_node(self, node: ProcessNode, all_nodes: List[ProcessNode],
                          lines: List[str], depth: int, max_depth: int):
        """Recursive tree formatter with depth guard."""
        if depth > max_depth:
            lines.append(f"{'  ' * (depth + 1)}... (truncated)")
            return
        indent = "  " + "  │ " * depth
        lines.append(f"{indent}{'├─ ' if depth > 0 else ''}{node.name} (PID {node.pid})")
        if node.cmd and depth <= 2:
            lines.append(f"{indent}   cmd: {node.cmd[:120]}")
        nodes_by_pid = {n.pid: n for n in all_nodes}
        for child_pid in node.children[:5]:
            if child_pid in nodes_by_pid:
                self._format_tree_node(nodes_by_pid[child_pid], all_nodes,
                                       lines, depth + 1, max_depth)


# ════════════════════════════════════════════════════════════════
# DEMO — runs both real samples
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    import os

    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")

    extractor = CAPEEvidenceExtractor()

    # Accept path from CLI or use defaults
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        paths = [
            "/mnt/user-data/uploads/report.json",           # sample 5 — WinosStager
            "/tmp/cape_new/12/reports/report.json",         # sample 12 — Emotet
        ]

    for report_path in paths:
        if not os.path.exists(report_path):
            print(f"[skip] {report_path} not found")
            continue

        print("\n" + "=" * 72)
        print(f"ANALYSING: {report_path}")
        print("=" * 72)

        brief = extractor.from_report_file(report_path)

        # Check for KSPN sidecar
        kspn_path = report_path.replace("report.json", "kspn_report_summary.json")
        if os.path.exists(kspn_path):
            print(f"[kspn] Enriching from {kspn_path}")
            with open(kspn_path, "r") as fh:
                kspn_data = json.load(fh)
            extractor.enrich_from_kspn(brief, kspn_data)

        print(extractor._format_evidence(brief))

        # Show a snippet of the full-report prompt
        prompt = extractor.build_expert_prompt(brief, task="full_report")
        print(f"\n{'─'*72}")
        print("EXPERT PROMPT (first 800 chars):")
        print(prompt[:800] + "...")

        # Save JSON sidecar
        out_path = report_path.replace("report.json", "evidence_brief.json")
        try:
            if _HAVE_ORJSON:
                with open(out_path, "wb") as fh:
                    fh.write(orjson.dumps(brief.to_dict(), option=orjson.OPT_INDENT_2))
            else:
                with open(out_path, "w") as fh:
                    json.dump(brief.to_dict(), fh, indent=2)
            print(f"\n[saved] {out_path}")
        except Exception:
            pass

        print(f"\nBrief stats: behaviors={len(brief.behaviors)}, iocs={len(brief.iocs)}, "
              f"capabilities={len(brief.capabilities)}, known_gaps={len(brief.known_gaps)}, "
              f"api_ngrams={len(brief.api_ngrams)}, process_tree={len(brief.process_tree)}, "
              f"amsi_payloads={len(brief.amsi_payloads)}")
