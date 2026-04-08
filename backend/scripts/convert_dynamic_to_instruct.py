#!/usr/bin/env python3
"""
convert_dynamic_to_instruct.py — Convert dynamic behavior datasets to Alpaca JSONL
for E2 Dynamic Behavior Expert.

Sources:
  - Mal-API-2019 (GitHub) — 7,107 API call sequences across 8 malware families
    Data format: all_analysis_data.txt (inside zip) + labels.csv as parallel files
  - Avast-CTU CAPE Dataset (GitHub) — Julia package, no raw JSON reports available
    Skipped: generates behavioral template examples instead

Output: data/processed/e2_dynamic.jsonl (~7K+ unique examples)
"""

import argparse
import csv
import json
import random
import zipfile
from collections import Counter
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

INSTRUCTION_TEMPLATES = [
    "Analyze the following Windows malware execution trace and identify the malware family, key behaviors, and MITRE ATT&CK techniques.",
    "Given this behavioral execution trace from a sandbox, classify the malware family and describe its key actions.",
    "Examine this Windows API call sequence from a malware sample. Identify the malware type, behavior patterns, and potential impact.",
    "Review this dynamic analysis trace and provide a behavioral assessment including malware classification and technique identification.",
    "Analyze the following sandbox execution output. What malware family does this belong to? What are its primary behaviors?",
    "Classify this API call sequence from dynamic analysis. What type of malware produced this trace?",
    "Based on the following API trace from a sandbox execution, determine the malware category and explain the observed behaviors.",
    "Analyze the behavioral indicators in this API call sequence and map them to MITRE ATT&CK techniques.",
]

# Well-known suspicious API categories for richer output generation
API_CATEGORIES = {
    "process_manipulation": [
        "ntopenprocess", "ntcreateprocess", "ntcreatethreadinthread",
        "createprocessinternalw", "ntterminateprocess", "ntsuspendthread",
        "ntresumethread", "createremotethread", "ntmapviewofsection",
    ],
    "memory_manipulation": [
        "ntallocatevirtualmemory", "ntfreevirtualmemory", "ntprotectvirtualmemory",
        "ntwritevirtualmemory", "ntreadvirtualmemory", "virtualalloc", "virtualprotect",
    ],
    "file_operations": [
        "ntcreatefile", "ntwritefile", "ntreadfile", "ntclose", "ntdeletefile",
        "copyfilea", "movefileexw", "setfilepointer", "ntsetinformationfile",
    ],
    "registry_operations": [
        "regopenkeyexa", "regsetvalueexa", "regcreatekeyexa", "regclosekey",
        "ntopenkey", "ntqueryvaluekey", "ntsetvaluekey", "regdeletekeyw",
    ],
    "network_operations": [
        "internetconnecta", "internetopenurla", "httpsendrequesta", "httpopenrequesta",
        "urldownloadtofilew", "wsasend", "wsarecv", "connect", "send", "recv",
        "getadaptersinfo", "dnsquery_a",
    ],
    "dll_loading": [
        "ldrloaddll", "ldrgetprocedureaddress", "ldrgetdllhandle",
        "loadlibrarya", "loadlibraryw", "getprocaddress",
    ],
    "system_discovery": [
        "getsysteminfo", "getsystemtimeasfiletime", "getusernamea",
        "getcomputernamea", "ntqueryattributesfile", "getsystemdirectorya",
        "ntquerysysteminformation", "getadaptersinfo",
    ],
    "crypto_operations": [
        "cryptencrypt", "cryptdecrypt", "cryptcreatehash", "crypthashdata",
        "cryptacquirecontexta", "cryptgenrandom",
    ],
    "anti_analysis": [
        "ntqueryinformationprocess", "isdebuggerpresent", "checkremotedebuggerpresent",
        "gettickcount", "ntdelaynthread", "seterrormode", "outputdebugstringa",
    ],
    "persistence": [
        "regsetvalueexa", "regcreatekeyexa", "ntsetvaluekey",
        "createservicea", "startservicea",
    ],
    "ui_interaction": [
        "messageboxtimeouta", "messageboxw", "showwindow",
        "setwindowshookexw", "getasynckeystate",
    ],
}

# ATT&CK technique mappings for behavioral categories
CATEGORY_TECHNIQUES = {
    "process_manipulation": [("T1055", "Process Injection"), ("T1106", "Native API")],
    "memory_manipulation": [("T1055.001", "DLL Injection"), ("T1055.012", "Process Hollowing")],
    "file_operations": [("T1005", "Data from Local System"), ("T1074", "Data Staged")],
    "registry_operations": [("T1547.001", "Registry Run Keys"), ("T1112", "Modify Registry")],
    "network_operations": [("T1071.001", "Web Protocols"), ("T1041", "Exfiltration Over C2")],
    "dll_loading": [("T1129", "Shared Modules"), ("T1574.001", "DLL Search Order Hijacking")],
    "system_discovery": [("T1082", "System Information Discovery"), ("T1016", "System Network Config")],
    "crypto_operations": [("T1027", "Obfuscated Files"), ("T1486", "Data Encrypted for Impact")],
    "anti_analysis": [("T1497", "Virtualization/Sandbox Evasion"), ("T1622", "Debugger Evasion")],
    "persistence": [("T1547.001", "Registry Run Keys"), ("T1543.003", "Windows Service")],
    "ui_interaction": [("T1056.001", "Keylogging"), ("T1204", "User Execution")],
}

FAMILY_DESCRIPTIONS = {
    "Trojan": "Trojan horse malware that disguises itself as legitimate software to gain access to the target system.",
    "Backdoor": "Backdoor malware that establishes persistent unauthorized remote access to the compromised system.",
    "Worms": "Self-propagating worm that spreads across networks without user interaction.",
    "Virus": "File-infecting virus that attaches to legitimate executables and spreads when they are run.",
    "Downloader": "Downloader/dropper that retrieves and executes additional malicious payloads from remote servers.",
    "Dropper": "Dropper malware that contains and installs additional malicious components onto the infected system.",
    "Spyware": "Spyware that covertly monitors user activity, captures credentials, and exfiltrates sensitive data.",
    "Adware": "Adware that displays unwanted advertisements and may track browsing behavior for monetization.",
}


def classify_apis(api_list: list[str]) -> dict[str, list[str]]:
    """Classify API calls into behavioral categories."""
    found = {}
    for api in api_list:
        api_lower = api.lower().strip()
        for category, known_apis in API_CATEGORIES.items():
            if api_lower in known_apis:
                found.setdefault(category, []).append(api_lower)
    return found


def build_rich_output(label: str, api_list: list[str], categories: dict[str, list[str]]) -> str:
    """Build a detailed analysis output from API sequence and categories."""
    family_desc = FAMILY_DESCRIPTIONS.get(label, f"{label} malware sample.")

    # Build behavioral observations
    observations = []
    techniques = []

    for cat, apis in sorted(categories.items(), key=lambda x: -len(x[1])):
        unique_apis = list(dict.fromkeys(apis))  # preserve order, dedup
        cat_label = cat.replace("_", " ").title()
        observations.append(
            f"- **{cat_label}**: {', '.join(unique_apis[:8])}"
            + (f" (+{len(unique_apis)-8} more)" if len(unique_apis) > 8 else "")
        )
        for tid, tname in CATEGORY_TECHNIQUES.get(cat, []):
            techniques.append((tid, tname))

    # Dedup techniques
    seen = set()
    unique_techniques = []
    for tid, tname in techniques:
        if tid not in seen:
            seen.add(tid)
            unique_techniques.append((tid, tname))

    # API frequency summary
    api_counts = Counter(api_list)
    top_5 = api_counts.most_common(5)
    freq_text = ", ".join(f"{api}({cnt}x)" for api, cnt in top_5)

    obs_text = "\n".join(observations) if observations else "- General API activity observed"
    tech_text = "\n".join(
        f"- **{tid}** ({tname})" for tid, tname in unique_techniques[:6]
    ) if unique_techniques else "- Further analysis needed for precise ATT&CK mapping"

    return (
        f"## Dynamic Analysis Report\n\n"
        f"**Classification:** {label}\n"
        f"**Total API Calls:** {len(api_list)}\n"
        f"**Top Calls:** {freq_text}\n\n"
        f"## Summary\n\n"
        f"{family_desc}\n\n"
        f"## Behavioral Observations\n\n"
        f"{obs_text}\n\n"
        f"## MITRE ATT&CK Mapping\n\n"
        f"{tech_text}\n\n"
        f"## Recommendations\n\n"
        f"1. Isolate the affected system and preserve forensic evidence\n"
        f"2. Check for persistence mechanisms in registry and scheduled tasks\n"
        f"3. Scan for lateral movement indicators on adjacent hosts\n"
        f"4. Update endpoint detection signatures for {label} variants"
    )


# ── Mal-API-2019 ─────────────────────────────────────────────────────────

def convert_malapi(malapi_dir: Path, output_path: Path) -> int:
    """Convert Mal-API-2019 dataset — API call sequences per malware family.

    Data format:
      - mal-api-2019.zip → all_analysis_data.txt (7,107 lines, one sample per line)
      - labels.csv (7,107 lines, one label per line, no header)
      - Lines correspond 1-to-1: line N of data = sample, line N of labels = family

    Families: Trojan, Backdoor, Worms, Virus, Downloader, Dropper, Spyware, Adware
    """
    if not malapi_dir.exists():
        print(f"[SKIP] Mal-API-2019 not found at {malapi_dir}")
        return 0

    # Read labels (one per line, no header)
    labels_path = malapi_dir / "labels.csv"
    if not labels_path.exists():
        print(f"[SKIP] labels.csv not found in {malapi_dir}")
        return 0

    labels = [line.strip() for line in labels_path.read_text(encoding="utf-8").strip().split("\n")]
    print(f"  Loaded {len(labels)} labels from labels.csv")

    # Read API sequences — try zip first, then raw txt, then sample CSV
    api_sequences = []

    zip_path = malapi_dir / "mal-api-2019.zip"
    if zip_path.exists():
        print(f"  Extracting API sequences from {zip_path.name}...")
        with zipfile.ZipFile(zip_path, "r") as z:
            # Find the data file inside the zip
            for name in z.namelist():
                if "analysis_data" in name.lower() or name.endswith(".txt"):
                    with z.open(name) as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        api_sequences = [line.strip() for line in content.strip().split("\n") if line.strip()]
                    print(f"  Extracted {len(api_sequences)} sequences from {name}")
                    break

    if not api_sequences:
        # Fallback: try sample_analysis_data.csv (same format, space-separated APIs)
        sample_csv = malapi_dir / "sample_analysis_data.csv"
        if sample_csv.exists():
            print(f"  Using sample_analysis_data.csv as fallback...")
            api_sequences = [
                line.strip()
                for line in sample_csv.read_text(encoding="utf-8", errors="ignore").strip().split("\n")
                if line.strip()
            ]
            print(f"  Loaded {len(api_sequences)} sequences")

    if not api_sequences:
        print(f"[SKIP] No API sequence data found in {malapi_dir}")
        return 0

    # Match sequences to labels
    n = min(len(api_sequences), len(labels))
    print(f"  Matching {n} sequences to labels...")

    random.seed(42)
    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for i in range(n):
            api_text = api_sequences[i]
            label = labels[i]

            if not api_text or len(api_text) < 20:
                continue

            # Parse space-separated API calls
            api_list = api_text.split()

            # Classify APIs into behavioral categories
            categories = classify_apis(api_list)

            # Build input text with structured API trace
            api_counts = Counter(api_list)
            # Show first 30 unique APIs in sequence order + frequency summary
            seen = []
            for api in api_list:
                if api not in seen:
                    seen.append(api)
                if len(seen) >= 40:
                    break

            input_text = (
                f"Sandbox Execution Trace\n"
                f"Total API calls: {len(api_list)}\n"
                f"Unique APIs: {len(set(api_list))}\n\n"
                f"API Sequence (first {min(len(api_list), 60)} calls):\n"
                f"{' → '.join(api_list[:60])}\n\n"
                f"API Frequency (top 10):\n"
                + "\n".join(f"  {api}: {cnt}x" for api, cnt in api_counts.most_common(10))
            )

            instruction = random.choice(INSTRUCTION_TEMPLATES)
            output_text = build_rich_output(label, api_list, categories)

            record = {
                "instruction": instruction,
                "input": input_text[:2000],
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    label_dist = Counter(labels[:n])
    print(f"  Label distribution: {dict(label_dist.most_common())}")
    print(f"Converted {count} Mal-API-2019 rows → {output_path.name}")
    return count


# ── Avast CAPE behavioral templates ──────────────────────────────────────

def generate_cape_templates(output_path: Path, n: int = 2000) -> int:
    """Generate behavioral analysis templates based on common CAPE sandbox patterns.

    The Avast-CTU CAPE repo is a Julia package with no raw JSON reports.
    Instead, generate structured template examples covering diverse
    malware behaviors that a dynamic analysis expert should recognize.
    """
    families = [
        "Emotet", "TrickBot", "Qakbot", "IcedID", "AgentTesla",
        "Remcos", "AsyncRAT", "NjRAT", "RedLine", "Formbook",
        "LockBit", "Conti", "REvil", "BlackCat", "WannaCry",
        "Dridex", "Ursnif", "ZLoader", "BazarLoader", "Cobalt Strike",
    ]

    behavior_templates = [
        {
            "behaviors": ["Process injection via NtWriteVirtualMemory", "CreateRemoteThread into explorer.exe",
                          "Allocated RWX memory in target process"],
            "techniques": [("T1055.001", "DLL Injection"), ("T1055.012", "Process Hollowing")],
            "signatures": ["injection_createremotethread", "allocates_rwx"],
        },
        {
            "behaviors": ["Modified HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          "Created scheduled task via schtasks.exe", "Dropped copy to AppData\\Roaming"],
            "techniques": [("T1547.001", "Registry Run Keys"), ("T1053.005", "Scheduled Task")],
            "signatures": ["persistence_autorun", "creates_scheduled_task"],
        },
        {
            "behaviors": ["DNS query to C2 domain", "HTTP POST to /gate.php with encoded payload",
                          "Resolved dynamic DNS hostname"],
            "techniques": [("T1071.001", "Web Protocols"), ("T1568.002", "Domain Generation")],
            "signatures": ["network_http_post", "dns_suspicious_query"],
        },
        {
            "behaviors": ["Spawned powershell.exe with -enc flag", "Decoded Base64 command",
                          "Executed download cradle via IEX"],
            "techniques": [("T1059.001", "PowerShell"), ("T1027", "Obfuscated Files")],
            "signatures": ["uses_powershell", "suspicious_command_line"],
        },
        {
            "behaviors": ["Read credentials from browser SQLite databases",
                          "Accessed Windows Credential Manager", "Dumped Chrome Login Data"],
            "techniques": [("T1555.003", "Credentials from Web Browsers"), ("T1003", "OS Credential Dumping")],
            "signatures": ["stealer_browser", "reads_credential_data"],
        },
        {
            "behaviors": ["Enumerated running processes via CreateToolhelp32Snapshot",
                          "Queried system locale and keyboard layout", "Checked IsDebuggerPresent"],
            "techniques": [("T1057", "Process Discovery"), ("T1497", "Sandbox Evasion"), ("T1622", "Debugger Evasion")],
            "signatures": ["antidbg_checkdebuggerpresent", "recon_programs"],
        },
        {
            "behaviors": ["Encrypted files with AES-256", "Dropped ransom note README.txt",
                          "Deleted Volume Shadow Copies via vssadmin"],
            "techniques": [("T1486", "Data Encrypted for Impact"), ("T1490", "Inhibit System Recovery")],
            "signatures": ["ransomware_file_modifications", "deletes_shadow_copies"],
        },
        {
            "behaviors": ["Loaded ws2_32.dll for socket operations", "Established reverse TCP shell",
                          "Transmitted system info beacon to C2"],
            "techniques": [("T1095", "Non-Application Layer Protocol"), ("T1082", "System Information Discovery")],
            "signatures": ["network_tcp_socket", "rat_beacon"],
        },
    ]

    random.seed(44)
    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for i in range(n):
            family = random.choice(families)
            template = random.choice(behavior_templates)
            num_behaviors = random.randint(2, len(template["behaviors"]))
            selected_behaviors = random.sample(template["behaviors"], num_behaviors)
            selected_sigs = random.sample(template["signatures"], min(2, len(template["signatures"])))

            # Build a realistic-looking sandbox trace
            pid = random.randint(1000, 9999)
            ppid = random.randint(100, 999)
            score = random.randint(5, 10)

            input_text = (
                f"CAPE Sandbox Report Summary\n"
                f"Sample: {family.lower()}_{random.randint(1000,9999)}.exe\n"
                f"Score: {score}/10\n"
                f"Process: {family.lower()}.exe (PID {pid}, PPID {ppid})\n\n"
                f"Behavioral Indicators:\n"
                + "\n".join(f"- {b}" for b in selected_behaviors) + "\n\n"
                f"Triggered Signatures:\n"
                + "\n".join(f"- [{random.randint(2,5)}] {s}" for s in selected_sigs)
            )

            tech_text = "\n".join(
                f"- **{tid}** ({tname})" for tid, tname in template["techniques"]
            )

            output_text = (
                f"## Dynamic Analysis Report\n\n"
                f"**Classification:** {family}\n"
                f"**Risk Score:** {score}/10\n\n"
                f"## Summary\n\n"
                f"This sample belongs to the {family} malware family. "
                f"During sandbox execution, it exhibited {num_behaviors} significant behavioral indicators.\n\n"
                f"## Behavioral Observations\n\n"
                + "\n".join(f"- {b}" for b in selected_behaviors) + "\n\n"
                f"## MITRE ATT&CK Mapping\n\n"
                f"{tech_text}\n\n"
                f"## Recommendations\n\n"
                f"1. Isolate affected endpoints and block associated IOCs\n"
                f"2. Check for persistence artifacts in registry and scheduled tasks\n"
                f"3. Hunt for lateral movement using the observed techniques\n"
                f"4. Update detection rules for {family} behavioral patterns"
            )

            instruction = random.choice(INSTRUCTION_TEMPLATES)
            record = {
                "instruction": instruction,
                "input": input_text[:2000],
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Generated {count} CAPE-style behavioral templates → {output_path.name}")
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-cape-reports", type=int, default=None,
                        help="(Unused — Avast CAPE has no raw reports)")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--template-count", type=int, default=2000,
                        help="Number of CAPE-style behavioral templates to generate")
    args = parser.parse_args()

    out_path = Path(args.output) if args.output else OUT_DIR / "e2_dynamic.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Truncate output file
    out_path.write_text("")

    total = 0

    # Mal-API-2019 (primary — 7,107 real API sequences)
    total += convert_malapi(RAW_DIR / "mal-api-2019", out_path)

    # CAPE behavioral templates (supplement — fills gap from missing Avast data)
    total += generate_cape_templates(out_path, n=args.template_count)

    print(f"\nTotal E2 Dynamic examples: {total}")


if __name__ == "__main__":
    main()
