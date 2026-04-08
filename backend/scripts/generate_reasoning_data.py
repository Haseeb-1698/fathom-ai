#!/usr/bin/env python3
"""
generate_reasoning_data.py — Generate chain-of-thought reasoning supplement
for unified v2 training.

Creates ~3K synthetic CoT examples that supplement the Plan A 120K dataset.
These teach the model to show reasoning steps before conclusions.

Output: data/processed/v2_cot_supplement.jsonl
"""

import json
import random
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

# Reasoning chain templates
COT_SCENARIOS = [
    {
        "category": "dynamic_analysis",
        "instructions": [
            "Analyze this API call sequence step by step and determine what the malware is doing.",
            "Walk through this behavioral trace systematically and identify each malicious action.",
        ],
        "inputs": [
            "CreateFileW('C:\\Users\\victim\\AppData\\Local\\Temp\\svchost.exe') → WriteFile → CreateProcessW('svchost.exe') → RegSetValueExW('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'WindowsUpdate')",
            "WSAStartup → socket → connect('185.141.27.101:443') → send(encrypted_data) → recv → CreateThread → VirtualAlloc(PAGE_EXECUTE_READWRITE) → WriteProcessMemory",
            "NtCreateFile → NtWriteFile('C:\\Windows\\System32\\drivers\\maldrv.sys') → NtLoadDriver → NtDeviceIoControlFile",
        ],
        "cot_template": (
            "Let me analyze this step by step:\n\n"
            "{steps}\n\n"
            "## Conclusion\n\n{conclusion}"
        ),
    },
    {
        "category": "static_analysis",
        "instructions": [
            "Examine these PE file characteristics and reason about whether this is malicious.",
            "Review the following static indicators step by step.",
        ],
        "inputs": [
            "PE32 executable, UPX packed, 3 sections (.text entropy: 7.98, .rsrc entropy: 7.95, .reloc entropy: 2.1), imports: kernel32.dll(VirtualAlloc, WriteProcessMemory, CreateRemoteThread), no valid signature",
            "PE32+ DLL, signed by 'Microsoft Corporation' (expired 2019), imports: advapi32.dll(RegSetValueEx, CryptEncrypt), ws2_32.dll(connect, send), 5 TLS callbacks",
        ],
        "cot_template": (
            "Analyzing the static features systematically:\n\n"
            "{steps}\n\n"
            "## Verdict\n\n{conclusion}"
        ),
    },
    {
        "category": "threat_intel",
        "instructions": [
            "Given these IOCs, reason through the likely threat actor and campaign.",
            "Analyze these indicators and determine the threat attribution step by step.",
        ],
        "inputs": [
            "C2 domains: update-microsoft[.]com, windowsupdate-check[.]net. User-agent: 'Mozilla/5.0 (compatible; MSIE 10.0)'. Beacon interval: 60s ± 15%. XOR key: 0x3A. Targets: government sector.",
            "Spearphishing PDF with macro dropper → PowerShell download cradle → Cobalt Strike beacon → lateral movement via PsExec → data staging in %TEMP% → exfil over DNS",
        ],
        "cot_template": (
            "Let me trace through the indicators:\n\n"
            "{steps}\n\n"
            "## Attribution Assessment\n\n{conclusion}"
        ),
    },
    {
        "category": "attck_mapping",
        "instructions": [
            "Map the following behaviors to ATT&CK techniques with reasoning for each mapping.",
            "Identify ATT&CK techniques and explain your reasoning step by step.",
        ],
        "inputs": [
            "The malware drops a copy of itself to the Startup folder, creates a scheduled task running every 30 minutes, modifies the registry Run key, and installs a Windows service.",
            "The sample uses reflective DLL injection to load into explorer.exe, hooks ntdll.dll to intercept file operations, and uses process hollowing on svchost.exe.",
        ],
        "cot_template": (
            "Mapping each behavior to ATT&CK:\n\n"
            "{steps}\n\n"
            "## Summary\n\n{conclusion}"
        ),
    },
]

STEP_CONNECTORS = [
    "**Step {n}:** ", "**{n}.** ", "**Observation {n}:** ", "{n}. ",
]

DYNAMIC_STEPS = [
    "The API call {api} suggests {behavior}. This is a {severity} indicator.",
    "Observing {api} — this typically indicates {behavior}.",
    "The sequence {api} → {api2} is characteristic of {behavior}.",
    "Network activity to {detail} indicates {behavior}.",
    "File system modification at {detail} suggests {behavior}.",
    "Registry modification targeting {detail} indicates {behavior}.",
]

BEHAVIORS = [
    ("process injection", "T1055", "defense evasion"),
    ("persistence via registry", "T1547.001", "persistence"),
    ("C2 communication", "T1071", "command and control"),
    ("credential theft", "T1003", "credential access"),
    ("data exfiltration", "T1041", "exfiltration"),
    ("privilege escalation", "T1055", "privilege escalation"),
    ("defense evasion via packing", "T1027", "defense evasion"),
    ("lateral movement", "T1021", "lateral movement"),
    ("discovery of system info", "T1082", "discovery"),
    ("file encryption for impact", "T1486", "impact"),
]


def generate_cot_example() -> dict:
    scenario = random.choice(COT_SCENARIOS)
    instruction = random.choice(scenario["instructions"])
    input_text = random.choice(scenario["inputs"])

    # Generate reasoning steps
    num_steps = random.randint(3, 6)
    steps = []
    for i in range(1, num_steps + 1):
        behavior = random.choice(BEHAVIORS)
        connector = random.choice(STEP_CONNECTORS).format(n=i)
        step_text = (
            f"{connector}This indicates **{behavior[0]}** "
            f"(ATT&CK: {behavior[1]}, Tactic: {behavior[2]}). "
        )
        steps.append(step_text)

    conclusion_behaviors = random.sample(BEHAVIORS, min(3, len(BEHAVIORS)))
    conclusion = (
        "Based on the analysis above, this sample demonstrates:\n"
        + "\n".join(f"- {b[0]} ({b[1]})" for b in conclusion_behaviors)
        + "\n\nOverall threat level: **HIGH**. Immediate containment recommended."
    )

    output = scenario["cot_template"].format(
        steps="\n".join(steps),
        conclusion=conclusion,
    )

    return {
        "instruction": instruction,
        "input": input_text,
        "output": output,
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "v2_cot_supplement.jsonl"

    n = 3000
    count = 0
    random.seed(42)

    with open(out_path, "w", encoding="utf-8") as f:
        for _ in range(n):
            example = generate_cot_example()
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            count += 1

    print(f"Generated {count} CoT supplement examples → {out_path}")


if __name__ == "__main__":
    main()
