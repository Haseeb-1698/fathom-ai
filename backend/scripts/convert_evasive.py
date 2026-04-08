#!/usr/bin/env python3
"""
convert_evasive.py
Converts evasive_dataset folder structure to Alpaca JSONL for e1_static training.

Folder naming convention:
  cf=Control Flow Flattening, gc=Garbage Code, gd=Garbage Data,
  meta=Metadata Modification, poly=Polymorphic, sd=Self-Decryption,
  var=Variable Obfuscation, sb/sand=Sandbox Evasion
  Special: "Consolidated_Standalone_Source" = original clean code (no evasion)
           "all" = all techniques combined

Usage:
  python3 convert_evasive.py \
    --input /workspace/fathom/data/evasive_dataset \
    --output /workspace/fathom/data/experts/e1_evasion_static.jsonl
"""

import json
import argparse
from pathlib import Path

TECHNIQUE_MAP = {
    "cf":   "Control Flow Flattening — the program's control flow is restructured using a dispatcher/state-machine pattern; dead branches and opaque predicates are inserted to obscure the original execution path",
    "gc":   "Garbage Code Injection — non-functional junk instructions, empty loops, and dead code blocks are inserted throughout function bodies to inflate complexity and confuse disassemblers/decompilers",
    "gd":   "Garbage Data Insertion — meaningless constant arrays and dummy variables are added to the binary to inflate its size and break similarity-based/heuristic detection",
    "meta": "Metadata Modification — PE section names, string literals, and file metadata are altered or relocated into non-standard sections (via custom pragma directives) to defeat signature-based scanning",
    "poly": "Polymorphic Encoding — code or payload bytes are encoded/transformed at rest and contain a self-modifying decoder stub that reconstructs them at runtime, preventing static disassembly",
    "sd":   "Self-Decryption — critical code regions or payloads are encrypted at rest; a built-in decryption routine executes first to reconstruct the actual code in memory, bypassing static analysis",
    "var":  "Variable Obfuscation/Encryption — variable names are randomised and sensitive values are XOR-encoded during storage, decoded only on access, preventing pattern-matching against known strings or constants",
    "sb":   "Sandbox Evasion — the code performs environment checks (CPU timing, hardware enumeration, user-activity heuristics, registry keys) and alters or terminates execution when an analysis sandbox is detected",
    "sand": "Sandbox Evasion — environment fingerprinting checks to detect and evade automated malware analysis sandboxes (equivalent to 'sb')",
    "va":   "Variable Obfuscation/Encryption — same as 'var': value encoding and name randomisation to resist static pattern-matching",
}

ALL_TECHNIQUES = ["CF", "GC", "GD", "META", "POLY", "SD", "VAR", "SB"]

INSTRUCTION_OBFUSCATED = (
    "Perform static analysis on the following obfuscated C++ malware source code. "
    "Identify every evasion technique present, explain where each technique manifests "
    "in the code, and assess the combined detection difficulty."
)
INSTRUCTION_CLEAN = (
    "Perform static analysis on the following C++ source code. "
    "Identify any evasion or anti-analysis techniques present, or confirm if the code "
    "is clean/unobfuscated."
)


def folder_to_techniques(folder_name: str):
    """Return list of (ABBREV, full_description) for the folder label."""
    name = folder_name.lower().strip()

    # Special cases
    if "consolidated" in name or "standalone" in name:
        return None  # clean code — handled separately

    if name == "all":
        return [(k.upper(), TECHNIQUE_MAP[k]) for k in ["cf", "gc", "gd", "meta", "poly", "sd", "var", "sb"]]

    # Named technique folders
    if "cntrl flow" in name or "control flow" in name:
        return [("CF", TECHNIQUE_MAP["cf"])]
    if "garbage data" in name:
        return [("GD", TECHNIQUE_MAP["gd"])]
    if "garbage code" in name:
        return [("GC", TECHNIQUE_MAP["gc"])]
    if "sb evasion" in name or "sandbox" in name:
        return [("SB", TECHNIQUE_MAP["sb"])]
    if "var enc" in name:
        return [("VAR", TECHNIQUE_MAP["var"])]
    if "poly shll" in name or "poly shell" in name:
        return [("POLY", TECHNIQUE_MAP["poly"])]

    # Standard "cf+meta+poly" style
    parts = name.replace(" ", "").split("+")
    result = []
    for p in parts:
        if p in TECHNIQUE_MAP:
            result.append((p.upper(), TECHNIQUE_MAP[p]))
    return result if result else None


def build_output_obfuscated(techniques, folder_name: str) -> str:
    if not techniques:
        return (
            f"Static Analysis Result: No recognised evasion techniques could be "
            f"mapped from folder label '{folder_name}'. Manual review required."
        )

    abbrevs = [t[0] for t in techniques]
    lines = [
        "Static Analysis — Evasion Technique Detection\n",
        f"Evasion label: {folder_name}",
        f"Techniques identified ({len(techniques)}): {', '.join(abbrevs)}\n",
    ]
    for i, (abbrev, desc) in enumerate(techniques, 1):
        title, detail = desc.split(" — ", 1)
        lines.append(f"{i}. **{abbrev} — {title}**")
        lines.append(f"   {detail}\n")

    if len(techniques) >= 5:
        note = (
            f"The combination of {' + '.join(abbrevs)} represents advanced multi-layer evasion. "
            "This level of stacking ({} techniques) is characteristic of APT-grade malware loaders "
            "and sophisticated ransomware, designed to defeat both static and dynamic analysis pipelines.".format(len(techniques))
        )
    elif len(techniques) >= 3:
        note = (
            f"The combination of {' + '.join(abbrevs)} significantly increases detection difficulty. "
            "Multi-layer evasion (3+ techniques) is characteristic of APT-grade implants and loaders."
        )
    else:
        note = (
            f"The combination of {' + '.join(abbrevs)} is common in commodity crimeware. "
            "Dual-technique obfuscation raises the detection bar above simple signature matching."
        )
    lines.append("Analyst note: " + note)
    return "\n".join(lines)


def build_output_clean(filename: str) -> str:
    return (
        "Static Analysis — Clean Source Code\n\n"
        "No evasion or anti-analysis techniques detected in this file. "
        "The code does not exhibit control flow obfuscation, garbage insertion, "
        "metadata manipulation, polymorphic encoding, self-decryption, variable obfuscation, "
        "or sandbox evasion patterns. This appears to be unmodified source code without "
        "intentional obfuscation applied."
    )


def convert(input_dir: str, output_path: str, max_code_chars: int = 6000):
    input_dir = Path(input_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    skipped = 0
    folder_counts = {}

    with open(output_path, "w") as out_f:
        for folder in sorted(input_dir.iterdir()):
            if not folder.is_dir():
                continue

            folder_name = folder.name
            techniques = folder_to_techniques(folder_name)
            is_clean = ("consolidated" in folder_name.lower() or "standalone" in folder_name.lower())

            files = sorted(list(folder.glob("*.cpp")) + list(folder.glob("*.c")))
            folder_written = 0

            for src_file in files:
                try:
                    code = src_file.read_text(errors="replace").strip()
                except Exception:
                    skipped += 1
                    continue

                if len(code) < 100:
                    skipped += 1
                    continue

                if len(code) > max_code_chars:
                    code = code[:max_code_chars] + "\n// [truncated for length]"

                if is_clean:
                    instruction = INSTRUCTION_CLEAN
                    output_text = build_output_clean(src_file.name)
                elif techniques is not None:
                    instruction = INSTRUCTION_OBFUSCATED
                    output_text = build_output_obfuscated(techniques, folder_name)
                else:
                    skipped += 1
                    continue

                record = {
                    "instruction": instruction,
                    "input": code,
                    "output": output_text,
                }
                out_f.write(json.dumps(record) + "\n")
                total += 1
                folder_written += 1

            folder_counts[folder_name] = folder_written

    print(f"\nConversion complete: {total} training examples → {output_path}")
    print(f"Skipped: {skipped} files")
    print(f"\nPer-folder breakdown:")
    for fname, cnt in sorted(folder_counts.items()):
        print(f"  {cnt:4d}  {fname}")
    return total


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input",  required=True, help="Path to evasive_dataset folder")
    p.add_argument("--output", required=True, help="Output JSONL path")
    p.add_argument("--max-code-chars", type=int, default=6000,
                   help="Truncate code snippets to this many characters (default 6000 ≈ 150 lines)")
    args = p.parse_args()
    convert(args.input, args.output, args.max_code_chars)
