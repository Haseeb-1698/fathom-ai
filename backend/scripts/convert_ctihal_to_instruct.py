#!/usr/bin/env python3
"""
convert_ctihal_to_instruct.py — Convert CTI-Bench / threat intel data to Alpaca JSONL
for E5 Threat Intelligence expert (stretch goal).

Output: data/processed/e5_threatintel.jsonl (~10K)
"""

import argparse
import json
import random
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

CTI_INSTRUCTIONS = [
    "Analyze the following threat intelligence report and extract key IOCs, TTPs, and threat actor attribution.",
    "Map the techniques described in this CTI report to MITRE ATT&CK framework entries.",
    "Given this threat intelligence context, identify the threat actor, their objectives, and recommended defenses.",
    "Review this CTI excerpt and produce a structured threat assessment with ATT&CK mappings.",
    "Extract indicators of compromise and tactical information from the following threat report.",
]


def convert_cti_reports(input_path: Path, output_path: Path) -> int:
    """Convert mrmoor/cyber-threat-intelligence dataset to instruction format.

    Schema: id, text, entities [{id, label, start_offset, end_offset}], relations, Comments
    """
    if not input_path.exists():
        print(f"[SKIP] CTI reports not found at {input_path}")
        return 0

    count = 0
    with open(input_path, "r", encoding="utf-8") as f, \
         open(output_path, "w", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)

            text = row.get("text", "")
            entities = row.get("entities", [])

            if not text or len(text) < 50:
                continue

            instruction = random.choice(CTI_INSTRUCTIONS)

            # Build output from entities
            entity_lines = []
            if isinstance(entities, list):
                for ent in entities[:20]:
                    if isinstance(ent, dict):
                        label = ent.get("label", "unknown")
                        start = ent.get("start_offset", 0)
                        end = ent.get("end_offset", 0)
                        entity_text = text[start:end] if start < len(text) and end <= len(text) else ""
                        if entity_text:
                            entity_lines.append(f"- **{label}**: {entity_text}")

            if entity_lines:
                output_text = (
                    f"## Threat Intelligence Analysis\n\n"
                    f"### Extracted Entities\n\n"
                    + "\n".join(entity_lines)
                    + "\n\n### Assessment\n\n"
                    f"This report contains {len(entity_lines)} identified threat entities. "
                    f"Further correlation with known threat actor databases is recommended."
                )
            else:
                output_text = (
                    f"## Threat Intelligence Analysis\n\n"
                    f"This CTI report discusses the following:\n\n"
                    f"{text[:500]}\n\n"
                    f"### Recommended Actions\n\n"
                    f"1. Cross-reference IOCs with threat intelligence platforms\n"
                    f"2. Update detection signatures based on described TTPs\n"
                    f"3. Brief the SOC team on the described campaign"
                )

            record = {
                "instruction": instruction,
                "input": text[:2000],
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Converted {count} CTI report rows → {output_path.name}")
    return count


def generate_ioc_examples(output_path: Path, n: int = 3000) -> int:
    """Generate IOC extraction and attribution training examples."""
    threat_actors = [
        ("APT28", "Fancy Bear", "Russia", "GRU"),
        ("APT29", "Cozy Bear", "Russia", "SVR"),
        ("APT41", "Double Dragon", "China", "MSS"),
        ("Lazarus Group", "Hidden Cobra", "North Korea", "RGB"),
        ("FIN7", "Carbanak Group", "Financially motivated", ""),
        ("Turla", "Snake", "Russia", "FSB"),
        ("Sandworm", "Voodoo Bear", "Russia", "GRU"),
        ("APT32", "OceanLotus", "Vietnam", ""),
        ("Kimsuky", "Velvet Chollima", "North Korea", ""),
        ("MuddyWater", "Mercury", "Iran", "MOIS"),
    ]

    techniques = [
        ("T1566.001", "Spearphishing Attachment", "Initial Access"),
        ("T1059.001", "PowerShell", "Execution"),
        ("T1547.001", "Registry Run Keys", "Persistence"),
        ("T1055", "Process Injection", "Defense Evasion"),
        ("T1078", "Valid Accounts", "Privilege Escalation"),
        ("T1087", "Account Discovery", "Discovery"),
        ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
        ("T1005", "Data from Local System", "Collection"),
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        ("T1071.001", "Web Protocols", "Command and Control"),
    ]

    count = 0
    with open(output_path, "a", encoding="utf-8") as out:
        for i in range(n):
            actor = random.choice(threat_actors)
            num_techs = random.randint(2, 5)
            selected = random.sample(techniques, min(num_techs, len(techniques)))

            instruction = random.choice(CTI_INSTRUCTIONS)
            input_text = (
                f"Threat Actor: {actor[0]} (aka {actor[1]})\n"
                f"Attribution: {actor[2]}\n"
                f"Observed Techniques: {', '.join(t[0] for t in selected)}\n"
                f"Target Sector: Government/Defense"
            )

            tech_analysis = "\n".join(
                f"- **{t[0]} ({t[1]})** [{t[2]}]: Utilized for {t[2].lower()} operations"
                for t in selected
            )

            output_text = (
                f"## Threat Actor Assessment: {actor[0]}\n\n"
                f"**Aliases:** {actor[1]}\n"
                f"**Attribution:** {actor[2]}"
                + (f" ({actor[3]})" if actor[3] else "") + "\n\n"
                f"## ATT&CK Technique Mapping\n\n{tech_analysis}\n\n"
                f"## Defensive Recommendations\n\n"
                f"1. Deploy detection rules targeting {actor[0]} TTPs\n"
                f"2. Monitor for indicators associated with {actor[1]} tooling\n"
                f"3. Implement network segmentation to limit lateral movement\n"
                f"4. Enable enhanced logging for the identified technique categories"
            )

            record = {
                "instruction": instruction,
                "input": input_text,
                "output": output_text,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"Generated {count} CTI examples → {output_path.name}")
    return count


def convert_lolbas(lolbas_dir: Path, output_path: Path) -> int:
    """Convert LOLBAS YAML files to threat intel instruction format."""
    if not lolbas_dir.exists():
        print(f"[SKIP] LOLBAS not found at {lolbas_dir}")
        return 0

    count = 0
    yml_files = list(lolbas_dir.rglob("*.yml")) + list(lolbas_dir.rglob("*.yaml"))
    if not yml_files:
        print(f"[SKIP] No YAML files in {lolbas_dir}")
        return 0

    try:
        import yaml
    except ImportError:
        # Fallback: parse YAML manually for simple fields
        yaml = None

    with open(output_path, "a", encoding="utf-8") as out:
        for yml_path in yml_files:
            try:
                content = yml_path.read_text(encoding="utf-8", errors="ignore")
                if yaml:
                    data = yaml.safe_load(content)
                else:
                    data = {"raw": content[:1000]}

                if not isinstance(data, dict):
                    continue

                name = data.get("Name", data.get("name", yml_path.stem))
                description = data.get("Description", data.get("description", ""))
                if not description:
                    continue

                instruction = "Explain this Living Off The Land Binary/Script and how it can be abused by threat actors."
                output_text = (
                    f"## LOLBAS Analysis: {name}\n\n"
                    f"{description}\n\n"
                    f"### Threat Relevance\n\n"
                    f"This legitimate system binary can be abused by attackers for defense evasion. "
                    f"Monitor for anomalous usage patterns in your environment."
                )

                record = {
                    "instruction": instruction,
                    "input": f"Binary/Script: {name}\nDescription: {description[:500]}",
                    "output": output_text,
                }
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
            except Exception:
                continue

    print(f"Converted {count} LOLBAS entries → {output_path.name}")
    return count


def convert_atomic_red_team(atomic_dir: Path, output_path: Path) -> int:
    """Convert Atomic Red Team atomics to threat intel instruction format."""
    if not atomic_dir.exists():
        print(f"[SKIP] Atomic Red Team not found at {atomic_dir}")
        return 0

    atomics_dir = atomic_dir / "atomics"
    if not atomics_dir.exists():
        print(f"[SKIP] No atomics/ dir in {atomic_dir}")
        return 0

    count = 0
    try:
        import yaml
    except ImportError:
        yaml = None

    with open(output_path, "a", encoding="utf-8") as out:
        for yml_path in sorted(atomics_dir.rglob("*.yaml")):
            try:
                content = yml_path.read_text(encoding="utf-8", errors="ignore")
                if yaml:
                    data = yaml.safe_load(content)
                else:
                    continue  # YAML parsing required for Atomic

                if not isinstance(data, dict):
                    continue

                technique_name = data.get("display_name", data.get("attack_technique", ""))
                technique_id = data.get("attack_technique", "")
                tests = data.get("atomic_tests", [])

                for test in tests[:3]:  # limit per technique
                    if not isinstance(test, dict):
                        continue
                    test_name = test.get("name", "")
                    test_desc = test.get("description", "")
                    if not test_desc:
                        continue

                    instruction = f"Explain ATT&CK technique {technique_id} ({technique_name}) and how to detect it."
                    output_text = (
                        f"## ATT&CK Technique: {technique_id} - {technique_name}\n\n"
                        f"### Test: {test_name}\n\n"
                        f"{test_desc}\n\n"
                        f"### Detection\n\n"
                        f"Monitor for the behaviors described above. "
                        f"Implement detection rules targeting {technique_id} indicators."
                    )

                    record = {
                        "instruction": instruction,
                        "input": f"Technique: {technique_id} {technique_name}\nTest: {test_name}\n{test_desc[:500]}",
                        "output": output_text,
                    }
                    out.write(json.dumps(record, ensure_ascii=False) + "\n")
                    count += 1
            except Exception:
                continue

    print(f"Converted {count} Atomic Red Team tests → {output_path.name}")
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    out_path = Path(args.output) if args.output else OUT_DIR / "e5_threatintel.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("")  # truncate

    total = 0
    total += convert_cti_reports(RAW_DIR / "cti_reports.jsonl", out_path)
    total += convert_lolbas(RAW_DIR / "lolbas", out_path)
    total += convert_atomic_red_team(RAW_DIR / "atomic-red-team", out_path)
    total += generate_ioc_examples(out_path, n=3000)

    print(f"\nTotal E5 Threat Intelligence examples: {total}")


if __name__ == "__main__":
    main()
