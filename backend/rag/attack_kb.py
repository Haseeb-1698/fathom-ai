"""
attack_kb.py — Parse MITRE ATT&CK Enterprise STIX JSON into indexable chunks.

Extracts ~700 techniques with IDs, names, descriptions, tactics, and mitigations
into a list of dictionaries ready for FAISS indexing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_stix_bundle(stix_path: str | Path) -> list[dict[str, Any]]:
    """
    Parse enterprise-attack.json (STIX 2.1 bundle) into technique records.

    Returns list of:
        {
            "technique_id": "T1055",
            "name": "Process Injection",
            "description": "...",
            "tactics": ["defense-evasion", "privilege-escalation"],
            "platforms": ["Windows", "Linux"],
            "detection": "...",
            "mitigations": [...],
            "text": "..."  # combined text for embedding
        }
    """
    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Build ID → object lookup
    id_map = {obj["id"]: obj for obj in objects}

    # Build relationship map: technique_id → [mitigation objects]
    mitigations_map: dict[str, list[str]] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            target_ref = obj.get("target_ref", "")
            source_ref = obj.get("source_ref", "")
            source = id_map.get(source_ref, {})
            if source.get("type") == "course-of-action":
                mitigations_map.setdefault(target_ref, []).append(
                    source.get("name", "")
                )

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract technique ID from external references
        technique_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        if not technique_id:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")

        # Extract tactics from kill_chain_phases
        tactics = [
            kc.get("phase_name", "")
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]

        platforms = obj.get("x_mitre_platforms", [])
        detection = obj.get("x_mitre_detection", "")
        mitigations = mitigations_map.get(obj["id"], [])

        # Combined text for embedding
        text = (
            f"{technique_id} {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"{description[:1000]}\n"
            f"Detection: {detection[:500]}"
        )

        techniques.append({
            "technique_id": technique_id,
            "name": name,
            "description": description,
            "tactics": tactics,
            "platforms": platforms,
            "detection": detection,
            "mitigations": mitigations,
            "text": text,
        })

    return techniques


def load_attack_kb(stix_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load ATT&CK KB, using default path if not specified."""
    if stix_path is None:
        # Check common locations
        candidates = [
            Path(__file__).parent.parent.parent / "data" / "raw" / "enterprise-attack.json",
            Path("/workspace/data/raw/enterprise-attack.json"),
        ]
        for c in candidates:
            if c.exists():
                stix_path = c
                break

    if stix_path is None or not Path(stix_path).exists():
        raise FileNotFoundError("enterprise-attack.json not found. Run download_extended_v5.py first.")

    return parse_stix_bundle(stix_path)
