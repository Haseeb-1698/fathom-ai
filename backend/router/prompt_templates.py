"""
prompt_templates.py — 8 domain-specific prompt templates.

Each template structures the LLM prompt for a specific expert domain,
incorporating evidence, RAG context, and domain-specific instructions.
"""

from __future__ import annotations

from config import build_prompt

# ── Domain prompt templates ──────────────────────────────────────────────

DOMAIN_TEMPLATES = {
    "E1_static": {
        "system": (
            "You are Fathom, a malware static analysis expert. Analyze PE file "
            "characteristics, import tables, sections, strings, and packer signatures. "
            "Identify suspicious indicators and classify the sample."
        ),
        "instruction_prefix": "Perform static analysis on this PE executable:",
    },
    "E2_dynamic": {
        "system": (
            "You are Fathom, a malware dynamic behavior analyst. Analyze API call "
            "sequences, process trees, registry modifications, file operations, and "
            "network activity from sandbox execution traces. Identify malware behaviors "
            "and classify the family."
        ),
        "instruction_prefix": "Analyze this dynamic execution trace:",
    },
    "E3_network": {
        "system": (
            "You are Fathom, a network traffic analyst specializing in malware C2 "
            "communication. Analyze DNS queries, HTTP/HTTPS traffic patterns, beacon "
            "intervals, and TLS fingerprints to identify C2 infrastructure."
        ),
        "instruction_prefix": "Analyze this network traffic capture:",
    },
    "E4_forensics": {
        "system": (
            "You are Fathom, a digital forensics expert. Analyze persistence mechanisms, "
            "registry artifacts, file system changes, and temporal indicators to "
            "reconstruct the attack timeline."
        ),
        "instruction_prefix": "Analyze these forensic artifacts:",
    },
    "E5_threatintel": {
        "system": (
            "You are Fathom, a cyber threat intelligence analyst. Map indicators to "
            "threat actors, correlate IOCs across campaigns, and produce ATT&CK-aligned "
            "threat assessments."
        ),
        "instruction_prefix": "Analyze this threat intelligence:",
    },
    "E6_detection": {
        "system": (
            "You are Fathom, a detection engineering specialist. Write YARA rules, "
            "Sigma rules, and detection logic based on observed malware behaviors "
            "and indicators."
        ),
        "instruction_prefix": "Create detection rules for:",
    },
    "E7_reports": {
        "system": (
            "You are Fathom, a malware analysis report writer. Produce structured, "
            "evidence-driven analysis reports with executive summaries, technical findings, "
            "MITRE ATT&CK technique mappings, IOC lists, and actionable recommendations."
        ),
        "instruction_prefix": "Generate a comprehensive malware analysis report:",
    },
    "E8_remediation": {
        "system": (
            "You are Fathom, an incident response specialist. Provide containment, "
            "eradication, and recovery procedures. Prioritize actions by urgency and "
            "impact."
        ),
        "instruction_prefix": "Provide incident response guidance:",
    },
}


def build_domain_prompt(
    domain_id: str,
    query: str,
    evidence_text: str = "",
    rag_context: str = "",
) -> str:
    """
    Build a complete domain-specific prompt in Alpaca format.

    Combines: domain system prompt + evidence brief + RAG context + user query.
    """
    template = DOMAIN_TEMPLATES.get(domain_id, DOMAIN_TEMPLATES["E7_reports"])

    # Build instruction
    instruction = template["system"] + "\n\n" + template["instruction_prefix"]
    if query:
        instruction += f"\n{query}"

    # Build input (evidence + RAG context)
    input_parts = []
    if evidence_text:
        input_parts.append(f"## Evidence\n{evidence_text}")
    if rag_context:
        input_parts.append(f"## Reference Context\n{rag_context}")

    input_text = "\n\n".join(input_parts)

    return build_prompt(instruction, input_text)
