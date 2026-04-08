"""
report_generator.py — Generate structured report sections from analysis data.

Uses Kimi (Azure) to produce Joe Sandbox-style report sections from:
  - The raw analysis report text (from Fathom)
  - Extracted IOCs and techniques
  - Sample metadata

Each section is generated with a targeted prompt so the output is
precise and grounded in the actual evidence.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

import requests

AZURE_ENDPOINT = os.environ.get(
    "AZURE_ENDPOINT", "https://cb26haseeb-5473-resource.openai.azure.com/openai/v1"
)
AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "")
AZURE_MODEL = os.environ.get("AZURE_MODEL", "Kimi-K2.5")


def _call_kimi(prompt: str, system: str, max_tokens: int = 800) -> str:
    """Single Kimi call, returns text or empty string on failure."""
    if not AZURE_API_KEY:
        return ""
    try:
        r = requests.post(
            f"{AZURE_ENDPOINT}/chat/completions",
            headers={"api-key": AZURE_API_KEY, "Content-Type": "application/json"},
            json={
                "model": AZURE_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.1,
            },
            timeout=60,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return ""


def _extract_techniques(text: str) -> list[dict]:
    """Extract ATT&CK technique IDs from text and return structured list."""
    ids = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", text)))
    # Map common IDs to names/tactics
    KNOWN = {
        "T1055": ("Process Injection", "Defense Evasion"),
        "T1055.001": ("Process Injection: DLL Injection", "Defense Evasion"),
        "T1055.002": ("Process Injection: PE Injection", "Defense Evasion"),
        "T1055.012": ("Process Injection: Process Hollowing", "Defense Evasion"),
        "T1547.001": ("Boot/Logon Autostart: Registry Run Keys", "Persistence"),
        "T1059.001": ("Command and Scripting: PowerShell", "Execution"),
        "T1059.003": ("Command and Scripting: Windows Command Shell", "Execution"),
        "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
        "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
        "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
        "T1027.002": ("Obfuscated Files: Software Packing", "Defense Evasion"),
        "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
        "T1497.001": ("Virtualization/Sandbox Evasion: System Checks", "Defense Evasion"),
        "T1012": ("Query Registry", "Discovery"),
        "T1082": ("System Information Discovery", "Discovery"),
        "T1083": ("File and Directory Discovery", "Discovery"),
        "T1573.001": ("Encrypted Channel: Symmetric Cryptography", "Command and Control"),
        "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
        "T1003": ("OS Credential Dumping", "Credential Access"),
        "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    }
    result = []
    for tid in ids[:12]:
        name, tactic = KNOWN.get(tid, (tid, "Unknown"))
        # Infer severity from tactic
        severity = "critical" if tactic in ("Credential Access", "Exfiltration") else \
                   "high" if tactic in ("Persistence", "Command and Control") else \
                   "medium"
        result.append({"id": tid, "name": name, "tactic": tactic, "severity": severity})
    return result


def _extract_iocs(text: str, sample_meta: dict) -> list[dict]:
    """Extract IOCs from report text and sample metadata."""
    iocs = []
    seen = set()

    def add(ioc_type: str, value: str, severity: str):
        key = (ioc_type, value)
        if key not in seen and value:
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value, "severity": severity})

    # SHA256 / MD5 from metadata
    if sample_meta.get("sha256"):
        add("hash-sha256", sample_meta["sha256"], "critical")
    if sample_meta.get("md5"):
        add("hash-md5", sample_meta["md5"], "critical")

    # IPs from text (exclude private)
    for ip in re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text):
        if not any(ip.startswith(p) for p in ("192.168.", "10.", "172.", "127.", "0.")):
            add("ip", ip, "critical")

    # Domains
    for domain in re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:xyz|com|net|org|io|ru|cn|info|biz|top)\b",
        text, re.IGNORECASE
    ):
        if len(domain) > 6 and "." in domain:
            add("domain", domain.lower(), "high")

    # Mutexes
    for mutex in re.findall(r"Global\\[\w\{\}\-]+", text):
        add("mutex", mutex, "medium")

    # Registry keys
    for reg in re.findall(r"HKLM\\[^\s,\"']+|HKCU\\[^\s,\"']+", text):
        add("registry", reg[:120], "high")

    # URLs
    for url in re.findall(r"https?://[^\s\"'<>]+", text):
        if len(url) > 10:
            add("url", url[:200], "high")

    return iocs[:30]


def generate_report_sections(
    report_text: str,
    sample_meta: dict,
    include_ai_sections: bool = True,
) -> dict:
    """
    Generate all report sections from analysis text + metadata.

    Args:
        report_text: The full Fathom analysis report text.
        sample_meta: {file_name, sha256, md5, file_type, file_size, family, score}
        include_ai_sections: If True, call Kimi to generate detailed sections.

    Returns:
        Dict with all report fields ready for the frontend.
    """
    techniques = _extract_techniques(report_text)
    iocs = _extract_iocs(report_text, sample_meta)

    # Determine verdict from report text
    text_lower = report_text.lower()
    if any(w in text_lower for w in ["malicious", "malware", "trojan", "ransomware", "stealer", "rat ", "backdoor"]):
        verdict = "malicious"
    elif any(w in text_lower for w in ["suspicious", "potentially", "possibly"]):
        verdict = "suspicious"
    else:
        verdict = "benign"

    # Extract risk score
    score_match = re.search(r"(?:risk score|score)[:\s]+(\d+(?:\.\d+)?)\s*/\s*10", report_text, re.IGNORECASE)
    risk_score = float(score_match.group(1)) if score_match else (
        9.0 if verdict == "malicious" else 5.0 if verdict == "suspicious" else 2.0
    )

    # Extract malware family
    family = sample_meta.get("family", "")
    if not family:
        for fam in ["Emotet", "Cobalt Strike", "Vidar", "Amadey", "Formbook", "Redline",
                    "AgentTesla", "Lokibot", "NjRAT", "AsyncRAT", "Remcos", "Raccoon"]:
            if fam.lower() in text_lower:
                family = fam
                break
        if not family:
            family = "Unknown"

    # Split report into sections by markdown headers
    sections_raw = _split_report_sections(report_text)

    # Build structured sections
    sections = []

    # 1. Executive Summary
    exec_text = sections_raw.get("executive summary", report_text[:800])
    sections.append({
        "id": "executive-summary",
        "title": "Executive Summary",
        "icon": "BookOpen",
        "content": exec_text,
    })

    # 2. Static Analysis
    static_text = sections_raw.get("static analysis", "")
    if not static_text and include_ai_sections:
        static_text = _call_kimi(
            f"Based on this malware analysis, write a concise Static Analysis section "
            f"covering PE structure, packing, imports, entropy, and compilation timestamp:\n\n{report_text[:2000]}",
            "You are a malware analyst. Write precise, evidence-based analysis sections. "
            "Be concise (3-5 sentences). Reference specific technical details from the evidence.",
            max_tokens=300,
        )
    sections.append({
        "id": "static-analysis",
        "title": "Static Analysis",
        "icon": "Search",
        "content": static_text or "Static analysis data not available for this sample.",
    })

    # 3. Dynamic Behavior
    dynamic_text = sections_raw.get("behavioral indicators", sections_raw.get("dynamic", ""))
    if not dynamic_text and include_ai_sections:
        dynamic_text = _call_kimi(
            f"Based on this malware analysis, write a Dynamic Behavior section covering "
            f"process execution, API calls, file system changes, registry modifications, "
            f"and anti-analysis techniques:\n\n{report_text[:2000]}",
            "You are a malware analyst. Write precise, evidence-based analysis sections. "
            "Be concise (3-5 sentences). Reference specific technical details.",
            max_tokens=300,
        )
    sections.append({
        "id": "dynamic-analysis",
        "title": "Dynamic Behavior",
        "icon": "Activity",
        "content": dynamic_text or "Dynamic behavior data not available for this sample.",
    })

    # 4. Network Indicators
    network_text = sections_raw.get("network", "")
    if not network_text and iocs:
        domains = [i["value"] for i in iocs if i["type"] == "domain"][:5]
        ips = [i["value"] for i in iocs if i["type"] == "ip"][:5]
        if domains or ips:
            network_text = f"C2 domains: {', '.join(domains)}. " if domains else ""
            network_text += f"C2 IPs: {', '.join(ips)}." if ips else ""
    sections.append({
        "id": "network-indicators",
        "title": "Network Indicators",
        "icon": "Network",
        "content": network_text or "No network indicators extracted.",
    })

    # 5. IOC Table (special — rendered as table)
    sections.append({
        "id": "ioc-extraction",
        "title": "IOC Extraction",
        "icon": "Crosshair",
        "iocTable": True,
    })

    # 6. MITRE ATT&CK (special — rendered as table)
    sections.append({
        "id": "mitre-mapping",
        "title": "MITRE ATT&CK Mapping",
        "icon": "Radar",
        "mitreTable": True,
    })

    # 7. Detection Recommendations
    detection_text = sections_raw.get("detection", "")
    if not detection_text and include_ai_sections and techniques:
        tids = ", ".join(t["id"] for t in techniques[:5])
        detection_text = _call_kimi(
            f"Write detection recommendations for malware using techniques {tids}. "
            f"Include Sigma rule suggestions, YARA hints, and EDR detection points. "
            f"Context: {report_text[:1000]}",
            "You are a detection engineer. Write actionable detection guidance. Be concise.",
            max_tokens=300,
        )
    sections.append({
        "id": "detection-rules",
        "title": "Detection Recommendations",
        "icon": "Target",
        "content": detection_text or "Run detection engineering analysis to generate Sigma/YARA rules.",
    })

    # 8. Risk Assessment
    risk_text = sections_raw.get("threat assessment", sections_raw.get("risk", ""))
    if not risk_text:
        risk_text = (
            f"Overall risk: {'CRITICAL' if risk_score >= 8 else 'HIGH' if risk_score >= 6 else 'MEDIUM'} "
            f"({risk_score}/10). "
            f"The sample is classified as {verdict} ({family}). "
            f"Immediate containment is {'strongly ' if risk_score >= 8 else ''}recommended."
        )
    sections.append({
        "id": "risk-assessment",
        "title": "Risk Assessment",
        "icon": "AlertTriangle",
        "content": risk_text,
    })

    # 9. Remediation
    remediation_text = sections_raw.get("remediation", "")
    if not remediation_text and include_ai_sections:
        remediation_text = _call_kimi(
            f"Write remediation steps for a {verdict} {family} infection. "
            f"IOCs to block: {json.dumps([i['value'] for i in iocs[:5]])}. "
            f"Techniques used: {', '.join(t['id'] for t in techniques[:5])}.",
            "You are an incident responder. Write numbered remediation steps. Be specific and actionable.",
            max_tokens=300,
        )
    sections.append({
        "id": "remediation",
        "title": "Remediation Steps",
        "icon": "Zap",
        "content": remediation_text or "Isolate affected systems and block identified IOCs.",
    })

    return {
        "verdict": verdict,
        "confidence": min(99, max(50, int(risk_score * 10))),
        "riskScore": risk_score,
        "malwareFamily": family,
        "sections": sections,
        "iocs": iocs,
        "techniques": techniques,
    }


def _split_report_sections(text: str) -> dict[str, str]:
    """Split a markdown report into sections by ## headers."""
    sections: dict[str, str] = {}
    current_key = ""
    current_lines: list[str] = []

    for line in text.splitlines():
        if line.startswith("## "):
            if current_key and current_lines:
                sections[current_key] = "\n".join(current_lines).strip()
            current_key = line[3:].strip().lower()
            current_lines = []
        elif line.startswith("# "):
            if current_key and current_lines:
                sections[current_key] = "\n".join(current_lines).strip()
            current_key = line[2:].strip().lower()
            current_lines = []
        else:
            current_lines.append(line)

    if current_key and current_lines:
        sections[current_key] = "\n".join(current_lines).strip()

    return sections
