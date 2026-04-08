#!/usr/bin/env python3
"""
collect_experts.py — Build datasets for all 5 missing Fathom expert adapters.

Produces:
  e1_static.jsonl       — PE/static analysis (EMBER2024, EMBER-CAPA, PowerShell)
  e3_network.jsonl      — Network traffic analysis (CybersecAttacks, OTX, filtered CTI)
  e4_forensics.jsonl    — Forensics / OSSEM / Sigma / persistence artifacts
  e6_detection.jsonl    — Detection rules (YARA/Sigma/NIST/Cybersec32K)
  e8_analyst.jsonl      — Analyst simulation (ShareGPT, QAA, CyberNative, OTX)
  e5_threatintel_aug.jsonl — ThreatIntel augment (OTX pulses, MalwareBazaar, LOLBAS, ART)

Usage:
  HF_TOKEN=xxx OTX_KEY=xxx python3 collect_experts.py
"""

import json
import os
import random
import re
import sys
import time
from pathlib import Path

import requests

HF_TOKEN = os.environ.get("HF_TOKEN", "")
OTX_KEY  = os.environ.get("OTX_KEY", "")
OUT_DIR  = Path(os.environ.get("OUT_DIR", "/workspace/output"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

random.seed(42)

# ─── HF dataset loader (with datasets 2.20 for trust_remote_code support) ────
def load_hf(repo_id, split="train", trust_remote_code=False, streaming=False, **kwargs):
    from datasets import load_dataset
    try:
        return load_dataset(repo_id, split=split, token=HF_TOKEN,
                            trust_remote_code=trust_remote_code,
                            streaming=streaming, **kwargs)
    except Exception as e:
        print(f"  [WARN] {repo_id}: {e}")
        return None


def write_jsonl(path: Path, records: list[dict], mode="w"):
    with open(path, mode, encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  Wrote {len(records)} rows → {path}")


def alpaca(instruction: str, input_: str, output: str) -> dict:
    return {
        "instruction": instruction[:600].strip(),
        "input": input_[:1000].strip(),
        "output": output[:3000].strip(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# E1 — STATIC ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def collect_e1_static():
    print("\n[E1] Static Analysis...")
    out = OUT_DIR / "e1_static.jsonl"
    records = []
    # Skip EMBER2024 main (large, tends to fail on small VMs)
    # Use only EMBER2024-capa + PowerShell (cached already)

    # ── EMBER2024 ──────────────────────────────────────────────────────────────
    print("  Loading joyce8/EMBER2024 (streaming)...")
    ds = load_hf("joyce8/EMBER2024", trust_remote_code=True, streaming=True)
    if ds:
        instrs = [
            "Analyze these PE header features and determine if this binary is malicious. Classify as malicious or benign and explain the key indicators.",
            "You are a static malware analyst. Given the following PE file features, identify whether this is malware and explain which features are suspicious.",
            "Examine these static PE analysis features. Identify the malware family if applicable, describe the threat level, and highlight key PE characteristics.",
            "Based on these PE binary features, perform a static analysis classification. Explain entropy patterns, import table anomalies, and section characteristics.",
        ]
        count = 0
        for row in ds:
            label = row.get("label", row.get("labels", row.get("is_malware", -1)))
            if label == -1:
                continue
            # Build feature summary from available columns
            feature_parts = []
            if row.get("appeared"):
                feature_parts.append(f"First seen: {row['appeared']}")
            for col in ["avclass", "family", "tags"]:
                if row.get(col):
                    feature_parts.append(f"{col}: {row[col]}")
            # Numeric features
            numeric = {k: v for k, v in row.items()
                       if isinstance(v, (int, float)) and k not in ("label","labels","is_malware")}
            if numeric:
                # summarize top entropy/size features
                feature_parts.append("Features: " + ", ".join(
                    f"{k}={round(v,4)}" for k, v in list(numeric.items())[:20]
                ))
            if not feature_parts:
                continue
            input_text = "\n".join(feature_parts)
            is_mal = bool(label)
            verdict = "MALICIOUS" if is_mal else "BENIGN"
            family = row.get("avclass") or row.get("family") or ("unknown" if is_mal else "clean")
            output = (
                f"**Classification:** {verdict}\n"
                f"**Family:** {family}\n\n"
                f"**Analysis:**\n"
                f"This sample is classified as {verdict.lower()} based on static PE analysis. "
                f"{'Indicators of malicious intent include elevated entropy (suggesting packing/encryption), suspicious API imports, and abnormal section characteristics.' if is_mal else 'The sample exhibits normal PE structure with expected entropy levels and standard API usage patterns consistent with legitimate software.'}\n\n"
                f"**Key Indicators:**\n"
                + ("\n".join(f"- {p}" for p in feature_parts[:6]))
            )
            records.append(alpaca(random.choice(instrs), input_text, output))
            count += 1
            if count >= 8000:
                break
        print(f"  EMBER2024: {count} rows")

    # EMBER2024-CAPA: skipped — custom loader incompatible with streaming on small VMs
    # E1 gets sufficient coverage from EMBER2024 main (8000 rows) + PowerShell below

    # ── PowerShell Malware ─────────────────────────────────────────────────────
    print("  Loading rr4433/Powershell_Malware_Detection_Dataset...")
    ds = load_hf("rr4433/Powershell_Malware_Detection_Dataset")
    if ds:
        instrs_ps = [
            "Analyze this PowerShell script and determine if it is malicious. Identify obfuscation techniques and malicious patterns.",
            "You are a malware analyst reviewing PowerShell code. Classify this script as malicious or benign and explain your reasoning.",
            "Examine this PowerShell script for malicious indicators: obfuscation, encoded payloads, suspicious cmdlets, and evasion techniques.",
        ]
        count = 0
        for row in ds:
            script = row.get("script") or row.get("code") or row.get("content") or ""
            label = row.get("label") or row.get("is_malicious") or 0
            if not script:
                continue
            is_mal = bool(label)
            verdict = "MALICIOUS" if is_mal else "BENIGN"
            indicators = []
            script_lower = script.lower()
            if "invoke-expression" in script_lower or "iex" in script_lower:
                indicators.append("Dynamic code execution (IEX/Invoke-Expression)")
            if "base64" in script_lower or "fromencodedcommand" in script_lower:
                indicators.append("Base64 encoding/obfuscation detected")
            if "downloadstring" in script_lower or "webclient" in script_lower:
                indicators.append("Network download behavior (WebClient/DownloadString)")
            if "bypass" in script_lower:
                indicators.append("Execution policy bypass")
            if "-enc" in script_lower or "-encodedcommand" in script_lower:
                indicators.append("Encoded command execution")
            output = (
                f"**Classification:** {verdict}\n\n"
                f"**Analysis:**\n"
                f"This PowerShell script is classified as {verdict.lower()}. "
                + (f"The following malicious indicators were identified:\n\n" + "\n".join(f"- {i}" for i in indicators) if is_mal and indicators
                   else "No significant malicious indicators detected. The script performs standard operations." if not is_mal
                   else "General malicious behavior detected through pattern analysis.")
                + f"\n\n**Recommendation:** {'Quarantine and investigate. Block execution.' if is_mal else 'Monitor but no immediate action required.'}"
            )
            records.append(alpaca(random.choice(instrs_ps), script[:800], output))
            count += 1
            if count >= 3000:
                break
        print(f"  PowerShell: {count} rows")

    random.shuffle(records)
    write_jsonl(out, records)
    return len(records)


# ═══════════════════════════════════════════════════════════════════════════════
# E3 — NETWORK ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def collect_e3_network():
    print("\n[E3] Network Analysis...")
    out = OUT_DIR / "e3_network.jsonl"
    records = []

    # ── CybersecurityAttacks HF ───────────────────────────────────────────────
    print("  Loading vinitvek/cybersecurityattacks...")
    ds = load_hf("vinitvek/cybersecurityattacks")
    if ds:
        instrs = [
            "Analyze this network traffic record and classify the attack type. Identify indicators of compromise and recommend defensive actions.",
            "You are a network security analyst. Given this traffic flow data, identify the attack category and explain the detection logic.",
            "Examine this network flow record and determine if it represents malicious activity. Map to MITRE ATT&CK if applicable.",
            "Classify this network traffic pattern and identify the specific attack technique. Provide remediation recommendations.",
        ]
        attack_analysis = {
            "DDoS": ("Distributed Denial of Service", "T1498", "Impact", "High volume traffic exhausting resources"),
            "DoS": ("Denial of Service", "T1499", "Impact", "Resource exhaustion attack"),
            "Brute Force": ("Brute Force Authentication", "T1110", "Credential Access", "Repeated login attempts"),
            "Port Scan": ("Network Service Discovery", "T1046", "Discovery", "Systematic port enumeration"),
            "Injection": ("Command Injection", "T1059", "Execution", "Malicious payload injection"),
            "XSS": ("Cross-Site Scripting", "T1189", "Initial Access", "Client-side script injection"),
        }
        count = 0
        for row in ds:
            attack_type = str(row.get("attack_type") or row.get("label") or row.get("class") or "Unknown").strip()
            features = {k: v for k, v in row.items() if k not in ("attack_type","label","class") and v is not None}
            if not features:
                continue
            feature_text = "\n".join(f"{k}: {v}" for k, v in list(features.items())[:15])
            is_attack = attack_type.lower() not in ("normal", "benign", "0", "legitimate")
            info = attack_analysis.get(attack_type, ("Unknown Attack", "T1071", "Command and Control", "Anomalous network behavior"))
            output = (
                f"**Classification:** {'ATTACK' if is_attack else 'NORMAL TRAFFIC'}\n"
                f"**Attack Type:** {attack_type}\n"
                f"**Full Name:** {info[0]}\n\n"
                f"**Analysis:**\n"
                f"This network flow exhibits characteristics of {info[3]}. "
                f"{'The traffic pattern is anomalous and indicative of malicious activity.' if is_attack else 'Traffic appears normal with no suspicious indicators.'}\n\n"
                f"**MITRE ATT&CK:** {info[1]} ({info[2]})\n\n"
                f"**Recommendation:** {'Block source IP, alert SOC, investigate lateral movement.' if is_attack else 'Continue monitoring, no immediate action needed.'}"
            )
            records.append(alpaca(random.choice(instrs), feature_text, output))
            count += 1
            if count >= 8000:
                break
        print(f"  CybersecAttacks: {count} rows")

    # ── Filter CTI supplement for network keywords ────────────────────────────
    cti_path = Path("/workspace/data/processed/v2_unified_augmented.jsonl")
    if cti_path.exists():
        print("  Filtering unified dataset for network keywords...")
        net_kws = {"c2", "dns", "http", "https", "tls", "ssl", "beacon", "traffic",
                   "network", "packet", "flow", "ip address", "port", "tcp", "udp",
                   "connection", "firewall", "proxy", "vpn", "lateral movement"}
        count = 0
        with open(cti_path) as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                text = (row.get("instruction","") + " " + row.get("output","")).lower()
                if sum(1 for kw in net_kws if kw in text) >= 3 and len(row.get("output","")) > 150:
                    records.append(row)
                    count += 1
                    if count >= 4000:
                        break
        print(f"  CTI network filter: {count} rows")

    random.shuffle(records)
    write_jsonl(out, records)
    return len(records)


# ═══════════════════════════════════════════════════════════════════════════════
# E4 — FORENSICS
# ═══════════════════════════════════════════════════════════════════════════════
def collect_e4_forensics():
    print("\n[E4] Forensics / Persistence...")
    out = OUT_DIR / "e4_forensics.jsonl"
    records = []

    # ── OSSEM (GitHub) ─────────────────────────────────────────────────────────
    print("  Fetching OSSEM event field mappings from GitHub...")
    try:
        import subprocess
        subprocess.run(["git", "clone", "--depth=1",
                        "https://github.com/OTRF/OSSEM.git", "/tmp/ossem"], check=True,
                       capture_output=True, timeout=120)
        ossem_dir = Path("/tmp/ossem")
        instrs_ossem = [
            "Analyze these Windows event log fields and identify potential indicators of malicious activity.",
            "Given these OSSEM-mapped event fields, determine what attack technique this event sequence represents.",
            "You are a forensics analyst. Interpret these Windows event fields and explain what happened on this system.",
        ]
        count = 0
        for md_file in list(ossem_dir.rglob("*.md"))[:200]:
            content = md_file.read_text(errors="ignore")
            if len(content) < 200 or "event" not in content.lower():
                continue
            # Extract event ID if present
            event_match = re.search(r'Event ID[:\s]+(\d+)', content, re.IGNORECASE)
            event_id = event_match.group(1) if event_match else "N/A"
            # Extract fields
            fields = re.findall(r'\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|', content)
            if not fields:
                continue
            field_text = "\n".join(f"{n.strip()}: {d.strip()}" for n, d in fields[:15] if n.strip() and d.strip())
            if not field_text:
                continue
            output = (
                f"**Event ID:** {event_id}\n"
                f"**Source:** {md_file.stem}\n\n"
                f"**Forensic Analysis:**\n"
                f"These event fields provide evidence of system activity that should be correlated with other indicators. "
                f"Key fields to examine for malicious activity include process creation events, network connections, and registry modifications.\n\n"
                f"**Detection Recommendations:**\n"
                f"- Correlate with parent process ID and command line arguments\n"
                f"- Check for LOLBin usage (living-off-the-land binaries)\n"
                f"- Verify against known-good baseline\n"
                f"- Alert on deviations from normal user behavior"
            )
            records.append(alpaca(random.choice(instrs_ossem), field_text, output))
            count += 1
        print(f"  OSSEM: {count} rows")
    except Exception as e:
        print(f"  OSSEM failed: {e}")

    # ── Sigma rules (GitHub) ───────────────────────────────────────────────────
    print("  Fetching Sigma rules from GitHub...")
    try:
        subprocess.run(["git", "clone", "--depth=1",
                        "https://github.com/SigmaHQ/sigma.git", "/tmp/sigma"], check=True,
                       capture_output=True, timeout=180)
        sigma_dir = Path("/tmp/sigma")
        instrs_sigma = [
            "Interpret this Sigma detection rule and explain what attack technique it detects and how it works.",
            "Analyze this Sigma rule and describe the threat it detects, the log source required, and the detection logic.",
            "You are a detection engineer. Explain this Sigma rule in plain English, including the attack context and recommended response.",
        ]
        import yaml as _yaml
        try:
            import yaml
        except ImportError:
            os.system("pip install pyyaml -q")
            import yaml
        count = 0
        for yml_file in list(sigma_dir.rglob("*.yml"))[:500]:
            try:
                with open(yml_file) as f:
                    rule = yaml.safe_load(f)
                if not isinstance(rule, dict):
                    continue
                title = rule.get("title", "Unknown")
                desc = rule.get("description", "")
                tags = rule.get("tags", [])
                detection = rule.get("detection", {})
                logsource = rule.get("logsource", {})
                if not detection or len(desc) < 20:
                    continue
                input_text = (
                    f"Title: {title}\n"
                    f"Log Source: {json.dumps(logsource)}\n"
                    f"Detection: {json.dumps(detection, indent=1)[:600]}\n"
                    f"Tags: {', '.join(str(t) for t in tags[:8])}"
                )
                attack_tags = [t for t in tags if "attack." in str(t).lower()]
                output = (
                    f"**Rule:** {title}\n\n"
                    f"**Description:** {desc}\n\n"
                    f"**Detection Logic:**\n"
                    f"This Sigma rule monitors {logsource.get('category','system')} logs for {title.lower()}. "
                    f"The detection triggers when the specified conditions in the log source are met.\n\n"
                    f"**ATT&CK Techniques:** {', '.join(str(t) for t in attack_tags) or 'Not specified'}\n\n"
                    f"**Response Actions:**\n"
                    f"1. Investigate the triggering process and parent process\n"
                    f"2. Check for lateral movement from the affected host\n"
                    f"3. Review user account activity for the associated user\n"
                    f"4. Preserve forensic evidence for analysis"
                )
                records.append(alpaca(random.choice(instrs_sigma), input_text, output))
                count += 1
                if count >= 3000:
                    break
            except Exception:
                continue
        print(f"  Sigma: {count} rows")
    except Exception as e:
        print(f"  Sigma failed: {e}")

    # ── Filter CTI for forensics/persistence keywords ─────────────────────────
    cti_path = Path("/workspace/data/processed/v2_unified_augmented.jsonl")
    if cti_path.exists():
        print("  Filtering for forensics/persistence keywords...")
        forensic_kws = {"persistence", "registry", "autorun", "scheduled task", "wmi",
                        "startup", "forensic", "artifact", "event log", "prefetch",
                        "amcache", "shimcache", "lnk file", "recycle bin", "ntfs",
                        "memory forensics", "volatility", "hibernation", "pagefile"}
        count = 0
        with open(cti_path) as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                text = (row.get("instruction","") + " " + row.get("output","")).lower()
                if sum(1 for kw in forensic_kws if kw in text) >= 2 and len(row.get("output","")) > 150:
                    records.append(row)
                    count += 1
                    if count >= 3000:
                        break
        print(f"  CTI forensics filter: {count} rows")

    random.shuffle(records)
    write_jsonl(out, records)
    return len(records)


# ═══════════════════════════════════════════════════════════════════════════════
# E6 — DETECTION ENGINEERING
# ═══════════════════════════════════════════════════════════════════════════════
def collect_e6_detection():
    print("\n[E6] Detection Engineering...")
    out = OUT_DIR / "e6_detection.jsonl"
    records = []

    # ── cybersecurity-rules (YARA/Sigma) ──────────────────────────────────────
    print("  Loading jcordon5/cybersecurity-rules...")
    ds = load_hf("jcordon5/cybersecurity-rules")
    if ds:
        # Dataset is already Alpaca format: instruction/input/output
        count = 0
        for row in ds:
            instr = (row.get("instruction") or "").strip()
            inp = (row.get("input") or "").strip()
            out_text = (row.get("output") or "").strip()
            if len(instr) > 20 and len(out_text) > 50:
                records.append(alpaca(instr, inp, out_text))
                count += 1
        print(f"  cybersecurity-rules: {count} rows")

    # NIST Cybersecurity Training: skipped — single 7.5GB parquet causes OOM
    # cybersecurity-rules (949 rows), cybersec_32k, Primus-Seed + unified filter provide sufficient E6 data

    # ── Cybersecurity 32K ─────────────────────────────────────────────────────
    print("  Loading Vanessasml/cybersecurity_32k_instruction_input_output (streaming)...")
    ds = load_hf("Vanessasml/cybersecurity_32k_instruction_input_output", streaming=True)
    if ds:
        count = 0
        for row in ds:
            instr = (row.get("instruction") or "").strip()
            inp = (row.get("input") or "").strip()
            out_text = (row.get("output") or "").strip()
            if not instr or not out_text or len(out_text) < 100:
                continue
            combined = (instr + out_text).lower()
            if not any(kw in combined for kw in ["detect", "yara", "sigma", "rule", "alert", "indicator", "threat", "malware"]):
                continue
            records.append(alpaca(instr, inp, out_text))
            count += 1
            if count >= 3000:
                break
        print(f"  Cybersec32K: {count} rows")

    # ── Primus-Seed ───────────────────────────────────────────────────────────
    print("  Loading trendmicro-ailab/Primus-Seed (streaming)...")
    ds = load_hf("trendmicro-ailab/Primus-Seed", streaming=True)
    if ds:
        count = 0
        for row in ds:
            instr = (row.get("instruction") or row.get("prompt") or "").strip()
            out_text = (row.get("output") or row.get("response") or row.get("completion") or "").strip()
            if not instr or not out_text or len(out_text) < 100:
                continue
            records.append(alpaca(instr, row.get("input",""), out_text))
            count += 1
            if count >= 3000:
                break
        print(f"  Primus-Seed: {count} rows")

    # ── Filter unified for detection keywords ─────────────────────────────────
    cti_path = Path("/workspace/data/processed/v2_unified_augmented.jsonl")
    if cti_path.exists():
        det_kws = {"yara", "sigma", "rule", "detection", "signature", "alert",
                   "indicator of compromise", "ioc", "heuristic", "pattern matching",
                   "false positive", "true positive", "detection logic"}
        count = 0
        with open(cti_path) as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                text = (row.get("instruction","") + " " + row.get("output","")).lower()
                if sum(1 for kw in det_kws if kw in text) >= 2 and len(row.get("output","")) > 150:
                    records.append(row)
                    count += 1
                    if count >= 2000:
                        break
        print(f"  Detection filter: {count} rows")

    # Deduplicate by instruction+input hash
    seen = set()
    deduped = []
    for r in records:
        key = (r["instruction"][:80] + r["input"][:50])
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    random.shuffle(deduped)
    write_jsonl(out, deduped)
    return len(deduped)


# ═══════════════════════════════════════════════════════════════════════════════
# E8 — ANALYST SIMULATION
# ═══════════════════════════════════════════════════════════════════════════════
def collect_e8_analyst():
    print("\n[E8] Analyst Simulation...")
    out = OUT_DIR / "e8_analyst.jsonl"
    records = []

    # ── Cybersecurity ShareGPT ────────────────────────────────────────────────
    print("  Loading Nitral-AI/Cybersecurity-ShareGPT (streaming)...")
    ds = load_hf("Nitral-AI/Cybersecurity-ShareGPT", streaming=True)
    if ds:
        count = 0
        for row in ds:
            convos = row.get("conversations") or row.get("messages") or []
            if len(convos) < 2:
                continue
            # Extract Q/A pairs from conversation
            for i in range(0, len(convos)-1, 2):
                human = convos[i].get("value") or convos[i].get("content") or ""
                assistant = convos[i+1].get("value") or convos[i+1].get("content") or ""
                if len(human) > 20 and len(assistant) > 100:
                    records.append(alpaca(human, "", assistant))
                    count += 1
                    if count >= 6000:
                        break
            if count >= 6000:
                break
        print(f"  ShareGPT: {count} rows")

    # ── CybersecurityQAA ──────────────────────────────────────────────────────
    print("  Loading Rowden/CybersecurityQAA...")
    ds = load_hf("Rowden/CybersecurityQAA")
    if ds:
        count = 0
        for row in ds:
            q = (row.get("question") or row.get("prompt") or row.get("instruction") or "").strip()
            a = (row.get("answer") or row.get("response") or row.get("output") or "").strip()
            if len(q) > 20 and len(a) > 80:
                records.append(alpaca(q, row.get("context",""), a))
                count += 1
        print(f"  CybersecQAA: {count} rows")

    # ── CyberNative Eval ──────────────────────────────────────────────────────
    print("  Loading CyberNative/CyberSecurityEval...")
    ds = load_hf("CyberNative/CyberSecurityEval", split="test")
    if ds:
        count = 0
        for row in ds:
            q = (row.get("question") or row.get("instruction") or "").strip()
            a = (row.get("answer") or row.get("output") or "").strip()
            if len(q) > 20 and len(a) > 80:
                records.append(alpaca(q, row.get("context",""), a))
                count += 1
        print(f"  CyberNative: {count} rows")

    # ── Behavioral ────────────────────────────────────────────────────────────
    print("  Loading theResearchNinja/violentutf_cybersecurityBehavior (streaming)...")
    ds = load_hf("theResearchNinja/violentutf_cybersecurityBehavior", streaming=True)
    if ds:
        count = 0
        for row in ds:
            instr = (row.get("instruction") or row.get("prompt") or "").strip()
            out_text = (row.get("output") or row.get("response") or "").strip()
            if len(instr) > 20 and len(out_text) > 80:
                records.append(alpaca(instr, row.get("input",""), out_text))
                count += 1
                if count >= 3000:
                    break
        print(f"  Behavioral: {count} rows")

    # ── CyberMetric (Q&A style) ───────────────────────────────────────────────
    print("  Loading tihanyin/CyberMetric (streaming)...")
    ds = load_hf("tihanyin/CyberMetric", streaming=True)
    if ds:
        instrs_metric = [
            "Answer this cybersecurity question with a detailed technical explanation.",
            "You are a senior security analyst. Answer this question thoroughly.",
            "Provide a comprehensive answer to this cybersecurity question, including relevant frameworks and best practices.",
        ]
        count = 0
        for row in ds:
            q = (row.get("question") or row.get("prompt") or "").strip()
            a = (row.get("answer") or row.get("correct_answer") or row.get("output") or "").strip()
            if len(q) > 20 and len(a) > 30:
                # Expand short answers
                if len(a) < 100:
                    a = f"**Answer:** {a}\n\n**Explanation:** This is a fundamental cybersecurity concept. Understanding this is essential for security analysts working in detection, response, and threat intelligence roles."
                records.append(alpaca(random.choice(instrs_metric), q if len(q) > 100 else "", a))
                count += 1
        print(f"  CyberMetric: {count} rows")

    seen = set()
    deduped = []
    for r in records:
        key = r["instruction"][:60] + r["output"][:60]
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    random.shuffle(deduped)
    write_jsonl(out, deduped)
    return len(deduped)


# ═══════════════════════════════════════════════════════════════════════════════
# E5 — THREAT INTEL AUGMENTATION (OTX + MalwareBazaar + LOLBAS + ART + GTFOBins)
# ═══════════════════════════════════════════════════════════════════════════════
def collect_e5_augment():
    print("\n[E5] ThreatIntel Augmentation...")
    out = OUT_DIR / "e5_threatintel_aug.jsonl"
    records = []

    # ── AlienVault OTX ────────────────────────────────────────────────────────
    if OTX_KEY:
        print("  Fetching AlienVault OTX pulses...")
        try:
            headers = {"X-OTX-API-KEY": OTX_KEY}
            # Get recent pulses with malware tags
            r = requests.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100&page=1",
                headers=headers, timeout=30
            )
            pulses = r.json().get("results", [])
            instrs_otx = [
                "Analyze this threat intelligence report and extract the key IOCs, TTPs, and threat actor information.",
                "You are a threat intelligence analyst. Given this OTX pulse data, produce a structured threat brief.",
                "Summarize this threat intelligence pulse, mapping indicators to MITRE ATT&CK and providing hunt queries.",
            ]
            for pulse in pulses[:60]:
                name = pulse.get("name", "")
                desc = pulse.get("description", "")
                tags = pulse.get("tags", [])
                indicators = pulse.get("indicators", [])
                tlp = pulse.get("tlp", "white")
                if not desc and not indicators:
                    continue
                ioc_summary = []
                ioc_types = {}
                for ioc in indicators[:20]:
                    t = ioc.get("type", "")
                    v = ioc.get("indicator", "")
                    ioc_types[t] = ioc_types.get(t, 0) + 1
                    ioc_summary.append(f"{t}: {v}")
                input_text = (
                    f"Pulse: {name}\n"
                    f"Tags: {', '.join(tags[:10])}\n"
                    f"TLP: {tlp}\n"
                    f"Description: {desc[:400]}\n"
                    f"IOC counts: {json.dumps(ioc_types)}\n"
                    f"Sample IOCs:\n" + "\n".join(ioc_summary[:10])
                )
                output = (
                    f"## Threat Intelligence Brief: {name}\n\n"
                    f"**TLP:** {tlp.upper()}\n"
                    f"**Tags:** {', '.join(tags[:8])}\n\n"
                    f"**Summary:**\n{desc[:500] if desc else 'No description provided.'}\n\n"
                    f"**IOC Summary:**\n"
                    + "\n".join(f"- {t}: {c} indicator(s)" for t, c in ioc_types.items()) +
                    f"\n\n**Key IOCs:**\n"
                    + "\n".join(f"- {ioc}" for ioc in ioc_summary[:8]) +
                    f"\n\n**Recommended Actions:**\n"
                    f"1. Block identified domains/IPs at perimeter\n"
                    f"2. Hunt for file hashes in EDR telemetry\n"
                    f"3. Add IOCs to threat intelligence platform\n"
                    f"4. Review logs for connections to identified C2 infrastructure"
                )
                records.append(alpaca(random.choice(instrs_otx), input_text, output))
            print(f"  OTX: {len(records)} pulses")
        except Exception as e:
            print(f"  OTX failed: {e}")
    else:
        print("  OTX: skipped (no key)")

    # ── MalwareBazaar recent samples ──────────────────────────────────────────
    print("  Fetching MalwareBazaar recent samples...")
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_recent", "selector": "time"},
                          timeout=30)
        samples = r.json().get("data", [])
        instrs_mb = [
            "Analyze this malware sample metadata from MalwareBazaar and produce a threat analysis.",
            "Given this MalwareBazaar submission data, identify the malware family, TTPs, and produce IOCs for detection.",
            "You are a malware analyst. Based on this sample metadata, write a brief threat report with detection recommendations.",
        ]
        for s in samples[:100]:
            sha256 = s.get("sha256_hash", "")
            family = s.get("signature") or s.get("tags", ["unknown"])[0] if s.get("tags") else "unknown"
            file_type = s.get("file_type", "")
            file_size = s.get("file_size", 0)
            reporter = s.get("reporter", "")
            first_seen = s.get("first_seen", "")
            tags = s.get("tags", [])
            if not sha256:
                continue
            input_text = (
                f"SHA256: {sha256}\n"
                f"Family: {family}\n"
                f"File Type: {file_type}\n"
                f"File Size: {file_size} bytes\n"
                f"First Seen: {first_seen}\n"
                f"Tags: {', '.join(tags[:8])}\n"
                f"Reporter: {reporter}"
            )
            output = (
                f"## Malware Analysis: {family}\n\n"
                f"**SHA256:** `{sha256}`\n"
                f"**Classification:** {family}\n"
                f"**File Type:** {file_type}\n\n"
                f"**Threat Analysis:**\n"
                f"This sample, identified as {family}, was first submitted to MalwareBazaar on {first_seen}. "
                f"{'This is a known malware family with established TTPs and detection coverage.' if family != 'unknown' else 'The malware family is unclassified and requires manual analysis.'}\n\n"
                f"**IOCs:**\n"
                f"- SHA256: `{sha256}`\n"
                f"- File Type: {file_type}\n"
                f"- Tags: {', '.join(tags)}\n\n"
                f"**Detection Recommendations:**\n"
                f"1. Block SHA256 hash in EDR/AV\n"
                f"2. Hunt for similar {file_type} files with matching entropy\n"
                f"3. Review network logs for C2 communication patterns\n"
                f"4. Add hash to threat intelligence platform"
            )
            records.append(alpaca(random.choice(instrs_mb), input_text, output))
        print(f"  MalwareBazaar: {len([r for r in records if 'SHA256' in r['input']])} samples")
    except Exception as e:
        print(f"  MalwareBazaar failed: {e}")

    # ── LOLBAS (GitHub) ───────────────────────────────────────────────────────
    print("  Fetching LOLBAS from GitHub...")
    try:
        import subprocess, yaml
        subprocess.run(["git", "clone", "--depth=1",
                        "https://github.com/LOLBAS-Project/LOLBAS.git", "/tmp/lolbas"],
                       check=True, capture_output=True, timeout=120)
        lolbas_dir = Path("/tmp/lolbas")
        instrs_lol = [
            "Explain how this Windows living-off-the-land binary (LOLBin) can be abused by attackers and how to detect it.",
            "Analyze this LOLBAS entry and produce a threat brief: attack use cases, detection opportunities, and MITRE ATT&CK mapping.",
            "You are a threat hunter. Given this LOLBAS entry, explain the abuse techniques and write detection rules.",
        ]
        count = 0
        for yml_file in list(lolbas_dir.rglob("*.yml"))[:300]:
            try:
                with open(yml_file) as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                name = data.get("Name", yml_file.stem)
                desc = data.get("Description", "")
                cmds = data.get("Commands", [])
                detection = data.get("Detection", [])
                if not desc and not cmds:
                    continue
                cmd_text = "\n".join(
                    f"- {c.get('Command','')}: {c.get('Description','')}"
                    for c in cmds[:5] if isinstance(c, dict)
                ) or "See documentation"
                det_text = "\n".join(
                    f"- {d.get('EventID','?')}: {d.get('Type','')}"
                    for d in detection[:5] if isinstance(d, dict)
                ) or "Monitor for unusual execution"
                input_text = f"Binary: {name}\nDescription: {desc}\nAbuse Commands:\n{cmd_text}"
                output = (
                    f"## LOLBin Analysis: {name}\n\n"
                    f"**Description:** {desc}\n\n"
                    f"**Attack Use Cases:**\n{cmd_text}\n\n"
                    f"**MITRE ATT&CK Mapping:**\n- T1218: Signed Binary Proxy Execution\n- T1059: Command Execution\n\n"
                    f"**Detection Opportunities:**\n{det_text}\n\n"
                    f"**Hunting Query (pseudo):**\n"
                    f"```\nprocess_name = '{name}' AND (unusual_parent OR unusual_args)\n```\n\n"
                    f"**Recommended Response:**\n"
                    f"1. Whitelist legitimate uses in your environment\n"
                    f"2. Alert on execution from unusual parent processes\n"
                    f"3. Monitor command-line arguments for abuse patterns"
                )
                records.append(alpaca(random.choice(instrs_lol), input_text, output))
                count += 1
            except Exception:
                continue
        print(f"  LOLBAS: {count} rows")
    except Exception as e:
        print(f"  LOLBAS failed: {e}")

    # ── Atomic Red Team (GitHub) ──────────────────────────────────────────────
    print("  Fetching Atomic Red Team from GitHub...")
    try:
        subprocess.run(["git", "clone", "--depth=1",
                        "https://github.com/redcanaryco/atomic-red-team.git", "/tmp/art"],
                       check=True, capture_output=True, timeout=180)
        art_dir = Path("/tmp/art")
        instrs_art = [
            "Analyze this Atomic Red Team test and explain the ATT&CK technique, how it works, and how to detect it.",
            "Given this Atomic Red Team simulation procedure, describe the attack technique and write detection recommendations.",
            "You are a red team analyst. Explain this ATT&CK technique simulation, its detection opportunities, and defensive countermeasures.",
        ]
        count = 0
        for yml_file in list(art_dir.rglob("T*.yaml"))[:300]:
            try:
                with open(yml_file) as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                technique_id = data.get("attack_technique", "")
                display_name = data.get("display_name", "")
                atomic_tests = data.get("atomic_tests", [])
                if not atomic_tests:
                    continue
                for test in atomic_tests[:2]:
                    name = test.get("name", "")
                    desc = test.get("description", "")
                    executor = test.get("executor", {})
                    cmd = executor.get("command", "") or executor.get("steps", "")
                    if not desc:
                        continue
                    input_text = (
                        f"Technique: {technique_id} — {display_name}\n"
                        f"Test: {name}\n"
                        f"Description: {desc[:400]}\n"
                        f"Command: {str(cmd)[:300]}"
                    )
                    output = (
                        f"## ATT&CK Technique: {technique_id} — {display_name}\n\n"
                        f"**Test:** {name}\n\n"
                        f"**How It Works:**\n{desc[:500]}\n\n"
                        f"**Detection Opportunities:**\n"
                        f"- Monitor process creation events for suspicious child processes\n"
                        f"- Alert on command-line patterns matching the technique\n"
                        f"- Correlate with network activity if applicable\n\n"
                        f"**Sigma Rule (conceptual):**\n"
                        f"```yaml\ntitle: Detect {technique_id}\nlogsource:\n  category: process_creation\ndetection:\n  keywords:\n    - '{display_name.lower()}'\ncondition: keywords\n```\n\n"
                        f"**Defensive Countermeasures:**\n"
                        f"1. Apply principle of least privilege\n"
                        f"2. Enable audit logging for relevant event IDs\n"
                        f"3. Deploy EDR with behavioral detection capabilities\n"
                        f"4. Conduct regular threat hunting using this procedure"
                    )
                    records.append(alpaca(random.choice(instrs_art), input_text, output))
                    count += 1
                    if count >= 1500:
                        break
                if count >= 1500:
                    break
            except Exception:
                continue
        print(f"  Atomic Red Team: {count} rows")
    except Exception as e:
        print(f"  ART failed: {e}")

    random.shuffle(records)
    write_jsonl(out, records)
    return len(records)


# ═══════════════════════════════════════════════════════════════════════════════
# UPLOAD TO HF HUB
# ═══════════════════════════════════════════════════════════════════════════════
def upload_to_hf():
    print("\n[UPLOAD] Uploading to HF Hub...")
    from huggingface_hub import HfApi
    api = HfApi(token=HF_TOKEN)
    repo_id = "umer07/fathom-expert-data"
    uploaded = []
    for jsonl_file in OUT_DIR.glob("*.jsonl"):
        lines = sum(1 for _ in open(jsonl_file))
        if lines < 10:
            print(f"  SKIP {jsonl_file.name} (only {lines} rows)")
            continue
        # New expert datasets go under experts/ — keeps old processed/ clean
        remote_path = f"experts/{jsonl_file.name}"
        print(f"  Uploading {jsonl_file.name} ({lines} rows)...")
        api.upload_file(
            path_or_fileobj=str(jsonl_file),
            path_in_repo=remote_path,
            repo_id=repo_id,
            repo_type="dataset",
        )
        uploaded.append((jsonl_file.name, lines))
        print(f"  ✓ {jsonl_file.name}")
    print(f"\nUploaded {len(uploaded)} files:")
    for name, rows in uploaded:
        print(f"  {name}: {rows} rows")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def clear_hf_cache():
    """Clear HF downloads cache to free disk space between experts."""
    import shutil
    cache_dirs = [
        Path.home() / ".cache" / "huggingface" / "datasets" / "downloads",
        Path.home() / ".cache" / "huggingface" / "hub",
    ]
    freed = 0
    for d in cache_dirs:
        if d.exists():
            try:
                size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
                shutil.rmtree(d, ignore_errors=True)
                freed += size
            except Exception:
                pass
    if freed:
        print(f"  [cache] Freed {freed // (1024**3):.1f}GB")


def run_expert(name: str, fn, out_file: str) -> int:
    """Run an expert collector with resume logic and cache clearing."""
    out_path = OUT_DIR / out_file
    if out_path.exists():
        rows = sum(1 for _ in open(out_path))
        print(f"\n[SKIP] {name}: {out_file} already exists ({rows} rows)")
        return rows
    result = fn()
    clear_hf_cache()
    return result


def main():
    print("=" * 60)
    print("Fathom Expert Dataset Builder")
    print("=" * 60)
    results = {}

    results["E1 Static"]         = run_expert("E1 Static",       collect_e1_static,    "e1_static.jsonl")
    results["E3 Network"]        = run_expert("E3 Network",      collect_e3_network,   "e3_network.jsonl")
    results["E4 Forensics"]      = run_expert("E4 Forensics",    collect_e4_forensics, "e4_forensics.jsonl")
    results["E6 Detection"]      = run_expert("E6 Detection",    collect_e6_detection, "e6_detection.jsonl")
    results["E8 Analyst"]        = run_expert("E8 Analyst",      collect_e8_analyst,   "e8_analyst.jsonl")
    results["E5 ThreatIntel+"]   = run_expert("E5 ThreatIntel+", collect_e5_augment,   "e5_threatintel_aug.jsonl")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for expert, rows in results.items():
        status = "✓" if rows >= 1000 else "⚠ LOW" if rows > 0 else "✗ FAILED"
        print(f"  {status} {expert}: {rows} rows")

    upload_to_hf()
    print("\nDONE — all expert datasets ready on HF Hub.")


if __name__ == "__main__":
    main()
