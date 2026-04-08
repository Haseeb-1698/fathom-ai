#!/usr/bin/env python3
"""
demo_end_to_end.py — Run Fathom end-to-end demo scenarios.

Tests the full pipeline: evidence → router → adapter → RAG → LLM → output.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


DEMO_SCENARIOS = [
    {
        "name": "1. Dynamic Analysis Query",
        "query": "Analyze this API sequence: CreateFileW, WriteFile, CreateProcessW, RegSetValueExW targeting HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "expected_domain": "E2_dynamic",
    },
    {
        "name": "2. Report Generation",
        "query": "Generate a comprehensive malware analysis report for an Emotet trojan sample that performs process injection and establishes C2 communication",
        "expected_domain": "E7_reports",
    },
    {
        "name": "3. ATT&CK Mapping",
        "query": "Map the following behaviors to ATT&CK techniques: DLL side-loading, scheduled task persistence, DNS tunneling for exfiltration",
        "expected_domain": "E5_threatintel",
    },
    {
        "name": "4. Static Analysis",
        "query": "Analyze this PE file: UPX packed, .text section entropy 7.98, imports kernel32.dll(VirtualAlloc, WriteProcessMemory, CreateRemoteThread)",
        "expected_domain": "E1_static",
    },
    {
        "name": "5. Threat Intel Query",
        "query": "What is known about APT28 Fancy Bear and their use of Cobalt Strike beacons targeting government networks?",
        "expected_domain": "E5_threatintel",
    },
    {
        "name": "6. Detection Rule",
        "query": "Write a YARA rule to detect Emotet packed executables based on their known string patterns and PE characteristics",
        "expected_domain": "E6_detection",
    },
    {
        "name": "7. Remediation",
        "query": "An endpoint has been compromised with ransomware that has encrypted user files and established persistence. What incident response steps should be taken?",
        "expected_domain": "E8_remediation",
    },
    {
        "name": "8. Cross-sample Correlation",
        "query": "What malware families use process injection (T1055) with CreateRemoteThread for defense evasion?",
        "expected_domain": "E2_dynamic",
    },
]


def run_routing_demo():
    """Test domain routing without LLM generation."""
    from router.domain_classifier import DomainRouter
    from config import DOMAINS

    router = DomainRouter()
    print("=" * 70)
    print("  ROUTING DEMO (no LLM required)")
    print("=" * 70)

    correct = 0
    for scenario in DEMO_SCENARIOS:
        domain_id, confidence, scores = router.route(scenario["query"])
        domain_name = DOMAINS.get(domain_id, {}).get("name", domain_id)
        match = "OK" if domain_id == scenario["expected_domain"] else "MISMATCH"
        if match == "OK":
            correct += 1

        print(f"\n{scenario['name']}")
        print(f"  Query: {scenario['query'][:80]}...")
        print(f"  Routed to: {domain_name} ({domain_id})")
        print(f"  Confidence: {confidence:.3f}")
        print(f"  Expected: {scenario['expected_domain']} → {match}")

    print(f"\n{'=' * 70}")
    print(f"  Routing accuracy: {correct}/{len(DEMO_SCENARIOS)}")
    print(f"{'=' * 70}")


def run_full_demo():
    """Test full pipeline including LLM generation."""
    from llm.inference import generate

    print("=" * 70)
    print("  FULL PIPELINE DEMO (requires GPU + model loaded)")
    print("=" * 70)

    for scenario in DEMO_SCENARIOS:
        print(f"\n{'─' * 60}")
        print(f"  {scenario['name']}")
        print(f"{'─' * 60}")
        print(f"Query: {scenario['query'][:100]}...")

        try:
            result = generate(query=scenario["query"])
            print(f"Domain: {result.domain_name} (confidence: {result.confidence:.3f})")
            print(f"Adapter: {result.adapter_used}")
            print(f"Response ({result.tokens_generated} tokens):")
            print(result.text[:500])
            if len(result.text) > 500:
                print(f"... ({len(result.text) - 500} more chars)")
        except Exception as e:
            print(f"ERROR: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["routing", "full"], default="routing",
                        help="routing: test routing only; full: test with LLM generation")
    args = parser.parse_args()

    if args.mode == "routing":
        run_routing_demo()
    else:
        run_full_demo()


if __name__ == "__main__":
    main()
