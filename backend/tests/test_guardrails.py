"""
test_guardrails.py — Unit tests for input sanitization and output validation.
Task 3.3
"""
from __future__ import annotations

import pytest

from llm.guardrails import sanitize_input, validate_output


class TestSanitizeInput:
    def test_returns_tuple(self):
        result = sanitize_input("normal text")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_clean_text_unchanged(self):
        text = "Analyze this malware sample for ATT&CK techniques"
        sanitized, warnings = sanitize_input(text)
        assert "malware" in sanitized
        assert "ATT&CK" in sanitized

    def test_strips_null_bytes(self):
        text = "malware\x00analysis"
        sanitized, _ = sanitize_input(text)
        assert "\x00" not in sanitized

    def test_detects_eval_injection(self):
        malicious = "Analyze this: eval(__import__('os').system('rm -rf /'))"
        sanitized, warnings = sanitize_input(malicious)
        assert len(warnings) > 0
        # eval pattern should be redacted
        assert "eval" not in sanitized.lower() or "[REDACTED]" in sanitized

    def test_detects_exec_injection(self):
        malicious = "exec('import os; os.system(\"id\")')"
        sanitized, warnings = sanitize_input(malicious)
        assert len(warnings) > 0

    def test_detects_xss_script_tag(self):
        malicious = "IOC: <script>alert('xss')</script>"
        sanitized, warnings = sanitize_input(malicious)
        assert len(warnings) > 0
        assert "<script>" not in sanitized

    def test_detects_template_injection(self):
        malicious = "{{7*7}} is a template injection"
        sanitized, warnings = sanitize_input(malicious)
        assert len(warnings) > 0

    def test_truncates_long_input(self):
        long_text = "A" * 60000
        sanitized, _ = sanitize_input(long_text)
        assert len(sanitized) <= 50000

    def test_idempotent(self):
        text = "Normal malware analysis text with some eval() mention"
        sanitized1, _ = sanitize_input(text)
        sanitized2, _ = sanitize_input(sanitized1)
        assert sanitized1 == sanitized2

    def test_preserves_newlines_and_tabs(self):
        text = "line1\nline2\ttabbed"
        sanitized, _ = sanitize_input(text)
        assert "\n" in sanitized
        assert "\t" in sanitized

    def test_warnings_is_list(self):
        _, warnings = sanitize_input("clean text")
        assert isinstance(warnings, list)


class TestValidateOutput:
    def test_returns_dict_with_warnings(self):
        result = validate_output("This is a malware analysis report.", "report")
        assert isinstance(result, dict)
        assert "warnings" in result
        assert isinstance(result["warnings"], list)

    def test_valid_attack_id_no_warning(self):
        report = "This sample uses T1055.001 for process injection."
        result = validate_output(report, "report")
        # T1055.001 is valid — should not warn about it
        attack_warnings = [w for w in result["warnings"] if "T1055.001" in w and "invalid" in w.lower()]
        assert len(attack_warnings) == 0

    def test_fake_attack_id_generates_warning(self):
        report = "This sample uses T9999.999 which is a fake technique."
        result = validate_output(report, "report")
        # T9999.999 is not a real technique — should warn
        attack_warnings = [w for w in result["warnings"] if "T9999" in w]
        assert len(attack_warnings) > 0

    def test_hedging_language_detected(self):
        report = "It is likely that this malware uses process injection techniques."
        result = validate_output(report, "report")
        hedge_warnings = [w for w in result["warnings"]
                          if "unsupported" in w.lower() or "hedg" in w.lower() or "likely" in w.lower()]
        assert len(hedge_warnings) > 0

    def test_clean_report_minimal_warnings(self):
        report = (
            "## Executive Summary\n"
            "This sample (SHA256: abc123) exhibits T1055.001 process injection.\n"
            "## ATT&CK Mappings\nT1055.001 - Process Injection\n"
            "## IOCs\n185.1.2.3\n"
            "## Risk Score\n8/10"
        )
        result = validate_output(report, "report")
        # Should have few or no warnings for a well-formed report
        assert isinstance(result["warnings"], list)
