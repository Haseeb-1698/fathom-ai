"""
guardrails.py — Input sanitization and output validation for Fathom.

Based on Implementation Plan v2 PromptSanitizer + ResponseValidator.
Protects against prompt injection from malware artifacts, validates
LLM output quality, and checks for hallucination indicators.

NOTE: Does not depend on the 'guardrails' pip package (Guardrails AI).
All checks are implemented with stdlib regex for zero external deps.
"""

from __future__ import annotations

import re
from typing import Any


# ═════════════════════════════════════════════════════════════════════════
# INPUT SANITIZATION (PromptSanitizer from Implementation Plan v2)
# ═════════════════════════════════════════════════════════════════════════

# Malware-specific injection patterns — these are commonly found in
# malware strings, sandbox artifacts, and adversarial report payloads.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior",
    r"you\s+are\s+now\s+(?:a|an)\s+",
    r"system\s*:\s*",
    r"<\s*script\s*>",               # XSS in artifact strings
    r"eval\s*\(",                     # code injection
    r"exec\s*\(",                     # code injection
    r"\{\{.*?\}\}",                   # template injection (Jinja/Mustache)
    r"\\x[0-9a-fA-F]{2}",            # hex escape sequences in malware strings
]

_injection_re = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

# Control characters to strip (null bytes, BEL, BS, etc.)
# Preserves \t (0x09), \n (0x0a), \r (0x0d)
_control_chars_re = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_INPUT_LENGTH = 50_000


def sanitize_input(text: str) -> tuple[str, list[str]]:
    """
    Sanitize user input / malware artifact text.

    Returns (cleaned_text, warnings).
    Warnings include blocked pattern details for audit logging.
    """
    warnings: list[str] = []
    blocked: list[str] = []

    # Step 1: Check for injection patterns
    for match in _injection_re.finditer(text):
        blocked.append(match.group())
    if blocked:
        text = _injection_re.sub("[REDACTED]", text)
        warnings.append(f"Prompt injection patterns blocked: {blocked[:5]}")

    # Step 2: Truncate excessively long inputs (malware strings can be huge)
    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
        warnings.append(f"Input truncated to {MAX_INPUT_LENGTH} characters")

    # Step 3: Strip control characters (preserve tabs, newlines, carriage returns)
    cleaned = _control_chars_re.sub("", text)
    if len(cleaned) != len(text):
        warnings.append("Control characters removed from input")
        text = cleaned

    return text, warnings


def sanitize_malware_report(report: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively sanitize an entire malware analysis report dict.

    Walks all string values, sanitizes them, and returns a cleaned copy.
    Used before passing evidence JSON to the LLM context.
    """
    sanitized: dict[str, Any] = {}

    for key, value in report.items():
        if isinstance(value, str):
            cleaned, _ = sanitize_input(value)
            sanitized[key] = cleaned
        elif isinstance(value, dict):
            sanitized[key] = sanitize_malware_report(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_input(item)[0] if isinstance(item, str) else item
                for item in value
            ]
        else:
            sanitized[key] = value

    return sanitized


# ═════════════════════════════════════════════════════════════════════════
# OUTPUT VALIDATION (ResponseValidator from Implementation Plan v2)
# ═════════════════════════════════════════════════════════════════════════

# ATT&CK technique ID pattern
ATTCK_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

# Forbidden content patterns — LLM artifacts that degrade report quality
FORBIDDEN_PATTERNS = [
    r"I cannot|I'm unable|I don't have access",   # refusals
    r"As an AI|As a language model",               # AI self-reference
    r"I apologize|Sorry,?\s+but",                  # unnecessary apologies
]
_forbidden_re = re.compile("|".join(FORBIDDEN_PATTERNS), re.IGNORECASE)

# Hallucination indicators — overconfidence without evidence
HALLUCINATION_PATTERNS = [
    r"\bdefinitely\b|\bcertainly\b|\b100\s*%",     # overconfidence
    r"\ball malware\b|\bevery sample\b|\balways\b", # overgeneralization
]
_hallucination_res = [re.compile(p, re.IGNORECASE) for p in HALLUCINATION_PATTERNS]

# Required sections for report-type outputs
REQUIRED_REPORT_SECTIONS = [
    "Executive Summary",
    "MITRE ATT&CK",
    "Risk",
]

# LLM artifact prefixes to strip
_artifact_prefixes = [
    re.compile(r"^\s*Sure[,!]?\s*", re.IGNORECASE),
    re.compile(r"^\s*Here is\s*", re.IGNORECASE),
    re.compile(r"^\s*Of course[,!]?\s*", re.IGNORECASE),
    re.compile(r"^\s*Certainly[,!]?\s*", re.IGNORECASE),
]


def validate_attck_ids(text: str, valid_ids: set[str] | None = None) -> list[str]:
    """
    Check that ATT&CK technique IDs mentioned in output are valid.
    Returns list of invalid IDs found.
    """
    found_ids = ATTCK_PATTERN.findall(text)
    if valid_ids is None:
        return []
    return [tid for tid in found_ids if tid not in valid_ids]


def validate_output(
    text: str,
    response_type: str = "general",
    valid_attck_ids: set[str] | None = None,
) -> dict:
    """
    Validate LLM output quality.

    Args:
        text: The LLM response to validate.
        response_type: "report" enables section/ATT&CK checks, "general" is relaxed.
        valid_attck_ids: Optional set of valid technique IDs for hallucination check.

    Returns dict with:
        valid: bool
        cleaned: str (cleaned response text)
        warnings: list[str]
        length: int
    """
    warnings: list[str] = []

    # Check for empty/too short output
    if len(text.strip()) < 10:
        return {
            "valid": False,
            "cleaned": text,
            "warnings": ["Output too short"],
            "length": len(text),
        }

    # Check for forbidden patterns (AI self-reference, refusals)
    forbidden_matches = _forbidden_re.findall(text)
    if forbidden_matches:
        warnings.append(f"Contains forbidden patterns: {forbidden_matches[:3]}")

    # Check for hallucination indicators (flag if excessive)
    for pattern_re in _hallucination_res:
        matches = pattern_re.findall(text)
        if len(matches) > 3:
            warnings.append(f"Potential hallucination indicator: {pattern_re.pattern}")

    # Check for repetition (same phrase repeated many times)
    words = text.split()
    if len(words) > 20:
        last_chunk = " ".join(words[-10:])
        if text.count(last_chunk) > 3:
            warnings.append("Repetitive output detected")

    # Report-specific checks
    if response_type == "report":
        # Check required sections
        text_lower = text.lower()
        for section in REQUIRED_REPORT_SECTIONS:
            if section.lower() not in text_lower:
                warnings.append(f"Missing required section: {section}")

        # Check for ATT&CK technique presence
        techniques = ATTCK_PATTERN.findall(text)
        if not techniques:
            warnings.append("No ATT&CK technique IDs found in report")

    # Validate ATT&CK IDs against known-good set
    if valid_attck_ids:
        invalid = validate_attck_ids(text, valid_attck_ids)
        if invalid:
            warnings.append(f"Invalid ATT&CK IDs: {', '.join(invalid[:5])}")

    # Clean the response
    cleaned = _clean_response(text)

    return {
        "valid": len(warnings) == 0,
        "cleaned": cleaned,
        "warnings": warnings,
        "length": len(cleaned),
    }


def _clean_response(text: str) -> str:
    """Clean and normalize LLM response."""
    # Remove LLM artifact prefixes
    for prefix_re in _artifact_prefixes:
        text = prefix_re.sub("", text)

    # Remove excessive whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" {2,}", " ", text)

    return text.strip()
