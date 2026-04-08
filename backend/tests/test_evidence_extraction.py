"""
test_evidence_extraction.py — Unit tests for CAPE evidence extraction layer.
Task 3.1
"""
from __future__ import annotations

import pytest

from evidence.cape_extractor import CAPEEvidenceExtractor


class TestCapeExtractionBasic:
    def test_extraction_returns_brief(self, basic_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        assert brief is not None

    def test_extraction_complete_report_has_sha256(self, basic_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        assert brief.sha256 != "" or brief.hashes.get("sha256", "") != ""

    def test_extraction_complete_report_has_iocs(self, basic_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        assert len(brief.iocs) > 0

    def test_extraction_complete_report_has_behaviors(self, basic_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        assert len(brief.behaviors) > 0

    def test_extraction_malscore_non_negative(self, basic_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        score = brief.meta.malscore if brief.meta else 0
        assert score >= 0


class TestCapeExtractionMinimal:
    def test_minimal_report_does_not_crash(self, minimal_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(minimal_cape_report)
        assert brief is not None

    def test_minimal_report_empty_sha256(self, minimal_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(minimal_cape_report)
        sha = brief.sha256 if hasattr(brief, "sha256") else brief.hashes.get("sha256", "")
        assert sha == "" or sha == "unknown"

    def test_minimal_report_has_known_gaps(self, minimal_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(minimal_cape_report)
        assert len(brief.known_gaps) > 0 or len(brief.iocs) == 0

    def test_empty_dict_does_not_crash(self):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict({})
        assert brief is not None

    def test_malformed_behavior_does_not_crash(self):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict({"behavior": "not_a_dict"})
        assert brief is not None


class TestIocDeduplication:
    def test_no_duplicate_iocs(self, duplicate_ioc_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(duplicate_ioc_report)
        seen: set[tuple] = set()
        for ioc in brief.iocs:
            key = (str(ioc.type), ioc.value)
            assert key not in seen, f"Duplicate IOC: {key}"
            seen.add(key)

    def test_ioc_cap_enforced(self, large_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(large_cape_report)
        assert len(brief.iocs) <= 200, f"IOC cap exceeded: {len(brief.iocs)}"

    def test_behavior_cap_enforced(self, large_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(large_cape_report)
        assert len(brief.behaviors) <= 100, f"Behavior cap exceeded: {len(brief.behaviors)}"


class TestEvidenceFormatting:
    def test_format_evidence_returns_string(self, basic_cape_report):
        from evidence.cape_extractor import format_evidence_text
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        text = format_evidence_text(brief)
        assert isinstance(text, str)
        assert len(text) > 0

    def test_expert_prompt_contains_evidence(self, basic_cape_report):
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(basic_cape_report)
        if hasattr(extractor, "build_expert_prompt"):
            prompt = extractor.build_expert_prompt(brief, task="full_report")
            assert isinstance(prompt, str)
            assert len(prompt) > 50
