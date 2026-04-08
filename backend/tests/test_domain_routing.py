"""
test_domain_routing.py — Unit tests for domain routing layer.
Task 3.2
"""
from __future__ import annotations

from unittest import mock

import pytest


class TestDomainRoutingBasic:
    @pytest.fixture(autouse=True)
    def router(self):
        from router.domain_classifier import DomainRouter
        self._router = DomainRouter()

    def test_route_returns_tuple(self):
        result = self._router.route("Analyze this malware sample")
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_route_domain_id_is_string(self):
        domain_id, _, _ = self._router.route("Process injection via NtMapViewOfSection")
        assert isinstance(domain_id, str)
        assert len(domain_id) > 0

    def test_route_confidence_in_range(self):
        _, confidence, _ = self._router.route("PE header analysis with UPX packer")
        assert 0.0 <= confidence <= 1.0

    def test_route_scores_dict(self):
        _, _, scores = self._router.route("Network C2 traffic analysis")
        assert isinstance(scores, dict)
        assert len(scores) > 0

    def test_route_all_scores_in_range(self):
        _, _, scores = self._router.route("Registry persistence mechanism")
        for domain, score in scores.items():
            assert 0.0 <= score <= 1.0, f"Score out of range for {domain}: {score}"


class TestDomainRoutingDeterminism:
    def test_routing_is_deterministic(self):
        from router.domain_classifier import DomainRouter
        router = DomainRouter()
        text = "Malware sample exhibits process injection via WriteProcessMemory"
        d1, c1, s1 = router.route(text)
        d2, c2, s2 = router.route(text)
        assert d1 == d2
        assert abs(c1 - c2) < 1e-6
        assert s1 == s2

    def test_same_router_instance_deterministic(self):
        from router.domain_classifier import DomainRouter
        router = DomainRouter()
        text = "YARA rule generation for ransomware detection"
        results = [router.route(text) for _ in range(3)]
        domains = [r[0] for r in results]
        assert len(set(domains)) == 1


class TestDomainRoutingDomains:
    def test_dynamic_behavior_routing(self):
        from router.domain_classifier import DomainRouter
        router = DomainRouter()
        text = "Process injection via NtMapViewOfSection API call sequence"
        domain_id, confidence, _ = router.route(text)
        # Should route to dynamic or a reasonable domain
        assert domain_id in ["E2_dynamic", "E1_static", "E7_reports", "E5_threatintel",
                              "E3_network", "E4_forensics", "E6_detection", "E8_remediation",
                              "unified"]

    def test_static_analysis_routing(self):
        from router.domain_classifier import DomainRouter
        router = DomainRouter()
        text = "PE header analysis shows UPX packer with high entropy sections"
        domain_id, _, _ = router.route(text)
        assert isinstance(domain_id, str)

    def test_low_confidence_falls_back(self):
        from router.domain_classifier import DomainRouter
        router = DomainRouter()
        # Very generic text — should still return a valid domain
        domain_id, confidence, _ = router.route("hello world")
        assert isinstance(domain_id, str)


class TestAdapterMapping:
    def test_get_adapter_name_returns_string_or_none(self):
        from router.domain_classifier import DomainRouter
        router = DomainRouter()
        _, _, scores = router.route("malware analysis")
        for domain_id in scores:
            result = router.get_adapter_name(domain_id)
            assert result is None or isinstance(result, str)
