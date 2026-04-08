"""
test_properties.py — Property-based tests using Hypothesis.
Task 3.4
"""
from __future__ import annotations

import pytest

try:
    from hypothesis import given, settings, strategies as st, HealthCheck
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not HYPOTHESIS_AVAILABLE, reason="hypothesis not installed"
)


# ── Evidence extraction properties ───────────────────────────────────────────

@given(st.dictionaries(
    keys=st.text(min_size=1, max_size=20),
    values=st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=50),
        lambda children: st.lists(children, max_size=5) | st.dictionaries(
            st.text(max_size=10), children, max_size=5
        ),
        max_leaves=20,
    ),
    max_size=10,
))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_extraction_never_crashes(report_dict):
    """Property: extraction never raises on arbitrary dict input."""
    from evidence.cape_extractor import CAPEEvidenceExtractor
    try:
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(report_dict)
        # Caps must always be respected
        assert len(brief.iocs) <= 200
        assert len(brief.behaviors) <= 100
    except (ValueError, TypeError):
        pass  # Expected for structurally invalid input


@given(st.text(min_size=10, max_size=500))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_routing_always_returns_valid_domain(text):
    """Property: routing always returns a non-empty domain string."""
    from router.domain_classifier import DomainRouter
    router = DomainRouter()
    domain_id, confidence, scores = router.route(text)
    assert isinstance(domain_id, str)
    assert len(domain_id) > 0
    assert 0.0 <= confidence <= 1.0


@given(st.text(min_size=10, max_size=500))
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
def test_routing_deterministic(text):
    """Property: routing is deterministic for the same input."""
    from router.domain_classifier import DomainRouter
    router = DomainRouter()
    d1, c1, s1 = router.route(text)
    d2, c2, s2 = router.route(text)
    assert d1 == d2
    assert abs(c1 - c2) < 1e-6


@given(st.text(max_size=200))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_sanitization_idempotent(text):
    """Property: sanitize(sanitize(x)) == sanitize(x)."""
    from llm.guardrails import sanitize_input
    sanitized1, _ = sanitize_input(text)
    sanitized2, _ = sanitize_input(sanitized1)
    assert sanitized1 == sanitized2


@given(st.text(max_size=200))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_sanitization_never_crashes(text):
    """Property: sanitize_input never raises."""
    from llm.guardrails import sanitize_input
    result = sanitize_input(text)
    assert isinstance(result, tuple)
    assert len(result) == 2


@given(st.text(max_size=200))
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
def test_sanitization_output_within_limit(text):
    """Property: sanitized output never exceeds 50K chars."""
    from llm.guardrails import sanitize_input
    sanitized, _ = sanitize_input(text)
    assert len(sanitized) <= 50000


@given(st.lists(
    st.tuples(
        st.sampled_from(["ip", "domain", "url", "hash", "email", "mutex"]),
        st.text(min_size=3, max_size=50),
    ),
    max_size=50,
))
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
def test_ioc_deduplication_correct(ioc_pairs):
    """Property: no duplicate (type, value) IOC pairs after extraction."""
    from evidence.cape_extractor import CAPEEvidenceExtractor
    # Build a minimal report with duplicate network hosts
    hosts = [v for t, v in ioc_pairs if t == "ip"]
    report = {
        "info": {"id": 1},
        "behavior": {},
        "network": {"hosts": hosts * 3, "domains": [], "http": [], "dns": []},
    }
    extractor = CAPEEvidenceExtractor()
    brief = extractor.from_report_dict(report)
    seen: set[tuple] = set()
    for ioc in brief.iocs:
        key = (str(ioc.type), ioc.value)
        assert key not in seen, f"Duplicate IOC: {key}"
        seen.add(key)
