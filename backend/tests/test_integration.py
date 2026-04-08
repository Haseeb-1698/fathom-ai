"""
test_integration.py — Integration tests for the full Fathom API pipeline.
Task 3.5

These tests use FastAPI TestClient and mock heavy dependencies (model, Neo4j)
so they run without GPU or database.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest


@pytest.fixture(scope="module")
def client():
    """Create a TestClient with model inference mocked out."""
    from llm.inference import GenerationResult

    mock_result = GenerationResult(
        text="## Executive Summary\nThis sample exhibits process injection via T1055.001.",
        domain_id="E2_dynamic",
        domain_name="Dynamic Behavior Analysis",
        confidence=0.87,
        adapter_used="expert-e2-dynamic",
        domain_scores={"E2_dynamic": 0.87, "E1_static": 0.13},
        tokens_generated=42,
    )

    with mock.patch("llm.inference.generate", return_value=mock_result), \
         mock.patch("llm.model_loader.get_model_and_tokenizer", return_value=(mock.MagicMock(), mock.MagicMock())), \
         mock.patch("graph.ingest_cape.ingest_evidence_brief", return_value=None):
        import sys
        sys.path.insert(0, ".")
        from main import app
        from fastapi.testclient import TestClient
        yield TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_api_health_returns_ok(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200


class TestUploadEndpoint:
    def test_upload_cape_json(self, client, basic_cape_report):
        content = json.dumps(basic_cape_report).encode()
        response = client.post(
            "/api/upload",
            files={"file": ("malware.json", content, "application/json")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "brief_id" in data
        assert data["file_type"] == "cape_report"
        assert isinstance(data["ioc_count"], int)
        assert isinstance(data["behavior_count"], int)

    def test_upload_unsupported_type_returns_400(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("malware.pdf", b"fake content", "application/pdf")},
        )
        assert response.status_code == 400

    def test_upload_invalid_json_returns_400(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("malware.json", b"not valid json {{{", "application/json")},
        )
        assert response.status_code == 400

    def test_upload_oversized_file_returns_413(self, client):
        big_content = b"A" * (51 * 1024 * 1024)  # 51MB
        response = client.post(
            "/api/upload",
            files={"file": ("big.json", big_content, "application/json")},
        )
        assert response.status_code == 413


class TestAnalyzeEndpoint:
    def test_analyze_basic_query(self, client):
        response = client.post(
            "/api/analyze",
            json={"query": "Analyze this malware sample"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "text" in data
        assert "routing" in data
        assert "warnings" in data
        assert "kimi_enrichment_used" in data
        assert "enrichment_gaps_filled" in data

    def test_analyze_with_evidence(self, client, basic_cape_report):
        response = client.post(
            "/api/analyze",
            json={
                "query": "Analyze this malware sample",
                "evidence": basic_cape_report,
                "enable_enrichment": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["text"]) > 0
        assert data["kimi_enrichment_used"] is False

    def test_analyze_returns_graph_id_with_evidence(self, client, basic_cape_report):
        response = client.post(
            "/api/analyze",
            json={
                "query": "Analyze this malware",
                "evidence": basic_cape_report,
            },
        )
        assert response.status_code == 200
        # graph_id may be None if sha256 not extracted, but field must exist
        assert "graph_id" in response.json()

    def test_analyze_routing_result_structure(self, client):
        response = client.post(
            "/api/analyze",
            json={"query": "Process injection analysis"},
        )
        assert response.status_code == 200
        routing = response.json()["routing"]
        assert "domain_id" in routing
        assert "confidence" in routing
        assert "adapter" in routing


class TestRouteEndpoint:
    def test_route_returns_domain(self, client):
        response = client.post(
            "/api/route",
            json={"text": "Process injection via WriteProcessMemory"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "domain_id" in data
        assert "confidence" in data


class TestGraphEndpoint:
    def test_graph_unknown_query_returns_400(self, client):
        response = client.post(
            "/api/graph",
            json={"query_name": "nonexistent_query"},
        )
        assert response.status_code == 400
