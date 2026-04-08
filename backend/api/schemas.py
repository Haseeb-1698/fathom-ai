"""
schemas.py — Pydantic models for FastAPI request/response validation.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Request models ───────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    query: str = Field(..., description="Analysis query or instruction")
    evidence: Optional[dict[str, Any]] = Field(None, description="Raw CAPE/Module1 JSON")
    domain_id: Optional[str] = Field(None, description="Force a specific domain (skip routing)")
    max_tokens: int = Field(512, ge=32, le=2048)
    temperature: float = Field(0.3, ge=0.0, le=2.0)
    enable_enrichment: bool = Field(False, description="Enable 3-phase Kimi enrichment pipeline")
    cape_task_id: str = Field("", description="CAPE task ID — forces enrichment on first report")
    cape_context: str = Field("", description="Pre-extracted CAPE evidence text (skips re-extraction)")


class ChatRequest(BaseModel):
    message: str = Field(..., description="User chat message")
    session_id: Optional[str] = Field(None, description="Conversation session ID")
    evidence_context: Optional[dict[str, Any]] = Field(None)
    history: list[dict[str, Any]] = Field(default_factory=list, description="Last N conversation turns [{user, bot}]")
    cape_context: str = Field("", description="Pre-extracted CAPE evidence text")


class RouteRequest(BaseModel):
    text: str = Field(..., description="Text to route to a domain")


class GraphQueryRequest(BaseModel):
    query_name: str = Field(..., description="Predefined query name: process_tree, sample_iocs, sample_techniques, ioc_correlation, sample_graph")
    sample_hash: Optional[str] = Field(None, description="Filter by sample hash")
    technique_id: Optional[str] = Field(None, description="ATT&CK technique ID for technique_search")


# ── Response models ──────────────────────────────────────────────────────

class RoutingResult(BaseModel):
    domain_id: str
    domain_name: str
    confidence: float
    scores: dict[str, float]
    adapter: str


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    requests: int = 0


class AnalysisResponse(BaseModel):
    text: str
    routing: RoutingResult
    tokens_generated: int
    warnings: list[str] = []
    # Enrichment metadata
    kimi_enrichment_used: bool = False
    enrichment_gaps_filled: list[str] = []
    synthesis_model: str = ""
    graph_id: Optional[str] = None
    # Token usage
    token_usage: TokenUsage = TokenUsage()


class ChatResponse(BaseModel):
    response: str
    session_id: str
    sources: list[str] = []


class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    query_used: str


class HealthResponse(BaseModel):
    status: str
    version: str
    adapters_loaded: list[str] = []
    model_loaded: bool = False


class UploadResponse(BaseModel):
    brief_id: str
    sha256: str
    file_type: str
    ioc_count: int
    behavior_count: int
