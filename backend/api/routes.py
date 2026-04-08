"""
routes.py — FastAPI routes: /upload, /analyze, /chat, /route, /graph, /health.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import uuid
from typing import Dict

import orjson
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from api.schemas import (
    AnalyzeRequest, AnalysisResponse, RoutingResult,
    ChatRequest, ChatResponse,
    RouteRequest,
    GraphQueryRequest, GraphResponse,
    HealthResponse,
    UploadResponse,
    TokenUsage,
)
from evidence.cape_extractor import (
    CAPEEvidenceExtractor, EvidenceBrief,
    extract_from_cape_dict, format_evidence_text,
)
from evidence.module1_adapter import Module1Adapter, from_module1_output
from llm.inference import generate
from llm.guardrails import sanitize_input, sanitize_malware_report, validate_output
from llm.token_usage import TokenUsageTracker, estimate_tokens_from_text
from router.domain_classifier import DomainRouter

logger = logging.getLogger(__name__)

router = APIRouter()
_domain_router = DomainRouter()

# In-memory evidence brief store: brief_id -> EvidenceBrief
_evidence_store: Dict[str, EvidenceBrief] = {}

# ── Auth ──────────────────────────────────────────────────────────────────────
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

_security = HTTPBearer(auto_error=False)
_VALID_TOKENS: set[str] = set(
    t for t in os.environ.get("API_TOKENS", "").split(",") if t.strip()
)


def _verify_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> str | None:
    """Bearer token auth. Skipped when API_TOKENS env var is not set."""
    if not _VALID_TOKENS:
        return None  # Auth disabled — no tokens configured
    if credentials is None or credentials.credentials not in _VALID_TOKENS:
        raise HTTPException(401, "Invalid or missing API token")
    return credentials.credentials


# ── Rate limiter (imported from app state) ────────────────────────────────────
from slowapi import Limiter
from slowapi.util import get_remote_address

_limiter = Limiter(key_func=get_remote_address)


def store_evidence_brief(brief: EvidenceBrief) -> str:
    """Store an EvidenceBrief in memory and return its unique ID."""
    brief_id = str(uuid.uuid4())
    _evidence_store[brief_id] = brief
    return brief_id


@router.post("/upload", response_model=UploadResponse)
@_limiter.limit("20/minute")
async def upload_file(request: Request, file: UploadFile = File(...), _token: str | None = Depends(_verify_token)):
    """Accept CAPE JSON or PE binary uploads and return a brief_id for /analyze."""
    content = await file.read()
    filename = file.filename or ""

    # Validate file size (<50MB)
    if len(content) > 50 * 1024 * 1024:
        from audit.logger import audit
        audit.log_upload_rejected(request, reason="file_too_large", filename=filename, size=len(content))
        raise HTTPException(413, "File too large (max 50MB)")

    if filename.endswith(".json"):
        try:
            report = orjson.loads(content)
        except Exception:
            raise HTTPException(400, "Invalid JSON file")
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(report)
        file_type = "cape_report"
    elif filename.endswith((".exe", ".dll", ".sys")):
        suffix = os.path.splitext(filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(content)
            temp_path = tmp.name
        try:
            adapter = Module1Adapter()
            brief = adapter.analyze_pe_binary(temp_path)
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        file_type = "pe_binary"
    else:
        raise HTTPException(400, "Unsupported file type")

    brief_id = store_evidence_brief(brief)

    # ── Store in MinIO (async, best-effort) ───────────────────────────────
    sha256_val = brief.sha256 or brief.hashes.get("sha256", "")
    stored_minio = False
    if sha256_val:
        try:
            from storage.minio_client import store_sample, store_cape_report
            ct = "application/json" if filename.endswith(".json") else "application/octet-stream"
            stored_minio = store_sample(sha256_val, content, filename, ct)
            if filename.endswith(".json"):
                try:
                    store_cape_report(sha256_val, orjson.loads(content))
                except Exception:
                    pass
        except Exception as e:
            logger.debug("MinIO storage skipped: %s", e)

    # ── Audit log ─────────────────────────────────────────────────────────
    from audit.logger import audit
    audit.log_upload(
        request,
        sha256=sha256_val,
        filename=filename,
        size=len(content),
        file_type=file_type,
        ioc_count=len(brief.iocs),
        behavior_count=len(brief.behaviors),
        stored_in_minio=stored_minio,
    )

    return UploadResponse(
        brief_id=brief_id,
        sha256=sha256_val,
        file_type=file_type,
        ioc_count=len(brief.iocs),
        behavior_count=len(brief.behaviors),
    )


@router.post("/analyze", response_model=AnalysisResponse)
@_limiter.limit("10/minute")
async def analyze(request: Request, req: AnalyzeRequest, _token: str | None = Depends(_verify_token)):
    """Run the full Fathom analysis pipeline with optional 3-phase enrichment."""
    # Sanitize input
    query, input_warnings = sanitize_input(req.query)

    # Extract evidence
    evidence_text = ""
    brief: EvidenceBrief | None = None
    if req.evidence:
        try:
            sanitized_evidence = sanitize_malware_report(req.evidence)
            if "behavior" in sanitized_evidence or "signatures" in sanitized_evidence:
                brief = extract_from_cape_dict(sanitized_evidence)
            else:
                brief = from_module1_output(sanitized_evidence)
            evidence_text = format_evidence_text(brief)
        except Exception as e:
            input_warnings.append(f"Evidence extraction error: {e}")

    # RAG context
    rag_context = ""
    try:
        from rag.retriever import RAGRetriever
        rag_context = RAGRetriever().query_to_text(query, top_k=5)
    except Exception:
        pass

    # ── Graph context: query Neo4j for related samples (Step 14b) ────────
    graph_context = ""
    if brief is not None:
        try:
            from graph.context_retriever import (
                get_graph_context,
                extract_techniques_from_brief,
                extract_iocs_from_brief,
            )
            techniques = extract_techniques_from_brief(brief)
            ioc_values = extract_iocs_from_brief(brief)
            graph_context = get_graph_context(
                sha256=brief.hashes.get("sha256", ""),
                techniques=techniques,
                ioc_values=ioc_values,
            )
            if graph_context:
                logger.info("Graph context injected: %d chars", len(graph_context))
        except Exception as e:
            logger.debug("Graph context retrieval skipped: %s", e)

    # ── Cross-sample FAISS similarity ─────────────────────────────────────
    similarity_context = ""
    if brief is not None:
        try:
            from rag.sample_similarity import find_similar_samples, format_similar_context
            similar = find_similar_samples(brief, top_k=3)
            similarity_context = format_similar_context(similar)
        except Exception as e:
            logger.debug("Sample similarity skipped: %s", e)

    # Merge all context sources
    if graph_context or similarity_context:
        extra = "\n\n".join(filter(None, [graph_context, similarity_context]))
        evidence_text = f"{evidence_text}\n\n{extra}" if evidence_text else extra

    kimi_enrichment_used = False
    enrichment_gaps_filled: list[str] = []
    synthesis_model = ""
    tracker = TokenUsageTracker()

    if req.enable_enrichment:
        # ── 3-phase enrichment pipeline ──────────────────────────────────────
        from agent.orchestrator import run_fathom_phase, run_swarm_phase, stream_synthesis_chunks

        force = bool(req.cape_task_id.strip())
        analysis_text, contract = run_fathom_phase(
            query, cape_context=evidence_text, history=[], force_enrichment=force,
            tracker=tracker,
        )

        if contract and contract.get("gaps"):
            swarm_enrichment, swarm_results = run_swarm_phase(contract)
            if swarm_enrichment:
                final_report = "".join(stream_synthesis_chunks(
                    analysis_text, swarm_enrichment, swarm_results,
                    query, evidence_text, [], tracker=tracker,
                ))
                kimi_enrichment_used = True
                enrichment_gaps_filled = list(swarm_results.keys())
                synthesis_model = os.environ.get("AZURE_MODEL", "Kimi-K2.5")
            else:
                final_report = analysis_text
        else:
            final_report = analysis_text

        # Build a minimal GenerationResult-compatible object for the response
        from llm.inference import GenerationResult
        from router.domain_classifier import DomainRouter
        _dr = DomainRouter()
        _domain_id, _conf, _scores = _dr.route(evidence_text or query)
        from config import DOMAINS
        result = GenerationResult(
            text=final_report,
            domain_id=_domain_id,
            domain_name=DOMAINS.get(_domain_id, {}).get("name", _domain_id),
            confidence=_conf,
            adapter_used="orchestrator",
            domain_scores=_scores,
            tokens_generated=len(final_report.split()),
        )
    else:
        # ── Fast path: local Fathom inference ────────────────────────────────
        result = generate(
            query=query,
            evidence_text=evidence_text,
            rag_context=rag_context,
            domain_id=req.domain_id,
            max_new_tokens=req.max_tokens,
            temperature=req.temperature,
        )
        # Record local inference token count
        tracker.record(
            input_tokens=estimate_tokens_from_text(evidence_text + query),
            output_tokens=result.tokens_generated,
            source=f"local/{result.adapter_used}",
        )

    # Validate output
    validation = validate_output(result.text, response_type="report")
    all_warnings = input_warnings + validation.get("warnings", [])

    # Background Neo4j ingestion (Task 1.2)
    if brief is not None:
        try:
            from graph.ingest_cape import ingest_evidence_brief
            asyncio.create_task(ingest_evidence_brief(brief))
        except Exception as e:
            logger.warning("Neo4j ingestion task creation failed: %s", e)

    graph_id = brief.sha256 if brief and brief.sha256 else None

    usage = tracker.summary()

    # ── Store report in MinIO + audit log ─────────────────────────────────
    import time as _time
    from audit.logger import audit
    sha256_val = graph_id or ""
    try:
        from storage.minio_client import store_analysis_report
        store_analysis_report(
            sha256_val,
            result.text,
            metadata={
                "verdict": "malicious" if "malicious" in result.text.lower() else "unknown",
                "domain": result.domain_id,
                "enrichment": kimi_enrichment_used,
            },
        )
    except Exception as e:
        logger.debug("MinIO report storage skipped: %s", e)

    # Extract technique count from result text for audit
    import re as _re
    tech_count = len(set(_re.findall(r"T\d{4}(?:\.\d{3})?", result.text)))
    audit.log_analysis_complete(
        request,
        sha256=sha256_val,
        verdict="malicious" if "malicious" in result.text.lower() else "unknown",
        confidence=int(result.confidence * 100),
        technique_count=tech_count,
        ioc_count=len(brief.iocs) if brief else 0,
        enrichment_used=kimi_enrichment_used,
        duration_ms=0,
        adapter_used=result.adapter_used,
    )

    return AnalysisResponse(
        text=result.text,
        routing=RoutingResult(
            domain_id=result.domain_id,
            domain_name=result.domain_name,
            confidence=result.confidence,
            scores=result.domain_scores,
            adapter=result.adapter_used,
        ),
        tokens_generated=result.tokens_generated,
        warnings=all_warnings,
        kimi_enrichment_used=kimi_enrichment_used,
        enrichment_gaps_filled=enrichment_gaps_filled,
        synthesis_model=synthesis_model,
        graph_id=graph_id,
        token_usage=TokenUsage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
            cache_read_tokens=usage.cache_read_tokens,
            requests=usage.requests,
        ),
    )


@router.post("/analyze/stream")
@_limiter.limit("10/minute")
async def analyze_stream(request: Request, req: AnalyzeRequest, _token: str | None = Depends(_verify_token)):
    """SSE streaming version of /analyze — streams synthesis chunks as they arrive."""
    from agent.orchestrator import (
        run_fathom_phase, run_swarm_phase, stream_synthesis_chunks, stream_direct_chunks
    )

    query, _ = sanitize_input(req.query)

    evidence_text = ""
    brief: EvidenceBrief | None = None
    if req.evidence:
        try:
            sanitized_evidence = sanitize_malware_report(req.evidence)
            if "behavior" in sanitized_evidence or "signatures" in sanitized_evidence:
                brief = extract_from_cape_dict(sanitized_evidence)
            else:
                brief = from_module1_output(sanitized_evidence)
            evidence_text = format_evidence_text(brief)
        except Exception:
            pass

    def _sse(event_type: str, text: str) -> str:
        return f"data: {json.dumps({'type': event_type, 'text': text})}\n\n"

    async def event_generator():
        loop = asyncio.get_event_loop()

        if req.enable_enrichment:
            yield _sse("status", "Fathom analyzing...")
            force = bool(req.cape_task_id.strip())
            analysis_text, contract = await loop.run_in_executor(
                None,
                lambda: run_fathom_phase(query, evidence_text, [], force_enrichment=force),
            )

            if contract and contract.get("gaps"):
                yield _sse("status", "Running 4 intelligence agents in parallel...")
                swarm_enrichment, swarm_results = await loop.run_in_executor(
                    None, lambda: run_swarm_phase(contract)
                )

                if swarm_enrichment:
                    yield _sse("status", "Synthesizing final report...")
                    for chunk in stream_synthesis_chunks(
                        analysis_text, swarm_enrichment, swarm_results,
                        query, evidence_text, []
                    ):
                        yield _sse("chunk", chunk)
                else:
                    for chunk in stream_direct_chunks(query, evidence_text):
                        yield _sse("chunk", chunk)
            else:
                for chunk in stream_direct_chunks(query, evidence_text):
                    yield _sse("chunk", chunk)
        else:
            yield _sse("status", "Fathom analyzing...")
            for chunk in stream_direct_chunks(query, evidence_text):
                yield _sse("chunk", chunk)

        yield _sse("done", json.dumps({"graph_id": brief.sha256 if brief and brief.sha256 else None}))

        # Background Neo4j ingestion
        if brief is not None:
            try:
                from graph.ingest_cape import ingest_evidence_brief
                asyncio.create_task(ingest_evidence_brief(brief))
            except Exception:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.post("/agent")
@_limiter.limit("5/minute")
async def agent_investigate(
    request: Request,
    req: AnalyzeRequest,
    _token: str | None = Depends(_verify_token),
):
    """
    Full LangChain ReAct agent investigation with Langfuse tracing.
    Runs the 5-tool agent loop: evidence_extract → fathom_analyze → attack_map → ioc_lookup → knowledge_search.
    Slower than /analyze but produces richer multi-step reasoning.
    """
    import asyncio
    from agent.lc_agent import run_lc_investigation

    query, _ = sanitize_input(req.query)
    evidence_text = ""
    if req.evidence:
        try:
            sanitized = sanitize_malware_report(req.evidence)
            if "behavior" in sanitized or "signatures" in sanitized:
                brief = extract_from_cape_dict(sanitized)
            else:
                brief = from_module1_output(sanitized)
            evidence_text = format_evidence_text(brief)
        except Exception:
            pass

    session_id = req.cape_task_id or None
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: run_lc_investigation(query, evidence_text, session_id),
    )
    return {"report": result, "agent": "langchain-react", "session_id": session_id}


@router.post("/route")
async def route_query(request: Request, req: RouteRequest):
    """Route text to a domain without generation."""
    domain_id, confidence, scores = _domain_router.route(req.text)

    from config import DOMAINS
    domain_name = DOMAINS.get(domain_id, {}).get("name", domain_id)
    adapter = _domain_router.get_adapter_name(domain_id) or "unified"

    return RoutingResult(
        domain_id=domain_id,
        domain_name=domain_name,
        confidence=confidence,
        scores=scores,
        adapter=adapter,
    )


@router.post("/chat", response_model=ChatResponse)
@_limiter.limit("100/minute")
async def chat(request: Request, req: ChatRequest, _token: str | None = Depends(_verify_token)):
    """
    Chat endpoint for follow-up questions about an analyzed sample.
    Maintains conversation history via session_id stored client-side.
    Routes through the Fathom orchestrator with CAPE context if provided.
    """
    query, _ = sanitize_input(req.message)

    evidence_text = ""
    if req.evidence_context:
        try:
            brief = extract_from_cape_dict(req.evidence_context)
            evidence_text = format_evidence_text(brief)
        except Exception:
            pass

    # Use pre-extracted cape_context if provided (faster than re-extracting)
    if req.cape_context:
        evidence_text = req.cape_context or evidence_text

    # Build history from request (client sends last N turns)
    history = getattr(req, "history", []) or []

    session_id = req.session_id or str(uuid.uuid4())

    # ── 1. Semantic cache check (FAISS) ──────────────────────────────────
    from graph.chat_store import cache_lookup, cache_store, save_turn, get_history_as_turns
    cached = cache_lookup(query, sample_sha256=evidence_text[:64] if evidence_text else "")
    if cached:
        # Persist the turn even on cache hit
        asyncio.create_task(asyncio.to_thread(save_turn, session_id, "user", query))
        asyncio.create_task(asyncio.to_thread(save_turn, session_id, "assistant", cached,
                                               tags=["cache_hit"]))
        return ChatResponse(response=cached, session_id=session_id)

    # ── 2. Load persistent history from Neo4j ────────────────────────────
    if not history:
        try:
            history = await asyncio.get_event_loop().run_in_executor(
                None, lambda: get_history_as_turns(session_id)
            )
        except Exception:
            pass

    # ── 3. Generate response ──────────────────────────────────────────────
    try:
        from agent.orchestrator import run_investigation
        loop = asyncio.get_event_loop()
        response_text = await loop.run_in_executor(
            None,
            lambda: run_investigation(
                query=query,
                cape_context=evidence_text,
                history=history,
                use_swarm=False,
            ),
        )
    except Exception:
        result = generate(query=query, evidence_text=evidence_text)
        response_text = result.text

    # ── 4. Persist turn + cache response ─────────────────────────────────
    sha256 = evidence_text[:64] if evidence_text else ""
    asyncio.create_task(asyncio.to_thread(save_turn, session_id, "user", query, sha256))
    asyncio.create_task(asyncio.to_thread(save_turn, session_id, "assistant", response_text, sha256))
    asyncio.create_task(asyncio.to_thread(cache_store, query, response_text, sha256))

    return ChatResponse(response=response_text, session_id=session_id)

@router.post("/chat/stream")
@_limiter.limit("100/minute")
async def chat_stream(request: Request, req: ChatRequest, _token: str | None = Depends(_verify_token)):
    """
    Streaming chat endpoint — SSE stream of text chunks.
    Used by CopilotKit and the frontend chat panel for real-time responses.
    Each chunk: data: {"type": "chunk", "text": "..."}
    Final:      data: {"type": "done", "text": ""}
    """
    query, _ = sanitize_input(req.message)

    evidence_text = req.cape_context or ""
    if not evidence_text and req.evidence_context:
        try:
            brief = extract_from_cape_dict(req.evidence_context)
            evidence_text = format_evidence_text(brief)
        except Exception:
            pass

    history = req.history or []

    def _sse(event_type: str, text: str) -> str:
        return f"data: {json.dumps({'type': event_type, 'text': text})}\n\n"

    async def event_generator():
        import asyncio
        from agent.orchestrator import stream_direct_chunks
        from graph.chat_store import cache_lookup, cache_store, save_turn, get_history_as_turns

        session_id = req.session_id or str(uuid.uuid4())
        sha256 = evidence_text[:64] if evidence_text else ""

        # ── 1. Semantic cache check ───────────────────────────────────────
        cached = cache_lookup(query, sample_sha256=sha256)
        if cached:
            chunk_size = 180
            for i in range(0, len(cached), chunk_size):
                yield _sse("chunk", cached[i:i + chunk_size])
            yield _sse("done", "")
            asyncio.create_task(asyncio.to_thread(save_turn, session_id, "user", query, sha256, ["cache_hit"]))
            asyncio.create_task(asyncio.to_thread(save_turn, session_id, "assistant", cached, sha256, ["cache_hit"]))
            return

        # ── 2. Load persistent history if not provided ────────────────────
        hist = history or []
        if not hist:
            try:
                hist = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: get_history_as_turns(session_id)
                )
            except Exception:
                pass

        # ── 3. Stream response ────────────────────────────────────────────
        loop = asyncio.get_event_loop()
        full_response = ""

        try:
            chunks = await loop.run_in_executor(
                None,
                lambda: list(stream_direct_chunks(
                    query=query,
                    cape_context=evidence_text,
                    history=hist,
                    mode="followup",
                )),
            )
            for chunk in chunks:
                full_response += chunk
                yield _sse("chunk", chunk)
        except Exception as e:
            err = f"Error generating response: {e}"
            full_response = err
            yield _sse("chunk", err)

        yield _sse("done", "")

        # ── 4. Persist turn + cache ───────────────────────────────────────
        asyncio.create_task(asyncio.to_thread(save_turn, session_id, "user", query, sha256))
        asyncio.create_task(asyncio.to_thread(save_turn, session_id, "assistant", full_response, sha256))
        if full_response and not full_response.startswith("Error"):
            asyncio.create_task(asyncio.to_thread(cache_store, query, full_response, sha256))

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.post("/graph", response_model=GraphResponse)
async def query_graph(req: GraphQueryRequest):
    """Query the Neo4j behavior graph using predefined queries only."""
    from graph import queries as Q

    ALLOWED_QUERIES = {
        "process_tree": Q.PROCESS_TREE,
        "sample_iocs": Q.SAMPLE_IOCS,
        "sample_techniques": Q.SAMPLE_TECHNIQUES,
        "ioc_correlation": Q.IOC_CORRELATION,
        "technique_search": Q.TECHNIQUE_SEARCH,
        "sample_graph": Q.SAMPLE_GRAPH,
    }

    if req.query_name not in ALLOWED_QUERIES:
        raise HTTPException(400, f"Unknown query. Allowed: {list(ALLOWED_QUERIES.keys())}")

    cypher = ALLOWED_QUERIES[req.query_name]

    try:
        from graph.neo4j_client import Neo4jClient
        client = Neo4jClient()
        params = {}
        if req.sample_hash:
            params["hash"] = req.sample_hash
        if req.technique_id:
            params["technique_id"] = req.technique_id
        nodes, edges = client.query(cypher, sample_hash=req.sample_hash)
        from audit.logger import audit
        audit.log_graph_query(None, query_name=req.query_name, sample_hash=req.sample_hash or "")
        return GraphResponse(nodes=nodes, edges=edges, query_used=req.query_name)
    except ImportError:
        raise HTTPException(503, "Neo4j client not available")
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Retrieve full conversation history for a session from Neo4j."""
    from graph.chat_store import get_session_history
    turns = get_session_history(session_id, limit=50)
    return {"session_id": session_id, "turns": turns, "count": len(turns)}


@router.get("/sessions/{session_id}/cache-stats")
async def session_cache_stats(session_id: str):
    """Return cache hit stats for a session."""
    try:
        from graph.neo4j_client import Neo4jClient
        client = Neo4jClient()
        rows = client.run("""
            MATCH (sess:ChatSession {session_id: $sid})-[:HAS_TURN]->(t:ChatTurn)
            WHERE 'cache_hit' IN t.tags
            RETURN count(t) AS cache_hits
        """, {"sid": session_id})
        hits = rows[0]["cache_hits"] if rows else 0
        total_rows = client.run("""
            MATCH (sess:ChatSession {session_id: $sid})-[:HAS_TURN]->(t:ChatTurn)
            WHERE t.role = 'user'
            RETURN count(t) AS total
        """, {"sid": session_id})
        total = total_rows[0]["total"] if total_rows else 0
        return {"session_id": session_id, "cache_hits": hits, "total_queries": total,
                "hit_rate": round(hits / total, 2) if total else 0}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/report/generate")
@_limiter.limit("5/minute")
async def generate_report(
    request: Request,
    req: AnalyzeRequest,
    _token: str | None = Depends(_verify_token),
):
    """
    Generate a fully structured report from analysis data.

    Uses the same 3-phase pipeline as the demo:
    1. Fathom first-pass on CAPE evidence
    2. Kimi swarm enrichment (if enable_enrichment=True)
    3. Kimi synthesis into structured sections

    Returns structured report data ready for the frontend report page.
    """
    from api.report_generator import generate_report_sections

    query, _ = sanitize_input(req.query)
    evidence_text = req.cape_context if req.cape_context else ""

    if req.evidence:
        try:
            sanitized = sanitize_malware_report(req.evidence)
            if "behavior" in sanitized or "signatures" in sanitized:
                brief = extract_from_cape_dict(sanitized)
            else:
                brief = from_module1_output(sanitized)
            evidence_text = format_evidence_text(brief)
        except Exception:
            pass

    # Run the full 3-phase pipeline to get the enriched report text
    from agent.orchestrator import run_fathom_phase, run_swarm_phase, stream_synthesis_chunks
    import asyncio

    loop = asyncio.get_event_loop()
    force = bool(req.cape_task_id.strip()) if req.cape_task_id else False

    analysis_text, contract = await loop.run_in_executor(
        None,
        lambda: run_fathom_phase(
            query or "Analyze this CAPE sandbox report. Provide executive summary, ATT&CK technique mappings, behavioral indicators, IOCs, and threat assessment.",
            cape_context=evidence_text,
            history=[],
            force_enrichment=force or req.enable_enrichment,
        ),
    )

    full_report = analysis_text
    enrichment_used = False

    if req.enable_enrichment and contract and contract.get("gaps"):
        swarm_enrichment, swarm_results = await loop.run_in_executor(
            None, lambda: run_swarm_phase(contract)
        )
        if swarm_enrichment:
            full_report = "".join(stream_synthesis_chunks(
                analysis_text, swarm_enrichment, swarm_results,
                query, evidence_text, []
            ))
            enrichment_used = True

    # Parse the report into structured sections
    sample_meta = {}
    if req.evidence:
        try:
            sanitized = sanitize_malware_report(req.evidence)
            brief = extract_from_cape_dict(sanitized)
            sample_meta = {
                "sha256": brief.hashes.get("sha256", ""),
                "md5": brief.hashes.get("md5", ""),
                "file_name": brief.file_name or "",
                "family": brief.detections[0]["family"] if brief.detections else "",
                "score": brief.meta.malscore if brief.meta else 0,
            }
        except Exception:
            pass

    structured = generate_report_sections(
        full_report,
        sample_meta,
        include_ai_sections=False,  # already have full report from pipeline
    )
    structured["report_text"] = full_report
    structured["kimi_enrichment_used"] = enrichment_used
    structured["generated_at"] = __import__("datetime").datetime.utcnow().isoformat()

    return structured


@router.get("/similar/{sha256}")
async def get_similar_samples(sha256: str, top_k: int = 5):
    """
    Find samples similar to the given SHA256 using FAISS cross-sample similarity.
    Returns top-k most similar previously analyzed samples with shared TTPs and IOCs.
    """
    try:
        from rag.sample_similarity import find_similar_samples
        from graph.context_retriever import get_graph_context

        # Get FAISS similarity results
        # We need the brief from the evidence store if available
        brief = _evidence_store.get(sha256)  # may be None if not in current session

        similar = []
        if brief:
            similar = find_similar_samples(brief, top_k=top_k)
        else:
            # Fall back to Neo4j-only correlation by SHA256
            try:
                from graph.neo4j_client import Neo4jClient
                client = Neo4jClient()
                # Get techniques for this sample from Neo4j
                rows = client.run("""
                    MATCH (s:Sample {sha256: $hash})-[:USES_TECHNIQUE]->(t:Technique)
                    RETURN collect(t.technique_id) AS techniques
                """, {"hash": sha256})
                techniques = rows[0]["techniques"] if rows else []

                ioc_rows = client.run("""
                    MATCH (s:Sample {sha256: $hash})-[:HAS_IOC]->(i:IOC)
                    RETURN collect(i.value) AS iocs
                """, {"hash": sha256})
                ioc_values = ioc_rows[0]["iocs"] if ioc_rows else []

                # Find related samples via Neo4j
                if techniques or ioc_values:
                    related_rows = client.run("""
                        UNWIND $tids AS tid
                        MATCH (t:Technique {technique_id: tid})<-[:USES_TECHNIQUE]-(s:Sample)
                        WHERE s.sha256 <> $hash
                        WITH s, collect(DISTINCT tid) AS shared_tids
                        ORDER BY size(shared_tids) DESC
                        LIMIT $limit
                        RETURN s.sha256 AS sha256, s.name AS file_name,
                               s.family AS family, s.score AS malscore,
                               shared_tids AS shared_techniques
                    """, {"tids": techniques[:10], "hash": sha256, "limit": top_k})

                    for r in related_rows:
                        similar.append({
                            "sha256": r.get("sha256", ""),
                            "file_name": r.get("file_name", ""),
                            "family": r.get("family", ""),
                            "malscore": r.get("malscore", 0),
                            "similarity": 0.0,  # no FAISS score available
                            "shared_techniques": r.get("shared_techniques", []),
                            "shared_iocs": [],
                        })
            except Exception as e:
                logger.debug("Neo4j similarity fallback failed: %s", e)

        return {"sha256": sha256, "similar": similar, "count": len(similar)}

    except Exception as e:
        logger.warning("Similar samples lookup failed for %s: %s", sha256[:16], e)
        return {"sha256": sha256, "similar": [], "count": 0}


@router.get("/joe-reports")
async def list_joe_reports():
    """List all pre-processed Joe Sandbox reports from the catalog."""
    import json as _json
    from pathlib import Path
    catalog_path = Path(__file__).resolve().parent.parent.parent / "joe sandbox" / "catalog.json"
    if not catalog_path.exists():
        return {"reports": [], "message": "Run backend/scripts/build_joe_catalog.py to generate catalog"}
    catalog = _json.loads(catalog_path.read_text(encoding="utf-8"))
    return {"reports": catalog}


@router.get("/joe-reports/{report_id}")
async def get_joe_report(report_id: str):
    """Get a specific Joe Sandbox report by analysis ID."""
    import json as _json
    from pathlib import Path
    catalog_path = Path(__file__).resolve().parent.parent.parent / "joe sandbox" / "catalog.json"
    if not catalog_path.exists():
        raise HTTPException(404, "Catalog not built. Run backend/scripts/build_joe_catalog.py")
    catalog = _json.loads(catalog_path.read_text(encoding="utf-8"))
    report = next((r for r in catalog if str(r.get("analysis_id")) == str(report_id)), None)
    if not report:
        raise HTTPException(404, f"Report {report_id} not found")
    return report


@router.get("/health", response_model=HealthResponse)
async def health():
    """Health check with model status."""
    from llm.model_loader import _model, _current_adapter
    from llm.adapter_registry import AdapterRegistry

    adapters = []
    try:
        registry = AdapterRegistry()
        adapters = list(registry.list_available().keys())
    except Exception:
        pass

    return HealthResponse(
        status="ok",
        version="0.2.0",
        adapters_loaded=adapters,
        model_loaded=_model is not None,
    )
