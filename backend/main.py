"""Fathom FastAPI entry point."""

import os
import sys
from pathlib import Path

# Ensure backend/ is on sys.path for bare imports (Fix #8)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Fathom",
    description="LLM-Powered Automated Malware Analysis Framework",
    version="0.2.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",              # local dev
        "http://134.199.201.243:3000",        # VM dashboard
        "http://134.199.201.243:7860",        # VM API self-reference
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
from api.routes import router as api_router  # noqa: E402
from api.copilot_handler import copilot_router  # noqa: E402

app.include_router(api_router, prefix="/api")
app.include_router(copilot_router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


# ── Prometheus metrics (Task 4.2) ─────────────────────────────────────────────
try:
    import torch
    from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

    _analysis_requests = Counter(
        "fathom_analysis_requests_total", "Total /analyze requests"
    )
    _analysis_duration = Histogram(
        "fathom_analysis_duration_seconds", "Analysis duration in seconds"
    )
    _enrichment_requests = Counter(
        "fathom_enrichment_requests_total", "Total enriched analysis requests"
    )
    _gpu_memory = Gauge(
        "fathom_gpu_memory_bytes", "GPU memory allocated in bytes"
    )

    @app.get("/metrics")
    async def metrics():
        if torch.cuda.is_available():
            _gpu_memory.set(torch.cuda.memory_allocated())
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Instrument /api/analyze via middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    import time

    class MetricsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if request.url.path == "/api/analyze":
                _analysis_requests.inc()
                start = time.time()
                response = await call_next(request)
                _analysis_duration.observe(time.time() - start)
                return response
            return await call_next(request)

    app.add_middleware(MetricsMiddleware)

except ImportError:
    pass  # prometheus_client not installed — metrics endpoint disabled
