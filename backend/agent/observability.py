"""
observability.py — Langfuse tracing for all LLM calls in Fathom.

Wraps every LLM interaction (orchestrator phases, LangChain agent, swarm agents)
with Langfuse traces so you can see:
  - Full prompt/response for every call
  - Token usage per call and per session
  - Latency per phase (Fathom phase1, swarm, synthesis)
  - Error rates and fallback triggers

Usage:
    from agent.observability import trace_span, get_langfuse_callback, flush

    # Manual span (for orchestrator phases)
    with trace_span("fathom_phase1", input=query, session_id=sid) as span:
        result = run_fathom_phase(query)
        span.end(output=result)

    # LangChain callback (auto-traces all LLM calls)
    cb = get_langfuse_callback(session_id=sid)
    executor.invoke({"input": query}, config={"callbacks": [cb]})
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

# ── Langfuse client (lazy init) ───────────────────────────────────────────────

_langfuse = None


def _get_langfuse():
    """Lazy-init Langfuse client. Returns None if not configured."""
    global _langfuse
    if _langfuse is not None:
        return _langfuse

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY", "")
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not public_key or not secret_key:
        logger.debug("Langfuse not configured (LANGFUSE_PUBLIC_KEY/SECRET_KEY not set) — tracing disabled")
        return None

    try:
        from langfuse import Langfuse
        _langfuse = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
        )
        logger.info("Langfuse tracing enabled → %s", host)
        return _langfuse
    except ImportError:
        logger.warning("langfuse package not installed — tracing disabled")
        return None
    except Exception as e:
        logger.warning("Langfuse init failed: %s — tracing disabled", e)
        return None


# ── LangChain callback handler ────────────────────────────────────────────────

def get_langfuse_callback(
    session_id: str | None = None,
    trace_name: str = "fathom_agent",
    user_id: str = "fathom-system",
) -> Optional[Any]:
    """
    Return a LangChain CallbackHandler that traces to Langfuse.
    Returns None if Langfuse is not configured.
    """
    lf = _get_langfuse()
    if lf is None:
        return None

    try:
        from langfuse.callback import CallbackHandler
        return CallbackHandler(
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
            secret_key=os.environ.get("LANGFUSE_SECRET_KEY", ""),
            host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
            session_id=session_id,
            trace_name=trace_name,
            user_id=user_id,
        )
    except Exception as e:
        logger.warning("Langfuse callback init failed: %s", e)
        return None


# ── Manual span context manager ───────────────────────────────────────────────

class _NoopSpan:
    """No-op span when Langfuse is not configured."""
    def update(self, **kwargs): pass
    def end(self, **kwargs): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


@contextmanager
def trace_span(
    name: str,
    input: Any = None,
    session_id: str | None = None,
    metadata: dict | None = None,
) -> Generator:
    """
    Context manager that creates a Langfuse span for a pipeline phase.

    Usage:
        with trace_span("fathom_phase1", input=query, session_id=sid) as span:
            result = do_work()
            span.end(output=result, usage={"input_tokens": 120, "output_tokens": 50})
    """
    lf = _get_langfuse()
    if lf is None:
        span = _NoopSpan()
        yield span
        return

    try:
        trace = lf.trace(
            name=f"fathom/{name}",
            input=str(input)[:2000] if input else None,
            session_id=session_id,
            metadata=metadata or {},
        )
        span = trace.span(name=name, input=str(input)[:2000] if input else None)
        yield span
        span.end()
    except Exception as e:
        logger.warning("Langfuse span error: %s", e)
        yield _NoopSpan()


def record_generation(
    name: str,
    model: str,
    prompt: str,
    completion: str,
    input_tokens: int = 0,
    output_tokens: int = 0,
    session_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    """
    Record a single LLM generation to Langfuse (for non-LangChain calls).
    Used by the orchestrator to trace Fathom phase1, swarm agents, synthesis.
    """
    lf = _get_langfuse()
    if lf is None:
        return

    try:
        trace = lf.trace(
            name=f"fathom/{name}",
            session_id=session_id,
            metadata=metadata or {},
        )
        trace.generation(
            name=name,
            model=model,
            input=prompt[:4000],
            output=completion[:4000],
            usage={
                "input": input_tokens,
                "output": output_tokens,
                "total": input_tokens + output_tokens,
            },
        )
    except Exception as e:
        logger.warning("Langfuse record_generation error: %s", e)


def flush() -> None:
    """Flush pending Langfuse events (call at shutdown or end of request)."""
    lf = _get_langfuse()
    if lf:
        try:
            lf.flush()
        except Exception:
            pass
