"""
token_usage.py — Token usage tracking and limit enforcement for Fathom.

Wraps pydantic_ai.usage to track input/output tokens across:
  - Azure API calls (orchestrator swarm + synthesis)
  - Local Mixtral inference (token counts from HF tokenizer)

Usage:
    tracker = get_session_tracker()
    tracker.record(input_tokens=120, output_tokens=50, source="azure/Kimi-K2.5")
    summary = tracker.summary()
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Try to import pydantic_ai.usage (optional dep) ───────────────────────────
try:
    from pydantic_ai.usage import RunUsage, UsageLimits, UsageLimitExceeded
    _PYDANTIC_AI_AVAILABLE = True
except ImportError:
    _PYDANTIC_AI_AVAILABLE = False
    RunUsage = None
    UsageLimits = None
    UsageLimitExceeded = None
    logger.warning("pydantic_ai not installed — token tracking uses fallback counters")


@dataclass
class TokenRecord:
    """Single call record."""
    source: str          # e.g. "azure/Kimi-K2.5", "local/Mixtral-8x7B", "azure/fathom-phase1"
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    requests: int = 1


@dataclass
class UsageSummary:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    requests: int = 0
    records: list[TokenRecord] = field(default_factory=list)
    limit_exceeded: bool = False
    limit_exceeded_reason: str = ""


class TokenUsageTracker:
    """
    Thread-safe token usage tracker for a single analysis session.

    If pydantic_ai is available, uses RunUsage for accumulation and
    UsageLimits for enforcement. Falls back to plain counters otherwise.
    """

    def __init__(self, limits: Optional["UsageLimits"] = None):
        self._lock = threading.Lock()
        self._records: list[TokenRecord] = []
        self._limits = limits

        if _PYDANTIC_AI_AVAILABLE:
            self._usage = RunUsage()
        else:
            self._input_tokens = 0
            self._output_tokens = 0
            self._cache_read_tokens = 0
            self._requests = 0

    def record(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        source: str = "unknown",
    ) -> None:
        """Record token usage from one API call or inference run."""
        with self._lock:
            rec = TokenRecord(
                source=source,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=cache_read_tokens,
            )
            self._records.append(rec)

            if _PYDANTIC_AI_AVAILABLE:
                self._usage.incr(
                    RunUsage(
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        cache_read_tokens=cache_read_tokens,
                        requests=1,
                    )
                )
                # Enforce limits if configured
                if self._limits:
                    try:
                        self._limits.check(self._usage)
                    except Exception as e:  # UsageLimitExceeded
                        logger.warning("Token limit exceeded: %s", e)
                        raise
            else:
                self._input_tokens += input_tokens
                self._output_tokens += output_tokens
                self._cache_read_tokens += cache_read_tokens
                self._requests += 1

    def summary(self) -> UsageSummary:
        """Return aggregated usage summary."""
        with self._lock:
            if _PYDANTIC_AI_AVAILABLE:
                u = self._usage
                return UsageSummary(
                    input_tokens=u.input_tokens or 0,
                    output_tokens=u.output_tokens or 0,
                    total_tokens=(u.input_tokens or 0) + (u.output_tokens or 0),
                    cache_read_tokens=u.cache_read_tokens or 0,
                    requests=u.requests or 0,
                    records=list(self._records),
                )
            else:
                return UsageSummary(
                    input_tokens=self._input_tokens,
                    output_tokens=self._output_tokens,
                    total_tokens=self._input_tokens + self._output_tokens,
                    cache_read_tokens=self._cache_read_tokens,
                    requests=self._requests,
                    records=list(self._records),
                )

    def reset(self) -> None:
        with self._lock:
            self._records.clear()
            if _PYDANTIC_AI_AVAILABLE:
                self._usage = RunUsage()
            else:
                self._input_tokens = 0
                self._output_tokens = 0
                self._cache_read_tokens = 0
                self._requests = 0


def estimate_tokens_from_text(text: str) -> int:
    """Rough token estimate when exact counts aren't available (~4 chars/token)."""
    return max(1, len(text) // 4)


def extract_usage_from_azure_response(response_json: dict) -> tuple[int, int]:
    """
    Pull input/output token counts from an Azure OpenAI response dict.
    Returns (input_tokens, output_tokens).
    """
    usage = response_json.get("usage", {})
    return (
        usage.get("prompt_tokens", 0),
        usage.get("completion_tokens", 0),
    )
