"""
orchestrator.py — 3-phase Fathom enrichment orchestration pipeline.

Decision flow:
  1. Fathom runs first-pass analysis on CAPE evidence / query
  2. Fathom emits "=== ENRICHMENT GAPS ===" section (or contract is auto-built)
  3. Azure swarm (Kimi-K2.5 × 4 parallel agents) fills each gap
  4. Kimi synthesizes final report (streamed to browser)

Public API:
  run_fathom_phase(query, cape_context, history, force_enrichment) -> (analysis_text, contract)
  run_swarm_phase(contract) -> (enrichment_text, swarm_results_dict)
  stream_synthesis_chunks(...) -> Iterator[str]
  stream_direct_chunks(query, cape_context, history, mode) -> Iterator[str]
  run_investigation(query, cape_context, history, use_swarm) -> str  [non-streaming compat]
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Iterator, Optional

import requests

from llm.token_usage import TokenUsageTracker, estimate_tokens_from_text, extract_usage_from_azure_response
from agent.observability import record_generation, flush as lf_flush

FATHOM_ENDPOINT = os.environ.get("FATHOM_ENDPOINT", "http://134.199.201.243:8000")
AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "")
AZURE_ENDPOINT = os.environ.get(
    "AZURE_ENDPOINT", "https://cb26haseeb-5473-resource.openai.azure.com/openai/v1"
)
AZURE_MODEL = os.environ.get("AZURE_MODEL", "Kimi-K2.5")

VALID_GAPS = {
    "live_threat_intel",
    "family_background",
    "ioc_correlation",
    "attack_enrichment",
}

# ── Prompt templates ─────────────────────────────────────────────────────────

FATHOM_ANALYSIS_PROMPT = """\
You are Fathom, a specialized cybersecurity AI trained on malware analysis, \
behavioral forensics, and MITRE ATT&CK framework mapping.

Analyze the provided evidence/query and produce an initial analysis. Then assess \
your own completeness.

After writing the full analysis, you MUST append this exact section at the very end:

=== ENRICHMENT GAPS ===
- <gap item 1>
- <gap item 2>
...

If there are no meaningful gaps, write exactly:
No significant enrichment gaps detected.

Gap examples:
- Unknown malware family background or historical campaigns
- No recent threat actor attribution
- IOCs that need live reputation / passive DNS correlation
- Missing sub-technique details or mitigations
- Victim profile or targeted sector unclear
"""

FATHOM_SYNTHESIS_PROMPT = """\
You are Kimi, acting as the synthesis engine for the Fathom malware analysis platform. \
Fathom (a specialized malware AI) performed the initial behavioral analysis, and you \
received enrichment from four specialist intelligence agents.

Synthesize everything into a FINAL consolidated investigation report using this structure:

## Executive Summary

## ATT&CK Mappings
(technique IDs with sub-techniques, tactic paths)

## Behavioral Indicators

## IOCs
(with reputation data where available from swarm agents)

## Threat Assessment
(severity, confidence level, risk rating)

## Actor Attribution
(if supported by evidence)

## Intelligence Contributors
**Fathom (Mixtral-8x7B + LoRA):** Initial behavioral forensics, technique identification, IOC extraction
**Kimi Swarm — Threat Intel Agent:** {threat_intel_used}
**Kimi Swarm — ATT&CK Agent:** {attack_enrichment_used}
**Kimi Swarm — IOC Agent:** {ioc_used}
**Kimi Swarm — Family Context Agent:** {context_used}
**Kimi (Synthesis):** Final report integration and structured output

Be precise. Use exact technique IDs. This is the definitive investigative report.

Important formatting constraints:
- Start directly with the heading `## Executive Summary`.
- Do NOT add preamble blocks before the first section heading.
- Keep output markdown clean and compact.
"""

AZURE_DIRECT_PROMPT = """\
You are Fathom, a specialized cybersecurity AI trained on malware analysis, \
threat intelligence, and ATT&CK framework mapping. You have deep expertise in \
CAPE/Joe Sandbox reports, behavioral analysis, IOC extraction, and MITRE ATT&CK. \
For malware reports structure your response: Executive Summary, ATT&CK Mappings \
(with technique IDs), Behavioral Indicators, IOCs, Threat Assessment. \
For general cybersecurity questions be concise and technically precise.
"""

FOLLOWUP_QA_PROMPT = """\
You are Fathom. This is a follow-up question about an already analyzed sample/report.
Answer the specific question directly and briefly (2-6 bullets or a short paragraph).
Do NOT regenerate a full malware report unless explicitly requested.
If evidence is missing, state that in one line and suggest what evidence is needed.
"""

ENRICHMENT_KEYWORDS = [
    "enrich", "latest intel", "threat intel", "latest campaigns",
    "threat actor", "more context", "family background", "historical campaigns",
    "correlate iocs", "ioc reputation", "passive dns", "add mitigations",
    "detection opportunities", "sub-technique", "victim profile",
    "targeted sectors", "similar malware", "related variants", "attribution",
    "recent activity", "campaign details", "actor attribution",
    "infrastructure links", "add background", "deep dive",
    "more information on", "update on", "latest on", "enrich this",
    "get more intel", "correlate", "add threat context",
]


# ── Azure helpers ─────────────────────────────────────────────────────────────

def _azure_headers() -> dict:
    return {"api-key": AZURE_API_KEY, "Content-Type": "application/json"}


def _stream_azure_raw(messages: list, max_tokens: int = 3000) -> Iterator[str]:
    """Yield text chunks from Azure streaming API."""
    payload = {
        "model": AZURE_MODEL,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "stream": True,
    }
    try:
        with requests.post(
            f"{AZURE_ENDPOINT}/chat/completions",
            json=payload,
            headers=_azure_headers(),
            stream=True,
            timeout=600,
        ) as r:
            r.raise_for_status()
            for raw in r.iter_lines():
                if not raw:
                    continue
                line = (
                    raw.decode("utf-8", errors="ignore")
                    if isinstance(raw, bytes)
                    else raw
                )
                if not line.startswith("data: "):
                    continue
                chunk_str = line[6:].strip()
                if chunk_str == "[DONE]":
                    return
                try:
                    chunk = json.loads(chunk_str)
                    delta = chunk["choices"][0]["delta"].get("content") or ""
                    if delta:
                        yield delta
                except Exception:
                    pass
    except Exception as e:
        yield f"\n\n[Stream error: {e}]"


def _collect_azure(
    messages: list,
    max_tokens: int = 3000,
    tracker: Optional[TokenUsageTracker] = None,
    source: str = "azure/Kimi-K2.5",
    session_id: str | None = None,
) -> str:
    """Collect full Azure response, record token usage and Langfuse trace."""
    payload = {
        "model": AZURE_MODEL,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "stream": False,
    }
    try:
        r = requests.post(
            f"{AZURE_ENDPOINT}/chat/completions",
            json=payload,
            headers=_azure_headers(),
            timeout=600,
        )
        r.raise_for_status()
        data = r.json()
        text = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
        inp, out = extract_usage_from_azure_response(data)
        if inp == 0:
            inp = estimate_tokens_from_text(" ".join(m.get("content", "") for m in messages))
            out = estimate_tokens_from_text(text)
        if tracker:
            tracker.record(input_tokens=inp, output_tokens=out, source=source)
        # Langfuse trace
        prompt_text = "\n".join(f"[{m['role']}] {m.get('content','')}" for m in messages)
        record_generation(
            name=source,
            model=AZURE_MODEL,
            prompt=prompt_text,
            completion=text,
            input_tokens=inp,
            output_tokens=out,
            session_id=session_id,
        )
        return text or "No response generated."
    except Exception as e:
        return f"No response generated. [Error: {e}]"


def _build_messages_with_history(user_content: str, system: str, history: list) -> list:
    messages = [{"role": "system", "content": system}]
    for turn in (history or [])[-6:]:
        if turn.get("user"):
            messages.append({"role": "user", "content": turn["user"]})
        if turn.get("bot"):
            messages.append({"role": "assistant", "content": turn["bot"]})
    messages.append({"role": "user", "content": user_content})
    return messages


def _chunk_text(text: str, chunk_size: int = 180) -> Iterator[str]:
    """Yield stable-sized chunks to reduce SSE socket pressure."""
    if not text:
        return
    for i in range(0, len(text), chunk_size):
        yield text[i: i + chunk_size]


# ── Quality checks ────────────────────────────────────────────────────────────

def _looks_degenerate(text: str) -> bool:
    """Detect low-information repetitive outputs from local model."""
    if not text:
        return True
    s = text.strip()
    if len(s) < 40:
        return True
    c = Counter(s)
    top_char, top_count = c.most_common(1)[0]
    if top_count / max(1, len(s)) > 0.7 and top_char in "-*_=.#":
        return True
    words = re.findall(r"[A-Za-z0-9_]{2,}", s)
    if len(words) >= 30:
        unique_ratio = len(set(w.lower() for w in words)) / len(words)
        if unique_ratio < 0.08:
            return True
    return False


# ── Gap parsing & contract building ──────────────────────────────────────────

def _parse_fathom_output(text: str) -> tuple[str, Optional[dict]]:
    """Parse Fathom's response for enrichment gaps section."""
    gap_hdr = "=== ENRICHMENT GAPS ==="
    if gap_hdr in text:
        analysis, gap_part = text.split(gap_hdr, 1)
        analysis = analysis.strip()
        lines = [ln.strip(" -\t") for ln in gap_part.strip().splitlines() if ln.strip()]
        if not lines:
            return analysis or text.strip(), None
        if "no significant enrichment gaps detected" in lines[0].lower():
            return analysis or text.strip(), None
        return analysis or text.strip(), {
            "gaps_text": lines,
            "evidence_summary": (analysis or text)[:500],
        }

    # Backward compat: DECISION/json contract parser
    decision_match = re.search(
        r"DECISION:\s*(complete|enrichment_needed)", text, re.IGNORECASE
    )
    if not decision_match:
        return text, None
    decision = decision_match.group(1).lower()
    analysis = text[: decision_match.start()].strip()
    if decision == "complete":
        return analysis, None
    json_match = re.search(r"```json\s*([\s\S]+?)\s*```", text)
    if not json_match:
        return analysis, None
    try:
        contract = json.loads(json_match.group(1))
        contract["gaps"] = [g for g in contract.get("gaps", []) if g in VALID_GAPS]
        if not contract["gaps"]:
            return analysis, None
        return analysis, contract
    except json.JSONDecodeError:
        return analysis, None


def _contract_from_gap_text(
    query: str, analysis_text: str, cape_context: str, gap_lines: list[str]
) -> Optional[dict]:
    """Map free-text gap lines to structured enrichment contract."""
    joined = " ".join(gap_lines).lower()
    gaps: set[str] = set()
    if any(k in joined for k in ["ioc", "reputation", "passive dns", "infrastructure", "c2"]):
        gaps.add("ioc_correlation")
    if any(k in joined for k in ["sub-technique", "mitigation", "detection", "att&ck", "technique"]):
        gaps.add("attack_enrichment")
    if any(k in joined for k in ["family", "variant", "background", "historical", "context"]):
        gaps.add("family_background")
    if any(k in joined for k in ["actor", "campaign", "latest", "recent", "victim", "sector", "attribution"]):
        gaps.add("live_threat_intel")
    if not gaps:
        gaps = {"live_threat_intel", "ioc_correlation", "attack_enrichment", "family_background"}

    specific = {
        "live_threat_intel": f"Latest campaigns, actor links, and sector targeting for: {query}",
        "ioc_correlation": "Correlate extracted IOCs with reputation, passive DNS, ASN, and infrastructure clusters.",
        "attack_enrichment": "Add precise ATT&CK sub-techniques, detection opportunities, and mitigations.",
        "family_background": "Provide malware family background, related variants, and historical campaign evolution.",
    }
    ordered = ["live_threat_intel", "ioc_correlation", "attack_enrichment", "family_background"]
    return {
        "gaps": [g for g in ordered if g in gaps],
        "evidence_summary": (cape_context or analysis_text)[:500],
        "specific_questions": {g: specific[g] for g in ordered if g in gaps},
    }


def _auto_contract(query: str, raw: str, cape_context: str) -> Optional[dict]:
    """Auto-generate enrichment contract when analyst requests live intel."""
    ql = query.lower()
    _intel_trigger = any(
        kw in ql for kw in [
            "latest", "recent", "campaign", "threat actor", "attribution",
            "ioc reputation", "reputation", "infrastructure", "c2", "whois",
            "asn", "virustotal", "enrich", "correlat",
        ]
    )
    if not _intel_trigger:
        return None

    iocs = [w for w in raw.split() if w.startswith(("185.", "evil-", "http"))]
    ttps = [w.strip(".,)") for w in raw.split() if w.startswith("T1")]
    return {
        "gaps": ["live_threat_intel", "ioc_correlation", "attack_enrichment", "family_background"],
        "evidence_summary": (cape_context or raw)[:500],
        "specific_questions": {
            "live_threat_intel": f"Recent campaigns and threat actors using: {', '.join(ttps[:5]) or 'observed techniques'}",
            "ioc_correlation": f"Reputation and infrastructure of: {', '.join(iocs[:5]) or 'IOCs from analysis'}",
            "attack_enrichment": f"Sub-techniques and detections for: {', '.join(ttps[:5]) or 'process injection techniques'}",
            "family_background": "Identify malware family, infection chain, and related variants based on the evidence",
        },
    }


def _query_requests_enrichment(query: str) -> bool:
    ql = (query or "").lower()
    if "full enriched malware investigation report" in ql:
        return True
    # Fast-path: summary/QA prompts stay fast unless explicitly requesting enrichment
    if any(k in ql for k in ["summarize", "summary", "3 bullet", "bullet points",
                               "explain", "what does", "why", "how does"]):
        return False
    return any(k in ql for k in ENRICHMENT_KEYWORDS)


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC PHASE API
# ══════════════════════════════════════════════════════════════════════════════

def run_fathom_phase(
    query: str,
    cape_context: str = "",
    history: list | None = None,
    force_enrichment: bool = False,
    tracker: Optional[TokenUsageTracker] = None,
) -> tuple[str, Optional[dict]]:
    """
    Phase 1: First-pass analysis via local Fathom model.
    Falls back to Azure if Fathom is offline or returns degenerate output.

    Returns:
        (analysis_text, enrichment_contract_or_None)
    """
    raw: Optional[str] = None

    if FATHOM_ENDPOINT:
        content = query
        if cape_context:
            content = f"CAPE Evidence:\n{cape_context[:3000]}\n\nTask: {query}"
        try:
            r = requests.post(
                f"{FATHOM_ENDPOINT}/v1/chat/completions",
                json={
                    "model": "fathom",
                    "messages": [
                        {"role": "system", "content": FATHOM_ANALYSIS_PROMPT},
                        {"role": "user", "content": content},
                    ],
                    "max_tokens": 1500,
                    "temperature": 0.1,
                },
                timeout=180,
            )
            r.raise_for_status()
            raw = r.json()["choices"][0]["message"].get("content", "").strip() or None
            if raw and _looks_degenerate(raw):
                raw = None
            elif raw and tracker:
                usage = r.json().get("usage", {})
                inp = usage.get("prompt_tokens", estimate_tokens_from_text(content))
                out = usage.get("completion_tokens", estimate_tokens_from_text(raw))
                tracker.record(input_tokens=inp, output_tokens=out, source="local/fathom")
                record_generation(
                    name="fathom_phase1",
                    model="umer07/fathom-mixtral",
                    prompt=content,
                    completion=raw,
                    input_tokens=inp,
                    output_tokens=out,
                )
        except Exception:
            raw = None

    if raw is None:
        # Fathom offline — use Azure for first pass
        cape_prefix = f"CAPE Evidence:\n{cape_context[:3000]}\n\n" if cape_context else ""
        msgs = _build_messages_with_history(
            f"{cape_prefix}{query}", AZURE_DIRECT_PROMPT, history or []
        )
        raw = _collect_azure(msgs, tracker=tracker, source="azure/fathom-phase1")

    analysis_text, parsed_contract = _parse_fathom_output(raw)
    should_enrich = force_enrichment or _query_requests_enrichment(query)

    contract: Optional[dict] = None
    if should_enrich:
        if parsed_contract and parsed_contract.get("gaps_text"):
            contract = _contract_from_gap_text(
                query=query,
                analysis_text=analysis_text or raw,
                cape_context=cape_context,
                gap_lines=parsed_contract.get("gaps_text", []),
            )
        elif parsed_contract and parsed_contract.get("gaps"):
            contract = parsed_contract

    if contract is None and should_enrich:
        contract = _auto_contract(query, raw, cape_context)
        if contract is None:
            # Force full enrichment for CAPE reports
            contract = {
                "gaps": ["live_threat_intel", "ioc_correlation", "attack_enrichment", "family_background"],
                "evidence_summary": (cape_context or raw)[:500],
                "specific_questions": {
                    "live_threat_intel": "Identify latest campaigns, actor links, and targeted sectors.",
                    "ioc_correlation": "Correlate observed IOCs with reputation and infrastructure links.",
                    "attack_enrichment": "Add ATT&CK sub-techniques with detections and mitigations.",
                    "family_background": "Provide family history, related variants, and typical infection chain.",
                },
            }

    return analysis_text or raw, contract


def run_swarm_phase(contract: dict) -> tuple[str, dict]:
    """
    Phase 2: Dispatch 4 parallel Kimi agents.

    Returns:
        (formatted_enrichment_text, raw_results_dict)
    """
    from agent.azure_swarm import run_swarm, format_swarm_results

    key_map = {
        "live_threat_intel": "threat_intel",
        "family_background": "context_enrichment",
        "ioc_correlation": "ioc_correlation",
        "attack_enrichment": "attack_enrichment",
    }
    gaps = contract.get("gaps", [])
    specific_q = contract.get("specific_questions", {})
    evidence = contract.get("evidence_summary", "")

    fathom_gaps: dict[str, str] = {}
    swarm_keys: list[str] = []
    for gap in gaps:
        sk = key_map.get(gap)
        if sk:
            fathom_gaps[sk] = specific_q.get(gap, "")
            swarm_keys.append(sk)

    if not swarm_keys:
        return "", {}

    results = run_swarm(
        fathom_gaps=fathom_gaps,
        evidence_context=evidence,
        agents_to_run=swarm_keys,
    )
    return format_swarm_results(results), results


def stream_synthesis_chunks(
    fathom_analysis: str,
    swarm_enrichment: str,
    swarm_results: dict,
    query: str,
    cape_context: str = "",
    history: list | None = None,
    tracker: Optional[TokenUsageTracker] = None,
) -> Iterator[str]:
    """
    Phase 3: Stream Kimi synthesis combining all sources.
    Yields 180-char text chunks from Azure streaming API.
    """

    def _used(key: str) -> str:
        val = swarm_results.get(key, "")
        if not val or val.startswith("["):
            return "Not queried / unavailable"
        return val.strip().split("\n")[0][:120]

    synthesis_system = FATHOM_SYNTHESIS_PROMPT.format(
        threat_intel_used=_used("threat_intel"),
        attack_enrichment_used=_used("attack_enrichment"),
        ioc_used=_used("ioc_correlation"),
        context_used=_used("context_enrichment"),
    )

    cape_section = f"Original CAPE evidence:\n{cape_context[:2000]}\n\n" if cape_context else ""
    user_content = (
        f"{cape_section}"
        f"Fathom initial analysis:\n{fathom_analysis[:2000]}\n\n"
        f"Live intelligence from specialist agents:\n{swarm_enrichment[:3000]}\n\n"
        f"Original user query: {query}"
    )

    messages = _build_messages_with_history(user_content, synthesis_system, history or [])

    # Collect full text to record usage, then stream it out in chunks
    full_text = _collect_azure(messages, max_tokens=3000, tracker=tracker, source="azure/synthesis")
    yield from _chunk_text(full_text)


def stream_direct_chunks(
    query: str,
    cape_context: str = "",
    history: list | None = None,
    mode: str = "default",
    tracker: Optional[TokenUsageTracker] = None,
) -> Iterator[str]:
    """Stream a direct Azure response (no swarm) for fast/simple queries."""
    cape_prefix = f"CAPE Report Context:\n{cape_context[:3000]}\n\n" if cape_context else ""
    system_prompt = FOLLOWUP_QA_PROMPT if mode == "followup" else AZURE_DIRECT_PROMPT
    msgs = _build_messages_with_history(
        f"{cape_prefix}{query}", system_prompt, history or []
    )
    full = _collect_azure(msgs, max_tokens=3000, tracker=tracker, source="azure/direct")
    yield from _chunk_text(full)


# ══════════════════════════════════════════════════════════════════════════════
# NON-STREAMING COMPAT  (kept for /api/chat fallback)
# ══════════════════════════════════════════════════════════════════════════════

def run_investigation(
    query: str,
    cape_context: str = "",
    history: list | None = None,
    use_swarm: bool = True,
) -> str:
    """Non-streaming full pipeline. Used by /api/chat fallback."""
    tracker = TokenUsageTracker()
    analysis_text, contract = run_fathom_phase(query, cape_context, history, tracker=tracker)

    if not use_swarm or not AZURE_API_KEY or contract is None:
        return analysis_text

    swarm_enrichment, swarm_results = run_swarm_phase(contract)
    if not swarm_enrichment:
        return analysis_text

    result = (
        "".join(
            stream_synthesis_chunks(
                analysis_text, swarm_enrichment, swarm_results,
                query, cape_context, history, tracker=tracker,
            )
        ).strip()
        or analysis_text
    )

    summary = tracker.summary()
    import logging as _log
    _log.getLogger(__name__).info(
        "Token usage — input: %d, output: %d, total: %d, requests: %d",
        summary.input_tokens, summary.output_tokens,
        summary.total_tokens, summary.requests,
    )
    lf_flush()
    return result


def get_agent():
    """Compat shim — returns None (agent replaced by orchestrator)."""
    return None
