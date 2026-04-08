"""
inference.py — Generation with adapter-aware routing.

Combines: domain router → adapter selection → prompt template → RAG → generate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import torch

from config import MAX_NEW_TOKENS, TEMPERATURE, TOP_P, REPETITION_PENALTY, build_prompt
from llm.model_loader import get_model_and_tokenizer, load_adapter
from llm.adapter_registry import AdapterRegistry
from router.domain_classifier import DomainRouter
from router.prompt_templates import build_domain_prompt


@dataclass
class GenerationResult:
    text: str
    domain_id: str
    domain_name: str
    confidence: float
    adapter_used: str  # "expert-e2-dynamic", "fathom-unified-v2", or "base"
    domain_scores: dict
    tokens_generated: int = 0


# Module-level singletons (lazy-initialized)
_router: Optional[DomainRouter] = None
_registry: Optional[AdapterRegistry] = None


def _get_router() -> DomainRouter:
    global _router
    if _router is None:
        _router = DomainRouter()
    return _router


def _get_registry() -> AdapterRegistry:
    global _registry
    if _registry is None:
        _registry = AdapterRegistry()
    return _registry


def generate(
    query: str,
    evidence_text: str = "",
    rag_context: str = "",
    domain_id: str | None = None,
    max_new_tokens: int = MAX_NEW_TOKENS,
    temperature: float = TEMPERATURE,
    top_p: float = TOP_P,
) -> GenerationResult:
    """
    Full pipeline: route → adapter select → prompt → generate.

    Args:
        query: User query or analysis instruction.
        evidence_text: EvidenceBrief text from evidence extractor.
        rag_context: RAG-retrieved context text.
        domain_id: Force a specific domain (skip routing).
        max_new_tokens: Max tokens to generate.
        temperature: Sampling temperature.
        top_p: Nucleus sampling threshold.
    """
    router = _get_router()
    registry = _get_registry()

    # Step 1: Route to domain
    if domain_id is None:
        route_input = query
        if evidence_text:
            route_input += "\n" + evidence_text[:500]
        domain_id, confidence, scores = router.route(route_input)
    else:
        confidence = 1.0
        scores = {domain_id: 1.0}

    # Step 2: Select adapter
    adapter_path = registry.get_adapter_path(domain_id)
    adapter_name = "base"
    if adapter_path:
        try:
            load_adapter(str(adapter_path))
            adapter_name = adapter_path.name
        except Exception as e:
            print(f"[Inference] Adapter load failed ({adapter_path}): {e}")
            adapter_name = "base"

    # Step 3: Build prompt
    prompt = build_domain_prompt(
        domain_id=domain_id,
        query=query,
        evidence_text=evidence_text,
        rag_context=rag_context,
    )

    # Step 4: Generate
    model, tokenizer = get_model_and_tokenizer()

    # Safety check: if the prompt would be truncated, shorten evidence_text and rebuild.
    # Mixtral supports 32k context but we keep a generous budget for output.
    # Truncation that removes [/INST] causes the model to echo context instead of analyzing.
    MAX_INPUT_TOKENS = 3072
    probe = tokenizer(prompt, return_tensors="pt")
    if probe["input_ids"].shape[1] > MAX_INPUT_TOKENS and evidence_text:
        # Binary-search a safe evidence length that fits within budget
        budget_chars = len(evidence_text)
        while budget_chars > 100:
            budget_chars = int(budget_chars * 0.85)
            trimmed_prompt = build_prompt(query, evidence_text[:budget_chars])
            t = tokenizer(trimmed_prompt, return_tensors="pt")
            if t["input_ids"].shape[1] <= MAX_INPUT_TOKENS:
                prompt = trimmed_prompt
                print(f"[Inference] Evidence truncated to {budget_chars} chars to fit context window")
                break

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    try:
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,           # greedy — deterministic T-code output
                repetition_penalty=REPETITION_PENALTY,
                pad_token_id=tokenizer.pad_token_id,
            )
    except torch.cuda.OutOfMemoryError:
        # Retry with truncated evidence
        import logging as _log
        _log.getLogger(__name__).warning("CUDA OOM — retrying with truncated evidence")
        if evidence_text:
            prompt = build_domain_prompt(
                domain_id=domain_id,
                query=query,
                evidence_text=evidence_text[:1000],
                rag_context=rag_context,
            )
            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        try:
            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=False,
                    repetition_penalty=REPETITION_PENALTY,
                    pad_token_id=tokenizer.pad_token_id,
                )
        except torch.cuda.OutOfMemoryError:
            _log.getLogger(__name__).error("CUDA OOM persists — falling back to Azure")
            return _generate_azure_fallback(query, evidence_text, rag_context, domain_id, scores)

    # Decode only the new tokens
    new_tokens = outputs[0][inputs["input_ids"].shape[1]:]
    response_text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

    from config import DOMAINS
    domain_name = DOMAINS.get(domain_id, {}).get("name", domain_id)

    return GenerationResult(
        text=response_text,
        domain_id=domain_id,
        domain_name=domain_name,
        confidence=confidence,
        adapter_used=adapter_name,
        domain_scores=scores,
        tokens_generated=len(new_tokens),
    )


def _generate_azure_fallback(
    query: str,
    evidence_text: str,
    rag_context: str,
    domain_id: str,
    scores: dict,
) -> GenerationResult:
    """Azure OpenAI fallback when local GPU inference fails."""
    import os, requests as _req
    from config import DOMAINS

    azure_endpoint = os.environ.get("AZURE_ENDPOINT", "")
    azure_key = os.environ.get("AZURE_API_KEY", "")
    azure_model = os.environ.get("AZURE_MODEL", "Kimi-K2.5")

    context = ""
    if evidence_text:
        context += f"\n\nEvidence:\n{evidence_text[:3000]}"
    if rag_context:
        context += f"\n\nATT&CK Context:\n{rag_context[:1000]}"

    try:
        r = _req.post(
            f"{azure_endpoint}/chat/completions",
            headers={"api-key": azure_key, "Content-Type": "application/json"},
            json={
                "model": azure_model,
                "messages": [
                    {"role": "system", "content": "You are a malware analysis expert."},
                    {"role": "user", "content": f"{query}{context}"},
                ],
                "max_tokens": 2048,
                "temperature": 0.1,
            },
            timeout=180,
        )
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        text = f"Analysis unavailable: local GPU OOM and Azure fallback failed ({e})"

    domain_name = DOMAINS.get(domain_id, {}).get("name", domain_id)
    return GenerationResult(
        text=text,
        domain_id=domain_id,
        domain_name=domain_name,
        confidence=0.0,
        adapter_used="azure-fallback",
        domain_scores=scores,
        tokens_generated=0,
    )
