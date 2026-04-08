"""
lc_agent.py — LangChain ReAct agent for Fathom malware investigation.

Uses LangChain's create_react_agent with 5 specialist tools:
  1. fathom_analyze    — local Mixtral inference via serve.py
  2. attack_map        — FAISS ATT&CK KB retrieval
  3. knowledge_search  — FAISS KB search
  4. ioc_lookup        — Neo4j cross-sample IOC correlation
  5. evidence_extract  — CAPE report structured extraction

All LLM calls are traced via Langfuse (see observability.py).
"""

from __future__ import annotations

import os
from typing import Optional

from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import tool
from langchain_openai import AzureChatOpenAI

from agent.observability import get_langfuse_callback

# ── Azure LLM (Kimi-K2.5 via Azure AI Foundry) ───────────────────────────────

def _get_llm() -> AzureChatOpenAI:
    """Build AzureChatOpenAI pointing at the Kimi-K2.5 deployment."""
    return AzureChatOpenAI(
        azure_endpoint=os.environ.get(
            "AZURE_ENDPOINT",
            "https://cb26haseeb-5473-resource.openai.azure.com/openai/v1",
        ),
        api_key=os.environ.get("AZURE_API_KEY", ""),
        azure_deployment=os.environ.get("AZURE_MODEL", "Kimi-K2.5"),
        api_version="2024-02-01",
        temperature=0.1,
        max_tokens=2048,
        streaming=False,
    )


# ── Tool definitions ──────────────────────────────────────────────────────────

@tool
def fathom_analyze(query: str) -> str:
    """Analyze malware behavior or evidence using the local Fathom model (Mixtral-8x7B + LoRA).
    Use for: generating expert malware analysis, classifying behavior, ATT&CK mapping from evidence.
    Input: a clear description of the behavior or evidence to analyze."""
    import requests as _req
    endpoint = os.environ.get("FATHOM_ENDPOINT", "http://127.0.0.1:8000")
    try:
        r = _req.post(
            f"{endpoint}/v1/chat/completions",
            json={
                "model": "fathom",
                "messages": [{"role": "user", "content": query}],
                "max_tokens": 1024,
                "temperature": 0.1,
            },
            timeout=180,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"Fathom model unavailable: {e}"


@tool
def attack_map(query: str) -> str:
    """Map behaviors or API calls to MITRE ATT&CK technique IDs using the FAISS knowledge base.
    Use for: identifying precise technique IDs (e.g. T1055.001), finding detection methods.
    Input: behavior description, API name, or capability."""
    try:
        from rag.retriever import RAGRetriever
        return RAGRetriever("attack_kb").query_to_text(query, top_k=5)
    except Exception as e:
        return f"ATT&CK lookup failed: {e}"


@tool
def knowledge_search(query: str) -> str:
    """Search the cybersecurity knowledge base for malware families, threat actors, or techniques.
    Use for: background on malware families, actor profiles, technique explanations.
    Input: malware family name, threat actor, or cybersecurity topic."""
    try:
        from rag.retriever import RAGRetriever
        return RAGRetriever("attack_kb").query_to_text(query, top_k=3)
    except Exception as e:
        return f"Knowledge search unavailable: {e}"


@tool
def ioc_lookup(ioc_value: str) -> str:
    """Look up an IOC (IP, domain, file hash) in the Neo4j behavior graph for cross-sample correlation.
    Use for: checking if an IOC appeared in other analyzed samples, finding related malware.
    Input: IP address, domain name, MD5 or SHA256 hash."""
    try:
        from graph.neo4j_client import Neo4jClient
        results = Neo4jClient().run(
            "MATCH (i:IOC {value: $value})<-[:HAS_IOC]-(s:Sample) "
            "RETURN s.sha256 AS hash, s.name AS name, s.family AS family, s.score AS score",
            {"value": ioc_value},
        )
        if not results:
            return f"IOC '{ioc_value}' not found in graph database."
        lines = [f"IOC '{ioc_value}' found in {len(results)} sample(s):"]
        for r in results:
            lines.append(
                f"  - {r.get('name','?')} ({r.get('family','unknown')}) "
                f"hash={str(r.get('hash','?'))[:16]}... score={r.get('score','?')}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"IOC lookup failed: {e}"


@tool
def evidence_extract(cape_report_json: str) -> str:
    """Extract structured behavioral evidence from a CAPE sandbox report JSON string.
    Use for: parsing raw CAPE JSON into structured evidence (processes, APIs, IOCs, TTPs).
    Input: CAPE report as a JSON string (or first 4000 chars of it)."""
    import json as _json
    try:
        report = _json.loads(cape_report_json)
    except Exception:
        return "Invalid JSON — provide the CAPE report as a valid JSON string."
    try:
        from evidence.cape_extractor import CAPEEvidenceExtractor, format_evidence_text
        extractor = CAPEEvidenceExtractor()
        brief = extractor.from_report_dict(report)
        return format_evidence_text(brief)
    except Exception as e:
        return f"Evidence extraction failed: {e}"


FATHOM_TOOLS = [fathom_analyze, attack_map, knowledge_search, ioc_lookup, evidence_extract]

# ── ReAct prompt ──────────────────────────────────────────────────────────────

REACT_PROMPT = PromptTemplate.from_template("""You are Fathom Agent, an autonomous malware investigation AI.

You have access to these tools:
{tools}

For any malware analysis request, follow this investigation sequence:
1. Use evidence_extract if raw CAPE JSON is provided
2. Use fathom_analyze with the evidence to get expert analysis
3. Use attack_map to get precise ATT&CK technique IDs
4. Use ioc_lookup for any IPs, domains, or hashes found
5. Use knowledge_search for malware family context

Produce a final consolidated report with:
- Executive Summary
- ATT&CK Technique IDs (e.g. T1059.001)
- Behavioral Indicators
- IOCs (with cross-sample correlations if any)
- Threat Assessment

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}""")


# ── Agent factory ─────────────────────────────────────────────────────────────

def build_agent_executor(callbacks: list | None = None) -> AgentExecutor:
    """Build a LangChain ReAct AgentExecutor with Fathom tools."""
    llm = _get_llm()
    agent = create_react_agent(llm, FATHOM_TOOLS, REACT_PROMPT)
    return AgentExecutor(
        agent=agent,
        tools=FATHOM_TOOLS,
        verbose=True,
        max_iterations=8,
        handle_parsing_errors=True,
        callbacks=callbacks or [],
    )


def run_lc_investigation(
    query: str,
    cape_context: str = "",
    session_id: str | None = None,
) -> str:
    """
    Run a full LangChain ReAct investigation with Langfuse tracing.

    Args:
        query: User question or analysis request
        cape_context: Pre-extracted CAPE evidence text (injected into query)
        session_id: Langfuse session ID for grouping traces

    Returns:
        Final investigation report string
    """
    from agent.observability import get_langfuse_callback

    callbacks = []
    lf_cb = get_langfuse_callback(session_id=session_id, trace_name="lc_investigation")
    if lf_cb:
        callbacks.append(lf_cb)

    executor = build_agent_executor(callbacks=callbacks)

    # Inject CAPE context into the query if provided
    full_query = query
    if cape_context:
        full_query = (
            f"CAPE Evidence (first 3000 chars):\n{cape_context[:3000]}\n\n"
            f"Task: {query}"
        )

    try:
        result = executor.invoke({"input": full_query})
        return result.get("output", str(result))
    except Exception as e:
        return f"Agent error: {e}"
