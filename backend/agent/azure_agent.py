"""
azure_agent.py — Azure AI Foundry Agent replacing local Qwen2.5 ReAct agent.

Architecture:
  • Azure AI Foundry Agent Service handles the ReAct loop + reasoning
  • GPT-4o-mini (or any catalog model) orchestrates 5 tool calls
  • Tool functions execute locally (CAPE extraction, FAISS, Neo4j)
  • One Azure endpoint replaces local model + LangChain

Flow per query:
  1. Create/reuse a persistent Azure agent (created once, cached)
  2. Open a thread, post user message
  3. Poll run → handle tool_calls → submit results
  4. Return final assistant message
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import requests

# ── Config ─────────────────────────────────────────────────────────────────────
AZURE_ENDPOINT  = os.environ.get(
    "AZURE_AGENT_ENDPOINT",
    "https://fathoms-resource.services.ai.azure.com/api/projects/fathoms",
)
AZURE_API_KEY   = os.environ.get("AZURE_API_KEY", "")
AGENT_MODEL     = os.environ.get("AZURE_AGENT_MODEL", "gpt-5.1-chat-2025-11-13")  # $1.25/$10 per 1M — best price/perf for agents
API_VERSION     = "2025-05-01"

AGENT_SYSTEM_PROMPT = """\
You are Fathom Agent, an autonomous malware investigation AI.

You have access to 5 specialist tools. For any malware analysis request, you MUST:
1. Call evidence_extract first if a CAPE report path or context is provided
2. Call fathom_analyze with the extracted evidence to get the expert analysis
3. Call attack_map to get precise MITRE ATT&CK technique IDs
4. Call ioc_lookup for any IPs, domains, or hashes found
5. Call knowledge_search for any malware family or technique you need more context on

Produce a consolidated final report with:
- Executive Summary
- ATT&CK Technique IDs (e.g. T1059.001)
- Behavioral Indicators
- IOCs (with cross-sample correlations if any)
- Threat Assessment (severity, actor attribution if possible)
"""

# ── Session headers ─────────────────────────────────────────────────────────────
def _headers() -> dict:
    return {
        "api-key": AZURE_API_KEY,
        "Content-Type": "application/json",
    }


def _url(path: str) -> str:
    return f"{AZURE_ENDPOINT}/{path.lstrip('/')}?api-version={API_VERSION}"


# ── Tool definitions (OpenAI function-calling schema) ──────────────────────────
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "fathom_analyze",
            "description": (
                "Analyze a malware sample or behavioral description using Fathom's expert pipeline. "
                "Returns domain classification, confidence score, and a detailed analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The malware behavior, API sequence, or evidence text to analyze.",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "attack_map",
            "description": (
                "Map behaviors or API calls to MITRE ATT&CK technique IDs. "
                "Returns the top matching techniques with descriptions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "A behavior description, API name, or capability to look up in ATT&CK.",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "knowledge_search",
            "description": (
                "Search the cybersecurity knowledge base for malware families, "
                "threat actors, or technique explanations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The cybersecurity topic or malware family to search for.",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ioc_lookup",
            "description": (
                "Look up an IOC (IP address, domain, file hash) in the behavior graph "
                "to check cross-sample correlations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {
                        "type": "string",
                        "description": "The IOC value: IP address, domain name, MD5/SHA256 hash.",
                    }
                },
                "required": ["ioc_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "evidence_extract",
            "description": (
                "Extract structured evidence from a CAPE sandbox report. "
                "Returns process tree, API calls, network activity, dropped files, and IOCs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cape_json": {
                        "type": "string",
                        "description": "Path to CAPE JSON report OR the raw JSON content as a string.",
                    }
                },
                "required": ["cape_json"],
            },
        },
    },
]


# ── Local tool execution ────────────────────────────────────────────────────────
def _exec_tool(name: str, arguments: dict) -> str:
    """Execute a tool locally and return its string result."""
    try:
        if name == "fathom_analyze":
            return _tool_fathom_analyze(arguments["query"])
        elif name == "attack_map":
            return _tool_attack_map(arguments["query"])
        elif name == "knowledge_search":
            return _tool_knowledge_search(arguments["query"])
        elif name == "ioc_lookup":
            return _tool_ioc_lookup(arguments["ioc_value"])
        elif name == "evidence_extract":
            return _tool_evidence_extract(arguments["cape_json"])
        else:
            return f"Unknown tool: {name}"
    except Exception as e:
        return f"Tool '{name}' error: {e}"


def _tool_fathom_analyze(query: str) -> str:
    try:
        from llm.inference import generate
        result = generate(query=query, max_new_tokens=512)
        return (
            f"[Domain: {result.domain_name} | Adapter: {result.adapter_used} | "
            f"Confidence: {result.confidence:.2f}]\n\n{result.text}"
        )
    except ImportError:
        # Demo fallback: call Azure model directly for analysis
        return _azure_analyze_fallback(query)


def _azure_analyze_fallback(query: str) -> str:
    """Use Azure model directly when local Fathom inference is unavailable."""
    from server import AZURE_ENDPOINT as base, AZURE_API_KEY as key, AZURE_MODEL as model
    headers = {"api-key": key, "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a malware analysis expert. Analyze the provided sample/behavior concisely."},
            {"role": "user", "content": query},
        ],
        "max_tokens": 512,
        "temperature": 0.1,
    }
    try:
        r = requests.post(f"{base}/chat/completions", headers=headers, json=payload, timeout=30)
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Analysis unavailable: {e}"


def _tool_attack_map(query: str) -> str:
    try:
        from rag.retriever import RAGRetriever
        retriever = RAGRetriever("attack_kb")
        return retriever.query_to_text(query, top_k=5)
    except Exception as e:
        return f"ATT&CK lookup failed: {e}"


def _tool_knowledge_search(query: str) -> str:
    try:
        from rag.retriever import RAGRetriever
        retriever = RAGRetriever("knowledge_kb")
        return retriever.query_to_text(query, top_k=5)
    except Exception:
        try:
            from rag.retriever import RAGRetriever
            return RAGRetriever("attack_kb").query_to_text(query, top_k=3)
        except Exception as e:
            return f"Knowledge search unavailable: {e}"


def _tool_ioc_lookup(ioc_value: str) -> str:
    try:
        from graph.neo4j_client import Neo4jClient
        client = Neo4jClient()
        results = client.run(
            "MATCH (i:IOC {value: $value})<-[:HAS_IOC]-(s:Sample) "
            "RETURN s.sha256 AS hash, s.name AS name, s.family AS family, s.score AS score",
            {"value": ioc_value},
        )
        if not results:
            return f"IOC '{ioc_value}' not found in the graph database."
        lines = [f"IOC '{ioc_value}' found in {len(results)} sample(s):"]
        for r in results:
            lines.append(
                f"  - {r.get('name','?')} ({r.get('family','unknown')}) "
                f"hash={str(r.get('hash','?'))[:16]}... score={r.get('score','?')}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"IOC lookup unavailable: {e}"


def _tool_evidence_extract(cape_json: str) -> str:
    # Try as file path first, then as raw JSON content
    path = Path(cape_json)
    if path.exists() and path.suffix == ".json":
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            return f"Could not read file: {e}"
    else:
        # Treat as raw JSON string or partial content
        try:
            report = json.loads(cape_json)
        except Exception:
            report = {"raw_input": cape_json}

    try:
        from evidence.cape_extraction_layer_v3 import CAPEEvidenceExtractor, ExtractorConfig
        config = ExtractorConfig(max_api_calls_per_process=5000, max_dropped_files=50)
        extractor = CAPEEvidenceExtractor(config=config)
        brief = extractor.from_report_dict(report)
        return extractor.build_expert_prompt(brief, task="full_report")
    except ImportError:
        pass
    try:
        from evidence.cape_extractor import extract_from_cape_json, format_evidence_text
        brief = extract_from_cape_json(cape_json)
        return format_evidence_text(brief)
    except Exception as e:
        return f"Evidence extraction unavailable: {e}"


# ── Azure Agent API helpers ─────────────────────────────────────────────────────
def _get_or_create_agent() -> str:
    """Return a cached agent ID, creating the Azure agent if it doesn't exist."""
    cache_file = Path(__file__).parent / ".azure_agent_id"
    if cache_file.exists():
        agent_id = cache_file.read_text().strip()
        # Verify it still exists
        r = requests.get(_url(f"assistants/{agent_id}"), headers=_headers(), timeout=10)
        if r.status_code == 200:
            return agent_id

    # Create new agent
    payload = {
        "model": AGENT_MODEL,
        "name": "fathom-investigation-agent",
        "description": "Fathom autonomous malware investigation agent",
        "instructions": AGENT_SYSTEM_PROMPT,
        "tools": TOOL_DEFINITIONS,
    }
    r = requests.post(_url("assistants"), headers=_headers(), json=payload, timeout=30)
    r.raise_for_status()
    agent_id = r.json()["id"]
    cache_file.write_text(agent_id)
    return agent_id


def _run_agent_loop(agent_id: str, user_message: str, cape_context: str = "") -> str:
    """Create a thread, post message, run agent, handle tool calls, return answer."""
    # 1. Create thread
    r = requests.post(_url("threads"), headers=_headers(), json={}, timeout=15)
    r.raise_for_status()
    thread_id = r.json()["id"]

    try:
        # 2. Add user message (inject CAPE context if present)
        content = user_message
        if cape_context:
            content = f"CAPE Report Evidence:\n{cape_context[:4000]}\n\nTask: {user_message}"

        r = requests.post(
            _url(f"threads/{thread_id}/messages"),
            headers=_headers(),
            json={"role": "user", "content": content},
            timeout=15,
        )
        r.raise_for_status()

        # 3. Create run
        r = requests.post(
            _url(f"threads/{thread_id}/runs"),
            headers=_headers(),
            json={"assistant_id": agent_id},
            timeout=15,
        )
        r.raise_for_status()
        run_id = r.json()["id"]

        # 4. Poll + handle tool calls
        for _ in range(60):  # max 2 min @ 2s intervals
            time.sleep(2)
            r = requests.get(
                _url(f"threads/{thread_id}/runs/{run_id}"),
                headers=_headers(),
                timeout=15,
            )
            r.raise_for_status()
            run = r.json()
            status = run["status"]

            if status == "completed":
                break

            elif status == "requires_action":
                tool_calls = run["required_action"]["submit_tool_outputs"]["tool_calls"]
                outputs = []
                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    fn_args = json.loads(tc["function"]["arguments"])
                    result = _exec_tool(fn_name, fn_args)
                    outputs.append({"tool_call_id": tc["id"], "output": result})

                # Submit results
                requests.post(
                    _url(f"threads/{thread_id}/runs/{run_id}/submit_tool_outputs"),
                    headers=_headers(),
                    json={"tool_outputs": outputs},
                    timeout=15,
                ).raise_for_status()

            elif status in ("failed", "cancelled", "expired"):
                err = run.get("last_error", {}).get("message", "unknown error")
                return f"Agent run {status}: {err}"

        # 5. Get final message
        r = requests.get(
            _url(f"threads/{thread_id}/messages"),
            headers=_headers(),
            timeout=15,
        )
        r.raise_for_status()
        messages = r.json().get("data", [])
        for msg in messages:
            if msg["role"] == "assistant":
                parts = msg.get("content", [])
                text_parts = [p["text"]["value"] for p in parts if p.get("type") == "text"]
                if text_parts:
                    return "\n\n".join(text_parts)

        return "No response from agent."

    finally:
        # Clean up thread (threads are ephemeral, not needed after)
        requests.delete(_url(f"threads/{thread_id}"), headers=_headers(), timeout=10)


# ── Public API ──────────────────────────────────────────────────────────────────
_cached_agent_id: Optional[str] = None


def run_investigation(query: str, cape_context: str = "", history: list | None = None) -> str:
    """
    Run an agentic investigation via Azure AI Foundry.
    Replaces the local LangChain AgentExecutor.

    Args:
        query: User question or investigation request
        cape_context: Pre-extracted CAPE report context (from /api/analyze-cape)
        history: Ignored (Azure threads handle context per-run)

    Returns:
        Consolidated investigation report as a string
    """
    global _cached_agent_id

    if not AZURE_API_KEY:
        return "Error: AZURE_API_KEY not set. Cannot reach Azure AI Foundry agent."

    try:
        if _cached_agent_id is None:
            _cached_agent_id = _get_or_create_agent()
        return _run_agent_loop(_cached_agent_id, query, cape_context)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 403:
            return (
                "Azure Agent Service: permission denied. "
                "Please assign 'Azure AI Developer' role in the Azure portal IAM settings."
            )
        return f"Azure API error: {e}"
    except Exception as e:
        return f"Agent error: {e}"
