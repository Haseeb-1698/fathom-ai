"""
azure_swarm.py — Multi-agent swarm using Kimi-K2.5 tool calling.

No Assistants API needed. Each sub-agent runs a ReAct loop via
/v1/chat/completions — Kimi batches parallel tool calls natively.

Swarm pattern:
  • 4 specialized agents run in parallel Python threads
  • Each agent loops: think → call tools → observe → repeat until done
  • All 4 collapse results to orchestrator
  • ThreadPoolExecutor fans out, as_completed collapses

Sub-agents:
  ┌─ threat_intel      → live campaigns, actor attribution, recent activity
  ├─ attack_enrichment → ATT&CK sub-techniques, detection, mitigations
  ├─ ioc_correlation   → IP/domain/hash reputation, infrastructure links
  └─ context_enrichment → malware family history, infection chain
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

# ── Config ──────────────────────────────────────────────────────────────────────
AZURE_CHAT_ENDPOINT = os.environ.get(
    "AZURE_ENDPOINT",
    "https://cb26haseeb-5473-resource.openai.azure.com/openai/v1",
)
AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "")
SWARM_MODEL   = os.environ.get("AZURE_MODEL", "Kimi-K2.5")

# ── Sub-agent system prompts ────────────────────────────────────────────────────
AGENT_PROMPTS = {
    "threat_intel": (
        "You are a threat intelligence specialist embedded in the Fathom malware analysis system. "
        "Given malware behaviors, IOCs, or technique IDs, provide: "
        "recent threat campaigns using these TTPs, known threat actor groups, "
        "current prevalence and targeting, and any public reporting or advisories. "
        "Cite specific technique IDs and actor names. Be concise and factual."
    ),
    "attack_enrichment": (
        "You are a MITRE ATT&CK framework expert embedded in the Fathom malware analysis system. "
        "Given behaviors or high-level technique IDs, provide: "
        "precise sub-technique IDs (e.g. T1059.001 PowerShell), "
        "detection opportunities and data sources, "
        "applicable mitigations (M-IDs), "
        "and the full tactic → technique → sub-technique path. "
        "Always be specific with IDs."
    ),
    "ioc_correlation": (
        "You are an IOC analyst embedded in the Fathom malware analysis system. "
        "Given IPs, domains, or file hashes, provide: "
        "reputation and threat category, "
        "known infrastructure links (shared hosting, ASN, registrar patterns), "
        "associated malware families, "
        "and any known C2 or delivery infrastructure connections."
    ),
    "context_enrichment": (
        "You are a malware family historian embedded in the Fathom malware analysis system. "
        "Given a malware sample description or family name, provide: "
        "family origin and evolution history, "
        "typical infection chain and delivery mechanism, "
        "primary victim sectors and geographies, "
        "and comparison with related families or variants."
    ),
}

# ── Shared tool definitions across all sub-agents ──────────────────────────────
# Sub-agents can call these; results executed locally
SWARM_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "ioc_lookup",
            "description": "Look up an IP, domain, or file hash for reputation and cross-sample correlation in the Fathom graph database.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_value": {"type": "string", "description": "IP address, domain, MD5, or SHA256 to look up"}
                },
                "required": ["ioc_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "attack_lookup",
            "description": "Search the ATT&CK knowledge base for technique details, detection methods, and mitigations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_or_behavior": {"type": "string", "description": "ATT&CK technique ID (e.g. T1059) or behavior description"}
                },
                "required": ["technique_or_behavior"],
            },
        },
    },
]

# ── Local tool execution ────────────────────────────────────────────────────────
def _exec_tool(name: str, args: dict) -> str:
    if name == "ioc_lookup":
        return _tool_ioc_lookup(args.get("ioc_value", ""))
    elif name == "attack_lookup":
        return _tool_attack_lookup(args.get("technique_or_behavior", ""))
    return f"Unknown tool: {name}"


def _tool_ioc_lookup(value: str) -> str:
    try:
        from graph.neo4j_client import Neo4jClient
        results = Neo4jClient().run(
            "MATCH (i:IOC {value: $v})<-[:HAS_IOC]-(s:Sample) "
            "RETURN s.sha256 AS hash, s.name AS name, s.family AS family, s.score AS score",
            {"v": value},
        )
        if not results:
            return f"'{value}' not found in local graph database."
        lines = [f"'{value}' found in {len(results)} sample(s):"]
        for r in results:
            lines.append(f"  {r.get('name','?')} ({r.get('family','unknown')}) score={r.get('score','?')}")
        return "\n".join(lines)
    except Exception as e:
        return f"Graph lookup unavailable: {e}"


def _tool_attack_lookup(query: str) -> str:
    try:
        from rag.retriever import RAGRetriever
        return RAGRetriever("attack_kb").query_to_text(query, top_k=5)
    except Exception as e:
        return f"ATT&CK KB unavailable: {e}"


# ── ReAct loop for one sub-agent ────────────────────────────────────────────────
def _run_agent_loop(agent_key: str, user_message: str, max_turns: int = 6) -> str:
    """
    Single sub-agent: system prompt + user message → ReAct loop with tool calling.
    Kimi-K2.5 batches parallel tool calls in one shot.
    """
    headers = {"api-key": AZURE_API_KEY, "Content-Type": "application/json"}
    messages = [
        {"role": "system", "content": AGENT_PROMPTS[agent_key]},
        {"role": "user",   "content": user_message},
    ]

    for _ in range(max_turns):
        payload = {
            "model": SWARM_MODEL,
            "messages": messages,
            "tools": SWARM_TOOLS,
            "tool_choice": "auto",
            "max_tokens": 1024,
            "temperature": 0.1,
        }
        try:
            r = requests.post(
                f"{AZURE_CHAT_ENDPOINT}/chat/completions",
                headers=headers,
                json=payload,
                timeout=120,
            )
            r.raise_for_status()
            choice = r.json()["choices"][0]
        except Exception as e:
            return f"[{agent_key} error: {e}]"

        msg = choice["message"]
        finish = choice.get("finish_reason", "")

        # Append assistant turn
        messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": msg.get("tool_calls", [])})

        if finish == "stop" or not msg.get("tool_calls"):
            return msg.get("content") or "[no response]"

        # Execute all tool calls (Kimi may batch multiple in one response)
        for tc in msg["tool_calls"]:
            fn_name = tc["function"]["name"]
            fn_args = json.loads(tc["function"]["arguments"])
            result  = _exec_tool(fn_name, fn_args)
            messages.append({
                "role":         "tool",
                "tool_call_id": tc["id"],
                "content":      result,
            })

    # Max turns reached — return whatever the last content was
    for m in reversed(messages):
        if m["role"] == "assistant" and m.get("content"):
            return m["content"]
    return "[max iterations reached]"


# ── Task builder per sub-agent ──────────────────────────────────────────────────
def _build_task(agent_key: str, fathom_gaps: dict, evidence_context: str) -> str:
    specific = fathom_gaps.get(agent_key, "")
    evidence = evidence_context[:600] if evidence_context else ""

    base = f"Evidence context from Fathom analysis:\n{evidence}\n\n" if evidence else ""
    question = specific or {
        "threat_intel":       "Identify threat actors and recent campaigns matching these behaviors.",
        "attack_enrichment":  "Map all behaviors to precise ATT&CK sub-technique IDs with detection guidance.",
        "ioc_correlation":    "Look up all IOCs found in the evidence for reputation and infrastructure links.",
        "context_enrichment": "Identify the malware family and provide historical context and infection chain.",
    }.get(agent_key, "Provide specialist analysis.")

    return f"{base}Task: {question}"


# ── Public swarm API ────────────────────────────────────────────────────────────
def run_swarm(
    fathom_gaps: dict,
    evidence_context: str = "",
    agents_to_run: list[str] | None = None,
) -> dict[str, str]:
    """
    Fan out to sub-agents in parallel. Returns {agent_key: result_str}.

    Args:
        fathom_gaps:      {agent_key: specific_question} from Fathom's JSON contract
        evidence_context: raw evidence text for context injection
        agents_to_run:    subset of keys to run (default: all 4)
    """
    if not AZURE_API_KEY:
        return {"error": "AZURE_API_KEY not set"}

    keys = agents_to_run or list(AGENT_PROMPTS.keys())
    results: dict[str, str] = {}

    def run_one(key: str) -> tuple[str, str]:
        task = _build_task(key, fathom_gaps, evidence_context)
        return key, _run_agent_loop(key, task)

    with ThreadPoolExecutor(max_workers=len(keys)) as pool:
        futures = {pool.submit(run_one, k): k for k in keys}
        for future in as_completed(futures):
            try:
                key, result = future.result(timeout=240)
                results[key] = result
            except Exception as e:
                results[futures[future]] = f"[agent timeout/error: {e}]"

    return results


def format_swarm_results(results: dict[str, str]) -> str:
    sections = {
        "threat_intel":       "## Live Threat Intelligence",
        "attack_enrichment":  "## ATT&CK Enrichment",
        "ioc_correlation":    "## IOC Correlation",
        "context_enrichment": "## Malware Family Context",
    }
    parts = []
    for key, heading in sections.items():
        if key in results and not results[key].startswith("[agent error"):
            parts.append(f"{heading}\n{results[key]}")
    return "\n\n".join(parts)
