"""Fathom backend configuration — paths, model IDs, domain definitions."""

import os
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # fathom/
BACKEND_ROOT = Path(__file__).resolve().parent  # fathom/backend/
DATA_DIR = PROJECT_ROOT / "data"
TRAINING_DIR = PROJECT_ROOT / "training"

# Adapter storage (downloaded from HF Hub after training)
ADAPTERS_DIR = BACKEND_ROOT / "adapters"
ADAPTERS_DIR.mkdir(parents=True, exist_ok=True)

# FAISS index path
FAISS_INDEX_DIR = BACKEND_ROOT / "rag" / "index"
FAISS_INDEX_DIR.mkdir(parents=True, exist_ok=True)

# Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "change-me-in-production")

# ── Model IDs ────────────────────────────────────────────────────────────
BASE_MODEL_ID = "mistralai/Mixtral-8x7B-Instruct-v0.1"
AGENT_MODEL_ID = "Qwen/Qwen2.5-7B-Instruct"
EMBEDDING_MODEL_ID = "sentence-transformers/all-mpnet-base-v2"

# HF Hub adapter repo (private)
HF_ADAPTER_REPO = "umer07/fathom-expert-data"

# ── Precision / Quantization ─────────────────────────────────────────────
# Full BF16 on MI300 by default (no bitsandbytes quantization).
LOAD_IN_4BIT = False
BNB_4BIT_COMPUTE_DTYPE = "bfloat16"
BNB_4BIT_QUANT_TYPE = "nf4"

# ── Generation defaults ──────────────────────────────────────────────────
MAX_NEW_TOKENS = 1024
TEMPERATURE = 0.3
TOP_P = 0.9
REPETITION_PENALTY = 1.15

# ── Domain definitions (8 expert domains) ────────────────────────────────
DOMAINS = {
    "E1_static": {
        "name": "Static Analysis",
        "description": "PE header parsing, import table analysis, string extraction, packer detection",
        "adapter": "expert-e1-static",  # LlamaFactory output dir name
        "has_trained_adapter": False,  # stretch goal
        "keywords": [
            "PE",
            "import",
            "export",
            "section",
            "header",
            "packer",
            "UPX",
            "entropy",
            "string",
            "binary",
            "disassembly",
            "static",
        ],
    },
    "E2_dynamic": {
        "name": "Dynamic Behavior Analysis",
        "description": "API call sequences, process trees, behavioral traces, sandbox output",
        "adapter": "expert-e2-dynamic",
        "has_trained_adapter": True,  # confirmed
        "keywords": [
            "API",
            "process",
            "registry",
            "mutex",
            "network",
            "behavior",
            "sandbox",
            "CreateProcess",
            "WriteFile",
            "dynamic",
            "trace",
        ],
    },
    "E3_network": {
        "name": "Network Analysis",
        "description": "C2 traffic, DNS queries, HTTP patterns, TLS fingerprints",
        "adapter": None,
        "has_trained_adapter": False,
        "keywords": [
            "C2",
            "DNS",
            "HTTP",
            "TLS",
            "beacon",
            "traffic",
            "network",
            "IP",
            "domain",
            "callback",
            "JA3",
        ],
    },
    "E4_forensics": {
        "name": "Forensic Artifacts",
        "description": "Persistence mechanisms, registry artifacts, file system changes",
        "adapter": None,
        "has_trained_adapter": False,
        "keywords": [
            "persistence",
            "registry",
            "autorun",
            "scheduled task",
            "WMI",
            "forensic",
            "artifact",
            "startup",
            "service",
        ],
    },
    "E5_threatintel": {
        "name": "Threat Intelligence",
        "description": "APT attribution, campaign mapping, IOC correlation, CTI reports",
        "adapter": "expert-e5-threatintel",
        "has_trained_adapter": False,  # stretch goal
        "keywords": [
            "APT",
            "campaign",
            "threat actor",
            "IOC",
            "CTI",
            "attribution",
            "TTP",
            "intelligence",
            "adversary",
            "group",
        ],
    },
    "E6_detection": {
        "name": "Detection Engineering",
        "description": "YARA rules, Sigma rules, detection logic, signature writing",
        "adapter": None,
        "has_trained_adapter": False,
        "keywords": [
            "YARA",
            "Sigma",
            "rule",
            "detection",
            "signature",
            "alert",
            "indicator",
            "pattern",
            "heuristic",
        ],
    },
    "E7_reports": {
        "name": "Report Generation",
        "description": "Structured malware analysis reports, executive summaries, ATT&CK mapping",
        "adapter": "expert-e7-reports",
        "has_trained_adapter": True,  # confirmed
        "keywords": [
            "report",
            "summary",
            "executive",
            "ATT&CK",
            "technique",
            "finding",
            "recommendation",
            "analysis report",
            "brief",
        ],
    },
    "E8_remediation": {
        "name": "Remediation & Response",
        "description": "Incident response steps, containment, eradication, recovery",
        "adapter": None,
        "has_trained_adapter": False,
        "keywords": [
            "remediation",
            "response",
            "containment",
            "eradication",
            "recovery",
            "incident",
            "playbook",
            "mitigation",
        ],
    },
}

# Unified v2 adapter (fallback for domains without trained expert)
UNIFIED_ADAPTER = "fathom-unified-v2"


# ── Mixtral [INST] prompt format (matches Mixtral-8x7B-Instruct training format) ──
# Mixtral was trained on [INST]...[/INST] NOT Alpaca ### format.
# Using Alpaca format causes the model to echo input before generating output,
# exhausting the token budget before any analysis is produced.
def build_prompt(instruction: str, input_text: str = "") -> str:
    instruction = (instruction or "").strip()
    input_text = (input_text or "").strip()
    combined = instruction
    if input_text:
        combined += f"\n\n{input_text}"
    return f"[INST] {combined} [/INST]"
