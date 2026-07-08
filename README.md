# Fathom AI

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)

**AI-Powered Malware Analysis & Threat Intelligence Platform**

[Features](#features) • [Architecture](#architecture) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Model](#model)

</div>

---

## Overview

Fathom is an advanced cybersecurity platform that leverages fine-tuned Large Language Models to automate malware analysis, threat intelligence correlation, and incident response. Built on Mixtral-8x7B with specialized LoRA adapters, Fathom provides expert-level analysis across 8 cybersecurity domains.

---

## Reproducibility

The tables below map the results and design decisions in the accompanying paper to the artifacts, source files, and benchmark runs in this repository.

### Public artifacts

| Artifact | Location | Corresponding section |
|---|---|---|
| Trained LoRA adapters (1 unified + 9 experts) | [`umer07/fathom-mixtral`](https://huggingface.co/umer07/fathom-mixtral) | §4.8 training, §6.2 per-expert results |
| Instruction corpus (332,392 rows, 28 sources) + per-run benchmark outputs | [`umer07/fathom-expert-data`](https://huggingface.co/datasets/umer07/fathom-expert-data) | §4.1 dataset; `benchmarks/` holds raw eval outputs |
| Full 12-run benchmark log | [`BENCHMARK_RESULTS_LOG.md`](BENCHMARK_RESULTS_LOG.md) | §6 (chronological, with commands and per-sample outputs) |
| Training script (direct PEFT + TRL stack) | [`training/train_expert.py`](training/train_expert.py) | §4.8, §6.6 (the LlamaFactory → PEFT+TRL switch) |
| Dataset preprocessing | [`backend/scripts/preprocess_data.py`](backend/scripts/preprocess_data.py), [`convert_evasive.py`](backend/scripts/convert_evasive.py), [`download_extended_v5.py`](backend/scripts/download_extended_v5.py) | §4.1 raw-artefact conversion pipelines |

### Reported results

Each value is recorded in [`BENCHMARK_RESULTS_LOG.md`](BENCHMARK_RESULTS_LOG.md) under the run listed, and the raw prediction files are mirrored on the Hugging Face dataset under `benchmarks/`.

| Result | Value | Benchmark run |
|---|---|---|
| CyberMetric-500 accuracy | 88.0% (440/500) | Run 8 |
| CyberMetric-80 (unified-v2) | 91.25% (73/80); base Mixtral 82.5% | Runs 1–2 |
| ATT&CK behaviour→technique MCQ (30q) | 80% (24/30) | Run 3 |
| Real CAPE pipeline (Emotet, Formbook, Dridex) | Exact F1 0.868 / Parent F1 0.841 | Run 7 |
| Inference-layer progression (no retraining) | Parent F1 0.095 → 0.429 → 0.508 → 0.841 | Runs 4–7 |
| Inference speed (MI300X, bf16) | 15.36 tok/s (base 18.76; −18.1% LoRA) | Run 9 |
| Adversarial robustness (15 prompts) | 11/15 (73%) | Run 10 |
| Mal-API-2019 family classification | 12.6% raw / 10.9% filtered | Runs 11–12 |

### Where each design decision lives in the code

The paper's central engineering finding (§6.3) is that three inference-layer fixes lift Parent F1 from 0.095 to 0.841 with no retraining. Each corresponds to a specific module here:

| Design decision (paper §6.3 / Table 4) | File |
|---|---|
| Mixtral `[INST]…[/INST]` prompt template (replaces Alpaca) | [`backend/config.py`](backend/config.py) `build_prompt()`, [`backend/router/prompt_templates.py`](backend/router/prompt_templates.py) |
| Tokenizer context window 3,072 → 8,192 + pre-truncation guard | [`backend/llm/inference.py`](backend/llm/inference.py) |
| 13-category evidence extraction with inline T-code hints | [`backend/evidence/cape_extraction_layer_v3.py`](backend/evidence/cape_extraction_layer_v3.py) |
| Embedding-centroid domain routing (8 centroids, 0.45 threshold) | [`backend/router/domain_classifier.py`](backend/router/domain_classifier.py) |
| FAISS ATT&CK retrieval (top-5) + cross-sample index | [`backend/rag/`](backend/rag/) |
| Four-agent Kimi-K2.5 enrichment swarm + synthesis | [`backend/agent/azure_swarm.py`](backend/agent/azure_swarm.py), [`backend/agent/orchestrator.py`](backend/agent/orchestrator.py) |
| Output guardrails (injection filter, hallucination checks) | [`backend/llm/guardrails.py`](backend/llm/guardrails.py) |

### Notes

- Adapters and datasets are fully public via the Hugging Face links above; the benchmark log records the exact command line for each run.
- Training used a single AMD Instinct MI300X (205.8 GB VRAM, ROCm 7.0) in full bf16 without quantisation (see `train_expert.py` and §5.1). Provide `HF_TOKEN` via an environment variable; the script contains no embedded credentials.
- The live inference stack (vLLM + CAPE sandbox + Neo4j/MinIO) requires a ROCm GPU host and a CAPE v2 instance, so end-to-end reproduction needs that hardware; the benchmark log and the Hugging Face `benchmarks/` outputs allow the reported numbers to be checked without it.
- Model weights, sandbox binaries, and VM credentials are intentionally not committed to this repository.



## Features

- 🔬 **Automated Malware Analysis** — Upload CAPE/Joe Sandbox reports and get comprehensive behavioral analysis
- 🎯 **MITRE ATT&CK Mapping** — Automatic technique and sub-technique identification with confidence scores
- 🧠 **8 Expert Domains** — Specialized adapters for static analysis, dynamic behavior, network analysis, forensics, threat intel, detection engineering, reporting, and remediation
- 🔍 **RAG-Enhanced Context** — FAISS-powered retrieval from MITRE ATT&CK knowledge base
- 📊 **Knowledge Graph** — Neo4j graph database for IOC correlation and relationship mapping
- 💬 **Interactive Chat** — Follow-up questions with streaming responses and persistent history
- 🔐 **Enterprise Auth** — Firebase authentication with Google/GitHub OAuth
- 🚀 **Scalable Deployment** — Docker Compose orchestration with GPU support

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER BROWSER                                  │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Next.js Dashboard  •  Upload → Analysis → Report → Graph    │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FastAPI Backend (Docker)                                           │
│  • Evidence Extraction  • Domain Routing  • RAG Pipeline            │
│  • Graph Operations    • Chat API        • Report Generation        │
└─────────────────────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
┌──────────────┐ ┌────────────┐ ┌─────────────┐ ┌─────────────────┐
│ Fathom Model │ │   Neo4j    │ │ FAISS Index │ │  Azure AI       │
│ Mixtral+LoRA │ │ Knowledge  │ │ Vector DB   │ │  (Enrichment)   │
│ umer07/      │ │   Graph    │ │ ATT&CK KB   │ │  Kimi Swarm     │
│ fathom-mixtral└────────────┘ └─────────────┘ └─────────────────┘
└──────────────┘
```

## Model

Fathom uses a fine-tuned Mixtral-8x7B-Instruct model with LoRA adapters:

| Component | HuggingFace Repo | Description |
|-----------|------------------|-------------|
| **Base Model** | `mistralai/Mixtral-8x7B-Instruct-v0.1` | Mixture of Experts, 46.7B parameters |
| **Fathom LoRA** | [`umer07/fathom-mixtral`](https://huggingface.co/umer07/fathom-mixtral) | Primary malware analysis adapter |
| **Expert Adapters** | `umer07/fathom-expert-data` | Domain-specific LoRA adapters |

### Expert Domains

| ID | Domain | Focus Area |
|----|--------|------------|
| E1 | Static Analysis | PE headers, imports, strings, packer detection |
| E2 | Dynamic Analysis | API calls, process trees, sandbox behavior |
| E3 | Network Analysis | C2 traffic, DNS, HTTP patterns, TLS fingerprints |
| E4 | Digital Forensics | Persistence, registry artifacts, file system |
| E5 | Threat Intelligence | APT attribution, campaigns, IOC correlation |
| E6 | Detection Engineering | YARA, Sigma rules, signature development |
| E7 | Report Generation | Structured reports, executive summaries |
| E8 | SOC Analyst | Incident response, containment, remediation |

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.10+ (for local development)
- Node.js 18+ (for frontend development)
- GPU with 48GB+ VRAM (recommended) or CPU with quantization

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/Haseeb-1698/fathom-ai.git
cd fathom-ai

# Create environment file
cp .env.example .env
# Edit .env with your API keys and configuration

# Start all services
docker compose up -d

# Access the dashboard
open http://localhost:3000
```

### Manual Setup

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 7860
```

**Frontend:**
```bash
cd dashboard
npm install
npm run dev
```

**Model Server (GPU required):**
```bash
# Download and run the inference server
python serve.py --port 8000
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `HF_TOKEN` | HuggingFace API token (for model access) | Yes |
| `AZURE_API_KEY` | Azure OpenAI key (for enrichment) | Optional |
| `AZURE_ENDPOINT` | Azure OpenAI endpoint | Optional |
| `NEO4J_PASSWORD` | Neo4j database password | Yes |
| `FIREBASE_PROJECT_ID` | Firebase project for auth | Optional |

See `.env.example` for full configuration options.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/upload` | POST | Upload CAPE JSON or PE file |
| `/api/analyze/stream` | POST | Stream analysis results (SSE) |
| `/api/chat/stream` | POST | Interactive chat with history |
| `/api/report/generate` | POST | Generate structured report |
| `/api/graph` | POST | Query Neo4j knowledge graph |
| `/api/sessions` | GET | List user chat sessions |
| `/health` | GET | Service health check |

## Documentation

- [Deployment Guide](DEPLOYMENT.md) — Production deployment instructions
- [Platform Design](PLATFORM_DESIGN.md) — Detailed architecture documentation
- [Enrichment Integration](ENRICHMENT_INTEGRATION_GUIDE.md) — Azure swarm integration
- [Dashboard Specification](dashboard/FATHOM_DASHBOARD.md) — Frontend documentation

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/

# Frontend tests
cd dashboard
npm run test
```

### Training Custom Adapters

```bash
cd training
./train_expert.py --expert e2_dynamic --dataset path/to/data.json
```

See [training/](training/) for training pipeline documentation.

## Roadmap

- [ ] Multi-file analysis (sample + memory dump + PCAP)
- [ ] Real-time collaboration on reports
- [ ] Integration with VirusTotal, Hybrid Analysis
- [ ] YARA/Sigma rule auto-generation
- [ ] Threat actor tracking dashboard

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Mistral AI](https://mistral.ai/) for Mixtral-8x7B
- [HuggingFace](https://huggingface.co/) for model hosting and PEFT
- [MITRE Corporation](https://attack.mitre.org/) for ATT&CK framework
- [CAPE Sandbox](https://capesandbox.com/) for malware analysis

---

<div align="center">

**[⬆ Back to Top](#fathom-ai)**

Made with ❤️ by the Fathom Team

</div>
