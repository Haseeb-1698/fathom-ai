# Fathom: Integrated Static, Dynamic, and LLM-Assisted Malware Analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Model](https://img.shields.io/badge/Hugging%20Face-model-ffcc4d)](https://huggingface.co/umer07/fathom-mixtral)
[![Dataset](https://img.shields.io/badge/Hugging%20Face-dataset-ffcc4d)](https://huggingface.co/datasets/umer07/fathom-expert-data)

Fathom is an on-premises malware-analysis framework that combines format-aware
static analysis, CAPE v2 dynamic analysis, and domain-specialized LLM inference.
A single sample is transformed into an analyst-oriented report containing an
executive summary, behavioral narrative, indicators of compromise, and
evidence-grounded MITRE ATT&CK mappings.

This repository is the source-code and reproducibility companion for the paper
**"Fathom: An Integrated Static, Dynamic, and LLM-Assisted Malware Analysis
Framework."**

> **Safety:** This repository contains defensive analysis software and selected
> integration artifacts. It does not include malware samples, sandbox
> credentials, model weights, or local runtime state. Run untrusted files only
> inside an isolated, properly configured malware-analysis environment.

## What Fathom contributes

- A unified workflow for PE, Office, and PDF static analysis, CAPE v2
  detonation, evidence normalization, and report generation.
- Mixtral-8x7B-Instruct with ten LoRA adapters: one unified adapter and nine
  domain experts.
- A 332,392-example cybersecurity instruction corpus assembled from 28 source
  datasets, including examples derived from raw CAPE and Joe Sandbox artifacts.
- FAISS retrieval over MITRE ATT&CK, embedding-centroid domain routing, output
  guardrails, and an optional four-agent Kimi-K2.5 enrichment stage.
- A reproducible twelve-run evaluation campaign, including failed experiments
  and known limitations.

## Architecture

```text
Sample upload
    |
    +-- Static analysis: PE / Office / PDF, YARA, strings, entropy
    |
    +-- Dynamic analysis: CAPE v2 behavior, processes, registry, network, files
    |
    v
Normalized evidence brief
    |
    +-- Domain router -> unified or expert LoRA adapter
    +-- FAISS MITRE ATT&CK retrieval
    +-- Prompt-injection and output guardrails
    |
    v
Mixtral-8x7B inference -> optional Kimi-K2.5 enrichment -> synthesis
    |
    v
ATT&CK-mapped analyst report + persisted evidence
```

The core inference and analysis path is designed for infrastructure controlled
by the analyst. The Kimi/Azure enrichment integration is optional and requires
external service credentials when enabled.

## Reported results

| Evaluation | Paper result | Reproduction record |
|---|---:|---|
| CyberMetric-500 | 88.0% (440/500) | Run 8 |
| CyberMetric-80, unified-v2 | 91.25% (73/80) | Runs 1-2 |
| ATT&CK behavior-to-technique MCQ | 80% (24/30) | Run 3 |
| Three real malscore-10 CAPE samples | Exact F1 0.868; Parent F1 0.841 | Run 7 |
| Inference-only improvement | Parent F1 0.095 -> 0.841 | Runs 4-7 |
| Adversarial prompt suite | 73% (11/15) | Run 10 |
| MI300X LoRA throughput | 15.36 tokens/s | Run 9 |

Commands, configurations, intermediate results, and failure notes are recorded
in [BENCHMARK_RESULTS_LOG.md](BENCHMARK_RESULTS_LOG.md). Raw per-run outputs are
also published with the dataset.

The central inference result required no retraining. It came from aligning
prompts with Mixtral's native `[INST]...[/INST]` template, increasing the
tokenizer context window from 3,072 to 8,192, and improving evidence extraction.

## Public artifacts

| Artifact | Location |
|---|---|
| Source code | [github.com/Haseeb-1698/fathom-ai](https://github.com/Haseeb-1698/fathom-ai) |
| Model and LoRA adapters | [umer07/fathom-mixtral](https://huggingface.co/umer07/fathom-mixtral) |
| Training corpus and benchmark outputs | [umer07/fathom-expert-data](https://huggingface.co/datasets/umer07/fathom-expert-data) |
| Journal submission artifacts | [journal-artifacts/](journal-artifacts/) |
| Twelve-run benchmark record | [BENCHMARK_RESULTS_LOG.md](BENCHMARK_RESULTS_LOG.md) |

The journal bundle contains the curated static-analysis implementation and
tests, the CAPE v2 dynamic-integration patch and selected modified files, and
combined workflow case-study documentation. See
[journal-artifacts/README.md](journal-artifacts/README.md) for its scope and
exclusions.

## Paper-to-code map

| Paper component | Implementation |
|---|---|
| Static analysis and submitted journal artifacts | [`journal-artifacts/static-analysis/`](journal-artifacts/static-analysis/) |
| CAPE integration and submitted patches | [`journal-artifacts/dynamic-analysis/`](journal-artifacts/dynamic-analysis/) |
| CAPE evidence extraction | [`backend/evidence/cape_extraction_layer_v3.py`](backend/evidence/cape_extraction_layer_v3.py) |
| Evidence-domain routing | [`backend/router/domain_classifier.py`](backend/router/domain_classifier.py) |
| Prompt construction | [`backend/router/prompt_templates.py`](backend/router/prompt_templates.py) |
| Model loading and inference | [`backend/llm/`](backend/llm/) |
| ATT&CK and sample retrieval | [`backend/rag/`](backend/rag/) |
| Guardrails | [`backend/llm/guardrails.py`](backend/llm/guardrails.py) |
| Enrichment and synthesis | [`backend/agent/`](backend/agent/) |
| Adapter training | [`training/train_expert.py`](training/train_expert.py) |
| Dataset conversion | [`backend/scripts/`](backend/scripts/) |
| FastAPI application | [`backend/`](backend/) |
| Next.js dashboard | [`dashboard/`](dashboard/) |

## Repository layout

```text
backend/             FastAPI API, evidence extraction, routing, RAG, LLM, agents
dashboard/           Next.js analyst interface
training/            PEFT/TRL training and evaluation scripts
journal-artifacts/   Curated static and dynamic artifacts submitted for review
scripts/             Database setup and import/export helpers
docker-compose.yml   Application service orchestration
```

## Quick start

### Prerequisites

- Docker with Compose
- A CAPE v2 instance for dynamic detonation
- A model inference endpoint compatible with the backend configuration
- Sufficient GPU memory for Mixtral-8x7B, or a separately hosted endpoint
- Hugging Face access token for gated model downloads

```bash
git clone https://github.com/Haseeb-1698/fathom-ai.git
cd fathom-ai
cp .env.example .env
# Review every value in .env before starting the stack.
docker compose up -d
```

The dashboard is exposed at `http://localhost:3000` by default. Service
topology, GPU-host setup, required secrets, and production hardening are
documented in [DEPLOYMENT.md](DEPLOYMENT.md). Do not expose a CAPE instance or
the sample-upload API directly to the public internet.

### Local backend tests

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
pytest backend/tests
```

On Windows PowerShell, activate the environment with
`.venv\Scripts\Activate.ps1`.

### Train an expert adapter

Training was performed with direct PEFT + TRL on an AMD Instinct MI300X using
ROCm and bf16:

```bash
python training/train_expert.py \
  --name expert-e2-dynamic \
  --datasets /path/to/e2_dynamic.jsonl \
  --output-dir /path/to/checkpoints/expert-e2-dynamic \
  --no-upload
```

Review `python training/train_expert.py --help` and the expert configuration
files before launching a run. Training Mixtral-8x7B is a high-memory workload.

## Reproducibility notes

- The paper's training environment used one AMD Instinct MI300X with ROCm 7.0
  and full bf16, without quantization.
- The public corpus contains 332,392 instruction examples from 28 sources.
- Model adapters, datasets, and benchmark predictions are hosted externally to
  keep this Git repository manageable.
- The repository intentionally excludes malware binaries, CAPE runtime state,
  secrets, VM images, and generated scan outputs.
- Full end-to-end reproduction requires a GPU host and an isolated CAPE v2
  deployment. Published predictions and logs allow the reported metrics to be
  audited without rerunning malware.

## Known limitations

- Sub-technique prediction is weaker than parent-technique prediction,
  especially for rare ATT&CK classes.
- The adversarial suite exposed prompt-injection role-override failures.
- Sparse evidence can cause unsupported malware-family or APT attribution.
- Sandbox-aware samples may produce incomplete dynamic traces.
- The complete Mixtral deployment has substantial GPU memory requirements.

These limitations and the unsuccessful bf16 v3 retraining,
LlamaFactory-on-ROCm, and RunPod A100 experiments are reported explicitly in
the paper and benchmark log.

## Authors and contributions

- **Muhammad Haseeb:** LLM training infrastructure, LoRA adapter design,
  dataset curation, FAISS retrieval, enrichment swarm, benchmark campaign, and
  inference engineering.
- **Abdul Hadi:** CAPE v2 integration, evidence extraction, dynamic-analysis
  interface, and Office/PDF static-analysis pipelines.
- **Muhammad Ammar:** PE static-analysis parser, YARA curation, Module 1
  adapter, cross-format triage, and journal artifact preparation.
- **Dr. Sana Aurangzeb:** project supervision and academic methodology.

## Citation

The manuscript is under journal review. Until its final bibliographic record is
available, cite the repository and include the access date:

```bibtex
@misc{fathom2026,
  title        = {Fathom: An Integrated Static, Dynamic, and LLM-Assisted
                  Malware Analysis Framework},
  author       = {Abdul Hadi and Muhammad Haseeb and Muhammad Ammar and
                  Sana Aurangzeb},
  year         = {2026},
  howpublished = {\url{https://github.com/Haseeb-1698/fathom-ai}},
  note         = {Source code and reproducibility artifacts}
}
```

## Documentation

- [Deployment guide](DEPLOYMENT.md)
- [Platform design](PLATFORM_DESIGN.md)
- [Enrichment integration](ENRICHMENT_INTEGRATION_GUIDE.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

Fathom is released under the [MIT License](LICENSE).
