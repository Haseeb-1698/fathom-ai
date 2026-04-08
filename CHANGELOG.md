# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open source release
- 8 expert domain adapters for specialized analysis
- Neo4j knowledge graph integration
- FAISS-powered RAG pipeline
- Azure AI swarm enrichment
- Firebase authentication
- Docker Compose deployment

## [1.0.0] - 2025-01-XX

### Added
- Core malware analysis pipeline
- CAPE sandbox report ingestion
- MITRE ATT&CK technique mapping
- Interactive chat interface
- Report generation
- Knowledge graph visualization
- Streaming analysis responses (SSE)
- Multi-session chat history

### Model
- Fine-tuned Mixtral-8x7B-Instruct with LoRA
- Published to HuggingFace: `umer07/fathom-mixtral`
- Expert adapters for 8 cybersecurity domains

### Infrastructure
- FastAPI backend with async support
- Next.js 15 dashboard
- Docker containerization
- GPU inference support (ROCm/CUDA)

[Unreleased]: https://github.com/USERNAME/fathom-ai/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/USERNAME/fathom-ai/releases/tag/v1.0.0
