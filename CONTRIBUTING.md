# Contributing to Fathom

First off, thank you for considering contributing to Fathom! It's people like you that make Fathom such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed and what you expected**
* **Include logs, screenshots, or screen recordings if helpful**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested enhancement**
* **Provide specific examples to demonstrate the expected behavior**
* **Explain why this enhancement would be useful**
* **List any other tools or applications that have this feature, if applicable**

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

## Development Setup

### Prerequisites

* Python 3.10+
* Node.js 18+
* Docker & Docker Compose
* (Optional) CUDA/ROCm GPU for local inference

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd dashboard
npm install
npm run dev
```

### Running with Docker

```bash
docker compose up -d
```

## Coding Standards

### Python

* Follow PEP 8 style guidelines
* Use type hints where appropriate
* Write docstrings for public functions and classes
* Keep functions focused and under 50 lines when possible

### TypeScript/React

* Use functional components with hooks
* Follow the existing component structure
* Use TypeScript types, avoid `any`

## Project Structure

```
fathom-ai/
├── backend/           # FastAPI Python backend
│   ├── agent/         # AI agents and orchestration
│   ├── api/           # API routes and schemas
│   ├── evidence/      # Evidence extraction
│   ├── graph/         # Neo4j graph operations
│   ├── llm/           # Model loading and inference
│   ├── rag/           # RAG pipeline
│   └── router/        # Domain routing
├── dashboard/         # Next.js frontend
│   ├── app/           # App router pages
│   ├── components/    # React components
│   └── lib/           # Utilities
├── training/          # Model training scripts
└── scripts/           # Utility scripts
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
