# Static Analysis Artifact Notes

This folder contains the curated static-analysis implementation used for Fathom AI.

Included components:

- FastAPI backend and detector modules under `server/`
- static analysis logic for PDF, Office, PE/DLL, YARA, entropy, reporting, and CAPE-result normalization
- React dashboard source under `dashboard/`
- maintained pytest suite under `tests/`
- reproducibility and setup scripts under `scripts/`
- static-analysis guides, testing notes, and LaTeX report material under `docs/`

Excluded components:

- generated outputs from `server/out/`
- quarantined uploads and raw samples from `server/quarantine/`
- extracted runtime content from `server/extracted_content/`
- local virtual environments, cache folders, coverage artifacts, frontend build output, and manual one-off tests

The repository is intended to publish the method and implementation, not raw malware or private analysis inputs.
