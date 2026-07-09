# Fathom AI Journal Artifacts

This directory contains the curated static-analysis and dynamic-analysis artifacts prepared for journal/review upload.

## Contents

- `static-analysis/`: static file analysis implementation, maintained tests, frontend dashboard source, documentation, YARA integration code, and helper scripts.
- `dynamic-analysis/`: CAPEv2 integration patch, selected modified CAPEv2 files for inspection, custom CAPE reporting utilities, and focused tests.
- `docs/`: high-level case-study and evaluation documentation for the combined static/dynamic workflow.

## Excluded Material

The following local-only or unsafe materials were intentionally excluded:

- virtual environments, caches, compiled Python files, IDE settings, and build output
- generated scan outputs, generated PDF reports, coverage artifacts, and debug logs
- quarantine folders, malware samples, personal documents, and raw submitted files
- local CAPEv2 runtime state, VM/systemd configuration, batch-run logs, and notebooks/notes

For CAPEv2, this repository does not vendor the full upstream framework. Instead, it includes a patch file and the selected integration files needed to reproduce the journal changes against a CAPEv2 checkout.
