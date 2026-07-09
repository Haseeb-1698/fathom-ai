# Dynamic Analysis Unit Tests

This folder contains focused unit tests for Fathom's dynamic-analysis modules.

The tests are intentionally offline and mocked. They do not submit malware to
CAPE, start CAPE services, or execute any sample. Instead, they build small CAPE
report fixtures and temporary analysis directories to validate:

- CAPE report path resolution and loader validation.
- Dynamic CAPE parser extraction for process, file, registry, network, and IOC data.
- Normalized dynamic-analysis schema and verdict thresholds.
- CAPE integration helpers for summaries, state files, lookup, callbacks, and
  orchestration success/failure paths.

Run from the `File Scan` project root:

```bash
python3 -m pytest tests/dynamic_analysis_unit
```

