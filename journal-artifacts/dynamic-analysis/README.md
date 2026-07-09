# Dynamic Analysis Artifacts

This folder contains the CAPEv2-related part of the Fathom AI journal artifacts.

## Structure

- `cape-patches/fathom-cape-integration.patch`: patch generated from the local CAPEv2 checkout. It captures tracked upstream modifications for Office/PDF handling, demux behavior, task route defaults, and KSPN report configuration.
- `cape-integration/modified-cape-files/`: reference copies of the modified CAPEv2 files after applying the patch.
- `cape-integration/modules/reporting/kspnreport.py`: CAPEv2 report module wrapper that invokes the host-side report generator.
- `cape-integration/utils/`: standalone report-generation utilities.
- `cape-integration/tests/`: focused tests for the custom reporting utilities.
- `cape-integration/run_cape_zip.sh`: local helper script retained as an operational reference.

## Reproduction Notes

Use the patch with a compatible CAPEv2 checkout:

```bash
cd CAPEv2
git apply /path/to/fathom-cape-integration.patch
```

Then copy the files from `cape-integration/` into the same relative locations in the CAPEv2 checkout if they are not already present.

Raw CAPEv2 storage, malware samples, generated reports, VM snapshots, and local environment folders are intentionally not included.
