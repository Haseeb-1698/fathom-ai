# PE Static Analysis (static_pe)

## Capabilities
- Parses Windows PE32/PE32+ executables and DLLs (prefer `pefile`; graceful fallback when unavailable).
- Extracts header metadata (machine, compile timestamp, entry point, image base, TLS callbacks).
- Enumerates sections with entropy metrics, characteristics, and overlay detection.
- Enumerates imports/exports/resources and highlights suspicious API usage.
- Computes per-file and per-section entropy to flag potential packers/obfuscation.
- Runs YARA signatures from `server/detector/rules/yara/*.yar` (fail-soft if yara is missing).
- Extracts ASCII/UTF-16 strings, URLs, and suspicious keywords.
- Produces bounded Capstone disassembly snippets around the entry point (fail-soft when capstone is unavailable).
- Detects Authenticode presence (lief optional for signer details) and notes overlay size.
- Respects a 64 MB size cap; files above the cap receive a light scan with anomaly `file_too_large_for_full_scan`.

## Libraries Used
- `pefile` (preferred) for core parsing.
- Optional: `lief` for signature metadata, `capstone` for disassembly, `yara` for rule matching.
- Pure-Python fallbacks for entropy, strings, and heuristics when optional libraries are missing.

## API Routes
- `POST /api/static/pe/analyze` - multipart upload; stores sample in `server/quarantine`, writes merged JSON to `server/out/<sha>.json`, and returns `{ sha256, static, counts, errors }`.
- `GET /api/static/pe/{sha}` - loads persisted report from `server/out/<sha>.json` and returns `{ static, counts, errors }`.

## Dashboard Mapping
- Basic view shows file info, signing status, packing heuristics, high-entropy counts, suspicious imports, YARA matches, and IOC samples.
- Advanced view lists sections, imports/exports/resources, YARA details, entrypoint disassembly, overlay info, anomalies, and engine warnings.
- Static indicators/mini summary surface signed/packed/suspicious-import counts for quick triage.

## What the dashboard shows
- We parse PE headers (machine arch, compile time, entrypoint RVA).
- We detect TLS callbacks and overlay data.
- We compute per-section entropy and flag potential packing.
- We list suspicious Windows API imports (e.g., LoadLibrary, GetProcAddress, ShellExecute).
- We extract and score strings (ASCII + UTF-16) to surface IOCs and OS command usage (powershell, cmd.exe, rundll32).
- We run YARA rules against the binary to highlight known behaviors (packers, anti-debug, .NET).
- We attempt to parse Authenticode, surfacing "Signed: YES/NO" and signer when known.
- We generate bounded entrypoint disassembly with Capstone (no execution).
- The dashboard Static tab now offers a Basic risk summary and an Advanced analyst view (sections/imports/resources/disassembly/YARA).
- All analysis is offline, static-only, capped at 64 MB, and fail-soft so the API never crashes on malformed binaries.

## Acceptance Checklist
- [x] Parse PE headers, sections, and TLS callbacks.
- [x] Enumerate imports, exports, and resources with fail-soft behaviour.
- [x] Compute entropy and flag high-entropy/packer-suspect sections.
- [x] Run repository YARA rules when available and report matches.
- [x] Extract strings and IOC URLs, highlight suspicious keywords.
- [x] Provide bounded disassembly snippets (entry point focused).
- [x] Detect overlay size and Authenticode presence.
- [x] Fail-soft on missing optional libraries and respect the 64 MB analysis cap.
