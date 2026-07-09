PDF Full Structural Analysis (Fathom)

Module: `server/detector/pdf_full.py`

Entrypoint
- `analyze_pdf_full(path: str, config: dict | None) -> dict`
  - Returns: `{ "static": { "pdf": { ... } }, "counts": { ... }, "errors": [ ... ] }`

Config Knobs (defaults)
- `MAX_INPUT_SIZE` (64MB): reject larger input files
- `MAX_DECOMPRESSED_TOTAL` (8MB): total budget across all stream decodes
- `MAX_STREAM_PREVIEW` (8KB): per-stream decoded preview length
- `MAX_OBJECT_GRAPH_DEPTH` (50): object/action resolution depth bound
- `DECOMPRESS_TIMEOUT_SEC` (1.0s): budget for per-stream decode pipeline

Safety
- No network/process execution
- No JavaScript evaluation (preview only, decoded text is shown when safe)
- Fail-soft: append errors and return partial results

Running Tests
- Requires `pytest`
- From repo root: `pytest -q`
- Tests live in `tests/test_pdf_full.py` and generate small PDFs in-place (no internet required)

API Integration
- Routes added in `server/app.py`:
  - `POST /api/static/pdf/analyze` — upload a PDF for structural analysis
  - `GET /api/static/pdf/{sha}` — returns `static`, `counts`, `errors` from persisted report

Notes
- Some filters (`LZWDecode`, `JBIG2Decode`) are detected but not decoded; entries are marked and decoding is skipped safely. Objects with LZW add an `lzw_unsupported` annotation.
- Classic xref tables are parsed; xref streams are decoded (Flate/others) and used to populate the object offset map when possible.
- PNG-style predictor handling is attempted for Flate streams when `DecodeParms /Predictor >= 10` and `Columns` is present (filter 0 only). Failures append `predictor_parse_failed` to errors.

ACCEPTANCE CHECKLIST
- Parses all PDF revisions and trailers
- Decodes xref tables / xref streams and builds object offset map with anomaly reporting (missing EOF, multiple EOFs, duplicate xref entries, out-of-bounds offsets, non‑monotonic subsections)
- Extracts document metadata (/Info) and encryption info (/Encrypt)
- Resolves interactive / auto-exec actions (OpenAction, AA) and records URI/JS previews without execution
- Enumerates embedded files with raw SHA‑256 and size hints
- Enforces global decompression/preview budgets and never executes code
- Surfaces results via FastAPI and can be rendered in dashboard Static tab
- Fail-soft: always returns JSON with `static.pdf`, `counts`, and `errors`

## String Analysis and IOC Extraction

The analyzer performs a global, printable-string sweep (ASCII + UTF‑16LE) across the file bytes, building:

- `strings.total`, `strings.unique` counts
- `strings.ioc_urls` matched via `https?://…`
- `strings.suspicious_keywords` with common indicators: `powershell`, `cmd.exe`, `rundll32`, `WScript.Shell`, `ActiveXObject`, `shell32.dll`, `AutoOpen`
- `strings.sample_strings` (first 10 items, ≤120 chars each)

Counts extended:
- `strings_total` and `ioc_urls_total` surface to the top-level `counts`.

## Entropy Analysis

The analyzer computes Shannon entropy:

- `entropy.overall` for the whole file (cap at 4 MB)
- Per-stream entropy on raw bytes and decoded preview
- `entropy.suspicious_streams` lists any stream with entropy > 7.5 (raw/decoded), and
  `high_entropy_stream_count` counts these events; also surfaced in `counts`.

These metrics are displayed in the dashboard’s Static tab under
“Content Signals” and “Obfuscation / Packing”.

### Updated Acceptance Checklist
- Performs global string/IOC sweep
- Performs entropy analysis and flags high-entropy streams
- Surfaces both metrics in the dashboard’s Basic view
