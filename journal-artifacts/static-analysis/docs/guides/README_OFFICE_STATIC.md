# Office Static Analysis (static_office)

What it does
- Parses Microsoft Office documents in two families:
  - OOXML (docx/xlsx/pptx/docm/xlsm/pptm…): ZIP container with [Content_Types].xml
  - Legacy OLE/CFB (doc/xls/ppt): compound file with macro stream hints
- Extracts:
  - Structure: parts map, main part, relationships, external references
  - Macros: presence, auto-exec indicators, text previews (no execution)
  - Embedded payloads: name/path/size, SHA-256 of raw bytes, entropy flags
  - Metadata: Creator/LastModifiedBy/Created/Modified, Application, Company
  - Strings & IOCs: ASCII + UTF-16LE, URLs, suspicious keywords (powershell, cmd.exe, etc.)
  - Entropy: overall file, high-entropy embedded payload count
- Fail-soft, offline-only, 64MB cap

API routes
- POST `/api/static/office/analyze`
  - Multipart file upload (≤64MB). Returns `{ sha256, static.office, counts, errors }`.
- GET `/api/static/office/{sha}`
  - Loads persisted report from `server/out/{sha}.json` and returns `{ static, counts, errors }`.

Dashboard
- Static tab supports Office docs with:
  - Basic Analysis: Document Info, Behavior/Execution Surface, Content Signals, Obfuscation/Packing, Structural Anomalies
  - Advanced Analysis: parts (sample), external references, macros (autoexec flags, preview), embedded payloads, string samples, entropy hotspots, engine warnings
- StaticIndicatorsCard / StaticMiniSummary now render Office indicators for quick triage

Acceptance Checklist
- Parses OOXML containers safely (no extraction, bounded ZIP analysis)
- Best-effort legacy OLE checks (macro hints) without executing code
- Extracts metadata (authoring and app properties) when available
- Detects macro presence and auto-exec entry point strings
- Identifies external references and embedded payloads, computes SHA-256 previews
- Performs global string/IOC sweep and flags suspicious keywords
- Computes overall entropy and flags high-entropy embedded payloads
- Surfaces results in the dashboard’s Static tab with beginner and advanced views
- Returns results through `/api/static/office/*`
- Fail-soft design: never crashes API; appends to `errors`

### Macro Analysis (olevba integration)

We optionally use oletools.olevba (VBA_Parser) to statically extract and decompress VBA macros from both OOXML and legacy OLE Office documents.

- No macro execution. We only parse text, under a strict preview budget (default 8KB per module).
- We detect auto-exec entrypoints (AutoOpen, Workbook_Open, etc.) and OS command usage indicators (powershell, cmd.exe, WScript.Shell, CreateObject, ADODB.Stream, etc.).
- Results feed into:
  - `static.office.macros[]`: per-module preview and indicators (autoexec_indicators, suspicious_indicators, preview_truncated)
  - `static.office.flags`: `macro_present`, `suspicious_auto_exec`, `suspicious_shell_usage`
  - `counts.macros_total`, `counts.autoexec_macros_total`
- UI (Static tab, Basic view) surfaces:
  - "Macros: YES/NO"
  - "Auto-exec Macros: YES/NO"
  - "OS Command Indicators: YES/NO"

If `olevba` is unavailable, we fall back to heuristics and still fail-soft; errors record `olevba_unavailable` in the returned JSON.

Additional Acceptance Checklist
- Extracts and inspects VBA macros using olevba (if available), including auto-exec hooks and OS command usage
- Surfaces macro risk (Macros / Auto-exec / OS command indicators) directly in the dashboard for Office documents
