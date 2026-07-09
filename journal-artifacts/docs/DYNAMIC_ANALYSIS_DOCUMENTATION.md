# Dynamic Malware Analysis Documentation

## 1. Purpose

This project now combines two forms of malware analysis:

- Static analysis through the Fathom/FYP backend.
- Dynamic analysis through CAPE v2.

Static analysis inspects the uploaded file without executing it. Dynamic analysis submits the same file into a controlled CAPE sandbox so the malware can be observed at runtime. The goal is to give analysts both perspectives in one workflow: what the file looks like internally, and what it actually does when executed.

The Dynamic tab in the Fathom frontend is no longer just a basic status panel. It now acts as a CAPE report viewer that can display runtime behavior, process activity, network indicators, and report metadata directly from CAPE `report.json` output.

## 2. High-Level Workflow

The integrated workflow is:

```text
Sample upload
-> Fathom static analysis
-> Static result saved as JSON
-> Same sample submitted to CAPE v2
-> CAPE runs the sample in the sandbox VM
-> CAPE processor generates report.json and HTML reports
-> Fathom backend exposes the CAPE result through API endpoints
-> Optional callback POST sends static/dynamic outputs to an external LLM endpoint
-> Fathom frontend displays the result in the Dynamic tab
```

This means the user uploads one file once. The static and dynamic pipelines then work together around the same sample.

If the LLM component runs on another device, send the sample to Fathom with a
callback URL:

```bash
curl -F "file=@sample.exe" \
     -F "callback_url=http://<llm-device>:<port>/analysis/results" \
     http://<fathom-device>:8000/api/upload
```

Fathom will POST JSON callback events to that endpoint:

- `static_completed`: sent after the static record is saved.
- `dynamic_completed`: sent after CAPE `report.json` is available.
- `dynamic_timeout`: sent if CAPE does not produce a report before timeout.
- `dynamic_failed`: sent if CAPE submission or polling fails.

Callback delivery is best-effort. A failed callback is recorded in the dynamic
state file but does not stop local analysis.

## 3. What Dynamic Analysis Does

Dynamic analysis is focused on behavior. Instead of only checking file structure, hashes, signatures, and embedded indicators, CAPE runs the sample and records what happens during execution.

The CAPE dynamic analysis captures:

- Process execution and child processes.
- API calls made by each process.
- File reads, writes, deletions, and created artifacts.
- Registry reads, writes, and deleted keys.
- Mutex creation and usage.
- Service creation or service start attempts.
- DNS requests.
- HTTP traffic when present.
- TCP and UDP connections.
- External IPs and contacted hosts.
- Dropped files.
- CAPE extracted payloads.
- CAPE extracted malware configs when available.
- Process memory and TLS dumps when available.
- CAPE errors, debug logs, and sandbox metadata.

The main CAPE JSON report is usually found here:

```text
<CAPEv2_ROOT>/storage/analyses/<task_id>/reports/report.json
```

CAPE/KSPN HTML reports are usually found here:

```text
<CAPEv2_ROOT>/storage/analyses/<task_id>/reports/kspn_report.html
```

## 4. What We Added To Fathom

### Backend Integration

The Fathom backend now contains a CAPE integration layer:

```text
journal-artifacts/static-analysis/server/cape_integration.py
```

This module handles:

- Creating a dynamic state file for each uploaded sample.
- Submitting the sample to CAPE.
- Passing ZIP files to CAPE with the archive package and password option.
- Polling CAPE until the report is generated.
- Finding `report.json`, `reports.json`, `report.html`, `reports.html`, or `kspn_report.html`.
- Summarizing CAPE results for the frontend.
- Looking up old CAPE results by analysis number or hash.

The Fathom API file was updated here:

```text
journal-artifacts/static-analysis/server/app.py
```

### Frontend Dynamic Tab

The Dynamic tab was upgraded here:

```text
journal-artifacts/static-analysis/dashboard/src/DynamicView.jsx
```

Styling was added here:

```text
journal-artifacts/static-analysis/dashboard/src/styles.css
```

The Dynamic tab now includes:

- Overview
- IOCs
- Behavior
- Processes
- Network
- Debug
- Raw JSON

The Artifacts tab was removed from the navigation because it was not the clearest way to present analyst-relevant runtime behavior. Artifact-related data can still be represented in the raw JSON and summarized through the backend where needed.

## 5. Dynamic Tab Capabilities

### Overview

The Overview section shows:

- Malware status.
- CAPE malware score.
- Number of processes.
- Number of API calls.
- Number of enhanced behavior events.
- Number of network events.
- CAPE task ID.
- File name.
- File type.
- File size.
- SHA-256.
- Analysis start and end time.
- Sandbox package and machine metadata.

### IOCs

The IOCs section shows runtime indicators:

- Domains.
- Hosts and IP addresses.
- URLs.
- Files touched.
- Registry keys touched.
- Mutexes.
- Executed commands.

This is useful because many indicators only appear when the malware actually runs.

### Behavior

The Behavior section shows:

- Read files.
- Written files.
- Deleted files.
- Read registry keys.
- Written registry keys.
- Services created or started.
- Enhanced CAPE behavior events.

This helps explain what the sample attempted to change on the system.

### Processes

The Processes section shows:

- Process tree.
- Process name.
- PID and parent PID.
- Module path.
- First-seen timestamp.
- API calls grouped by process.
- Search/filter over process names, API names, categories, and arguments.

This is one of the strongest parts of the dynamic frontend because it lets the analyst search through runtime API behavior without opening the raw CAPE JSON manually.

### Network

The Network section shows:

- DNS requests.
- HTTP requests.
- TCP connections.
- UDP connections.
- ICMP activity.
- Dead hosts.

The TCP/UDP view was improved from cramped side-by-side tables into readable connection cards. Each card shows:

- Protocol.
- Source IP and port.
- Destination IP and port.
- Time value from the CAPE report.

This makes network behavior easier to read on both desktop and smaller screens.

### Debug

The Debug section shows:

- Current integration state.
- CAPE task ID.
- CAPE analysis directory.
- JSON report path.
- HTML report path.
- CAPE errors.
- CAPE debug log excerpts.

This is useful when a sample was submitted but the report is missing, still running, or failed.

### Raw JSON

The Raw JSON section keeps the full CAPE report available to analysts.

This matters because CAPE reports are large and not every possible field can be turned into a polished UI panel. The raw JSON viewer ensures no evidence is hidden.

## 6. Existing CAPE Report Lookup

The Dynamic tab can now load an existing CAPE result even if it was not created by the current Fathom upload session.

The lookup box accepts:

- CAPE analysis number, for example `99`.
- SHA-256.
- SHA-1.
- MD5.
- Hashes found in CAPE payloads.
- Hashes found in dropped files.
- Hashes found in process memory artifacts.

Backend endpoint:

```text
GET /api/dynamic/lookup?q=<analysis_id_or_hash>
```

HTML report endpoint for looked-up CAPE tasks:

```text
GET /api/dynamic/task/<task_id>/report-html
```

Example:

```bash
curl 'http://127.0.0.1:8000/api/dynamic/lookup?q=99'
```

This was tested successfully with CAPE analysis `99`.

## 7. Where Results Are Stored

### Static Analysis Results

Static Fathom results are stored here:

```text
journal-artifacts/static-analysis/server/out/
```

Main static result format:

```text
server/out/<sha256>.json
```

Dynamic state file format:

```text
server/out/<sha256>.dynamic.json
```

Uploaded samples are stored here:

```text
server/quarantine/
```

Static PDF and Office extraction outputs are stored under:

```text
server/out/extractions/
server/out/macro_extractions/
```

### CAPE Dynamic Results

CAPE dynamic results are stored here:

```text
<CAPEv2_ROOT>/storage/analyses/<task_id>/reports/
```

Important CAPE report files:

```text
report.json
reports.json
report.html
reports.html
kspn_report.html
kspn_report_summary.json
```

## 8. What Was Tested

The local CAPE storage contains:

- 587 CAPE `report.json` dynamic analysis reports.
- 580 `kspn_report.html` reports.
- 580 `kspn_report_summary.json` reports.
- CAPE analysis IDs ranging from `2` to `593`.
- 55 Fathom static JSON reports in `server/out`.
- 2 Fathom dynamic state JSON files in `server/out`.

A bounded telemetry scan was performed across 240 CAPE reports smaller than 20 MB. Very large reports were avoided during the scan because some CAPE JSON files contain huge API-call logs.

From that 240-report sample:

- 125 reports had unknown malware status.
- 79 reports were marked `Undetected`.
- 36 reports were marked `Malicious`.
- 196 process records were observed.
- 19,472 enhanced behavior events were observed.
- 269 DNS events were observed.
- 8 TCP events were observed.
- 2,653 UDP events were observed.
- 1,806 host entries were observed.
- 269 domain entries were observed.
- 67 CAPE payload entries were observed.
- 10 CAPE config entries were observed.
- 49 dropped-file entries were observed.

Observed package types included:

- DLL analysis.
- PDF analysis.
- EXE analysis.
- DOC analysis.
- VBS analysis.
- Archive analysis.
- Edge/browser-style analysis.

This confirms that the dynamic pipeline was exercised across several malware/document types rather than only one file type.

## 9. Example High-Activity CAPE Reports

The sampled CAPE reports showed several analyses with heavy runtime activity. Examples include:

| CAPE Task | File Name | Malware Status | Malscore | Runtime Network Events |
|---:|---|---|---:|---:|
| 30 | `0e42e5927b3e7628d578.dll` | Undetected | 0 | 18 |
| 34 | `139bf62f701613c60d5b.dll` | Undetected | 0 | 16 |
| 38 | `1d2f1a8c2962658d1492.dll` | Undetected | 0 | 12 |
| 39 | `1d9427b7739d112e11fe.dll` | Undetected | 0 | 15 |
| 57 | `44f23052f2fd19cafef3.dll` | Undetected | 0 | 46 |
| 71 | `6e903365b95c58d682d2.dll` | Undetected | 0 | 40 |
| 47 | `32cad76bb888bbbf53ee.dll` | Undetected | 0 | 44 |
| 37 | `170852ad01f40abf3922.dll` | Undetected | 0 | 43 |

These examples are important because dynamic analysis is still useful even when a sample is marked `Undetected`. Runtime telemetry can still reveal DNS activity, UDP/TCP connections, process execution, file activity, registry activity, and payload extraction.

## 10. What We Should Be Proud Of

### One Upload, Two Analysis Modes

The user no longer has to manually run static and dynamic analysis separately. A single upload now triggers static analysis first and then automatically submits the same sample to CAPE.

### CAPE Integration Without Breaking Static Analysis

The original static workflow was preserved. Dynamic analysis was added after static analysis rather than replacing or interfering with it.

### Real CAPE Report Parsing

The Dynamic tab is not using fake or placeholder data. It reads real CAPE `report.json` fields and presents them in analyst-friendly sections.

### Existing Report Search

The Dynamic tab can load older CAPE reports by analysis number or hash. This is useful because CAPE already contains many previous malware runs, and analysts can inspect them without re-running the sample.

### Better Analyst Experience

Instead of forcing the analyst to open a huge JSON file manually, the frontend now separates the report into readable sections:

- Overview.
- IOCs.
- Behavior.
- Processes.
- Network.
- Debug.
- Raw JSON.

### API Call Search

The process/API call section includes filtering. This makes it easier to search for suspicious behavior such as file writes, registry changes, process creation, memory protection, or network-related APIs.

### KSPN Report Compatibility

The backend recognizes KSPN-style CAPE HTML reports:

```text
kspn_report.html
```

This lets the Fathom UI link to existing richer HTML reports when CAPE has produced them.

### Better Network Display

The TCP/UDP connection view was improved from a cramped table layout into readable cards. This makes runtime network behavior easier to understand and prevents important destination data from being clipped.

### Practical Run Script

A launcher script was created:

```text
<CAPEv2_ROOT>/run_cape_zip.sh
```

It starts the required CAPE and Fathom services and allows a user to submit a sample path directly.

## 11. How To Use The System

Start the system:

```bash
cd ~/Desktop
./run_fathom_cape.sh
```

Then open:

```text
http://127.0.0.1:5173/
```

To analyze a new sample:

1. Upload the sample in the Fathom website.
2. Wait for static analysis to complete.
3. Open the Dynamic tab.
4. Wait for CAPE status to become completed.
5. Review Overview, IOCs, Behavior, Processes, Network, Debug, or Raw JSON.

To inspect an existing CAPE result:

1. Open the Dynamic tab.
2. Use the lookup box.
3. Enter a CAPE analysis number, SHA-256, SHA-1, MD5, or artifact hash.
4. Load the result.

Example values:

```text
99
b6e579457bd4e516dbeb39f0d1a267555367c452558bb08e3333c289a922d550
```

## 12. Important Backend Endpoints

Static report:

```text
GET /api/report/<sha256>
```

Dynamic status for current uploaded sample:

```text
GET /api/dynamic/<sha256>
```

Dynamic JSON report for current uploaded sample:

```text
GET /api/dynamic/<sha256>/report-json
```

Dynamic HTML report for current uploaded sample:

```text
GET /api/dynamic/<sha256>/report-html
```

Existing CAPE report lookup:

```text
GET /api/dynamic/lookup?q=<analysis_id_or_hash>
```

Existing CAPE task HTML report:

```text
GET /api/dynamic/task/<task_id>/report-html
```

## 13. Limitations And Honest Notes

Some CAPE reports can be very large because they contain detailed API-call logs. The UI avoids rendering everything at once and gives the user structured views plus raw JSON access.

Some reports may be marked `Undetected` even when runtime behavior exists. This is expected. Dynamic analysis is not only about final malware labels; it is also about observing behavior and extracting evidence.

Some fields may be missing depending on the sample type, package, execution success, sandbox state, or CAPE module output.

If CAPE does not generate `report.json`, the Dynamic tab cannot show a completed result. In that case, the Debug section and CAPE logs should be checked.

If the CAPE processor is not running, samples may execute but reports may not be generated.

## 14. Summary

The dynamic-analysis work turns Fathom from a static-only scanner into a combined static and dynamic malware-analysis interface.

The strongest achievement is that the system now connects the full pipeline:

```text
Fathom upload
-> static analysis
-> CAPE submission
-> CAPE report discovery
-> dynamic report API
-> frontend Dynamic tab
-> existing CAPE report lookup
```

This gives the project a much more complete malware-analysis story. It can inspect the file before execution, observe it during execution, and present both sides through a single UI.
