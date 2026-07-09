# Fathom FYP Combined Static + CAPE Dynamic Analysis Guide

Project: F25-057-D-Fathom

Purpose: prepare the next-round demonstration exactly around the faculty feedback:

> "Prepare case study for demonstration, first show what malware do and then identify all malicious activities from your analysis and then confirm, explain and enrich from LLM."

This document combines the FYP static-analysis material in `File Scan/` with the CAPE dynamic-analysis work described in `DYNAMIC_ANALYSIS_DOCUMENTATION.md`. It is meant to be the big master Markdown file for your team: system understanding, demo flow, case study structure, evidence mapping, and LLM enrichment plan.

---

## 1. What The Faculty Actually Wants

The comment is positive. They approved the project for the job fair, but they want the next demo to be more forensic and story-driven.

They do not only want to see that the tool runs. They want to see:

1. What the malware does.
2. How your tool identifies each malicious activity.
3. How static analysis and CAPE dynamic analysis support each other.
4. How an LLM helps explain, confirm, and enrich the findings.
5. A clean case study that feels like a real malware-analysis investigation.

So the next demo should not start with "Here is our UI." It should start with:

"Here is a suspicious file. If opened in a controlled sandbox, it performs these behaviors. Now we will use Fathom to prove and explain those behaviors."

That order matters.

---

## 2. One-Line Project Summary

Fathom is a malware-analysis platform that combines static file inspection with CAPE sandbox dynamic execution, then presents file structure, suspicious indicators, runtime behavior, IOCs, and analyst-friendly explanations in one workflow.

---

## 3. Current Project Layout

Main workspace:

```text
journal-artifacts
```

Important files and folders:

```text
DYNAMIC_ANALYSIS_DOCUMENTATION.md
how to run.txt
confidence scroing .txt
File Scan/
  README.md
  server/
    app.py
    cape_integration.py
    detector/
      hardened.py
      pdf_full.py
      pdf_enhanced.py
      office_full.py
      office_enhanced.py
      pe_full.py
      yara_loader.py
      rules/
    dynamic/
      parser.py
      normalizer.py
    report_generator.py
    out/
    quarantine/
  dashboard/
    src/
      DynamicView.jsx
      StaticView.jsx
      ReportGenerator.jsx
      YaraExplain.jsx
      SystemStatus.jsx
  docs/
    guides/
    implementation/
    testing/
  test_samples/
  tests/
```

Static-analysis part lives mainly inside:

```text
File Scan/server/detector/
File Scan/dashboard/src/StaticView.jsx
File Scan/docs/guides/
File Scan/docs/implementation/
```

Dynamic-analysis part lives mainly inside:

```text
DYNAMIC_ANALYSIS_DOCUMENTATION.md
File Scan/server/cape_integration.py
File Scan/server/dynamic/
File Scan/dashboard/src/DynamicView.jsx
<CAPEv2_ROOT>/storage/analyses/
```

---

## 4. High-Level Combined Workflow

The intended full workflow is:

```text
Sample upload
-> Fathom saves sample to quarantine
-> Static detector identifies type and extracts structural evidence
-> Static detector runs YARA and file-type-specific analyzers
-> Static JSON is written to server/out/<sha256>.json
-> Same sample is submitted to CAPE
-> CAPE executes the file in a Windows sandbox
-> CAPE generates report.json and optional HTML/KSPN reports
-> Fathom writes dynamic state to server/out/<sha256>.dynamic.json
-> Fathom frontend shows Basic, Static, Dynamic, and Report views
-> Analyst asks LLM to confirm, explain, enrich, and summarize evidence
```

The strongest product message:

```text
One suspicious file in.
Static evidence + runtime evidence + analyst explanation out.
```

---

## 5. Static Analysis: What Fathom Already Does

Static analysis means the file is inspected without executing it. This is safer and faster than dynamic analysis, and it gives a forensic view of how the file is built.

Fathom supports:

1. PDF files.
2. Microsoft Office documents.
3. PE executables and DLLs.
4. YARA rule scanning.
5. Professional PDF report generation.

### 5.1 Static Entry Point

Main backend endpoint:

```text
POST /api/upload
```

Direct static endpoints:

```text
POST /api/static/pdf/analyze
POST /api/static/office/analyze
POST /api/static/pe/analyze
GET  /api/static/pdf/{sha}
GET  /api/static/office/{sha}
GET  /api/static/pe/{sha}
```

Core detector:

```text
File Scan/server/detector/hardened.py
```

The detector identifies file type using:

1. Magic bytes and headers.
2. Structural markers.
3. Extension consistency.
4. YARA rule matches.
5. File-type-specific probes.

### 5.2 Confidence Scoring

Current confidence formula from `confidence scroing .txt`:

```text
+45 magic/header verified
+45 structural probe success
+10 extension match
-10 extension mismatch
+8 per strong YARA match
+2 per hint YARA match
+5 macro flag
Score is clamped from 0 to 100
High >= 85, Medium >= 60, Low < 60
```

Example:

```text
PDF with %PDF header, EOF marker, and .pdf extension
= 45 + 45 + 10
= 100 high confidence
```

This is important in the demo because confidence answers:

"How sure is the system about the file type and why?"

### 5.3 PDF Static Analysis

PDF analysis can detect:

1. PDF header and EOF markers.
2. Object count.
3. Stream count.
4. JavaScript objects.
5. Document actions.
6. Embedded files.
7. URLs and IOCs.
8. Suspicious keywords.
9. Metadata.
10. Encryption.
11. Entropy anomalies.
12. Structural anomalies.

Relevant modules:

```text
File Scan/server/detector/pdf_full.py
File Scan/server/detector/pdf_enhanced.py
File Scan/server/pdf_extractor.py
```

Dashboard:

```text
File Scan/dashboard/src/StaticView.jsx
File Scan/dashboard/src/PDFExtractor.jsx
```

Example static sample:

```text
File Scan/test_samples/malicious_sample.pdf
SHA-256: d26dba5bfedb361b1d17f7e4a56768efb64263ab59b6a868657188a1f334b302
```

Observed static evidence from existing JSON:

```text
Type: pdf
Confidence: 100 high
JavaScript objects: 6
Embedded files: 0
IOC URLs: 6
YARA:
  PDF_Basic_Robust
  PDF_Structure_OK
  PDF_With_JavaScript_Strict
```

JavaScript previews show:

```text
Auto-execution JavaScript - runs when PDF opens
Main malicious JavaScript payload
Payload dropper and execution
Data exfiltration module
Anti-debugging and evasion techniques
```

This is excellent case-study material because it clearly supports:

1. Auto-execution.
2. JavaScript payload.
3. Dropper-like logic.
4. Data-exfiltration intent.
5. Evasion logic.

### 5.4 Office Static Analysis

Office analysis supports:

1. OOXML documents such as docx, xlsx, pptx, docm, xlsm, pptm.
2. Legacy OLE documents such as doc, xls, ppt.
3. Macro detection.
4. Auto-exec macro indicators.
5. Suspicious shell indicators.
6. Embedded payloads.
7. External relationships.
8. Metadata extraction.
9. Strings and IOCs.
10. Entropy checks.

Relevant modules:

```text
File Scan/server/detector/office_full.py
File Scan/server/detector/office_enhanced.py
File Scan/server/office_extractor.py
```

Office static guide:

```text
File Scan/docs/guides/README_OFFICE_STATIC.md
```

Example dynamic-connected Office sample:

```text
File Scan/server/out/8a93756d5216c93984b74f02f27b5c434dc8535492cf5c1d477a742af374435d.json
Filename: 8a93756d5216c93984b74f02f27b5c434dc8535492cf5c1d477a742af374435d.xlsx
Type: office_ooxml
Confidence: 100 high
Parts: 15
Embedded payloads: 1
Macros: 0
YARA matches: 6
```

YARA matched:

```text
OOXML_Basic_Robust
OOXML_Family_Excel
OOXML_Embedded_Object_Soft
```

This supports a case-study claim like:

"The spreadsheet itself does not contain macros, but static analysis finds an embedded object surface that requires deeper analysis."

### 5.5 PE/DLL Static Analysis

PE analysis supports:

1. PE32 and PE32+ executables.
2. DLL detection.
3. Header parsing.
4. Section listing.
5. Entropy per section.
6. Import/export analysis.
7. Resource analysis.
8. Suspicious API imports.
9. Overlay detection.
10. TLS callback detection.
11. Authenticode presence.
12. Entry-point disassembly snippets when Capstone is available.
13. YARA matching.

Relevant module:

```text
File Scan/server/detector/pe_full.py
```

PE static guide:

```text
File Scan/docs/guides/README_PE_STATIC.md
```

Dynamic-connected PE sample:

```text
Filename: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c.exe
Type: pe
YARA matches: 10
CAPE task: 600
```

### 5.6 YARA Integration

YARA is one of Fathom's strongest static-analysis features.

Fathom loads:

```text
File Scan/server/detector/rules/yara
File Scan/server/detector/rules/yara-new
```

Rule categories:

```text
legacy
filetype
capability
family
research
```

Current documentation says the system contains about 1,378+ YARA rules.

YARA match objects include:

```json
{
  "rule": "PDF_With_JavaScript_Strict",
  "category": "filetype",
  "tags": ["pdf", "strong"],
  "meta": {
    "family": "pdf",
    "behavior": "embedded_js",
    "confidence": "high"
  },
  "source_file": "..."
}
```

For the demo, do not only say "YARA matched." Say:

"This rule confirms embedded JavaScript behavior. The rule metadata says behavior equals embedded_js and confidence equals high."

That sounds much more analytical.

---

## 6. CAPE Dynamic Analysis: What The New Part Adds

Dynamic analysis means the sample is executed inside a controlled sandbox. CAPE observes runtime behavior that static analysis cannot always prove.

Dynamic analysis can reveal:

1. Process execution.
2. Child processes.
3. API calls.
4. Files read, written, or deleted.
5. Registry reads, writes, and deletes.
6. Mutexes.
7. Service creation/start attempts.
8. DNS requests.
9. HTTP requests.
10. TCP/UDP connections.
11. Dropped files.
12. Extracted payloads.
13. Extracted configs.
14. Memory and TLS dumps.
15. Screenshots and PCAP.

### 6.1 CAPE Paths

CAPE root:

```text
<CAPEv2_ROOT>
```

CAPE reports:

```text
<CAPEv2_ROOT>/storage/analyses/<task_id>/reports/report.json
<CAPEv2_ROOT>/storage/analyses/<task_id>/reports/kspn_report.html
<CAPEv2_ROOT>/storage/analyses/<task_id>/reports/kspn_report_summary.json
```

### 6.2 Fathom Dynamic Integration

Main module:

```text
File Scan/server/cape_integration.py
```

It handles:

1. Creating `server/out/<sha256>.dynamic.json`.
2. Submitting the sample to CAPE.
3. Handling ZIP submissions using archive package and password.
4. Polling until CAPE report is created.
5. Finding `report.json`, `reports.json`, `report.html`, `reports.html`, or `kspn_report.html`.
6. Summarizing dynamic results.
7. Looking up existing CAPE tasks by task ID or hash.

Frontend:

```text
File Scan/dashboard/src/DynamicView.jsx
```

Dynamic UI sections:

```text
Overview
IOCs
Behavior
Processes
Network
Debug
Raw JSON
```

### 6.3 Dynamic Endpoints

```text
GET /api/dynamic/<sha256>
GET /api/dynamic/<sha256>/report-json
GET /api/dynamic/<sha256>/report-html
GET /api/dynamic/lookup?q=<analysis_id_or_hash>
GET /api/dynamic/task/<task_id>/report-html
```

### 6.4 Existing CAPE Evidence In This Workspace

Existing documentation says the CAPE storage has:

```text
587 CAPE report.json dynamic analysis reports
580 kspn_report.html reports
580 kspn_report_summary.json reports
CAPE analysis IDs from 2 to 593
55 Fathom static JSON reports
```

The current `server/out` folder contains several dynamic state files:

```text
CAPE 588: simple_js_test.pdf
CAPE 593: DLL sample
CAPE 597: ZIP sample
CAPE 598: ZIP sample
CAPE 599: XLSX sample
CAPE 600: EXE sample
```

This is enough to demonstrate that the system has handled PDF, Office, PE, DLL, and archive-style samples.

---

## 7. Recommended Next-Round Demonstration Structure

Use this exact structure in the next round.

### Step 1: Introduce The Case Study

Say:

"For this demonstration, we selected one suspicious document as a case study. We will first describe and show what it does in a controlled environment, then use Fathom static analysis, CAPE dynamic analysis, and LLM enrichment to identify and explain each malicious activity."

### Step 2: Show What The Malware Does First

This satisfies the first part of the feedback.

Show a short behavior summary before opening the tool:

```text
Observed behavior:
1. Opens as a document.
2. Triggers script or embedded-object execution surface.
3. Touches files and user/application data paths.
4. Reads or modifies registry keys.
5. Performs DNS or outbound network activity.
6. Drops or stages payload artifacts.
7. Produces IOCs: hashes, domains, IPs, file paths, registry keys.
```

If using the existing CAPE XLSX task 599:

```text
CAPE task: 599
Classification: Suspicious .NET malware
Objective: Browser data collection
Risk rating: High
Risk score: 80
Payloads: 1
Dropped files: 32
DNS/domain indicators: 10 domains
Registry writes/deletes: 210 writes and 16 deletes
MITRE:
  T1055 Process Injection
  T1112 Modify Registry
  T1547.001 Registry Run Keys / Startup Folder
  T1071 Application Layer Protocol
  T1071.004 DNS
  T1012 Query Registry
  T1083 File and Directory Discovery
```

Important: frame this as sandbox-observed behavior, then let the tool prove it.

### Step 3: Upload Or Lookup The Sample In Fathom

If running a new sample:

```text
Open http://127.0.0.1:5173/
Upload sample
Wait for static analysis
Open Static tab
Open Dynamic tab
Wait for CAPE completion
```

If using an existing CAPE result:

```text
Open Dynamic tab
Lookup CAPE task ID 599
Show Overview, IOCs, Behavior, Processes, Network, Raw JSON
```

### Step 4: Identify Malicious Activities From Fathom Evidence

Use an evidence table. This is the most important part of the demo.

Example:

| Activity | Static Evidence | Dynamic Evidence | Why It Matters |
|---|---|---|---|
| Embedded execution surface | Office static shows embedded object; YARA `OOXML_Embedded_Object_Soft` | CAPE extracted runtime payload artifact | Embedded objects can carry second-stage code |
| Registry modification | Static may show suspicious strings or embedded object only | CAPE shows registry writes/deletes | Registry writes can indicate persistence or tampering |
| Browser/profile access | Static may show document container evidence | CAPE/KSPN says browser/profile paths referenced | Browser profile access can indicate credential or data theft |
| Outbound communication | Static may reveal URLs/strings if present | CAPE shows DNS, UDP, hosts, PCAP | Network indicators support C2 or exfiltration hypotheses |
| Payload staging | Static finds embedded object or script | CAPE extracts payloads/dropped files | Confirms second-stage material exists |
| Process injection | Static may show PE/API capability if binary is available | CAPE memory payload extraction maps to T1055 | Runtime-only behavior, hard to prove statically |

### Step 5: Confirm, Explain, And Enrich From LLM

This is the final part of the feedback.

Do not make the LLM the detector. Make it the analyst assistant.

The LLM should:

1. Confirm which findings are supported by evidence.
2. Explain what each finding means.
3. Enrich with MITRE ATT&CK mapping.
4. Separate confirmed evidence from hypotheses.
5. Produce a human-readable case-study summary.
6. Recommend containment and further analysis steps.

The LLM must not invent evidence. It should cite the static and dynamic fields you give it.

---

## 8. Strongest Case Study Option

For the next round, the best approach is:

1. Use `embedded_malware_sample.pdf` or `malicious_sample.pdf` as the controlled static sample.
2. Run that same sample through CAPE before the next evaluation.
3. Use the same SHA-256 in static and dynamic evidence.
4. Export screenshots from the Fathom UI.
5. Ask the LLM to enrich only that same case.

Why this is best:

1. The static sample clearly contains suspicious PDF features.
2. The dynamic part will show what happens when it is opened in the sandbox.
3. The evidence chain is clean because both analyses refer to the same file.

### 8.1 Controlled PDF Case Study: Static Evidence Already Available

Sample:

```text
File Scan/test_samples/embedded_malware_sample.pdf
SHA-256: 917a03d663cdc46c5b103614e16ff0032fdbf2ac9bd58d6ab262db39194946fa
```

Static result:

```text
Type: pdf
Confidence: 100 high
JavaScript objects: 2
Embedded files: 3
IOC URLs: 1
YARA matches:
  PDF_Basic_Robust
  PDF_Structure_OK
  PDF_With_JavaScript_Strict
```

Embedded files discovered:

```text
backdoor.exe
  Type: PE/EXE
  Size: 128 bytes
  SHA-256: bfdf5e72651b4ec588bd5fc6a9f17e9e0972248146bbacc10478f48d72f29b81

keylogger.bat
  Type: Batch Script
  Size: 308 bytes
  SHA-256: 08929766af1035c75fe9a15d55d546bf16f761505d47a67122375e41cd99050b
  Preview indicators:
    powershell.exe -WindowStyle Hidden
    keyboard input monitoring simulation
    ping -t google.com

stealer.ps1
  Type: PowerShell script
  Size: 694 bytes
  SHA-256: 0e6c50fc8550d74a62a91f6500f5b2a85d7282596a9624cbb50b0c3b7c21b726
  Preview indicators:
    Collects computer name, username, OS, architecture, domain
    References browser profile paths
    Uses Invoke-RestMethod
    Exfiltration URL: http://data-collector.malicious.com/upload
```

This case study is very strong because it lets you say:

"Before execution, static analysis already finds an embedded executable, a batch script, and a PowerShell stealer. CAPE dynamic analysis should then confirm whether these payloads execute, whether files are dropped, whether PowerShell starts, and whether network activity occurs."

### 8.2 Controlled PDF Case Study: What To Show In Demo

Start with the malware behavior story:

```text
This PDF is designed as a document-based dropper.
It contains JavaScript that attempts to trigger activity when opened.
It embeds three payload-like files:
  backdoor.exe
  keylogger.bat
  stealer.ps1
The PowerShell payload collects host/user/browser-related information and posts it to a remote URL.
```

Then show Fathom proof:

```text
Basic tab:
  Type: PDF
  Confidence: 100 high
  Detection reason: %PDF header and EOF marker
  YARA: PDF_With_JavaScript_Strict

Static tab:
  JavaScript present
  Embedded files present
  Embedded payload hashes
  Script previews
  IOC URL

Dynamic tab after CAPE run:
  Process tree
  File writes/drops
  PowerShell or child process activity if triggered
  DNS/HTTP/TCP/UDP indicators
  Dropped files and CAPE payloads
  Raw report evidence

LLM enrichment:
  Explains dropper behavior
  Maps to MITRE
  Separates confirmed vs suspected behavior
  Produces analyst report summary
```

---

## 9. Existing CAPE Case Study: XLSX Task 599

Until the PDF sample is run through CAPE, you can also demonstrate existing CAPE task 599.

Static sample:

```text
Filename: 8a93756d5216c93984b74f02f27b5c434dc8535492cf5c1d477a742af374435d.xlsx
SHA-256: 8a93756d5216c93984b74f02f27b5c434dc8535492cf5c1d477a742af374435d
Fathom type: office_ooxml
Confidence: 100 high
Parts: 15
Embedded payloads: 1
YARA matches: 6
```

Static interpretation:

```text
The file is a valid Excel OOXML container.
It contains an embedded object surface.
It has no detected macros.
YARA confirms Excel OOXML and embedded-object indicators.
```

CAPE dynamic evidence:

```text
CAPE task: 599
Classification: Suspicious .NET malware
Objective: Browser data collection
Risk rating: High
Risk score: 80
Payload artifacts: 1
Dropped files: 32
Domains: 10
Registry writes: 210
Registry deletes: 16
Registry reads: 6032
Screenshots: 127
PCAP: true
```

MITRE enrichment from KSPN summary:

```text
T1055 Process Injection
T1112 Modify Registry
T1547.001 Registry Run Keys / Startup Folder
T1071 Application Layer Protocol
T1071.004 DNS
T1012 Query Registry
T1083 File and Directory Discovery
```

Capabilities:

```text
Credential or browser data access
Registry modification
In-memory unpacking or secondary payload material
Outbound network activity
```

How to explain it:

"Static analysis tells us the spreadsheet is an OOXML Excel file with an embedded-object surface. CAPE then shows the runtime impact: payload extraction, dropped files, registry activity, browser/profile-related access, and outbound network indicators. The LLM enrichment turns that raw evidence into a readable analyst conclusion and MITRE mapping."

Important caveat:

"Because dynamic reports include benign application noise from Office/Windows, the LLM and analyst must separate normal application behavior from maliciously relevant evidence. This is why the evidence matrix is essential."

---

## 10. Existing CAPE Case Study: PDF Task 588

Static sample:

```text
Filename: simple_js_test.pdf
SHA-256: 9d567b6a2521d021d9444c9c261a5889cdc337e1d90f20591f69b959a5ec6e22
Fathom type: pdf
Confidence: 100 high
JavaScript objects: 2
YARA matches: 6
```

Static interpretation:

```text
The sample is a valid PDF.
It contains JavaScript.
YARA confirms embedded JavaScript behavior.
```

CAPE dynamic state:

```text
CAPE task: 588
Status: completed
Malscore: 0.0
Network hosts: 15
DNS events: 4
UDP events: 26
Dropped files: 25
CAPE payloads: 6
```

KSPN summary:

```text
Classification: Credential theft / infostealer
Objective: Credential theft and data collection
Risk rating: High
Risk score: 95
Payloads: 6
Dropped files: 25
PCAP: true
```

MITRE enrichment:

```text
T1055 Process Injection
T1112 Modify Registry
T1547.001 Registry Run Keys / Startup Folder
T1071 Application Layer Protocol
T1071.004 DNS
T1012 Query Registry
T1083 File and Directory Discovery
```

How to use this safely in the demo:

Use it as a demonstration of the dynamic viewer and LLM enrichment, but be honest that the static sample is a simple JavaScript PDF. If an evaluator asks, say:

"This existing CAPE task demonstrates the dynamic report pipeline. For the final case study, we will use the same file across static and dynamic analysis to avoid mixing evidence from different sample complexities."

---

## 11. Evidence Matrix Template For The Final Demo

Use this table in your slides or report.

| Malicious Activity | Evidence Source | Exact Evidence | Confidence | Explanation | MITRE |
|---|---|---|---|---|---|
| Script execution surface | Static PDF/Office | JavaScript object, macro, embedded object, YARA match | High/Medium | Explains how code can start from a document | T1204, T1059 |
| Payload embedding | Static PDF/Office | Embedded EXE/BAT/PS1/object with SHA-256 | High | Document carries second-stage payload | T1204, T1027 |
| Process execution | CAPE process tree/API calls | Child process, command line, API calls | High if observed | Runtime proof of execution | T1059 |
| File creation/drop | CAPE dropped/files | Dropped file path and hash | High | Confirms payload staging on disk | T1105/T1027 |
| Registry modification | CAPE registry summary | Write/delete key counts and paths | High | Supports persistence or tampering | T1112, T1547.001 |
| Network communication | CAPE network/PCAP | DNS, HTTP, TCP, UDP, hosts | Medium/High | Supports C2 or exfil hypothesis | T1071 |
| Credential/browser data access | Static strings or dynamic paths | Browser profile paths, credential paths | Medium/High | Supports data theft objective | T1555 |
| Exfiltration | Static URL or dynamic HTTP | POST/Invoke-RestMethod/remote URL | High if both static and dynamic | Confirms data leaving host | T1041 |
| Injection/unpacking | CAPE payload/memory | CAPE payload extraction/injected data | Medium/High | Indicates in-memory staging | T1055 |
| Evasion | Static strings/dynamic behavior | Anti-debug strings, sandbox checks | Medium | Explains avoidance behavior | T1497 |

---

## 12. LLM Enrichment Design

The LLM should sit after static and dynamic evidence extraction.

Correct role:

```text
Evidence explainer and report writer
```

Wrong role:

```text
Primary detector
```

The LLM should not be allowed to invent new indicators. It should only explain what Fathom and CAPE have already found.

### 12.1 LLM Input

Give the LLM a compact evidence packet:

```json
{
  "sample": {
    "filename": "...",
    "sha256": "...",
    "type": "...",
    "confidence": 100
  },
  "static": {
    "yara_matches": [],
    "javascript": [],
    "macros": [],
    "embedded_files": [],
    "strings": [],
    "urls": []
  },
  "dynamic": {
    "processes": [],
    "file_activity": [],
    "registry_activity": [],
    "network_activity": [],
    "dropped_files": [],
    "payloads": []
  },
  "kspn_or_cape_summary": {
    "classification": "...",
    "risk_score": 0,
    "mitre": [],
    "capabilities": []
  }
}
```

### 12.2 LLM System Prompt

Use this:

```text
You are a malware-analysis report assistant. You must only use the evidence provided by Fathom static analysis and CAPE dynamic analysis. Do not invent indicators, file paths, domains, registry keys, or malware-family names. Separate confirmed evidence from hypotheses. Explain findings in clear language for faculty evaluators. When possible, map findings to MITRE ATT&CK techniques and state why the mapping is justified.
```

### 12.3 LLM User Prompt

Use this:

```text
Analyze this malware case study evidence.

Tasks:
1. Summarize what the sample does.
2. List each malicious activity.
3. For each activity, cite static evidence and dynamic evidence separately.
4. Mark each activity as Confirmed, Likely, or Hypothesis.
5. Explain the technical meaning in simple language.
6. Add MITRE ATT&CK mapping where justified.
7. Provide containment recommendations.
8. Provide a 60-second demo narration.

Evidence:
<paste compact JSON evidence packet here>
```

### 12.4 LLM Output Format

Ask for this format:

```text
Executive Summary
Confirmed Behaviors
Likely Behaviors
Evidence Matrix
MITRE Mapping
Indicators of Compromise
Analyst Explanation
Containment Recommendations
Demo Narration
Limitations
```

### 12.5 Example LLM Enrichment For Embedded PDF

Example wording:

```text
The sample is a malicious PDF-style dropper. Static analysis confirms a valid PDF structure with embedded JavaScript and three embedded payload-like files: an EXE, a batch script, and a PowerShell script. The PowerShell preview contains host/user collection and browser-profile path references, and it includes an HTTP upload endpoint. This supports a likely data-theft objective. If CAPE confirms PowerShell execution, dropped files, or network traffic to the same endpoint, the behavior becomes confirmed rather than only static-intent evidence.
```

This is exactly the kind of explanation faculty want.

---

## 13. Demo Script

Use this script in the next round.

### Opening

```text
Our previous demo showed that Fathom can scan files. For this round, we prepared a case study. We will first show what the suspicious document does, then prove each behavior through static analysis, CAPE dynamic execution, and LLM-assisted explanation.
```

### Show Behavior First

```text
In the sandbox, this sample shows document-based execution behavior. It exposes an execution surface, stages payload artifacts, touches system/user paths, performs registry activity, and produces network indicators. Now we will use Fathom to identify exactly where these behaviors come from.
```

### Static Analysis

```text
The Basic tab identifies the file type and confidence. The Static tab explains why: PDF/Office/PE structure, YARA matches, JavaScript or macro indicators, embedded payloads, strings, URLs, and hashes. This tells us what the file is capable of before execution.
```

### Dynamic Analysis

```text
The Dynamic tab loads CAPE report.json. Here we see what happened at runtime: processes, file activity, registry activity, network traffic, dropped files, payloads, and raw JSON evidence. This confirms which static suspicions actually happened in the sandbox.
```

### LLM Enrichment

```text
Finally, we pass the evidence packet to the LLM. The LLM does not detect malware by itself; it explains and enriches our evidence. It separates confirmed findings from hypotheses, maps behavior to MITRE ATT&CK, and generates a readable analyst summary.
```

### Closing

```text
So the value of Fathom is not only detection. It creates a complete analysis chain: suspicious file, static indicators, dynamic behavior, IOC extraction, MITRE mapping, and report-ready explanation.
```

---

## 14. Commands To Run The System

From `how to run.txt`:

### Backend

```bash
cd "journal-artifacts/static-analysis/server"
/tmp/file_scan_venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Check:

```text
http://127.0.0.1:8000/api/status
```

### Frontend

```bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm use 20
cd "journal-artifacts/static-analysis/dashboard"
npm run dev
```

Open:

```text
http://127.0.0.1:5173/
```

### API Upload Test

```bash
curl -sS -X POST \
  -F file=@"journal-artifacts/static-analysis/test_samples/embedded_malware_sample.pdf" \
  http://127.0.0.1:8000/api/upload
```

### Dynamic Lookup Test

```bash
curl 'http://127.0.0.1:8000/api/dynamic/lookup?q=599'
```

### Static Report Download

```text
POST /api/report/generate/{sha}
GET  /api/report/download/{filename}
```

---

## 15. What To Prepare Before The Next Evaluation

### 15.1 Must-Have Preparation

Prepare one final case study folder:

```text
case_study/
  sample/
    selected_sample.pdf or selected_sample.xlsx
  evidence/
    static_report.json
    dynamic_state.json
    cape_report_summary.json
    llm_enrichment.md
  screenshots/
    01_behavior_first.png
    02_basic_tab.png
    03_static_tab_yara.png
    04_static_tab_payloads.png
    05_dynamic_overview.png
    06_dynamic_iocs.png
    07_dynamic_processes.png
    08_dynamic_network.png
    09_llm_enrichment.png
  final_case_study_report.md
```

### 15.2 Required Demo Artifacts

Have these ready:

1. Original sample hash.
2. Static JSON output.
3. CAPE task ID.
4. CAPE `report.json`.
5. KSPN summary if available.
6. PDF report generated by Fathom.
7. LLM enriched Markdown report.
8. Evidence matrix slide.
9. 60-second explanation script.

### 15.3 Do Not Skip This

Run the same sample through both static and dynamic analysis before the evaluation.

Avoid mixing:

```text
Static sample A
Dynamic sample B
```

Use:

```text
Same sample
Same SHA-256
Static evidence + dynamic evidence
```

That will make the demo much stronger.

---

## 16. Suggested Final Case Study Report Structure

Use this as the report table of contents:

```text
1. Case Study Objective
2. Sample Identity
3. Behavior First: What The Malware Does
4. Static Analysis Findings
5. CAPE Dynamic Analysis Findings
6. Evidence Correlation Matrix
7. LLM Confirmation And Enrichment
8. MITRE ATT&CK Mapping
9. Indicators Of Compromise
10. Risk Assessment
11. Containment And Recommendations
12. Limitations
13. Appendix: Raw Evidence References
```

### 16.1 Sample Identity Section

Include:

```text
Filename
SHA-256
MD5/SHA-1 if available
File size
File type
Analysis date
CAPE task ID
Sandbox package
```

### 16.2 Behavior First Section

Write:

```text
The sample was executed in CAPE under a controlled Windows sandbox. Runtime telemetry showed the following behavior...
```

Then list behaviors.

### 16.3 Static Findings Section

Write:

```text
Static analysis identified the file as <type> with <confidence> confidence because <reasons>. The file contained the following suspicious static indicators...
```

Then list:

1. YARA matches.
2. JavaScript/macros/embedded objects.
3. Embedded payloads.
4. URLs/strings.
5. Entropy or structural anomalies.

### 16.4 Dynamic Findings Section

Write:

```text
CAPE dynamic analysis observed the following runtime behavior...
```

Then list:

1. Processes.
2. File activity.
3. Registry activity.
4. Network activity.
5. Dropped files.
6. Payloads.
7. PCAP/screenshots.

### 16.5 LLM Enrichment Section

Write:

```text
The LLM was provided with structured Fathom and CAPE evidence. It was instructed not to invent indicators and to separate confirmed findings from hypotheses.
```

Then include:

1. LLM summary.
2. Confirmed findings.
3. MITRE mapping.
4. Plain-English explanation.
5. Recommendations.

---

## 17. How To Answer Faculty Questions

### Question: What is new in your project?

Answer:

```text
The project combines static analysis and CAPE dynamic analysis in one workflow. Static analysis identifies file structure, YARA matches, scripts, macros, payloads, and IOCs without execution. CAPE dynamic analysis confirms runtime behavior such as processes, file changes, registry changes, network activity, dropped files, and extracted payloads. We then use an LLM as an explanation layer to convert raw evidence into a case-study report.
```

### Question: Why do you need both static and dynamic analysis?

Answer:

```text
Static analysis is safe and fast, and it shows what is inside the file. Dynamic analysis shows what actually happens when the sample runs. Some behaviors are visible only statically, such as embedded scripts. Other behaviors are visible only dynamically, such as registry writes, child processes, and network traffic. Together they reduce uncertainty.
```

### Question: Does the LLM detect malware?

Answer:

```text
No. The LLM does not replace Fathom or CAPE. It receives evidence produced by our static and dynamic analyzers, then explains, correlates, and enriches it. We instruct it to separate confirmed evidence from hypotheses and not invent indicators.
```

### Question: How do you avoid false claims from the LLM?

Answer:

```text
We use evidence-grounded prompting. The LLM receives structured evidence only, and the output must cite whether each behavior came from static analysis, dynamic analysis, or both. Anything not directly supported is marked as a hypothesis or omitted.
```

### Question: Why can CAPE show activity when static score is low?

Answer:

```text
Static score depends on visible structure and signatures. Dynamic behavior can still reveal activity caused by the application runtime, embedded content, child processes, or staged payloads. That is why dynamic telemetry is useful even when static rules do not produce a high malware-family label.
```

### Question: Why are some CAPE reports marked Undetected but still have behavior?

Answer:

```text
CAPE's final label is not the only useful output. Even if the final malware status is Undetected, the report may still contain process activity, DNS traffic, UDP/TCP traffic, file writes, registry activity, and dropped artifacts. Analysts use those behaviors as evidence.
```

---

## 18. Suggested Improvements Before Job Fair

These are practical improvements that directly align with the feedback.

### 18.1 Add A Case Study Button

Add a UI button:

```text
Generate Case Study
```

It should export:

1. Static summary.
2. Dynamic summary.
3. Evidence matrix.
4. LLM prompt packet.
5. Markdown report.

### 18.2 Add LLM Enrichment Tab

Add a tab:

```text
LLM Explanation
```

It should show:

1. Confirmed behaviors.
2. Likely behaviors.
3. MITRE mappings.
4. IOC summary.
5. Plain-language explanation.
6. Recommended action.

### 18.3 Add Evidence Labels Everywhere

Every malicious activity should have a label:

```text
Static evidence
Dynamic evidence
Both static and dynamic evidence
LLM explanation
```

This makes the demo more convincing.

### 18.4 Add Correlation Logic

Correlate:

```text
Static embedded file hash -> CAPE dropped file hash
Static URL -> CAPE HTTP/DNS/network
Static PowerShell string -> CAPE process command line
Static macro autoexec -> CAPE Office child process
YARA behavior -> CAPE behavior category
```

This is the exact bridge faculty are asking for.

### 18.5 Add MITRE Mapping

The dynamic normalizer currently has placeholders:

```text
mitre_mapping: []
risk_score: None
verdict: derived from indicator count
```

Add MITRE mapping based on:

```text
Process injection -> T1055
Registry modification -> T1112
Run keys/startup -> T1547.001
DNS -> T1071.004
HTTP/TCP outbound -> T1071
PowerShell -> T1059.001
Command shell -> T1059.003
File discovery -> T1083
Credential/browser profile access -> T1555
Exfiltration over web -> T1041
```

### 18.6 Improve Test Story

Existing test documentation shows many tests but also some failing/skipped areas. For the next round, keep the test discussion honest and focused:

```text
Core detector utilities, YARA loader, Office analyzer, PDF analyzer, and PE analyzer have tests.
Some API/frontend/report-generator tests need dependency/version cleanup.
For the demo, we validated the end-to-end case-study path manually using a controlled sample.
```

Do not overclaim full production test maturity.

---

## 19. Final Next-Round Checklist

Before the next round:

```text
[ ] Choose one final sample.
[ ] Run static analysis in Fathom.
[ ] Run the same sample in CAPE.
[ ] Confirm same SHA-256 in static and dynamic outputs.
[ ] Save static JSON.
[ ] Save dynamic state JSON.
[ ] Save CAPE report summary.
[ ] Generate Fathom PDF report.
[ ] Prepare evidence matrix.
[ ] Run LLM enrichment prompt.
[ ] Save LLM output as Markdown.
[ ] Prepare screenshots for Basic, Static, Dynamic, and LLM sections.
[ ] Practice the 5-minute demo script.
```

During demo:

```text
[ ] Start with what malware does.
[ ] Show Fathom static proof.
[ ] Show CAPE dynamic proof.
[ ] Show evidence matrix.
[ ] Show LLM explanation.
[ ] End with why combined analysis is better.
```

---

## 20. Best Final Message To Evaluators

Say this near the end:

```text
The main contribution of Fathom is evidence correlation. Static analysis tells us what the file contains and what it may be capable of. CAPE dynamic analysis tells us what it actually did in a sandbox. The LLM layer then turns that evidence into a clear analyst report, but it does not replace the evidence. This gives us a complete malware-analysis case study from sample upload to final explanation.
```

That directly satisfies:

```text
first show what malware do
identify all malicious activities from your analysis
confirm, explain and enrich from LLM
```

---

## 21. Short Version For Slides

Use this slide wording:

```text
Fathom Case Study Workflow

1. Behavior first
   Show sandbox-observed malware behavior.

2. Static proof
   Identify file type, scripts/macros, embedded payloads, YARA matches, strings, IOCs.

3. Dynamic proof
   Confirm processes, file writes, registry changes, dropped files, payloads, DNS/network activity.

4. LLM enrichment
   Explain evidence, separate confirmed vs likely behavior, map to MITRE, produce analyst report.

5. Final output
   Evidence matrix + IOC list + risk assessment + recommendations.
```

---

## 22. Bottom Line

Your FYP is already approved and the technical base is strong. The next round is mainly about presentation and evidence correlation.

The winning demo is not:

```text
We built a scanner.
```

The winning demo is:

```text
We investigated a malicious document end to end.
We first observed what it did.
Then Fathom proved the behavior using static and dynamic analysis.
Then the LLM explained and enriched the evidence into a report.
```

