# Fathom Platform — Architecture & Flow Design

**Version:** 2.0  
**VM:** 134.199.201.243 (AMD MI300X · Ubuntu 22.04 · ROCm 7.0)

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER BROWSER                                  │
│                                                                      │
│  ┌──────────────────┐    ┌──────────────────────────────────────┐   │
│  │  /showcase/*     │    │  /app/*  (authenticated)             │   │
│  │  Demo/marketing  │    │  Upload → Analysis → Report → Graph  │   │
│  │  (static UI)     │    │  + Chat panel (streaming)            │   │
│  └──────────────────┘    └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         │                              │
         │ HTTPS                        │ HTTPS
         ▼                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    VM: 134.199.201.243                               │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Next.js Dashboard  (Docker · port 3000)                    │   │
│  │  /app/api/copilotkit  /app/api/chat                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          │ HTTP                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  FastAPI Backend  (Docker · port 7860)                      │   │
│  │  /api/upload  /api/analyze/stream  /api/chat/stream         │   │
│  │  /api/report/generate  /api/graph  /api/sessions            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│         │              │              │                              │
│         ▼              ▼              ▼                              │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────────┐     │
│  │ serve.py │  │  Neo4j       │  │  FAISS chat_kb           │     │
│  │ port 8000│  │  (Docker)    │  │  (file volume)           │     │
│  │ Mixtral  │  │  port 7687   │  │  attack_kb + chat_kb     │     │
│  │ +LoRA    │  └──────────────┘  └──────────────────────────┘     │
│  └──────────┘                                                        │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Azure AI Foundry (external)                                │   │
│  │  Kimi-K2.5 · 4 parallel swarm agents · synthesis           │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Firebase (Google Cloud)                                             │
│  Auth: Google + GitHub OAuth                                         │
│  Firestore: users/{uid}/chatMessages  users/{uid}/chatSessions       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Scenario A — File Upload & Analysis

```
User                  Dashboard              Backend              serve.py
 │                       │                      │                    │
 │  Drop CAPE .json       │                      │                    │
 │──────────────────────►│                      │                    │
 │                       │  POST /api/upload     │                    │
 │                       │─────────────────────►│                    │
 │                       │                      │ CAPEEvidenceExtractor
 │                       │                      │ v3 extraction      │
 │                       │                      │ (13 stages)        │
 │                       │  {brief_id, sha256,  │                    │
 │                       │   ioc_count, ...}    │                    │
 │                       │◄─────────────────────│                    │
 │                       │                      │                    │
 │  Redirect /app/analysis/{brief_id}           │                    │
 │◄──────────────────────│                      │                    │
 │                       │                      │                    │
 │  Page loads           │                      │                    │
 │──────────────────────►│                      │                    │
 │                       │  POST /api/analyze/stream                  │
 │                       │─────────────────────►│                    │
 │                       │                      │  POST /v1/cape/context
 │                       │                      │───────────────────►│
 │                       │                      │  120K chars context│
 │                       │                      │◄───────────────────│
 │                       │                      │                    │
 │                       │                      │  run_fathom_phase()│
 │                       │                      │───────────────────►│
 │                       │                      │  Mixtral inference │
 │                       │                      │◄───────────────────│
 │                       │                      │                    │
 │  SSE: status chunks   │◄─────────────────────│                    │
 │◄──────────────────────│                      │                    │
 │  Report streams in    │                      │                    │
 │  real-time (180-char  │                      │                    │
 │  chunks)              │                      │                    │
 │                       │                      │                    │
 │                       │                      │ Background:        │
 │                       │                      │ Neo4j ingest       │
 │                       │                      │ (async task)       │
```

---

## 3. Scenario B — Enriched Analysis (Kimi Swarm)

```
User                  Backend              serve.py         Azure Kimi-K2.5
 │                       │                    │                    │
 │  enable_enrichment=T  │                    │                    │
 │──────────────────────►│                    │                    │
 │                       │                    │                    │
 │                       │── Phase 1 ─────────►                    │
 │                       │  run_fathom_phase() │                    │
 │                       │  (Mixtral first-pass)                   │
 │                       │◄───────────────────│                    │
 │                       │  analysis_text +   │                    │
 │                       │  enrichment_contract                    │
 │                       │                    │                    │
 │  SSE: "Fathom analyzing..."               │                    │
 │◄──────────────────────│                    │                    │
 │                       │                    │                    │
 │                       │── Phase 2 ─────────────────────────────►│
 │                       │  run_swarm_phase()  │  4 agents parallel │
 │                       │                    │  ┌─ threat_intel   │
 │                       │                    │  ├─ attack_enrichment
 │                       │                    │  ├─ ioc_correlation│
 │                       │                    │  └─ context_enrichment
 │                       │                    │  (ThreadPoolExecutor)
 │                       │◄───────────────────────────────────────│
 │                       │  swarm_enrichment  │                    │
 │                       │                    │                    │
 │  SSE: "Running 4 agents..."               │                    │
 │◄──────────────────────│                    │                    │
 │                       │                    │                    │
 │                       │── Phase 3 ─────────────────────────────►│
 │                       │  stream_synthesis_chunks()              │
 │                       │  (Kimi synthesizes all sources)         │
 │                       │◄───────────────────────────────────────│
 │                       │  streaming chunks  │                    │
 │                       │                    │                    │
 │  SSE: "Synthesizing..." + report chunks   │                    │
 │◄──────────────────────│                    │                    │
 │                       │                    │                    │
 │  Final report:        │                    │                    │
 │  ## Executive Summary │                    │                    │
 │  ## ATT&CK Mappings   │                    │                    │
 │  ## Behavioral Indicators                 │                    │
 │  ## IOCs              │                    │                    │
 │  ## Threat Assessment │                    │                    │
 │  ## Actor Attribution │                    │                    │
 │  ## Intelligence Contributors             │                    │
```

---

## 4. Scenario C — Chat Follow-up (Streaming + Persistent History)

```
User          ChatPanel        Backend          Neo4j/FAISS       Firebase
 │               │                │                  │                │
 │  "What C2     │                │                  │                │
 │  domains?"    │                │                  │                │
 │──────────────►│                │                  │                │
 │               │                │                  │                │
 │               │  POST /api/chat/stream             │                │
 │               │───────────────►│                  │                │
 │               │                │                  │                │
 │               │                │── cache_lookup() ►                │
 │               │                │  (FAISS semantic │                │
 │               │                │   similarity)    │                │
 │               │                │                  │                │
 │               │                │  [CACHE HIT]     │                │
 │               │                │◄─────────────────│                │
 │               │  SSE chunks    │                  │                │
 │               │◄───────────────│                  │                │
 │  Response     │                │                  │                │
 │  streams in   │                │                  │                │
 │◄──────────────│                │                  │                │
 │               │                │                  │                │
 │               │                │  [CACHE MISS]    │                │
 │               │                │  stream_direct_chunks()           │
 │               │                │  (Kimi followup) │                │
 │               │                │                  │                │
 │               │                │── save_turn() ───►                │
 │               │                │  (ChatTurn node) │                │
 │               │                │── cache_store() ─►                │
 │               │                │  (FAISS embed)   │                │
 │               │                │                  │                │
 │               │                │                  │── saveChatMessage()►
 │               │                │                  │  users/{uid}/  │
 │               │                │                  │  chatMessages  │
 │               │                │                  │                │
 │  Next session:│                │                  │                │
 │  Open panel   │                │                  │                │
 │──────────────►│                │                  │                │
 │               │── loadChatMessages(uid, sid) ──────────────────────►
 │               │◄──────────────────────────────────────────────────│
 │  History      │                │                  │                │
 │  restored     │                │                  │                │
 │◄──────────────│                │                  │                │
```

---

## 5. Scenario D — Report Generation (Structured Sections)

```
User          /app/report/[id]     Backend           Kimi-K2.5
 │                  │                  │                  │
 │  Navigate to     │                  │                  │
 │  report page     │                  │                  │
 │─────────────────►│                  │                  │
 │                  │                  │                  │
 │                  │ loadAnalysis()   │                  │
 │                  │ (sessionStorage) │                  │
 │                  │                  │                  │
 │                  │  POST /api/report/generate          │
 │                  │─────────────────►│                  │
 │                  │                  │                  │
 │                  │                  │ run_fathom_phase()
 │                  │                  │ (full CAPE context)
 │                  │                  │                  │
 │                  │                  │ generate_report_sections()
 │                  │                  │ ┌─ Executive Summary
 │                  │                  │ ├─ Static Analysis ──────────►
 │                  │                  │ ├─ Dynamic Behavior ─────────►
 │                  │                  │ ├─ Network Indicators ───────►
 │                  │                  │ ├─ Detection Rules ──────────►
 │                  │                  │ └─ Remediation Steps ────────►
 │                  │                  │◄─────────────────────────────│
 │                  │                  │                  │
 │                  │  {sections,      │                  │
 │                  │   iocs[],        │                  │
 │                  │   techniques[],  │                  │
 │                  │   verdict,       │                  │
 │                  │   riskScore}     │                  │
 │                  │◄─────────────────│                  │
 │                  │                  │                  │
 │  Renders:        │                  │                  │
 │  ┌─ Section nav  │                  │                  │
 │  ├─ IOC table    │                  │                  │
 │  ├─ MITRE table  │                  │                  │
 │  └─ AI sections  │                  │                  │
 │◄─────────────────│                  │                  │
```

---

## 6. Scenario E — Authentication & User Session

```
User          Login Page        Firebase Auth      /app/* Layout
 │                │                  │                  │
 │  Visit /app/*  │                  │                  │
 │─────────────────────────────────────────────────────►│
 │                │                  │                  │
 │                │                  │  useAuth() check │
 │                │                  │◄─────────────────│
 │                │                  │  user=null       │
 │                │                  │─────────────────►│
 │                │                  │  redirect /login │
 │◄─────────────────────────────────────────────────────│
 │                │                  │                  │
 │  Click Google  │                  │                  │
 │───────────────►│                  │                  │
 │                │  signInWithPopup()                  │
 │                │─────────────────►│                  │
 │                │  Google OAuth    │                  │
 │                │◄─────────────────│                  │
 │                │  user.uid        │                  │
 │                │                  │                  │
 │  Redirect /app/upload             │                  │
 │◄───────────────│                  │                  │
 │                │                  │                  │
 │  All /app/* pages:                │                  │
 │  - Show user avatar + name        │                  │
 │  - Chat History button            │                  │
 │  - Sign out button                │                  │
 │  - Chat messages saved to         │                  │
 │    Firestore users/{uid}/...      │                  │
```

---

## 7. Scenario F — Neo4j Graph Traversal

```
User          /app/graph         Backend           Neo4j
 │                │                  │                │
 │  Navigate      │                  │                │
 │───────────────►│                  │                │
 │                │                  │                │
 │                │ sessionStorage   │                │
 │                │ fathom_last_analysis.graph_id     │
 │                │                  │                │
 │                │  POST /api/graph │                │
 │                │  query: sample_graph              │
 │                │  hash: {sha256}  │                │
 │                │─────────────────►│                │
 │                │                  │  MATCH (s:Sample)
 │                │                  │  -[:SPAWNED*]->│
 │                │                  │  (p:Process)   │
 │                │                  │  -[:HAS_IOC]-> │
 │                │                  │  (i:IOC)       │
 │                │                  │  -[:USES_TECHNIQUE]->
 │                │                  │  (t:Technique) │
 │                │                  │◄───────────────│
 │                │  {nodes, edges}  │                │
 │                │◄─────────────────│                │
 │                │                  │                │
 │  ForceGraph2D  │                  │                │
 │  renders:      │                  │                │
 │  ● Sample node │                  │                │
 │  ● Process tree│                  │                │
 │  ● IOC nodes   │                  │                │
 │  ● Technique   │                  │                │
 │    nodes       │                  │                │
 │◄───────────────│                  │                │
 │                │                  │                │
 │  Click node    │                  │                │
 │───────────────►│                  │                │
 │  Detail panel  │                  │                │
 │  shows props + │                  │                │
 │  connections   │                  │                │
 │◄───────────────│                  │                │
```

---

## 8. Data Flow Summary

```
CAPE report.json
      │
      ▼
CAPEEvidenceExtractor v3
  ├─ 13 extraction stages
  ├─ IOC dedup (max 200)
  ├─ Behavior cap (max 100)
  └─ KSPN enrichment (optional)
      │
      ▼
EvidenceBrief (~30 fields)
      │
      ├──────────────────────────────────────────────────────┐
      │                                                      │
      ▼                                                      ▼
DomainRouter                                          Neo4j Ingestion
  (sentence-transformers                              (background task)
   all-mpnet-base-v2)                                 Sample → Process
  8 domain centroids                                  → IOC → Technique
  cosine similarity                                   nodes + edges
      │
      ▼
Adapter selection
  (PEFT LoRA, rank=32)
  expert-e2-dynamic
  expert-e7-reports
  fathom-unified-v2
      │
      ▼
RAG Retrieval
  FAISS attack_kb
  691 ATT&CK vectors
  top-5 techniques
      │
      ▼
Mixtral-8x7B inference
  bf16, device_map=auto
  greedy decoding
  repetition_penalty=1.15
      │
      ▼
Guardrails
  sanitize_input()
  validate_output()
  ATT&CK ID validation
      │
      ├── enable_enrichment=False ──► Response
      │
      └── enable_enrichment=True
              │
              ▼
          Kimi Swarm (4 parallel)
          ┌─ threat_intel
          ├─ attack_enrichment
          ├─ ioc_correlation
          └─ context_enrichment
              │
              ▼
          Kimi Synthesis
          (streaming, 180-char chunks)
              │
              ▼
          Final Report
          ## Executive Summary
          ## ATT&CK Mappings
          ## Behavioral Indicators
          ## IOCs
          ## Threat Assessment
          ## Actor Attribution
          ## Intelligence Contributors
```

---

## 9. Storage Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNIVERSAL (shared, no user isolation)         │
│                                                                  │
│  Neo4j (Docker)                    FAISS (file volume)          │
│  ┌─────────────────────┐          ┌──────────────────────────┐  │
│  │ :Sample             │          │ attack_kb/               │  │
│  │ :Process            │          │   index.faiss (2MB)      │  │
│  │ :IOC                │          │   metadata.json          │  │
│  │ :Technique          │          │   691 ATT&CK vectors     │  │
│  │ :Behavior           │          │                          │  │
│  │ :ChatSession        │          │ chat_kb/                 │  │
│  │ :ChatTurn           │          │   index.faiss (grows)    │  │
│  │ :AnalysisCache      │          │   metadata.json          │  │
│  └─────────────────────┘          │   Q&A semantic cache     │  │
│                                   └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    PER-USER (Firebase Firestore)                  │
│                                                                  │
│  users/{uid}/                                                    │
│    chatMessages/                                                 │
│      {docId}: {role, content, sessionId, sampleSha256, ts}      │
│    chatSessions/                                                 │
│      {sessionId}: {sampleName, lastMessage, messageCount, ...}  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    BROWSER SESSION (sessionStorage)              │
│                                                                  │
│  fathom_upload    → {brief_id, sha256, file_name, ...}          │
│  fathom_analysis  → {report, verdict, routing, ...}             │
│  fathom_report    → {sections[], iocs[], techniques[], ...}     │
│  fathom_last_analysis → {graph_id}                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Performance Targets

| Path | Target | Notes |
|---|---|---|
| File upload + extraction | < 2s | v3 extractor, orjson fast-path |
| Fast analysis (no enrichment) | < 31s | Fathom only |
| Enriched analysis | < 131s | 3-phase pipeline |
| Chat (cache hit) | < 300ms | FAISS semantic cache |
| Chat (cache miss) | < 15s | Kimi followup mode |
| Graph query | < 500ms | Neo4j indexed queries |
| Report generation | < 60s | Kimi section generation |
| Firebase history load | < 1s | Firestore indexed query |
