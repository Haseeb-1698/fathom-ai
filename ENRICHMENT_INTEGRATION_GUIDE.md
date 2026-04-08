# Fathom Enrichment Pattern Integration Guide

## Overview

The fathom-demo orchestration pattern uses a **3-phase enrichment pipeline** that significantly improves response quality:

1. **Phase 1: Fathom First-Pass Analysis** - Local specialized model analyzes CAPE evidence
2. **Phase 2: Parallel Swarm Enrichment** - 4 Azure agents run in parallel to fill knowledge gaps
3. **Phase 3: Synthesis** - Azure model synthesizes everything into a final report

## Architecture Pattern

```
User Query + CAPE Context
         ↓
    [Phase 1: Fathom]
    - Analyzes evidence
    - Identifies gaps
    - Returns contract
         ↓
    [Phase 2: Swarm] (if gaps exist)
    ├─ Threat Intel Agent
    ├─ ATT&CK Enrichment Agent  
    ├─ IOC Correlation Agent
    └─ Family Context Agent
         ↓
    [Phase 3: Synthesis]
    - Combines all results
    - Streams final report
```

## Key Files to Study

### 1. Orchestrator (`model_vm_backup_20260407_011405/agent/orchestrator.py`)

**Core Functions:**
- `run_fathom_phase()` - First-pass analysis with gap detection
- `run_swarm_phase()` - Parallel agent dispatch
- `stream_synthesis_chunks()` - Final report streaming

**Gap Detection Pattern:**
```python
# Fathom outputs analysis + gap section
=== ENRICHMENT GAPS ===
- Unknown malware family background
- IOCs need reputation correlation
- Missing sub-technique details
```

### 2. Azure Swarm (`backend/agent/azure_swarm.py`)

**4 Specialized Agents:**
- `threat_intel` - Recent campaigns, actor attribution
- `attack_enrichment` - ATT&CK sub-techniques, detections
- `ioc_correlation` - IP/domain/hash reputation
- `context_enrichment` - Malware family history

**Parallel Execution:**
```python
with ThreadPoolExecutor(max_workers=4) as pool:
    futures = {pool.submit(run_one, k): k for k in keys}
    for future in as_completed(futures):
        results[key] = future.result()
```

### 3. Server Integration (`fathom_demo/server.py`)

**Streaming Endpoint Pattern:**
```python
@app.post("/api/chat/stream")
async def chat_stream(req: ChatRequest):
    # Phase 1: Fathom analysis
    yield _sse("status", "Fathom analyzing...")
    analysis_text, contract = run_fathom_phase(...)
    
    # Phase 2: Swarm enrichment (if needed)
    if contract:
        yield _sse("status", "Running 4 intelligence agents...")
        swarm_enrichment, swarm_results = run_swarm_phase(contract)
    
    # Phase 3: Stream synthesis
    yield _sse("status", "Synthesizing final report...")
    for chunk in stream_synthesis_chunks(...):
        yield _sse("chunk", chunk)
```

## Integration Steps for Your Platform

### Step 1: Add Orchestrator Module

Copy the orchestration pattern to your backend:

```bash
backend/agent/orchestrator_enriched.py  # New file
```

Key functions to implement:
- `run_fathom_phase()` - Call your local Fathom model
- `run_swarm_phase()` - Dispatch to Azure agents
- `stream_synthesis_chunks()` - Stream final synthesis

### Step 2: Update API Routes

Modify `backend/api/routes.py` to use the enriched orchestrator:

```python
from agent.orchestrator_enriched import (
    run_fathom_phase,
    run_swarm_phase,
    stream_synthesis_chunks
)

@router.post("/chat/stream")
async def chat_stream(request: ChatRequest):
    # Phase 1
    analysis, contract = await run_fathom_phase(
        request.message,
        cape_context=request.cape_context
    )
    
    # Phase 2 (conditional)
    if contract and contract.get("gaps"):
        swarm_enrichment, swarm_results = await run_swarm_phase(contract)
        
        # Phase 3
        async for chunk in stream_synthesis_chunks(
            analysis, swarm_enrichment, swarm_results, request.message
        ):
            yield {"type": "chunk", "text": chunk}
    else:
        # Direct response (no enrichment needed)
        yield {"type": "chunk", "text": analysis}
```

### Step 3: Configure Azure Swarm

Add to `backend/config.py`:

```python
# Azure AI Foundry config
AZURE_ENDPOINT = os.getenv("AZURE_ENDPOINT", "")
AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")
AZURE_MODEL = os.getenv("AZURE_MODEL", "Kimi-K2.5")

# Swarm agents to enable
SWARM_AGENTS = [
    "threat_intel",
    "attack_enrichment", 
    "ioc_correlation",
    "context_enrichment"
]
```

### Step 4: Update Frontend

Modify your dashboard to handle streaming status updates:

```typescript
// dashboard/app/(app)/app/analysis/[id]/page.tsx

const handleStream = async (message: string) => {
  const response = await fetch('/api/chat/stream', {
    method: 'POST',
    body: JSON.stringify({ message, cape_context })
  });
  
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    const chunk = decoder.decode(value);
    const lines = chunk.split('\n');
    
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const event = JSON.parse(line.slice(6));
        
        if (event.type === 'status') {
          setStatus(event.text); // "Fathom analyzing..."
        } else if (event.type === 'chunk') {
          appendToResponse(event.text);
        }
      }
    }
  }
};
```

## Benefits of This Pattern

### 1. **Intelligent Gap Detection**
- Fathom identifies what it doesn't know
- Only calls expensive Azure agents when needed
- Reduces latency for simple queries

### 2. **Parallel Enrichment**
- 4 agents run simultaneously (not sequential)
- ~30-60s total vs 2-4min sequential
- ThreadPoolExecutor handles concurrency

### 3. **Structured Synthesis**
- Azure model combines all sources
- Maintains consistent report format
- Cites which agents contributed what

### 4. **Cost Optimization**
- Local Fathom model handles first pass (free)
- Azure only for enrichment gaps
- Typical cost: $0.02-0.05 per enriched report

## Example Flow

### Simple Query (No Enrichment)
```
User: "What is T1055 Process Injection?"
  ↓
Fathom: Answers directly from training
  ↓
Response: ~2-3 seconds
```

### Complex Analysis (With Enrichment)
```
User: "Analyze this CAPE report"
  ↓
Fathom: Initial analysis + identifies gaps
  ├─ "Unknown malware family"
  ├─ "IOCs need reputation check"
  └─ "Missing ATT&CK sub-techniques"
  ↓
Swarm (parallel):
  ├─ Threat Intel: "Emotet campaign, TA542"
  ├─ IOC Agent: "185.x.x.x = known C2"
  ├─ ATT&CK Agent: "T1055.001 PowerShell"
  └─ Context Agent: "Emotet banking trojan history"
  ↓
Synthesis: Comprehensive report
  ↓
Response: ~45-60 seconds
```

## Configuration Options

### Enrichment Triggers

Control when swarm enrichment activates:

```python
# Always enrich for CAPE reports
force_enrichment = bool(cape_task_id)

# Enrich when user explicitly requests
analyst_requested = any(kw in query.lower() for kw in [
    "enrich", "latest intel", "threat actor", 
    "attribution", "correlate"
])

# Auto-detect from Fathom's gap analysis
should_enrich = force_enrichment or analyst_requested
```

### Agent Selection

Run subset of agents based on gaps:

```python
# Only run needed agents
agents_to_run = []
if "ioc" in gaps:
    agents_to_run.append("ioc_correlation")
if "attack" in gaps:
    agents_to_run.append("attack_enrichment")

results = run_swarm(agents_to_run=agents_to_run)
```

## Testing the Integration

### 1. Test Phase 1 (Fathom Only)
```bash
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is ransomware?"}'
```

### 2. Test Phase 2 (With Swarm)
```bash
curl -X POST http://localhost:8000/api/chat/stream \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Analyze this CAPE report",
    "cape_context": "...",
    "cape_task_id": "12345"
  }'
```

### 3. Monitor Agent Execution
```python
# Add logging to orchestrator
import logging
logger = logging.getLogger(__name__)

def run_swarm_phase(contract):
    logger.info(f"Swarm gaps: {contract['gaps']}")
    results = run_swarm(...)
    logger.info(f"Swarm results: {list(results.keys())}")
    return results
```

## Next Steps

1. **Copy orchestrator pattern** from `model_vm_backup_20260407_011405/agent/orchestrator.py`
2. **Adapt to your backend** structure (`backend/agent/`)
3. **Update API routes** to use streaming pattern
4. **Test with sample CAPE reports**
5. **Monitor performance** and adjust agent selection logic

## Questions to Consider

- Do you want enrichment for ALL CAPE reports or only on-demand?
- Which Azure model to use? (Kimi-K2.5, GPT-4o, etc.)
- Should users see agent status updates in real-time?
- How to handle enrichment failures gracefully?

Let me know which part you'd like to implement first!
