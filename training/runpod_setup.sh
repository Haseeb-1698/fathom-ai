#!/usr/bin/env bash
# runpod_setup.sh — RunPod A100 setup for Fathom expert training
# Run once after pod creation. Sets up workspace, downloads all data, installs deps.
# Usage: bash runpod_setup.sh
# Required env: HF_TOKEN

set -euo pipefail
HF_TOKEN="${HF_TOKEN:?HF_TOKEN required}"
HF_REPO="umer07/fathom-expert-data"
WORKSPACE="/workspace"
DATA="$WORKSPACE/data"
TRAINING="$WORKSPACE/training"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

mkdir -p "$DATA/processed" "$DATA/experts" "$DATA/infra" \
         "$WORKSPACE/checkpoints" "$WORKSPACE/logs"

# ─── 1. Install LlamaFactory + deps ──────────────────────────────────────────
log "Installing LlamaFactory and dependencies..."
pip install llamafactory transformers peft datasets accelerate \
    sentencepiece protobuf bitsandbytes faiss-cpu sentence-transformers \
    huggingface_hub --upgrade -q

# Flash attention for A100
pip install flash-attn --no-build-isolation -q || log "flash-attn install failed (non-fatal)"

# ─── 2. Clone repo to /workspace ─────────────────────────────────────────────
if [ ! -d "$TRAINING" ]; then
    log "Copying training configs..."
    mkdir -p "$TRAINING/experts"
fi

# ─── 3. Download datasets from HF Hub ────────────────────────────────────────
log "Downloading datasets from HF Hub..."
python3 - <<PYEOF
import os
from huggingface_hub import hf_hub_download, list_repo_files
from pathlib import Path

token = os.environ["HF_TOKEN"]
repo = "umer07/fathom-expert-data"
data = Path("/workspace/data")

# Files to download: (remote_path, local_dir)
downloads = [
    # Processed (Plan A — E2, E7 confirmed experts)
    ("processed/v2_unified_augmented.jsonl",  data / "processed"),
    ("processed/e2_dynamic.jsonl",            data / "processed"),
    ("processed/e5_threatintel.jsonl",        data / "processed"),
    ("processed/e7_reports.jsonl",            data / "processed"),
    # New expert datasets (Plan B)
    ("experts/e1_static.jsonl",              data / "experts"),
    ("experts/e3_network.jsonl",             data / "experts"),
    ("experts/e4_forensics.jsonl",           data / "experts"),
    ("experts/e5_threatintel_aug.jsonl",     data / "experts"),
    ("experts/e6_detection.jsonl",           data / "experts"),
    ("experts/e8_analyst.jsonl",             data / "experts"),
    # Infra
    ("infra/centroid_data.json",             data / "infra"),
    ("infra/rag_index/index.faiss",          data / "infra/rag_index"),
    ("infra/rag_index/metadata.json",        data / "infra/rag_index"),
]

for remote_path, local_dir in downloads:
    local_dir = Path(local_dir)
    local_dir.mkdir(parents=True, exist_ok=True)
    dest = local_dir / Path(remote_path).name
    if dest.exists():
        print(f"  [skip] {remote_path} already exists")
        continue
    try:
        path = hf_hub_download(
            repo_id=repo,
            filename=remote_path,
            repo_type="dataset",
            local_dir=str(local_dir),
            token=token,
        )
        size = Path(path).stat().st_size
        print(f"  [ok] {remote_path} ({size//1024//1024}MB)")
    except Exception as e:
        print(f"  [WARN] {remote_path}: {e}")

print("Download complete.")
PYEOF

# ─── 4. Copy centroid_data.json to backend/router for inference ──────────────
mkdir -p "$WORKSPACE/fathom/backend/router"
cp "$DATA/infra/centroid_data.json" "$WORKSPACE/fathom/backend/router/centroid_data.json" 2>/dev/null || true
mkdir -p "$WORKSPACE/fathom/backend/rag/index/attack_kb"
cp "$DATA/infra/rag_index/"* "$WORKSPACE/fathom/backend/rag/index/attack_kb/" 2>/dev/null || true

# ─── 5. Verify ───────────────────────────────────────────────────────────────
log "=== DATA INVENTORY ==="
for f in \
    "$DATA/processed/v2_unified_augmented.jsonl" \
    "$DATA/processed/e2_dynamic.jsonl" \
    "$DATA/processed/e7_reports.jsonl" \
    "$DATA/experts/e1_static.jsonl" \
    "$DATA/experts/e3_network.jsonl" \
    "$DATA/experts/e4_forensics.jsonl" \
    "$DATA/experts/e5_threatintel_aug.jsonl" \
    "$DATA/experts/e6_detection.jsonl" \
    "$DATA/experts/e8_analyst.jsonl"; do
    if [ -f "$f" ]; then
        rows=$(wc -l < "$f")
        size=$(du -sh "$f" | cut -f1)
        log "  ✓ $(basename $f): $rows rows ($size)"
    else
        log "  ✗ $(basename $f): MISSING"
    fi
done

log "=== SETUP COMPLETE — ready to train ==="
log ""
log "Training commands:"
log "  Unified v2:  python training/train_fathom_hf.py --max-steps 6000"
log "  E1 Static:   llamafactory-cli train training/experts/e1_static.yaml"
log "  E2 Dynamic:  llamafactory-cli train training/experts/e2_dynamic.yaml"
log "  E3 Network:  llamafactory-cli train training/experts/e3_network.yaml"
log "  E4 Forensics: llamafactory-cli train training/experts/e4_forensics.yaml"
log "  E5 ThreatIntel: llamafactory-cli train training/experts/e5_threatintel.yaml"
log "  E6 Detection: llamafactory-cli train training/experts/e6_detection.yaml"
log "  E7 Reports:  llamafactory-cli train training/experts/e7_reports.yaml"
log "  E8 Analyst:  llamafactory-cli train training/experts/e8_analyst.yaml"
