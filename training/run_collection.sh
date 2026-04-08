#!/usr/bin/env bash
# run_collection.sh — Full expert dataset collection on VM
# Runs collect_experts.py + convert_cape_hf.py, then uploads all to HF Hub.
# Usage: bash run_collection.sh
# Required env: HF_TOKEN, OTX_KEY

set -euo pipefail
HF_TOKEN="${HF_TOKEN:?HF_TOKEN required}"
OTX_KEY="${OTX_KEY:-c5f3a2d4d9045aed84d875315254e4fc3672209263e3e73f04e3d5ca39a12469}"
OUT="/workspace/output"
LOGS="/workspace/logs"
mkdir -p "$OUT" "$LOGS"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "=== Fathom Full Collection Run ==="
log "Host: $(hostname) | CPUs: $(nproc) | RAM: $(free -h | awk '/Mem/{print $2}') | Disk: $(df -h / | awk 'NR==2{print $4}') free"

# ─── 1. Expert datasets (E1/E3/E4/E5/E6/E8) ──────────────────────────────────
log "--- Phase 1: Expert datasets ---"
HF_TOKEN="$HF_TOKEN" OTX_KEY="$OTX_KEY" \
  python3 /workspace/collect_experts.py \
  2>&1 | tee "$LOGS/collect_experts.log"

# ─── 2. CAPE sandbox reports + CTI supplement ─────────────────────────────────
log "--- Phase 2: CAPE reports + CTI ---"
HF_TOKEN="$HF_TOKEN" \
  python3 /workspace/convert_cape_hf.py \
  --output-dir "$OUT" \
  2>&1 | tee "$LOGS/cape.log"

# ─── 3. Upload ALL outputs to HF Hub under experts/ ──────────────────────────
log "--- Phase 3: Uploading to HF Hub ---"
python3 - <<PYEOF
import os
from huggingface_hub import HfApi
from pathlib import Path

token = os.environ["HF_TOKEN"]
api = HfApi(token=token)
repo_id = "umer07/fathom-expert-data"
out = Path("$OUT")

uploads = []
for f in sorted(out.glob("*.jsonl")):
    if f.stat().st_size > 1000:
        uploads.append(f)

if not uploads:
    print("ERROR: No output files found!")
    exit(1)

print(f"Uploading {len(uploads)} files to {repo_id}/experts/...")
for f in uploads:
    rows = sum(1 for _ in open(f))
    size = f.stat().st_size
    remote = f"experts/{f.name}"
    print(f"  {f.name}: {rows:,} rows ({size//1024//1024}MB) → {remote}")
    api.upload_file(
        path_or_fileobj=str(f),
        path_in_repo=remote,
        repo_id=repo_id,
        repo_type="dataset",
    )

print("All uploads complete.")
PYEOF

log "=== COLLECTION COMPLETE ==="
log "Files:"
for f in "$OUT"/*.jsonl; do
  [ -f "$f" ] && echo "  $(basename $f): $(wc -l < $f) rows"
done
