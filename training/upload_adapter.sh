#!/usr/bin/env bash
# upload_adapter.sh — Upload a trained LoRA adapter to HF Hub
# Usage: bash upload_adapter.sh <expert_id> <checkpoint_dir>
# Example: bash upload_adapter.sh e2_dynamic /workspace/checkpoints/expert-e2-dynamic
# Required env: HF_TOKEN

set -euo pipefail
HF_TOKEN="${HF_TOKEN:?HF_TOKEN required}"
EXPERT_ID="${1:?Usage: upload_adapter.sh <expert_id> <checkpoint_dir>}"
CKPT_DIR="${2:?Usage: upload_adapter.sh <expert_id> <checkpoint_dir>}"

HF_REPO="umer07/fathom-expert-data"

echo "Uploading $EXPERT_ID adapter from $CKPT_DIR to $HF_REPO/adapters/$EXPERT_ID/"

python3 - <<PYEOF
import os
from huggingface_hub import HfApi
from pathlib import Path

token = os.environ["HF_TOKEN"]
api = HfApi(token=token)
repo_id = "umer07/fathom-expert-data"
expert_id = "$EXPERT_ID"
ckpt_dir = Path("$CKPT_DIR")

if not ckpt_dir.exists():
    raise FileNotFoundError(f"Checkpoint dir not found: {ckpt_dir}")

# Upload all adapter files (adapter_model.safetensors, adapter_config.json, etc.)
files = list(ckpt_dir.glob("*"))
adapter_files = [f for f in files if f.is_file() and f.suffix in (".json", ".safetensors", ".bin", ".pt")]

if not adapter_files:
    raise FileNotFoundError(f"No adapter files found in {ckpt_dir}")

print(f"Uploading {len(adapter_files)} files to adapters/{expert_id}/...")
for f in adapter_files:
    repo_path = f"adapters/{expert_id}/{f.name}"
    size = f.stat().st_size
    print(f"  {f.name} ({size//1024//1024}MB)...")
    api.upload_file(
        path_or_fileobj=str(f),
        path_in_repo=repo_path,
        repo_id=repo_id,
        repo_type="dataset",
    )

print(f"Done. Adapter at: {repo_id}/adapters/{expert_id}/")
PYEOF

echo "Upload complete: HF Hub adapters/$EXPERT_ID/"
