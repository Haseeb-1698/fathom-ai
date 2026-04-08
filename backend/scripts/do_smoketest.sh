#!/usr/bin/env bash
# do_smoketest.sh — LlamaFactory smoke test for AMD MI300X (ROCm)
# Runs on the DO GPU droplet. Exit 0 = pass, Exit 1 = fail.
# Required env: HF_TOKEN

set -euo pipefail
HF_TOKEN="${HF_TOKEN:?HF_TOKEN required}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
WORKSPACE="/workspace"
mkdir -p "$WORKSPACE/logs" "$WORKSPACE/data" "$WORKSPACE/checkpoints"

# ─── 1. System deps ───────────────────────────────────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y python3-pip python3-dev git wget curl --no-install-recommends -qq

# ─── 2. ROCm + PyTorch (AMD MI300X = gfx942) ─────────────────────────────────
log "Installing PyTorch with ROCm support..."
pip install --upgrade pip -q
pip install torch torchvision torchaudio \
  --index-url https://download.pytorch.org/whl/rocm6.2 -q
python3 -c "
import torch
print('PyTorch:', torch.__version__)
print('ROCm available:', torch.cuda.is_available())
if torch.cuda.is_available():
    print('GPU:', torch.cuda.get_device_name(0))
    print('VRAM:', round(torch.cuda.get_device_properties(0).total_memory/1e9,1), 'GB')
"

# ─── 3. LlamaFactory + deps ───────────────────────────────────────────────────
log "Installing LlamaFactory..."
pip install llamafactory transformers peft datasets huggingface_hub \
  accelerate sentencepiece protobuf -q

# ─── 4. Download smoke test dataset (500 rows from E5) ───────────────────────
log "Downloading E5 ThreatIntel sample from HF Hub..."
python3 - <<PYEOF
from huggingface_hub import hf_hub_download
import json, pathlib

path = hf_hub_download(
    repo_id="umer07/fathom-expert-data",
    filename="e5_threatintel.jsonl",
    repo_type="dataset",
    local_dir="/workspace/data",
    token="$HF_TOKEN",
)

# Take first 500 rows as smoke test set
src = pathlib.Path(path)
dst = pathlib.Path("/workspace/data/e5_smoketest.jsonl")
with open(src) as fin, open(dst, "w") as fout:
    for i, line in enumerate(fin):
        if i >= 500: break
        fout.write(line)
print(f"Wrote {min(500, i+1)} rows to {dst}")
PYEOF

# ─── 5. Write dataset_info.json for LlamaFactory ─────────────────────────────
log "Writing LlamaFactory dataset config..."
mkdir -p /workspace/data
cat > /workspace/data/dataset_info.json << 'JSON'
{
  "fathom_e5_smoke": {
    "file_name": "e5_smoketest.jsonl",
    "formatting": "alpaca",
    "columns": {
      "prompt": "instruction",
      "query": "input",
      "response": "output"
    }
  }
}
JSON

# ─── 6. Write smoke test YAML ─────────────────────────────────────────────────
log "Writing training config..."
cat > /workspace/smoketest.yaml << 'YAML'
model_name_or_path: mistralai/Mixtral-8x7B-Instruct-v0.1
dataset: fathom_e5_smoke
dataset_dir: /workspace/data
template: alpaca

finetuning_type: lora
lora_target: q_proj,v_proj,k_proj,o_proj
lora_rank: 16
lora_alpha: 32
lora_dropout: 0.0

# No quantization — 192GB VRAM is plenty
bf16: true

per_device_train_batch_size: 2
gradient_accumulation_steps: 4
learning_rate: 1.0e-4
max_steps: 50
max_grad_norm: 1.0
lr_scheduler_type: cosine
warmup_steps: 10

cutoff_len: 1024
logging_steps: 5
save_steps: 999999

output_dir: /workspace/checkpoints/smoketest
overwrite_output_dir: true
YAML

# ─── 7. Run smoke test ────────────────────────────────────────────────────────
log "Starting LlamaFactory smoke test (50 steps)..."
START_TIME=$(date +%s)

llamafactory-cli train /workspace/smoketest.yaml 2>&1 | tee /workspace/logs/llamafactory_smoke.log
TRAIN_EXIT=${PIPESTATUS[0]}

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# ─── 8. Validate result ───────────────────────────────────────────────────────
if [ $TRAIN_EXIT -eq 0 ]; then
    # Extract final loss from log
    FINAL_LOSS=$(grep -oE "'loss': [0-9]+\.[0-9]+" /workspace/logs/llamafactory_smoke.log | \
                 tail -1 | grep -oE "[0-9]+\.[0-9]+" || echo "N/A")
    STEPS_DONE=$(grep -c "{'loss'" /workspace/logs/llamafactory_smoke.log || echo "0")

    log "==========================="
    log "SMOKE TEST PASSED"
    log "Steps completed: $STEPS_DONE / 50"
    log "Final loss: $FINAL_LOSS"
    log "Elapsed: ${ELAPSED}s (~$(( ELAPSED / 60 )) min)"
    log "GPU: AMD MI300X 192GB"
    log "==========================="
    echo ""
    echo "SMOKE TEST PASSED — Steps: $STEPS_DONE, Loss: $FINAL_LOSS, Time: ${ELAPSED}s"
    exit 0
else
    log "==========================="
    log "SMOKE TEST FAILED (exit $TRAIN_EXIT)"
    log "See /workspace/logs/llamafactory_smoke.log"
    log "==========================="
    tail -30 /workspace/logs/llamafactory_smoke.log
    echo "SMOKE TEST FAILED"
    exit 1
fi
