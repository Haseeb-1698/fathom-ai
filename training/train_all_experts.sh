#!/bin/bash
# train_all_experts.sh
# Direct PEFT+TRL training — bypasses LlamaFactory (fixes ROCm multi-device issue).
# Settings tuned for MI300X 205GB VRAM, ~33-38h total within 40h budget.
#
# cutoff=2048 for all reasoning-heavy adapters (full context matters for quality).
# cutoff=1024 only for e7_reports (94k rows, template-style outputs — 1024 sufficient).
# Epochs calibrated to dataset size: small datasets → more epochs, large → 1 epoch.
#
# Usage: screen -dmS fathom-train bash -c 'source /opt/fathom-env/bin/activate && bash /workspace/fathom/train_all_experts.sh >> /workspace/logs/train_all.log 2>&1'

set -eo pipefail
source /opt/fathom-env/bin/activate

LOG=/workspace/logs/train_all.log
mkdir -p /workspace/logs /workspace/checkpoints
SCRIPT=/workspace/fathom/train_expert.py
DATA=/workspace/fathom/data

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

train() {
    local name=$1; shift
    log "====== START $name ======"
    python3 "$SCRIPT" --name "$name" "$@" 2>&1 | tee -a "$LOG"
    log "====== DONE $name ======"
}

log "=== FATHOM FRESH TRAINING START ==="
log "Batch=16 grad_accum=2 (eff=32). cutoff=2048 everywhere except e7 (1024)."
log "Est. total: ~33-38h on MI300X 205GB."

# ── Unified base adapter ──────────────────────────────────────
# 123k rows — 1 epoch sufficient for large corpus. cutoff=2048 for full context.
train unified-v2 \
    --datasets "$DATA/processed/v2_unified_augmented.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 100 \
    --output-dir /workspace/checkpoints/unified-v2

# ── E1: Static Analysis ───────────────────────────────────────
# 11k general static analysis + 25k evasive_dataset (obfuscated C++ labeled by technique) = 36k rows.
# 1 epoch sufficient given dataset size (3x larger than original plan).
# evasive_dataset covers 92 technique combinations: cf, gc, gd, meta, poly, sd, var, sb + combos.
train expert-e1-static \
    --datasets "$DATA/experts/e1_static.jsonl,$DATA/experts/e1_evasion_static.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 100

# ── E2: Dynamic Analysis ──────────────────────────────────────
# 2.7k rows (small) — 3 epochs for better convergence.
train expert-e2-dynamic \
    --datasets "$DATA/experts/cape_hf_reports.jsonl" \
    --epochs 3 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 30

# ── E3: Network ───────────────────────────────────────────────
# 20k rows — 1 epoch (large enough for single pass).
train expert-e3-network \
    --datasets "$DATA/experts/e3_network.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 50

# ── E4: Forensics ─────────────────────────────────────────────
# 19k rows — 1 epoch.
train expert-e4-forensics \
    --datasets "$DATA/experts/e4_forensics.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 50

# ── E5: Threat Intel ──────────────────────────────────────────
# 832 rows (tiny) — 5 epochs to squeeze value from small dataset.
train expert-e5-threatintel \
    --datasets "$DATA/experts/e5_threatintel_aug.jsonl" \
    --epochs 5 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 20

# ── E6: Detection ─────────────────────────────────────────────
# 20k rows — 1 epoch.
train expert-e6-detection \
    --datasets "$DATA/experts/e6_detection.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 50

# ── E7: Reports ───────────────────────────────────────────────
# 94k rows — 1 epoch. cutoff=1024 (large corpus, template-style outputs,
# full 2048 context less critical vs. budget savings of ~7h).
train expert-e7-reports \
    --datasets "$DATA/experts/e7_reports.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 1024 --warmup-steps 100

# ── E8: Analyst ───────────────────────────────────────────────
# 19.5k rows — 1 epoch.
train expert-e8-analyst \
    --datasets "$DATA/experts/e8_analyst.jsonl" \
    --epochs 1 --lr 1e-4 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 50

# ── E9: CoT Reasoning ─────────────────────────────────────────
# 1626 rows (tiny) — 5 epochs + full 2048 cutoff critical for reasoning quality.
# joe sandbox summaries + 704 blog writeups + ATT&CK supplement.
train expert-e9-cot \
    --datasets "$DATA/experts/joe_cot_reasoning.jsonl,$DATA/experts/blog_cot_training.jsonl,$DATA/experts/cot_supplement_fixed.jsonl" \
    --epochs 5 --lr 5e-5 --lora-rank 32 --batch-size 16 --grad-accum 2 \
    --cutoff-len 2048 --warmup-steps 20

log "=== ALL ADAPTERS COMPLETE ==="
