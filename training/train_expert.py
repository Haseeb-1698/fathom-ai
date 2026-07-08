#!/usr/bin/env python3
"""
train_expert.py — Direct PEFT+TRL training for Fathom expert adapters.
Bypasses LlamaFactory; loads Mixtral-8x7B in bf16 on a single ROCm/CUDA device.

Usage:
  python train_expert.py \
    --name expert-e1-static \
    --datasets /workspace/fathom/data/experts/e1_static.jsonl \
    --epochs 3 \
    --output-dir /workspace/checkpoints/expert-e1-static

  # Multiple datasets (comma-separated or repeated --datasets):
  python train_expert.py \
    --name expert-e9-cot \
    --datasets /workspace/fathom/data/experts/joe_cot_reasoning.jsonl,/workspace/fathom/data/experts/blog_cot_training.jsonl
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

import torch
from datasets import load_dataset, concatenate_datasets
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments
from peft import get_peft_model, LoraConfig, TaskType
from trl import SFTTrainer, SFTConfig
from huggingface_hub import HfApi

MODEL_ID   = "mistralai/Mixtral-8x7B-Instruct-v0.1"
HF_TOKEN   = os.environ.get("HF_TOKEN", "")
HF_REPO    = "umer07/fathom-expert-data"

ALPACA_TEMPLATE = (
    "### Instruction:\n{instruction}\n\n"
    "### Input:\n{input}\n\n"
    "### Response:\n{output}"
)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--name",        required=True,  help="Adapter name, e.g. expert-e1-static")
    p.add_argument("--datasets",    required=True,  help="Comma-separated JSONL paths")
    p.add_argument("--epochs",      type=int,   default=3)
    p.add_argument("--lr",          type=float, default=1e-4)
    p.add_argument("--lora-rank",   type=int,   default=32)
    p.add_argument("--lora-alpha",  type=int,   default=64)
    p.add_argument("--batch-size",  type=int,   default=2)
    p.add_argument("--grad-accum",  type=int,   default=8)
    p.add_argument("--cutoff-len",  type=int,   default=2048)
    p.add_argument("--warmup-steps",type=int,   default=100)
    p.add_argument("--output-dir",  type=str,   default=None)
    p.add_argument("--no-upload",   action="store_true", help="Skip HF Hub upload")
    return p.parse_args()


def format_alpaca(example):
    return ALPACA_TEMPLATE.format(
        instruction=example.get("instruction", ""),
        input=example.get("input", ""),
        output=example.get("output", ""),
    )


def load_datasets(paths_str: str):
    paths = [p.strip() for p in paths_str.split(",") if p.strip()]
    parts = []
    for path in paths:
        if not Path(path).exists():
            print(f"  [WARN] Dataset not found, skipping: {path}")
            continue
        ds = load_dataset("json", data_files=path, split="train")
        parts.append(ds)
        print(f"  Loaded {len(ds):,} rows from {Path(path).name}")
    if not parts:
        raise RuntimeError("No valid datasets found")
    if len(parts) == 1:
        return parts[0]
    merged = concatenate_datasets(parts)
    print(f"  Total: {len(merged):,} rows")
    return merged


def main():
    args = parse_args()
    output_dir = args.output_dir or f"/workspace/checkpoints/{args.name}"
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs("/workspace/logs", exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  Fathom Expert Training: {args.name}")
    print(f"  Started: {datetime.now().isoformat()}")
    print(f"  GPU: {torch.cuda.get_device_name(0)}")
    print(f"  VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    print(f"{'='*60}\n")

    # ── 1. Load tokenizer ──────────────────────────────────────
    print("[1/5] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ID, token=HF_TOKEN, trust_remote_code=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    print(f"  Vocab size: {tokenizer.vocab_size:,}")

    # ── 2. Load model ──────────────────────────────────────────
    print("[2/5] Loading Mixtral-8x7B in bf16 (no quantization)...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        token=HF_TOKEN,
        dtype=torch.bfloat16,
        device_map={"": 0},          # Force single GPU — avoids multi-device issue
        trust_remote_code=True,
        attn_implementation="sdpa",  # PyTorch SDPA: faster than eager on ROCm
    )
    model.config.use_cache = False
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Loaded: {total_params/1e9:.1f}B parameters")

    # ── 3. Apply LoRA ──────────────────────────────────────────
    print(f"[3/5] Applying LoRA (rank={args.lora_rank})...")
    lora_cfg = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.0,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
        bias="none",
    )
    model = get_peft_model(model, lora_cfg)
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Trainable: {trainable:,} / {total_params:,} ({trainable/total_params*100:.3f}%)")

    # ── 4. Load datasets ───────────────────────────────────────
    print("[4/5] Loading datasets...")
    dataset = load_datasets(args.datasets)
    dataset = dataset.map(
        lambda ex: {"text": format_alpaca(ex)},
        remove_columns=dataset.column_names,
    )

    # ── 5. Train ───────────────────────────────────────────────
    print(f"[5/5] Training...")
    effective_batch = args.batch_size * args.grad_accum
    print(f"  Epochs: {args.epochs}")
    print(f"  Batch: {args.batch_size} × {args.grad_accum} = {effective_batch} effective")
    print(f"  LR: {args.lr}")
    print(f"  Rows: {len(dataset):,}")

    sft_cfg = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_steps=args.warmup_steps,
        max_grad_norm=1.0,
        bf16=True,
        logging_steps=10,
        save_steps=500,
        save_total_limit=2,
        report_to="none",
        max_length=args.cutoff_len,
        dataset_text_field="text",
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset,
        args=sft_cfg,
    )

    trainer.train()

    # Save adapter
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"\n  Adapter saved: {output_dir}")

    # Save training log
    if trainer.state.log_history:
        log_path = Path(output_dir) / "training_log.json"
        with open(log_path, "w") as f:
            json.dump(trainer.state.log_history, f, indent=2)

    # ── Upload ─────────────────────────────────────────────────
    if not args.no_upload:
        print(f"\nUploading {args.name} to HF Hub...")
        api = HfApi(token=HF_TOKEN)
        api.upload_folder(
            folder_path=output_dir,
            path_in_repo=f"adapters/{args.name}",
            repo_id=HF_REPO,
            repo_type="dataset",
        )
        print(f"  Uploaded: {HF_REPO}/adapters/{args.name}")

    print(f"\n{'='*60}")
    print(f"  DONE: {args.name}")
    print(f"  Finished: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
