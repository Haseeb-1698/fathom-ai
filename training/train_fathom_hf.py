#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime

import torch
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)


DEFAULTS = {
    "model_id": "mistralai/Mixtral-8x7B-Instruct-v0.1",
    "train_file": "/workspace/train.jsonl",
    "eval_file": "/workspace/eval.jsonl",
    "output_dir": "/workspace/fathom-model-hf",
    "max_seq_length": 2048,
    "batch_size": 1,
    "grad_accum": 16,
    "epochs": 3,
    "learning_rate": 2e-4,
    "lora_r": 32,
    "lora_alpha": 64,
    "lora_dropout": 0.0,
    "logging_steps": 10,
    "warmup_steps": 100,
}


def build_prompt(instruction: str, input_text: str) -> str:
    instruction = (instruction or "").strip()
    input_text = (input_text or "").strip()
    if input_text:
        return (
            "### Instruction:\n"
            f"{instruction}\n\n"
            "### Input:\n"
            f"{input_text}\n\n"
            "### Response:\n"
        )
    return f"### Instruction:\n{instruction}\n\n### Response:\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fathom Mixtral training via plain HF PEFT"
    )
    parser.add_argument("--model-id", default=DEFAULTS["model_id"])
    parser.add_argument("--train-file", default=DEFAULTS["train_file"])
    parser.add_argument("--eval-file", default=DEFAULTS["eval_file"])
    parser.add_argument("--output-dir", default=DEFAULTS["output_dir"])
    parser.add_argument("--seq-length", type=int, default=DEFAULTS["max_seq_length"])
    parser.add_argument("--batch-size", type=int, default=DEFAULTS["batch_size"])
    parser.add_argument("--grad-accum", type=int, default=DEFAULTS["grad_accum"])
    parser.add_argument("--epochs", type=int, default=DEFAULTS["epochs"])
    parser.add_argument("--lr", type=float, default=DEFAULTS["learning_rate"])
    parser.add_argument("--lora-r", type=int, default=DEFAULTS["lora_r"])
    parser.add_argument("--max-train-samples", type=int, default=None)
    parser.add_argument("--max-eval-samples", type=int, default=None)
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument("--save-steps", type=int, default=250)
    parser.add_argument("--eval-steps", type=int, default=250)
    parser.add_argument("--resume-from-checkpoint", default=None)
    return parser.parse_args()


def tokenize_row(example, tokenizer, max_length: int):
    prompt = build_prompt(example.get("instruction", ""), example.get("input", ""))
    answer = (example.get("output", "") or "").strip() + tokenizer.eos_token

    prompt_ids = tokenizer(prompt, add_special_tokens=False).input_ids
    answer_ids = tokenizer(answer, add_special_tokens=False).input_ids

    input_ids = prompt_ids + answer_ids
    labels = ([-100] * len(prompt_ids)) + answer_ids

    input_ids = input_ids[:max_length]
    labels = labels[:max_length]
    attention_mask = [1] * len(input_ids)

    return {
        "input_ids": input_ids,
        "attention_mask": attention_mask,
        "labels": labels,
    }


def main() -> None:
    args = parse_args()

    print("=" * 60)
    print("FATHOM Mixtral Training - Plain HF PEFT")
    print("=" * 60)
    print(f"Started: {datetime.now().isoformat()}")
    print(
        f"GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}"
    )
    if torch.cuda.is_available():
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    print()

    os.makedirs(args.output_dir, exist_ok=True)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )

    print("[1/5] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    print("[2/5] Loading Mixtral in 4-bit...")
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        quantization_config=bnb_config,
        device_map={"": 0},
        torch_dtype=torch.bfloat16,
        low_cpu_mem_usage=True,
        attn_implementation="sdpa",
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model)
    model.gradient_checkpointing_enable(
        gradient_checkpointing_kwargs={"use_reentrant": False}
    )
    print("  model loaded")

    print("[3/5] Adding attention-only LoRA...")
    peft_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=DEFAULTS["lora_alpha"],
        lora_dropout=DEFAULTS["lora_dropout"],
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, peft_config)
    model.print_trainable_parameters()

    print("[4/5] Loading and tokenizing dataset...")
    train_ds = load_dataset("json", data_files=args.train_file, split="train")
    eval_ds = load_dataset("json", data_files=args.eval_file, split="train")
    if args.max_train_samples is not None:
        train_ds = train_ds.select(range(min(args.max_train_samples, len(train_ds))))
    if args.max_eval_samples is not None:
        eval_ds = eval_ds.select(range(min(args.max_eval_samples, len(eval_ds))))
    train_ds = train_ds.map(
        lambda row: tokenize_row(row, tokenizer, args.seq_length),
        remove_columns=train_ds.column_names,
        num_proc=1,
        desc="Tokenizing train",
    )
    eval_ds = eval_ds.map(
        lambda row: tokenize_row(row, tokenizer, args.seq_length),
        remove_columns=eval_ds.column_names,
        num_proc=1,
        desc="Tokenizing eval",
    )
    print(f"  train: {len(train_ds):,}")
    print(f"  eval:  {len(eval_ds):,}")

    collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        label_pad_token_id=-100,
        pad_to_multiple_of=8,
    )

    step_capped = args.max_steps is not None and args.max_steps > 0

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        logging_steps=DEFAULTS["logging_steps"],
        warmup_steps=DEFAULTS["warmup_steps"],
        lr_scheduler_type="cosine",
        save_strategy="steps" if step_capped else "epoch",
        save_steps=args.save_steps,
        eval_strategy="steps" if step_capped else "epoch",
        eval_steps=args.eval_steps,
        bf16=True,
        optim="paged_adamw_8bit",
        report_to="none",
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        remove_unused_columns=False,
        dataloader_num_workers=2,
        max_steps=args.max_steps,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        data_collator=collator,
        tokenizer=tokenizer,
    )

    print("[5/5] Starting training...")
    trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)

    lora_dir = os.path.join(args.output_dir, "lora-adapter")
    model.save_pretrained(lora_dir)
    tokenizer.save_pretrained(lora_dir)

    with open(
        os.path.join(args.output_dir, "hf_training_summary.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(
            {
                "model_id": args.model_id,
                "train_examples": len(train_ds),
                "eval_examples": len(eval_ds),
                "seq_length": args.seq_length,
                "batch_size": args.batch_size,
                "grad_accum": args.grad_accum,
                "epochs": args.epochs,
                "learning_rate": args.lr,
                "completed": datetime.now().isoformat(),
            },
            f,
            indent=2,
        )

    print("Training complete")
    print(f"Saved LoRA adapter to {lora_dir}")


if __name__ == "__main__":
    main()
