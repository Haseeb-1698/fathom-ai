#!/usr/bin/env python3
import argparse
import json
import os
import re
import time
from datetime import datetime

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def token_overlap(a: str, b: str) -> float:
    a_set = set(re.findall(r"[a-zA-Z0-9_\-]+", normalize_text(a)))
    b_set = set(re.findall(r"[a-zA-Z0-9_\-]+", normalize_text(b)))
    if not b_set:
        return 0.0
    return len(a_set & b_set) / len(b_set)


def parse_answer_letter(text: str):
    if not text:
        return None
    t = text.upper()
    patterns = [
        r"(?:CORRECT\s+ANSWER\s*(?:IS|:)\s*)([A-E])\b",
        r"(?:ANSWER\s*(?:IS|:)\s*)([A-E])\b",
        r"(?:OPTION\s*)([A-E])\b",
        r"^\s*([A-E])\s*(?:[\).:\-]|\b)",
        r"\b([A-E])\b",
    ]
    for p in patterns:
        m = re.search(p, t)
        if m:
            return m.group(1)
    return None


def parse_gold_letter(row: dict):
    for k in ["correct_letter", "correct_answer", "answer", "label", "gold"]:
        v = row.get(k)
        if isinstance(v, str):
            l = parse_answer_letter(v)
            if l:
                return l
    out = row.get("output")
    if isinstance(out, str):
        return parse_answer_letter(out)
    return None


def build_cyber_prompt(row: dict):
    instruction = (row.get("instruction") or "").strip()
    input_text = (row.get("input") or "").strip()

    if instruction:
        prompt = instruction
        if input_text:
            prompt += "\n\n" + input_text
        if not re.search(r"\banswer\s*:\s*$", prompt, flags=re.IGNORECASE):
            prompt = prompt.rstrip() + "\n\nAnswer:"
        return prompt

    q = row.get("question", "")
    answers = row.get("answers")
    options = row.get("options")
    choices = row.get("choices")

    opts_text = ""
    if isinstance(answers, dict):
        opts_text = "\n".join([f"{k}. {v}" for k, v in sorted(answers.items())])
    elif isinstance(options, dict):
        opts_text = "\n".join([f"{k}. {v}" for k, v in sorted(options.items())])
    elif isinstance(choices, list):
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        opts_text = "\n".join(
            [f"{letters[i]}. {v}" for i, v in enumerate(choices) if i < len(letters)]
        )

    return (
        "You are a cybersecurity assistant. Answer the MCQ with a single letter first, then a short reason.\n\n"
        f"Question: {q}\n\nOptions:\n{opts_text}\n\nAnswer:"
    )


def rubric_scores(output_text: str):
    out = output_text or ""
    out_l = out.lower()

    structure = (
        1
        if any(
            h in out_l
            for h in ["summary", "analysis", "recommend", "verdict", "assessment"]
        )
        else 0
    )
    attck = 1 if re.search(r"\bT\d{4}(\.\d{3})?\b", out) else 0
    reasoning = (
        1
        if any(
            k in out_l
            for k in ["because", "therefore", "indicates", "suggests", "likely"]
        )
        else 0
    )
    evidence = (
        1
        if any(
            k in out_l
            for k in [
                "evidence",
                "observed",
                "based on",
                "artifact",
                "indicator",
                "ioc",
            ]
        )
        else 0
    )
    usefulness = (
        1
        if any(
            k in out_l
            for k in [
                "recommend",
                "contain",
                "isolate",
                "mitigate",
                "next step",
                "action",
            ]
        )
        else 0
    )

    return {
        "structure": structure,
        "attck_correctness": attck,
        "malware_reasoning": reasoning,
        "evidence_awareness": evidence,
        "analyst_usefulness": usefulness,
    }


def build_prompt_instruction(instruction: str, input_text: str):
    input_text = (input_text or "").strip()
    if input_text:
        return (
            "### Instruction:\n"
            f"{instruction.strip()}\n\n"
            "### Input:\n"
            f"{input_text}\n\n"
            "### Response:\n"
        )
    return f"### Instruction:\n{instruction.strip()}\n\n### Response:\n"


def generate(model, tokenizer, prompt: str, max_new_tokens: int):
    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, max_length=2048
    ).to(model.device)
    start = time.time()
    with torch.inference_mode():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=0.0,
            top_p=1.0,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.pad_token_id,
        )
    latency = time.time() - start
    gen_ids = out[0][inputs["input_ids"].shape[1] :]
    gen_text = tokenizer.decode(gen_ids, skip_special_tokens=True)
    gen_tokens = int(gen_ids.shape[0])
    tps = (gen_tokens / latency) if latency > 0 else 0.0
    vram_used = (
        int(torch.cuda.memory_allocated() / (1024 * 1024))
        if torch.cuda.is_available()
        else 0
    )
    vram_reserved = (
        int(torch.cuda.memory_reserved() / (1024 * 1024))
        if torch.cuda.is_available()
        else 0
    )
    return gen_text, latency, gen_tokens, tps, vram_used, vram_reserved


def main():
    p = argparse.ArgumentParser(description="Base/Finetuned benchmark for Plan A")
    p.add_argument("--model-id", default="mistralai/Mixtral-8x7B-Instruct-v0.1")
    p.add_argument("--adapter-path", default=None)
    p.add_argument("--workdir", default="/workspace")
    p.add_argument("--out-tag", default="base")
    p.add_argument("--max-new-eval", type=int, default=256)
    p.add_argument("--max-new-cyber", type=int, default=96)
    p.add_argument("--max-new-malware", type=int, default=512)
    p.add_argument("--skip-eval", action="store_true")
    p.add_argument("--skip-cyber", action="store_true")
    p.add_argument("--skip-malware", action="store_true")
    args = p.parse_args()

    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

    os.makedirs(os.path.join(args.workdir, "baseline_outputs"), exist_ok=True)
    run_dir = os.path.join(
        args.workdir,
        "baseline_outputs",
        f"{args.out_tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
    )
    os.makedirs(run_dir, exist_ok=True)

    print(f"Run dir: {run_dir}")

    tokenizer = AutoTokenizer.from_pretrained(args.model_id, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ROCm fix: no BitsAndBytes — MI300X has 205 GB VRAM, load full bf16
    load_mode = "bf16_full"
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        device_map={"": 0},
        dtype=torch.bfloat16,
        low_cpu_mem_usage=True,
        attn_implementation="sdpa",
    )
    model.eval()

    if args.adapter_path:
        model = PeftModel.from_pretrained(model, args.adapter_path)
        model.eval()

    # ---------- eval.jsonl ----------
    eval_metrics = {
        "count": 0,
        "mean_overlap": 0.0,
        "exact_match_rate": 0.0,
        "mean_latency_sec": 0.0,
        "mean_toks_per_s": 0.0,
        "mean_vram_used_mb": 0.0,
        "mean_vram_reserved_mb": 0.0,
    }

    overlap_sum = 0.0
    exact_sum = 0
    lat_sum = 0.0
    tps_sum = 0.0
    vram_u_sum = 0.0
    vram_r_sum = 0.0

    if not args.skip_eval:
        eval_path = os.path.join(args.workdir, "eval.jsonl")
        eval_out = os.path.join(run_dir, "eval_predictions.jsonl")
        idx = 0
        with (
            open(eval_path, "r", encoding="utf-8") as f_in,
            open(eval_out, "w", encoding="utf-8") as f_out,
        ):
            for idx, line in enumerate(f_in, 1):
                row = json.loads(line)
                prompt = build_prompt_instruction(
                    row.get("instruction", ""), row.get("input", "")
                )
                pred, lat, toks, tps, vu, vr = generate(
                    model, tokenizer, prompt, args.max_new_eval
                )
                ref = row.get("output", "")
                ov = token_overlap(pred, ref)
                ex = 1 if normalize_text(pred) == normalize_text(ref) else 0

                overlap_sum += ov
                exact_sum += ex
                lat_sum += lat
                tps_sum += tps
                vram_u_sum += vu
                vram_r_sum += vr

                out = {
                    "id": idx,
                    "prompt": prompt,
                    "reference": ref,
                    "prediction": pred,
                    "scores": {"token_overlap": ov, "exact_match": ex},
                    "latency_sec": lat,
                    "generated_tokens": toks,
                    "tokens_per_sec": tps,
                    "vram_used_mb": vu,
                    "vram_reserved_mb": vr,
                }
                f_out.write(json.dumps(out, ensure_ascii=False) + "\n")

        n = idx
        if n > 0:
            eval_metrics.update(
                {
                    "count": n,
                    "mean_overlap": overlap_sum / n,
                    "exact_match_rate": exact_sum / n,
                    "mean_latency_sec": lat_sum / n,
                    "mean_toks_per_s": tps_sum / n,
                    "mean_vram_used_mb": vram_u_sum / n,
                    "mean_vram_reserved_mb": vram_r_sum / n,
                }
            )

    # ---------- cybermetric_80 ----------
    cm_path = os.path.join(args.workdir, "cybermetric_80.jsonl")
    cm_out = os.path.join(run_dir, "cybermetric80_predictions.jsonl")
    cm_correct = 0
    cm_count = 0
    cm_lat = 0.0
    cm_tps = 0.0

    if not args.skip_cyber:
        with (
            open(cm_path, "r", encoding="utf-8") as f_in,
            open(cm_out, "w", encoding="utf-8") as f_out,
        ):
            for idx, line in enumerate(f_in, 1):
                row = json.loads(line)
                prompt = build_cyber_prompt(row)
                pred, lat, toks, tps, vu, vr = generate(
                    model, tokenizer, prompt, args.max_new_cyber
                )
                pred_letter = parse_answer_letter(pred)
                gold = parse_gold_letter(row) or ""
                ok = 1 if (pred_letter and gold and pred_letter == gold) else 0
                cm_correct += ok
                cm_count += 1
                cm_lat += lat
                cm_tps += tps

                out = {
                    "id": idx,
                    "prompt": prompt,
                    "gold": gold,
                    "prediction": pred,
                    "pred_letter": pred_letter,
                    "correct": ok,
                    "latency_sec": lat,
                    "generated_tokens": toks,
                    "tokens_per_sec": tps,
                    "vram_used_mb": vu,
                    "vram_reserved_mb": vr,
                }
                f_out.write(json.dumps(out, ensure_ascii=False) + "\n")

    cyber_metrics = {
        "count": cm_count,
        "accuracy": (cm_correct / cm_count) if cm_count else 0.0,
        "mean_latency_sec": (cm_lat / cm_count) if cm_count else 0.0,
        "mean_toks_per_s": (cm_tps / cm_count) if cm_count else 0.0,
    }

    # ---------- malware_eval_25 ----------
    mw_path = os.path.join(args.workdir, "malware_eval_25.jsonl")
    mw_out = os.path.join(run_dir, "malware25_predictions.jsonl")
    mw_count = 0
    mw_lat = 0.0
    mw_tps = 0.0
    mw_rubric_sum = {
        "structure": 0,
        "attck_correctness": 0,
        "malware_reasoning": 0,
        "evidence_awareness": 0,
        "analyst_usefulness": 0,
    }

    if not args.skip_malware:
        with (
            open(mw_path, "r", encoding="utf-8") as f_in,
            open(mw_out, "w", encoding="utf-8") as f_out,
        ):
            for idx, line in enumerate(f_in, 1):
                row = json.loads(line)
                prompt = build_prompt_instruction(
                    row.get("instruction", ""), row.get("input", "")
                )
                pred, lat, toks, tps, vu, vr = generate(
                    model, tokenizer, prompt, args.max_new_malware
                )
                rub = rubric_scores(pred)
                for k in mw_rubric_sum:
                    mw_rubric_sum[k] += rub[k]
                mw_count += 1
                mw_lat += lat
                mw_tps += tps

                out = {
                    "id": idx,
                    "category": row.get("category", ""),
                    "prompt": prompt,
                    "expected_capabilities": row.get("expected_capabilities", []),
                    "prediction": pred,
                    "rubric_scores": rub,
                    "latency_sec": lat,
                    "generated_tokens": toks,
                    "tokens_per_sec": tps,
                    "vram_used_mb": vu,
                    "vram_reserved_mb": vr,
                }
                f_out.write(json.dumps(out, ensure_ascii=False) + "\n")

    malware_metrics = {
        "count": mw_count,
        "mean_latency_sec": (mw_lat / mw_count) if mw_count else 0.0,
        "mean_toks_per_s": (mw_tps / mw_count) if mw_count else 0.0,
        "rubric_means": {
            k: (mw_rubric_sum[k] / mw_count if mw_count else 0.0) for k in mw_rubric_sum
        },
    }

    summary = {
        "run_tag": args.out_tag,
        "timestamp": datetime.now().isoformat(),
        "model_id": args.model_id,
        "load_mode": load_mode,
        "adapter_path": args.adapter_path,
        "generation": {
            "do_sample": False,
            "temperature": 0.0,
            "top_p": 1.0,
            "max_new_eval": args.max_new_eval,
            "max_new_cyber": args.max_new_cyber,
            "max_new_malware": args.max_new_malware,
        },
        "eval_jsonl": eval_metrics,
        "cybermetric_80": cyber_metrics,
        "malware_eval_25": malware_metrics,
    }

    with open(
        os.path.join(run_dir, "aggregate_metrics.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"Saved benchmark outputs in: {run_dir}")


if __name__ == "__main__":
    main()
