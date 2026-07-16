#!/usr/bin/env python3
"""
score_secure_cybersoceval.py

Scores Fathom (via the live vLLM OpenAI-compatible API, model="fathom") on:
  - SECURE: MAET, CWET, KCV, VOOD (MCQ/boolean, A-D or True/False/Unknown)
  - SECURE: RERT (risk-eval summary, free text) — recorded but not auto-scored (ROUGE-L needs a ref impl)
  - SECURE: CPST (CVSS vector prediction, free text) — recorded but not auto-scored (needs MAD impl)
  - CyberSOCEval: malware_analysis, threat_intel_reasoning (multi-select MCQ)

Mirrors the Fathom benchmark harness's MCQ methodology (build_cyber_prompt /
parse_answer_letter from benchmark_fixed.py): greedy decode, short answer budget,
"Answer:" suffix, single-letter-first parsing.

Concurrency: fires N concurrent requests against vLLM (max_num_seqs=2 server-side,
so client concurrency just keeps the queue full).
"""
import argparse, asyncio, csv, json, os, re, sys, time
import urllib.request

VLLM_URL = "http://127.0.0.1:8000/v1/completions"
MODEL = "fathom"


def call_vllm(prompt, max_tokens=96, temperature=0.0):
    body = json.dumps({
        "model": MODEL, "prompt": prompt, "max_tokens": max_tokens,
        "temperature": temperature, "top_p": 1.0,
    }).encode()
    req = urllib.request.Request(VLLM_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["choices"][0]["text"]


def parse_letter(text):
    if not text:
        return None
    t = text.upper()
    for p in [r"(?:ANSWER\s*(?:IS|:)\s*)([A-EX])\b", r"^\s*([A-EX])\s*(?:[\).:\-]|\b)", r"\b([A-EX])\b"]:
        m = re.search(p, t)
        if m:
            return m.group(1)
    return None


def parse_multi_letters(text):
    if not text:
        return []
    t = text.upper()
    return sorted(set(re.findall(r"\b([A-E])\b", t)))


def load_secure_tsv(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            rows.append(r)
    return rows


def build_mcq_prompt(question, options, extra=""):
    opts_text = "\n".join(options) if options else ""
    return (
        "You are a cybersecurity assistant. Answer the question with a single letter first, "
        "then a short reason.\n\n"
        f"Question: {question}\n\n{extra}Options:\n{opts_text}\n\nAnswer:"
    )


_progress = {"done": 0, "total": 0, "t0": 0.0, "label": ""}


async def worker(name, queue, results, sem):
    loop = asyncio.get_event_loop()
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        idx, prompt, meta = item
        async with sem:
            try:
                text = await loop.run_in_executor(None, call_vllm, prompt, meta.get("max_tokens", 96))
            except Exception as e:
                text = f"[ERROR: {e}]"
        results[idx] = {"prompt_id": idx, "raw_output": text, **meta}
        _progress["done"] += 1
        if _progress["done"] % 25 == 0 or _progress["done"] == _progress["total"]:
            el = time.time() - _progress["t0"]
            rate = _progress["done"] / el if el > 0 else 0
            eta = (_progress["total"] - _progress["done"]) / rate if rate > 0 else 0
            print(f"[{_progress['label']}] {_progress['done']}/{_progress['total']} "
                  f"({100*_progress['done']/_progress['total']:.1f}%) "
                  f"rate={rate:.2f}/s ETA={eta/60:.1f}min", flush=True)
        queue.task_done()


async def run_batch(tasks, concurrency=4, label=""):
    queue = asyncio.Queue()
    results = {}
    for t in tasks:
        queue.put_nowait(t)
    for _ in range(concurrency):
        queue.put_nowait(None)
    sem = asyncio.Semaphore(concurrency)
    _progress["done"] = 0
    _progress["total"] = len(tasks)
    _progress["t0"] = time.time()
    _progress["label"] = label
    print(f"[{label}] starting {len(tasks)} items...", flush=True)
    workers = [asyncio.create_task(worker(i, queue, results, sem)) for i in range(concurrency)]
    await queue.join()
    for w in workers:
        w.cancel()
    return results


def score_secure_mcq(path, name, out_dir, concurrency):
    rows = load_secure_tsv(path)
    tasks = []
    for i, r in enumerate(rows):
        q = r.get("Question", "")
        opts = [f"{L}. {r[c]}" for L, c in [("A", "Option A"), ("B", "Option B"), ("C", "Option C"), ("D", "Option D")] if c in r and r[c]]
        prompt = build_mcq_prompt(q, opts)
        gold = (r.get("Correct Answer") or "").strip().upper()[:1]
        tasks.append((i, prompt, {"gold": gold, "question": q, "max_tokens": 96}))
    results = asyncio.run(run_batch(tasks, concurrency, label=name))
    correct = 0
    out_path = os.path.join(out_dir, f"{name}_predictions.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for i in range(len(rows)):
            r = results.get(i, {"raw_output": "[MISSING]", "gold": "", "question": ""})
            pred = parse_letter(r["raw_output"])
            ok = 1 if (pred and r["gold"] and pred == r["gold"]) else 0
            correct += ok
            f.write(json.dumps({"id": i, "gold": r["gold"], "pred_letter": pred, "correct": ok,
                                 "raw_output": r["raw_output"]}, ensure_ascii=False) + "\n")
    acc = 100 * correct / max(1, len(rows))
    print(f"{name}: {correct}/{len(rows)} = {acc:.2f}%  -> {out_path}")
    return {"name": name, "n": len(rows), "correct": correct, "accuracy": acc}


def parse_tfx(text):
    if not text:
        return None
    t = text.upper()
    for p in [r"(?:ANSWER\s*(?:IS|:)\s*)([TFX])\b", r"^\s*([TFX])\s*(?:[\).:\-]|\b)", r"\b([TFX])\b"]:
        m = re.search(p, t)
        if m:
            return m.group(1)
    return None


def build_tfx_prompt(question):
    return (
        "You are a cybersecurity assistant. Analyze the following statement and indicate "
        "whether it is True or False. Return your answer as a single letter first (T for True, "
        "F for False, X if you do not know), then a short reason.\n\n"
        f"Statement: {question}\n\nAnswer:"
    )


def score_secure_boolean(path, name, out_dir, concurrency):
    """KCV/VOOD's raw 'Prompt' column embeds full CVE JSON records, long enough
    to exceed vLLM's --max-num-batched-tokens 4096 (chunked-prefill disabled),
    which silently returns empty completions. Use only the short 'Question' field,
    same approach as MAET/CWET, just with the paper's T/F/X answer format."""
    rows = load_secure_tsv(path)
    tasks = []
    for i, r in enumerate(rows):
        q = r.get("Question", "")
        prompt = build_tfx_prompt(q)
        gold = (r.get("Correct Answer") or "").strip().upper()[:1]
        tasks.append((i, prompt, {"gold": gold, "question": q, "max_tokens": 32}))
    results = asyncio.run(run_batch(tasks, concurrency, label=name))
    correct = 0
    out_path = os.path.join(out_dir, f"{name}_predictions.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for i in range(len(rows)):
            r = results.get(i, {"raw_output": "[MISSING]", "gold": "", "question": ""})
            pred = parse_tfx(r["raw_output"])
            ok = 1 if (pred and r["gold"] and pred == r["gold"]) else 0
            correct += ok
            f.write(json.dumps({"id": i, "gold": r["gold"], "pred_letter": pred, "correct": ok,
                                 "raw_output": r["raw_output"]}, ensure_ascii=False) + "\n")
    acc = 100 * correct / max(1, len(rows))
    print(f"{name}: {correct}/{len(rows)} = {acc:.2f}%  -> {out_path}")
    return {"name": name, "n": len(rows), "correct": correct, "accuracy": acc}


def score_cybersoceval(path, name, out_dir, concurrency, qfield="question", gold_field="correct_options"):
    items = json.load(open(path, encoding="utf-8"))
    tasks = []
    for i, it in enumerate(items):
        q = it.get(qfield, "")
        opts = it.get("options", [])
        prompt = build_mcq_prompt(q, opts, extra="(Select ALL correct options, e.g. 'A, C')\n\n")
        gold = sorted(set(x.strip().upper()[:1] for x in it.get(gold_field, [])))
        tasks.append((i, prompt, {"gold": gold, "question": q, "max_tokens": 96}))
    results = asyncio.run(run_batch(tasks, concurrency, label=name))
    exact = jaccard_sum = 0.0
    out_path = os.path.join(out_dir, f"{name}_predictions.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for i in range(len(items)):
            r = results.get(i, {"raw_output": "[MISSING]", "gold": [], "question": ""})
            pred = parse_multi_letters(r["raw_output"])
            gold = r["gold"]
            pset, gset = set(pred), set(gold)
            ex = 1 if pset == gset else 0
            jac = len(pset & gset) / len(pset | gset) if (pset | gset) else 1.0
            exact += ex; jaccard_sum += jac
            f.write(json.dumps({"id": i, "gold": gold, "pred": pred, "exact": ex, "jaccard": round(jac, 3),
                                 "raw_output": r["raw_output"]}, ensure_ascii=False) + "\n")
    n = len(items)
    print(f"{name}: exact-set={100*exact/n:.2f}%  mean-jaccard={jaccard_sum/n:.3f}  -> {out_path}")
    return {"name": name, "n": n, "exact_set_acc": 100 * exact / n, "mean_jaccard": jaccard_sum / n}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--secure_dir", required=True)
    ap.add_argument("--cybersoceval_dir", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    def already_done(name):
        p = os.path.join(args.out_dir, f"{name}_predictions.jsonl")
        return os.path.exists(p) and os.path.getsize(p) > 0

    def rescore_from_existing(name, gold_ok):
        """Recompute the summary line from an existing predictions file (skip re-inference)."""
        p = os.path.join(args.out_dir, f"{name}_predictions.jsonl")
        rows = [json.loads(l) for l in open(p, encoding="utf-8")]
        n = len(rows)
        if "correct" in rows[0]:
            correct = sum(r["correct"] for r in rows)
            acc = 100 * correct / max(1, n)
            print(f"[skip-reuse] {name}: {correct}/{n} = {acc:.2f}%  (from existing {p})")
            return {"name": name, "n": n, "correct": correct, "accuracy": acc}
        else:
            exact = sum(r["exact"] for r in rows)
            jac = sum(r["jaccard"] for r in rows) / max(1, n)
            print(f"[skip-reuse] {name}: exact-set={100*exact/n:.2f}%  mean-jaccard={jac:.3f}  (from existing {p})")
            return {"name": name, "n": n, "exact_set_acc": 100 * exact / n, "mean_jaccard": jac}

    summary = []
    for name, fn, fargs in [
        ("secure_maet", score_secure_mcq, (os.path.join(args.secure_dir, "SECURE_-_MAET.tsv"),)),
        ("secure_cwet", score_secure_mcq, (os.path.join(args.secure_dir, "SECURE_-_CWET.tsv"),)),
        ("secure_kcv", score_secure_boolean, (os.path.join(args.secure_dir, "SECURE_-_KCV.tsv"),)),
        ("secure_vood", score_secure_boolean, (os.path.join(args.secure_dir, "SECURE_-_VOOD.tsv"),)),
    ]:
        if already_done(name):
            summary.append(rescore_from_existing(name, True))
        else:
            summary.append(fn(fargs[0], name, args.out_dir, args.concurrency))

    for name, path, qfield, gold_field in [
        ("cybersoceval_malware", os.path.join(args.cybersoceval_dir, "malware_analysis_questions.json"), "question", "correct_options"),
        ("cybersoceval_threatintel", os.path.join(args.cybersoceval_dir, "threat_intel_report_questions.json"), "question_text", "correct_answer"),
    ]:
        if already_done(name):
            summary.append(rescore_from_existing(name, True))
        else:
            summary.append(score_cybersoceval(path, name, args.out_dir, args.concurrency, qfield=qfield, gold_field=gold_field))

    with open(os.path.join(args.out_dir, "SUMMARY.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print("\n=== SUMMARY ===")
    for s in summary:
        print(s)
