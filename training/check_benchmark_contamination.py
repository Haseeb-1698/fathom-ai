#!/usr/bin/env python3
"""
check_benchmark_contamination.py

Quantifies train--test overlap between a multiple-choice benchmark
(CyberMetric-80 / CyberMetric-500 JSON) and the training corpus, and
optionally recomputes benchmark accuracy with the overlapping questions
removed. Implements the decontamination analysis reported in the Fathom
paper (Section 6.1).

Method: 8-word token shingles. A benchmark question is flagged "contaminated"
when >= THRESHOLD of its 8-gram shingles also appear in the training corpus.
This is robust to Alpaca-style reformatting, which breaks exact-string hashes.

Usage:
  python check_benchmark_contamination.py \
      --benchmark CyberMetric-80-v1.json \
      --train fathom_train_combined.jsonl unified_v3_train.jsonl \
      [--predictions cybermetric80_predictions.jsonl] \
      [--threshold 0.5]

Benchmark JSON is the Tihanyi et al. CyberMetric format:
  {"questions": [{"question": "...", "answers": {...}, "solution": "B"}, ...]}
Training files are Alpaca JSONL (instruction/input/output).
Prediction files (optional) carry per-question `id` (1-based) and `correct`.
"""
import argparse, json, re


def toks(s):
    return re.findall(r"[a-z0-9]+", (s or "").lower())


def shingles(words, n=8, stride=1):
    return {hash(" ".join(words[i:i + n]))
            for i in range(0, max(1, len(words) - n + 1), stride)}


def build_index(paths, n=8, stride=3):
    idx, rows = set(), 0
    for p in paths:
        try:
            for line in open(p, encoding="utf-8", errors="ignore"):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rows += 1
                w = toks(r.get("instruction", "")) + toks(r.get("input", "")) + toks(r.get("output", ""))
                idx |= shingles(w, n, stride)
        except FileNotFoundError:
            print(f"  [warn] training file not found: {p}")
    return idx, rows


def load_questions(path):
    d = json.load(open(path))
    qs = d["questions"] if isinstance(d, dict) else d
    return [q.get("question", "") for q in qs]


def is_contaminated(question, idx, threshold, n=8):
    w = toks(question)
    if len(w) < n:
        return False
    sh = shingles(w, n, 1)
    return (len(sh & idx) / max(1, len(sh))) >= threshold


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmark", required=True, help="CyberMetric JSON")
    ap.add_argument("--train", nargs="+", required=True, help="training JSONL file(s)")
    ap.add_argument("--predictions", help="optional per-question predictions JSONL (id, correct)")
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    print("Building shingle index over training corpus...")
    idx, rows = build_index(args.train)
    print(f"  training rows: {rows:,} | unique 8-gram shingles: {len(idx):,}")

    questions = load_questions(args.benchmark)
    flags = [is_contaminated(q, idx, args.threshold) for q in questions]
    n_contam = sum(flags)
    n = len(questions)
    print(f"\nBenchmark: {args.benchmark}")
    print(f"  contaminated (>={int(args.threshold*100)}% shingle overlap): "
          f"{n_contam}/{n} ({100*n_contam/n:.1f}%)")

    if args.predictions:
        preds = [json.loads(l) for l in open(args.predictions)]

        def correct(x):
            return str(x.get("correct")) in ("1", "True", "true")

        clean = [x for x in preds if not flags[int(x["id"]) - 1]]
        contam = [x for x in preds if flags[int(x["id"]) - 1]]
        full_acc = 100 * sum(correct(x) for x in preds) / len(preds)
        clean_acc = 100 * sum(correct(x) for x in clean) / max(1, len(clean))
        contam_acc = 100 * sum(correct(x) for x in contam) / max(1, len(contam))
        print(f"\n  accuracy FULL:          {full_acc:.2f}%  (n={len(preds)})")
        print(f"  accuracy CLEAN:         {clean_acc:.2f}%  (n={len(clean)}, removed {len(contam)})")
        print(f"  accuracy CONTAM subset: {contam_acc:.2f}%  (n={len(contam)})")
        print(f"  delta (full - clean):   {full_acc - clean_acc:+.2f} pp")
        print("\n  Interpretation: a near-zero delta and comparable seen/unseen "
              "accuracy indicate genuine capability, not memorisation.")


if __name__ == "__main__":
    main()
