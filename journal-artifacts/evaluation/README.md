# Evaluation artifacts — n=12 CAPE expansion + independent benchmarks

Raw predictions, logs, and per-sample results from a GPU evaluation session extending the
campaign in [`BENCHMARK_RESULTS_LOG.md`](../../BENCHMARK_RESULTS_LOG.md). All runs used the
`unified-v2` LoRA adapter served on an AMD Instinct MI300X.

## 1. CAPE real-pipeline evaluation, n=3 → n=12

Ran the same pipeline as Run 7 (`benchmark_pipeline_real.py`: identical SOC-analyst
instruction, `[INST]` prompt template, real `CAPEEvidenceExtractor`, greedy decode,
`max_new_tokens=1024`, `repetition_penalty=1.15`, `max_length=8192`) against the same
`unified-v2` adapter, extended from 3 to 12 CAPE-detonated samples across 5 malware families.

**Validation gate** (ids 12/15/16, the original Run 7 set): reproduced **Exact F1 0.886,
Parent F1 0.861** vs. the published 0.868/0.841 — within normal run-to-run variance,
confirming the pipeline and environment match the original.

**Full n=12 result:**

| id | family | Exact F1 | Parent F1 | GT status |
|---|---|---|---|---|
| 12 | Emotet | 0.889 | 0.857 | verified (original Run 7 sample) |
| 15 | Formbook | 0.909 | 1.000 | verified (original Run 7 sample) |
| 16 | Dridex | 1.000 | 1.000 | verified (original Run 7 sample) |
| 601 | AgentTesla | 0.125 | 0.400 | auto-derived, not hand-verified |
| 603 | Conti | 0.000 | 0.500 | auto-derived, not hand-verified |
| 604 | Conti | 0.200 | 0.400 | auto-derived, not hand-verified |
| 605 | Conti | 0.200 | 0.200 | auto-derived, not hand-verified |
| 607 | Conti | 0.333 | 0.333 | auto-derived, not hand-verified |
| 608 | Conti | 0.400 | 0.444 | auto-derived, not hand-verified |
| 609 | Dridex | 0.000 | 0.000 | auto-derived, not hand-verified |
| 610 | Emotet | 0.167 | 0.364 | auto-derived, not hand-verified |
| 613 | Formbook | 0.667 | 0.667 | auto-derived, not hand-verified |
| **MEAN (n=12)** | | **0.408** | **0.514** | |

Independently cross-checked with `scripts/score_attack_f1.py`; both scorers agree.
As expected, the n=12 mean lands well below the original n=3 headline (0.868/0.841) —
those three were unusually clean samples — but well above the rigorous 20-case synthetic
floor (0.344) already disclosed in the paper.

**⚠️ Status: preliminary, not yet a validated headline result.** The ground truth for the 9
new samples is auto-derived from sandbox behavior (`scripts/derive_ground_truth.py`), not
hand-verified against each report. Two samples (603, 607) have thin 1-2 code ground truth,
which is fragile to F1 scoring. Do not cite the n=12 numbers as final without a hand-check
pass over `samples/ground_truth.csv`'s auto-derived rows.

Files: [`cape/cape_val_n3.json`](cape/cape_val_n3.json),
[`cape/cape_n12.json`](cape/cape_n12.json),
[`cape/predictions_n12.json`](cape/predictions_n12.json).

## 2. SECURE — independent, contamination-checked benchmark

[SECURE](https://github.com/aiforsec/SECURE) (Bhusal et al., 2024) is not derived from
CyberMetric or MMLU; an 8-gram shingle-overlap check against the training corpus found
0.00-0.21% overlap across all subsets scored — genuinely independent evaluation data.

| Subset | Fathom | Published base Mixtral-8x7B (SECURE paper, Table V) | Delta |
|---|---|---|---|
| MAET — ATT&CK technique MCQ (n=1072) | **87.78%** | 80.9% | **+6.9pp** |
| CWET — CWE weakness MCQ (n=965) | **87.88%** | 83.4% | **+4.5pp** |

MAET and CWET are direct ATT&CK/CWE technique-mapping tasks, aligned with Fathom's domain,
and give an apples-to-apples comparison against the exact base model on data with no training
overlap. The other two SECURE subsets (KCV, VOOD — CVE-severity boolean prediction) were
scoped out: they're a different task from Fathom's ATT&CK/malware-analysis focus, and a
serving-configuration limit prevented reproducing the paper's full CVE-context-grounded
prompt for those two without further engineering.

Files: [`secure_cybersoceval/secure_maet_predictions.jsonl`](secure_cybersoceval/secure_maet_predictions.jsonl),
[`secure_cybersoceval/secure_cwet_predictions.jsonl`](secure_cybersoceval/secure_cwet_predictions.jsonl)
(KCV/VOOD predictions are also included for completeness, but are not comparable to the
published baseline for the reason above).

## 3. CyberSOCEval — domain-aligned independent benchmark

[CyberSOCEval](https://arxiv.org/abs/2503.19107) (Meta CyberSecEval 4) evaluates SOC-analyst
reasoning: multi-select MCQ over real sandbox detonation logs and CTI reports. 0% training
overlap confirmed. No published Mixtral-8x7B baseline exists for this benchmark, so results
are standalone evidence of domain capability rather than a base-model comparison.

| Subset | Exact-set accuracy | Mean Jaccard overlap |
|---|---|---|
| Malware-analysis reasoning (n=609) | 10.18% | **0.415** |
| Threat-intel reasoning (n=588) | 27.04% | **0.555** |

Exact-set match requires selecting the precise correct answer subset with nothing missing or
extra — a strict bar for multi-select questions with up to 10 candidates. Mean Jaccard overlap
is more informative: on average the model's selected answers overlap 41.5% (malware-analysis)
and 55.5% (threat-intel) with the gold set.

Files: [`secure_cybersoceval/cybersoceval_malware_predictions.jsonl`](secure_cybersoceval/cybersoceval_malware_predictions.jsonl),
[`secure_cybersoceval/cybersoceval_threatintel_predictions.jsonl`](secure_cybersoceval/cybersoceval_threatintel_predictions.jsonl).

## Reproducing these results

- `scripts/score_secure_cybersoceval.py` — scores Fathom against a live vLLM
  OpenAI-compatible endpoint (`model=fathom`) for SECURE and CyberSOCEval; greedy decode.
- `logs/` — full stdout from each run (per-item progress, per-sample generations for CAPE),
  kept for audit purposes.

## Infrastructure note

Serving `umer07/fathom-mixtral` via vLLM's `--lora-modules` flag requires `HF_TOKEN` in the
serving process's environment to resolve the private adapter repository; without it, vLLM's
LoRA loader fails immediately (`FileNotFoundError`) rather than falling back to a Hugging Face
Hub download. Pre-downloading the adapter and pointing `--lora-modules` at the resolved local
snapshot path avoids the issue.
