#!/usr/bin/env python3
"""
Fathom Data Preprocessor v4.0
Converts all 5 core datasets to unified instruction-tuning JSONL format.

Output format per line:
{"instruction": "...", "input": "...", "output": "..."}

Run after download_datasets_v4.sh completes.
"""

import json
import os
import glob
import random
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

RAW_DIR = Path("/opt/fathom/data/crash_training/raw")
OUT_DIR = Path("/opt/fathom/data/crash_training/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

all_examples = []
stats = {}


def add_examples(name, examples):
    """Track examples by source."""
    global all_examples
    all_examples.extend(examples)
    stats[name] = len(examples)
    log.info(f"  → {name}: {len(examples):,} examples")


# ──────────────────────────────────────────────────────────
# 1. CyberMetric → instruction Q&A pairs
# ──────────────────────────────────────────────────────────
def process_cybermetric():
    log.info("\n[1] Processing CyberMetric...")
    examples = []
    for config_dir in sorted(RAW_DIR.glob("cybermetric/CyberMetric-*")):
        try:
            from datasets import load_from_disk
            ds = load_from_disk(str(config_dir))
            for split in ds.keys() if hasattr(ds, 'keys') else ['train']:
                data = ds[split] if hasattr(ds, 'keys') else ds
                for row in data:
                    q = row.get('question', row.get('Question', ''))
                    a = row.get('answer', row.get('Answer', ''))
                    choices = row.get('options', row.get('Options', ''))
                    if q and a:
                        inp = f"{choices}" if choices else ""
                        examples.append({
                            "instruction": f"Answer this cybersecurity question:\n{q}",
                            "input": inp,
                            "output": str(a)
                        })
        except Exception as e:
            log.warning(f"  CyberMetric {config_dir.name}: {e}")
    add_examples("CyberMetric", examples)


# ──────────────────────────────────────────────────────────
# 2. Trendyol Cybersecurity IT → instruction pairs
# ──────────────────────────────────────────────────────────
def process_trendyol():
    log.info("\n[2] Processing Trendyol Cybersecurity IT...")
    examples = []
    try:
        from datasets import load_from_disk
        ds = load_from_disk(str(RAW_DIR / "trendyol_cybersec"))
        for split in ds.keys() if hasattr(ds, 'keys') else ['train']:
            data = ds[split] if hasattr(ds, 'keys') else ds
            for row in data:
                inst = row.get('instruction', row.get('Instruction', ''))
                inp = row.get('input', row.get('Input', ''))
                out = row.get('output', row.get('Output', row.get('response', '')))
                if inst and out:
                    examples.append({
                        "instruction": str(inst),
                        "input": str(inp) if inp else "",
                        "output": str(out)
                    })
    except Exception as e:
        log.warning(f"  Trendyol: {e}")
    add_examples("Trendyol", examples)


# ──────────────────────────────────────────────────────────
# 3. Cybersecurity ShareGPT → conversation pairs
# ──────────────────────────────────────────────────────────
def process_sharegpt():
    log.info("\n[3] Processing Cybersecurity ShareGPT...")
    examples = []
    try:
        from datasets import load_from_disk
        ds = load_from_disk(str(RAW_DIR / "cybersec_sharegpt"))
        for split in ds.keys() if hasattr(ds, 'keys') else ['train']:
            data = ds[split] if hasattr(ds, 'keys') else ds
            for row in data:
                convs = row.get('conversations', row.get('messages', []))
                if isinstance(convs, list) and len(convs) >= 2:
                    # Take first human-assistant pair
                    human_msg = ""
                    assistant_msg = ""
                    for msg in convs:
                        role = msg.get('from', msg.get('role', ''))
                        content = msg.get('value', msg.get('content', ''))
                        if role in ('human', 'user') and not human_msg:
                            human_msg = content
                        elif role in ('gpt', 'assistant') and human_msg and not assistant_msg:
                            assistant_msg = content
                    if human_msg and assistant_msg:
                        examples.append({
                            "instruction": str(human_msg),
                            "input": "",
                            "output": str(assistant_msg)
                        })
    except Exception as e:
        log.warning(f"  ShareGPT: {e}")
    add_examples("ShareGPT", examples)


# ──────────────────────────────────────────────────────────
# 4. CyberLLMInstruct → instruction pairs from repo
# ──────────────────────────────────────────────────────────
def process_cyberllminstruct():
    log.info("\n[4] Processing CyberLLMInstruct...")
    examples = []
    repo_dir = RAW_DIR / "cyberllminstruct"
    # Look for JSON/JSONL files in the repo
    for pattern in ["**/*.json", "**/*.jsonl"]:
        for fpath in repo_dir.glob(pattern):
            try:
                if fpath.suffix == '.jsonl':
                    with open(fpath) as f:
                        for line in f:
                            row = json.loads(line.strip())
                            inst = row.get('instruction', row.get('prompt', ''))
                            inp = row.get('input', row.get('context', ''))
                            out = row.get('output', row.get('response', row.get('completion', '')))
                            if inst and out:
                                examples.append({"instruction": str(inst), "input": str(inp) if inp else "", "output": str(out)})
                else:
                    with open(fpath) as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for row in data:
                            inst = row.get('instruction', row.get('prompt', ''))
                            inp = row.get('input', row.get('context', ''))
                            out = row.get('output', row.get('response', row.get('completion', '')))
                            if inst and out:
                                examples.append({"instruction": str(inst), "input": str(inp) if inp else "", "output": str(out)})
            except Exception as e:
                log.warning(f"  File {fpath.name}: {e}")
    add_examples("CyberLLMInstruct", examples)


# ──────────────────────────────────────────────────────────
# 5. MITRE ATT&CK → technique instruction pairs
# ──────────────────────────────────────────────────────────
def process_mitre_attack():
    log.info("\n[5] Processing MITRE ATT&CK techniques...")
    examples = []
    attack_dir = RAW_DIR / "mitre_attack" / "enterprise-attack" / "attack-pattern"

    if not attack_dir.exists():
        # Try alternate path
        for alt in [RAW_DIR / "mitre_attack" / "enterprise-attack", RAW_DIR / "mitre_attack"]:
            json_files = list(alt.glob("**/*.json"))
            if json_files:
                attack_dir = alt
                break

    for fpath in sorted(attack_dir.glob("**/*.json")):
        try:
            with open(fpath) as f:
                data = json.load(f)

            objects = data.get('objects', [data]) if isinstance(data, dict) else data
            for obj in objects:
                if obj.get('type') != 'attack-pattern':
                    continue

                name = obj.get('name', '')
                desc = obj.get('description', '')
                ext_refs = obj.get('external_references', [])
                technique_id = ''
                for ref in ext_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id', '')
                        break

                kill_chain = [p.get('phase_name', '') for p in obj.get('kill_chain_phases', [])]
                platforms = obj.get('x_mitre_platforms', [])

                if name and desc and technique_id:
                    # Instruction 1: Explain the technique
                    examples.append({
                        "instruction": f"Explain the MITRE ATT&CK technique {technique_id} ({name}).",
                        "input": "",
                        "output": f"**{technique_id}: {name}**\n\nTactic(s): {', '.join(kill_chain)}\nPlatform(s): {', '.join(platforms)}\n\n{desc[:2000]}"
                    })

                    # Instruction 2: Map behavior to technique
                    if len(desc) > 100:
                        behavior_snippet = desc[:300].rsplit('.', 1)[0] + '.'
                        examples.append({
                            "instruction": "Given the following malware behavior, identify the MITRE ATT&CK technique.",
                            "input": behavior_snippet,
                            "output": f"This behavior maps to **{technique_id}: {name}** under the tactic(s): {', '.join(kill_chain)}."
                        })

                    # Instruction 3: Detection guidance
                    detect = obj.get('x_mitre_detection', '')
                    if detect:
                        examples.append({
                            "instruction": f"How can a SOC analyst detect {technique_id} ({name})?",
                            "input": "",
                            "output": detect[:2000]
                        })

        except Exception as e:
            log.warning(f"  ATT&CK file {fpath.name}: {e}")

    add_examples("MITRE ATT&CK", examples)


# ──────────────────────────────────────────────────────────
# BONUS: Additional small datasets
# ──────────────────────────────────────────────────────────
def process_bonus():
    log.info("\n[BONUS] Processing additional datasets...")

    # CybersecurityQAA
    try:
        from datasets import load_from_disk
        ds = load_from_disk(str(RAW_DIR / "cybersec_qaa"))
        examples = []
        for split in ds.keys() if hasattr(ds, 'keys') else ['train']:
            for row in (ds[split] if hasattr(ds, 'keys') else ds):
                q = row.get('question', row.get('Question', ''))
                a = row.get('answer', row.get('Answer', ''))
                if q and a:
                    examples.append({"instruction": str(q), "input": "", "output": str(a)})
        add_examples("CybersecurityQAA", examples)
    except Exception as e:
        log.warning(f"  QAA: {e}")

    # NIST
    try:
        ds = load_from_disk(str(RAW_DIR / "nist_cybersec"))
        examples = []
        for split in ds.keys() if hasattr(ds, 'keys') else ['train']:
            for row in (ds[split] if hasattr(ds, 'keys') else ds):
                inst = row.get('instruction', row.get('text', ''))
                out = row.get('output', row.get('response', ''))
                if inst and out:
                    examples.append({"instruction": str(inst), "input": "", "output": str(out)})
        add_examples("NIST", examples)
    except Exception as e:
        log.warning(f"  NIST: {e}")


# ──────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("FATHOM Data Preprocessor v4.0")
    log.info("=" * 60)

    process_cybermetric()
    process_trendyol()
    process_sharegpt()
    process_cyberllminstruct()
    process_mitre_attack()
    process_bonus()

    # Shuffle and split
    random.seed(42)
    random.shuffle(all_examples)

    total = len(all_examples)
    eval_size = min(2000, int(total * 0.1))
    train_data = all_examples[eval_size:]
    eval_data = all_examples[:eval_size]

    log.info(f"\n{'=' * 60}")
    log.info(f"TOTAL: {total:,} examples")
    log.info(f"TRAIN: {len(train_data):,}  |  EVAL: {len(eval_data):,}")
    log.info(f"{'=' * 60}")

    # Per-source stats
    log.info("\nPer-source breakdown:")
    for name, count in sorted(stats.items(), key=lambda x: -x[1]):
        pct = count / total * 100 if total else 0
        log.info(f"  {name:25s} {count:>8,}  ({pct:.1f}%)")

    # Save
    train_path = OUT_DIR / "fathom_train_combined.jsonl"
    eval_path = OUT_DIR / "fathom_eval.jsonl"

    with open(train_path, 'w') as f:
        for ex in train_data:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')

    with open(eval_path, 'w') as f:
        for ex in eval_data:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')

    # Save metadata
    meta = {
        'timestamp': datetime.now().isoformat(),
        'total_examples': total,
        'train_examples': len(train_data),
        'eval_examples': len(eval_data),
        'sources': stats,
        'train_file': str(train_path),
        'eval_file': str(eval_path)
    }
    with open(OUT_DIR / "preprocessing_metadata.json", 'w') as f:
        json.dump(meta, f, indent=2)

    log.info(f"\n✅ Train: {train_path}")
    log.info(f"✅ Eval:  {eval_path}")
    log.info(f"✅ Meta:  {OUT_DIR / 'preprocessing_metadata.json'}")


if __name__ == "__main__":
    main()
