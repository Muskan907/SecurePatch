"""
LLM-as-judge for SecurePatch experiment patches.

A fixed judge model (DeepSeek-Coder-V2, a different model family from the
generators Qwen and Llama, to avoid self-preference bias) scores every
generated patch from 1 to 5 on three criteria with a written rubric.
Temperature 0 and a fixed seed make the judge deterministic.

    python judge_patches.py                 # judge all patches not judged yet
    python judge_patches.py --sample 12     # also write a human-check sheet

Output: workspace/experiments/v2/judgements.jsonl
        workspace/experiments/v2/human_check.csv (fill in, then re-run analysis)
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "workspace" / "experiments" / "v2"
RUNS_FILE = OUT / "runs.jsonl"
JUDGE_FILE = OUT / "judgements.jsonl"
HUMAN_FILE = OUT / "human_check.csv"

OLLAMA = "http://127.0.0.1:11434"
JUDGE_MODEL = "deepseek-coder-v2:16b-lite-instruct-q2_K"
JUDGE_OPTIONS = {"temperature": 0.0, "seed": 7, "num_ctx": 4096, "num_predict": 200}

RUBRIC = """You are a strict senior application-security reviewer.
Compare the ORIGINAL vulnerable Python function with the PATCHED version.

Score each criterion from 1 (very poor) to 5 (excellent):
- security: Does the patch genuinely remove the reported vulnerability
  (not hide it, e.g. with "# nosec", renaming, or deleting the feature)?
- behavior: Does the patched function keep the original intended behaviour
  for legitimate inputs (same purpose, signature, return values)?
- quality: Is the change minimal, clean and idiomatic, without unrelated edits?

Answer with ONLY one JSON object, no other text:
{"security": <1-5>, "behavior": <1-5>, "quality": <1-5>, "reason": "<one sentence>"}"""


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def original_function(row: dict) -> str:
    sys.path.insert(0, str(ROOT))
    from run_experiments import DATASETS, function_at

    repo = ROOT / DATASETS[row["dataset"]]["repo"]
    source = (repo / row["file"]).read_text(encoding="utf-8")
    return function_at(source, int(row["line"])) or ""


def judge(row: dict) -> dict:
    prompt = (
        f"{RUBRIC}\n\nREPORTED VULNERABILITY: {row['vulnerability']} ({row['severity']})\n\n"
        f"ORIGINAL FUNCTION:\n{original_function(row)}\n\nPATCHED FUNCTION:\n{row['patch_text']}\n"
    )
    t0 = time.perf_counter()
    resp = requests.post(
        f"{OLLAMA}/api/generate",
        json={"model": JUDGE_MODEL, "prompt": prompt, "stream": False,
              "format": "json", "options": JUDGE_OPTIONS},
        timeout=600,
    )
    resp.raise_for_status()
    text = resp.json().get("response", "")
    match = re.search(r"\{.*\}", text, re.S)
    data = json.loads(match.group(0)) if match else {}
    scores = {}
    for k in ("security", "behavior", "quality"):
        try:
            scores[k] = max(1, min(5, int(round(float(data.get(k))))))
        except (TypeError, ValueError):
            scores[k] = None
    return {"key": row["key"], **scores, "reason": str(data.get("reason", ""))[:300],
            "judge_model": JUDGE_MODEL, "judge_seconds": round(time.perf_counter() - t0, 2),
            "raw": text[:500] if not match else None}


def write_human_sheet(rows: list[dict], n: int):
    random.Random(2024).shuffle(rows)
    sample = rows[:n]
    with HUMAN_FILE.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["key", "vulnerability", "verdict", "original_function", "patched_function",
                    "human_security_1to5", "human_behavior_1to5", "human_quality_1to5"])
        for r in sample:
            w.writerow([r["key"], r["vulnerability"], r["verdict"], original_function(r),
                        r["patch_text"], "", "", ""])
    print(f"Human-check sheet: {HUMAN_FILE}  (fill the last 3 columns, 1-5)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=12, help="Patches in the human-check sheet")
    args = ap.parse_args()

    runs = [r for r in load_runs_unique() if r.get("patch_generated") and r.get("patch_text")]
    done = {j["key"] for j in load_jsonl(JUDGE_FILE)}
    todo = [r for r in runs if r["key"] not in done]
    print(f"{len(runs)} patches, {len(done)} already judged, {len(todo)} to judge with {JUDGE_MODEL}")
    t0 = time.time()
    for i, row in enumerate(todo, 1):
        try:
            res = judge(row)
        except requests.ConnectionError:
            sys.exit("Ollama not reachable. Start Ollama and re-run to resume.")
        except Exception as exc:  # noqa: BLE001
            res = {"key": row["key"], "security": None, "behavior": None, "quality": None,
                   "reason": f"judge error: {exc}"[:300], "judge_model": JUDGE_MODEL}
        with JUDGE_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(res) + "\n")
        left = (time.time() - t0) / i * (len(todo) - i) / 60
        print(f"[{i}/{len(todo)}] {row['key']}: S={res['security']} B={res['behavior']} "
              f"Q={res['quality']}  ~{left:.0f} min left", flush=True)
    if not HUMAN_FILE.exists() and runs:
        write_human_sheet(list(runs), args.sample)


def load_runs_unique() -> list[dict]:
    rows = {}
    for r in load_jsonl(RUNS_FILE):
        rows[r["key"]] = r  # last record wins
    return list(rows.values())


if __name__ == "__main__":
    main()
