"""
LLM-as-judge for SecurePatch experiment patches.

Independent judge models score every generated patch from 1 to 5 on three
criteria with a fixed rubric. The judges come from different model families
than the generators (Qwen, Llama) to avoid self-preference bias:

    groq    openai/gpt-oss-120b      (open-weight, OpenAI)  -> main judge
    gemini  Gemini Flash             (Google)               -> second judge

Both are called through their OpenAI-compatible chat endpoints with
temperature 0. API keys are read from the environment only (never saved):

    $env:GROQ_API_KEY   = "..."   ; python judge_patches.py --judge groq
    $env:GEMINI_API_KEY = "..."   ; python judge_patches.py --judge gemini
    python judge_patches.py --judge groq --probe    # 4 known patches only

Identical patches (same vulnerability, same patch text, e.g. across seeds)
are judged once and the score is reused for every run that produced them.

Output: workspace/experiments/v2/judgements_<judge>.jsonl
        workspace/experiments/v2/human_check.csv (fill in, then re-run analysis)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "workspace" / "experiments" / "v2"
RUNS_FILE = OUT / "runs.jsonl"
HUMAN_FILE = OUT / "human_check.csv"

JUDGES = {
    "groq": {
        "label": "GPT-OSS-120B (Groq)",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "key_env": "GROQ_API_KEY",
        "model": "openai/gpt-oss-120b",
        "file": "judgements_gpt-oss-120b.jsonl",
    },
    "gemini": {
        "label": "Gemini Flash (Google AI Studio)",
        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "key_env": "GEMINI_API_KEY",
        "model": "gemini-3.8-flash",  # pinned version (not "latest") for reproducibility
        "file": "judgements_gemini.jsonl",
    },
}
TEMPERATURE = 0.0
MAX_TOKENS = 2000  # reasoning models spend tokens before the JSON answer

SYSTEM = "You are a strict senior application-security reviewer. You review security patches for Python code."

RUBRIC = """Review this security patch.

Reported vulnerability: {vuln}

ORIGINAL function:
```python
{orig}
```

PATCHED function:
```python
{patch}
```

Judge three things independently:
(1) security - is the reported vulnerability really gone? A patch that hides it
    (e.g. "# nosec", renaming, swapping to an equally unsafe library) or adds a
    new vulnerability is NOT a fix.
(2) behavior - does the function still do its intended job for legitimate inputs
    (same purpose, signature, return values)? Code that would crash or that
    removes the feature is broken.
(3) quality - is the change minimal, clean and idiomatic, without unrelated edits?

Integer scores from 1 to 5 (5 = best, 1 = worst):
security: 5 = fully fixed, 3 = partly fixed, 1 = still vulnerable or new vulnerability
behavior: 5 = same intended behaviour, 3 = minor changes, 1 = broken or feature removed
quality:  5 = minimal clean idiomatic change, 3 = acceptable, 1 = messy or unrelated edits

Answer with ONLY one JSON object, no other text:
{{"security": <1-5>, "behavior": <1-5>, "quality": <1-5>, "reason": "<one sentence>"}}"""

# Patches with a known correct answer, used by --probe to sanity-check a judge.
PROBES = [
    ("qwen_full|B105@benchmark_vulnerabilities.py:111|11", "good fix -> security high"),
    ("llama_full|B102@benchmark_vulnerabilities.py:30|11", "ast.parse(code object) crashes -> behavior low"),
    ("llama_full|B301@services/file_service.py:33|11", "pickle -> dill, equally unsafe -> security low"),
    ("qwen_full|B202@benchmark_vulnerabilities.py:86|11", "extractall unchanged -> security low"),
]


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def load_runs_unique() -> list[dict]:
    rows = {}
    for r in load_jsonl(RUNS_FILE):
        rows[r["key"]] = r  # last record wins
    return list(rows.values())


def original_function(row: dict) -> str:
    sys.path.insert(0, str(ROOT))
    from run_experiments import DATASETS, function_at

    repo = ROOT / DATASETS[row["dataset"]]["repo"]
    source = (repo / row["file"]).read_text(encoding="utf-8")
    return function_at(source, int(row["line"])) or ""


def patch_id(row: dict) -> str:
    """Runs with the same target and the same patch text share one judgement."""
    text = "\n".join(line.rstrip() for line in row["patch_text"].strip().splitlines())
    return f"{row['dataset']}|{row['file']}|{row['line']}|{text}"


class StopJudging(Exception):
    pass


def call_judge(cfg: dict, key: str, prompt: str) -> str:
    body = {
        "model": cfg["model"],
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
    }
    for attempt in range(8):
        try:
            resp = requests.post(cfg["url"], json=body, timeout=120,
                                 headers={"Authorization": f"Bearer {key}"})
        except requests.RequestException as exc:
            wait = 10 * (attempt + 1)
            print(f"    network error ({exc.__class__.__name__}), retrying in {wait}s", flush=True)
            time.sleep(wait)
            continue
        if resp.status_code == 429:
            retry = resp.headers.get("retry-after")
            wait = min(float(retry), 120) if retry and retry.replace(".", "").isdigit() else 20 * (attempt + 1)
            low = resp.text.lower()
            daily = "per day" in low or "(tpd)" in low or "(rpd)" in low or "perday" in low
            if daily or ("quota" in low and attempt >= 5):
                raise StopJudging(f"Rate limit / daily quota reached: {resp.text[:300]}")
            print(f"    rate limited, waiting {wait:.0f}s", flush=True)
            time.sleep(wait)
            continue
        if resp.status_code in (401, 403):
            raise StopJudging(f"API key rejected (HTTP {resp.status_code}): {resp.text[:300]}")
        if resp.status_code == 404 or (resp.status_code == 400 and "model" in resp.text.lower()):
            raise StopJudging(f"Model not found: {resp.text[:300]}  (use --model with the exact name)")
        if resp.status_code >= 500:
            wait = 10 * (attempt + 1)
            print(f"    judge server error HTTP {resp.status_code} ({resp.text[:120].strip()}), "
                  f"retrying in {wait}s", flush=True)
            time.sleep(wait)
            continue
        resp.raise_for_status()
        choice = resp.json()["choices"][0]["message"]
        return choice.get("content") or ""
    raise StopJudging("Judge API kept failing after 8 attempts; re-run later to resume.")


def parse_scores(text: str) -> dict:
    matches = re.findall(r"\{[^{}]*\"security\"[^{}]*\}", text, re.S)
    data = {}
    if matches:
        try:
            data = json.loads(matches[-1])
        except json.JSONDecodeError:
            data = {}
    scores = {}
    for k in ("security", "behavior", "quality"):
        try:
            scores[k] = max(1, min(5, int(round(float(data.get(k))))))
        except (TypeError, ValueError):
            scores[k] = None
    scores["reason"] = str(data.get("reason", ""))[:300]
    return scores


def judge_row(cfg: dict, key: str, row: dict) -> dict:
    prompt = RUBRIC.format(vuln=f"{row['vulnerability']} ({row['severity']})",
                           orig=original_function(row), patch=row["patch_text"])
    t0 = time.perf_counter()
    text = call_judge(cfg, key, prompt)
    scores = parse_scores(text)
    return {**scores, "judge_model": cfg["model"], "judge_seconds": round(time.perf_counter() - t0, 2),
            "raw": None if scores["security"] is not None else text[:500]}


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
    ap.add_argument("--judge", choices=sorted(JUDGES), required=True)
    ap.add_argument("--model", help="Override the judge model name")
    ap.add_argument("--probe", action="store_true", help="Judge only 4 patches with known answers")
    ap.add_argument("--list-models", action="store_true", help="Show the model names this key can use")
    ap.add_argument("--delay", type=float, default=2.5, help="Seconds between API calls (free-tier limits)")
    ap.add_argument("--sample", type=int, default=12, help="Patches in the human-check sheet")
    args = ap.parse_args()

    cfg = dict(JUDGES[args.judge])
    if args.model:
        cfg["model"] = args.model
    key = os.environ.get(cfg["key_env"], "").strip()
    if not key:
        sys.exit(f"Set the API key first:  $env:{cfg['key_env']} = \"your-key\"")

    if args.list_models:
        url = cfg["url"].rsplit("/chat/completions", 1)[0] + "/models"
        resp = requests.get(url, headers={"Authorization": f"Bearer {key}"}, timeout=30)
        print(f"HTTP {resp.status_code}")
        try:
            for m in resp.json().get("data", []):
                print(" ", m.get("id"))
        except ValueError:
            print(resp.text[:500])
        return

    runs = [r for r in load_runs_unique() if r.get("patch_generated") and r.get("patch_text")]
    by_key = {r["key"]: r for r in runs}

    if args.probe:
        print(f"Probe with {cfg['model']}:")
        for k, expected in PROBES:
            try:
                res = judge_row(cfg, key, by_key[k])
            except StopJudging as exc:
                sys.exit(f"STOPPED: {exc}")
            print(f"  S={res['security']} B={res['behavior']} Q={res['quality']}  expected: {expected}\n"
                  f"     {k}\n     reason: {res['reason'] or res['raw']}", flush=True)
            time.sleep(args.delay)
        return

    out_file = OUT / cfg["file"]
    existing = load_jsonl(out_file)
    done = {j["key"] for j in existing if j.get("security") is not None}
    cache = {j["patch_id"]: j for j in existing if j.get("security") is not None and j.get("patch_id")}

    todo = [r for r in runs if r["key"] not in done]
    unique = {patch_id(r) for r in todo} - set(cache)
    print(f"{len(runs)} patches, {len(done)} already judged, {len(todo)} to go "
          f"({len(unique)} unique) with {cfg['model']}")
    t0, calls = time.time(), 0
    try:
        for i, row in enumerate(todo, 1):
            pid = patch_id(row)
            if pid in cache:
                src = cache[pid]
                res = {k: src[k] for k in ("security", "behavior", "quality", "reason", "judge_model")}
                res.update(judge_seconds=0.0, raw=None, reused_from=src["key"])
            else:
                res = judge_row(cfg, key, row)
                calls += 1
                time.sleep(args.delay)
            res = {"key": row["key"], "patch_id": pid, **res}
            if res.get("security") is not None:
                cache[pid] = res
            with out_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(res) + "\n")
            left = (time.time() - t0) / max(calls, 1) * max(len(unique) - calls, 0) / 60
            print(f"[{i}/{len(todo)}] {row['key']}: S={res['security']} B={res['behavior']} "
                  f"Q={res['quality']}{' (reused)' if 'reused_from' in res else ''}  ~{left:.0f} min left",
                  flush=True)
    except StopJudging as exc:
        sys.exit(f"\nSTOPPED: {exc}\nRe-run the same command later to resume.")
    print(f"Done: {out_file}")
    if not HUMAN_FILE.exists() and runs:
        write_human_sheet(list(runs), args.sample)


if __name__ == "__main__":
    main()
