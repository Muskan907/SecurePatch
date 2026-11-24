"""
Build every results table and figure for the report from the v2 runs.

    python analyze_experiments.py

Reads  workspace/experiments/v2/{runs.jsonl, judgements.jsonl, environment.json, human_check.csv}
Writes reports/experiment_results/
         RESULTS.md            all tables (best values in bold), ready to paste
         summary.json          every number in machine-readable form
         fig1_main_comparison.png  fig2_heatmap.png  fig3_ablation.png
         fig4_failures.png     fig5_time_vs_success.png  fig6_severity.png
         fig7_judge.png

Rates are computed per seed over all vulnerabilities, then reported as
mean ± sample standard deviation over the 3 seeds.
"""
from __future__ import annotations

import csv
import json
import math
import statistics as st
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from run_experiments import DATASETS, EXPERIMENTS, SEEDS, TEMPERATURE  # noqa: E402

ROOT = Path(__file__).resolve().parent
IN = ROOT / "workspace" / "experiments" / "v2"
OUT = ROOT / "reports" / "experiment_results"

METRICS = [  # key, title, higher_is_better, reason
    ("patch_generated", "Patch generated (%)", True,
     "Share of runs that produced a usable function at all."),
    ("syntax_valid", "Valid syntax (%)", True,
     "The patch parses as exactly one Python function."),
    ("vulnerability_removed", "Vulnerability removed (%)", True,
     "The scanner no longer reports the targeted finding: the security goal."),
    ("regression_passed", "Tests pass (%)", True,
     "The project's existing tests still pass: behaviour is preserved."),
    ("verified", "Verified (%)", True,
     "Main metric: vulnerability removed AND tests pass AND no guardrail violation."),
]

COLORS = ["#2563eb", "#16a34a", "#f59e0b", "#dc2626", "#7c3aed", "#0891b2", "#64748b"]


# ---------------------------------------------------------------------------
def load_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def runs():
    rows = {}
    for r in load_jsonl(IN / "runs.jsonl"):
        r["verified"] = r.get("verdict") == "VERIFIED"
        rows[r["key"]] = r
    return list(rows.values())


def mean_std(values):
    values = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    if not values:
        return None, None
    m = st.mean(values)
    s = st.stdev(values) if len(values) > 1 else 0.0
    return m, s


def per_seed_rate(rows, key):
    by_seed = defaultdict(list)
    for r in rows:
        by_seed[r["seed"]].append(bool(r.get(key)))
    return [100 * sum(v) / len(v) for _, v in sorted(by_seed.items()) if v]


def per_seed_mean(rows, key, only=None):
    by_seed = defaultdict(list)
    for r in rows:
        if only and not only(r):
            continue
        if r.get(key) is not None:
            by_seed[r["seed"]].append(float(r[key]))
    return [st.mean(v) for _, v in sorted(by_seed.items()) if v]


def fmt(m, s, digits=1):
    if m is None:
        return "–"
    return f"{m:.{digits}f} ± {s:.{digits}f}"


def bold_best(table, col_idx, values, higher=True):
    valid = [(i, v) for i, v in enumerate(values) if v is not None]
    if not valid:
        return
    best = max(v for _, v in valid) if higher else min(v for _, v in valid)
    for i, v in valid:
        if abs(v - best) < 1e-9:
            table[i][col_idx] = f"**{table[i][col_idx]}**"


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def judge_index():
    return {j["key"]: j for j in load_jsonl(IN / "judgements.jsonl")}


# ---------------------------------------------------------------------------
def summarize(exp_rows, judges):
    s = {"runs": len(exp_rows)}
    for key, *_ in METRICS:
        s[key] = mean_std(per_seed_rate(exp_rows, key))
    s["generation_seconds"] = mean_std(per_seed_mean(exp_rows, "generation_seconds"))
    s["new_findings"] = mean_std(per_seed_mean(exp_rows, "new_findings"))
    for crit in ("security", "behavior", "quality"):
        vals = defaultdict(list)
        for r in exp_rows:
            j = judges.get(r["key"])
            if j and j.get(crit) is not None:
                vals[r["seed"]].append(j[crit])
        s[f"judge_{crit}"] = mean_std([st.mean(v) for v in vals.values() if v])
    return s


def results_table(dataset, exps, summaries):
    headers = ["Method"] + [m[1] for m in METRICS] + ["Gen. time (s) ↓", "Judge security (1–5)",
                                                       "Judge behaviour (1–5)", "Judge quality (1–5)"]
    rows, cols = [], defaultdict(list)
    for name in exps:
        s = summaries[name]
        row = [EXPERIMENTS[name]["label"]]
        for key, *_ in METRICS:
            row.append(fmt(*s[key]))
            cols[key].append(s[key][0])
        row.append(fmt(*s["generation_seconds"]))
        cols["time"].append(s["generation_seconds"][0])
        for crit in ("security", "behavior", "quality"):
            row.append(fmt(*s[f"judge_{crit}"], digits=2))
            cols[crit].append(s[f"judge_{crit}"][0])
        rows.append(row)
    for i, (key, _, higher, _) in enumerate(METRICS, start=1):
        bold_best(rows, i, cols[key], higher)
    bold_best(rows, len(METRICS) + 1, cols["time"], higher=False)
    for k, crit in enumerate(("security", "behavior", "quality")):
        bold_best(rows, len(METRICS) + 2 + k, cols[crit], True)
    return md_table(headers, rows)


# ---------------------------------------------------------------------------
def failure_category(r):
    if r.get("verified"):
        return "Verified"
    if not r.get("patch_generated"):
        return "No patch / generation failed"
    if not r.get("syntax_valid") or r.get("verdict") == "REJECTED" and r.get("tests_passed") in (None, 0) \
            and not r.get("regression_passed") and "guardrail" in str(r.get("reason", "")).lower():
        return "Invalid / blocked by guardrails"
    if not r.get("regression_passed"):
        return "Broke existing tests"
    if not r.get("vulnerability_removed"):
        return "Vulnerability still present"
    return "Other rejection"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    all_rows = runs()
    judges = judge_index()
    by_exp = defaultdict(list)
    for r in all_rows:
        by_exp[r["experiment"]].append(r)
    present = [e for e in EXPERIMENTS if by_exp.get(e)]
    summaries = {e: summarize(by_exp[e], judges) for e in present}
    md = ["# SecurePatch experiment results (v2)", "",
          "Generated from `workspace/experiments/v2`. Every rate is computed per seed "
          f"(seeds {SEEDS}) over all vulnerabilities, then reported as **mean ± standard deviation** "
          "over the seeds. Best value per column in **bold**.", ""]

    # ---- Environment and parameters -----------------------------------
    envs = json.loads((IN / "environment.json").read_text(encoding="utf-8")) if (IN / "environment.json").exists() else []
    if envs:
        env = envs[-1]
        b = env.get("backend", {})
        hw = env.get("hardware", {})
        md += ["## Test environment", "", md_table(["Item", "Value"], [
            ["CPU", hw.get("cpu", "–")], ["RAM", f"{hw.get('ram_gb', '–')} GB"], ["GPU", hw.get("gpu", "–")],
            ["OS", hw.get("os", "–")], ["Python (backend)", b.get("python", "–")],
            ["Ollama", b.get("ollama_version", "–")],
            *[[k, v or "–"] for k, v in (b.get("packages") or {}).items()],
            ["Semgrep", (b.get("semgrep") or {}).get("version") or "1.186.0 (pinned in scripts/setup_semgrep.py)"],
            ["Sandbox isolation", (b.get("sandbox") or {}).get("isolation", "–")],
        ]), ""]
        models = b.get("models", {})
        md += ["## Models", "", md_table(["Key", "Ollama model", "Parameters", "Quantization", "Digest"], [
            [k, v.get("ollama_name"), v.get("parameters", "–"), v.get("quantization", "–"), v.get("digest", "–")]
            for k, v in models.items()]), ""]
        opts = (b.get("generation_options") or {}).get("llama3.1", {})
        rag = b.get("rag", {})
        md += ["## Parameters", "", md_table(["Parameter", "Value"], [
            ["Temperature (generation)", TEMPERATURE], ["Random seeds", ", ".join(map(str, SEEDS))],
            ["Runs per configuration", f"{len(SEEDS)} (one per seed)"],
            ["num_predict (max output tokens)", opts.get("num_predict")], ["top_p", opts.get("top_p")],
            ["repeat_penalty (Llama / Qwen)", f"{opts.get('repeat_penalty')} / "
             f"{(b.get('generation_options') or {}).get('qwen2.5-coder', {}).get('repeat_penalty')}"],
            ["num_ctx (context window)", opts.get("num_ctx")],
            ["Embedding model", rag.get("embedding_model")], ["RAG chunk size / overlap (chars)",
             f"{rag.get('chunk_size_chars')} / {rag.get('chunk_overlap_chars')}"],
            ["RAG top-k chunks", rag.get("top_k")], ["Max RAG context (chars)", rag.get("max_context_chars")],
            ["Fallback order", " → ".join(b.get("fallback_order", []))],
            ["pytest timeout (s)", b.get("pytest_timeout_seconds")],
            ["Judge model / temperature / seed", "deepseek-coder-v2:16b-lite-instruct-q2_K / 0.0 / 7"],
        ]), ""]

    # ---- Datasets -------------------------------------------------------
    md += ["## Datasets", ""]
    for k, d in DATASETS.items():
        sev = defaultdict(int)
        for v in d["vulns"]:
            sev[v[3]] += 1
        md += [f"- **{k}: {d['name']}**: {len(d['vulns'])} vulnerabilities "
               f"({', '.join(f'{n} {s}' for s, n in sev.items())}). {d['source']}. "
               f"Rules: {', '.join(v[0] for v in d['vulns'])}."]
    md += ["", "## Metrics", "", md_table(["Metric", "Why"], [[m[1], m[3]] for m in METRICS] + [
        ["Generation time (s)", "Practicality on a laptop: wall-clock time to produce a patch."],
        ["Judge scores (1–5)", "Patch quality beyond what the scanner can see (real fix, behaviour, minimality)."],
    ]), ""]

    # ---- Main results ---------------------------------------------------
    figs = []
    for ds in DATASETS:
        exps = [e for e in present if EXPERIMENTS[e]["dataset"] == ds and EXPERIMENTS[e]["role"] in ("method", "baseline")]
        if exps:
            md += [f"## Results on {ds} ({DATASETS[ds]['name']})", "", results_table(ds, exps, summaries), ""]

    # ---- Ablation -------------------------------------------------------
    abl = [e for e in ("llama_full", "ablation_no_rag", "plain_llm_d1", "qwen_full", "fallback_full") if e in summaries]
    if abl:
        md += ["## Ablation study (D1)", "", results_table("D1", abl, summaries), "",
               "- *without RAG*: retrieved repository context removed, everything else unchanged.",
               "- *Plain LLM*: RAG, source graph, callers, tests and imports all removed (finding + function only).",
               "- *full system*: Qwen first, automatic fallback to other models when generation fails.", ""]
    # Without the Bandit re-scan: accept whenever the patch is valid and tests pass.
    rows_rescan = []
    for e in [x for x in ("qwen_full", "llama_full", "fallback_full", "llama_full_d2") if x in by_exp]:
        rr = by_exp[e]
        accept = per_seed_rate([dict(r, acc=r.get("patch_generated") and r.get("syntax_valid") and r.get("regression_passed")) for r in rr], "acc")
        false_acc = per_seed_rate([dict(r, fa=r.get("patch_generated") and r.get("syntax_valid") and r.get("regression_passed") and not r.get("vulnerability_removed")) for r in rr], "fa")
        rows_rescan.append([EXPERIMENTS[e]["label"] + f" ({EXPERIMENTS[e]['dataset']})", fmt(*mean_std(accept)),
                            fmt(*summaries[e]["verified"]), fmt(*mean_std(false_acc))])
    if rows_rescan:
        md += ["### Ablation: removing the security re-scan from validation", "",
               md_table(["Method", "Accepted without re-scan (%)", "Accepted with re-scan = Verified (%)",
                         "Insecure patches wrongly accepted without re-scan (%)"], rows_rescan), ""]

    # ---- Per-vulnerability ----------------------------------------------
    d1_exps = [e for e in present if EXPERIMENTS[e]["dataset"] == "D1"]
    vulns = [v[0] for v in DATASETS["D1"]["vulns"]]
    matrix = []
    for e in d1_exps:
        row = []
        for v in vulns:
            rr = [r for r in by_exp[e] if r["vulnerability"] == v]
            row.append(sum(r["verified"] for r in rr) if rr else 0)
        matrix.append(row)
    if matrix:
        md += ["## Per-vulnerability results (D1, verified runs out of 3)", "",
               md_table(["Method"] + vulns, [[EXPERIMENTS[e]["label"]] + matrix[i] for i, e in enumerate(d1_exps)]), ""]

    # ---- Failure analysis -----------------------------------------------
    cats = ["Verified", "Vulnerability still present", "Broke existing tests",
            "Invalid / blocked by guardrails", "No patch / generation failed", "Other rejection"]
    fail = {e: defaultdict(int) for e in present}
    for e in present:
        for r in by_exp[e]:
            fail[e][failure_category(r)] += 1
    md += ["## Error analysis (all runs)", "", md_table(["Method (dataset)"] + cats, [
        [f"{EXPERIMENTS[e]['label']} ({EXPERIMENTS[e]['dataset']})"] + [fail[e][c] for c in cats] for e in present]), ""]

    # ---- Severity -------------------------------------------------------
    sev_rows = []
    for e in d1_exps:
        row = [EXPERIMENTS[e]["label"]]
        for sv in ("HIGH", "MEDIUM", "LOW"):
            rr = [r for r in by_exp[e] if r["severity"] == sv]
            row.append(fmt(*mean_std(per_seed_rate(rr, "verified"))) if rr else "–")
        sev_rows.append(row)
    if sev_rows:
        md += ["## Verified rate by severity (D1)", "", md_table(["Method", "HIGH", "MEDIUM", "LOW"], sev_rows), ""]

    # ---- Previous study comparison --------------------------------------
    old = ROOT / "workspace" / "experiments" / "final_30_runs" / "model_summary.csv"
    if old.exists():
        with old.open(encoding="utf-8") as f:
            old_rows = {r["model"]: r for r in csv.DictReader(f)}
        comp = []
        for name, key in (("Qwen2.5-Coder 7B", "qwen_full"), ("Llama 3.1 8B", "llama_full")):
            if name in old_rows and key in summaries:
                comp.append([name, f"{float(old_rows[name]['verified_rate']):.1f} (1 run, temp 0)",
                             fmt(*summaries[key]["verified"])])
        if comp:
            md += ["## Before vs after this iteration (D1, verified %)", "",
                   md_table(["Model", "Earlier study", "Now (mean ± std, 3 seeds)"], comp),
                   "", "Changes since the earlier study: context-window fix (num_ctx 8192, task placed last), "
                   "capped RAG context, related tests passed to the prompt, Semgrep-assisted validation.", ""]

    # ---- Judge agreement with human ------------------------------------
    hfile = IN / "human_check.csv"
    if hfile.exists():
        pairs = []
        with hfile.open(encoding="utf-8") as f:
            for r in csv.DictReader(f):
                j = judges.get(r["key"])
                for crit, col in (("security", "human_security_1to5"), ("behavior", "human_behavior_1to5"),
                                  ("quality", "human_quality_1to5")):
                    if j and r.get(col, "").strip() and j.get(crit) is not None:
                        pairs.append((float(r[col]), float(j[crit])))
        if pairs:
            within1 = 100 * sum(abs(a - b) <= 1 for a, b in pairs) / len(pairs)
            exact = 100 * sum(a == b for a, b in pairs) / len(pairs)
            mae = st.mean(abs(a - b) for a, b in pairs)
            try:
                r_val = st.correlation([a for a, _ in pairs], [b for _, b in pairs])
            except Exception:  # noqa: BLE001
                r_val = float("nan")
            md += ["## LLM-judge agreement with human review", "", md_table(
                ["Scores compared", "Exact agreement (%)", "Within ±1 (%)", "Mean abs. difference", "Pearson r"],
                [[len(pairs), f"{exact:.1f}", f"{within1:.1f}", f"{mae:.2f}", f"{r_val:.2f}"]]), ""]

    # ---- Figures --------------------------------------------------------
    plt.rcParams.update({"figure.dpi": 150, "font.size": 9, "axes.spines.top": False, "axes.spines.right": False})

    def bar_with_err(ax, labels, ms, ss, color_list, ylabel):
        xs = range(len(labels))
        ax.bar(xs, [m or 0 for m in ms], yerr=[s or 0 for s in ss], capsize=4, color=color_list)
        ax.set_xticks(list(xs))
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_ylabel(ylabel)
        for x, m in zip(xs, ms):
            if m is not None:
                ax.text(x, (m or 0) + 2, f"{m:.0f}", ha="center", fontsize=8)

    main_exps = [e for e in present if EXPERIMENTS[e]["dataset"] == "D1" and EXPERIMENTS[e]["role"] in ("method", "baseline")]
    if main_exps:
        fig, ax = plt.subplots(figsize=(7, 4))
        bar_with_err(ax, [EXPERIMENTS[e]["label"].replace(" (baseline)", "\n(baseline)") for e in main_exps],
                     [summaries[e]["verified"][0] for e in main_exps], [summaries[e]["verified"][1] for e in main_exps],
                     COLORS, "Verified fixes (%)")
        ax.set_ylim(0, 110)
        ax.set_title("Fig. 1  Verified fix rate on D1 (mean ± std, 3 seeds)")
        fig.tight_layout()
        fig.savefig(OUT / "fig1_main_comparison.png")
        figs.append("fig1_main_comparison.png")
        plt.close(fig)

    if matrix:
        fig, ax = plt.subplots(figsize=(8, 0.6 * len(d1_exps) + 1.5))
        im = ax.imshow(matrix, cmap="Greens", vmin=0, vmax=3, aspect="auto")
        ax.set_xticks(range(len(vulns)))
        ax.set_xticklabels(vulns)
        ax.set_yticks(range(len(d1_exps)))
        ax.set_yticklabels([EXPERIMENTS[e]["label"] for e in d1_exps])
        for i, row in enumerate(matrix):
            for j, v in enumerate(row):
                ax.text(j, i, v, ha="center", va="center", color="white" if v >= 2 else "black")
        fig.colorbar(im, ax=ax, label="Verified runs (of 3)")
        ax.set_title("Fig. 2  Which method fixes which vulnerability (D1)")
        fig.tight_layout()
        fig.savefig(OUT / "fig2_heatmap.png")
        figs.append("fig2_heatmap.png")
        plt.close(fig)

    if abl:
        fig, ax = plt.subplots(figsize=(7, 4))
        bar_with_err(ax, [EXPERIMENTS[e]["label"].replace("SecurePatch ", "SP ") for e in abl],
                     [summaries[e]["verified"][0] for e in abl], [summaries[e]["verified"][1] for e in abl],
                     COLORS[1:], "Verified fixes (%)")
        ax.set_ylim(0, 110)
        ax.set_title("Fig. 3  Ablation: effect of RAG, context and fallback (D1)")
        fig.tight_layout()
        fig.savefig(OUT / "fig3_ablation.png")
        figs.append("fig3_ablation.png")
        plt.close(fig)

    if present:
        fig, ax = plt.subplots(figsize=(8, 4))
        bottom = [0] * len(present)
        for c, col in zip(cats, ["#16a34a", "#f59e0b", "#dc2626", "#7c3aed", "#64748b", "#94a3b8"]):
            vals = [fail[e][c] for e in present]
            ax.bar(range(len(present)), vals, bottom=bottom, label=c, color=col)
            bottom = [b + v for b, v in zip(bottom, vals)]
        ax.set_xticks(range(len(present)))
        ax.set_xticklabels([f"{e}\n({EXPERIMENTS[e]['dataset']})" for e in present], rotation=30, ha="right", fontsize=7)
        ax.set_ylabel("Runs")
        ax.legend(fontsize=7, bbox_to_anchor=(1.01, 1), loc="upper left")
        ax.set_title("Fig. 4  Error analysis: outcome of every run")
        fig.tight_layout()
        fig.savefig(OUT / "fig4_failures.png")
        figs.append("fig4_failures.png")
        plt.close(fig)

    llm_exps = [e for e in present if EXPERIMENTS[e]["method"] == "llm" and summaries[e]["generation_seconds"][0]]
    if llm_exps:
        fig, ax = plt.subplots(figsize=(6, 4))
        for i, e in enumerate(llm_exps):
            s = summaries[e]
            ax.errorbar(s["generation_seconds"][0], s["verified"][0], xerr=s["generation_seconds"][1],
                        yerr=s["verified"][1], fmt="o", color=COLORS[i % len(COLORS)], capsize=3,
                        label=f"{EXPERIMENTS[e]['label']} ({EXPERIMENTS[e]['dataset']})")
        ax.set_xlabel("Generation time per patch (s)")
        ax.set_ylabel("Verified fixes (%)")
        ax.legend(fontsize=6)
        ax.set_title("Fig. 5  Success vs. time")
        fig.tight_layout()
        fig.savefig(OUT / "fig5_time_vs_success.png")
        figs.append("fig5_time_vs_success.png")
        plt.close(fig)

    if sev_rows:
        fig, ax = plt.subplots(figsize=(7, 4))
        width = 0.8 / max(1, len(d1_exps))
        for i, e in enumerate(d1_exps):
            ms, ss = [], []
            for sv in ("HIGH", "MEDIUM", "LOW"):
                m, s = mean_std(per_seed_rate([r for r in by_exp[e] if r["severity"] == sv], "verified"))
                ms.append(m or 0)
                ss.append(s or 0)
            ax.bar([x + i * width for x in range(3)], ms, width, yerr=ss, capsize=2,
                   label=EXPERIMENTS[e]["label"], color=COLORS[i % len(COLORS)])
        ax.set_xticks([x + width * (len(d1_exps) - 1) / 2 for x in range(3)])
        ax.set_xticklabels(["HIGH", "MEDIUM", "LOW"])
        ax.set_ylabel("Verified fixes (%)")
        ax.set_ylim(0, 110)
        ax.legend(fontsize=6)
        ax.set_title("Fig. 6  Verified rate by vulnerability severity (D1)")
        fig.tight_layout()
        fig.savefig(OUT / "fig6_severity.png")
        figs.append("fig6_severity.png")
        plt.close(fig)

    judged = [e for e in present if summaries[e]["judge_security"][0] is not None]
    if judged:
        fig, ax = plt.subplots(figsize=(8, 4))
        width = 0.25
        for k, crit in enumerate(("security", "behavior", "quality")):
            ax.bar([x + k * width for x in range(len(judged))], [summaries[e][f"judge_{crit}"][0] for e in judged],
                   width, yerr=[summaries[e][f"judge_{crit}"][1] for e in judged], capsize=2, label=crit,
                   color=COLORS[k])
        ax.set_xticks([x + width for x in range(len(judged))])
        ax.set_xticklabels([f"{e}\n({EXPERIMENTS[e]['dataset']})" for e in judged], rotation=30, ha="right", fontsize=7)
        ax.set_ylim(0, 5.5)
        ax.set_ylabel("Judge score (1–5)")
        ax.legend(fontsize=7)
        ax.set_title("Fig. 7  LLM-as-judge patch quality (mean ± std over seeds)")
        fig.tight_layout()
        fig.savefig(OUT / "fig7_judge.png")
        figs.append("fig7_judge.png")
        plt.close(fig)

    md += ["## Figures", ""] + [f"![{f}]({f})" for f in figs] + [""]
    (OUT / "RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(
        {e: {k: (list(v) if isinstance(v, tuple) else v) for k, v in s.items()} for e, s in summaries.items()},
        indent=2), encoding="utf-8")
    print(f"Wrote {OUT / 'RESULTS.md'} and {len(figs)} figures for {len(all_rows)} runs "
          f"across {len(present)} experiments.")


if __name__ == "__main__":
    main()
