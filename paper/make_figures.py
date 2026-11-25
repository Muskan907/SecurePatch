"""Paper figures (vector PDF) built from the experiment data.

Run from the repository root:
    python paper/make_figures.py
Reads reports/experiment_results/summary.json and workspace/experiments/v2/runs.jsonl
and writes paper/figures/*.pdf (no titles: LaTeX captions number the figures).
"""
import json
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze_experiments import failure_category  # noqa: E402

OUT = ROOT / "paper" / "figures"
S = json.loads((ROOT / "reports/experiment_results/summary.json").read_text(encoding="utf-8"))
RUNS = [json.loads(l) for l in (ROOT / "workspace/experiments/v2/runs.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
    "savefig.bbox": "tight", "pdf.fonttype": 42,
})
BLUE, GREEN, ORANGE, RED, GREY, PURPLE = "#2563eb", "#16a34a", "#f59e0b", "#dc2626", "#64748b", "#7c3aed"


def ms(exp, metric="verified"):
    return S[exp][metric] if exp in S else (float("nan"), 0.0)


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.pdf")
    plt.close(fig)


# Fig: verified rate per method on D1 and D2 ----------------------------------
methods = [("SecurePatch\n(Qwen2.5-Coder 7B)", "qwen_full", None, BLUE),
           ("SecurePatch\n(Llama 3.1 8B)", "llama_full", "llama_full_d2", GREEN),
           ("Plain LLM\n(Llama 3.1 8B)", "plain_llm_d1", "plain_llm_d2", PURPLE),
           ("Rule-based\nfixer", "rule_d1", "rule_d2", ORANGE)]
fig, ax = plt.subplots(figsize=(6.3, 3.0))
w = 0.38
for i, (label, d1, d2, col) in enumerate(methods):
    for j, (exp, hatch) in enumerate(((d1, ""), (d2, "//"))):
        if not exp:
            continue
        m, s = ms(exp)
        x = i + (j - 0.5) * w
        ax.bar(x, m, w * 0.95, yerr=s, capsize=3, color=col, hatch=hatch, edgecolor="black", linewidth=0.5,
               error_kw={"elinewidth": 0.8})
        ax.text(x, m + s + 2, f"{m:.1f}", ha="center", va="bottom", fontsize=8)
ax.set_xticks(range(len(methods)), [m[0] for m in methods])
ax.set_ylabel("Verified fixes (%)")
ax.set_ylim(0, 108)
from matplotlib.patches import Patch  # noqa: E402
ax.legend(handles=[Patch(facecolor="white", edgecolor="black", label="D1 (synthetic)"),
                   Patch(facecolor="white", edgecolor="black", hatch="//", label="D2 (OWASP PyGoat)")],
          loc="upper right", frameon=False, fontsize=8, ncol=2)
save(fig, "verified_main")

# Fig: ablation of the context components -------------------------------------
groups = [("Full pipeline\n(RAG k=6 + context)", "llama_full", "llama_full_d2"),
          ("Without RAG\n(k=0, context kept)", "ablation_no_rag", "ablation_no_rag_d2"),
          ("Plain LLM\n(no context)", "plain_llm_d1", "plain_llm_d2")]
fig, ax = plt.subplots(figsize=(6.3, 2.9))
for i, (label, d1, d2) in enumerate(groups):
    for j, (exp, col) in enumerate(((d1, BLUE), (d2, GREEN))):
        m, s = ms(exp)
        x = i + (j - 0.5) * w
        ax.bar(x, m, w * 0.95, yerr=s, capsize=3, color=col, edgecolor="black", linewidth=0.5,
               error_kw={"elinewidth": 0.8})
        ax.text(x, m + s + 2, f"{m:.1f}", ha="center", va="bottom", fontsize=8)
ax.set_xticks(range(len(groups)), [g[0] for g in groups])
ax.set_ylabel("Verified fixes (%)")
ax.set_ylim(0, 108)
ax.legend(handles=[Patch(facecolor=BLUE, edgecolor="black", label="D1 (synthetic)"),
                   Patch(facecolor=GREEN, edgecolor="black", label="D2 (OWASP PyGoat)")],
          loc="upper right", frameon=False, fontsize=8, ncol=2)
save(fig, "ablation_context")

# Fig: trend over the number of retrieved chunks k ------------------------------
ks = [(0, "ablation_no_rag"), (3, "topk_3"), (6, "llama_full")]
fig, ax1 = plt.subplots(figsize=(5.2, 2.7))
v = [ms(e) for _, e in ks]
t = [ms(e, "generation_seconds") for _, e in ks]
ax1.errorbar([k for k, _ in ks], [a for a, _ in v], yerr=[b for _, b in v], marker="o", color=BLUE, capsize=3,
             label="Verified fixes (%)")
ax1.set_xlabel("Retrieved RAG chunks k")
ax1.set_ylabel("Verified fixes (%)", color=BLUE)
ax1.set_ylim(50, 100)
ax1.set_xticks([0, 3, 6])
ax2 = ax1.twinx()
ax2.spines["right"].set_visible(True)
ax2.errorbar([k for k, _ in ks], [a for a, _ in t], yerr=[b for _, b in t], marker="s", linestyle="--",
             color=ORANGE, capsize=3, label="Generation time (s)")
ax2.set_ylabel("Generation time per patch (s)", color=ORANGE)
ax2.set_ylim(0, 40)
h1, l1 = ax1.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax1.legend(h1 + h2, l1 + l2, loc="upper left", frameon=False, fontsize=8)
save(fig, "topk_trend")

# Fig: error analysis -------------------------------------------------------------
order = [("SecurePatch, Qwen (D1)", "qwen_full"), ("SecurePatch, Llama (D1)", "llama_full"),
         ("SecurePatch, fallback chain (D1)", "fallback_full"), ("Without RAG (D1)", "ablation_no_rag"),
         ("RAG k=3 (D1)", "topk_3"), ("Plain LLM (D1)", "plain_llm_d1"), ("Rule-based (D1)", "rule_d1"),
         ("SecurePatch, Llama (D2)", "llama_full_d2"), ("Without RAG (D2)", "ablation_no_rag_d2"),
         ("Plain LLM (D2)", "plain_llm_d2"), ("Rule-based (D2)", "rule_d2")]
cats = [("Verified", GREEN), ("Vulnerability still present", ORANGE), ("Broke existing tests", PURPLE),
        ("Invalid / blocked by guardrails", RED), ("No patch / generation failed", GREY)]
counts = {}
for r in RUNS:
    r = dict(r, verified=r.get("verdict") == "VERIFIED")
    counts.setdefault(r["experiment"], Counter())[failure_category(r)] += 1
fig, ax = plt.subplots(figsize=(6.3, 3.6))
y = list(range(len(order)))[::-1]
left = [0] * len(order)
for cat, col in cats:
    vals = [counts.get(e, Counter())[cat] for _, e in order]
    if not any(vals):
        continue
    ax.barh(y, vals, left=left, color=col, edgecolor="black", linewidth=0.4, label=cat)
    left = [a + b for a, b in zip(left, vals)]
ax.set_yticks(y, [o[0] for o in order], fontsize=8)
ax.set_xlabel("Runs (out of 30 per configuration)")
ax.set_xlim(0, 30)
ax.legend(loc="upper center", bbox_to_anchor=(0.45, -0.17), ncol=2, frameon=False, fontsize=8)
save(fig, "error_analysis")

# Fig: LLM judge vs automatic verdict ----------------------------------------------
from analyze_experiments import judge_index  # noqa: E402
J = judge_index()
by = {}
for r in RUNS:
    j = J.get(r["key"]) if J else None
    if not j or j.get("security") is None:
        continue
    r = dict(r, verified=r.get("verdict") == "VERIFIED")
    c = failure_category(r)
    by.setdefault(c, []).append(j)
labels = [c for c in ("Verified", "Vulnerability still present", "Invalid / blocked by guardrails") if c in by]
fig, ax = plt.subplots(figsize=(5.6, 2.7))
w3 = 0.27
for k, (crit, col) in enumerate((("security", BLUE), ("behavior", GREEN), ("quality", ORANGE))):
    vals = [sum(x[crit] for x in by[c]) / len(by[c]) for c in labels]
    xs = [i + (k - 1) * w3 for i in range(len(labels))]
    ax.bar(xs, vals, w3 * 0.95, color=col, edgecolor="black", linewidth=0.5,
           label={"behavior": "Behaviour"}.get(crit, crit.capitalize()))
    for x_, v_ in zip(xs, vals):
        ax.text(x_, v_ + 0.08, f"{v_:.2f}", ha="center", va="bottom", fontsize=7)
ax.set_xticks(range(len(labels)), [f"{c}\n(n = {len(by[c])})" for c in labels], fontsize=8)
ax.set_ylabel("Mean judge score (1-5)")
ax.set_ylim(0, 5.6)
ax.legend(loc="upper right", frameon=False, fontsize=8, ncol=3)
save(fig, "judge_vs_sast")

print("wrote", sorted(p.name for p in OUT.glob("*.pdf")))
