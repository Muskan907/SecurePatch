"""Architecture and workflow diagrams for the paper (vector PDF).

Run from the repository root:  python paper/make_diagrams.py [preview_dir]
"""
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon  # noqa: E402

OUT = Path(__file__).resolve().parent / "figures"
PREVIEW = Path(sys.argv[1]) if len(sys.argv) > 1 else None
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
                     "pdf.fonttype": 42})

EDGE = "#1f2937"
FILL = {"io": "#e0ecff", "core": "#ffffff", "ok": "#dcfce7", "bad": "#fee2e2", "dec": "#fef9c3", "band": "#f3f4f6",
        "llm": "#ede9fe", "ops": "#f1f5f9"}


def box(ax, x, y, w, h, text, fill="core", fs=8.5, bold=False, round_=0.06, ls="-"):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h, boxstyle=f"round,pad=0,rounding_size={round_}",
                                fc=FILL[fill], ec=EDGE, lw=0.9, ls=ls))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal",
            linespacing=1.15)


def diamond(ax, x, y, w, h, text, fs=8.2):
    ax.add_patch(Polygon([(x, y + h / 2), (x + w / 2, y), (x, y - h / 2), (x - w / 2, y)], closed=True,
                         fc=FILL["dec"], ec=EDGE, lw=0.9))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, linespacing=1.1)


def arrow(ax, p, q, label=None, lpos=0.5, loff=(0.06, 0.0), conn="arc3", fs=7.5, ha="left"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=10, lw=0.9, color=EDGE,
                                 connectionstyle=conn, shrinkA=0, shrinkB=0))
    if label:
        lx = p[0] + (q[0] - p[0]) * lpos + loff[0]
        ly = p[1] + (q[1] - p[1]) * lpos + loff[1]
        ax.text(lx, ly, label, fontsize=fs, ha=ha, va="center", style="italic")


def poly_arrow(ax, pts, label=None, lpt=None, fs=7.5, ha="left"):
    for a, b in zip(pts[:-2], pts[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=EDGE, lw=0.9)
    arrow(ax, pts[-2], pts[-1])
    if label:
        ax.text(lpt[0], lpt[1], label, fontsize=fs, ha=ha, va="center", style="italic")


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight", pad_inches=0.03)
    if PREVIEW:
        fig.savefig(PREVIEW / f"{name}.png", dpi=130, bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)


# ============================================================ Architecture
fig, ax = plt.subplots(figsize=(7.2, 7.0))
ax.set_xlim(0, 7.2)
ax.set_ylim(0, 7.0)
ax.axis("off")

bands = [  # (label, y-centre)
    ("Interface", 6.35), ("Detection", 5.25), ("Context", 4.15), ("Generation", 3.05), ("Validation", 1.95),
    ("Output", 0.85)]
BH = 0.92
X0, X1 = 0.05, 6.05  # band extent (right part reserved for the deployment column)
for label, y in bands:
    ax.add_patch(FancyBboxPatch((X0, y - BH / 2), X1 - X0, BH, boxstyle="round,pad=0,rounding_size=0.05",
                                fc=FILL["band"], ec="#9ca3af", lw=0.6))
    ax.text(X0 + 0.2, y, label, rotation=90, ha="center", va="center", fontsize=8.5, fontweight="bold",
            color="#374151")

W, H = 1.62, 0.62
C = [1.3, 3.15, 5.0]  # column centres inside a band
ROW = {lab: y for lab, y in bands}
# Interface
box(ax, C[0], ROW["Interface"], W, H, "Web interface\n(React + Vite)", "io")
box(ax, C[1], ROW["Interface"], W, H, "REST API\n(FastAPI backend)", "io")
box(ax, C[2], ROW["Interface"], W, H, "Repository import\n(Git URL / ZIP)", "io")
arrow(ax, (C[0] + W / 2, ROW["Interface"]), (C[1] - W / 2, ROW["Interface"]))
arrow(ax, (C[2] - W / 2, ROW["Interface"]), (C[1] + W / 2, ROW["Interface"]))
# Detection
box(ax, C[0], ROW["Detection"], W, H, "Bandit scanner\n(AST rules)")
box(ax, C[1], ROW["Detection"], W, H, "Semgrep scanner\n(pattern rules)")
box(ax, C[2], ROW["Detection"], W, H, "Finding list\n(rule, line, severity)")
arrow(ax, (C[0] + W / 2, ROW["Detection"]), (C[1] - W / 2, ROW["Detection"]))
arrow(ax, (C[1] + W / 2, ROW["Detection"]), (C[2] - W / 2, ROW["Detection"]))
# Context
box(ax, C[0], ROW["Context"], W, H, "Source graph\n(callers, callees)")
box(ax, C[1], ROW["Context"], W, H, "Related tests\nand imports")
box(ax, C[2], ROW["Context"], W, H, "RAG retriever\n(MiniLM + ChromaDB)")
# Generation
box(ax, C[0], ROW["Generation"], W, H, "Prompt builder\n(task placed last)")
box(ax, C[1], ROW["Generation"], W, H, "Local LLM (Ollama)\n+ fallback chain", "llm")
box(ax, C[2], ROW["Generation"], W, H, "Pre-apply\nguardrails")
arrow(ax, (C[0] + W / 2, ROW["Generation"]), (C[1] - W / 2, ROW["Generation"]))
arrow(ax, (C[1] + W / 2, ROW["Generation"]), (C[2] - W / 2, ROW["Generation"]))
# Validation
box(ax, C[0], ROW["Validation"], W, H, "Sandbox patcher\n+ post-apply guard")
box(ax, C[1], ROW["Validation"], W, H, "Security re-scan\n(Bandit + Semgrep)")
box(ax, C[2], ROW["Validation"], W, H, "Regression tests\n(pytest)")
arrow(ax, (C[0] + W / 2, ROW["Validation"]), (C[1] - W / 2, ROW["Validation"]))
arrow(ax, (C[1] + W / 2, ROW["Validation"]), (C[2] - W / 2, ROW["Validation"]))
# Output
box(ax, C[0], ROW["Output"], W, H, "Verdict: verified\nor rejected", "ok")
box(ax, C[1], ROW["Output"], W, H, "Report and fixed\ncode (download / Git)", "ok")
box(ax, C[2], ROW["Output"], W, H, "Metrics: Prometheus\n+ Grafana dashboard", "ops")
arrow(ax, (C[0] + W / 2, ROW["Output"]), (C[1] - W / 2, ROW["Output"]))

# flow between layers
arrow(ax, (C[1], ROW["Interface"] - H / 2), (C[1], ROW["Detection"] + H / 2))
arrow(ax, (C[2], ROW["Detection"] - H / 2), (C[2], ROW["Context"] + H / 2))
for c in C:
    arrow(ax, (c, ROW["Context"] - H / 2), (C[0] + (c - C[0]) * 0.0 + (0.25 * (C.index(c) - 1)), ROW["Generation"] + H / 2))
poly_arrow(ax, [(C[2], ROW["Generation"] - H / 2), (C[2], ROW["Generation"] - 0.55), (C[0], ROW["Generation"] - 0.55),
                (C[0], ROW["Validation"] + H / 2)])
poly_arrow(ax, [(C[2], ROW["Validation"] - H / 2), (C[2], ROW["Validation"] - 0.55), (C[0], ROW["Validation"] - 0.55),
                (C[0], ROW["Output"] + H / 2)])
ax.text(C[1] + 0.08, ROW["Generation"] - 0.47, "candidate patch $\\phi'$", fontsize=7.5, style="italic", va="center")
ax.text(C[1] + 0.08, ROW["Validation"] - 0.47, "all checks pass $\\Rightarrow$ verified", fontsize=7.5,
        style="italic", va="center")

# deployment column
dx = 6.62
ax.add_patch(FancyBboxPatch((dx - 0.45, 0.39), 0.9, 6.42, boxstyle="round,pad=0,rounding_size=0.05",
                            fc=FILL["ops"], ec=EDGE, lw=0.9, ls="--"))
ax.text(dx, 3.6, "Deployment: Docker Compose / Kubernetes\n(backend, frontend, Ollama, monitoring)",
        rotation=90, ha="center", va="center", fontsize=8.2, linespacing=1.3)
save(fig, "architecture")

# ============================================================ Workflow
fig, ax = plt.subplots(figsize=(6.6, 10.1))
ax.set_xlim(0, 6.6)
ax.set_ylim(0, 10.1)
ax.axis("off")
MX = 2.9            # main column x
SW, SH = 3.3, 0.48  # step box
DW, DH = 2.3, 0.62  # decision diamond
REJ_X = 5.75
y = dict([("start", 9.8), ("s1", 9.1), ("s2", 8.45), ("s3", 7.8), ("s4", 7.15), ("d1", 6.4), ("d2", 5.55),
          ("s5", 4.8), ("d3", 4.05), ("s6", 3.3), ("d4", 2.55), ("s7", 1.8), ("d5", 1.05), ("end", 0.3)])
REJ_Y = y["d3"]

box(ax, MX, y["start"], 2.6, 0.42, "Input: repository $R$ and SAST finding $f$", "io", round_=0.2)
box(ax, MX, y["s1"], SW, SH, "Step 1: scan $R$ with Bandit and Semgrep")
box(ax, MX, y["s2"], SW, SH, "Step 2: locate the vulnerable function $\\phi$")
box(ax, MX, y["s3"], SW, SH, "Step 3: build context (callers, tests,\nimports, top-$k$ RAG chunks)")
box(ax, MX, y["s4"], SW, SH, "Step 4: build prompt, generate $\\phi'$\nwith the current model $m$", "llm")
diamond(ax, MX, y["d1"], DW, DH, "Usable function\nreturned?")
diamond(ax, MX, y["d2"], DW, DH, "Pre-apply\nguardrails pass?")
box(ax, MX, y["s5"], SW, SH, "Step 5: replace $\\phi$ by $\\phi'$ in a sandbox copy")
diamond(ax, MX, y["d3"], DW, DH, "All names\ndefined?")
box(ax, MX, y["s6"], SW, SH, "Step 6: function-scoped Bandit re-scan\nand Semgrep comparison")
diamond(ax, MX, y["d4"], DW, DH, "Rule $r$ removed\nfrom $\\phi'$?")
box(ax, MX, y["s7"], SW, SH, "Step 7: run regression tests (pytest)\nin the sandbox")
diamond(ax, MX, y["d5"], DW, DH, "All tests\npass?")
box(ax, MX, y["end"], 2.6, 0.42, "VERIFIED: return $\\phi'$ and report", "ok", round_=0.2, bold=True)

order = ["start", "s1", "s2", "s3", "s4", "d1", "d2", "s5", "d3", "s6", "d4", "s7", "d5", "end"]
half = {k: (DH / 2 if k.startswith("d") else (0.21 if k in ("start", "end") else SH / 2)) for k in order}
for a, b in zip(order[:-1], order[1:]):
    arrow(ax, (MX, y[a] - half[a]), (MX, y[b] + half[b]), label="yes" if a.startswith("d") else None, lpos=0.45)

# rejection path: every failed check ends in REJECTED
RW, RH = 1.35, 0.5
box(ax, REJ_X, REJ_Y, RW, RH, "REJECTED\n(reason logged)", "bad", bold=True, round_=0.2)
VX = REJ_X - 0.35
for d in ("d2", "d3", "d4", "d5"):
    if d == "d3":
        arrow(ax, (MX + DW / 2, y[d]), (REJ_X - RW / 2, y[d]), label="no", lpos=0.08, loff=(0.0, 0.11))
        continue
    end_y = REJ_Y + RH / 2 if y[d] > REJ_Y else REJ_Y - RH / 2
    poly_arrow(ax, [(MX + DW / 2, y[d]), (VX, y[d]), (VX, end_y)], label="no",
               lpt=(MX + DW / 2 + 0.08, y[d] + 0.11))

# fallback loop over the model chain
LX = 0.67
diamond(ax, LX, y["d1"], 1.15, 0.7, "Another\nmodel?", fs=7.6)
arrow(ax, (MX - DW / 2, y["d1"]), (LX + 0.575, y["d1"]), label="no", lpos=0.5, loff=(-0.05, 0.11), ha="center")
poly_arrow(ax, [(LX, y["d1"] + 0.35), (LX, y["s4"]), (MX - SW / 2, y["s4"])], label="yes",
           lpt=(LX + 0.07, y["d1"] + 0.52))
box(ax, LX, y["d2"] - 0.1, 1.05, 0.42, "NO_PATCH", "bad", bold=True, round_=0.2, fs=7.8)
arrow(ax, (LX, y["d1"] - 0.35), (LX, y["d2"] - 0.1 + 0.21), label="no", lpos=0.5, loff=(0.05, 0))
save(fig, "workflow")
print("diagrams written")
