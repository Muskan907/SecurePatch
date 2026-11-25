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
# Two columns: column A = preparation and generation, column B = checks.
fig, ax = plt.subplots(figsize=(7.0, 5.45))
ax.set_xlim(0, 7.0)
ax.set_ylim(0, 5.45)
ax.axis("off")
AX, BX = 1.55, 4.35          # column centres
SW, SH = 2.3, 0.44           # step box
DW, DH = 2.0, 0.52           # decision diamond
FS = 8.3
ya = {"start": 5.1, "s1": 4.47, "s2": 3.86, "s3": 3.25, "s4": 2.64, "d1": 1.96, "am": 1.18, "np": 0.45}
yb = {"d2": 5.1, "s5": 4.47, "d3": 3.84, "s6": 3.2, "d4": 2.56, "s7": 1.93, "d5": 1.3, "end": 0.45}

ax.text(AX, 5.42, "A. Preparation and generation", ha="center", va="center", fontsize=8.5, fontweight="bold")
ax.text(BX, 5.42, "B. Checks and verdict", ha="center", va="center", fontsize=8.5, fontweight="bold")

box(ax, AX, ya["start"], SW, 0.4, "Input: repository $R$, finding $f$", "io", fs=FS, round_=0.18)
box(ax, AX, ya["s1"], SW, SH, "Step 1: scan $R$ (Bandit, Semgrep)", fs=FS)
box(ax, AX, ya["s2"], SW, SH, "Step 2: locate vulnerable function $\\phi$", fs=FS)
box(ax, AX, ya["s3"], SW, SH, "Step 3: build context (callers,\ntests, imports, top-$k$ chunks)", fs=FS)
box(ax, AX, ya["s4"], SW, SH, "Step 4: generate $\\phi'$ with model $m$", "llm", fs=FS)
diamond(ax, AX, ya["d1"], DW, DH + 0.08, "Usable function?", fs=FS)
diamond(ax, AX, ya["am"], 1.7, DH + 0.08, "Another model?", fs=FS)
box(ax, AX, ya["np"], 1.4, 0.38, "NO_PATCH", "bad", fs=FS, bold=True, round_=0.18)

box(ax, BX, yb["s5"], SW, SH, "Step 5: apply $\\phi'$ in sandbox copy", fs=FS)
box(ax, BX, yb["s6"], SW, SH, "Step 6: function-scoped re-scan\n(Bandit) and Semgrep diff", fs=FS)
box(ax, BX, yb["s7"], SW, SH, "Step 7: run regression tests", fs=FS)
diamond(ax, BX, yb["d2"], DW, DH, "Guardrails pass?", fs=FS)
diamond(ax, BX, yb["d3"], DW, DH, "Names defined?", fs=FS)
diamond(ax, BX, yb["d4"], DW, DH, "Rule $r$ removed?", fs=FS)
diamond(ax, BX, yb["d5"], DW, DH, "Tests pass?", fs=FS)
box(ax, BX, yb["end"], SW, 0.4, "VERIFIED: return $\\phi'$", "ok", fs=FS, bold=True, round_=0.18)

hA = {"start": 0.2, "s1": SH / 2, "s2": SH / 2, "s3": SH / 2, "s4": SH / 2, "d1": (DH + 0.08) / 2,
      "am": (DH + 0.08) / 2, "np": 0.19}
for a, b in (("start", "s1"), ("s1", "s2"), ("s2", "s3"), ("s3", "s4"), ("s4", "d1")):
    arrow(ax, (AX, ya[a] - hA[a]), (AX, ya[b] + hA[b]))
arrow(ax, (AX, ya["d1"] - hA["d1"]), (AX, ya["am"] + hA["am"]), label="no", lpos=0.5)
arrow(ax, (AX, ya["am"] - hA["am"]), (AX, ya["np"] + hA["np"]), label="no", lpos=0.5)
# yes: next model -> back to step 4
LR = 0.22
poly_arrow(ax, [(AX - 0.85, ya["am"]), (LR, ya["am"]), (LR, ya["s4"]), (AX - SW / 2, ya["s4"])],
           label="yes", lpt=(LR + 0.05, (ya["am"] + ya["s4"]) / 2))
# usable -> column B (gutter)
GX = 2.95
poly_arrow(ax, [(AX + DW / 2, ya["d1"]), (GX, ya["d1"]), (GX, yb["d2"]), (BX - DW / 2, yb["d2"])],
           label="yes", lpt=(AX + DW / 2 + 0.05, ya["d1"] + 0.1))

hB = {"d2": DH / 2, "s5": SH / 2, "d3": DH / 2, "s6": SH / 2, "d4": DH / 2, "s7": SH / 2, "d5": DH / 2, "end": 0.2}
seqB = ["d2", "s5", "d3", "s6", "d4", "s7", "d5", "end"]
for a, b in zip(seqB[:-1], seqB[1:]):
    arrow(ax, (BX, yb[a] - hB[a]), (BX, yb[b] + hB[b]), label="yes" if a.startswith("d") else None, lpos=0.5)

# rejection rail on the right
RX, RAIL = 6.45, 5.85
box(ax, RX, 3.2, 0.95, 0.5, "REJECTED\n(logged)", "bad", fs=FS, bold=True, round_=0.18)
for d in ("d2", "d3", "d4", "d5"):
    ax.plot([BX + DW / 2, RAIL], [yb[d], yb[d]], color=EDGE, lw=0.9)
    ax.text(BX + DW / 2 + 0.05, yb[d] + 0.09, "no", fontsize=7.5, style="italic", va="center")
ax.plot([RAIL, RAIL], [yb["d2"], yb["d5"]], color=EDGE, lw=0.9)
arrow(ax, (RAIL, 3.2), (RX - 0.475, 3.2))
save(fig, "workflow")
print("diagrams written")
