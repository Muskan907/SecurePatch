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
# Three phases side by side; every step is a numbered box, every check a
# diamond, and every rejection reason gets its own outcome box.
W, H = 7.0, 6.05
fig, ax = plt.subplots(figsize=(W, H))
ax.set_xlim(-0.1, W)
ax.set_ylim(0, H)
ax.axis("off")
FS = 7.4
CA, CB, CC, CR = 0.86, 3.0, 5.1, 6.58     # column centres
BW, BH = 1.66, 0.42                       # step box
DW, DH = 1.62, 0.5                        # decision diamond
RW, RH = 0.8, 0.46                        # rejection box
TOP = 5.62

# phase bands
for cx, w, title in ((CA, 1.78, "Phase 1: Detection and context"),
                     (CB, 1.78, "Phase 2: Patch generation"),
                     (CC, 1.78, "Phase 3: Validation")):
    ax.add_patch(FancyBboxPatch((cx - w / 2, 0.08), w, H - 0.12, boxstyle="round,pad=0,rounding_size=0.06",
                                fc=FILL["band"], ec="#9ca3af", lw=0.7))
    ax.text(cx, H - 0.2, title, ha="center", va="center", fontsize=8, fontweight="bold")


def vline(x, y0, y1):
    ax.plot([x, x], [y0, y1], color=EDGE, lw=0.9)


# ---------------- Phase 1
ya = [TOP - 0.18 - i * 0.6 for i in range(8)]
A = [("Step 1: import repository\n(Git URL or ZIP upload)", "io"),
     ("Step 2: SAST scan with Bandit\nand Semgrep: list of findings", "core"),
     ("Step 3: select finding\n$f=(r,\\ell,s)$", "core"),
     ("Step 4: locate function $\\phi$\nthat contains line $\\ell$", "core"),
     ("Function\nfound?", "dec"),
     ("Step 5: source graph: callers,\nrelated tests and imports", "core"),
     ("Step 6: RAG: top-$k$ similar\nchunks (max 6,000 chars)", "core"),
     ("Step 7: build prompt (rule,\ncontext, task, $\\phi$ last)", "core")]
for (t, kind), y in zip(A, ya):
    if kind == "dec":
        diamond(ax, CA, y, DW, DH, t, fs=FS)
    else:
        box(ax, CA, y, BW, BH, t, kind, fs=FS)
for i in range(7):
    h0 = DH / 2 if A[i][1] == "dec" else BH / 2
    h1 = DH / 2 if A[i + 1][1] == "dec" else BH / 2
    arrow(ax, (CA, ya[i] - h0), (CA, ya[i + 1] + h1), label="yes" if A[i][1] == "dec" else None)
# function not found -> error
ERR_Y = 0.42
box(ax, CA, ERR_Y, 1.3, 0.38, "ERROR: function\nnot identified", "bad", fs=FS, bold=True, round_=0.12)
LX = 0.04
ax.plot([CA - DW / 2, LX], [ya[4], ya[4]], color=EDGE, lw=0.9)
ax.text(LX + 0.05, ya[4] - 0.1, "no", fontsize=7, style="italic", ha="left")
vline(LX, ERR_Y, ya[4])
arrow(ax, (LX, ERR_Y), (CA - 0.65, ERR_Y))

# Phase 1 -> Phase 2 (through the gutter, into the top of step 8)
G1 = 1.86
yb_s8 = TOP - 0.18
ax.plot([CA + BW / 2, G1], [ya[7], ya[7]], color=EDGE, lw=0.9)
vline(G1, ya[7], TOP + 0.12)
ax.plot([G1, CB], [TOP + 0.12, TOP + 0.12], color=EDGE, lw=0.9)
arrow(ax, (CB, TOP + 0.12), (CB, yb_s8 + 0.24))

# ---------------- Phase 2
SB_W = 1.4
box(ax, CB, yb_s8, SB_W, 0.48, "Step 8: generate $\\phi'$\nwith current model\n($T=0.2$, fixed seed)", "llm", fs=FS)
y9 = yb_s8 - 0.66
box(ax, CB, y9, SB_W, BH, "Step 9: extract one\nfunction, keep imports", fs=FS)
yd1 = y9 - 0.7
diamond(ax, CB, yd1, 1.62, 0.6, "Valid function\nand guardrails\npass?", fs=FS)
yd2 = yd1 - 0.8
diamond(ax, CB, yd2, 1.45, 0.52, "Another model\nin the chain?", fs=FS)
ynp = yd2 - 0.68
box(ax, CB, ynp, 1.3, 0.38, "NO_PATCH:\ngeneration failed", "bad", fs=FS, bold=True, round_=0.12)
arrow(ax, (CB, yb_s8 - 0.24), (CB, y9 + BH / 2))
arrow(ax, (CB, y9 - BH / 2), (CB, yd1 + 0.3))
arrow(ax, (CB, yd1 - 0.3), (CB, yd2 + 0.26), label="no")
arrow(ax, (CB, yd2 - 0.26), (CB, ynp + 0.19), label="no")
# yes: next model -> back to step 8
LB = 2.16
ax.plot([CB - 1.45 / 2, LB], [yd2, yd2], color=EDGE, lw=0.9)
vline(LB, yd2, yb_s8)
arrow(ax, (LB, yb_s8), (CB - SB_W / 2, yb_s8))
ax.text(LB - 0.12, (yd2 + yb_s8) / 2, "yes: try next model", fontsize=7, style="italic", va="center",
        ha="center", rotation=90)
# note box
box(ax, CB, 1.12, 1.66, 1.5,
    "Fallback chain:\nQwen2.5-Coder 7B\n$\\rightarrow$ Llama 3.1 8B\n$\\rightarrow$ Qwen2.5 1.5B $\\rightarrow$ Phi-3 Mini\n\n"
    "Guardrails: exactly one\nfunction, same name, no eval,\nexec, os.system, pickle.loads,\n"
    "marshal.loads, shell=True", "core", fs=6.6, ls="--")

# Phase 2 -> Phase 3
G2 = 4.06
ax.plot([CB + 1.62 / 2, G2], [yd1, yd1], color=EDGE, lw=0.9)
ax.text(CB + 1.62 / 2 + 0.03, yd1 + 0.09, "yes", fontsize=7, style="italic")

# ---------------- Phase 3
yc = [TOP - 0.18 - i * 0.64 for i in range(7)]
C = [("Step 10: replace $\\phi$ by $\\phi'$\nin a sandbox copy (AST)", "core"),
     ("All names\ndefined?", "dec"),
     ("Step 11: function-scoped Bandit\nre-scan and Semgrep diff", "core"),
     ("Rule $r$ removed\nfrom $\\phi'$?", "dec"),
     ("Step 12: run regression\ntests (pytest, 180 s)", "core"),
     ("Tests\npass?", "dec"),
     ("VERIFIED: return $\\phi'$,\ndiff and report", "ok")]
REJ = {1: "REJECTED:\nundefined\nname", 3: "REJECTED:\nvulnerability\nremains", 5: "REJECTED:\ntests failed"}
vline(G2, yd1, yc[0])
arrow(ax, (G2, yc[0]), (CC - BW / 2, yc[0]))
for i, ((t, kind), y) in enumerate(zip(C, yc)):
    if kind == "dec":
        diamond(ax, CC, y, DW, DH, t, fs=FS)
        arrow(ax, (CC + DW / 2, y), (CR - RW / 2, y))
        ax.text(CC + DW / 2 + 0.02, y + 0.09, "no", fontsize=7, style="italic")
        box(ax, CR, y, RW, RH + 0.06, REJ[i], "bad", fs=6.8, bold=True, round_=0.1)
    else:
        box(ax, CC, y, BW, BH, t, kind, fs=FS, bold=(kind == "ok"), round_=0.12 if kind == "ok" else 0.06)
for i in range(6):
    h0 = DH / 2 if C[i][1] == "dec" else BH / 2
    h1 = DH / 2 if C[i + 1][1] == "dec" else BH / 2
    arrow(ax, (CC, yc[i] - h0), (CC, yc[i + 1] + h1), label="yes" if C[i][1] == "dec" else None)
ax.text(CC, 0.55, "Every outcome (verified, rejected,\nno patch or error) is logged with\nits reason and exported as a\nPrometheus metric.",
        ha="center", va="center", fontsize=6.6, style="italic", linespacing=1.2)
save(fig, "workflow")
print("diagrams written")
