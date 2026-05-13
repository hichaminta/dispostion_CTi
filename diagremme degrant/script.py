"""
Gantt CTI Pipeline - BlueSec SOC
Design optimisé avec VOTRE contenu.
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

# ── CONFIG ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(SCRIPT_DIR, "gantt_cti_bluesec.png")
DPI = 200

MONTHS = [
    ("FÉV",  4,  0),
    ("MARS",  5,  4),
    ("AVRIL", 5,  9),
    ("MAI",   4, 14),
    ("JUIN",  4, 18),
    ("JUIL",  5, 22),
]
TOTAL_WEEKS = 27
RED_LINE    = 19   # Fin Mai (S20)
EXCEPT_W    = {6, 13}

PHASES = [
    {
        "title": "Phase 1", "sub": "Conception & mise en place",
        "color": "#2B3F6B",
        "tasks": [
            {"name": "Analyse besoins SOC & CTI",         "s": 1,  "e": 4},
            {"name": "Conception architecture pipeline",  "s": 2,  "e": 6},
            {"name": "Installation & config MISP",        "s": 6,  "e": 8},
            {"name": "Mise en place API & flux CTI",      "s": 7,  "e": 10},
        ]
    },
    {
        "title": "Phase 2", "sub": "Développement & collecte",
        "color": "#993C1D",
        "tasks": [
            {"name": "Collecte multi-sources (API, CVE, IOC)", "s": 8,  "e": 12},
            {"name": "Extraction des IOC",                     "s": 11, "e": 14},
        ]
    },
    {
        "title": "Phase 3", "sub": "Enrichissement & MISP",
        "color": "#7F77DD",
        "tasks": [
            {"name": "Enrichissement (VT, URLScan, géoloc)", "s": 11, "e": 16},
            {"name": "Surveillance et détection automatisée des fuites de données via Telegram et analyse IA.", "s": 14, "e": 17},
            {"name": "Envoi IOC enrichis vers MISP",         "s": 17, "e": 20},
        ]
    },
    {
        "title": "Phase 4", "sub": "Exploitation SOC",
        "color": "#0F6E56",
        "tasks": [
            {"name": "Rapport PFE",                          "s": 15, "e": 21},
            {"name": "Génération bulletin SOC auto",         "s": 22, "e": 26},
        ]
    },
]

# ── CALCUL HAUTEUR ───────────────────────────────────────────────────────────
n_tasks = sum(len(p["tasks"]) for p in PHASES)
HEADER_H   = 1.5
TASK_H     = 0.6
FOLLOW_H   = 1.0
LEGEND_H   = 1.5
GAP_H      = 0.1
LABEL_W    = 4.5

total_h = HEADER_H + n_tasks * TASK_H + (len(PHASES) * GAP_H) + FOLLOW_H + LEGEND_H
fig_w   = 20
fig_h   = total_h

fig, ax = plt.subplots(figsize=(fig_w, fig_h))
ax.set_xlim(-LABEL_W, TOTAL_WEEKS + 5) # Ajout de marge à droite pour le texte long
ax.set_ylim(0, total_h)
ax.axis('off')
fig.patch.set_facecolor('white')

# ── HELPERS ──────────────────────────────────────────────────────────────────
def bar(ax, s, e, y, color, height=0.35):
    ax.add_patch(FancyBboxPatch(
        (float(s), y - height/2), float(e-s), height,
        boxstyle="round,pad=0.02", linewidth=0,
        facecolor=color, zorder=3
    ))

# ── HEADER ───────────────────────────────────────────────────────────────────
y_top = total_h - 0.5
y_month = y_top + 0.4
y_week  = y_top

ax.text(-LABEL_W + 0.1, y_week + 0.3, "Phase / Tâche", ha='left', va='bottom', fontsize=10, color='#666666')

for label, nw, start in MONTHS:
    cx = start + nw / 2
    ax.text(cx, y_month, label, ha='center', va='center', fontsize=9, color='#666666')
    ax.axvline(start, color='#dddddd', linewidth=0.8, ymin=0.15, ymax=0.9, zorder=1)

ax.axhline(y_week + 0.2, color='#dddddd', linewidth=1, xmin=0, xmax=1)

wn = 1
for _, nw, start in MONTHS:
    for i in range(nw):
        cx = start + i + 0.5
        ax.text(cx, y_week, f"S{wn}", ha='center', va='center', fontsize=7, color='#999999')
        wn += 1

# ── TÂCHES ───────────────────────────────────────────────────────────────────
y_cursor = y_week - 0.4

for pi, phase in enumerate(PHASES):
    for ti, task in enumerate(phase["tasks"]):
        yc = y_cursor - TASK_H / 2
        ax.axhline(y_cursor, color='#eeeeee', linewidth=0.8, xmin=0, xmax=1, zorder=0)

        if ti == 0:
            ax.text(-LABEL_W + 0.1, yc + 0.15, phase["title"], ha='left', va='center', fontsize=10, fontweight='bold')
            ax.text(-LABEL_W + 0.1, yc - 0.10, phase["sub"], ha='left', va='center', fontsize=8, color='#7f8c8d')

        bar(ax, task["s"], task["e"], yc, phase["color"])
        # Texte un peu plus petit (fontsize=7) pour accommoder les phrases longues
        ax.text(task["e"] + 0.2, yc, task["name"], ha='left', va='center', fontsize=7.5, color='#333333')
        
        y_cursor -= TASK_H

# ── LIGNE ROUGE ─────────────────────────────────────────────────────────────
ax.axvline(RED_LINE + 0.5, color='#e74c3c', linewidth=1.5, zorder=5)

# ── SUIVI ENTREPRISE ─────────────────────────────────────────────────────────
y_cursor -= 0.5
ax.axhline(y_cursor + 0.4, color='#dddddd', linewidth=1, xmin=0, xmax=1)
y_follow = y_cursor - 0.2
ax.text(-LABEL_W + 0.1, y_follow + 0.1, "Suivi entreprise", ha='left', va='center', fontsize=10, fontweight='bold')
ax.text(-LABEL_W + 0.1, y_follow - 0.15, "Chaque vendredi", ha='left', va='center', fontsize=8, color='#7f8c8d')

for wi in range(TOTAL_WEEKS):
    cx = wi + 0.5
    if wi in EXCEPT_W:
        ax.text(cx, y_follow, "✕", ha='center', va='center', fontsize=10, color='#e74c3c', fontweight='bold')
    elif wi <= RED_LINE:
        ax.text(cx, y_follow, "★", ha='center', va='center', fontsize=10, color='#e74c3c')
    else:
        ax.text(cx, y_follow, "☆", ha='center', va='center', fontsize=10, color='#dddddd')

# ── LÉGENDE ──────────────────────────────────────────────────────────────────
y_leg = y_cursor - 1.2
leg_x = -LABEL_W + 0.1

ax.text(leg_x, y_leg, "★", color='#e74c3c', fontsize=12)
ax.text(leg_x + 0.4, y_leg, "Suivi effectué (fév → mi-mai)", fontsize=9, color='#666666')
ax.text(leg_x + 5.5, y_leg, "☆", color='#dddddd', fontsize=12)
ax.text(leg_x + 5.9, y_leg, "Suivi prévu", fontsize=9, color='#666666')
ax.text(leg_x + 8.5, y_leg, "✕", color='#e74c3c', fontsize=10, fontweight='bold')
ax.text(leg_x + 8.9, y_leg, "Pas de suivi", fontsize=9, color='#666666')
ax.text(leg_x + 13.5, y_leg, "─", color='#e74c3c', fontsize=12, fontweight='bold')
ax.text(leg_x + 14.1, y_leg, "Mi-mai", fontsize=9, color='#666666')

y_leg -= 0.5
for i, ph in enumerate(PHASES):
    px = leg_x + (i * 4.8)
    ax.add_patch(plt.Rectangle((px, y_leg - 0.1), 0.5, 0.3, color=ph["color"]))
    ax.text(px + 0.7, y_leg, f"{ph['title']}", fontsize=8, color='#666666', fontweight='bold')

# ── EXPORT ───────────────────────────────────────────────────────────────────
plt.savefig(OUTPUT, dpi=DPI, bbox_inches='tight')
plt.close()
print(f"✅ Design et contenu utilisateur restaurés : {OUTPUT}")
