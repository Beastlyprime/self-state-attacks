#!/usr/bin/env python3
"""Render a coverage-aware Figure 5 preview from the partial head-to-head report.

This preview deliberately leaves deferred and not-yet-rescored methods blank. It
must not be cited as a final result.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
REPORT = HERE / "PARTIAL_HEADTOHEAD_REPORT.json"
OUT = ROOT / "paper" / "figures" / "fig_detector_headtohead_preview_v2"

TPR_COLOR = "#4A4E52"
FPR_COLOR = "#9B3E36"
CONNECTOR = "#BFC3C6"
ATTACK_COV = "#4A4E52"
CLEAN_COV = "#8A8F94"
COV_BG = "#E4E6E8"
TEXT = "#202020"
MUTED = "#666666"


def load_report() -> dict:
    return json.loads(REPORT.read_text())


def main() -> None:
    report = load_report()
    methods = report["methods"]
    counts = report["population_counts"]
    attack_total = (
        counts["attacks_aide_only_fileop"] + counts["attacks_graph_present"]
    )
    clean_total = counts["clean_heldout_40"]

    rows = [
        {"key": "AIDE", "label": "AIDE", "y": 7.5},
        {"key": "Falco", "label": "Falco", "y": 6.6},
        {"key": "STIDE", "label": "STIDE", "y": 5.7},
        {"key": "UNICORN", "label": "UNICORN", "y": 4.8},
        {"key": "ours_B1", "label": "Pooled size/timing", "y": 3.35},
        {"key": "ours_B2", "label": "Profile-conditioned", "y": 2.45},
        {
            "key": None,
            "label": "L1-LR (size/timing)",
            "y": 1.0,
            "status": "pending final rescore",
        },
        {
            "key": None,
            "label": "RuleFit (n-grams)",
            "y": 0.1,
            "status": "pending final rescore",
        },
    ]

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": [
                "Times New Roman",
                "Times",
                "Nimbus Roman",
                "DejaVu Serif",
            ],
            "font.size": 8,
            "axes.titlesize": 8.5,
            "axes.labelsize": 8,
            "xtick.labelsize": 7.2,
            "ytick.labelsize": 7.6,
            "legend.fontsize": 7,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )

    fig = plt.figure(figsize=(7.0, 3.35))
    grid = fig.add_gridspec(
        1,
        2,
        width_ratios=[4.65, 1.95],
        left=0.205,
        right=0.985,
        top=0.78,
        bottom=0.16,
        wspace=0.12,
    )
    ax = fig.add_subplot(grid[0, 0])
    ax_cov = fig.add_subplot(grid[0, 1], sharey=ax)

    for axis in (ax, ax_cov):
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.spines["left"].set_visible(False)
        axis.tick_params(axis="y", length=0)

    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(-0.45, 8.35)
    ax.set_xticks([0.0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0", ".25", ".50", ".75", "1"])
    ax.grid(axis="x", color="#DDE2E6", linewidth=0.55, zorder=0)
    ax.set_xlabel("Rate at the frozen operating point")

    yticks = [row["y"] for row in rows]
    ax.set_yticks(yticks)
    ax.set_yticklabels([row["label"] for row in rows], color=TEXT)
    ax.tick_params(axis="x", color="#808890")
    ax.spines["bottom"].set_color("#808890")

    headings = [
        (8.13, "Existing OS baselines"),
        (3.98, "Size-and-timing baselines"),
        (1.63, "Supervised references"),
    ]
    for y, heading in headings:
        ax.text(
            -0.43,
            y,
            heading,
            transform=ax.transData,
            fontsize=6.6,
            fontweight="bold",
            color=MUTED,
            ha="left",
            va="center",
            clip_on=False,
        )
    for y in (4.3, 1.85):
        ax.axhline(y, color="#DDE2E6", linewidth=0.65, zorder=0)
        ax_cov.axhline(y, color="#DDE2E6", linewidth=0.65, zorder=0)

    for row in rows:
        y = row["y"]
        key = row["key"]
        entry = methods.get(key) if key else None
        pooled = entry.get("pooled") if entry else None

        if pooled:
            tpr = pooled["TPR"]
            fpr = pooled["FPR"]
            ax.plot(
                [fpr["rate"], tpr["rate"]],
                [y, y],
                color=CONNECTOR,
                linewidth=1.8,
                solid_capstyle="round",
                zorder=1,
            )
            ax.errorbar(
                tpr["rate"],
                y,
                xerr=[
                    [tpr["rate"] - tpr["lo"]],
                    [tpr["hi"] - tpr["rate"]],
                ],
                fmt="o",
                markersize=5.3,
                markerfacecolor=TPR_COLOR,
                markeredgecolor="white",
                markeredgewidth=0.55,
                ecolor=TPR_COLOR,
                elinewidth=1.0,
                capsize=2.0,
                zorder=4,
            )
            ax.errorbar(
                fpr["rate"],
                y,
                xerr=[
                    [fpr["rate"] - fpr["lo"]],
                    [fpr["hi"] - fpr["rate"]],
                ],
                fmt="s",
                markersize=4.8,
                markerfacecolor="white",
                markeredgecolor=FPR_COLOR,
                markeredgewidth=1.25,
                ecolor=FPR_COLOR,
                elinewidth=1.0,
                capsize=2.0,
                zorder=3,
            )

            attack_eval = tpr["n"]
            attack_den = tpr["n"] + tpr.get("non_evaluable", 0)
            clean_eval = fpr["n"]
            clean_den = fpr["n"] + fpr.get("non_evaluable", 0)
            attack_den = attack_den or attack_total
            clean_den = clean_den or clean_total
            coverage = [
                (
                    attack_eval / attack_den,
                    ATTACK_COV,
                    "-",
                    "o",
                    y + 0.12,
                    attack_eval,
                    attack_den,
                ),
                (
                    clean_eval / clean_den,
                    CLEAN_COV,
                    (0, (2.0, 1.4)),
                    "s",
                    y - 0.12,
                    clean_eval,
                    clean_den,
                ),
            ]
            for frac, color, linestyle, marker, yy, num, den in coverage:
                ax_cov.plot(
                    [0.0, 1.0],
                    [yy, yy],
                    color=COV_BG,
                    linewidth=2.5,
                    solid_capstyle="butt",
                    zorder=0,
                )
                ax_cov.plot(
                    [0.0, frac],
                    [yy, yy],
                    color=color,
                    linewidth=1.9 if color == ATTACK_COV else 1.35,
                    linestyle=linestyle,
                    solid_capstyle="butt",
                    zorder=2,
                )
                ax_cov.plot(
                    frac,
                    yy,
                    marker=marker,
                    markersize=2.8,
                    markerfacecolor=color if color == ATTACK_COV else "white",
                    markeredgecolor=color,
                    markeredgewidth=0.7,
                    zorder=3,
                )
                ax_cov.text(
                    1.48,
                    yy,
                    f"{num}/{den}",
                    ha="right",
                    va="center",
                    fontsize=6.5,
                    color=TEXT,
                    clip_on=False,
                )
        else:
            status = row.get("status")
            if not status and entry:
                status = entry.get("status", "not evaluable")
            status_map = {
                "DEFERRED_D2": "deferred",
                "non_evaluable_no_rescore": "not evaluable",
            }
            status = status_map.get(status, status or "pending")
            ax.text(
                0.5,
                y,
                status,
                ha="center",
                va="center",
                color=MUTED,
                fontsize=7,
                fontstyle="italic",
            )
            ax_cov.text(
                0.5,
                y,
                "pending" if "pending" in status else "n/a",
                ha="center",
                va="center",
                color=MUTED,
                fontsize=6.8,
                fontstyle="italic",
            )

    fig.legend(
        handles=[
            Line2D(
                [0],
                [0],
                marker="o",
                linestyle="none",
                markerfacecolor=TPR_COLOR,
                markeredgecolor="white",
                markersize=5.5,
                label="Attack-landed TPR",
            ),
            Line2D(
                [0],
                [0],
                marker="s",
                linestyle="none",
                markerfacecolor="white",
                markeredgecolor=FPR_COLOR,
                markeredgewidth=1.2,
                markersize=5,
                label="Natural-clean FPR",
            ),
        ],
        loc="upper left",
        bbox_to_anchor=(0.205, 0.855),
        frameon=False,
        ncol=2,
        handletextpad=0.4,
        columnspacing=1.2,
        borderaxespad=0,
    )

    # Reserve the interval beyond 1.0 for a fixed, right-aligned count column.
    # Keeping labels out of the share scale avoids collisions for fully
    # evaluable populations, whose rails end exactly at 1.0.
    ax_cov.set_xlim(0, 1.52)
    ax_cov.set_xticks([0.0, 0.5, 1.0])
    ax_cov.set_xticklabels(["0", ".5", "1"])
    ax_cov.set_xlabel("Evaluable share")
    ax_cov.xaxis.set_label_coords(0.33, -0.12)
    ax_cov.text(
        1.48,
        8.13,
        "n",
        ha="right",
        va="center",
        fontsize=6.6,
        fontweight="bold",
        color=MUTED,
    )
    ax_cov.tick_params(axis="x", color="#808890")
    ax_cov.spines["bottom"].set_color("#808890")
    ax_cov.tick_params(axis="y", labelleft=False)
    fig.legend(
        handles=[
            Line2D([0], [0], color=ATTACK_COV, linewidth=1.9, label="Attack"),
            Line2D(
                [0],
                [0],
                color=CLEAN_COV,
                linewidth=1.35,
                linestyle=(0, (2.0, 1.4)),
                label="Clean",
            ),
        ],
        loc="upper left",
        bbox_to_anchor=(0.765, 0.855),
        frameon=False,
        ncol=2,
        handlelength=1.25,
        handletextpad=0.35,
        columnspacing=0.8,
        borderaxespad=0,
    )

    fig.text(
        0.205,
        0.895,
        "(a) Detector outcomes",
        ha="left",
        va="center",
        fontsize=8.5,
        fontweight="bold",
        color=TEXT,
    )
    fig.text(
        0.765,
        0.895,
        "(b) Evaluable evidence",
        ha="left",
        va="center",
        fontsize=8.5,
        fontweight="bold",
        color=TEXT,
    )
    fig.text(
        0.985,
        0.965,
        "Partial preview · not for paper",
        ha="right",
        va="top",
        fontsize=6.5,
        fontweight="normal",
        color=FPR_COLOR,
    )
    fig.add_artist(
        Line2D(
            [0.747, 0.747],
            [0.13, 0.91],
            transform=fig.transFigure,
            color="#D2D4D6",
            linewidth=0.55,
        )
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.035)
    fig.savefig(
        OUT.with_suffix(".png"),
        dpi=300,
        bbox_inches="tight",
        pad_inches=0.035,
    )
    plt.close(fig)


if __name__ == "__main__":
    main()
