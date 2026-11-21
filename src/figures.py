"""Figures for the paper, from results/per_page.csv and results/summary.json.

Usage: python figures.py <results_dir>
"""
import csv
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"font.family": "Times New Roman", "font.size": 10, "figure.dpi": 300})


def main():
    res = Path(sys.argv[1])
    rows = list(csv.DictReader(open(res / "per_page.csv", encoding="utf-8")))
    S = json.loads((res / "summary.json").read_text(encoding="utf-8"))

    # Figure 1: capacity (maximum message length) per page, cumulative share
    # Redrawn after review comment 28: plain logarithmic axis with labelled ticks,
    # y axis in percent, one point per message length.
    from matplotlib.ticker import FixedLocator, NullFormatter, PercentFormatter
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    lengths = list(range(1, 3001))
    for col, label, ls in (("msg_auto", "All attribute pairs (auto key)", "-"),
                           ("msg_key20", "Top-20 key file", "--")):
        vals = [max(int(r[col]), 0) for r in rows]
        n = len(vals)
        share = [100 * sum(v >= L for v in vals) / n for L in lengths]
        ax.plot(lengths, share, ls=ls, color="black", label=label)
    ax.set_xscale("log")
    ax.set_xlim(1, 3000)
    ax.set_ylim(0, 70)
    ticks = [1, 10, 31, 100, 500, 1000, 3000]
    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.set_xticklabels([str(t) for t in ticks])
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.yaxis.set_major_formatter(PercentFormatter(decimals=0))
    ax.set_xlabel("Message length (bytes of text, after encryption overhead)")
    ax.set_ylabel("Pages that can hold it")
    ax.grid(alpha=0.3, which="major")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(res / "fig1_capacity.png")

    # Figure 2: detectability (AUC) by payload rate
    rates = [0.1, 0.25, 0.5, 1.0]
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    for stat, label, mk in (("cons", "Order-consistency detector", "o"), ("norm", "Web-norm detector", "s")):
        ax.plot([100 * r for r in rates], [S["detectability"][f"{stat}_rate{r}"]["auc"] for r in rates],
                marker=mk, color="black", label=label)
    ax.axhline(0.5, color="grey", ls=":", lw=1)
    ax.text(101, 0.51, "chance", color="grey", fontsize=8, ha="right")
    ax.set_xlabel("Payload (% of page capacity used)")
    ax.set_ylabel("Detection AUC")
    ax.set_ylim(0.25, 1.02)
    ax.grid(alpha=0.3)
    ax.legend(frameon=False, loc="lower right")
    fig.tight_layout()
    fig.savefig(res / "fig2_detectability.png")
    print("figures written")


if __name__ == "__main__":
    main()
