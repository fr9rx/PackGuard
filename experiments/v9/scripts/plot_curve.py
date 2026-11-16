import argparse
import json
import math

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

PALETTE = ["#0072B2", "#E69F00", "#009E73", "#CC79A7", "#56B4E9", "#D55E00"]


def tick_label(a):
    """Returns the x tick label: percent, mean malware reference names and mean benign references on three lines."""
    return "%.0f%%\n%s names\n%s benign" % (
        a["x_percent"],
        format(int(round(a["malware_names"] or 0)), ","),
        format(int(round(a["benign_refs"] or 0)), ","),
    )


def annotate(ax, xs, ys, digits, color, offset, ha, boxed):
    """Writes the value of each point at the given offset in points, on a white box when boxed is set."""
    for x, y in zip(xs, ys):
        if y is not None:
            ax.annotate("%.*f" % (digits, y), (x, y), textcoords="offset points", xytext=offset,
                        ha=ha, va="center", fontsize=8, color=color, fontweight="bold", zorder=6,
                        bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.85) if boxed else None)


def benign_total(rows):
    """Returns the benign sample count shared by every row, or None when it is missing or differs between rows."""
    totals = {(r.get("benign") or {}).get("expected") for r in rows}
    if len(totals) == 1:
        total = totals.pop()
        if isinstance(total, (int, float)) and total > 0:
            return int(total)
    return None


def main():
    """Plots recall and false-alarm rate against reference size from results.json."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--png", required=True)
    args = ap.parse_args()
    data = json.load(open(args.results))
    agg = data["aggregate"]
    rows = data["rows"]
    if not agg:
        raise SystemExit("no complete results to plot")
    xs = [a["x_percent"] for a in agg]
    cats = sorted(agg[0]["categories"])
    multi = len({r["seed"] for r in rows}) > 1

    fig, (top, bot) = plt.subplots(2, 1, sharex=True, figsize=(12, 8.5), gridspec_kw={"height_ratios": [3, 2]})

    recall_values = []
    for i, c in enumerate(cats):
        color = PALETTE[i % len(PALETTE)]
        ys = [a["categories"][c]["mean"] for a in agg]
        recall_values += ys
        top.plot(xs, ys, marker="o", ms=3.5, lw=1.2, color=color, alpha=0.85, label=c)
    mean = [a["recall"]["mean"] for a in agg]
    recall_values += mean
    if multi:
        band_lo = [a["recall"]["min"] for a in agg]
        band_hi = [a["recall"]["max"] for a in agg]
        recall_values += band_lo + band_hi
        top.fill_between(xs, band_lo, band_hi, color="black", alpha=0.12, linewidth=0)
        for seed in sorted({r["seed"] for r in rows}):
            pts = sorted((r["x_percent"], r["recall"]) for r in rows if r["seed"] == seed)
            recall_values += [p[1] for p in pts]
            top.scatter([p[0] for p in pts], [p[1] for p in pts], s=14, color="black", alpha=0.45, zorder=3)
    top.plot(xs, mean, marker="o", ms=7, lw=3, color="black", label="overall", zorder=4)
    annotate(top, xs, mean, 1, "black", (0, -14), "center", True)
    recall_values = [v for v in recall_values if v is not None]
    low = 5 * math.floor((min(recall_values) - 3) / 5) if recall_values else 0
    top.set_ylabel("Recall (%)")
    top.set_ylim(max(low, 0), 101)
    top.grid(alpha=0.3)
    top.legend(loc="lower right", fontsize=8, ncol=3, frameon=True)
    for ax in (top, bot):
        ax.axvline(100, color="gray", ls="--", lw=1.2, zorder=1)
    top.text(100, 1.01, "previous reference set", transform=top.get_xaxis_transform(), ha="center", va="bottom",
             fontsize=8, color="gray")
    top.set_title("PackGuard stage 1 learning curve (known mode)", pad=18)

    far = [a["far"]["mean"] for a in agg]
    if multi:
        bot.fill_between(xs, [a["far"]["min"] for a in agg], [a["far"]["max"] for a in agg],
                         color="#D55E00", alpha=0.15, linewidth=0)
    far_top = [v for v in far if v is not None]
    for seed in sorted({r["seed"] for r in rows}):
        pts = sorted((r for r in rows if r["seed"] == seed), key=lambda r: r["x_percent"])
        ys = [r["far"] for r in pts]
        lo = [r["far"] - r["far_ci"][0] for r in pts]
        hi = [r["far_ci"][1] - r["far"] for r in pts]
        far_top += [r["far_ci"][1] for r in pts]
        bot.errorbar([r["x_percent"] for r in pts], ys, yerr=[lo, hi], fmt="o" if multi else "o-", ms=4 if multi else 7,
                     lw=1 if multi else 2.5, capsize=3, color="#D55E00", alpha=0.5 if multi else 1.0)
    if multi:
        bot.plot(xs, far, lw=3, color="#D55E00", zorder=4)
    span = max(xs) - min(xs)
    crowded = [i + 1 < len(xs) and xs[i + 1] - xs[i] < 0.07 * span for i in range(len(xs))]
    annotate(bot, [x for x, c in zip(xs, crowded) if not c], [y for y, c in zip(far, crowded) if not c],
             1, "#D55E00", (8, 6), "left", False)
    annotate(bot, [x for x, c in zip(xs, crowded) if c], [y for y, c in zip(far, crowded) if c],
             1, "#D55E00", (-8, 8), "right", False)
    total = benign_total(rows)
    bot.set_ylabel("False alarms (%% of %s benign)" % format(total, ",") if total else "False-alarm rate (%)")
    bot.set_xlabel("Share of references used (malware reference names / benign references)")
    bot.set_ylim(0, (max(far_top) if far_top else 0) + 2)
    bot.grid(alpha=0.3)
    bot.set_xticks(xs)
    labels = [tick_label(a) for a in agg]
    for i in range(1, len(labels)):
        if crowded[i - 1] and not labels[i - 1].startswith("\n"):
            labels[i] = "\n\n\n" + labels[i]
    bot.set_xticklabels(labels, fontsize=7.5 if len(agg) > 7 else 8)
    bot.set_xlim(min(xs) - 0.04 * span, max(xs) + 0.06 * span)

    fig.tight_layout()
    fig.savefig(args.png, dpi=150)


if __name__ == "__main__":
    main()
