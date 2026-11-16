import argparse
import json
import math
import os
import re


def wilson(k, n, z=1.96):
    """Returns the Wilson score interval (low, high) in percent for k successes out of n."""
    if n == 0:
        return (None, None)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (100 * max(0.0, centre - half), 100 * min(1.0, centre + half))


def rate(k, n):
    """Returns k/n in percent, or None when n is zero."""
    return None if n == 0 else 100.0 * k / n


def count_reports(report_dir, expected_dirs):
    """Returns the number of expected packages with a report and how many of those are flagged."""
    reports = 0
    flagged = 0
    for name in expected_dirs:
        path = os.path.join(report_dir, name + ".json")
        if not os.path.isfile(path):
            continue
        try:
            data = json.load(open(path))
        except (OSError, ValueError):
            continue
        reports += 1
        if isinstance(data, dict) and data.get("flagged"):
            flagged += 1
    return reports, flagged


def read_done(path):
    """Returns (seconds, exit status) from a .done file, or None when it is absent or malformed."""
    try:
        parts = open(path).read().split()
        return (float(parts[0]), int(parts[1]))
    except (OSError, ValueError, IndexError):
        return None


def expected_sets(test_manifest):
    """Returns a dict mapping each test category folder to the list of expected package folders."""
    cats = {}
    for item in test_manifest["malware"]:
        cats.setdefault("%s_%s" % (item["set"], item["category"]), []).append(item["dir"])
    for key, dirs in cats.items():
        cats[key] = sorted(dirs)
    return cats, sorted(test_manifest["benign"])


def evaluate(seed_dir, pct_dir, seed, pct, test_manifest, seed_manifest):
    """Returns the result row of one seed and fraction, or the list of categories lacking a .done file."""
    mal_cats, benign_dirs = expected_sets(test_manifest)
    all_cats = dict(mal_cats)
    all_cats["benign"] = benign_dirs
    reports_root = os.path.join(pct_dir, "reports")
    dones = {c: read_done(os.path.join(reports_root, c + ".done")) for c in all_cats}
    lacking = sorted(c for c, d in dones.items() if d is None or d[1] != 0)
    if lacking:
        return None, lacking
    cats = {}
    for cat, dirs in all_cats.items():
        reports, flagged = count_reports(os.path.join(reports_root, cat), dirs)
        entry = {
            "expected": len(dirs),
            "reports": reports,
            "flagged": flagged,
            "missing": len(dirs) - reports,
            "rate": rate(flagged, len(dirs)),
        }
        entry["ci"] = wilson(flagged, len(dirs))
        cats[cat] = entry
    exp = sum(cats[c]["expected"] for c in mal_cats)
    hit = sum(cats[c]["flagged"] for c in mal_cats)
    info = seed_manifest["fractions"].get(str(pct), {})
    benign = cats.pop("benign")
    return {
        "seed": seed,
        "percent": pct,
        "x_percent": info.get("achieved_percent_malware") or pct,
        "malware_folders": info.get("malware_folders"),
        "malware_names": info.get("malware_names"),
        "benign_refs": info.get("benign"),
        "categories": cats,
        "recall": rate(hit, exp),
        "recall_ci": wilson(hit, exp),
        "malware_expected": exp,
        "malware_flagged": hit,
        "malware_missing": sum(cats[c]["missing"] for c in mal_cats),
        "benign": benign,
        "far": benign["rate"],
        "far_ci": benign["ci"],
        "seconds": sum(d[0] for d in dones.values()),
        "failed_exit_1": sum(1 for d in dones.values() if d[1] == 1),
    }, []


def stats(values):
    """Returns mean, min and max of the non-None values, or Nones when there are none."""
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "min": None, "max": None}
    return {"mean": sum(vals) / len(vals), "min": min(vals), "max": max(vals)}


def aggregate(rows):
    """Returns per-fraction aggregates over the seeds present in rows."""
    out = []
    for pct in sorted({r["percent"] for r in rows}):
        sel = sorted((r for r in rows if r["percent"] == pct), key=lambda r: r["seed"])
        cats = sorted(sel[0]["categories"])
        out.append(
            {
                "percent": pct,
                "x_percent": sel[0]["x_percent"],
                "seeds": [r["seed"] for r in sel],
                "n_seeds": len(sel),
                "malware_folders": stats([r["malware_folders"] for r in sel])["mean"],
                "malware_names": stats([r["malware_names"] for r in sel])["mean"],
                "benign_refs": stats([r["benign_refs"] for r in sel])["mean"],
                "recall": stats([r["recall"] for r in sel]),
                "categories": {c: stats([r["categories"][c]["rate"] for r in sel]) for c in cats},
                "far": stats([r["far"] for r in sel]),
                "first_seed_far_flagged": sel[0]["benign"]["flagged"],
                "first_seed_far_total": sel[0]["benign"]["expected"],
                "scan_minutes": stats([r["seconds"] / 60.0 for r in sel])["mean"],
            }
        )
    return out


def fmt(v, digits=1):
    """Formats a number with fixed digits, or a dash for None."""
    return "-" if v is None else "%.*f" % (digits, v)


def span(s, digits=1):
    """Formats a stats dict as mean [min-max]."""
    return "%s [%s–%s]" % (fmt(s["mean"], digits), fmt(s["min"], digits), fmt(s["max"], digits))


def render_md(rows, agg, incomplete):
    """Returns the markdown report text."""
    lines = []
    if agg:
        cats = sorted(agg[0]["categories"])
        head = ["Refs %", "Seeds", "Malware refs", "Benign refs", "Recall % mean [min–max]"]
        head += ["%s %%" % c for c in cats]
        head += ["False alarms % mean [min–max]", "FA flagged/total (first seed)", "Scan min"]
        lines.append("## Learning curve by reference size")
        lines.append("")
        lines.append("| " + " | ".join(head) + " |")
        lines.append("|" + "|".join(["---"] * len(head)) + "|")
        for a in agg:
            cells = [
                "%d" % a["percent"] if abs(a["x_percent"] - a["percent"]) < 0.05 else "%d (achieved %.1f)" % (a["percent"], a["x_percent"]),
                "%d" % a["n_seeds"],
                "%s folders / %s names" % (fmt(a["malware_folders"], 0), fmt(a["malware_names"], 0)),
                fmt(a["benign_refs"], 0),
                span(a["recall"]),
            ]
            cells += [fmt(a["categories"][c]["mean"]) for c in cats]
            cells += [
                span(a["far"], 2),
                "%d/%d" % (a["first_seed_far_flagged"], a["first_seed_far_total"]),
                fmt(a["scan_minutes"]),
            ]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
        lines.append("## Per-seed rows")
        lines.append("")
        head = ["Seed", "Refs %", "Malware recall % (95% CI)", "Flagged/expected", "Missing reports"]
        head += ["False alarms % (95% CI)", "FA flagged/total", "Scan s"]
        lines.append("| " + " | ".join(head) + " |")
        lines.append("|" + "|".join(["---"] * len(head)) + "|")
        for r in sorted(rows, key=lambda r: (r["seed"], r["percent"])):
            lines.append(
                "| %s | %d | %s (%s–%s) | %d/%d | %d | %s (%s–%s) | %d/%d | %s |"
                % (
                    r["seed"], r["percent"], fmt(r["recall"]),
                    fmt(r["recall_ci"][0]), fmt(r["recall_ci"][1]),
                    r["malware_flagged"], r["malware_expected"],
                    r["malware_missing"] + r["benign"]["missing"],
                    fmt(r["far"], 2), fmt(r["far_ci"][0], 2), fmt(r["far_ci"][1], 2),
                    r["benign"]["flagged"], r["benign"]["expected"], fmt(r["seconds"], 0),
                )
            )
    else:
        lines.append("No complete (seed, fraction) pairs yet.")
    if incomplete:
        lines.append("")
        lines.append("Incomplete pairs (excluded):")
        for item in incomplete:
            lines.append("- seed %s p%03d: no successful .done for %s" % (item["seed"], item["percent"], ", ".join(item["lacking"])))
    return "\n".join(lines) + "\n"


def main():
    """Summarises the learning-curve reports into results.json and results.md."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="~/pg-curve")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--md-out", default=None)
    args = ap.parse_args()
    out = os.path.expanduser(args.out)
    json_out = args.json_out or os.path.join(out, "results.json")
    md_out = args.md_out or os.path.join(out, "results.md")
    test_manifest = json.load(open(os.path.join(out, "test", "manifest.json")))

    rows = []
    incomplete = []
    for seed_name in sorted(os.listdir(out)):
        seed_dir = os.path.join(out, seed_name)
        if not re.fullmatch(r"seed(\d+)", seed_name) or not os.path.isdir(seed_dir):
            continue
        manifest_path = os.path.join(seed_dir, "manifest.json")
        if not os.path.isfile(manifest_path):
            continue
        seed_manifest = json.load(open(manifest_path))
        seed = seed_manifest["seed"]
        for pct_name in sorted(os.listdir(seed_dir)):
            pct_dir = os.path.join(seed_dir, pct_name)
            match = re.fullmatch(r"p(\d+)", pct_name)
            if not match or not os.path.isdir(os.path.join(pct_dir, "reports")):
                continue
            pct = int(match.group(1))
            row, lacking = evaluate(seed_dir, pct_dir, seed, pct, test_manifest, seed_manifest)
            if row is None:
                incomplete.append({"seed": seed, "percent": pct, "lacking": lacking})
            else:
                rows.append(row)

    agg = aggregate(rows)
    with open(json_out, "w") as f:
        json.dump(
            {
                "test": {
                    "test_seed": test_manifest["test_seed"],
                    "categories": test_manifest["categories"],
                    "benign": len(test_manifest["benign"]),
                    "dropped_for_leak": test_manifest["dropped_for_leak"],
                    "missing_dirs": test_manifest["missing_dirs"],
                },
                "rows": rows,
                "aggregate": agg,
                "incomplete": incomplete,
            },
            f,
            indent=1,
        )
    md = render_md(rows, agg, incomplete)
    with open(md_out, "w") as f:
        f.write(md)
    print(md)


if __name__ == "__main__":
    main()
