import argparse
import json
import math
import os


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


def read_done(path):
    """Returns (seconds, exit status) from a .done file, or None when it is absent or malformed."""
    try:
        parts = open(path).read().split()
        return (float(parts[0]), int(parts[1]))
    except (OSError, ValueError, IndexError):
        return None


def read_refs(path):
    """Returns (malware reference folders, benign reference folders) from refs.txt, or (None, None)."""
    try:
        parts = open(path).read().split()
        return int(parts[0]), int(parts[1])
    except (OSError, ValueError, IndexError):
        return None, None


def count_reports(report_dir, expected):
    """Returns the number of expected packages with a readable report and how many of those are flagged."""
    reports = 0
    flagged = 0
    for name in expected:
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


def evaluate(label_dir, label, test_manifest):
    """Returns the result row of one label, or the list of tiers lacking a successful .done file."""
    sets = dict(test_manifest["tiers"])
    sets["benign"] = test_manifest["benign"]
    reports_root = os.path.join(label_dir, "reports")
    dones = {t: read_done(os.path.join(reports_root, t + ".done")) for t in sets}
    lacking = sorted(t for t, d in dones.items() if d is None or d[1] != 0)
    if lacking:
        return None, lacking
    tiers = {}
    for tier, names in sets.items():
        reports, flagged = count_reports(os.path.join(reports_root, tier), names)
        tiers[tier] = {
            "expected": len(names),
            "reports": reports,
            "flagged": flagged,
            "missing": len(names) - reports,
            "rate": rate(flagged, len(names)),
            "ci": wilson(flagged, len(names)),
        }
    benign = tiers.pop("benign")
    exp = sum(t["expected"] for t in tiers.values())
    hit = sum(t["flagged"] for t in tiers.values())
    mal_refs, ben_refs = read_refs(os.path.join(label_dir, "refs.txt"))
    return {
        "label": label,
        "malware_refs": mal_refs,
        "benign_refs": ben_refs,
        "tiers": tiers,
        "recall": rate(hit, exp),
        "recall_ci": wilson(hit, exp),
        "flagged": hit,
        "expected": exp,
        "benign": benign,
        "far": benign["rate"],
        "far_ci": benign["ci"],
        "missing": sum(t["missing"] for t in tiers.values()) + benign["missing"],
        "minutes": sum(d[0] for d in dones.values()) / 60.0,
    }, []


def fmt(v, digits=1):
    """Formats a number with fixed digits, or a dash for None."""
    return "-" if v is None else "%.*f" % (digits, v)


def sfmt(v, digits=1):
    """Formats a signed difference with fixed digits, or a dash for None."""
    return "-" if v is None else "%+.*f" % (digits, v)


def diff(a, b):
    """Returns a - b, or None when either is None."""
    return None if a is None or b is None else a - b


def sort_key(label):
    """Orders the labels old, new, then the rest alphabetically."""
    return (0, label) if label == "old" else (1, label) if label == "new" else (2, label)


def render_md(rows, incomplete, tiers):
    """Returns the markdown with the main table and the differences against the old label."""
    lines = []
    head = ["Label", "Malware refs", "Benign refs"]
    head += ["%s recall %%" % t for t in tiers]
    head += ["All-tier recall % (95% CI)", "False alarms % (95% CI)", "Scan min"]
    lines.append("## T1-T4 recall and false alarms")
    lines.append("")
    if rows:
        lines.append("| " + " | ".join(head) + " |")
        lines.append("|" + "|".join(["---"] * len(head)) + "|")
        for r in rows:
            cells = [r["label"], fmt(r["malware_refs"], 0), fmt(r["benign_refs"], 0)]
            for t in tiers:
                e = r["tiers"][t]
                cells.append("%s (%d/%d)" % (fmt(e["rate"]), e["flagged"], e["expected"]))
            cells.append(
                "%s (%s-%s) %d/%d"
                % (fmt(r["recall"]), fmt(r["recall_ci"][0]), fmt(r["recall_ci"][1]), r["flagged"], r["expected"])
            )
            b = r["benign"]
            cells.append(
                "%s (%s-%s) %d/%d"
                % (fmt(r["far"], 2), fmt(r["far_ci"][0], 2), fmt(r["far_ci"][1], 2), b["flagged"], b["expected"])
            )
            cells.append(fmt(r["minutes"]))
            lines.append("| " + " | ".join(cells) + " |")
        old = next((r for r in rows if r["label"] == "old"), None)
        others = [r for r in rows if r["label"] != "old"]
        if old and others:
            lines.append("")
            lines.append("## Difference against old (points; minutes for scan time)")
            lines.append("")
            head = ["Label"] + ["%s" % t for t in tiers] + ["All-tier recall", "False alarms", "Scan min"]
            lines.append("| " + " | ".join(head) + " |")
            lines.append("|" + "|".join(["---"] * len(head)) + "|")
            for r in others:
                cells = [r["label"] + " - old"]
                cells += [sfmt(diff(r["tiers"][t]["rate"], old["tiers"][t]["rate"])) for t in tiers]
                cells += [
                    sfmt(diff(r["recall"], old["recall"])),
                    sfmt(diff(r["far"], old["far"]), 2),
                    sfmt(diff(r["minutes"], old["minutes"])),
                ]
                lines.append("| " + " | ".join(cells) + " |")
        lost = [(r["label"], r["missing"]) for r in rows if r["missing"]]
        if lost:
            lines.append("")
            lines.append("Missing reports counted as not flagged:")
            for label, n in lost:
                lines.append("- %s: %d" % (label, n))
    else:
        lines.append("No complete labels yet.")
    if incomplete:
        lines.append("")
        lines.append("Incomplete labels (excluded):")
        for item in incomplete:
            lines.append("- %s: no successful .done for %s" % (item["label"], ", ".join(item["lacking"])))
    return "\n".join(lines) + "\n"


def main():
    """Summarises the T1-T4 and benign scan reports of every label into results.json and results.md."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="~/pg-t1t4")
    args = ap.parse_args()
    out = os.path.expanduser(args.out)
    test_manifest = json.load(open(os.path.join(out, "test", "manifest.json")))
    tiers = list(test_manifest["tiers"])
    rows = []
    incomplete = []
    for label in sorted(os.listdir(out), key=sort_key):
        label_dir = os.path.join(out, label)
        if label == "test" or not os.path.isdir(os.path.join(label_dir, "reports")):
            continue
        row, lacking = evaluate(label_dir, label, test_manifest)
        if row is None:
            incomplete.append({"label": label, "lacking": lacking})
        else:
            rows.append(row)
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump(
            {
                "tiers": {t: len(v) for t, v in test_manifest["tiers"].items()},
                "benign": len(test_manifest["benign"]),
                "missing_dirs": test_manifest["missing_dirs"],
                "rows": rows,
                "incomplete": incomplete,
            },
            f,
            indent=1,
        )
    md = render_md(rows, incomplete, tiers)
    with open(os.path.join(out, "results.md"), "w") as f:
        f.write(md)
    print(md)


if __name__ == "__main__":
    main()
