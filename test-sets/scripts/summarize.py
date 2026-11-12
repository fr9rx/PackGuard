import argparse
import collections
import glob
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common


def summarize_manifest(paths):
    """Returns counts per set, kind and category from one or more manifests."""
    counts = collections.Counter()
    flagged = collections.Counter()
    total = 0
    for path in paths:
        if not os.path.exists(path):
            continue
        for item in common.load_json(path):
            key = (item.get("set"), item.get("kind"), item.get("category"))
            counts[key] += 1
            total += 1
            if item.get("primitive_flagged"):
                flagged[key] += 1
    rows = []
    for key in sorted(counts):
        rows.append({"set": key[0], "kind": key[1], "category": key[2],
                     "packages": counts[key], "primitive_flagged": flagged[key]})
    return rows, total


def summarize_reports(root):
    """Returns detection statistics for every report directory under root."""
    rows = []
    for directory in sorted(glob.glob(os.path.join(root, "*", "*", "*"))):
        if not os.path.isdir(directory):
            continue
        reports = sorted(glob.glob(os.path.join(directory, "*.json")))
        if not reports:
            continue
        scores = []
        flagged = 0
        primitive = 0
        threshold = None
        for path in reports:
            try:
                report = common.load_json(path)
            except (ValueError, OSError):
                continue
            if report.get("score") is not None:
                scores.append(report["score"])
            if report.get("flagged"):
                flagged += 1
            if report.get("primitive_flagged"):
                primitive += 1
            if report.get("threshold") is not None:
                threshold = report["threshold"]
        relative = os.path.relpath(directory, root).replace("\\", "/").split("/")
        set_name, kind, category = (relative + ["", "", ""])[:3]
        rows.append({
            "set": set_name,
            "kind": kind,
            "category": category,
            "packages": len(reports),
            "flagged": flagged,
            "flagged_pct": round(100.0 * flagged / len(reports), 1) if reports else 0.0,
            "primitive_flagged": primitive,
            "median_score": round(statistics.median(scores), 4) if scores else None,
            "threshold": threshold,
        })
    return rows


def print_rows(rows):
    """Prints a fixed-width summary table."""
    for row in rows:
        if "flagged_pct" in row:
            print("%-5s %-9s %-30s %6d %6d %6.1f%% prim=%d median=%s" % (
                row["set"], row["kind"], row["category"], row["packages"],
                row["flagged"], row["flagged_pct"], row["primitive_flagged"],
                row["median_score"]))
        else:
            print("%-5s %-9s %-30s %6d prim_flagged=%d" % (
                row["set"], row["kind"], row["category"], row["packages"],
                row["primitive_flagged"]))


def main():
    """Parses arguments and prints or writes the summary."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", action="append", default=[])
    parser.add_argument("--reports")
    parser.add_argument("--json-out")
    args = parser.parse_args()
    result = {}
    if args.manifest:
        rows, total = summarize_manifest(args.manifest)
        result["manifest"] = {"rows": rows, "total": total}
        print("manifest total", total)
        print_rows(rows)
    if args.reports:
        rows = summarize_reports(args.reports)
        result["reports"] = rows
        print("reports")
        print_rows(rows)
    if args.json_out:
        common.write_manifest(args.json_out, result)


if __name__ == "__main__":
    main()
