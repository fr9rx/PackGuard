import argparse
import json
import os
import random
import shutil
import sys


def norm_name(name):
    """Returns a package name in the comparable form scope/name, undoing the __ and @scope@name spellings."""
    return name.lstrip("@").replace("__", "/").replace("@", "/")


def dir_package(dirname):
    """Returns the normalised package name of a folder called <package>@<version>."""
    return norm_name(dirname.rsplit("@", 1)[0])


def list_dirs(path):
    """Returns the sorted names of the sub-directories of path."""
    return sorted(d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d)))


def link_tree(src, dst):
    """Recreates the tree src under dst with hard links, copying a file when linking fails.
    The tree is built in dst + ".tmp" and renamed to dst when complete; an existing dst is left alone."""
    if os.path.exists(dst):
        return
    tmp = dst + ".tmp"
    if os.path.exists(tmp):
        shutil.rmtree(tmp)
    os.makedirs(tmp)
    for cur, dirs, names in os.walk(src):
        rel = os.path.relpath(cur, src)
        target = tmp if rel == "." else os.path.join(tmp, rel)
        os.makedirs(target, exist_ok=True)
        for name in names:
            source = os.path.join(cur, name)
            if os.path.islink(source) or not os.path.isfile(source):
                continue
            dest = os.path.join(target, name)
            try:
                os.link(source, dest)
            except OSError:
                shutil.copy2(source, dest)
    os.rename(tmp, dst)


def write_json(path, data):
    """Writes data to path as indented JSON through a temporary file and an atomic rename."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def group_by_name(folders):
    """Returns a dict mapping each normalised package name to the sorted folders holding its versions."""
    groups = {}
    for folder in sorted(folders):
        groups.setdefault(dir_package(folder), []).append(folder)
    return groups


def leak_check(mal_new, ben_new, test_manifest):
    """Aborts when a new folder carries the name of a malware test package, or a new benign folder
    carries the name of a benign test package."""
    mal_test = {norm_name(i["package"]) for i in test_manifest["malware"]}
    ben_test = {dir_package(d) for d in test_manifest["benign"]}
    bad = ["malware_new %s" % d for d in mal_new if dir_package(d) in mal_test]
    bad += ["benign_new %s (malware test name)" % d for d in ben_new if dir_package(d) in mal_test]
    bad += ["benign_new %s (benign test name)" % d for d in ben_new if dir_package(d) in ben_test]
    if bad:
        sys.exit("leak guard: %d new folders clash with the test set, e.g. %s" % (len(bad), "; ".join(bad[:5])))


def shuffled_units(units, seed, tag):
    """Returns the units in a deterministic shuffled order that depends on the seed and the tag."""
    order = sorted(units)
    random.Random("%s:%s" % (seed, tag)).shuffle(order)
    return order


def plan_points(points, n_old_names, n_old_benign, mal_units, ben_units):
    """Returns one plan per distinct point: requested percent, units taken and achieved percentages.
    A point beyond what the additions can give is capped at all additions and later identical points are skipped."""
    plans = []
    last = None
    for pct in points:
        want_m = round((pct - 100) / 100.0 * n_old_names)
        want_b = round((pct - 100) / 100.0 * n_old_benign)
        take_m = min(want_m, len(mal_units))
        take_b = min(want_b, len(ben_units))
        if (take_m, take_b) == last:
            continue
        last = (take_m, take_b)
        plans.append(
            {
                "percent": pct,
                "take_m": take_m,
                "take_b": take_b,
                "capped": take_m < want_m or take_b < want_b,
                "achieved_m": 100.0 + 100.0 * take_m / n_old_names,
                "achieved_b": 100.0 + 100.0 * take_b / n_old_benign,
            }
        )
    return plans


def materialise(kind_dir, sources):
    """Makes kind_dir hold exactly the folders in sources (a dict folder -> source path) as hard-linked trees."""
    os.makedirs(kind_dir, exist_ok=True)
    for entry in os.listdir(kind_dir):
        if entry not in sources:
            stale = os.path.join(kind_dir, entry)
            if os.path.isdir(stale) and not os.path.islink(stale):
                shutil.rmtree(stale)
            else:
                os.remove(stale)
    for folder in sorted(sources):
        link_tree(sources[folder], os.path.join(kind_dir, folder))


def main():
    """Extends the learning-curve reference subsets beyond 100% with seeded additions from new malware and benign data."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--curve", default="~/pg-curve")
    ap.add_argument("--out-curve", default=None)
    ap.add_argument("--seed", type=int, default=20261114)
    ap.add_argument("--malware-new", default="/root/packguard-data/v9/malware_new")
    ap.add_argument("--benign-new", default="/root/packguard-data/v9/benign_new")
    ap.add_argument("--points", default="125,150,175,200")
    args = ap.parse_args()
    curve = os.path.expanduser(args.curve)
    out_curve = os.path.expanduser(args.out_curve) if args.out_curve else curve
    mal_root = os.path.expanduser(args.malware_new)
    ben_root = os.path.expanduser(args.benign_new)
    points = sorted({int(x) for x in args.points.split(",") if x.strip()})
    if not points or points[0] <= 100:
        sys.exit("points must all be above 100")

    seed_name = "seed%d" % args.seed
    seed_manifest = json.load(open(os.path.join(curve, seed_name, "manifest.json")))
    test_manifest = json.load(open(os.path.join(curve, "test", "manifest.json")))
    base = seed_manifest["fractions"]["100"]
    old_mal = list(base["malware"])
    old_ben = list(base["benign_list"])
    n_old_names = base["malware_names"]
    n_old_benign = len(old_ben)
    old_src_root = os.path.join(curve, seed_name, "p100")

    old_mal_set = set(old_mal)
    old_ben_set = set(old_ben)
    mal_new = [d for d in list_dirs(mal_root) if d not in old_mal_set]
    ben_new = [d for d in list_dirs(ben_root) if d not in old_ben_set]
    leak_check(mal_new, ben_new, test_manifest)

    mal_groups = group_by_name(mal_new)
    mal_units = shuffled_units(mal_groups, args.seed, "growth-malware")
    ben_units = shuffled_units(ben_new, args.seed, "growth-benign")
    plans = plan_points(points, n_old_names, n_old_benign, mal_units, ben_units)

    out_seed = os.path.join(out_curve, seed_name)
    os.makedirs(out_seed, exist_ok=True)
    os.makedirs(os.path.join(out_curve, "test"), exist_ok=True)
    out_manifest_path = os.path.join(out_seed, "manifest.json")
    if out_curve != curve:
        shutil.copy2(os.path.join(curve, "test", "manifest.json"), os.path.join(out_curve, "test", "manifest.json"))
        if not os.path.exists(out_manifest_path):
            shutil.copy2(os.path.join(curve, seed_name, "manifest.json"), out_manifest_path)
        out_manifest = json.load(open(out_manifest_path))
    else:
        out_manifest = seed_manifest

    for plan in plans:
        names = mal_units[: plan["take_m"]]
        add_mal = sorted(f for n in names for f in mal_groups[n])
        add_ben = sorted(ben_units[: plan["take_b"]])
        mal_sources = {f: os.path.join(old_src_root, "malware", f) for f in old_mal}
        mal_sources.update({f: os.path.join(mal_root, f) for f in add_mal})
        ben_sources = {f: os.path.join(old_src_root, "benign", f) for f in old_ben}
        ben_sources.update({f: os.path.join(ben_root, f) for f in add_ben})
        pdir = os.path.join(out_seed, "p%03d" % plan["percent"])
        materialise(os.path.join(pdir, "malware"), mal_sources)
        materialise(os.path.join(pdir, "benign"), ben_sources)
        all_names = {dir_package(f) for f in mal_sources}
        out_manifest["fractions"][str(plan["percent"])] = {
            "malware_folders": len(mal_sources),
            "malware_names": len(all_names),
            "benign": len(ben_sources),
            "malware": sorted(mal_sources),
            "benign_list": sorted(ben_sources),
            "achieved_percent_malware": plan["achieved_m"],
            "achieved_percent_benign": plan["achieved_b"],
            "additions_malware_names": plan["take_m"],
            "additions_benign": plan["take_b"],
            "capped": plan["capped"],
        }
        write_json(out_manifest_path, out_manifest)
        print(
            "p%03d" % plan["percent"], "malware folders", len(mal_sources), "names", len(all_names),
            "benign", len(ben_sources),
            "achieved malware %.1f%% benign %.1f%%" % (plan["achieved_m"], plan["achieved_b"]),
            "CAPPED" if plan["capped"] else "",
        )
    kept = {pl["percent"] for pl in plans}
    skipped = [p for p in points if p not in kept]
    print("new malware folders", len(mal_new), "names", len(mal_units), "new benign", len(ben_units))
    if skipped:
        print("skipped identical points:", ",".join(str(p) for p in skipped))


if __name__ == "__main__":
    main()
