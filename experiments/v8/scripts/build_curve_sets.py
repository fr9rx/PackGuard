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


def group_by_name(folders):
    """Returns a dict mapping each normalised package name to the sorted folders holding its versions."""
    groups = {}
    for folder in folders:
        groups.setdefault(dir_package(folder), []).append(folder)
    return groups


def find_test_dir(root, package, version):
    """Returns the existing flat folder name for a manifest item, or None when neither spelling exists."""
    candidates = [package.replace("/", "__") + "@" + version]
    if package.startswith("@") and "/" in package:
        candidates.append(package.replace("/", "@") + "@" + version)
    for cand in candidates:
        if os.path.isdir(os.path.join(root, cand)):
            return cand
    return None


def collect_malware_test(args, ref_names, categories):
    """Returns the malware test items, the leak-dropped count per category and the missing-dir count."""
    roots = {"known": os.path.expanduser(args.known), "new": os.path.expanduser(args.new)}
    items = json.load(open(os.path.expanduser(args.manifest)))
    per_cat = {c: [] for c in categories}
    dropped = {c: 0 for c in categories}
    missing = 0
    seen = set()
    for item in items:
        key = "%s:%s" % (item.get("set"), item.get("category"))
        if key not in per_cat:
            continue
        found = find_test_dir(roots[item["set"]], item["package"], item["version"])
        if found is None:
            missing += 1
            continue
        if (key, found) in seen:
            continue
        seen.add((key, found))
        if norm_name(item["package"]) in ref_names:
            dropped[key] += 1
            continue
        per_cat[key].append(
            {
                "set": item["set"],
                "category": item["category"],
                "package": item["package"],
                "version": item["version"],
                "dir": found,
                "src": os.path.join(roots[item["set"]], found),
            }
        )
    rng = random.Random(args.test_seed)
    chosen = []
    for key in categories:
        pool = sorted(per_cat[key], key=lambda i: i["dir"])
        if args.per_category > 0 and len(pool) > args.per_category:
            pool = sorted(rng.sample(pool, args.per_category), key=lambda i: i["dir"])
        chosen.extend(pool)
    return chosen, dropped, missing


def split_benign(args, ref_names, mal_test_names):
    """Returns the benign test folders, the benign reference pool, the count dropped for a reference
    malware name clash and the count dropped for a malware test name clash."""
    benign_root = os.path.expanduser(args.benign)
    dirs = list_dirs(benign_root)
    clash = [d for d in dirs if dir_package(d) in ref_names]
    clash_set = set(clash)
    test_clash = [d for d in dirs if d not in clash_set and dir_package(d) in mal_test_names]
    drop = clash_set | set(test_clash)
    candidates = [d for d in dirs if d not in drop]
    rng = random.Random(args.test_seed)
    test = sorted(rng.sample(candidates, min(args.benign_test, len(candidates))))
    test_names = {dir_package(d) for d in test}
    pool = [d for d in dirs if dir_package(d) not in test_names and d not in drop]
    pool_names = {dir_package(d) for d in pool}
    assert not test_names & pool_names
    assert not test_names & ref_names
    assert not test_names & mal_test_names
    assert not pool_names & mal_test_names
    return test, pool, len(clash), len(test_clash)


def nested_subsets(folders, fractions, seed):
    """Returns a dict mapping each percent to the folders of the first round(percent/100*n) shuffled names."""
    groups = group_by_name(sorted(folders))
    names = sorted(groups)
    random.Random(seed).shuffle(names)
    out = {}
    for pct in fractions:
        take = names[: round(pct / 100.0 * len(names))]
        out[pct] = {"names": sorted(take), "folders": sorted(f for n in take for f in groups[n])}
    return out


def write_json(path, data):
    """Writes data to path as indented JSON."""
    with open(path, "w") as f:
        json.dump(data, f, indent=1)


def build_test_tree(out, args, categories, ref_names):
    """Builds or verifies the seed-independent test tree and returns its manifest."""
    chosen, dropped, missing = collect_malware_test(args, ref_names, categories)
    mal_test_names = {norm_name(i["package"]) for i in chosen}
    benign_test, benign_pool, clash, test_clash = split_benign(args, ref_names, mal_test_names)
    counts = {c: sum(1 for i in chosen if "%s:%s" % (i["set"], i["category"]) == c) for c in categories}
    empty = [c for c, n in counts.items() if n == 0]
    if empty:
        sys.exit("no test items for categories: " + ", ".join(empty))
    if not benign_test:
        sys.exit("no benign test items")
    manifest = {
        "test_seed": args.test_seed,
        "categories": counts,
        "dropped_for_leak": sum(dropped.values()),
        "dropped_for_leak_by_category": dropped,
        "missing_dirs": missing,
        "benign_dropped_name_clash": clash,
        "benign_dropped_test_malware_name": test_clash,
        "malware": [{k: v for k, v in i.items() if k != "src"} for i in chosen],
        "benign": benign_test,
    }
    test_root = os.path.join(out, "test")
    path = os.path.join(test_root, "manifest.json")
    if os.path.exists(path):
        old = json.load(open(path))
        if old.get("malware") != manifest["malware"] or old.get("benign") != manifest["benign"]:
            sys.exit("existing test manifest differs from the newly computed test set; aborting")
        return old, benign_pool
    for i in chosen:
        link_tree(i["src"], os.path.join(test_root, "%s_%s" % (i["set"], i["category"]), i["dir"]))
    benign_root = os.path.expanduser(args.benign)
    for d in benign_test:
        link_tree(os.path.join(benign_root, d), os.path.join(test_root, "benign", d))
    write_json(path, manifest)
    return manifest, benign_pool


def main():
    """Builds the fixed test set and the nested malware and benign reference subsets for the learning curve."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--refs", default="~/packguard-data/combined/malware_js")
    ap.add_argument("--benign", default="~/pg-test-sets/benign")
    ap.add_argument("--known", default="~/pg-test-sets/known")
    ap.add_argument("--new", default="~/pg-test-sets/new")
    ap.add_argument("--manifest", default="~/pg-test-sets/manifests/manifest_real.json")
    ap.add_argument("--out", default="~/pg-curve")
    ap.add_argument("--seed", type=int, default=20261114)
    ap.add_argument("--test-seed", type=int, default=20261114)
    ap.add_argument("--fractions", default="10,25,50,75,100")
    ap.add_argument("--benign-test", type=int, default=600)
    ap.add_argument("--per-category", type=int, default=0)
    ap.add_argument(
        "--categories",
        default="known:mal_newname,new:mal_shape,new:mal_stream,new:mal_scripts,new:mal_encoded",
    )
    args = ap.parse_args()
    out = os.path.expanduser(args.out)
    fractions = [int(x) for x in args.fractions.split(",")]
    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    refs_root = os.path.expanduser(args.refs)
    benign_root = os.path.expanduser(args.benign)

    ref_folders = list_dirs(refs_root)
    ref_names = {dir_package(d) for d in ref_folders}
    test_manifest, benign_pool = build_test_tree(out, args, categories, ref_names)

    test_names = {norm_name(i["package"]) for i in test_manifest["malware"]}
    assert not test_names & ref_names, "test malware overlaps the malware references"

    mal_sub = nested_subsets(ref_folders, fractions, args.seed)
    ben_sub = nested_subsets(benign_pool, fractions, args.seed)
    seed_root = os.path.join(out, "seed%d" % args.seed)
    fraction_info = {}
    for pct in fractions:
        base = os.path.join(seed_root, "p%03d" % pct)
        for kind, root, folders in (
            ("malware", refs_root, mal_sub[pct]["folders"]),
            ("benign", benign_root, ben_sub[pct]["folders"]),
        ):
            kind_dir = os.path.join(base, kind)
            os.makedirs(kind_dir, exist_ok=True)
            wanted = set(folders)
            for entry in os.listdir(kind_dir):
                if entry not in wanted:
                    stale = os.path.join(kind_dir, entry)
                    if os.path.isdir(stale) and not os.path.islink(stale):
                        shutil.rmtree(stale)
                    else:
                        os.remove(stale)
            for folder in folders:
                link_tree(os.path.join(root, folder), os.path.join(kind_dir, folder))
        fraction_info[str(pct)] = {
            "malware_folders": len(mal_sub[pct]["folders"]),
            "malware_names": len(mal_sub[pct]["names"]),
            "benign": len(ben_sub[pct]["folders"]),
            "malware": mal_sub[pct]["folders"],
            "benign_list": ben_sub[pct]["folders"],
        }
    write_json(os.path.join(seed_root, "manifest.json"), {"seed": args.seed, "fractions": fraction_info})

    print("test seed", test_manifest["test_seed"], "ref seed", args.seed)
    print("malware test:", json.dumps(test_manifest["categories"]))
    print(
        "dropped for leak", test_manifest["dropped_for_leak"],
        "missing dirs", test_manifest["missing_dirs"],
        "benign test", len(test_manifest["benign"]),
        "benign pool", len(benign_pool),
    )
    for pct in fractions:
        info = fraction_info[str(pct)]
        print(
            "p%03d" % pct, "malware folders", info["malware_folders"],
            "names", info["malware_names"], "benign", info["benign"],
        )


if __name__ == "__main__":
    main()
