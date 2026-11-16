import argparse
import json
import os
import shutil
import sys

TIERS = ["T1_format", "T2_rename", "T3_padding", "T4_base64"]


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


def prune(tier_dir, wanted):
    """Removes every entry of tier_dir that is not in the wanted set."""
    os.makedirs(tier_dir, exist_ok=True)
    for entry in os.listdir(tier_dir):
        if entry not in wanted:
            stale = os.path.join(tier_dir, entry)
            if os.path.isdir(stale) and not os.path.islink(stale):
                shutil.rmtree(stale)
            else:
                os.remove(stale)


def collect_items(manifest_path, known_root, tiers, per_tier):
    """Returns the existing flat folder names per tier (first per_tier in manifest order when per_tier is
    positive) and the number of manifest items whose folder is missing, per tier."""
    items = json.load(open(manifest_path))
    found = {t: [] for t in tiers}
    missing = {t: 0 for t in tiers}
    seen = set()
    for item in items:
        tier = item.get("category")
        if tier not in found:
            continue
        name = "%s@%s" % (item["package"], item["version"])
        if (tier, name) in seen:
            continue
        seen.add((tier, name))
        if not os.path.isdir(os.path.join(known_root, name)):
            missing[tier] += 1
            continue
        found[tier].append(name)
    if per_tier > 0:
        found = {t: v[:per_tier] for t, v in found.items()}
    return found, missing


def main():
    """Builds the T1-T4 benchmark test tree as hard links, plus the held-out benign set, and writes its manifest."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="/root/pg-test-sets/manifests/manifest_invented.json")
    ap.add_argument("--known", default="/root/pg-test-sets/known")
    ap.add_argument("--benign-src", default="/root/pg-curve/test/benign")
    ap.add_argument("--out", default="~/pg-t1t4")
    ap.add_argument("--per-tier", type=int, default=0)
    args = ap.parse_args()
    out = os.path.expanduser(args.out)
    known_root = os.path.expanduser(args.known)
    benign_src = os.path.expanduser(args.benign_src)
    test_root = os.path.join(out, "test")

    found, missing = collect_items(os.path.expanduser(args.manifest), known_root, TIERS, args.per_tier)
    benign = sorted(d for d in os.listdir(benign_src) if os.path.isdir(os.path.join(benign_src, d)))
    if args.per_tier > 0:
        benign = benign[: args.per_tier]
    if not benign:
        sys.exit("no benign test folders in " + benign_src)
    empty = [t for t in TIERS if not found[t]]
    if empty:
        sys.exit("no test folders for tiers: " + ", ".join(empty))

    for tier in TIERS:
        tier_dir = os.path.join(test_root, tier)
        prune(tier_dir, set(found[tier]))
        for name in found[tier]:
            link_tree(os.path.join(known_root, name), os.path.join(tier_dir, name))
    prune(os.path.join(test_root, "benign"), set(benign))
    for name in benign:
        link_tree(os.path.join(benign_src, name), os.path.join(test_root, "benign", name))

    manifest = {
        "tiers": {t: found[t] for t in TIERS},
        "missing_dirs": missing,
        "benign": benign,
        "per_tier": args.per_tier,
    }
    with open(os.path.join(test_root, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    for tier in TIERS:
        print(tier, "linked", len(found[tier]), "missing", missing[tier])
    print("benign linked", len(benign), "missing dirs total", sum(missing.values()))


if __name__ == "__main__":
    main()
