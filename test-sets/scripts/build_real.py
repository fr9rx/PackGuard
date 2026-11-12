import argparse
import collections
import concurrent.futures
import json
import os
import random
import shutil
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common
import generate_invented as fixtures

API = "https://api.github.com/repos/DataDog/malicious-software-packages-dataset"
RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/"
JS_LIMIT = 64 * 1024


def fetch_tree(cache_dir):
    """Returns the DataDog malicious_intent Git tree, caching the JSON listing."""
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, "tree_malicious_intent.json")
    if os.path.exists(path):
        return common.load_json(path)
    listing = json.load(urllib.request.urlopen(API + "/contents/samples/npm", timeout=60))
    sha = next(entry["sha"] for entry in listing if entry["name"] == "malicious_intent")
    tree = json.load(urllib.request.urlopen(API + "/git/trees/" + sha + "?recursive=1", timeout=120))
    if tree.get("truncated"):
        raise SystemExit("DataDog tree listing is truncated")
    common.write_manifest(path, tree)
    return tree


def entry_fields(entry):
    """Returns (name, version, date, path, size) for one DataDog tree entry."""
    parts = entry["path"].split("/")
    name, version, filename = parts[0], parts[1], parts[2]
    return name, version, filename[:10], entry["path"], entry["size"]


def download(job):
    """Downloads one DataDog zip when it is missing and returns a status string."""
    url, dst, size = job
    if os.path.exists(dst) and os.path.getsize(dst) == size:
        return "kept"
    error = None
    for _ in range(5):
        try:
            blob = urllib.request.urlopen(url, timeout=120).read()
            if len(blob) != size:
                raise IOError("size %d != %d" % (len(blob), size))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst + ".part", "wb") as handle:
                handle.write(blob)
            os.replace(dst + ".part", dst)
            return "new"
        except Exception as exc:
            error = exc
    return "failed %s %r" % (url, error)


def download_pool(cache_dir, entries, threads):
    """Downloads the chosen DataDog zips and returns the local paths that exist."""
    jobs = []
    paths = []
    for entry in entries:
        name, version, date, path, size = entry_fields(entry)
        dst = os.path.join(cache_dir, "datadog", path)
        jobs.append((RAW + "malicious_intent/" + urllib.parse.quote(path), dst, size))
        paths.append(dst)
    counts = collections.Counter()
    with concurrent.futures.ThreadPoolExecutor(threads) as pool:
        for index, result in enumerate(pool.map(download, jobs), 1):
            counts[result.split()[0]] += 1
            if result.startswith("failed"):
                print(result, flush=True)
            if index % 500 == 0:
                print("download", index, "of", len(jobs), dict(counts), flush=True)
    print("download done", len(jobs), dict(counts))
    return [path for path in paths if os.path.exists(path) and os.path.getsize(path) > 0]


def corpus_packages(roots):
    """Returns (package_path, group, name, version) for every extracted corpus package."""
    packages = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for group in sorted(os.listdir(root)):
            group_dir = os.path.join(root, group)
            if not os.path.isdir(group_dir):
                continue
            for package in sorted(os.listdir(group_dir)):
                path = os.path.join(group_dir, package)
                if not os.path.isdir(path) or "@" not in package:
                    continue
                name, version = package.rsplit("@", 1)
                packages.append((path, group, name, version))
    return packages


def read_package(path, limit):
    """Reads one extracted package folder, capping total JavaScript bytes."""
    files = {}
    used = 0
    for name in sorted(os.listdir(path)):
        file_path = os.path.join(path, name)
        if not os.path.isfile(file_path):
            continue
        with open(file_path, "rb") as handle:
            data = handle.read()
        if common.is_js(name):
            if used >= limit:
                continue
            data = data[:limit - used]
            used += len(data)
        files[name] = data
    return files


def write_target(out_root, category, name, version, files, scripts=None):
    """Writes one target package with a realistic package.json."""
    final = fixtures.finalise(name, version, files, scripts=scripts)
    common.write_package(os.path.join(out_root, category, "%s@%s" % (common.safe_component(name),
                                                                     common.safe_component(version))), final)


def index_zip(path):
    """Reads one downloaded DataDog zip and returns a selection record."""
    try:
        files, manifest, name, version = common.read_datadog_zip(path)
    except Exception as exc:
        return {"error": repr(exc), "path": path}
    name = name or os.path.basename(os.path.dirname(os.path.dirname(path)))
    version = version or os.path.basename(os.path.dirname(path))
    files = common.truncated_files(files, JS_LIMIT)
    scripts = common.install_scripts_from_json(manifest) if manifest else b""
    shape_files = dict(files)
    if scripts:
        shape_files[common.SCRIPTS_FILE] = scripts
    js_hits, script_hits = common.package_primitive_hits(shape_files)
    return {
        "path": path,
        "name": name,
        "version": version,
        "files": files,
        "scripts": scripts,
        "shape": common.package_shape(shape_files),
        "js_bytes": sum(len(data) for key, data in files.items() if common.is_js(key)),
        "js_hits": sorted(js_hits),
        "script_hits": sorted(script_hits),
        "primitive_flagged": common.primitives_flagged(js_hits, False)
                             or common.primitives_flagged(script_hits, True),
        "encoded": bool({"eval", "decode", "encoding", "obfuscation"} & (js_hits | script_hits)),
    }


def index_pool(paths, threads):
    """Indexes the downloaded zips in parallel, skipping unreadable ones."""
    with concurrent.futures.ThreadPoolExecutor(threads) as pool:
        records = list(pool.map(index_zip, paths))
    return [record for record in records if "error" not in record and record["shape"]]


def build_known_corpus(roots, out_root, count, seed):
    """Writes raw known-family packages from the extracted v1/v2 corpora."""
    packages = corpus_packages(roots)
    rng = random.Random(seed)
    rng.shuffle(packages)
    manifest = []
    seen = set()
    known = 0
    scripts_count = 0
    known_target = int(count * 0.6)
    for path, group, name, version in packages:
        if known >= known_target and scripts_count >= count - known_target:
            break
        if (name, version) in seen:
            continue
        files = read_package(path, 32 * 1024)
        if not any(common.is_js(item) for item in files):
            continue
        seen.add((name, version))
        has_scripts = bool(files.get(common.SCRIPTS_FILE))
        if has_scripts and scripts_count < count - known_target:
            category = "mal_scripts"
            scripts_count += 1
        elif known < known_target:
            category = "mal_known"
            known += 1
        else:
            continue
        write_target(out_root, category, name, version, files)
        js_hits, script_hits = common.package_primitive_hits(files)
        manifest.append({"set": "known", "kind": "real", "category": category,
                         "package": name, "version": version, "group": group,
                         "source": "v1/v2 corpus", "primitive_flagged":
                         common.primitives_flagged(js_hits, False)
                         or common.primitives_flagged(script_hits, True),
                         "primitive_hits": sorted(js_hits | script_hits)})
    return manifest


def select_candidates(tree, ref_keys, ref_names, versions_target, names_target, max_bytes):
    """Picks DataDog entries for new versions and held-out package names."""
    rng = random.Random(20261106)
    new_versions = []
    new_names = []
    for entry in tree["tree"]:
        if not entry["path"].endswith(".zip") or entry["size"] > max_bytes:
            continue
        name, version, date, path, size = entry_fields(entry)
        if name in ref_names and (name, version) not in ref_keys:
            new_versions.append(entry)
        elif name not in ref_names:
            new_names.append(entry)
    rng.shuffle(new_versions)
    rng.shuffle(new_names)
    return new_versions[:versions_target] + new_names[:names_target]


def build_known_downloads(records, out_root, out_root_existing, limits):
    """Writes new-version and new-name packages from the downloaded pool."""
    manifest = []
    seen = set()
    written = collections.Counter()
    for record in records:
        category = record.get("known_category")
        if not category or written[category] >= limits.get(category, 0):
            continue
        if (record["name"], record["version"]) in seen:
            continue
        seen.add((record["name"], record["version"]))
        written[category] += 1
        write_target(out_root, category, record["name"], record["version"], record["files"],
                     [line for line in record["scripts"].decode("utf-8", "surrogateescape").splitlines() if line])
        manifest.append({"set": "known", "kind": "real", "category": category,
                         "package": record["name"], "version": record["version"],
                         "group": record["shape"], "source": "DataDog download",
                         "primitive_flagged": record["primitive_flagged"],
                         "primitive_hits": sorted(set(record["js_hits"]) | set(record["script_hits"]))})
    return manifest


def select_new(records, counts):
    """Splits the held-out pool into the new-campaign categories."""
    by_shape = collections.defaultdict(list)
    for record in records:
        by_shape[record["shape"]].append(record)
    rng = random.Random(20261107)
    used = set()

    def take(pool, amount):
        rng.shuffle(pool)
        taken = []
        for record in pool:
            if record["path"] in used:
                continue
            used.add(record["path"])
            taken.append(record)
            if len(taken) >= amount:
                break
        return taken

    encoded_records = take([record for record in records if record["encoded"]], counts["encoded"])
    script_records = take([record for record in records if record["scripts"]], counts["scripts"])
    shapes = sorted(by_shape)
    rng.shuffle(shapes)
    shape_records = []
    for shape in shapes:
        if len(shape_records) >= counts["shape"]:
            break
        shape_records.extend(take(by_shape[shape], 1))
    stream_records = take(list(records), counts["stream"])
    return {
        "mal_shape": shape_records,
        "mal_stream": stream_records,
        "mal_scripts": script_records,
        "mal_encoded": encoded_records,
    }


def build_new(records, out_root, counts):
    """Writes the held-out new-campaign packages."""
    selected = select_new(records, counts)
    manifest = []
    seen = set()
    for category, chosen in selected.items():
        for record in chosen:
            if (record["name"], record["version"]) in seen:
                continue
            seen.add((record["name"], record["version"]))
            scripts = [line for line in record["scripts"].decode("utf-8", "surrogateescape").splitlines()
                       if line.strip()]
            write_target(out_root, category, record["name"], record["version"], record["files"], scripts)
            manifest.append({"set": "new", "kind": "real", "category": category,
                             "package": record["name"], "version": record["version"],
                             "group": record["shape"], "source": "DataDog download",
                             "primitive_flagged": record["primitive_flagged"],
                             "primitive_hits": sorted(set(record["js_hits"]) | set(record["script_hits"]))})
    return manifest


def pack_categories(root, zips_dir, prefix):
    """Packs each category under root into an encrypted zip and returns its size."""
    packed = []
    if not os.path.isdir(root):
        return packed
    os.makedirs(zips_dir, exist_ok=True)
    for category in sorted(os.listdir(root)):
        path = os.path.join(root, category)
        if not os.path.isdir(path):
            continue
        out = os.path.join(zips_dir, "%s_%s.zip" % (prefix, category))
        files, size = common.write_encrypted_zip(out, path)
        packed.append({"zip": out, "files": files, "bytes": size})
        print("packed", out, files, "files", "%.1f MiB" % (size / 2 ** 20))
    return packed


def main():
    """Parses arguments, builds both real sets and writes their manifests."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--v1-root", default=os.path.expanduser("~/packguard-data/v1/malware_js"))
    parser.add_argument("--v2-root", default=os.path.expanduser("~/packguard-data/v2/malware_js"))
    parser.add_argument("--out", default=os.path.expanduser("~/pg-test-sets"))
    parser.add_argument("--cache", default=os.path.expanduser("~/pg-test-sets/cache"))
    parser.add_argument("--known-count", type=int, default=1200)
    parser.add_argument("--newver", type=int, default=500)
    parser.add_argument("--newname", type=int, default=2500)
    parser.add_argument("--shape", type=int, default=700)
    parser.add_argument("--stream", type=int, default=900)
    parser.add_argument("--new-scripts", type=int, default=300)
    parser.add_argument("--encoded", type=int, default=400)
    parser.add_argument("--max-zip-bytes", type=int, default=512 * 1024)
    parser.add_argument("--threads", type=int, default=32)
    parser.add_argument("--seed", type=int, default=20261106)
    parser.add_argument("--pack", action="store_true")
    parser.add_argument("--skip-download", action="store_true")
    args = parser.parse_args()

    known_out = os.path.join(args.out, "known", "real")
    new_out = os.path.join(args.out, "new", "real")
    for root in (known_out, new_out):
        common.remove_tree(root)
        os.makedirs(root, exist_ok=True)

    packages = corpus_packages([args.v1_root, args.v2_root])
    ref_keys = {(name, version) for _, _, name, version in packages}
    ref_names = {name for _, _, name, _ in packages}
    ref_shapes = set()
    if os.path.isdir(args.v2_root):
        ref_shapes = {name for name in os.listdir(args.v2_root)
                      if os.path.isdir(os.path.join(args.v2_root, name))}
    print("corpus", len(packages), "packages", len(ref_names), "names",
          len(ref_shapes), "v2 shapes", flush=True)

    manifest = build_known_corpus([args.v1_root, args.v2_root], known_out, args.known_count, args.seed)
    print("known corpus written", len(manifest), flush=True)

    if not args.skip_download:
        tree = fetch_tree(args.cache)
        entries = select_candidates(tree, ref_keys, ref_names, args.newver * 3, args.newname * 2,
                                    args.max_zip_bytes)
        print("selected", len(entries), "entries to download", flush=True)
        paths = download_pool(args.cache, entries, args.threads)
        records = index_pool(paths, args.threads)
        print("indexed", len(records), "usable packages", flush=True)
        for record in records:
            if record["name"] in ref_names and (record["name"], record["version"]) not in ref_keys:
                record["known_category"] = "mal_newver"
            elif record["name"] not in ref_names and record["shape"] in ref_shapes:
                record["known_category"] = "mal_newname"
            else:
                record["known_category"] = None
        manifest.extend(build_known_downloads(records, known_out, known_out,
                                              {"mal_newver": args.newver, "mal_newname": args.newname}))
        heard = [record for record in records if record["known_category"] is None]
        manifest.extend(build_new(heard, new_out, {"shape": args.shape, "stream": args.stream,
                                                   "scripts": args.new_scripts,
                                                   "encoded": args.encoded}))
    else:
        print("downloads skipped", flush=True)

    common.write_manifest(os.path.join(args.out, "manifest_real.json"), manifest)
    stats = collections.Counter((item["set"], item["kind"], item["category"]) for item in manifest)
    for key in sorted(stats):
        print("stat", key, stats[key])
    if args.pack:
        pack_categories(known_out, os.path.join(args.out, "zips", "known"), "known")
        pack_categories(new_out, os.path.join(args.out, "zips", "new"), "new")


if __name__ == "__main__":
    main()
