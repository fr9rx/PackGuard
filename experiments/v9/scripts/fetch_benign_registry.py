import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import os
import random
import re
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HIGH_IMPACT = "https://registry.npmjs.org/npm-high-impact/-/npm-high-impact-1.13.0.tgz"
SEARCH = "https://registry.npmjs.org/-/v1/search?text=%s&size=250&from=%d"
DOWNLOADS = "https://api.npmjs.org/downloads/point/last-month/%s"
GITHUB = "https://api.github.com/repos/DataDog/malicious-software-packages-dataset"
AGENT = "Mozilla/5.0 (compatible; research-fetch/1.0)"
CUTOFF = "2026-08-15"
JS_EXT = (".js", ".cjs", ".mjs")
KEYWORDS = """string array date color parser format convert validator logger config cli math helper
util plugin template markdown csv json url path hash random event stream cache queue retry
timer slug case diff merge deep clone sort search filter emoji unicode i18n locale
http request client server api rest graphql websocket socket proxy router middleware express koa
react vue angular svelte component hooks redux state store form input button modal table chart
canvas svg image video audio file fs glob watch build bundle webpack rollup babel eslint lint
prettier test mock assert spec benchmark promise async worker thread cluster child process
crypto encrypt token jwt auth oauth session cookie password uuid id number currency money
time duration timezone calendar cron schedule geo map location address phone email mail sms
database sql mysql postgres mongo redis orm query schema model validation types typescript
string-utils text word regex escape template-engine html xml yaml toml ini env dotenv argv
command terminal shell ansi progress spinner prompt table-format pretty print debug trace
""".split()

LOCK = threading.Lock()
LAST = [0.0]


def pace(gap):
    """Spaces requests at least gap seconds apart across all threads."""
    with LOCK:
        wait = LAST[0] + gap - time.time()
        LAST[0] = max(time.time(), LAST[0] + gap)
    if wait > 0:
        time.sleep(wait)


def get(url, tries=6, gap=0.0, headers=None, limit=None):
    """Fetches url with a generic user agent, retrying with exponential backoff, and returns the body bytes."""
    err = None
    for attempt in range(tries):
        if gap:
            pace(gap)
        req = urllib.request.Request(url, headers=dict({"User-Agent": AGENT, "Accept-Encoding": "gzip"}, **(headers or {})))
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read(limit + 1) if limit else r.read()
                if limit and len(body) > limit:
                    raise ValueError("too large")
                if r.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                return body
        except urllib.error.HTTPError as e:
            err = e
            if e.code in (400, 401, 403, 404, 410):
                if e.code != 403:
                    raise
            delay = 2 ** attempt * 2
            if e.code == 429 and e.headers.get("Retry-After", "").isdigit():
                delay = max(delay, int(e.headers["Retry-After"]))
            time.sleep(delay)
        except ValueError:
            raise
        except Exception as e:
            err = e
            time.sleep(2 ** attempt)
    raise err


def norm_key(name):
    """Returns the comparison key of a package name with scope separators ('/', '@', '_', '__') flattened."""
    return re.sub(r"[/@_]+", "_", name.lower())


def folder_name(folder):
    """Returns the package name of a '<name>@<version>' folder name."""
    return folder.rsplit("@", 1)[0]


def datadog_names(cache):
    """Returns the package names of DataDog malicious_intent and compromised_lib, caching each tree listing."""
    os.makedirs(cache, exist_ok=True)
    names = set()
    for cat in ("malicious_intent", "compromised_lib"):
        path = os.path.join(cache, "tree_%s.json" % cat)
        if os.path.exists(path):
            tree = json.load(open(path))
        else:
            listing = json.loads(get(GITHUB + "/contents/samples/npm"))
            sha = next(e["sha"] for e in listing if e["name"] == cat)
            tree = json.loads(get(GITHUB + "/git/trees/" + sha + "?recursive=1"))
            if tree.get("truncated"):
                raise SystemExit("tree listing truncated: " + cat)
            json.dump(tree, open(path, "w"))
        for e in tree["tree"]:
            if e["type"] == "blob" and e["path"].count("/") >= 2:
                names.add("/".join(e["path"].split("/")[:-2]))
    return names


def excluded_keys(existing_dir, malware_dir, manifest_path, datadog_cache):
    """Returns (keys, per-source counts) of every name that must never become a benign reference."""
    sources = {
        "existing_benign": [folder_name(d) for d in os.listdir(existing_dir)],
        "combined_malware": [folder_name(d) for d in os.listdir(malware_dir)],
        "manifest_real": [r["package"] for r in json.load(open(manifest_path))],
        "datadog": list(datadog_names(datadog_cache)),
    }
    keys, counts = set(), {}
    for label, names in sources.items():
        k = {norm_key(n) for n in names}
        counts[label] = len(k)
        keys |= k
    return keys, counts


def high_impact_names(cache):
    """Returns the sorted names of the npm-high-impact 1.13.0 list, caching the downloaded tarball."""
    path = os.path.join(cache, "npm-high-impact-1.13.0.tgz")
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(get(HIGH_IMPACT))
    with tarfile.open(path, mode="r:gz") as t:
        text = t.extractfile("package/lib/top.js").read().decode()
    return sorted(set(re.findall(r"'([^']+)'", text)))


def search_candidates(cache, pages):
    """Returns {name: (search date, search monthly downloads)} from keyword searches, caching every page."""
    os.makedirs(cache, exist_ok=True)
    found = {}
    for kw in KEYWORDS:
        for page in range(pages):
            path = os.path.join(cache, "%s_%d.json" % (kw, page * 250))
            if os.path.exists(path):
                res = json.load(open(path))
            else:
                try:
                    res = json.loads(get(SEARCH % (urllib.parse.quote(kw), page * 250), gap=1.5))
                except Exception:
                    break
                json.dump(res, open(path, "w"))
            objs = res.get("objects", [])
            for o in objs:
                p = o["package"]
                if o.get("flags", {}).get("insecure") or p.get("deprecated"):
                    continue
                found.setdefault(p["name"], (p.get("date", "")[:10], o.get("downloads", {}).get("monthly")))
            if len(objs) < 250:
                break
    return found


def bulk_downloads(names):
    """Returns {name: monthly downloads} for a batch of up to 100 unscoped names."""
    try:
        if len(names) == 1:
            doc = {names[0]: json.loads(get(DOWNLOADS % names[0], gap=1.0))}
        else:
            doc = json.loads(get(DOWNLOADS % ",".join(names), gap=1.0))
    except Exception:
        return {}
    return {k: v["downloads"] for k, v in doc.items() if isinstance(v, dict) and "downloads" in v}


def scoped_downloads(name):
    """Returns the monthly downloads of one scoped name, or None."""
    try:
        return json.loads(get(DOWNLOADS % urllib.parse.quote(name, safe="@"), gap=1.0)).get("downloads")
    except Exception:
        return None


def downloads_for(names, cache_path):
    """Returns {name: monthly downloads} for names, using and extending a disk cache."""
    counts = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
    todo = [n for n in names if n not in counts]
    plain = [n for n in todo if not n.startswith("@")]
    scoped = [n for n in todo if n.startswith("@")]
    for i in range(0, len(plain), 100):
        counts.update(bulk_downloads(plain[i:i + 100]))
        json.dump(counts, open(cache_path, "w"))
    for i, n in enumerate(scoped, 1):
        c = scoped_downloads(n)
        if c is not None:
            counts[n] = c
        if i % 50 == 0:
            json.dump(counts, open(cache_path, "w"))
            print("downloads scoped", i, "of", len(scoped), flush=True)
    json.dump(counts, open(cache_path, "w"))
    return counts


def packument(name, meta_dir):
    """Returns the full registry document of name, cached on disk, or None when it cannot be fetched."""
    path = os.path.join(meta_dir, name.replace("/", "__") + ".json")
    if os.path.exists(path):
        return json.load(open(path))
    try:
        blob = get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), gap=0.05)
        doc = json.loads(blob)
    except Exception:
        return None
    slim = {"name": doc.get("name"), "dist-tags": doc.get("dist-tags"), "time": doc.get("time"),
            "versions": {v: x for v, x in doc.get("versions", {}).items() if v == doc.get("dist-tags", {}).get("latest")}}
    with open(path + ".part", "w") as f:
        json.dump(slim, f)
    os.replace(path + ".part", path)
    return slim


def judge(name, source, doc, downloads, args, stats):
    """Returns an index row for the latest version of name, or None after counting the drop reason in stats."""
    def drop(reason):
        """Counts one dropped package under reason and returns None."""
        with LOCK:
            stats[reason] = stats.get(reason, 0) + 1
        return None

    if doc is None:
        return drop("no_metadata")
    latest = (doc.get("dist-tags") or {}).get("latest")
    ver = (doc.get("versions") or {}).get(latest)
    if not ver or not ver.get("dist", {}).get("tarball"):
        return drop("no_latest")
    if ver.get("deprecated"):
        return drop("deprecated")
    published = ((doc.get("time") or {}).get(latest) or "")[:10]
    if not published or published > CUTOFF:
        return drop("too_recent")
    if downloads is None:
        return drop("no_downloads")
    if source == "longtail" and not (args.min_downloads <= downloads <= args.max_downloads):
        return drop("downloads_out_of_range")
    if source == "popular" and downloads < 1:
        return drop("no_downloads")
    size = ver["dist"].get("unpackedSize")
    if size and size > args.max_unpacked:
        return drop("too_large")
    return {"name": name, "version": latest, "tarball": ver["dist"]["tarball"], "unpacked_size": size,
            "source": source, "published": published, "monthly_downloads": downloads}


def fetch_tarball(row, tar_dir, max_unpacked):
    """Downloads the tarball of row into tar_dir if missing and returns row extended with file and tarball_size, or None."""
    fname = "%s@%s.tgz" % (row["name"].replace("/", "_"), row["version"])
    path = os.path.join(tar_dir, fname)
    if not os.path.exists(path):
        try:
            blob = get(row["tarball"], gap=0.05, limit=max_unpacked)
        except Exception:
            return None
        with open(path + ".part", "wb") as f:
            f.write(blob)
        os.replace(path + ".part", path)
    return dict(row, file=fname, tarball_size=os.path.getsize(path))


def has_js(path):
    """Returns True when the tarball holds a JavaScript file outside node_modules."""
    try:
        with tarfile.open(path, mode="r:gz") as t:
            for m in t.getmembers():
                parts = m.name.split("/")
                if m.isfile() and m.name.endswith(JS_EXT) and "node_modules" not in parts:
                    return True
    except Exception:
        return False
    return False


def fetch(args):
    """Collects candidates, applies the date, download, deprecation and size filters, and downloads the tarballs."""
    base = os.path.expanduser(args.base)
    raw = os.path.join(base, "raw", "npm_benign")
    tar_dir = os.path.join(raw, "tarballs")
    meta_dir = os.path.join(raw, "metadata")
    for d in (tar_dir, meta_dir, os.path.join(raw, "search")):
        os.makedirs(d, exist_ok=True)
    rng = random.Random(args.seed)

    banned, banned_counts = excluded_keys(args.existing, args.malware, args.manifest, os.path.join(base, "raw", "datadog"))
    print("excluded keys", len(banned), banned_counts, flush=True)

    popular_all = high_impact_names(raw)
    popular = [n for n in popular_all if norm_key(n) not in banned]
    rng.shuffle(popular)
    popular_set = set(popular_all)

    found = search_candidates(os.path.join(raw, "search"), args.pages)
    stats = {"high_impact_total": len(popular_all), "high_impact_excluded": len(popular_all) - len(popular),
             "search_candidates": len(found)}
    lt = sorted(n for n, (date, dl) in found.items()
                if norm_key(n) not in banned and n not in popular_set and date <= CUTOFF
                and (dl is None or args.min_downloads * 0.5 <= dl <= args.max_downloads * 1.5))
    stats["longtail_after_prefilter"] = len(lt)
    rng.shuffle(lt)
    lt = lt[:args.longtail_pool]
    counts = downloads_for(lt + popular[:args.popular_pool], os.path.join(raw, "downloads.json"))
    print("stats", stats, flush=True)

    jobs = [("popular", n) for n in popular[:args.popular_pool]] + [("longtail", n) for n in lt]
    want = {"popular": args.popular, "longtail": args.longtail}
    got_rows = {"popular": [], "longtail": []}
    judged = {"popular": 0, "longtail": 0}

    def work(job):
        """Judges, downloads and checks one candidate; returns (source, index row or None)."""
        source, name = job
        row = judge(name, source, packument(name, meta_dir), counts.get(name), args, stats)
        if row is None:
            return source, None
        row = fetch_tarball(row, tar_dir, args.max_unpacked)
        if row is None:
            with LOCK:
                stats["download_failed"] = stats.get("download_failed", 0) + 1
            return source, None
        if not has_js(os.path.join(tar_dir, row["file"])):
            with LOCK:
                stats["no_javascript"] = stats.get("no_javascript", 0) + 1
            return source, None
        return source, row

    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        for i, (source, row) in enumerate(ex.map(work, jobs), 1):
            judged[source] += 1
            if row and len(got_rows[source]) < want[source]:
                got_rows[source].append(row)
            if i % 200 == 0:
                print("processed", i, "of", len(jobs), {k: len(v) for k, v in got_rows.items()}, flush=True)

    keep = {r["file"] for rows in got_rows.values() for r in rows}
    for f in os.listdir(tar_dir):
        if f.endswith(".tgz") and f not in keep:
            os.remove(os.path.join(tar_dir, f))
    index = sorted(got_rows["popular"] + got_rows["longtail"], key=lambda r: (r["source"], r["name"]))
    json.dump(index, open(os.path.join(raw, "index.json"), "w"), indent=1)
    stats["banned_counts"] = banned_counts
    json.dump(stats, open(os.path.join(raw, "fetch_stats.json"), "w"), indent=1)
    print("DONE index", len(index), {k: len(v) for k, v in got_rows.items()}, "stats", stats, flush=True)


def ws_key(data):
    """Returns the whitespace-insensitive content hash used to drop repeated files."""
    return hashlib.sha256(re.sub(rb"\s+", b"", data)).hexdigest()


def dedupe(args):
    """Drops files of the new reference folders that duplicate a file of the existing benign folders, and empty folders."""
    base = os.path.expanduser(args.base)
    new_dir = os.path.join(base, "benign_new")
    seen = set()
    for d in os.listdir(args.existing):
        p = os.path.join(args.existing, d)
        for f in os.listdir(p):
            seen.add(ws_key(open(os.path.join(p, f), "rb").read()))
    manifest = json.load(open(os.path.join(base, "benign_refs_manifest.json")))
    out, dropped_files, emptied = [], 0, 0
    for row in manifest:
        p = os.path.join(new_dir, "%s@%s" % (row["name"].replace("/", "_"), row["version"]))
        size, files = 0, 0
        for f in sorted(os.listdir(p)):
            fp = os.path.join(p, f)
            data = open(fp, "rb").read()
            if ws_key(data) in seen:
                os.remove(fp)
                dropped_files += 1
            else:
                size += len(data)
                files += 1
        if files == 0:
            os.rmdir(p)
            emptied += 1
            continue
        out.append(dict(row, js_bytes=size, files=files))
    index = {(r["name"], r["version"]): r for r in json.load(open(os.path.join(base, "raw", "npm_benign", "index.json")))}
    for r in out:
        meta = index[(r["name"], r["version"])]
        r.update(published=meta["published"], monthly_downloads=meta["monthly_downloads"])
    json.dump(out, open(os.path.join(base, "benign_new_manifest.json"), "w"), indent=1)
    print("kept", len(out), "popular", sum(r["source"] == "popular" for r in out),
          "longtail", sum(r["source"] == "longtail" for r in out), "dropped_files_vs_existing", dropped_files,
          "emptied_packages", emptied, "js_mib", round(sum(r["js_bytes"] for r in out) / 1048576, 1))


def main():
    """Runs the 'fetch' step (registry download) or the 'dedupe' step (cross-set deduplication after build_benign.py)."""
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["fetch", "dedupe"])
    ap.add_argument("--base", default="/root/packguard-data/v9")
    ap.add_argument("--existing", default="/root/pg-test-sets/benign")
    ap.add_argument("--malware", default="/root/packguard-data/combined/malware_js")
    ap.add_argument("--manifest", default="/root/pg-test-sets/manifests/manifest_real.json")
    ap.add_argument("--popular", type=int, default=1300)
    ap.add_argument("--longtail", type=int, default=1300)
    ap.add_argument("--popular-pool", type=int, default=1800)
    ap.add_argument("--longtail-pool", type=int, default=2600)
    ap.add_argument("--pages", type=int, default=4)
    ap.add_argument("--min-downloads", type=int, default=50)
    ap.add_argument("--max-downloads", type=int, default=2000)
    ap.add_argument("--max-unpacked", type=int, default=8 * 1024 * 1024)
    ap.add_argument("--jobs", type=int, default=10)
    ap.add_argument("--seed", type=int, default=20261115)
    args = ap.parse_args()
    if args.step == "fetch":
        fetch(args)
    else:
        dedupe(args)


if __name__ == "__main__":
    main()
