import argparse
import concurrent.futures
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = "DataDog/malicious-software-packages-dataset"
API = "https://api.github.com/repos/" + REPO
RAW = "https://raw.githubusercontent.com/" + REPO + "/main/samples/npm/"
HEADERS = {"User-Agent": "dataset-fetcher/1.0", "Accept": "application/vnd.github+json"}
DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-")


def api_get(url):
    """Returns the parsed JSON of a GitHub API URL, retrying transient errors and
    exiting with a clear message when the unauthenticated rate limit is hit."""
    headers = dict(HEADERS)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    err = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            err = e
            if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
                reset = e.headers.get("X-RateLimit-Reset", "?")
                raise SystemExit(f"GitHub API rate limit exhausted (resets at epoch {reset}); "
                                 "cached trees are kept, rerun later")
            if e.code == 404:
                raise SystemExit(f"not found: {url}")
        except Exception as e:
            err = e
        time.sleep(2 * (attempt + 1))
    raise SystemExit(f"API request failed {url}: {err!r}")


def cached_tree(out, name, url, refresh):
    """Returns a tree JSON from the on-disk cache named <name>, fetching and
    caching it from url when missing or when refresh is set."""
    path = os.path.join(out, name)
    if not refresh and os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except ValueError:
            pass
    tree = api_get(url)
    os.makedirs(out, exist_ok=True)
    with open(path + ".part", "w") as f:
        json.dump(tree, f)
    os.replace(path + ".part", path)
    return tree


def walk_tree(out, kind, sha, prefix, refresh, depth=0):
    """Lists all blob entries under a tree sha with paths relative to the kind
    directory, using one recursive request and descending into subtrees (each
    cached) when GitHub reports the recursive listing as truncated."""
    name = f"tree_{kind}.json" if depth == 0 else f"tree_{kind}__{sha}.json"
    tree = cached_tree(out, name, f"{API}/git/trees/{sha}?recursive=1", refresh)
    if not tree.get("truncated"):
        return [dict(e, path=prefix + e["path"]) for e in tree["tree"] if e["type"] == "blob"]
    shallow = cached_tree(out, f"tree_{kind}__{sha}__flat.json", f"{API}/git/trees/{sha}", refresh)
    entries = []
    for e in shallow["tree"]:
        if e["type"] == "blob":
            entries.append(dict(e, path=prefix + e["path"]))
        elif e["type"] == "tree":
            entries.extend(walk_tree(out, kind, e["sha"], prefix + e["path"] + "/", refresh, depth + 1))
    return entries


def list_kind(out, kind, refresh):
    """Returns the blob entries of samples/npm/<kind> (path relative to the kind
    directory, plus size), resolving the kind's tree sha from samples/npm."""
    root = cached_tree(out, "tree_npm_root.json", f"{API}/git/trees/main:samples/npm", refresh)
    sha = next((e["sha"] for e in root["tree"] if e["path"] == kind and e["type"] == "tree"), None)
    if sha is None:
        raise SystemExit(f"kind not found in samples/npm: {kind}")
    return walk_tree(out, kind, sha, "", refresh)


def parse_path(path):
    """Maps '<name>/<version>/<YYYY-MM-DD>-...zip' to (npm name, version, date or
    None); scoped packages are stored as '@scope@name' and become '@scope/name'."""
    parts = path.split("/")
    name, version, fname = "/".join(parts[:-2]), parts[-2], parts[-1]
    if name.startswith("@") and name.count("@") == 2:
        scope, pkg = name[1:].split("@", 1)
        name = "@" + scope + "/" + pkg
    m = DATE_RE.match(fname)
    return name, version, (m.group(1) if m else None)


def download(job):
    """Downloads one zip to <dst>.part and renames it, keeping an existing file of
    the expected size; returns 'kept', 'new' or 'failed <url> <error>'."""
    url, dst, size = job
    if os.path.exists(dst) and os.path.getsize(dst) == size:
        return "kept"
    err = None
    for attempt in range(5):
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            got = 0
            with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=120) as r, \
                    open(dst + ".part", "wb") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
                    got += len(chunk)
            if got != size:
                raise IOError(f"size {got} != {size}")
            os.replace(dst + ".part", dst)
            return "new"
        except Exception as e:
            err = e
            time.sleep(1 + attempt)
    if os.path.exists(dst + ".part"):
        os.remove(dst + ".part")
    return f"failed {url} {err!r}"


def write_index(out, records):
    """Writes the index.json list atomically."""
    path = os.path.join(out, "index.json")
    with open(path + ".part", "w") as f:
        json.dump(records, f)
    os.replace(path + ".part", path)


def main():
    """Parses arguments, lists the chosen kinds, downloads the zips within the size
    limit in parallel and writes index.json for every zip present on disk."""
    ap = argparse.ArgumentParser(description="Fetch DataDog npm malware zips (kept encrypted).")
    ap.add_argument("--out", default="~/packguard-data/v9/raw/datadog")
    ap.add_argument("--kinds", default="malicious_intent,compromised_lib")
    ap.add_argument("--max-bytes", type=int, default=20 << 20)
    ap.add_argument("--threads", type=int, default=24)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--refresh-tree", action="store_true")
    args = ap.parse_args()
    out = os.path.abspath(os.path.expanduser(args.out))
    os.makedirs(out, exist_ok=True)

    jobs, meta = [], {}
    for kind in [k.strip() for k in args.kinds.split(",") if k.strip()]:
        entries = list_kind(out, kind, args.refresh_tree)
        zips = sorted((e for e in entries if e["path"].endswith(".zip")), key=lambda e: e["path"])
        small = [e for e in zips if e["size"] <= args.max_bytes]
        if args.limit:
            small = small[:args.limit]
        print(f"{kind}: {len(zips)} zips listed, {len(small)} selected, "
              f"{sum(e['size'] for e in small)} bytes", flush=True)
        for e in small:
            dst = os.path.join(out, kind, *e["path"].split("/"))
            url = RAW + kind + "/" + urllib.parse.quote(e["path"])
            jobs.append((url, dst, e["size"]))
            meta[dst] = (kind, e)

    counts = {"kept": 0, "new": 0, "failed": 0}
    records = []
    with concurrent.futures.ThreadPoolExecutor(args.threads) as ex:
        futs = {ex.submit(download, j): j for j in jobs}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            res = fut.result()
            dst = futs[fut][1]
            if res.startswith("failed"):
                counts["failed"] += 1
                print(res, flush=True)
            else:
                counts[res] += 1
                kind, e = meta[dst]
                name, version, date = parse_path(e["path"])
                records.append({
                    "provider": "datadog", "category": kind, "name": name,
                    "version": version, "published": date,
                    "archive": os.path.relpath(dst, out).replace(os.sep, "/"),
                    "format": "zip-infected", "bytes": e["size"]})
            if i % 500 == 0 or i == len(jobs):
                print(f"{i} of {len(jobs)} {counts}", flush=True)
    records.sort(key=lambda r: r["archive"])
    write_index(out, records)
    print("done", len(jobs), counts, "indexed", len(records), flush=True)


if __name__ == "__main__":
    main()
