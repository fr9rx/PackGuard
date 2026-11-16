#!/usr/bin/env python3
import argparse
import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENT = "Mozilla/5.0 (compatible; dataset-fetch/1.0)"
API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
MIN_TGZ_BYTES = 100
DEFAULT_ROOT = os.path.expanduser("~/packguard-data/v9/raw")

NPMANALYSIS = {
    "id": "npmanalysis",
    "owner": "lxyeternal",
    "repo": "NPMAnalysis",
    "subtree": "Dataset/zip_malware",
}
MALPKG = {
    "id": "malpkg",
    "owner": "lxyeternal",
    "repo": "malicious-package-dataset",
    "subtree": "npm",
}
TIMES_URL = (
    RAW + "/lxyeternal/NPMAnalysis/main/Core/Data/timecollect/time/malware_time.csv"
)
NPMZOO_URL = "https://github.com/spaceraccoon/npm-zoo.git"

print_lock = threading.Lock()


def log(message):
    """Prints a progress line to stderr in a thread-safe way."""
    with print_lock:
        print(message, file=sys.stderr, flush=True)


def http_get(url, retries=5, timeout=60, accept=None):
    """Returns the body bytes of a GET request, retrying with backoff on errors and raising after the last attempt."""
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code in (403, 429) and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
            elif exc.code >= 500:
                time.sleep(2 * (attempt + 1))
            else:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise last


def http_json(url):
    """Returns the parsed JSON body of a GET request."""
    return json.loads(http_get(url, accept="application/vnd.github+json"))


def download_file(url, dest, retries=5, timeout=120):
    """Streams a URL to dest through a .part file and renames it on success, returning the byte count or raising after the last retry."""
    part = dest + ".part"
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                with open(part, "wb") as handle:
                    shutil.copyfileobj(resp, handle, 1 << 20)
            os.replace(part, dest)
            return os.path.getsize(dest)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    if os.path.exists(part):
        os.remove(part)
    raise last


def has_gzip_magic(path):
    """Returns True when the file starts with the two gzip magic bytes, reading nothing else."""
    with open(path, "rb") as handle:
        return handle.read(2) == b"\x1f\x8b"


def quote_path(path):
    """Percent-encodes every segment of a repository path for use in a raw URL."""
    return "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))


def decode_name(folder):
    """Converts a repository folder name such as @scope##pkg into the npm name @scope/pkg."""
    return folder.replace("##", "/")


def load_times():
    """Downloads the publish-time CSV of NPMAnalysis and returns a dict mapping (name, version) to YYYY-MM-DD, skipping rows without a timestamp."""
    try:
        text = http_get(TIMES_URL).decode("utf-8", "replace")
    except Exception as exc:
        log("publish-time table unavailable: %s" % exc)
        return {}
    times = {}
    for row in csv.DictReader(io.StringIO(text)):
        stamp = (row.get("timestamp") or "").strip()
        if len(stamp) >= 10 and stamp[4] == "-" and stamp[7] == "-":
            times[(row["package_name"], row["version"])] = stamp[:10]
    return times


def list_github_tgz(spec):
    """Returns sorted (path, size) pairs of npm tgz blobs of at least MIN_TGZ_BYTES under the provider subtree via the GitHub git-trees API."""
    repo = http_json("%s/repos/%s/%s" % (API, spec["owner"], spec["repo"]))
    branch = repo["default_branch"]
    ref = urllib.parse.quote("%s:%s" % (branch, spec["subtree"]), safe=":/")
    tree = http_json(
        "%s/repos/%s/%s/git/trees/%s?recursive=1"
        % (API, spec["owner"], spec["repo"], ref)
    )
    if tree.get("truncated"):
        raise RuntimeError("tree listing truncated for " + spec["id"])
    found = []
    for item in tree["tree"]:
        path = item["path"]
        if item["type"] != "blob" or not path.endswith(".tgz"):
            continue
        if path.count("/") != 2 or item["size"] < MIN_TGZ_BYTES:
            continue
        found.append((path, item["size"]))
    found.sort()
    return found, branch


def fetch_one(spec, branch, out_dir, path, expected):
    """Downloads one tgz unless already present at the expected size, validates the gzip magic, and returns (path, bytes) or (path, None) on failure."""
    dest = os.path.join(out_dir, *path.split("/"))
    try:
        if not (os.path.exists(dest) and os.path.getsize(dest) == expected):
            url = "%s/%s/%s/%s/%s/%s" % (
                RAW,
                spec["owner"],
                spec["repo"],
                branch,
                quote_path(spec["subtree"]),
                quote_path(path),
            )
            download_file(url, dest)
        if not has_gzip_magic(dest):
            os.remove(dest)
            log("not a gzip, dropped: " + path)
            return path, None
        return path, os.path.getsize(dest)
    except Exception as exc:
        log("failed %s: %s" % (path, exc))
        return path, None


def run_github_tgz(spec, out_dir, limit, workers):
    """Fetches the tgz samples of a GitHub-hosted provider in parallel, resumably, and writes index.json."""
    os.makedirs(out_dir, exist_ok=True)
    entries, branch = list_github_tgz(spec)
    if limit:
        entries = entries[:limit]
    times = load_times()
    log("%s: %d archives to fetch" % (spec["id"], len(entries)))
    sizes = {}
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(fetch_one, spec, branch, out_dir, path, size)
            for path, size in entries
        ]
        for future in as_completed(futures):
            path, got = future.result()
            if got is not None:
                sizes[path] = got
            done += 1
            if done % 500 == 0:
                log("%s: %d/%d" % (spec["id"], done, len(entries)))
    index = []
    for path, _ in entries:
        if path not in sizes:
            continue
        folder, version, _name = path.split("/")
        name = decode_name(folder)
        index.append(
            {
                "provider": spec["id"],
                "category": None,
                "name": name,
                "version": version,
                "published": times.get((name, version)),
                "archive": path,
                "format": "tgz",
                "password": None,
                "bytes": sizes[path],
            }
        )
    write_index(out_dir, index)
    log("%s: %d of %d archives indexed" % (spec["id"], len(index), len(entries)))


def write_index(out_dir, index):
    """Writes index.json atomically in the provider directory."""
    target = os.path.join(out_dir, "index.json")
    with open(target + ".part", "w", encoding="utf-8") as handle:
        json.dump(index, handle, indent=1)
    os.replace(target + ".part", target)


def dir_bytes(path):
    """Returns the total size in bytes of all files below a directory."""
    total = 0
    for base, _dirs, files in os.walk(path):
        for name in files:
            total += os.path.getsize(os.path.join(base, name))
    return total


def run_npmzoo(out_dir, limit):
    """Shallow-clones the small npm-zoo repository once and indexes each unpacked package directory as format dir."""
    os.makedirs(out_dir, exist_ok=True)
    repo_dir = os.path.join(out_dir, "repo")
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        tmp = tempfile.mkdtemp(dir=out_dir, prefix="clone_")
        target = os.path.join(tmp, "repo")
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", NPMZOO_URL, target],
            check=True,
            env=dict(os.environ, GIT_TERMINAL_PROMPT="0"),
        )
        os.replace(target, repo_dir)
        shutil.rmtree(tmp, ignore_errors=True)
    packages = os.path.join(repo_dir, "packages")
    index = []
    for folder in sorted(os.listdir(packages)):
        base = os.path.join(packages, folder)
        if not os.path.isdir(base):
            continue
        for sub in sorted(os.listdir(base)):
            pkg_dir = os.path.join(base, sub)
            manifest = os.path.join(pkg_dir, "package.json")
            if not os.path.isfile(manifest):
                continue
            with open(manifest, encoding="utf-8", errors="replace") as handle:
                meta = json.load(handle)
            index.append(
                {
                    "provider": "npmzoo",
                    "category": None,
                    "name": meta.get("name") or folder,
                    "version": meta.get("version"),
                    "published": None,
                    "archive": "repo/packages/%s/%s" % (folder, sub),
                    "format": "dir",
                    "password": None,
                    "bytes": dir_bytes(pkg_dir),
                }
            )
    if limit:
        index = index[:limit]
    write_index(out_dir, index)
    log("npmzoo: %d packages indexed" % len(index))


def build_parser():
    """Builds the command-line parser with one sub-command per provider plus all."""
    parser = argparse.ArgumentParser(
        description="Fetch npm malware sample archives from open providers, unchanged, with an index.json per provider."
    )
    sub = parser.add_subparsers(dest="provider", required=True)
    for name in ("npmanalysis", "malpkg", "npmzoo", "all"):
        item = sub.add_parser(name)
        if name == "all":
            item.add_argument("--out", default=DEFAULT_ROOT, help="root dir holding one folder per provider")
        else:
            item.add_argument("--out", default=os.path.join(DEFAULT_ROOT, name))
        item.add_argument("--limit", type=int, default=0, help="max packages per provider, 0 for all")
        item.add_argument("--workers", type=int, default=16)
    return parser


def main():
    """Parses arguments and runs the selected provider fetchers."""
    args = build_parser().parse_args()
    jobs = []
    if args.provider in ("npmanalysis", "all"):
        out = args.out if args.provider == "npmanalysis" else os.path.join(args.out, "npmanalysis")
        jobs.append(lambda out=out: run_github_tgz(NPMANALYSIS, out, args.limit, args.workers))
    if args.provider in ("malpkg", "all"):
        out = args.out if args.provider == "malpkg" else os.path.join(args.out, "malpkg")
        jobs.append(lambda out=out: run_github_tgz(MALPKG, out, args.limit, args.workers))
    if args.provider in ("npmzoo", "all"):
        out = args.out if args.provider == "npmzoo" else os.path.join(args.out, "npmzoo")
        jobs.append(lambda out=out: run_npmzoo(out, args.limit))
    for job in jobs:
        job()


if __name__ == "__main__":
    main()
