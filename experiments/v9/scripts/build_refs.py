import argparse
import collections
import concurrent.futures
import concurrent.futures.process
import datetime
import functools
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "v2", "scripts"))

from build_dataset import install_scripts, trivial_scripts, script_shape, ws_hash

JS_EXT = (".js", ".cjs", ".mjs")
SCRIPTS_FILE = "install_scripts.txt"
MARKER = ".pg_build_refs"
MAX_FILE = 8 << 20
MAX_MANIFEST = 1 << 20
MAX_MEMBERS = 20000
MAX_JS_TOTAL = 64 << 20
MAX_TAR_TOTAL = 1 << 30
MAX_FLAT = 180
MAX_FOLDER = 240
SHAPE_MAX = 2 << 20
STUB_MAX_FILE = 64 << 10
CACHE_VERSION = 4
CHECKPOINT_EVERY = 2000
BATCH = 2000
UNKNOWN_VERSION = "0.0.0-unknown"
HOLDING = b"security holding package"
FOLDER_RE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._~@+-]*")

STRING_TOKEN = (
    rb"""(?:"(?:\\.|[^"\\\n])*(?:"|(?=\n)|\Z)"""
    rb"""|'(?:\\.|[^'\\\n])*(?:'|(?=\n)|\Z)"""
    rb"""|`(?:\\.|[^`\\])*(?:`|\Z))""")
COMMENT_TOKEN = rb"(?:/\*.*?(?:\*/|\Z)|//[^\n]*)"
JS_TOKEN = re.compile(
    b"(" + STRING_TOKEN + b")|(" + COMMENT_TOKEN + b")"
    rb"""|(\b_0x[0-9a-fA-F]+\b)"""
    rb"""|(\b\d[\w.]*)"""
    rb"""|(\s+)""", re.S)
COMMENT_OR_SPACE = re.compile(b"(" + STRING_TOKEN + b")|(" + COMMENT_TOKEN + b")|(\\s+)", re.S)
STUB_BODY = re.compile(
    rb"""(?:;|["']use strict["']"""
    rb"""|console\.\w+\((?:"[^"]*"|'[^']*'|`[^`]*`)?\)"""
    rb"""|(?:module\.)?exports(?:\.\w+)?=\{\})+""")
STUB_MIN = 40


class TooLarge(Exception):
    pass


def norm_name(name):
    """Normalises an npm package name so that flattened forms compare equal.
    The name is lower-cased, a leading '@' is removed and every run of '/',
    '@' and '_' becomes one '/', so "@scope/name", "@scope__name",
    "@scope@name", "@scope_name" and "scope_name" all give "scope/name".
    The rule deliberately over-matches (a plain "a_b" equals "a/b"): for the
    leak check that only ever drops more samples, and for the per-name cap
    it lets existing '_'-flattened folders count against new scoped names."""
    return re.sub(r"[/@_]+", "/", str(name).lower().lstrip("@"))


def norm_published(value):
    """Normalises a published value to an ISO date string (YYYY-MM-DD) or
    None: numbers are Unix seconds (milliseconds above 1e11) read as UTC,
    strings must start with an ISO date, anything else gives None."""
    try:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            seconds = value / 1000 if abs(value) > 1e11 else value
            return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).date().isoformat()
        if isinstance(value, str):
            text = value.strip()
            if re.match(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
                return datetime.date.fromisoformat(text[:10]).isoformat()
    except (ValueError, OverflowError, OSError):
        return None
    return None


def flat_folder(name, version):
    """Returns the reference folder name for a package: '/' in the name
    becomes '__' and the version is appended after '@'."""
    return "%s@%s" % (name.replace("/", "__"), version)


def valid_folder(folder):
    """True when a folder name is safe to create: it matches
    ^[A-Za-z0-9@][A-Za-z0-9._~@+-]*$, contains no '..' and is at most 240
    bytes in UTF-8."""
    return (FOLDER_RE.fullmatch(folder) is not None and ".." not in folder
            and len(folder.encode("utf-8", "replace")) <= MAX_FOLDER)


def split_folder(folder):
    """Splits an existing folder name <name>@<version> at its last '@'."""
    name, _, version = folder.rpartition("@")
    return name, version


def shape_sub(m):
    """Replacement function of the code-shape substitution."""
    if m.group(1) is not None:
        return b'"'
    if m.group(3) is not None:
        return b"_0x"
    if m.group(4) is not None:
        return b"0"
    return b""


def code_shape(src):
    """Code shape of one JavaScript file: strings, numbers, comments and
    _0x obfuscator names blanked out, whitespace removed. Equivalent to the
    v2 js_shape for well-formed input, but linear in the input size: an
    unterminated block comment or template string runs to the end of the
    input and an unterminated quoted string to the end of its line."""
    return JS_TOKEN.sub(shape_sub, src)


def shape_digest(data):
    """Returns the hex shape hash of a file. Files over 2 MiB, and files on
    which the shaping fails, use the whitespace-insensitive hash instead."""
    if len(data) > SHAPE_MAX:
        return ws_hash(data)
    try:
        return hashlib.sha256(code_shape(data)).hexdigest()
    except (RecursionError, ValueError):
        return ws_hash(data)


def strip_js(src):
    """Returns a JavaScript source with comments and whitespace removed
    (strings are left untouched)."""
    return COMMENT_OR_SPACE.sub(lambda m: m.group(0) if m.group(1) is not None else b"", src)


def is_stub(src):
    """True when a JavaScript file under 64 KiB is a stub: after stripping
    comments and whitespace it is shorter than 40 bytes, or consists only of
    'use strict', console.* calls with one literal argument and empty
    module.exports / exports.x = {} assignments. Larger files never are."""
    if len(src) >= STUB_MAX_FILE:
        return False
    body = strip_js(src)
    return len(body) < STUB_MIN or STUB_BODY.fullmatch(body) is not None


def is_binary(data):
    """True when a file is not text: it holds a NUL byte, or more than 10% of
    its bytes fail to decode as UTF-8."""
    if b"\x00" in data:
        return True
    text = data.decode("utf-8", "replace")
    return text.count("�") * 10 > max(len(text), 1)


def unique_flat(rel, taken):
    """Flattens a path with '__' into a file name of at most 180 UTF-8 bytes
    (over-long names get an 8-hex digest prefix and keep the tail and the
    extension) and makes the result unique within taken."""
    flat = "__".join(rel).encode("utf-8", "replace").decode("utf-8")
    ext = os.path.splitext(flat)[1]
    stem = flat[:len(flat) - len(ext)].encode("utf-8")
    digest = ""
    if len(flat.encode("utf-8")) > MAX_FLAT:
        digest = hashlib.sha256(flat.encode("utf-8")).hexdigest()[:8] + "__"
    n = 1
    while True:
        suffix = "" if n == 1 else "_%d" % n
        room = MAX_FLAT - len((digest + suffix + ext).encode("utf-8"))
        body = stem if len(stem) <= room else stem[len(stem) - room:]
        cand = digest + body.decode("utf-8", "ignore") + suffix + ext
        if cand not in taken:
            taken.add(cand)
            return cand
        n += 1


def safe_name(name):
    """True when an archive member name is a plain relative path."""
    parts = name.split("/")
    return bool(name) and not name.startswith("/") and ".." not in parts and "\x00" not in name


def read_zip_member(z, info, pwd):
    """Reads one zip member, never more than its declared size."""
    with z.open(info, pwd=pwd) as fh:
        data = fh.read(info.file_size + 1)
    if len(data) > info.file_size:
        raise ValueError("zip member larger than declared")
    return data


def read_tar_member(t, member):
    """Reads the current member of a tar stream, never more than its size."""
    fh = t.extractfile(member)
    if fh is None:
        raise ValueError("tar member unreadable")
    data = fh.read(member.size + 1)
    if len(data) > member.size:
        raise ValueError("tar member larger than declared")
    return data


def read_regular(full, size):
    """Reads a regular file without following symlinks, never more than size
    bytes plus one."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(full, flags)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise OSError("not a regular file: " + full)
        data = fh.read(size + 1)
    if len(data) > size:
        raise OSError("file grew while reading: " + full)
    return data


def iter_members(path, fmt, pwd):
    """Yields (member name, size, read function) one member at a time for a
    zip, a tar or a directory, never holding more than the current member.
    Tar and directory members are re-rooted under 'package/' so that one
    selection rule serves every format. Raises TooLarge above 20,000 members
    (and above 1 GiB of streamed tar content). Directory entries are lstat'ed
    and only regular files are yielded."""
    if fmt in ("zip-infected", "zip"):
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            if len(infos) > MAX_MEMBERS:
                raise TooLarge("members")
            for info in infos:
                if not info.is_dir():
                    yield info.filename, info.file_size, functools.partial(read_zip_member, z, info, pwd)
        return
    if fmt == "tgz":
        count, total = 0, 0
        with tarfile.open(path, mode="r|*") as t:
            while True:
                m = t.next()
                if m is None:
                    break
                t.members.clear()
                count += 1
                total += max(m.size, 0)
                if count > MAX_MEMBERS or total > MAX_TAR_TOTAL:
                    raise TooLarge("members")
                if m.isfile():
                    parts = m.name.split("/")
                    yield "package/" + "/".join(parts[1:]), m.size, functools.partial(read_tar_member, t, m)
        return
    if fmt == "dir":
        count = 0
        for d, dirs, files in os.walk(path):
            keep = []
            for x in sorted(dirs):
                try:
                    if stat.S_ISDIR(os.lstat(os.path.join(d, x)).st_mode):
                        keep.append(x)
                except OSError:
                    continue
            dirs[:] = keep
            count += len(keep)
            for f in sorted(files):
                count += 1
                if count > MAX_MEMBERS:
                    raise TooLarge("members")
                full = os.path.join(d, f)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                if not rel.startswith("package/"):
                    rel = "package/" + rel
                yield rel, st.st_size, functools.partial(read_regular, full, st.st_size)
            if count > MAX_MEMBERS:
                raise TooLarge("members")
        return
    raise ValueError("unknown format %r" % fmt)


def scan_sample(path, fmt, pwd, visit, only=None):
    """Reads one sample in memory, one file at a time, and calls
    visit(flattened name, bytes) for each .js/.cjs/.mjs file outside
    node_modules (nested paths below 'package/' joined with '__'), skipping
    files over 8 MiB, which are counted in oversize. Returns (manifest,
    oversize): the bytes of the root package.json or None. With only, just
    those flattened names are visited. Raises TooLarge when the selected JS
    files total more than 64 MiB."""
    taken, oversize, total = set(), 0, 0
    best_key, manifest = None, None
    for name, size, read in iter_members(path, fmt, pwd):
        if "node_modules/" in name or not safe_name(name):
            continue
        parts = name.split("/")
        rooted = "package" in parts[:-1]
        rel = parts[parts.index("package") + 1:] if rooted else parts[-1:]
        if name.endswith(JS_EXT):
            flat = unique_flat(rel, taken)
            if size > MAX_FILE:
                oversize += 1
                continue
            total += size
            if total > MAX_JS_TOTAL:
                raise TooLarge("js bytes")
            if only is None or flat in only:
                visit(flat, read())
        elif parts[-1] == "package.json":
            key = len(rel) if rooted else 99 + len(parts)
            if best_key is None or key < best_key:
                best_key = key
                eligible = (key == 1 or not rooted) and size <= MAX_MANIFEST
                manifest = read() if eligible else None
    return manifest, oversize


def index_sample(job):
    """Indexes one raw sample: reads it in memory file by file and returns a
    record with the kept files (flattened name, size, whitespace-insensitive
    hash, code shape hash) and the install-script, placeholder and filter
    counters, or {"error": ...} when the archive cannot be read (corrupt,
    missing, wrong password, AES-encrypted, too large). Errors caused by
    OSError or MemoryError carry "transient": True and are never cached."""
    path, fmt, pwd = job
    rec = {"oversize": 0, "binary": 0, "stub": 0, "files": []}
    state = {"marker": False}
    visit = functools.partial(index_file, rec, state)
    try:
        manifest, rec["oversize"] = scan_sample(path, fmt, pwd, visit)
    except TooLarge:
        return {"error": "too large"}
    except gzip.BadGzipFile as e:
        return {"error": "%s: %s" % (type(e).__name__, str(e)[:100])}
    except (OSError, MemoryError) as e:
        return {"error": "%s: %s" % (type(e).__name__, str(e)[:100]), "transient": True}
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, str(e)[:100])}
    marker = state["marker"] or (manifest is not None and HOLDING in manifest.lower())
    rec["files"].sort(key=lambda f: (f[1], f[0]))
    scripts = install_scripts(manifest) if manifest is not None else b""
    rec["scripts_len"] = len(scripts)
    rec["scripts_trivial"] = bool(scripts) and trivial_scripts(scripts)
    rec["keep_scripts"] = bool(scripts) and not rec["scripts_trivial"]
    rec["script_ws"] = "s" + ws_hash(scripts) if rec["keep_scripts"] else None
    rec["script_shape"] = "s" + hashlib.sha256(script_shape(scripts)).hexdigest() if rec["keep_scripts"] else None
    rec["marker"] = marker
    return rec


def index_file(rec, state, flat, data):
    """Classifies one JS file of a sample (binary, stub or kept) into rec and
    notes a 'security holding package' marker in state, then drops it."""
    if not data:
        return
    if len(data) < 4096 and HOLDING in data.lower():
        state["marker"] = True
    if is_binary(data):
        rec["binary"] += 1
    elif is_stub(data):
        rec["stub"] += 1
    else:
        rec["files"].append([flat, len(data), ws_hash(data), shape_digest(data)])


def index_existing(job):
    """Indexes one existing reference folder: returns the whitespace-
    insensitive hash of each file, the code shape, the v2 content key and
    the stored byte count. Only regular files are read."""
    path, _ = job
    hashes, shapes, keys, total = [], [], [], 0
    script = None
    for f in sorted(os.listdir(path)):
        full = os.path.join(path, f)
        try:
            if not stat.S_ISREG(os.lstat(full).st_mode):
                continue
            with open(full, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        total += len(data)
        if not data:
            continue
        if f == SCRIPTS_FILE:
            script = data
        elif f.endswith(JS_EXT):
            h = ws_hash(data)
            hashes.append(h)
            keys.append(h)
            shapes.append(shape_digest(data))
    keys.sort()
    shapes.sort()
    if script is not None:
        hashes.append("s" + ws_hash(script))
        keys.append("s" + ws_hash(script))
        shapes.append("s" + hashlib.sha256(script_shape(script)).hexdigest())
    return {"hashes": hashes, "bytes": total,
            "shape": hashlib.sha256("\n".join(shapes).encode()).hexdigest()[:12] if shapes else None,
            "content": hashlib.sha256("\n".join(keys).encode()).hexdigest() if keys else None}


def load_cache(path):
    """Loads the index cache, or an empty one when absent or outdated. The
    "volatile" part holds results of this run that are never saved."""
    try:
        with open(path) as f:
            c = json.load(f)
        if c.get("version") == CACHE_VERSION:
            return {"version": CACHE_VERSION, "samples": c.get("samples", {}), "existing": c.get("existing", {}),
                    "volatile": {}}
    except (OSError, ValueError):
        pass
    return {"version": CACHE_VERSION, "samples": {}, "existing": {}, "volatile": {}}


def save_cache(path, cache):
    """Writes the index cache atomically (without the volatile results)."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({k: cache[k] for k in ("version", "samples", "existing")}, f)
    os.replace(tmp, path)


def store_sample(cache, key, rec):
    """Stores a sample record: transient errors only for this run, the rest
    in the saved cache."""
    cache["volatile" if rec.get("transient") else "samples"][key] = rec


def sample_rec(cache, key):
    """Returns the record of a sample from the cache or the volatile part."""
    rec = cache["samples"].get(key)
    return rec if rec is not None else cache["volatile"][key]


def store_existing(cache, failures, key, rec):
    """Stores an existing-folder record, or notes the failure."""
    if "error" in rec:
        failures.append((key, rec["error"]))
    else:
        cache["existing"][key] = rec


def run_jobs(items, func, threads, sink, checkpoint):
    """Runs func over [(key, job)] in worker processes, in batches of 2,000
    with a fresh pool per batch, and passes each (key, record) to sink. The
    checkpoint function runs every 2,000 results, after each batch and on
    KeyboardInterrupt (which is then re-raised). When a worker dies
    (BrokenProcessPool) the pool is rebuilt and the jobs that were in flight
    are retried with only as many jobs in flight as there are workers; jobs
    that break a pool again get a transient error record "worker crashed"."""
    queue, attempt, done = list(items), 0, 0
    while queue:
        size = BATCH if attempt == 0 else max(threads, 1)
        retry = []
        for i in range(0, len(queue), size):
            batch = queue[i:i + size]
            ex = concurrent.futures.ProcessPoolExecutor(threads)
            interrupted = False
            try:
                futs = {ex.submit(func, job): (key, job) for key, job in batch}
                for fut in concurrent.futures.as_completed(futs):
                    key, job = futs[fut]
                    try:
                        rec = fut.result()
                    except concurrent.futures.process.BrokenProcessPool:
                        if attempt == 0:
                            retry.append((key, job))
                            continue
                        rec = {"error": "worker crashed", "transient": True}
                    except Exception as e:
                        rec = {"error": "%s: %s" % (type(e).__name__, str(e)[:100]), "transient": True}
                    sink(key, rec)
                    done += 1
                    if done % CHECKPOINT_EVERY == 0:
                        checkpoint()
            except KeyboardInterrupt:
                interrupted = True
                ex.shutdown(wait=False, cancel_futures=True)
                checkpoint()
                raise
            finally:
                if not interrupted:
                    ex.shutdown(wait=True)
            checkpoint()
        queue, attempt = retry, attempt + 1


def find_providers(raw, wanted):
    """Returns the provider names to use: the --providers list in its given
    order, or every directory of raw holding an index.json, alphabetical."""
    if wanted:
        return [p for p in wanted.split(",") if p]
    return sorted(d for d in os.listdir(raw) if os.path.isfile(os.path.join(raw, d, "index.json")))


def load_samples(raw, providers):
    """Reads each provider's index.json and returns one row per sample with
    the resolved archive path, provider priority, normalised published date
    and a cache key made of the provider, the archive name and the archive's
    actual size and mtime_ns."""
    rows = []
    for prio, prov in enumerate(providers):
        base = os.path.realpath(os.path.join(raw, prov))
        try:
            with open(os.path.join(base, "index.json")) as f:
                entries = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("name"), str):
                continue
            archive = str(e.get("archive", ""))
            full = os.path.realpath(os.path.join(base, archive))
            fmt = e.get("format", "zip-infected")
            pwd = e.get("password")
            pwd = pwd.encode() if isinstance(pwd, str) else (b"infected" if fmt == "zip-infected" else None)
            version = e.get("version")
            version = str(version) if version not in (None, "") else None
            try:
                st = os.stat(full)
                ident = "%d|%d" % (st.st_size, st.st_mtime_ns)
            except OSError:
                ident = "nostat"
            rows.append({"provider": prov, "prio": prio, "category": e.get("category"), "name": e["name"],
                         "version": version, "published": norm_published(e.get("published")), "format": fmt,
                         "path": full, "inside": full == base or full.startswith(base + os.sep),
                         "key": "%s|%s|%s" % (prov, archive, ident), "pwd": pwd})
    return rows


def index_all(rows, cache, threads, cache_path):
    """Fills the cache for every row not yet cached, using a process pool,
    and returns how many samples were indexed afresh. Transient errors stay
    in cache["volatile"]."""
    todo = {}
    for r in rows:
        if r["key"] not in cache["samples"]:
            todo.setdefault(r["key"], r)
    live = []
    for key, r in todo.items():
        if r["inside"]:
            live.append((key, (r["path"], r["format"], r["pwd"])))
        else:
            cache["samples"][key] = {"error": "archive path outside provider directory"}
    if live:
        run_jobs(live, index_sample, threads, functools.partial(store_sample, cache),
                 functools.partial(save_cache, cache_path, cache))
    return len(todo)


def index_existing_all(existing, cache, threads, cache_path):
    """Indexes every folder of the existing reference set (cached by folder
    name, file count and byte count) and returns {folder: record}. Exits when
    a folder cannot be indexed."""
    folders = sorted(d for d in os.listdir(existing)
                     if os.path.isdir(os.path.join(existing, d)) and not os.path.islink(os.path.join(existing, d)))
    todo, keys = [], {}
    for d in folders:
        total, n = 0, 0
        for e in os.scandir(os.path.join(existing, d)):
            n += 1
            total += e.stat(follow_symlinks=False).st_size
        keys[d] = "%s|%d|%d" % (d, n, total)
        if keys[d] not in cache["existing"]:
            todo.append(d)
    failures = []
    if todo:
        run_jobs([(keys[d], (os.path.join(existing, d), d)) for d in todo], index_existing, threads,
                 functools.partial(store_existing, cache, failures),
                 functools.partial(save_cache, cache_path, cache))
    if failures:
        raise SystemExit("cannot index %d existing folders, first: %s" % (len(failures), failures[0]))
    live = {keys[d] for d in folders}
    cache["existing"] = {k: v for k, v in cache["existing"].items() if k in live}
    return {d: cache["existing"][keys[d]] for d in folders}


def load_leaks(real_path, curve_path):
    """Returns (real_names, curve_names, exact) for the leak check.
    real_names: normalised package names of manifest_real items outside the
    mal_known and mal_scripts categories (those two are copies of references
    on purpose). curve_names: normalised names of every malware package in
    the curve test manifest. exact: (normalised name, version) of every
    manifest_real item, whatever its category. Exits, after printing both
    counts, when either name set is empty."""
    with open(real_path) as f:
        real = json.load(f)
    with open(curve_path) as f:
        curve = json.load(f)
    real_names = {norm_name(m["package"]) for m in real if m["category"] not in ("mal_known", "mal_scripts")}
    curve_names = {norm_name(m["package"]) for m in curve.get("malware", [])}
    exact = {(norm_name(m["package"]), m["version"]) for m in real}
    print("leak names: real manifest %d, curve manifest %d" % (len(real_names), len(curve_names)))
    if not real_names or not curve_names:
        raise SystemExit("empty leak name set (real %d, curve %d): wrong manifest?" % (len(real_names), len(curve_names)))
    return real_names, curve_names, exact


def quality_reason(row, rec, min_bytes):
    """Returns the reason a sample fails the quality filter, or None.
    Reasons in order: too_large (more than 20,000 members or 64 MiB of JS);
    unreadable (archive cannot be read, including AES or wrong password, or a
    worker crash); nothing_stored (no JS file left after dropping binary
    and stub files and no non-trivial install script); placeholder (a
    'security holding package' marker or a -security version, no install
    scripts and under 2 KiB of JS); stub_only (every JS file was a stub and
    there are no install scripts); too_small (stored bytes below min_bytes)."""
    if "error" in rec:
        return "too_large" if rec["error"] == "too large" else "unreadable"
    holding = rec["marker"] or str(row["version"]).endswith("-security")
    js_bytes = sum(f[1] for f in rec["files"])
    if not rec["files"] and not rec["keep_scripts"]:
        if holding:
            return "placeholder"
        return "stub_only" if rec["stub"] else "nothing_stored"
    if holding and not rec["keep_scripts"] and js_bytes < 2048:
        return "placeholder"
    if js_bytes + (rec["scripts_len"] if rec["keep_scripts"] else 0) < min_bytes:
        return "too_small"
    return None


def preference_order(rows):
    """Sorts rows by preference: newest published first, null dates last,
    then provider priority, then name and version for determinism."""
    rows.sort(key=lambda r: (norm_name(r["name"]), str(r["version"])))
    rows.sort(key=lambda r: r["prio"])
    rows.sort(key=lambda r: r["published"] or "", reverse=True)
    return rows


def shape_of(files, script_shape_key):
    """Computes the code shape of a set of files plus an optional install
    script shape key."""
    shapes = sorted(f[3] for f in files)
    if script_shape_key:
        shapes.append(script_shape_key)
    return hashlib.sha256("\n".join(shapes).encode()).hexdigest()[:12] if shapes else None


def select(rows, cache, existing_recs, leaks, args):
    """Applies the funnel to the indexed samples and returns (kept, stats).
    Quality filter, leak exclusion (leak_real_name, leak_curve_name,
    leak_exact), then deduplication in preference order against the existing
    references and the packages kept so far: dup_package_existing and
    dup_package_new (same package content key), dup_files (no file left
    after dropping files whose whitespace-insensitive hash is already known;
    over_js_cap when the only files left exceed --max-js-bytes), too_small
    after dedupe, shape_cap, name_cap, then the folder name checks
    (bad_folder_name when the name is unsafe, dup_folder when the folder
    already exists or was already kept; a missing version becomes
    0.0.0-unknown.<8 hex of the content key> before the check), then
    target_reached. JS files are stored smallest first until --max-js-bytes
    is reached."""
    real_names, curve_names, exact = leaks
    stats = collections.defaultdict(collections.Counter)
    seen_files, pkg_existing = set(), set()
    per_shape, per_name = collections.Counter(), collections.Counter()
    taken = set(existing_recs)
    for folder, rec in existing_recs.items():
        seen_files.update(rec["hashes"])
        if rec["content"]:
            pkg_existing.add(rec["content"])
        if rec["shape"]:
            per_shape[rec["shape"]] += 1
        per_name[norm_name(split_folder(folder)[0])] += 1
    pkg_new, kept = set(), []
    for row in preference_order(list(rows)):
        s = stats[row["provider"]]
        rec = sample_rec(cache, row["key"])
        s["indexed"] += 1
        if "error" not in rec:
            s["files_binary_dropped"] += rec["binary"]
            s["files_stub_dropped"] += rec["stub"]
            s["files_oversize_skipped"] += rec["oversize"]
        why = quality_reason(row, rec, args.min_bytes)
        if why:
            s[why] += 1
            continue
        s["quality_pass"] += 1
        nn = norm_name(row["name"])
        if nn in real_names:
            s["leak_real_name"] += 1
            continue
        if nn in curve_names:
            s["leak_curve_name"] += 1
            continue
        if (nn, row["version"]) in exact:
            s["leak_exact"] += 1
            continue
        s["leak_pass"] += 1
        files = rec["files"]
        keys = sorted(f[2] for f in files)
        if rec["keep_scripts"]:
            keys.append(rec["script_ws"])
        content = hashlib.sha256("\n".join(keys).encode()).hexdigest()
        if content in pkg_existing:
            s["dup_package_existing"] += 1
            continue
        if content in pkg_new:
            s["dup_package_new"] += 1
            continue
        local, chosen, size, capped = set(), [], 0, 0
        for f in files:
            if f[2] in seen_files or f[2] in local:
                s["files_dup"] += 1
            elif size + f[1] > args.max_js_bytes:
                capped += 1
            else:
                local.add(f[2])
                chosen.append(f)
                size += f[1]
        script = rec["keep_scripts"] and rec["script_ws"] not in seen_files
        if not chosen and not script:
            s["over_js_cap" if capped else "dup_files"] += 1
            continue
        stored = size + (rec["scripts_len"] if script else 0)
        if stored < args.min_bytes:
            s["too_small_after_dedupe"] += 1
            continue
        shape = shape_of(chosen, rec["script_shape"] if script else None)
        if args.shape_cap and per_shape[shape] >= args.shape_cap:
            s["shape_cap"] += 1
            continue
        if args.name_cap and per_name[nn] >= args.name_cap:
            s["name_cap"] += 1
            continue
        version = row["version"] or "%s.%s" % (UNKNOWN_VERSION, content[:8])
        folder = flat_folder(row["name"], version)
        if not valid_folder(folder):
            s["bad_folder_name"] += 1
            continue
        if folder in taken:
            s["dup_folder"] += 1
            continue
        if args.target and len(kept) >= args.target:
            s["target_reached"] += 1
            continue
        taken.add(folder)
        pkg_new.add(content)
        seen_files.update(local)
        if script:
            seen_files.add(rec["script_ws"])
        per_shape[shape] += 1
        per_name[nn] += 1
        s["kept"] += 1
        kept.append({"provider": row["provider"], "category": row["category"], "name": row["name"],
                     "version": row["version"], "published": row["published"], "folder": folder,
                     "files": len(chosen) + (1 if script else 0), "bytes": stored, "shape": shape,
                     "_row": row, "_names": [f[0] for f in chosen], "_script": script})
    return kept, stats


def is_within(path, root):
    """True when the real path of path equals or lies inside the real path
    of root."""
    p, r = os.path.realpath(path), os.path.realpath(root)
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


def check_deletable(path, protected, parents, label):
    """Exits unless the directory path may be cleaned: it must not be the
    filesystem root or the home directory, no protected path may equal it or
    lie inside it, it must not lie inside a parent directory, it must not be
    a symlink, and it must be new, empty or hold the marker file this script
    writes."""
    real = os.path.realpath(path)
    if real in ("/", os.path.realpath(os.path.expanduser("~"))):
        raise SystemExit("refusing %s: %s" % (label, path))
    for p in protected:
        if is_within(p, path):
            raise SystemExit("refusing %s %s: it equals or contains protected path %s" % (label, path, p))
    for p in parents:
        if is_within(path, p):
            raise SystemExit("refusing %s %s: it lies inside %s" % (label, path, p))
    if os.path.lexists(path):
        if os.path.islink(path) or not os.path.isdir(path):
            raise SystemExit("refusing %s %s: not a plain directory" % (label, path))
        names = os.listdir(path)
        if names and MARKER not in names:
            raise SystemExit("refusing %s %s: not empty and has no %s marker (create the file to allow it)"
                             % (label, path, MARKER))


def remove_tree(path):
    """Deletes a file, symlink or directory tree made of read-only files
    without following symlinks."""
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
        return
    for d, dirs, _ in os.walk(path):
        os.chmod(d, 0o755)
    shutil.rmtree(path)


def prepare_dir(path):
    """Creates the directory when needed and makes sure it holds the marker."""
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, MARKER), "a") as f:
        f.write("written by build_refs.py\n")


def clean_dir(path):
    """Removes every entry of a directory that check_deletable accepted."""
    if os.path.isdir(path):
        for name in os.listdir(path):
            if name != MARKER:
                remove_tree(os.path.join(path, name))


def write_one(item):
    """Writes one kept package to <out>/<folder>.tmp as read-only (0444)
    plain-text files and renames it into place. Returns the bytes written.
    Raises when the target is not directly inside the real out directory."""
    out, k = item
    row = k["_row"]
    final = os.path.join(out, k["folder"])
    tmp = final + ".tmp"
    real_out = os.path.realpath(out)
    if os.path.realpath(os.path.dirname(final)) != real_out or os.path.realpath(os.path.dirname(tmp)) != real_out:
        raise RuntimeError("target outside out: " + final)
    js, manifest = {}, None
    manifest, _ = scan_sample(row["path"], row["format"], row["pwd"], js.__setitem__, only=set(k["_names"]))
    files = {n: js[n] for n in k["_names"]}
    if k["_script"]:
        files[SCRIPTS_FILE] = install_scripts(manifest)
    try:
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        total = 0
        for name, data in files.items():
            if name == "package.json" or not data or os.path.basename(name) != name:
                continue
            fd = os.open(os.path.join(tmp, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            total += len(data)
        os.rename(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return total


def write_all(out, kept, stats, threads):
    """Writes every kept package with a thread pool. A package that fails is
    counted as write_failed (and no longer as kept), reported on stderr and
    removed from kept. Returns the bytes written."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(threads) as ex:
        futs = {ex.submit(write_one, (out, k)): k for k in kept}
        for fut in concurrent.futures.as_completed(futs):
            k = futs[fut]
            try:
                results[id(k)] = fut.result()
            except Exception as e:
                s = stats[k["provider"]]
                s["write_failed"] += 1
                s["kept"] -= 1
                print("write failed %s: %s: %s" % (k["folder"], type(e).__name__, str(e)[:100]), file=sys.stderr)
    kept[:] = [k for k in kept if id(k) in results]
    return sum(results.values())


def link_folder(src, dst):
    """Hard-links the files of src into dst atomically (dst.tmp then
    rename), copying when linking fails."""
    tmp = dst + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    for f in os.listdir(src):
        a = os.path.join(src, f)
        if not stat.S_ISREG(os.lstat(a).st_mode):
            continue
        try:
            os.link(a, os.path.join(tmp, f))
        except OSError:
            shutil.copyfile(a, os.path.join(tmp, f))
            os.chmod(os.path.join(tmp, f), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    os.rename(tmp, dst)


def build_merged(existing, out, merged):
    """Makes merged a hard-linked union of existing and out. Folders coming
    from existing are linked when missing; folders coming from out are
    removed and relinked on every run so no stale inode stays. Stale entries
    are deleted only when they are directories with '@' in their name and
    belong to neither source. Returns the number of folders."""
    wanted = {}
    for base, from_out in ((existing, False), (out, True)):
        for d in os.listdir(base):
            full = os.path.join(base, d)
            if d == MARKER or d.endswith(".tmp") or os.path.islink(full) or not os.path.isdir(full):
                continue
            wanted.setdefault(d, (full, from_out))
    have = set(os.listdir(merged))
    for d in sorted(have - set(wanted)):
        p = os.path.join(merged, d)
        if d != MARKER and "@" in d and os.path.isdir(p) and not os.path.islink(p):
            remove_tree(p)
    for d, (src, from_out) in sorted(wanted.items()):
        dst = os.path.join(merged, d)
        if d in have:
            if not from_out:
                continue
            remove_tree(dst)
        link_folder(src, dst)
    return len(wanted)


def print_funnel(stats, providers):
    """Prints the per-provider funnel and the drop reasons as a compact table."""
    cols = ["indexed", "too_large", "unreadable", "nothing_stored", "placeholder", "stub_only", "too_small",
            "quality_pass", "leak_real_name", "leak_curve_name", "leak_exact", "leak_pass",
            "dup_package_existing", "dup_package_new", "dup_files", "over_js_cap", "too_small_after_dedupe",
            "shape_cap", "name_cap", "bad_folder_name", "dup_folder", "target_reached", "write_failed", "kept"]
    tot = collections.Counter()
    for p in providers:
        tot.update(stats[p])
    print("stage".ljust(24) + "".join(" %s" % p for p in providers) + " total")
    for c in cols:
        print(c.ljust(24) + "".join(" %*d" % (len(p), stats[p][c]) for p in providers)
              + " %d" % tot[c])


def main():
    """Builds the v9 malware references: indexes raw provider archives in
    memory, filters and deduplicates them against the existing references,
    writes the kept packages, merges and writes the manifest."""
    ap = argparse.ArgumentParser()
    home = os.path.expanduser("~/packguard-data/")
    ap.add_argument("--raw", default=home + "v9/raw")
    ap.add_argument("--existing", default=home + "combined/malware_js")
    ap.add_argument("--out", default=home + "v9/malware_new")
    ap.add_argument("--merged", default=home + "v9/malware_js")
    ap.add_argument("--manifest", default=home + "v9/malware_manifest.json")
    ap.add_argument("--real-manifest", default=os.path.expanduser("~/pg-test-sets/manifests/manifest_real.json"))
    ap.add_argument("--curve-manifest", default=os.path.expanduser("~/pg-curve/test/manifest.json"))
    ap.add_argument("--cache", default=home + "v9/index_cache.json")
    ap.add_argument("--providers", default="")
    ap.add_argument("--shape-cap", type=int, default=1)
    ap.add_argument("--name-cap", type=int, default=3)
    ap.add_argument("--max-js-bytes", type=int, default=1 << 20)
    ap.add_argument("--min-bytes", type=int, default=256)
    ap.add_argument("--target", type=int, default=0)
    ap.add_argument("--threads", type=int, default=3)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    for k in ("raw", "existing", "out", "merged", "manifest", "real_manifest", "curve_manifest", "cache"):
        setattr(args, k, os.path.abspath(os.path.expanduser(getattr(args, k))))
    if len({os.path.realpath(p) for p in (args.existing, args.out, args.merged)}) < 3:
        raise SystemExit("--existing, --out and --merged must differ")

    protected = [args.existing, args.raw, args.cache, args.manifest, args.real_manifest, args.curve_manifest]
    parents = [args.existing, args.raw]
    check_deletable(args.out, protected + [args.merged], parents, "--out")
    check_deletable(args.merged, protected + [args.out], parents, "--merged")

    leaks = load_leaks(args.real_manifest, args.curve_manifest)
    providers = find_providers(args.raw, args.providers)
    rows = load_samples(args.raw, providers)
    os.makedirs(os.path.dirname(args.cache), exist_ok=True)
    cache = load_cache(args.cache)
    fresh = index_all(rows, cache, args.threads, args.cache)
    existing_recs = index_existing_all(args.existing, cache, args.threads, args.cache)
    save_cache(args.cache, cache)
    kept, stats = select(rows, cache, existing_recs, leaks, args)

    written = 0
    if not args.dry_run:
        check_deletable(args.out, protected + [args.merged], parents, "--out")
        check_deletable(args.merged, protected + [args.out], parents, "--merged")
        prepare_dir(args.out)
        clean_dir(args.out)
        prepare_dir(args.merged)
        written = write_all(args.out, kept, stats, args.threads)
        merged_n = build_merged(args.existing, args.out, args.merged)
    else:
        merged_n = len(set(existing_recs) | {k["folder"] for k in kept})

    existing_names = {norm_name(split_folder(d)[0]) for d in existing_recs}
    new_names = {norm_name(k["name"]) for k in kept}
    manifest = {
        "parameters": {k: getattr(args, k) for k in ("raw", "existing", "out", "merged", "shape_cap", "name_cap",
                                                    "max_js_bytes", "min_bytes", "target", "threads", "dry_run")}
        | {"providers": providers},
        "funnel": {p: dict(stats[p]) for p in providers},
        "totals": {"samples_indexed_fresh": fresh, "existing_folders": len(existing_recs),
                   "existing_distinct_names": len(existing_names), "new_folders": len(kept),
                   "new_distinct_names": len(new_names), "new_bytes": sum(k["bytes"] for k in kept),
                   "bytes_written": written, "merged_folders": merged_n,
                   "merged_distinct_names": len(existing_names | new_names),
                   "real_leak_names": len(leaks[0]), "curve_leak_names": len(leaks[1])},
        "kept": [{k: v for k, v in item.items() if not k.startswith("_")} for item in kept],
    }
    os.makedirs(os.path.dirname(args.manifest), exist_ok=True)
    with open(args.manifest, "w") as f:
        json.dump(manifest, f, indent=1)
    if providers:
        print_funnel(stats, providers)
    print("existing %d new %d merged %d (dry-run=%s)" % (len(existing_recs), len(kept), merged_n, args.dry_run))


if __name__ == "__main__":
    main()
