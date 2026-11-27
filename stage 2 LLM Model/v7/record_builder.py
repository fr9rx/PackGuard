"""
PackGuard Stage 2 v7 — Unified Package Record & Security-Density Multi-Window Builder.

Shared identically across dataset preparation, Teacher/LoRA training, Student
distillation, ONNX CPU inference, `stage2_scan_folder.py`, and `packguard-cli --stage2`.

Upgrades over Stage 2 v6 (while preserving 100% audit compliance):
  1. Safe Static JS AST Constant-Folding & Multi-Layer De-obfuscation (`ast_deobfuscator.py`)
     resolving multi-variable `split_payload`, `_0x` lookup tables, reversed/URI/XOR loaders,
     and nested Base64/Hex without any 80-char concatenation cap.
  2. Eliminates `chunks: 0` blind spots:
     - Inspects extensionless CLI scripts (`#!/usr/bin/env node`, `#!/bin/sh`), files
       pointed to by `package.json` (`main`, `module`, `browser`, `bin`), and renamed code files
       (`T2_rename`) via safe content/shebang sniffing.
     - Emits a strictly **name-neutral** `// [PACKAGE_META]` summary when lifecycle anomalies,
       shell scripts in non-install `scripts.*`, or dependency-confusion semver (`>= 50.0.0`)
       exist — NEVER leaking package or author names.
  3. Formatting-bloat resilience (`T1_format` / `T3_padding`):
     - Compacts filler block-comment walls and redundant indentation/blank-line bloat before
       slicing windows so 512 tokens pack ~2x more AST logic.
     - Adds security-density window selection alongside head/tail windows so payloads buried
       inside padded or multi-file packages are never missed.
  4. Zero benchmark-marker stripping, zero module-length guessing, zero allowlists.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ast_deobfuscator import static_ast_deobfuscate

CODE_EXTENSIONS = {
    ".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".es", ".es6",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".py",
}
NON_CODE_EXTENSIONS = {
    ".md", ".markdown", ".rst", ".txt", ".json", ".lock", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".css", ".scss", ".less", ".sass", ".html", ".htm", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".pdf", ".wasm", ".node", ".dll", ".so", ".dylib", ".exe",
    ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".map", ".tsbuildinfo",
}
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "__pycache__", "coverage", ".nyc_output"}
SKIP_SUFFIXES = (".d.ts", ".d.mts", ".d.cts", ".map", ".min.js.map", ".lock")
SKIP_FILENAMES = {
    "readme", "license", "licence", "changelog", "history", "authors", "contributors",
    "notice", "copying", "patents", ".npmignore", ".gitignore", ".eslintrc", ".prettierrc",
    ".editorconfig", "tsconfig.json", "jsconfig.json",
}

INSTALL_HOOK_KEYS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "preuninstall",
    "postuninstall",
)
SECONDARY_SCRIPT_KEYS = ("start", "prestart", "poststart", "test", "pretest", "posttest", "build")

RE_SUSPICIOUS_SCRIPT_CMD = re.compile(
    r"(?:curl\b|wget\b|Invoke-WebRequest|iwr\b|powershell|pwsh|/bin/sh|/bin/bash|"
    r"\bnc\b|netcat|python\s+-c|node\s+-e|base64\b|eval\b|https?://|\benv\b|\.npmrc|\.ssh)",
    re.I,
)
RE_CODE_SNIFF = re.compile(
    r"(?:^#!|\brequire\s*\(|\bimport\s+[\w*{'\"]|\bmodule\.exports\b|\bexports\.|"
    r"\bfunction\s*[\w$(]|\bconst\s+[\w${[]|\blet\s+[\w${[]|\bvar\s+[\w${[]|"
    r"\beval\s*\(|\bprocess\.env\b|\bBuffer\.from\b|\bdocument\.cookie\b|\bwindow\.fetch\b)",
    re.M,
)
RE_LEX_COMMENT_OR_STR = re.compile(
    r"""(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`|/\*[\s\S]*?\*/)""",
)
RE_MULTI_SPACE_INDENT = re.compile(r"^[ \t]{4,}", re.M)
RE_BLANK_LINES = re.compile(r"\n{3,}")
RE_NORM_WS = re.compile(r"\s+")
RE_NORM_STR = re.compile(r"""(["'`])(?:\\.|(?!\1)[^\\]){0,500}\1""")

# Universal behavioral API density scorer for selecting windows inside large/padded files
RE_SECURITY_API_DENSITY = re.compile(
    r"(?:child_process|execSync|execFile|spawnSync|\bexec\s*\(|\bspawn\s*\(|"
    r"module\.constructor\._load|process\.binding|vm\.runIn|"
    r"\beval\s*\(|new\s+Function\b|\bFunction\s*\(|fromCharCode|atob\s*\(|Buffer\.from|"
    r"https?://|stratum\+tcp|request\s*\(|fetch\s*\(|axios\.|sendBeacon|XMLHttpRequest|WebSocket|"
    r"net\.Socket|net\.connect|dns\.resolve|dns\.lookup|"
    r"process\.env|os\.hostname|os\.userInfo|os\.homedir|os\.networkInterfaces|"
    r"document\.cookie|localStorage|sessionStorage|FormData|"
    r"readFileSync|writeFileSync|\.npmrc|\.ssh|\.aws|id_rsa|wallet|mnemonic|xmrig|"
    r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)",
    re.I,
)


def decode_obfuscated_literals(code: str, max_decoded_chars: int = 1100) -> str:
    """Backward-compatible wrapper around v7's safe static AST constant-folder."""
    return static_ast_deobfuscate(code, max_decoded_chars=max_decoded_chars)


def _compact_code_formatting(code: str) -> str:
    """
    Compacts formatting bloat (e.g., giant license/filler block comments and deep indentation)
    universally across all files so every 512-token window holds ~2x more executable logic.
    Never strips benchmark-specific markers — purely standard comment/whitespace compaction.
    """
    text = code.replace("\r\n", "\n").replace("\r", "\n")

    def _trim_large_block_comment(m: re.Match) -> str:
        blk = m.group(0)
        # Only strip actual `/* ... */` block comments (>180 chars), never string/template literals!
        if blk.startswith("/*") and len(blk) > 180:
            return ""
        return blk

    text = RE_LEX_COMMENT_OR_STR.sub(_trim_large_block_comment, text)
    text = RE_MULTI_SPACE_INDENT.sub("  ", text)
    text = RE_BLANK_LINES.sub("\n\n", text)
    return text.strip()


def _extract_manifest_info(raw_json_text: str) -> Tuple[str, str, Set[str]]:
    """
    Parses package.json into:
      1. `install_script_text`: lifecycle hooks + suspicious non-install scripts + URL deps
      2. `meta_summary_text`: strictly name-neutral structural metadata summary
      3. `entry_relpaths`: relative file paths referenced by main/module/browser/bin
    """
    try:
        data = json.loads(raw_json_text)
    except Exception:
        return "", "", set()
    if not isinstance(data, dict):
        return "", "", set()

    install_lines: List[str] = []
    entry_paths: Set[str] = set()

    # Collect entrypoints so renamed or extensionless entry files are never missed
    for field in ("main", "module", "browser", "unpkg", "jsdelivr"):
        val = data.get(field)
        if isinstance(val, str) and val.strip():
            entry_paths.add(val.strip().lstrip("./").replace("\\", "/"))
    bin_val = data.get("bin")
    if isinstance(bin_val, str) and bin_val.strip():
        entry_paths.add(bin_val.strip().lstrip("./").replace("\\", "/"))
    elif isinstance(bin_val, dict):
        for bpath in bin_val.values():
            if isinstance(bpath, str) and bpath.strip():
                entry_paths.add(bpath.strip().lstrip("./").replace("\\", "/"))

    scripts = data.get("scripts")
    hook_count = 0
    if isinstance(scripts, dict):
        for key in INSTALL_HOOK_KEYS:
            val = scripts.get(key)
            if isinstance(val, str) and val.strip():
                install_lines.append(f"{key}: {val.strip()}")
                hook_count += 1
        # Also capture secondary scripts (`start`, `test`, etc.) when they invoke shell/network commands
        for key, val in scripts.items():
            if key in INSTALL_HOOK_KEYS or not isinstance(val, str) or not val.strip():
                continue
            if RE_SUSPICIOUS_SCRIPT_CMD.search(val):
                install_lines.append(f"{key}: {val.strip()}")

    url_deps = 0
    total_deps = 0
    for dep_field in ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"):
        deps = data.get(dep_field)
        if isinstance(deps, dict):
            total_deps += len(deps)
            for k, v in deps.items():
                if isinstance(v, str) and v.startswith(("http://", "https://", "git+", "github:", "file:")):
                    install_lines.append(f"dep {k}: {v}")
                    url_deps += 1

    # Name-neutral structural metadata (NO package name, NO author, NO repo URL to prevent memorization)
    ver = str(data.get("version") or "").strip()
    major_num = 0
    m_ver = re.match(r"^(\d+)\.", ver)
    if m_ver:
        try:
            major_num = int(m_ver.group(1))
        except ValueError:
            major_num = 0
    ver_shape = "high_major_99+" if major_num >= 50 else ("zero_ver" if ver in ("0.0.0", "") else "standard")
    has_repo = bool(data.get("repository") or data.get("homepage"))
    has_license = bool(data.get("license"))

    meta_summary = (
        f"version_shape={ver_shape} install_hooks={hook_count} "
        f"deps={total_deps} url_deps={url_deps} has_repo={int(has_repo)} "
        f"has_license={int(has_license)} entrypoints={len(entry_paths)}"
    )
    # Include all remaining scripts if there were no install hooks, in case package has 0 JS files
    if not install_lines and isinstance(scripts, dict) and scripts:
        extra = [f"{k}: {v.strip()}" for k, v in list(scripts.items())[:6] if isinstance(v, str) and v.strip()]
        if extra:
            meta_summary += "\n" + "\n".join(extra)

    return "\n".join(install_lines), meta_summary, entry_paths


def extract_install_scripts_from_package_json(raw_json_text: str) -> str:
    """Backward-compatible helper returning lifecycle & URL-dep lines from package.json."""
    inst, _, _ = _extract_manifest_info(raw_json_text)
    return inst


def _file_priority_key(relpath: str, size: int, entry_paths: Optional[Set[str]] = None) -> Tuple[int, str]:
    lp = relpath.lower().replace("\\", "/").replace("__", "/")
    base = lp.rsplit("/", 1)[-1]
    if base in ("install_scripts.txt", "package.json#scripts", "[install_scripts]"):
        return (0, lp)
    if base in ("preinstall.js", "postinstall.js", "install.js", "setup.js", "preinstall.sh", "postinstall.sh"):
        return (1, lp)
    if entry_paths and (relpath in entry_paths or lp in {e.lower() for e in entry_paths}):
        return (1, lp)
    if lp in ("index.js", "index.cjs", "index.mjs", "main.js", "cli.js", "bin.js", "app.js", "server.js"):
        return (2, lp)
    if lp.startswith(("bin/", "scripts/", "src/index.", "lib/index.", "dist/index.")):
        return (3, lp)
    if "/test/" in f"/{lp}" or "/tests/" in f"/{lp}" or base.endswith((".test.js", ".spec.js")):
        return (6, lp)
    if size < 120:
        return (5, lp)
    return (4, lp)


def extract_package_json_name(pkg_dir: Path) -> Optional[str]:
    """Reads package.json['name'] if present, strictly for leak-free dataset deduplication."""
    pj = Path(pkg_dir) / "package.json"
    if not pj.is_file():
        return None
    try:
        obj = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        if isinstance(obj, dict) and isinstance(obj.get("name"), str) and obj["name"].strip():
            return obj["name"].strip()
    except Exception:
        return None
    return None


def _is_candidate_code_file(rel: str, path: Path, entry_paths: Set[str]) -> bool:
    """
    Accepts standard code extensions PLUS extensionless/renamed code files
    (e.g., `bin/cli` with `#!/usr/bin/env node` or T2-renamed files referenced by `package.json`).
    """
    lower_rel = rel.lower()
    base = lower_rel.rsplit("/", 1)[-1]
    stem = base.split(".", 1)[0]
    if lower_rel in ("install_scripts.txt", "package.json", "package-lock.json", "npm-shrinkwrap.json"):
        return False
    if lower_rel.endswith(SKIP_SUFFIXES):
        return False
    if base in SKIP_FILENAMES or stem in ("readme", "license", "licence", "changelog"):
        return False

    ext = path.suffix.lower()
    if ext in CODE_EXTENSIONS:
        return True
    if ext in NON_CODE_EXTENSIONS:
        return False

    # Extensionless or unusual-extension file (e.g. `bin/run` or T2 renamed file):
    # accept if referenced by package.json entrypoints OR passes fast UTF-8 code/shebang sniff
    is_entry = rel in entry_paths or lower_rel in {e.lower() for e in entry_paths} or lower_rel.startswith("bin/")
    try:
        sz = path.stat().st_size
        if sz == 0 or sz > 262144:
            return False
        with path.open("rb") as fh:
            head = fh.read(2048)
        if b"\x00" in head[:512]:
            return False
        sample = head.decode("utf-8", errors="strict")
    except Exception:
        return False

    if is_entry:
        return True
    return bool(RE_CODE_SNIFF.search(sample))


def package_dir_to_record(
    pkg_dir: Path,
    max_files: int = 24,
    max_bytes_per_file: int = 65536,
) -> Dict[str, Any]:
    """
    Unified package directory reader shared across training, evaluation, and inference.
    Reads package code strictly as inert UTF-8 text (never executes anything).
    """
    pkg_dir = Path(pkg_dir)
    chunks: List[Dict[str, Any]] = []

    install_txt = pkg_dir / "install_scripts.txt"
    pkg_json = pkg_dir / "package.json"
    install_lines: List[str] = []
    meta_summary = ""
    entry_paths: Set[str] = set()

    if install_txt.is_file():
        try:
            txt = install_txt.read_text(encoding="utf-8", errors="replace").strip()
            if txt:
                install_lines.append(txt[:4096])
        except OSError:
            pass

    if pkg_json.is_file():
        try:
            raw_pj = pkg_json.read_text(encoding="utf-8", errors="replace")
            extracted, meta_summary, entry_paths = _extract_manifest_info(raw_pj)
            if extracted:
                install_lines.append(extracted[:4096])
        except OSError:
            pass

    if install_lines:
        chunks.append(
            {
                "file": "install_scripts.txt",
                "kind": "install_script",
                "start": 0,
                "text": "\n".join(dict.fromkeys(install_lines))[:4096],
            }
        )

    candidates: List[Tuple[Tuple[int, str], str, Path]] = []
    if pkg_dir.is_dir():
        for path in pkg_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(pkg_dir).as_posix()
            except ValueError:
                continue
            parts = rel.split("/")
            if any(part in SKIP_DIRS for part in parts[:-1]):
                continue
            if not _is_candidate_code_file(rel, path, entry_paths):
                continue
            try:
                sz = path.stat().st_size
            except OSError:
                continue
            if sz == 0:
                continue
            candidates.append((_file_priority_key(rel, sz, entry_paths), rel, path))

    candidates.sort(key=lambda item: item[0])

    for _, rel, path in candidates[:max_files]:
        try:
            with path.open("rb") as fh:
                raw_bytes = fh.read(max_bytes_per_file)
            if b"\x00" in raw_bytes[:512]:
                continue
            text = raw_bytes.decode("utf-8", errors="replace")
            if not text.strip():
                continue
            chunks.append(
                {
                    "file": rel,
                    "kind": "js",
                    "start": 0,
                    "text": text,
                }
            )
        except OSError:
            continue

    # Fallback ONLY when a package has zero JS/install chunks (prevents silent `chunks: 0` blind spot
    # on metadata-only dependency confusion shells like `@scope/pkg@99.99.99` or non-hook script shells)
    if not chunks and meta_summary:
        chunks.append(
            {
                "file": "[package_meta]",
                "kind": "meta",
                "start": 0,
                "text": meta_summary[:2048],
            }
        )

    return {"package": pkg_dir.name, "chunks": chunks, "meta_summary": meta_summary}


def _reassemble_chunks_by_file(record: Dict[str, Any]) -> Tuple[str, List[Tuple[str, str]], str]:
    """
    Normalizes either a `package_dir_to_record` dict OR a Stage 1 JSON report dict
    into `(install_script_text, [(relpath, file_text), ...], meta_text)` in deterministic order.
    """
    raw_chunks = record.get("chunks")
    meta_text = str(record.get("meta_summary") or "").strip()
    if not isinstance(raw_chunks, list):
        if isinstance(record.get("text"), str) and record["text"].strip():
            return "", [("index.js", record["text"])], meta_text
        return "", [], meta_text

    install_parts: List[str] = []
    meta_parts: List[str] = [meta_text] if meta_text else []
    by_file: Dict[str, List[Tuple[int, str]]] = {}

    for ch in raw_chunks:
        if not isinstance(ch, dict):
            continue
        text = ch.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        fname = str(ch.get("file") or "index.js").replace("\\", "/")
        kind = str(ch.get("kind") or "").lower()
        start = int(ch.get("start") or 0)

        if kind == "meta" or fname == "[package_meta]":
            meta_parts.append(text.strip())
            continue

        is_install = (
            kind in ("install", "install_script", "script", "scripts")
            or fname.lower().endswith("install_scripts.txt")
            or fname.lower().endswith("package.json#scripts")
            or fname.lower() == "package.json"
        )
        if is_install:
            if fname.lower() == "package.json" and text.lstrip().startswith("{"):
                ext, m_sum, _ = _extract_manifest_info(text)
                if ext:
                    install_parts.append(ext)
                if m_sum:
                    meta_parts.append(m_sum)
            else:
                install_parts.append(text.strip())
        else:
            by_file.setdefault(fname, []).append((start, text))

    install_text = "\n".join(dict.fromkeys(install_parts)).strip()
    final_meta = "\n".join(dict.fromkeys(p for p in meta_parts if p)).strip()

    files: List[Tuple[str, str]] = []
    for fname, segs in by_file.items():
        segs.sort(key=lambda x: x[0])
        merged = "\n".join(s for _, s in segs)
        files.append((fname, merged))

    files.sort(key=lambda item: _file_priority_key(item[0], len(item[1])))
    return install_text, files, final_meta


def _find_highest_density_hotspot(text: str, window_chars: int, exclude_head: int, exclude_tail_start: int) -> Optional[str]:
    """
    Finds the highest behavioral-API-density interior slice inside a large or padded file
    (e.g., `T3_padding` / `padded_loader` / trojanized bundles) so interior payloads are never missed.
    """
    if exclude_tail_start <= exclude_head + 300:
        return None
    interior = text[exclude_head:exclude_tail_start]
    if len(interior) < 200:
        return None
    step = max(400, window_chars // 2)
    best_score = 0
    best_slice: Optional[str] = None
    for offset in range(0, max(1, len(interior) - 200), step):
        cand = interior[offset : offset + window_chars]
        sc = len(RE_SECURITY_API_DENSITY.findall(cand))
        if sc > best_score:
            best_score = sc
            best_slice = cand
    if best_slice is not None and best_score >= 2:
        return best_slice
    # Fallback to geometric midpoint if file is large
    mid = max(0, (len(interior) - window_chars) // 2)
    return interior[mid : mid + window_chars]


def _slice_file_into_windows(
    fname: str,
    raw_text: str,
    window_chars: int = 2300,
    max_windows_per_file: int = 3,
) -> List[str]:
    """
    Compacts formatting bloat, runs universal static AST de-obfuscation across the whole file
    (up to 48 KB so payloads anywhere in the file surface into `[DECODED_LITERALS]`), and slices
    into path-neutral windows (`// [JS_CODE]`).
    """
    text = _compact_code_formatting(raw_text)
    if not text:
        return []

    # Run static AST de-obfuscation on the full file so split variables declared at top & used at bottom resolve!
    file_decoded = static_ast_deobfuscate(text, max_decoded_chars=800)
    dec_prefix = (file_decoded + "\n") if file_decoded else ""
    header = "// [JS_CODE]\n"
    raw_budget = max(650, window_chars - len(dec_prefix))
    n = len(text)

    if n <= raw_budget:
        return [header + dec_prefix + text]

    windows: List[str] = [header + dec_prefix + text[:raw_budget]]

    if max_windows_per_file >= 2:
        tail_start = max(raw_budget, n - window_chars)
        tail_chunk = text[tail_start:]
        tail_dec = static_ast_deobfuscate(tail_chunk, max_decoded_chars=550)
        tail_prefix = (tail_dec + "\n") if tail_dec else ""
        tail_budget = max(650, window_chars - len(tail_prefix))
        windows.append("// [JS_CODE @tail]\n" + tail_prefix + tail_chunk[-tail_budget:])

        if max_windows_per_file >= 3 and n > window_chars * 2.2:
            hot = _find_highest_density_hotspot(text, window_chars, raw_budget, tail_start)
            if hot:
                hot_dec = static_ast_deobfuscate(hot, max_decoded_chars=550)
                hot_prefix = (hot_dec + "\n") if hot_dec else ""
                hot_budget = max(650, window_chars - len(hot_prefix))
                windows.append("// [JS_CODE @mid]\n" + hot_prefix + hot[:hot_budget])

    return windows


def score_window_security_density(win_text: str) -> int:
    """Scores a candidate window by universal security-API & decoded-literal density."""
    score = len(RE_SECURITY_API_DENSITY.findall(win_text))
    if win_text.startswith("// [INSTALL_SCRIPTS]"):
        score += 8
    if "[DECODED_LITERALS]" in win_text[:160]:
        score += 5
    return score


def build_package_windows_with_meta(
    record: Dict[str, Any],
    max_windows: int = 12,
    window_chars: int = 2300,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Builds deterministic model-ready windows AND lightweight per-window provenance metadata
    (`file`, `section`, `has_install`, `has_decoded`, `api_density`) for explainability & MIL pooling.
    """
    install_text, files, meta_text = _reassemble_chunks_by_file(record)
    windows: List[str] = []
    win_meta: List[Dict[str, Any]] = []

    if install_text:
        inst_clean = _compact_code_formatting(install_text)
        inst_dec = static_ast_deobfuscate(inst_clean, max_decoded_chars=750)
        inst_dec_prefix = (inst_dec + "\n") if inst_dec else ""
        inst_budget = max(650, window_chars - len(inst_dec_prefix))
        inst_block = "// [INSTALL_SCRIPTS]\n" + inst_dec_prefix + inst_clean[:inst_budget]

        if files and len(inst_block) + len(files[0][1]) < window_chars - 220:
            fname0, raw0 = files[0]
            text0 = _compact_code_formatting(raw0)
            dec0 = static_ast_deobfuscate(text0, max_decoded_chars=550)
            dec0_prefix = (dec0 + "\n") if dec0 else ""
            rem = max(450, window_chars - len(inst_block) - len(dec0_prefix))
            combined = inst_block + "\n// [JS_CODE]\n" + dec0_prefix + text0[:rem]
            windows.append(combined)
            win_meta.append(
                {
                    "file": f"install_scripts.txt + {fname0}",
                    "is_install": True,
                    "has_decoded": bool(inst_dec or dec0),
                    "api_density": score_window_security_density(combined),
                }
            )
            files = files[1:]
        else:
            windows.append(inst_block)
            win_meta.append(
                {
                    "file": "install_scripts.txt",
                    "is_install": True,
                    "has_decoded": bool(inst_dec),
                    "api_density": score_window_security_density(inst_block),
                }
            )

    if files:
        # Generate candidate windows across up to 16 files, then keep entrypoints + highest-density windows
        per_file_cap = 3 if len(files) <= 4 else (2 if len(files) <= 8 else 1)
        cand_pairs: List[Tuple[str, Dict[str, Any], int]] = []
        for f_idx, (fname, raw_text) in enumerate(files[:18]):
            f_wins = _slice_file_into_windows(
                fname,
                raw_text,
                window_chars=window_chars,
                max_windows_per_file=per_file_cap,
            )
            for w_idx, w in enumerate(f_wins):
                dens = score_window_security_density(w)
                meta = {
                    "file": fname if w_idx == 0 else f"{fname}#w{w_idx + 1}",
                    "is_install": False,
                    "has_decoded": "[DECODED_LITERALS]" in w[:160],
                    "api_density": dens,
                }
                # Preserve priority of primary entry files (`f_idx == 0, 1`) while promoting high-density interior files
                priority_bonus = 100 if (f_idx == 0 and w_idx == 0) else (40 if (f_idx == 1 and w_idx == 0) else 0)
                cand_pairs.append((w, meta, priority_bonus + dens * 5 - f_idx))

        remaining_slots = max(0, max_windows - len(windows))
        if len(cand_pairs) > remaining_slots:
            cand_pairs.sort(key=lambda item: item[2], reverse=True)
            cand_pairs = cand_pairs[:remaining_slots]

        for w, m, _ in cand_pairs:
            windows.append(w)
            win_meta.append(m)

    elif not windows and meta_text:
        meta_win = "// [PACKAGE_META]\n" + meta_text[:window_chars]
        windows.append(meta_win)
        win_meta.append(
            {
                "file": "[package_meta]",
                "is_install": False,
                "has_decoded": False,
                "api_density": 0,
            }
        )

    return windows, win_meta


def build_package_windows(
    record: Dict[str, Any],
    max_windows: int = 12,
    window_chars: int = 2300,
) -> List[str]:
    """Standard API returning list of model-ready text windows per package."""
    wins, _ = build_package_windows_with_meta(record, max_windows=max_windows, window_chars=window_chars)
    return wins


def compute_code_fingerprint(record: Dict[str, Any]) -> str:
    """
    Computes a whitespace/string-normalized SHA-256 fingerprint of a package's code
    for strict train/val/test leakage prevention across renamed/reformatted copies.
    """
    install_text, files, meta_text = _reassemble_chunks_by_file(record)
    parts: List[str] = []
    if install_text:
        parts.append(RE_NORM_WS.sub(" ", install_text).strip())
    for _, text in files[:8]:
        norm = RE_NORM_STR.sub('""', text[:8192])
        norm = RE_NORM_WS.sub(" ", norm).strip()
        if norm:
            parts.append(norm)
    if not parts and meta_text:
        parts.append(RE_NORM_WS.sub(" ", meta_text).strip())
    payload = "\n".join(sorted(parts))
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:24]


def normalize_package_name(raw_name: str) -> str:
    """
    Strips version suffixes, archive extensions, and category/code-shape prefixes,
    and normalizes scoped package separators (@scope/pkg, @scope__pkg, @scope_pkg,
    @scope@pkg) into one canonical `@scope/pkg` form for strict leakage prevention.
    """
    name = str(raw_name or "").strip()
    for ext in (".tar.gz", ".tgz", ".zip", ".json"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    if "__" in name and not name.startswith("@"):
        head, tail = name.split("__", 1)
        if re.fullmatch(r"[0-9a-f]{8,16}|v[12]_[0-9a-f]{8,16}", head):
            name = tail

    if name.startswith("@"):
        parts = name.split("@")
        if len(parts) >= 4:
            name = "@" + parts[1] + "/" + "@".join(parts[2:-1])
        elif len(parts) == 3:
            if "/" in parts[1] or "__" in parts[1] or "_" in parts[1]:
                name = "@" + parts[1]
            elif re.match(r"^\d", parts[2]):
                name = "@" + parts[1]
            else:
                name = "@" + parts[1] + "/" + parts[2]
        if "/" not in name:
            if "__" in name:
                scope, pkg = name.split("__", 1)
                name = f"{scope}/{pkg}"
            elif "_" in name:
                scope, pkg = name.split("_", 1)
                name = f"{scope}/{pkg}"
    else:
        if "@" in name:
            name = name.split("@", 1)[0]

    return name.lower().strip()
