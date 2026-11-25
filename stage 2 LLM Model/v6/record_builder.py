"""
PackGuard Stage 2 v6 — Unified Package Record & Multi-Window Builder.

Shared identically by dataset preparation, teacher/LoRA training, student
distillation, ONNX inference, stage2_scan_folder.py, and packguard-cli.

Design principles (addressing all Stage 2 v3/v5 audit flaws):
  - Zero benchmark-marker stripping (no /* reformatted */, /* padded */, _pg_pad_).
  - Zero module-name length guessing (no len=13 -> child_process heuristics).
  - Zero allowlist short-circuits or fixed-score regex overrides.
  - Universal non-destructive literal decoding (Base64 / hex / unicode / concat)
    appended as context for the neural network without deleting original code.
  - Multi-window coverage across install scripts and package JS files so large
    packages are never silently half-truncated.
"""

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CODE_EXTENSIONS = {".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".ps1", ".bat", ".cmd"}
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "__pycache__", "coverage", ".nyc_output"}
SKIP_SUFFIXES = (".d.ts", ".map", ".min.js.map", ".lock")
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

RE_BASE64_CALL = re.compile(
    r"""(?:Buffer\.from\s*\(\s*["']([A-Za-z0-9+/=_-]{20,8192})["']\s*,\s*["']base64(?:url)?["']\s*\)|atob\s*\(\s*["']([A-Za-z0-9+/=_-]{20,8192})["']\s*\))"""
)
RE_BASE64_STANDALONE = re.compile(r"""["']([A-Za-z0-9+/]{32,4096}={0,2})["']""")
RE_HEX_CALL = re.compile(
    r"""Buffer\.from\s*\(\s*["']((?:[0-9a-fA-F]{2}){8,8192})["']\s*,\s*["']hex["']\s*\)"""
)
RE_HEX_STANDALONE = re.compile(r"""["']((?:[0-9a-fA-F]{2}){20,4096})["']""")
RE_HEX_ESCAPES = re.compile(r"""((?:\\x[0-9a-fA-F]{2}){4,})""")
RE_UNICODE_ESCAPES = re.compile(r"""((?:\\u[0-9a-fA-F]{4}){4,})""")
RE_FROM_CHAR_CODE = re.compile(
    r"""String\.fromCharCode\s*\(\s*(\d+(?:\s*,\s*\d+){3,512})\s*\)"""
)
RE_SPLIT_STR_CONCAT = re.compile(
    r"""(["'])([A-Za-z0-9_./:@=+-]{1,80})\1\s*\+\s*(["'])([A-Za-z0-9_./:@=+-]{1,80})\3"""
)
RE_ARRAY_JOIN = re.compile(
    r"""\[\s*((?:["'][^"']{1,12}["']\s*,\s*){3,128}["'][^"']{1,12}["'])\s*\]\s*\.\s*join\s*\(\s*["']{2}\s*\)"""
)
RE_NORM_WS = re.compile(r"\s+")
RE_NORM_STR = re.compile(r"""(["'`])(?:\\.|(?!\1)[^\\]){0,500}\1""")


def _is_mostly_printable(text: str) -> bool:
    if not text or len(text) < 4:
        return False
    printable = sum(1 for ch in text if 32 <= ord(ch) <= 126 or ch in "\r\n\t")
    return (printable / len(text)) >= 0.85


def _try_decode_b64(raw: str) -> Optional[str]:
    try:
        padded = raw.strip().replace("-", "+").replace("_", "/")
        rem = len(padded) % 4
        if rem:
            padded += "=" * (4 - rem)
        data = base64.b64decode(padded, validate=False)
        if not data or len(data) > 16384:
            return None
        decoded = data.decode("utf-8", errors="strict")
        if _is_mostly_printable(decoded):
            return decoded
    except Exception:
        return None
    return None


def decode_obfuscated_literals(code: str, max_decoded_chars: int = 1200) -> str:
    """
    Universal, non-destructive literal decoder.
    Returns decoded hints (Base64, hex, \\xNN, \\uNNNN, String.fromCharCode,
    and split string concatenations) without modifying or deleting the source.
    """
    if not code:
        return ""
    hints: List[str] = []
    seen = set()
    budget = max_decoded_chars

    def add_hint(tag: str, val: str) -> None:
        nonlocal budget
        cleaned = val.strip()
        if len(cleaned) < 4 or cleaned in seen or budget <= 0:
            return
        seen.add(cleaned)
        snippet = cleaned[: min(len(cleaned), 400, budget)]
        hints.append(f"[{tag}] {snippet}")
        budget -= len(snippet)

    # Fold adjacent string concatenations FIRST so split Base64/Hex/API strings decode cleanly
    work_code = code[:32768]
    for _ in range(4):
        folded_code = RE_SPLIT_STR_CONCAT.sub(r'"\2\4"', work_code)
        if folded_code == work_code:
            break
        work_code = folded_code

    for m in RE_ARRAY_JOIN.finditer(work_code):
        parts = re.findall(r"""["']([^"']{1,12})["']""", m.group(1))
        joined_val = "".join(parts)
        if _is_mostly_printable(joined_val) and len(joined_val) >= 4:
            add_hint("arrjoin", joined_val)
            dec_b = _try_decode_b64(joined_val) if len(joined_val) >= 24 else None
            if dec_b:
                add_hint("arrjoin_b64", dec_b)

    for m in RE_BASE64_CALL.finditer(work_code):
        b64_str = m.group(1) or m.group(2)
        if not b64_str:
            continue
        dec = _try_decode_b64(b64_str)
        if dec:
            add_hint("b64", dec)
            inner = _try_decode_b64(dec) if len(dec) >= 24 and " " not in dec.strip() else None
            if inner:
                add_hint("b64_2", inner)

    for m in RE_HEX_CALL.finditer(work_code):
        try:
            dec = bytes.fromhex(m.group(1)).decode("utf-8", errors="strict")
            if _is_mostly_printable(dec):
                add_hint("hex", dec)
        except Exception:
            pass

    if budget > 200:
        for m in RE_HEX_STANDALONE.finditer(work_code[:24576]):
            if budget <= 100:
                break
            try:
                dec = bytes.fromhex(m.group(1)).decode("utf-8", errors="strict")
                if _is_mostly_printable(dec) and any(
                    ch in dec for ch in ("(", "/", ".", " ", "=", ";", "http", "sh", "require")
                ):
                    add_hint("hex_lit", dec)
            except Exception:
                pass

    for m in RE_HEX_ESCAPES.finditer(work_code):
        try:
            hex_bytes = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(1)))
            dec = hex_bytes.decode("utf-8", errors="strict")
            if _is_mostly_printable(dec):
                add_hint("xesc", dec)
        except Exception:
            pass

    for m in RE_UNICODE_ESCAPES.finditer(work_code):
        try:
            chars = "".join(chr(int(u, 16)) for u in re.findall(r"\\u([0-9a-fA-F]{4})", m.group(1)))
            if _is_mostly_printable(chars):
                add_hint("uesc", chars)
        except Exception:
            pass

    for m in RE_FROM_CHAR_CODE.finditer(work_code):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",")]
            if all(0 <= n <= 0x10FFFF for n in nums):
                dec = "".join(chr(n) for n in nums)
                if _is_mostly_printable(dec):
                    add_hint("charcode", dec)
        except Exception:
            pass

    if budget > 200:
        for m in RE_BASE64_STANDALONE.finditer(work_code[:16384]):
            if budget <= 100:
                break
            dec = _try_decode_b64(m.group(1))
            if dec and any(ch in dec for ch in ("(", "/", ".", " ", "=", ";", "http", "sh")):
                add_hint("b64_lit", dec)

    if budget > 100 and work_code != code[:32768]:
        joined = re.findall(r'"([A-Za-z0-9_./:@-]{5,80})"', work_code[:16384])
        orig = set(re.findall(r"""["']([A-Za-z0-9_./:@-]{5,80})["']""", code[:16384]))
        for j in joined:
            if j not in orig:
                add_hint("concat", j)

    if not hints:
        return ""
    return "\n// [DECODED_LITERALS]\n" + "\n".join(hints)


def extract_install_scripts_from_package_json(raw_json_text: str) -> str:
    """Extracts lifecycle scripts and suspicious non-registry dependency URLs from package.json."""
    try:
        data = json.loads(raw_json_text)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    lines: List[str] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key in INSTALL_HOOK_KEYS:
            val = scripts.get(key)
            if isinstance(val, str) and val.strip():
                lines.append(f"{key}: {val.strip()}")
    for dep_field in ("dependencies", "optionalDependencies", "devDependencies"):
        deps = data.get(dep_field)
        if isinstance(deps, dict):
            for k, v in deps.items():
                if isinstance(v, str) and (
                    v.startswith(("http://", "https://", "git+", "github:", "file:"))
                ):
                    lines.append(f"dep {k}: {v}")
    return "\n".join(lines)


def _file_priority_key(relpath: str, size: int) -> Tuple[int, str]:
    lp = relpath.lower().replace("\\", "/").replace("__", "/")
    base = lp.rsplit("/", 1)[-1]
    if base in ("install_scripts.txt", "package.json#scripts", "[install_scripts]"):
        return (0, lp)
    if base in ("preinstall.js", "postinstall.js", "install.js", "setup.js"):
        return (1, lp)
    if lp in ("index.js", "index.cjs", "index.mjs", "main.js", "cli.js", "bin.js"):
        return (2, lp)
    if lp.startswith(("bin/", "scripts/", "src/index.", "lib/index.", "dist/index.")):
        return (3, lp)
    if "/test/" in f"/{lp}" or "/tests/" in f"/{lp}" or base.endswith((".test.js", ".spec.js")):
        return (6, lp)
    if size < 120:
        return (5, lp)
    return (4, lp)


def extract_package_json_name(pkg_dir: Path) -> Optional[str]:
    """Reads package.json['name'] if present, for exact leak-free package deduplication."""
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
            extracted = extract_install_scripts_from_package_json(raw_pj)
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
            lower_rel = rel.lower()
            if lower_rel in ("install_scripts.txt", "package.json"):
                continue
            if lower_rel.endswith(SKIP_SUFFIXES):
                continue
            ext = path.suffix.lower()
            if ext not in CODE_EXTENSIONS:
                continue
            try:
                sz = path.stat().st_size
            except OSError:
                continue
            if sz == 0:
                continue
            candidates.append((_file_priority_key(rel, sz), rel, path))

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

    return {"package": pkg_dir.name, "chunks": chunks}


def _reassemble_chunks_by_file(record: Dict[str, Any]) -> Tuple[str, List[Tuple[str, str]]]:
    """
    Normalizes either a package_dir_to_record dict OR a Stage 1 JSON report dict
    into (install_script_text, [(relpath, file_text), ...]) in deterministic order.
    """
    raw_chunks = record.get("chunks")
    if not isinstance(raw_chunks, list):
        if isinstance(record.get("text"), str) and record["text"].strip():
            return "", [("index.js", record["text"])]
        return "", []

    install_parts: List[str] = []
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

        is_install = (
            kind in ("install", "install_script", "script", "scripts")
            or fname.lower().endswith("install_scripts.txt")
            or fname.lower().endswith("package.json#scripts")
            or fname.lower() == "package.json"
        )
        if is_install:
            if fname.lower() == "package.json" and text.lstrip().startswith("{"):
                ext = extract_install_scripts_from_package_json(text)
                if ext:
                    install_parts.append(ext)
            else:
                install_parts.append(text.strip())
        else:
            by_file.setdefault(fname, []).append((start, text))

    install_text = "\n".join(dict.fromkeys(install_parts)).strip()

    files: List[Tuple[str, str]] = []
    for fname, segs in by_file.items():
        segs.sort(key=lambda x: x[0])
        merged = "\n".join(s for _, s in segs)
        files.append((fname, merged))

    files.sort(key=lambda item: _file_priority_key(item[0], len(item[1])))
    return install_text, files


def _normalize_newlines(text: str) -> str:
    """Normalizes CRLF/CR to LF so line-ending differences never become a dataset shortcut."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _slice_file_into_windows(
    fname: str,
    text: str,
    window_chars: int = 2200,
    max_windows_per_file: int = 3,
) -> List[str]:
    """
    Slices a single file into clean windows covering head, middle, and tail
    for large files, using a path-neutral header (`// [JS_CODE]`) so flattened
    `__` vs `/` filenames can never become a dataset artifact shortcut, and placing
    universal decoded literals BEFORE the raw slice so 512-token truncation never
    drops decoded payloads.
    """
    text = _normalize_newlines(text)
    decoded = decode_obfuscated_literals(text, max_decoded_chars=700)
    dec_prefix = (decoded.lstrip("\n") + "\n") if decoded else ""
    header = "// [JS_CODE]\n"
    raw_budget = max(600, window_chars - len(dec_prefix))
    n = len(text)

    if n <= raw_budget:
        return [header + dec_prefix + text]

    windows: List[str] = []
    windows.append(header + dec_prefix + text[:raw_budget])

    if max_windows_per_file >= 2:
        tail_start = max(raw_budget, n - window_chars)
        tail_chunk = text[tail_start:]
        tail_dec = decode_obfuscated_literals(tail_chunk, max_decoded_chars=500)
        tail_prefix = (tail_dec.lstrip("\n") + "\n") if tail_dec else ""
        tail_raw_budget = max(600, window_chars - len(tail_prefix))
        windows.append("// [JS_CODE @tail]\n" + tail_prefix + tail_chunk[-tail_raw_budget:])

    if max_windows_per_file >= 3 and n > window_chars * 2.5:
        mid_start = (n - window_chars) // 2
        mid_chunk = text[mid_start : mid_start + window_chars]
        mid_dec = decode_obfuscated_literals(mid_chunk, max_decoded_chars=500)
        mid_prefix = (mid_dec.lstrip("\n") + "\n") if mid_dec else ""
        mid_raw_budget = max(600, window_chars - len(mid_prefix))
        windows.append("// [JS_CODE @mid]\n" + mid_prefix + mid_chunk[:mid_raw_budget])

    return windows


def build_package_windows(
    record: Dict[str, Any],
    max_windows: int = 10,
    window_chars: int = 2200,
) -> List[str]:
    """
    Converts a package record (from package_dir_to_record or Stage 1 report)
    into a deterministic list of model-ready text windows (each ~450-512 tokens).
    Every window uses the exact same canonical path-neutral format for training
    and inference.
    """
    install_text, files = _reassemble_chunks_by_file(record)
    windows: List[str] = []

    if install_text:
        install_text = _normalize_newlines(install_text)
        inst_dec = decode_obfuscated_literals(install_text, max_decoded_chars=700)
        inst_dec_prefix = (inst_dec.lstrip("\n") + "\n") if inst_dec else ""
        inst_budget = max(600, window_chars - len(inst_dec_prefix))
        inst_block = "// [INSTALL_SCRIPTS]\n" + inst_dec_prefix + install_text[:inst_budget]
        if files and len(inst_block) + len(files[0][1]) < window_chars - 200:
            fname0, text0 = files[0]
            text0 = _normalize_newlines(text0)
            dec0 = decode_obfuscated_literals(text0, max_decoded_chars=500)
            dec0_prefix = (dec0.lstrip("\n") + "\n") if dec0 else ""
            rem = max(400, window_chars - len(inst_block) - len(dec0_prefix))
            windows.append(inst_block + "\n// [JS_CODE]\n" + dec0_prefix + text0[:rem])
            files = files[1:]
        else:
            windows.append(inst_block)

    if not files:
        return windows

    per_file_cap = 3 if len(files) <= 3 else (2 if len(files) <= 6 else 1)
    for fname, text in files:
        if len(windows) >= max_windows:
            break
        file_wins = _slice_file_into_windows(
            fname,
            text,
            window_chars=window_chars,
            max_windows_per_file=per_file_cap,
        )
        for w in file_wins:
            if len(windows) >= max_windows:
                break
            windows.append(w)

    return windows


def compute_code_fingerprint(record: Dict[str, Any]) -> str:
    """
    Computes a whitespace/string-normalized SHA-256 fingerprint of a package's code
    for strict train/val/test leakage prevention across renamed/reformatted copies.
    """
    install_text, files = _reassemble_chunks_by_file(record)
    parts: List[str] = []
    if install_text:
        parts.append(RE_NORM_WS.sub(" ", install_text).strip())
    for _, text in files[:8]:
        norm = RE_NORM_STR.sub('""', text[:8192])
        norm = RE_NORM_WS.sub(" ", norm).strip()
        if norm:
            parts.append(norm)
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
        # Strip ONLY trailing @version when present (handles @scope/pkg@1.0, @scope__pkg@1.0, @scope@pkg@1.0)
        parts = name.split("@")
        if len(parts) >= 4:
            # e.g. ['', '0xobelisk', 'sui-cli', '1.2.0-pre.93'] -> '@0xobelisk/sui-cli'
            name = "@" + parts[1] + "/" + "@".join(parts[2:-1])
        elif len(parts) == 3:
            # Either '@scope/pkg@1.0.0' or '@scope@pkg' (no version)
            if "/" in parts[1] or "__" in parts[1] or "_" in parts[1]:
                name = "@" + parts[1]
            elif re.match(r"^\d", parts[2]):
                name = "@" + parts[1]
            else:
                name = "@" + parts[1] + "/" + parts[2]
        # Canonicalize scoped separator to '/'
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
