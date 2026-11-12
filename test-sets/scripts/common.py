import base64
import hashlib
import json
import os
import random
import re
import shutil
import struct
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_SETS = os.path.dirname(HERE)
REPO = os.path.dirname(TEST_SETS)
DATA = os.path.join(REPO, "data")
CACHE = os.path.join(TEST_SETS, "cache")
PASSWORD = b"infected"
JS_EXT = (".js", ".cjs", ".mjs")
SCRIPTS_FILE = "install_scripts.txt"
HOOKS = ("preinstall", "install", "postinstall")
KEYWORDS = {
    "async", "await", "break", "case", "catch", "class", "const", "continue",
    "debugger", "default", "delete", "do", "else", "export", "extends", "false",
    "finally", "for", "from", "function", "get", "if", "import", "in", "instanceof",
    "let", "new", "null", "of", "return", "set", "static", "super", "switch", "this",
    "throw", "true", "try", "typeof", "undefined", "var", "void", "while", "with",
    "yield", "require", "module", "exports", "process", "console", "Buffer", "global",
    "window", "document",
}
PRIMITIVE_NEEDLES = {
    "net": ("http://", "https://", "fetch(", "xmlhttprequest", "websocket", "axios",
            "require('http", 'require("http', "require('https", 'require("https',
            "require('net", 'require("net', "require('dns", 'require("dns',
            "nslookup", "ipify", ".oast"),
    "webhook": ("webhook", "telegram", "discord", "ipify", ".oast"),
    "host": ("hostname", "userinfo", "whoami", "homedir"),
    "env": ("process.env", "userdomain"),
    "exec": ("child_process", "exec(", "execsync", "spawn(", "spawnsync", "bash -c",
             "sh -c", "powershell", "cmd.exe", "node -e", "curl ", "wget ",
             "| sh", "| bash", "| node"),
    "encoding": ("base64", "atob(", "btoa(", "buffer.from", "fromcharcode",
                 "unescape(", "decodeuricomponent"),
    "sensitive": (".ssh", ".aws", ".npmrc", ".git-credentials", '".env"', "'.env'",
                  "/.env", "wallet", "privatekey", "mnemonic"),
    "obfuscation": ("_0x",),
    "eval": ("eval(", "new function", "function("),
    "decode": ("base64", "atob(", "btoa(", "buffer.from"),
}


def sha256(data):
    """Returns the SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def ws_hash(data):
    """Returns the hash of bytes with all whitespace removed."""
    return sha256(re.sub(rb"\s+", b"", data))


def safe_component(name):
    """Turns a package name, version or file path into a Windows-safe single path component."""
    name = name.replace("/", "__").replace("\\", "__").replace(":", "_")
    name = re.sub(r'[<>"|?*\x00-\x1f]', "_", name)
    return name.strip().strip(".")[:180] or "_"


def install_scripts_from_json(data):
    """Mirrors install_scripts() in src/manifest.c and returns the hook text as bytes."""
    if not data:
        return b""

    def no_constant(value):
        raise ValueError(value)

    try:
        doc = json.loads(data.decode("utf-8", "surrogateescape"), parse_constant=no_constant)
    except (ValueError, RecursionError):
        return b""
    if not isinstance(doc, dict) or not isinstance(doc.get("scripts"), dict):
        return b""
    out = []
    for hook in HOOKS:
        cmd = doc["scripts"].get(hook)
        if isinstance(cmd, str) and cmd:
            out.append(cmd.encode("utf-8", "surrogatepass"))
    return b"\n".join(out) + (b"\n" if out else b"")


def scripts_to_package_json(name, version, scripts):
    """Builds a minimal package.json whose install hooks hold the given script text."""
    hooks = {}
    lines = scripts.decode("utf-8", "surrogateescape").splitlines()
    for index, line in enumerate(lines):
        if line.strip():
            hooks[HOOKS[min(index, len(HOOKS) - 1)]] = line
    doc = {
        "name": name,
        "version": version,
        "description": "PackGuard test fixture",
        "main": "index.js",
        "scripts": hooks,
    }
    return json.dumps(doc, indent=2).encode("utf-8") + b"\n"


def is_js(name):
    """Returns True when name is a JavaScript file the scanner scores."""
    return name.lower().endswith(JS_EXT)


def read_datadog_zip(path):
    """Reads one DataDog sample zip in memory and returns (files, manifest, name, version)."""
    files = {}
    manifest = None
    manifest_rank = 10 ** 9
    name = ""
    version = ""
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir() or "node_modules/" in info.filename:
                continue
            parts = [p for p in info.filename.replace("\\", "/").split("/") if p]
            if not parts:
                continue
            if "package" in parts[:-1]:
                rel = parts[parts.index("package") + 1:]
            else:
                rel = parts[-1:]
            if parts[-1].lower().endswith(JS_EXT):
                files[safe_component("__".join(rel))] = archive.read(info, pwd=PASSWORD)
            elif parts[-1] == "package.json":
                rank = len(rel) if "package" in parts[:-1] else 1000 + len(parts)
                if rank < manifest_rank:
                    manifest_rank = rank
                    manifest = archive.read(info, pwd=PASSWORD)
    if manifest:
        try:
            doc = json.loads(manifest.decode("utf-8", "surrogateescape"))
            if isinstance(doc, dict):
                name = str(doc.get("name") or "")
                version = str(doc.get("version") or "")
        except (ValueError, RecursionError):
            pass
    return files, manifest, name, version


def read_corpus_zip(path):
    """Reads one shipped v1/v2 zip and yields (group, name, version, files) per package."""
    groups = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size == 0:
                continue
            parts = [p for p in info.filename.replace("\\", "/").split("/") if p]
            if len(parts) < 3:
                continue
            group, package = parts[0], parts[1]
            if "@" not in package:
                continue
            name, version = package.rsplit("@", 1)
            key = (group, name, version)
            groups.setdefault(key, {})[safe_component("__".join(parts[2:]))] = archive.read(info, pwd=PASSWORD)
    for (group, name, version), files in groups.items():
        yield group, name, version, files


def iter_packages(root):
    """Yields (category, package_dir, files) for every package under root/<category>/<name>@<version>."""
    if not os.path.isdir(root):
        return
    for category in sorted(os.listdir(root)):
        category_dir = os.path.join(root, category)
        if not os.path.isdir(category_dir):
            continue
        for package in sorted(os.listdir(category_dir)):
            package_dir = os.path.join(category_dir, package)
            if not os.path.isdir(package_dir):
                continue
            files = {}
            for name in sorted(os.listdir(package_dir)):
                path = os.path.join(package_dir, name)
                if os.path.isfile(path):
                    with open(path, "rb") as handle:
                        files[name] = handle.read()
            if files:
                yield category, package_dir, files


def write_package(package_dir, files):
    """Writes a package's files as read-only and returns the number of bytes."""
    os.makedirs(package_dir, exist_ok=True)
    total = 0
    for name, data in files.items():
        path = os.path.join(package_dir, safe_component(name))
        if os.path.exists(path):
            try:
                os.chmod(path, 0o644)
            except OSError:
                pass
        with open(path, "wb") as handle:
            handle.write(data)
        try:
            os.chmod(path, 0o444)
        except OSError:
            pass
        total += len(data)
    return total


def remove_tree(path):
    """Removes a directory tree, clearing read-only bits first."""
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path):
        try:
            os.chmod(root, 0o755)
        except OSError:
            pass
        for name in files:
            try:
                os.chmod(os.path.join(root, name), 0o644)
            except OSError:
                pass
    shutil.rmtree(path)


def js_shape(data):
    """Returns the v2 code shape of one JavaScript file."""
    token = re.compile(
        rb"""("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)"""
        rb"""|(/\*.*?\*/|//[^\n]*)"""
        rb"""|(\b_0x[0-9a-fA-F]+\b)"""
        rb"""|(\b\d[\w.]*)"""
        rb"""|(\s+)""", re.S)

    def replace(match):
        if match.group(1) is not None:
            return b'"'
        if match.group(3) is not None:
            return b"_0x"
        if match.group(4) is not None:
            return b"0"
        return b""

    return token.sub(replace, data)


def script_shape(text):
    """Returns the v2 code shape of install-script text."""
    words = re.compile(rb"[A-Za-z0-9_]+")

    def replace(match):
        word = match.group()
        return word if word.isalpha() and len(word) <= 10 else b"#"

    return re.sub(rb"\s+", b"", words.sub(replace, text))


def package_shape(files):
    """Returns a 12-hex code shape for a package, or None when it has no scorable files."""
    shapes = []
    for name, data in sorted(files.items()):
        if not data:
            continue
        if is_js(name):
            shapes.append(sha256(js_shape(data)))
        elif name == SCRIPTS_FILE:
            shapes.append("s" + sha256(script_shape(data)))
    if not shapes:
        return None
    return sha256("\n".join(sorted(shapes)).encode())[:12]


def map_code(text, ident, string, number):
    """Maps identifiers, string contents and numbers outside comments."""
    out = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in "'\"`":
            quote = char
            end = index + 1
            while end < length:
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == quote:
                    break
                end += 1
            content = text[index + 1:end]
            out.append(quote + string(content) + quote)
            index = end + 1 if end < length else length
        elif char == "/" and index + 1 < length and text[index + 1] == "/":
            end = text.find("\n", index)
            end = length if end < 0 else end
            out.append(text[index:end])
            index = end
        elif char == "/" and index + 1 < length and text[index + 1] == "*":
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            out.append(text[index:end])
            index = end
        elif char.isalpha() or char in "_$":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            word = text[index:end]
            out.append(word if word in KEYWORDS else ident(word))
            index = end
        elif char.isdigit():
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "._"):
                end += 1
            out.append(number(text[index:end]))
            index = end
        else:
            out.append(char)
            index += 1
    return "".join(out)


def t1_format(text, rng):
    """Adds a header comment and indentation, leaving the code intact."""
    lines = text.splitlines()
    return "/* reformatted */\n" + "\n".join("  " + line for line in lines) + "\n"


def t2_rename(text, rng):
    """Renames identifiers, strings and numbers consistently."""
    names = {}

    def ident(word):
        if word not in names:
            names[word] = "v%d" % len(names)
        return names[word]

    def string(value):
        return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in value)

    def number(value):
        return str(rng.randint(10000, 99999))

    return map_code(text, ident, string, number)


def t3_pad(text, rng):
    """Inserts about 18 KiB of dead code, crossing the 16 KiB split threshold."""
    dead = "".join("function _pg_pad_%d(){var x=%d;return x;}\n" % (i, i)
                   for i in range(320))
    return "/* padded */\n" + dead + text + "\n" + dead


def t4_base64(text, rng):
    """Wraps the whole file in a base64 payload behind eval."""
    payload = base64.b64encode(text.encode("utf-8", "surrogateescape")).decode("ascii")
    return 'eval(Buffer.from("%s","base64").toString());\n' % payload


TRANSFORMS = {
    "T1_format": t1_format,
    "T2_rename": t2_rename,
    "T3_padding": t3_pad,
    "T4_base64": t4_base64,
}


def transform_files(files, tier, rng):
    """Returns transformed JavaScript files for one package and the given tier."""
    out = {}
    index = 0
    for name, data in sorted(files.items()):
        if not is_js(name):
            continue
        text = data.decode("utf-8", "surrogateescape")
        transformed = TRANSFORMS[tier](text, rng)
        out_name = name if tier != "T2_rename" else "file_%02d%s" % (index, os.path.splitext(name)[1])
        out[out_name] = transformed.encode("utf-8", "surrogateescape")
        index += 1
    return out


def truncated_files(files, limit):
    """Returns files with JavaScript capped so that at most limit bytes of JavaScript remain."""
    out = {}
    used = 0
    for name, data in sorted(files.items()):
        if is_js(name):
            if used >= limit:
                continue
            room = limit - used
            if len(data) > room:
                data = data[:room]
            used += len(data)
            if not data:
                continue
        out[name] = data
    return out


def primitive_hits(data):
    """Returns the set of behavioural primitive categories present in a byte string."""
    lower = data.lower()
    hits = set()
    for category, needles in PRIMITIVE_NEEDLES.items():
        for needle in needles:
            if needle.encode("ascii") in lower:
                hits.add(category)
                break
    return hits


def primitives_flagged(hits, is_script):
    """Mirrors primitives_flagged() in src/primitives.c."""
    if is_script:
        return "net" in hits and bool(hits & {"host", "env", "exec", "encoding", "sensitive"})
    if "net" in hits and bool(hits & {"host", "sensitive"}):
        return True
    if "webhook" in hits and "exec" in hits:
        return True
    if "net" in hits and "env" in hits and "exec" in hits:
        return True
    if "eval" in hits and "decode" in hits:
        return True
    return False


def package_primitive_hits(files):
    """Returns the union of JavaScript and install-script primitive hits for a package."""
    js = set()
    scripts = set()
    for name, data in files.items():
        if is_js(name):
            js |= primitive_hits(data)
        elif name == SCRIPTS_FILE:
            scripts |= primitive_hits(data)
        elif name == "package.json":
            text = install_scripts_from_json(data)
            if text:
                scripts |= primitive_hits(text)
    return js, scripts


def _crc_table():
    """Builds the raw CRC-32 table used by the ZipCrypto key update."""
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


CRC_TABLE = _crc_table()


def _crc32_primitive(byte, crc):
    """Advances the raw CRC-32 primitive one byte, as ZipCrypto requires."""
    return (crc >> 8) ^ CRC_TABLE[(crc ^ byte) & 0xFF]


def zipcrypto_encrypt(password, data):
    """Encrypts data with the traditional PKWARE ZipCrypto stream."""
    keys = [0x12345678, 0x23456789, 0x34567890]
    for byte in password:
        keys[0] = _crc32_primitive(byte, keys[0])
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc32_primitive((keys[1] >> 24) & 0xFF, keys[2])
    out = bytearray()
    for byte in data:
        temp = (keys[2] | 2) & 0xFFFF
        out.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
        keys[0] = _crc32_primitive(byte, keys[0])
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc32_primitive((keys[1] >> 24) & 0xFF, keys[2])
    return bytes(out)


def _dos_datetime():
    return 0, (2026 - 1980) << 9 | 1 << 5 | 1


def _deflate(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def write_encrypted_zip(out_path, source_root, password=PASSWORD):
    """Writes every file under source_root into one encrypted ZipCrypto archive."""
    entries = []
    for root, dirs, files in os.walk(source_root):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, source_root).replace("\\", "/")
            with open(path, "rb") as handle:
                entries.append((rel, handle.read()))
    names = sorted({rel for rel, _ in entries})
    if len(names) != len(entries):
        raise ValueError("duplicate archive entry names")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    central = []
    with open(out_path, "wb") as handle:
        for rel, data in entries:
            crc = zlib.crc32(data) & 0xFFFFFFFF
            compressed = _deflate(data)
            header = os.urandom(11) + bytes([(crc >> 24) & 0xFF])
            encrypted = zipcrypto_encrypt(password, header + compressed)
            name_bytes = rel.encode("utf-8")
            time, date = _dos_datetime()
            offset = handle.tell()
            handle.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x0001, 8, time, date,
                                     crc, len(encrypted), len(data), len(name_bytes), 0))
            handle.write(name_bytes)
            handle.write(encrypted)
            central.append((name_bytes, crc, len(encrypted), len(data), offset, time, date))
        cd_offset = handle.tell()
        for name_bytes, crc, comp_size, size, offset, time, date in central:
            handle.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x0001, 8,
                                     time, date, crc, comp_size, size, len(name_bytes), 0, 0,
                                     0, 0, 0, offset))
            handle.write(name_bytes)
        cd_size = handle.tell() - cd_offset
        handle.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central), len(central),
                                 cd_size, cd_offset, 0))
    return len(entries), os.path.getsize(out_path)


def write_manifest(path, data):
    """Writes a JSON manifest with stable formatting."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, sort_keys=False)
        handle.write("\n")


def load_json(path):
    """Reads a JSON file."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def corpus_zips(version):
    """Returns the sorted encrypted corpus zips for data/v1 or data/v2."""
    folder = os.path.join(DATA, version)
    return sorted(os.path.join(folder, name) for name in os.listdir(folder)
                  if name.endswith(".zip"))
