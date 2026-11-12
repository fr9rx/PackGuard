import argparse
import hashlib
import json
import os
import shutil
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common


def package_names(root):
    """Returns the sorted package folder names directly under root."""
    return sorted(name for name in os.listdir(root)
                  if os.path.isdir(os.path.join(root, name)))


def group_char(name):
    """Returns the first hex character of the package name's SHA-256."""
    return hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()[0]


def link_package(source, destination):
    """Hard-links every file of one package into the staging tree."""
    for root, dirs, files in os.walk(source):
        relative = os.path.relpath(root, source)
        target_root = destination if relative == "." else os.path.join(destination, relative)
        os.makedirs(target_root, exist_ok=True)
        for name in files:
            src = os.path.join(root, name)
            dst = os.path.join(target_root, name)
            if os.path.exists(dst):
                os.unlink(dst)
            try:
                os.link(src, dst)
            except OSError:
                shutil.copy2(src, dst)


def verify_zip(path, password=common.PASSWORD):
    """Reads the first entry of an archive with the password and returns its size."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if not names:
            raise ValueError("empty archive")
        data = archive.read(names[0], pwd=password)
        return len(names), len(data)


def export(root, destination, prefix, work):
    """Groups a reference tree into encrypted per-hex archives and returns the manifest."""
    names = package_names(root)
    groups = {}
    for name in names:
        groups.setdefault(group_char(name), []).append(name)
    os.makedirs(destination, exist_ok=True)
    manifest = {"source": root, "prefix": prefix, "password": common.PASSWORD.decode(),
                "packages": len(names), "archives": []}
    for char in sorted(groups):
        members = groups[char]
        staging = os.path.join(work, "staging", "%s_%s" % (prefix, char))
        common.remove_tree(staging)
        os.makedirs(staging, exist_ok=True)
        for name in members:
            link_package(os.path.join(root, name), os.path.join(staging, name))
        out = os.path.join(destination, "%s_%s.zip" % (prefix, char))
        files, size = common.write_encrypted_zip(out, staging)
        entries, first_size = verify_zip(out)
        manifest["archives"].append({"zip": os.path.basename(out), "packages": len(members),
                                     "files": files, "bytes": size, "entries": entries,
                                     "first_entry_bytes": first_size})
        print("%s %s: %d packages, %d files, %.1f MiB" % (
            prefix, char, len(members), files, size / 2 ** 20), flush=True)
        shutil.rmtree(staging, ignore_errors=True)
    common.write_manifest(os.path.join(destination, "manifest_%s.json" % prefix), manifest)
    return manifest


def main():
    """Parses arguments and exports one or more reference trees."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", default=os.path.expanduser("~/pg-test-sets/export"))
    parser.add_argument("--work", default=os.path.expanduser("~/pg-test-sets/export-work"))
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    sources = {
        "combined": os.path.expanduser("~/packguard-data/combined/malware_js"),
        "benign": os.path.expanduser("~/packguard-data/v7/benign_refs"),
        "known": os.path.expanduser("~/pg-test-sets/known/flat"),
        "new": os.path.expanduser("~/pg-test-sets/new/flat"),
    }
    selected = [name for name in sources if not args.only or name in args.only.split(",")]
    os.makedirs(args.dest, exist_ok=True)
    for name in selected:
        root = sources[name]
        if not os.path.isdir(root):
            print("missing", root, flush=True)
            continue
        export(root, os.path.join(args.dest, name), name, args.work)
    shutil.rmtree(args.work, ignore_errors=True)


if __name__ == "__main__":
    main()
