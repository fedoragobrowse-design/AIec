#!/usr/bin/env python3
"""Rename the project to AIec everywhere: crates, binaries, identifiers, config.

The product is AIec; the `aiec` prefix was a working name. This rewrites
directory names, Cargo package names and paths, Rust module paths, public type
names, binary names, the environment-variable prefix, the site worker name and
the docs, then leaves the tree to the compiler for verification.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Directories that carry the old name.
DIRS = [
    ("crates/aiec-core", "crates/aiec-core"),
    ("crates/aiec-storage", "crates/aiec-storage"),
    ("crates/aiec-runtime", "crates/aiec-runtime"),
    ("crates/aiec-network-linux", "crates/aiec-network-linux"),
    ("crates/aiec-api", "crates/aiec-api"),
    ("crates/aiec-client", "crates/aiec-client"),
    ("crates/aiec-cli", "crates/aiec-cli"),
    ("guest/aiec-guest", "guest/aiec-guest"),
]

# Ordered so longer identifiers are rewritten before the bare crate name.
TEXT_SUBS = [
    # Public type names.
    ("AIecClient", "AIecClient"),
    ("AIecError", "AIecError"),
    ("AIec", "AIec"),
    # Crate/module identifiers.
    ("aiec_network_linux", "aiec_network_linux"),
    ("aiec_guest", "aiec_guest"),
    ("aiec_core", "aiec_core"),
    ("aiec_storage", "aiec_storage"),
    ("aiec_runtime", "aiec_runtime"),
    ("aiec_client", "aiec_client"),
    ("aiec_api", "aiec_api"),
    ("aiec_cli", "aiec_cli"),
    # Crate names and paths in Cargo files and prose.
    ("aiec-network-linux", "aiec-network-linux"),
    ("aiec-guest", "aiec-guest"),
    ("aiec-runtime", "aiec-runtime"),
    ("aiec-storage", "aiec-storage"),
    ("aiec-client", "aiec-client"),
    ("aiec-core", "aiec-core"),
    ("aiec-api", "aiec-api"),
    ("aiec-cli", "aiec-cli"),
    # Binaries.
    ("aiec-server", "aiec-server"),
    # Environment variables and the config prefix.
    ("AIEC_", "AIEC_"),
    # Container, service and image names.
    ("aiec-site", "aiec-site"),
    ("aiec-minio", "aiec-minio"),
    # Bare crate name last: everything longer has already been handled.
    ("aiec", "aiec"),
]

SKIP_DIRS = {".git", "target", "node_modules", "__pycache__", ".aiec"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".gz", ".zst", ".zip"}


def rewrite(path: pathlib.Path) -> bool:
    if path.suffix in BINARY_SUFFIXES:
        return False
    try:
        original = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False
    text = original
    for old, new in TEXT_SUBS:
        text = text.replace(old, new)
    if text != original:
        path.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> int:
    changed = 0
    for old, new in DIRS:
        src, dst = ROOT / old, ROOT / new
        if src.exists():
            subprocess.run(["git", "mv", str(src), str(dst)], cwd=ROOT, check=True)
            print(f"moved {old} -> {new}")
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if rewrite(path):
            changed += 1
    print(f"rewrote {changed} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
