#!/usr/bin/env python3
"""Fails if the documented Python import does not match the real package.

The SDK module is `agentforge` and the client class is `AIec`. That split is
easy to "tidy up" by accident, and then the website teaches an import that does
not work. Checking the module name alone is not enough either: the examples also
import `AIecError`, which is easy to leave out of the package's `__all__`. So
both the module and every documented name are checked.
"""
import html
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[1]
pkg = root / "sdk/python/agentforge"
problems = []

init_path = pkg / "__init__.py"
if not init_path.exists():
    print("SDK contract violated:\n  - the `agentforge` SDK package is missing", file=sys.stderr)
    raise SystemExit(1)

init = init_path.read_text(encoding="utf-8")
client = (pkg / "client.py").read_text(encoding="utf-8")
exported = set(re.findall(r'"([^"]+)"', init.split("__all__")[-1])) if "__all__" in init else set()

if not re.search(r"^class AIec\b", client, re.MULTILINE):
    problems.append("sdk/python/agentforge/client.py does not define `class AIec`")
if "AIec" not in exported:
    problems.append("sdk/python/agentforge/__init__.py does not export AIec")

# The site, the README and the examples are what a user copies from.
documented = (
    list((root / "web/pages").glob("*.html"))
    + [root / "README.md", root / "docs/MCP.md"]
    + list((root / "examples").glob("*.py"))
)

# Only a valid Python import list counts, so a name never runs past the closing
# HTML tag of the surrounding code sample.
NAME_LIST = r"[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*"

for path in documented:
    if not path.exists():
        continue
    # Some pages render a code sample one token at a time
    # (`from <span class="kw">agentforge</span> import ...`), so the raw markup
    # never contains a plain `from x import`. Scan the rendered text instead.
    text = html.unescape(path.read_text(encoding="utf-8"))
    text = re.sub(r"<[^>]+>", "", text)

    for module in re.findall(r"from\s+(\w+)\s+import", text):
        if module not in {"agentforge", "__future__"}:
            problems.append(
                f"{path.relative_to(root)} documents `from {module} import`, "
                "but the SDK module is `agentforge`"
            )

    for names in re.findall(rf"from\s+agentforge\s+import\s+({NAME_LIST})", text):
        for name in (n.strip() for n in names.split(",")):
            if name and name not in exported:
                problems.append(
                    f"{path.relative_to(root)} imports `{name}`, "
                    "which the package does not export"
                )

# A sample that names an image the API cannot resolve teaches a failing call.
# `aiec:latest` shipped in the samples for a while and was never resolvable.
RESOLVABLE = {
    "aiec-coding:latest",
    "python:3.13",
    "node:24",
    "rust:stable",
    "ubuntu:24.04",
    "alpine:3.21",
}
for path in documented:
    if not path.exists():
        continue
    text = html.unescape(path.read_text(encoding="utf-8"))
    text = re.sub(r"<[^>]+>", "", text)
    for image in re.findall(r'image="([^"]+)"', text):
        if image not in RESOLVABLE:
            problems.append(
                f"{path.relative_to(root)} uses image `{image}`, "
                "which the API cannot resolve"
            )

if problems:
    print("SDK contract violated:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    raise SystemExit(1)
print("sdk contract ok: from agentforge import AIec, AIecError")
