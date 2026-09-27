#!/usr/bin/env python3
"""Render the AIec site from page fragments.

The site is static HTML with no framework: a stranger should be able to read the
markup, and a reviewer should be able to change a page without a build step.
This script keeps the shell, navigation and telemetry rail in one place so a new
page cannot silently ship with a stale menu.

A fragment may carry directives:

    <!-- meta:title=... -->            page title
    <!-- meta:description=... -->      meta description
    <!-- block:rail --> … <!-- /block -->  override the telemetry rail

Usage:  python3 web/build.py
"""

from __future__ import annotations

import html
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAGES = ROOT / "pages"

CONSOLE_ROUTES = {"/cloud/console"}

NAV = [
    ("/", "Home"),
    ("/docs", "Docs"),
    ("/mcp", "MCP"),
    ("/pricing", "Pricing"),
    ("/cloud", "Cloud"),
    ("/cloud/keys", "API keys"),
    ("/cloud/usage", "Usage"),
    ("/cloud/sandboxes", "Sandboxes"),
    ("/security", "Security"),
    ("/status", "Status"),
    ("/cloud/console", "Console"),
]
FOOTER_NAV = [
    ("/docs", "Docs"),
    ("/mcp", "MCP"),
    ("/security", "Security"),
    ("/status", "Status"),
    ("/cloud/console", "Console"),
]


DASHBOARD_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — AIec</title>
<meta name="description" content="{description}">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#edf0f4">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@75..125,400..800&family=IBM+Plex+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="/assets/site.css">
<link rel="stylesheet" href="/assets/dashboard.css">
<link rel="icon" href="/assets/mark.svg" type="image/svg+xml">
</head>
<body>
<header class="masthead">
  <div class="masthead__inner">
    <a class="wordmark" href="/"><span class="wordmark__mark"></span>AIec</a>
    <nav class="masthead__nav">{nav}</nav>
  </div>
</header>
{body}
<footer class="colophon">
  <div class="colophon__inner">
    <span>Computers for AI agents.</span>
    <nav class="colophon__nav">{footer_nav}</nav>
  </div>
</footer>
<script src="/assets/dashboard.js" defer></script>
</body>
</html>
"""

FOOTER_CONSOLE_ROUTES = {"/cloud/console"}

CONSOLE_NAV = [
    ("/docs", "Docs"),
    ("/security", "Security"),
    ("/status", "Status"),
]

DEFAULT_RAIL = """
    <div class="rail__group">
      <span class="rail__caption">Runtime</span>
      <dl>
        <dt>isolation</dt><dd>Firecracker microVM</dd>
        <dt>lifetime</dt><dd>minutes, not months</dd>
        <dt>network</dt><dd>egress filtered</dd>
      </dl>
    </div>
    <div class="rail__group">
      <span class="rail__caption">Availability</span>
      <dl>
        <dt>signup</dt><dd>invite only</dd>
        <dt>regions</dt><dd>1</dd>
        <dt>SLA</dt><dd>none in alpha</dd>
      </dl>
    </div>
"""

SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — AIec</title>
<meta name="description" content="{description}">
<meta property="og:title" content="{title} — AIec">
<meta property="og:description" content="{description}">
<meta property="og:type" content="website">
<meta name="theme-color" content="#edf0f4">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@75..125,400..800&family=IBM+Plex+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="/assets/site.css">
<link rel="icon" href="/assets/mark.svg" type="image/svg+xml">
</head>
<body>
<header class="masthead">
  <div class="masthead__inner">
    <a class="wordmark" href="/"><span class="wordmark__mark"></span>AIec</a>
    <nav class="masthead__nav">
      {nav}
    </nav>
  </div>
</header>
<div class="shell">
  <aside class="rail">
    {rail}
  </aside>
  <main class="content{wide}">
{body}
  </main>
</div>

<footer class="colophon">
  <div class="colophon__inner">
    <span>Computers for AI agents.</span>
    <nav class="colophon__nav">
      {footer_nav}
    </nav>
  </div>
</footer>
</body>
</html>
"""


def _blocks(fragment: str, name: str) -> list[str]:
    """Extracts <!-- block:name --> … <!-- /block --> sections from a fragment."""
    start, end = f"<!-- block:{name} -->", f"<!-- /block:{name} -->"
    out: list[str] = []
    cursor = 0
    while (open_at := fragment.find(start, cursor)) != -1:
        close_at = fragment.find(end, open_at)
        if close_at == -1:
            break
        out.append(fragment[open_at + len(start) : close_at].strip())
        cursor = close_at + len(end)
    return out


def strip_blocks(fragment: str, name: str) -> str:
    """Removes an extracted block so it does not also appear in the body."""
    start, end = f"<!-- block:{name} -->", f"<!-- /block:{name} -->"
    out: list[str] = []
    cursor = 0
    while (open_at := fragment.find(start, cursor)) != -1:
        out.append(fragment[cursor:open_at])
        close_at = fragment.find(end, open_at)
        if close_at == -1:
            cursor = len(fragment)
            break
        cursor = close_at + len(end)
    out.append(fragment[cursor:])
    return "".join(out)


def _meta(fragment: str, key: str, fallback: str) -> str:
    """Reads a <!-- meta:key=value --> directive from the top of a fragment."""
    marker = f"<!-- meta:{key}="
    for line in fragment.splitlines():
        stripped = line.strip()
        if stripped.startswith(marker):
            return stripped[len(marker) :].split("-->", 1)[0].strip()
    return fallback


def render_nav(current: str) -> str:
    parts = []
    for href, label in NAV:
        mark = ' aria-current="page"' if href == current else ""
        parts.append(f'<a href="{html.escape(href)}"{mark}>{html.escape(label)}</a>')
    return "\n      ".join(parts)


def render_console_nav(current: str) -> str:
    parts = []
    for href, label in CONSOLE_NAV:
        mark = ' aria-current="page"' if href == current else ""
        parts.append(f'<a href="{html.escape(href)}"{mark}>{html.escape(label)}</a>')
    return "\n      ".join(parts)


def render_footer_nav() -> str:
    return "\n      ".join(
        f'<a href="{html.escape(href)}">{html.escape(label)}</a>' for href, label in FOOTER_NAV
    )


def render_rail(fragment: str) -> str:
    blocks = _blocks(fragment, "rail")
    return blocks[0] if blocks else DEFAULT_RAIL


def page_path(route: str) -> Path:
    if route == "/":
        return ROOT / "index.html"
    return ROOT / f"{route.strip('/')}/index.html"


def main() -> int:
    rendered = 0
    for route, _label in NAV:
        source = PAGES / (route.strip("/").replace("/", "-") or "home")
        fragment_path = source.with_suffix(".html")
        if not fragment_path.is_file():
            raise SystemExit(f"missing page fragment for {route}: {fragment_path}")
        fragment = fragment_path.read_text(encoding="utf-8")

        is_console = route in CONSOLE_ROUTES
        shell = DASHBOARD_SHELL if is_console else SHELL
        page_path(route).parent.mkdir(parents=True, exist_ok=True)
        page_path(route).write_text(
            shell.format(
                title=html.escape(_meta(fragment, "title", route)),
                description=html.escape(
                    _meta(fragment, "description", "AIec — computers for AI agents.")
                ),
                nav=render_console_nav(route) if is_console else render_nav(route),
                footer_nav=render_footer_nav(),
                rail=render_rail(fragment) if not is_console else "",
                wide=" content--wide" if "<!-- wide -->" in fragment else "",
                body=fragment if is_console else strip_blocks(fragment, "rail"),
            ),
            encoding="utf-8",
        )
        rendered += 1
    print(f"rendered {rendered} pages into {ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
