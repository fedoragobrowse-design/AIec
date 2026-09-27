#!/usr/bin/env python3
"""Render the AgentForge site from page fragments.

The site is static HTML with no framework: a stranger should be able to read the
markup, and a reviewer should be able to change a page without a build step.
This script keeps the shared header, footer and navigation in one place so a new
page cannot silently ship with a stale menu.

Usage:  python3 web/build.py
"""

from __future__ import annotations

import html
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAGES = ROOT / "pages"

NAV = [
    ("/", "Home"),
    ("/docs", "Docs"),
    ("/pricing", "Pricing"),
    ("/cloud", "Cloud"),
    ("/cloud/keys", "API keys"),
    ("/cloud/usage", "Usage"),
    ("/cloud/sandboxes", "Sandboxes"),
    ("/security", "Security"),
    ("/status", "Status"),
]

FOOTER_NAV = [
    ("/docs", "Docs"),
    ("/security", "Security"),
    ("/status", "Status"),
    ("https://github.com/fedoragobrowse-design/AIec", "GitHub"),
]

SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — AgentForge</title>
<meta name="description" content="{description}">
<meta property="og:title" content="{title} — AgentForge">
<meta property="og:description" content="{description}">
<meta property="og:type" content="website">
<link rel="stylesheet" href="/assets/site.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><circle cx='8' cy='8' r='6' fill='%234ade80'/></svg>">
</head>
<body>
<header class="site">
  <div class="wrap">
    <a class="brand" href="/"><span class="dot"></span>AgentForge</a>
    <nav class="site">{nav}</nav>
  </div>
</header>
<main><div class="wrap">
{body}
</div></main>
<footer class="site">
  <div class="wrap">
    <span>Computers for AI agents.</span>
    <nav>{footer_nav}</nav>
  </div>
</footer>
</body>
</html>
"""


def render_nav(current: str) -> str:
    parts = []
    for href, label in NAV:
        mark = ' aria-current="page"' if href == current else ""
        parts.append(f'<a href="{html.escape(href)}"{mark}>{html.escape(label)}</a>')
    return "\n      ".join(parts)


def render_footer_nav() -> str:
    return "\n      ".join(
        f'<a href="{html.escape(href)}">{html.escape(label)}</a>' for href, label in FOOTER_NAV
    )


def page_path(route: str) -> Path:
    if route == "/":
        return ROOT / "index.html"
    return ROOT / f"{route.strip('/')}/index.html"


def main() -> int:
    rendered = 0
    for route, _label in NAV:
        source = PAGES / (route.strip("/").replace("/", "-") or "home")
        if not source.with_suffix(".html").is_file():
            raise SystemExit(f"missing page fragment for {route}: {source}.html")
        fragment = source.with_suffix(".html").read_text(encoding="utf-8")

        title = _meta(fragment, "title", route)
        description = _meta(fragment, "description", "AgentForge — computers for AI agents.")

        page_path(route).parent.mkdir(parents=True, exist_ok=True)
        page_path(route).write_text(
            SHELL.format(
                title=html.escape(title),
                description=html.escape(description),
                nav=render_nav(route),
                footer_nav=render_footer_nav(),
                body=fragment,
            ),
            encoding="utf-8",
        )
        rendered += 1
    print(f"rendered {rendered} pages into {ROOT}")
    return 0


def _meta(fragment: str, key: str, fallback: str) -> str:
    """Reads a <!-- meta:key=value --> directive from the top of a fragment."""
    marker = f"<!-- meta:{key}="
    for line in fragment.splitlines():
        stripped = line.strip()
        if stripped.startswith(marker):
            return stripped[len(marker) :].split("-->", 1)[0].strip()
    return fallback


if __name__ == "__main__":
    raise SystemExit(main())
