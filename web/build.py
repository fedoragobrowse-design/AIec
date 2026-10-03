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

CONSOLE_ROUTES: set[str] = set()

NAV = [
    ("/", "Home"),
    ("/docs", "Docs"),
    ("/mcp", "MCP"),
    ("/pricing", "Pricing"),
    ("/security", "Security"),
    ("/status", "Status"),
]
FOOTER_NAV = [
    ("/docs", "Docs"),
    ("/mcp", "MCP"),
    ("/security", "Security"),
    ("/status", "Status"),
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

FOOTER_CONSOLE_ROUTES: set[str] = set()

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
      <span class="rail__caption">Deployment</span>
      <dl>
        <dt>hosting</dt><dd>self-hosted</dd>
        <dt>license</dt><dd>Apache 2.0</dd>
        <dt>capacity</dt><dd>your hosts</dd>
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

# Error pages are rendered from the same shell as everything else, so a reader
# who lands on a 404 sees the site rather than a server's default page. Each
# entry says what happened and what to do next; none of them is a dead end.
ERROR_PAGES: dict[int, dict[str, str]] = {
    403: {
        "title": "403 — Forbidden",
        "headline": "You do not have access to this",
        "body": """<p class="lede">This resource belongs to another tenant, or the key you
presented is not scoped for it. AIec never reveals whether a resource exists
to a caller who cannot see it.</p>""",
        "actions": '<a class="btn btn--solid" href="/docs">Read the docs</a>'
        '<a class="btn" href="https://github.com/fedoragobrowse-design/AIec">Repository</a>',
    },
    404: {
        "title": "404 — Not found",
        "headline": "There is nothing at this address",
        "body": """<p class="lede">The page moved, or the link that brought you here was
typed by hand. The sections below are the ones people usually want.</p>""",
        "actions": '<a class="btn btn--solid" href="/">Home</a>'
        '<a class="btn" href="/docs">Docs</a>'
        '<a class="btn" href="/mcp">MCP</a>',
    },
    429: {
        "title": "429 — Too many requests",
        "headline": "Too many requests",
        "body": """<p class="lede">The site is being asked for more than it will
answer at once. Wait a moment and try again.</p>""",
        "actions": '<a class="btn btn--solid" href="/docs">Read the docs</a>'
        '<a class="btn" href="/">Home</a>',
    },
    500: {
        "title": "500 — Internal error",
        "headline": "The site failed to build a page",
        "body": """<p class="lede">This is a fault in the website, not in your
request and not in your cluster. Try again shortly.</p>""",
        "actions": '<a class="btn btn--solid" href="/">Home</a>'
        '<a class="btn" href="/docs">Read the docs</a>',
    },
    503: {
        "title": "503 — Unavailable",
        "headline": "No local worker can take a sandbox right now",
        "body": """<p class="lede">Every worker in the cluster is out of capacity or
draining. AIec does not quietly move a workload to a cloud provider when the
local cluster is full, so the request failed here instead.</p>""",
        "actions": '<a class="btn btn--solid" href="/docs">Read the docs</a>'
        '<a class="btn" href="/status">Status</a>',
    },
}


def render_error_page(status: int) -> str:
    """Renders one error page in the site shell, with no rail and no nav state."""
    spec = ERROR_PAGES[status]
    body = f"""<h1>{html.escape(spec["title"])}</h1>
<p class="lede" style="font-size:1.5rem;font-weight:650;letter-spacing:-0.02em">
{html.escape(spec["headline"])}</p>
<div class="rule" aria-hidden="true"></div>
{spec["body"]}
<div class="actions">{spec["actions"]}</div>
<div class="grid-3" style="margin-top:44px">
  <div class="block">
    <h3><a href="/docs">Docs</a></h3>
    <p>Quickstart, the API reference, SDK usage and self-hosting.</p>
  </div>
  <div class="block">
    <h3><a href="/mcp">Local MCP</a></h3>
    <p>Give an agent a disposable machine on a cluster you run yourself.</p>
  </div>
  <div class="block">
    <h3><a href="/status">Status</a></h3>
    <p>Whether the control plane and its workers are serving right now.</p>
  </div>
</div>"""
    return SHELL.format(
        title=html.escape(f"{status} {spec['title'].split('—')[0].strip()}"),
        description=html.escape(spec["headline"]),
        nav=render_nav(""),
        footer_nav=render_footer_nav(),
        rail="",
        wide="",
        body=body,
    )


def render_error_pages() -> int:
    """Writes <status>.html for every error code, which the Worker serves."""
    for status in ERROR_PAGES:
        (ROOT / f"{status}.html").write_text(render_error_page(status), encoding="utf-8")
    return len(ERROR_PAGES)

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
    pages = render_error_pages()
    print(f"rendered {rendered} pages and {pages} error pages into {ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
