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
import json
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import render as docrender
except ModuleNotFoundError as missing:  # pragma: no cover - build guard
    raise SystemExit(
        f"{missing.name} is required to render the documentation: "
        f"pip install -r {ROOT / 'requirements.txt'}"
    ) from missing


PAGES = ROOT / "pages"
DATA = ROOT / "data"
DIST = ROOT / "dist"
"""The publish root. Output goes here and only here.

Sources and output used to share `web/`, which meant publishing the site
published the toolchain: `/build.py` returned the full renderer source and
`/pages/home.html` returned the unrendered fragment with its `<!-- meta: -->`
directives still in place. `dist/` is self-contained — copy it to a web root
and nothing but the site is reachable.
"""

REPO = ROOT.parent
"""The repository the documentation is written in. Documents are rendered from
here rather than copied into `web/pages/`, so there is exactly one of each and
the site cannot drift from what the repository says."""

SOURCE_NAMES = ("build.py", "render.py", "pages", "data", "src", "__pycache__")
"""Source-root entries that must never appear inside the publish root."""


def assert_publishable(root: Path) -> None:
    """Refuses to finish if the publish root would contain source, not just a site.

    A published build that answers `/build.py` is easy to introduce and hard to
    notice, so it is a build failure rather than a note in a README nobody
    reads before deploying.
    """
    leaked = [name for name in SOURCE_NAMES if (root / name).exists()]
    if leaked:
        raise SystemExit(
            f"publish root {root} contains source artifacts: {', '.join(leaked)}. "
            "Copy only this directory to a web root, not its parent."
        )
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".pyc"}:
            raise SystemExit(
                f"{path} would be published. The publish root must contain only "
                "rendered pages and copied assets."
            )



ANCHOR_RE = re.compile(r'id="([^"]+)"')
HREF_RE = re.compile(r'href="([^"]+)"')


def assert_links_resolve(root: Path) -> None:
    """Every internal link and every anchor in the publish root resolves.

    Rendering a repository's Markdown onto a site gives every document a second
    address, and the failure mode is quiet: a heading renamed last week leaves
    a `#section` link pointing at a page with no such section, and the reader is
    told the section does not exist rather than that the link is out of date.
    Checking the rendered bytes catches it here instead.
    """
    broken: list[str] = []
    for path in sorted(root.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        route = "/" + path.relative_to(root).as_posix()
        route = route[: -len("index.html")] if route.endswith("index.html") else route
        anchors = set(ANCHOR_RE.findall(text))
        for href in HREF_RE.findall(text):
            if href.startswith(("http://", "https://", "mailto:", "//", "data:")):
                continue
            target, _, fragment = href.partition("#")
            if not target:  # an anchor into the page it is on
                if fragment not in anchors:
                    broken.append(f"{route} -> #{fragment}")
                continue
            if not target.startswith("/"):
                broken.append(f"{route} -> {href} (not a site path)")
                continue
            candidate = root / target.strip("/")
            if candidate.is_file():  # a stylesheet, an icon, an image
                continue
            page = candidate / "index.html"
            if not page.is_file():
                broken.append(f"{route} -> {target} (no such page)")
                continue
            if fragment and fragment not in set(
                ANCHOR_RE.findall(page.read_text(encoding="utf-8"))
            ):
                broken.append(f"{route} -> {target}#{fragment} (no such section)")
    if broken:
        raise SystemExit(
            "the rendered site links to things it does not contain:\n  "
            + "\n  ".join(sorted(set(broken)))
            + "\nThese are dead ends a reader can reach. Fix the source and rebuild."
        )


CONSOLE_ROUTES: set[str] = set()

SITE_URL = "https://aiec.gobrowse.dev"
GITHUB_URL = "https://github.com/fedoragobrowse-design/AIec"


# Google's HTML-meta ownership check. It has to be on the page Google fetches,
# which is the homepage, and it is cheap and harmless to carry on every page
# — so it goes into all three shells rather than only one, and lives here
# rather than being repeated as a literal at each call site. The token is
# public by design: it is in the served HTML either way.
GOOGLE_SITE_VERIFICATION = (
    '<meta name="google-site-verification" '
    'content="O_CeS2xfccHtgQG77YxAgNW239U8Nu4kV1ozRR57xPc">'
)


def canonical_url(route: str) -> str:
    """The address a visitor is actually on.

    Cloudflare's `auto-trailing-slash` serves `/docs` at `/docs/`, so a
    canonical written from the bare route pointed at the redirect that leads
    here rather than at this page — telling a search engine the real address
    is somewhere else. The sitemap has to name the same address, or the two
    disagree about where the site lives.
    """
    return f"{SITE_URL}/" if route == "/" else f"{SITE_URL}{route.rstrip('/')}/"


def load_data(name: str) -> dict:
    """Loads one reviewed data file. A missing file is a build failure."""
    path = DATA / f"{name}.json"
    if not path.is_file():
        raise SystemExit(f"missing data source: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


NAV = [
    ("/", "Home"),
    ("/docs", "Docs"),
    ("/mcp", "MCP"),
    ("/pricing", "Pricing"),
    ("/security", "Security"),
    ("/status", "Status"),
    ("/benchmarks", "Benchmarks"),
    ("/ecosystem", "Ecosystem"),
    ("/limitations", "Limitations"),
    ("/roadmap", "Roadmap"),
    ("/contributing", "Contribute"),
]

MASTHEAD_NAV = [("/", "Home"), ("/docs", "Docs"), ("/benchmarks", "Benchmarks"),
                ("/ecosystem", "Ecosystem"), ("/security", "Security")]
"""The masthead carries the sections a visitor is most likely to want. The rest
live in the footer and on the pages themselves, so a phone-width header does
not wrap into a wall of links."""

FOOTER_NAV = [
    ("/docs", "Docs"),
    ("/mcp", "MCP"),
    ("/security", "Security"),
    ("/ecosystem", "Ecosystem"),
    ("/benchmarks", "Benchmarks"),
    ("/limitations", "Limitations"),
    ("/roadmap", "Roadmap"),
    ("/contributing", "Contribute"),
]

DASHBOARD_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
{verification}
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
{verification}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — AIec</title>
<meta name="description" content="{description}">
{robots}
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{title} — AIec">
<meta property="og:description" content="{description}">
<meta property="og:type" content="website">
<meta property="og:url" content="{canonical}">
<meta property="og:site_name" content="AIec">
<meta property="og:image" content="{og_image}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="AIec — disposable virtual machines for AI agents.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title} — AIec">
<meta name="twitter:description" content="{description}">
<meta name="twitter:image" content="{og_image}">
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
    <span>Computers for AI agents. Apache 2.0, self-hosted.</span>
    <nav class="colophon__nav">{footer_nav}</nav>
  </div>
</footer>
</body>
</html>
"""

DOCS_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
{verification}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — AIec</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{title} — AIec">
<meta property="og:description" content="{description}">
<meta property="og:type" content="article">
<meta property="og:url" content="{canonical}">
<meta property="og:site_name" content="AIec">
<meta property="og:image" content="{og_image}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="theme-color" content="#edf0f4">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@75..125,400..800&family=IBM+Plex+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="/assets/site.css">
<link rel="icon" href="/assets/mark.svg" type="image/svg+xml">
</head>
<body class="page-doc">
<header class="masthead">
  <div class="masthead__inner">
    <a class="wordmark" href="/"><span class="wordmark__mark"></span>AIec</a>
    <nav class="masthead__nav">
      {nav}
    </nav>
  </div>
</header>
<div class="{shell_class}">
  <nav class="docnav" aria-label="Documentation">
    {nav_html}
  </nav>
  <main class="docmain">
{body}
    {pager}
  </main>
{toc_html}
</div>

<footer class="colophon">
  <div class="colophon__inner">
    <span>Computers for AI agents. Apache 2.0, self-hosted.</span>
    <nav class="colophon__nav">{footer_nav}</nav>
  </div>
</footer>
</body>
</html>
"""


WORDS_PER_MINUTE = 220
"""Reading time is derived from the rendered document's own word count, so the
number on the page is the length of the thing being read and not a guess."""


def load_docs() -> tuple[list[dict], list[dict]]:
    """The curated document set and the groups it is filed under.

    Curated rather than a directory scan on purpose: the repository also holds
    audit records, measurement write-ups and working notes that are real
    documents and are not documentation. Publishing whatever happens to be in
    `docs/` would put a 160 KB defect ledger next to the API reference in a
    sidebar, and the sidebar is how a reader decides what to trust.
    """
    manifest = load_data("docs")
    groups = manifest["groups"]
    known = {group["id"] for group in groups}
    docs = []
    for entry in manifest["docs"]:
        if entry["group"] not in known:
            raise SystemExit(
                f"docs.json: {entry['slug']} names group {entry['group']!r}, "
                f"which is not one of {', '.join(sorted(known))}"
            )
        source = REPO / entry["source"]
        if not source.is_file():
            raise SystemExit(f"docs.json: {entry['slug']} has no source at {source}")
        docs.append(entry)
    slugs = [doc["slug"] for doc in docs]
    if len(set(slugs)) != len(slugs):
        raise SystemExit("docs.json: duplicate slug; each document needs its own route")
    return docs, groups


def doc_route(entry: dict) -> str:
    return f"/docs/{entry['slug']}/"


def doc_reading_time(text: str) -> str:
    words = len(text.split())
    return f"{max(1, round(words / WORDS_PER_MINUTE))} min read"


def content_variant(fragment: str) -> str:
    """The `.content` modifier a hand-written page asked for.

    `<!-- wide -->` gives a page the whole column, which is what a page of
    diagram or code wants. `<!-- prose -->` takes it away, which is what a
    page of running text wants: the column is 662px, and at 17px that is about
    88 characters a line, which is past the point where the eye reliably finds
    the start of the next one. The generated documents set the same cap in
    `.docmain`; this is the hand-written equivalent.
    """
    if "<!-- wide -->" in fragment:
        return " content--wide"
    if "<!-- prose -->" in fragment:
        return " content--prose"
    return ""


def render_doc_nav(docs: list[dict], groups: list[dict], current: str | None) -> str:
    """The documentation sidebar: every document, filed under why you would
    read it. The index link stays at the top because most readers arrive
    through `/docs` and want the way back out."""
    parts = ['<a class="docnav__home" href="/docs">All documentation</a>']
    for group in groups:
        members = [doc for doc in docs if doc["group"] == group["id"]]
        if not members:
            continue
        parts.append(f'<div class="docnav__group"><h2>{html.escape(group["title"])}</h2><ul>')
        for doc in members:
            mark = ' aria-current="page"' if doc["slug"] == current else ""
            parts.append(
                f'<li><a href="{doc_route(doc)}"{mark}>{html.escape(doc["title"])}</a></li>'
            )
        parts.append("</ul></div>")
    return "\n    ".join(parts)


def render_doc_toc(headings: list[tuple[int, str, str]]) -> str:
    """The on-page contents, from the document's own `##` and `###` headings.

    Short documents are not given one. A contents list beside four headings is
    noise that pushes the prose down the page.
    """
    if len(headings) < 3:
        return ""
    rows = [
        f'<li class="doctoc__item doctoc__item--{level}">'
        f'<a href="#{anchor}">{html.escape(label)}</a></li>'
        for level, anchor, label in headings
    ]
    return (
        '<h2 class="doctoc__title">On this page</h2>\n'
        f'    <ol class="doctoc__list">\n      {"".join(rows)}\n    </ol>'
    )


def render_doc_pager(docs: list[dict], current: str) -> str:
    """Previous and next in reading order, so a reader who finishes a document
    at the bottom of the page is told what comes after it rather than being
    left to scroll back up to the sidebar."""
    index = next(i for i, doc in enumerate(docs) if doc["slug"] == current)
    cells = []
    if index:
        previous = docs[index - 1]
        cells.append(
            '<a class="docpager__cell docpager__cell--prev" '
            f'href="{doc_route(previous)}"><span class="docpager__dir">Previous</span>'
            f'<span class="docpager__name">{html.escape(previous["title"])}</span></a>'
        )
    if index + 1 < len(docs):
        following = docs[index + 1]
        cells.append(
            '<a class="docpager__cell docpager__cell--next" '
            f'href="{doc_route(following)}"><span class="docpager__dir">Next</span>'
            f'<span class="docpager__name">{html.escape(following["title"])}</span></a>'
        )
    return f'<nav class="docpager" aria-label="Documents">{"".join(cells)}</nav>'


def render_doc_index() -> str:
    """The document catalogue on `/docs`: every published document, its group,
    and one line on what it answers.

    Grouped rather than one flat alphabetical list, because a reader arriving
    at `/docs` is asking "where do I start" or "how do I do X", not "what
    documents exist". The group order is the reading order.
    """
    docs, groups = load_docs()
    out = []
    for group in groups:
        members = [doc for doc in docs if doc["group"] == group["id"]]
        if not members:
            continue
        out.append(
            f'<div class="docgroup"><h2 id="{html.escape(group["id"])}">'
            f'{html.escape(group["title"])}</h2>'
            f'<p class="docgroup__blurb">{html.escape(group["blurb"])}</p>'
            '<dl class="doclist">'
        )
        for doc in members:
            text = (REPO / doc["source"]).read_text(encoding="utf-8")
            out.append(
                f'<dt><a href="{doc_route(doc)}">{html.escape(doc["title"])}</a></dt>'
                f'<dd>{html.escape(doc["summary"])} '
                f'<span class="doclist__meta">{html.escape(doc_reading_time(text))}</span></dd>'
            )
        out.append("</dl></div>")
    return "\n".join(out)


def render_doc_pages() -> list[str]:
    """Renders every curated document as a page, and returns its routes.

    The manifest title is checked against the document's own first heading:
    a sidebar that calls a document something the document does not call
    itself is the kind of small wrongness a reader trusts less without being
    able to say why.
    """
    docs, groups = load_docs()
    links = docrender.LinkMap(
        published={doc["source"]: doc_route(doc) for doc in docs},
        repo_root=REPO,
    )
    routes: list[str] = []
    for entry in docs:
        source = REPO / entry["source"]
        text = source.read_text(encoding="utf-8")
        heading = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        if not heading or heading.group(1).strip() != entry["title"]:
            raise SystemExit(
                f"{entry['source']}: its first heading is "
                f"{heading.group(1).strip() if heading else None!r}, but "
                f"web/data/docs.json titles it {entry['title']!r}. One of them "
                "is wrong; the sidebar and the page must agree."
            )
        # Reading time and provenance sit under the title. The sidebar already
        # carries the group, and a tracked label on its own block above an h1
        # is a decorative kicker that adds nothing the title does not say.
        meta = (
            f'<p class="docmeta">'
            f'<span>{html.escape(doc_reading_time(text))}</span>'
            f'<a href="{docrender.REPO_BLOB}/{quote(entry["source"])}" '
            f'rel="noopener noreferrer">{html.escape(entry["source"])}</a>'
            f"</p>"
        )
        rendered = docrender.render_markdown(
            entry["source"], text, links, after_title=meta
        )
        group = next(g for g in groups if g["id"] == entry["group"])
        body = rendered.body
        toc = render_doc_toc(rendered.headings)
        page_path(doc_route(entry)).parent.mkdir(parents=True, exist_ok=True)
        page_path(doc_route(entry)).write_text(
            DOCS_SHELL.format(
                title=html.escape(entry["title"]),
                description=html.escape(entry["summary"]),
                canonical=f"{SITE_URL}{doc_route(entry)}",
                verification=GOOGLE_SITE_VERIFICATION,
                og_image=f"{SITE_URL}/assets/og.png",
                nav=render_nav("/docs"),
                footer_nav=render_footer_nav(),
                nav_html=render_doc_nav(docs, groups, entry["slug"]),
                body=body,
                shell_class="docshell docshell--wide"
                if not toc
                else "docshell",
                toc_html=(
                    '<aside class="doctoc" aria-label="On this page">\n'
                    + toc
                    + "\n  </aside>"
                    if toc
                    else ""
                ),
                pager=render_doc_pager(docs, entry["slug"]),
            ),
            encoding="utf-8",
        )
        routes.append(doc_route(entry))
    if links.missing:
        raise SystemExit(
            "these links in the documentation point at files that do not exist:\n  "
            + "\n  ".join(sorted(set(links.missing)))
            + "\nFix the document, or publish it, before the site renders a dead link."
        )
    return routes




def _unclosed_block(fragment: str, name: str) -> bool:
    """True when a block opens and never closes.

    Without this check an unmatched opener silently swallows the rest of the
    page: the body renders empty and the build still reports success.
    """
    start, end = f"<!-- block:{name} -->", f"<!-- /block:{name} -->"
    return fragment.count(start) != fragment.count(end)


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
    for href, label in MASTHEAD_NAV:
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
        return DIST / "index.html"
    return DIST / f"{route.strip('/')}/index.html"

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
        # `spec["title"]` already opens with the status, so taking the text
        # before the dash produced "403 403 — AIec" in the tab.
        title=html.escape(f"{status} {spec['title'].split('—', 1)[1].strip()}"),
        description=html.escape(spec["headline"]),
        # `auto-trailing-slash` serves a root file without a trailing slash, so
        # this page is reached at `/404`, not `/404.html`. It stays out of the
        # sitemap, and it is noindex: a page that only renders when a request
        # failed is not something to offer a search engine.
        canonical=f"{SITE_URL}/{status}",
        robots='<meta name="robots" content="noindex">',
        verification=GOOGLE_SITE_VERIFICATION,
        og_image=f"{SITE_URL}/assets/og.svg",
        nav=render_nav(""),
        footer_nav=render_footer_nav(),
        rail="",
        wide="",
        body=body,
    )


def render_error_pages() -> int:
    """Writes <status>.html for every error code, which the Worker serves."""
    for status in ERROR_PAGES:
        (DIST / f"{status}.html").write_text(render_error_page(status), encoding="utf-8")
    return len(ERROR_PAGES)


def _num(value: float, digits: int = 2) -> str:
    return f"{value:,.{digits}f}"


def _provenance_tag(provenance: str) -> str:
    """Artifact-backed and prose-only are not the same confidence, so they look
    different. A page must not make a hand-written figure look like a run."""
    text = "machine-checked artifact" if provenance == "artifact" else "prose only"
    return f'<span class="prov prov--{html.escape(provenance)}">{text}</span>'


def render_benchmark_table() -> str:
    """Builds the measured table straight from web/data/benchmarks.json."""
    data = load_data("benchmarks")
    rows = []
    for metric in data["metrics"]:
        if "before" in metric and "after" in metric:
            before = _num(metric["before"], 2 if metric["unit"] == "s" else 0)
            after = _num(metric["after"], 2 if metric["unit"] == "s" else 0)
            change = metric["change_pct"]
            # A metric that went up is only good if going up is the point;
            # the data file only carries decreases, so a rise is a regression.
            tone = "good" if change < 0 else "bad"
            delta = f'<span class="delta delta--{tone}">{change:+.1f}%</span>'
            samples = f'{metric["samples_before"]} / {metric["samples_after"]}'
        else:
            before = after = "—"
            delta = "—"
            samples = "—"
        rows.append(
            "<tr>"
            f'<th scope="row">{html.escape(metric["label"])}'
            f'<br><span class="muted mono">{html.escape(metric["unit"])}</span></th>'
            f"<td>{before}</td><td>{after}</td><td>{delta}</td>"
            f"<td>{samples}</td>"
            f"<td>{html.escape(metric.get('value_label', '')) or html.escape(metric['description'])}</td>"
            f"<td>{_provenance_tag(metric['provenance'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_benchmark_table_head() -> str:
    columns = [
        "Metric",
        "Before",
        "After",
        "Change",
        "Samples b / a",
        "Notes",
        "Evidence",
    ]
    return "".join(f'<th scope="col">{html.escape(c)}</th>' for c in columns)


def render_metric_caveats() -> str:
    """The caveats the reviewer wrote, shown next to the numbers they qualify."""
    data = load_data("benchmarks")
    out = []
    for metric in data["metrics"]:
        caveat = metric.get("caveat")
        if not caveat:
            continue
        out.append(
            "<dt>{}</dt><dd>{}</dd>".format(
                html.escape(metric["label"]), html.escape(caveat)
            )
        )
    return "\n".join(out)


def render_capability_rows() -> str:
    data = load_data("capabilities")
    out = []
    for cap in data["capabilities"]:
        out.append(
            '<tr><td><strong>{}</strong><br>'
            '<span class="muted mono">{}</span></td>'
            '<td><span class="status status--{}">{}</span></td>'
            "<td>{}<br><span class=\"muted mono\">{}</span></td></tr>".format(
                html.escape(cap["capability"]),
                html.escape(cap["area"]),
                html.escape(cap["status"]),
                html.escape(cap["status"]),
                html.escape(cap["note"]),
                html.escape(cap["evidence"]),
            )
        )
    return "\n".join(out)


def render_status_terms() -> str:
    """The four status words, with the definition the project holds itself to."""
    data = load_data("capabilities")
    return "\n".join(
        '<dt><span class="status status--{}">{}</span></dt><dd>{}</dd>'.format(
            html.escape(status), html.escape(status), html.escape(meaning)
        )
        for status, meaning in data["status_terms"].items()
    )


def render_capability_summary() -> str:
    """One line per status, counting what is real and what is only a design."""
    grouped = render_capability_by_status()
    counts = {status: len(names) for status, names in grouped.items()}
    order = load_data("capabilities")["status_terms"].keys()
    return "\n".join(
        '<div class="block"><h3><span class="status status--{}">{}</span></h3>'
        '<p class="stat"><strong>{}</strong></p></div>'.format(
            html.escape(status), html.escape(status), counts.get(status, 0)
        )
        for status in order
    )


def render_capability_by_status() -> dict[str, list[str]]:
    data = load_data("capabilities")
    grouped: dict[str, list[str]] = {status: [] for status in data["status_terms"]}
    for cap in data["capabilities"]:
        grouped.setdefault(cap["status"], []).append(cap["capability"])
    return grouped


DATA_RENDERERS = {
    "benchmark_rows": render_benchmark_table,
    "benchmark_heads": render_benchmark_table_head,
    "benchmark_caveats": render_metric_caveats,
    "capability_rows": render_capability_rows,
    "status_terms": render_status_terms,
    "capability_summary": render_capability_summary,
    "doc_index": render_doc_index,
}


def expand_data(body: str) -> str:
    """Substitutes <!-- data:name --> placeholders with rendered data.

    A page that asks for a block the builder does not know is a build failure
    rather than a silently empty section.
    """
    out = body
    for name, render in DATA_RENDERERS.items():
        out = out.replace(f"<!-- data:{name} -->", render())
    # A typo'd placeholder would otherwise reach a reader as literal comment
    # text, or worse as an empty section that looks like missing data.
    if "<!-- data:" in out:
        leftover = out.split("<!-- data:", 1)[1].split("-->", 1)[0]
        raise SystemExit(
            f"unknown data placeholder <!-- data:{leftover} -->. Known "
            f"placeholders: {', '.join(sorted(DATA_RENDERERS))}."
        )
    return out


def render_sitemap(routes: list[str]) -> str:
    """Writes sitemap.xml from the routes that actually rendered."""
    entries = "".join(
        f"  <url><loc>{canonical_url(route)}</loc></url>\n" for route in routes
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}"
        "</urlset>\n"
    )


def render_robots() -> str:
    return f"User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}/sitemap.xml\n"


def render_og_image() -> str:
    """A social card drawn in the site palette, written as an SVG asset."""
    return """<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" \
viewBox="0 0 1200 630" role="img" aria-label="AIec — disposable virtual machines \
for AI agents.">
  <rect width="1200" height="630" fill="#edf0f4"/>
  <rect x="0" y="0" width="1200" height="8" fill="#1b44e8"/>
  <g font-family="Archivo, Helvetica, Arial, sans-serif" fill="#0f1a2e">
    <text x="80" y="150" font-size="86" font-weight="700" letter-spacing="-2">AIec</text>
    <text x="80" y="240" font-size="52" font-weight="650" letter-spacing="-1">Disposable virtual</text>
    <text x="80" y="304" font-size="52" font-weight="650" letter-spacing="-1">machines for AI</text>
    <text x="80" y="368" font-size="52" font-weight="650" letter-spacing="-1">agents.</text>
    <text x="80" y="452" font-size="27" fill="#5b6b84" font-family="IBM Plex Mono, \
monospace">Records what it did. Destroys the machine.</text>
    <text x="80" y="500" font-size="27" fill="#5b6b84" font-family="IBM Plex Mono, \
monospace">Firecracker &#183; Docker &#183; Bubblewrap &#183; self-hosted</text>
    <text x="80" y="566" font-size="24" fill="#1b44e8" font-family="IBM Plex Mono, \
monospace">aiec.gobrowse.dev</text>
  </g>
</svg>
"""


def write_og_image() -> str:
    """Writes the social card as both SVG and PNG, and names the PNG for meta.

    X, LinkedIn and Slack do not render SVG in `og:image`, so a card published
    only as SVG previews as a blank box on the three places a launch post is
    most likely to be shared. The PNG is what the tags point at; the SVG stays
    as the scalable source.
    """
    svg = render_og_image()
    assets = DIST / "assets"
    (assets / "og.svg").write_text(svg, encoding="utf-8")
    try:
        import cairosvg
    except ImportError:
        print(
            "note: cairosvg is not installed, so og.png was not written and "
            "og:image keeps pointing at the SVG. Install cairosvg for a card "
            "that social platforms will render."
        )
        return f"{SITE_URL}/assets/og.svg"
    cairosvg.svg2png(
        bytestring=svg.encode("utf-8"),
        write_to=str(assets / "og.png"),
        output_width=1200,
        output_height=630,
        background_color="#edf0f4",
    )
    return f"{SITE_URL}/assets/og.png"

def copy_assets() -> int:
    """Copies the hand-written static assets into the publish root.

    `assets/` is a source directory: it holds the stylesheet, the console
    script and the favicon that the shell links to by absolute path, so those
    bytes have to travel with the pages. The generated `og.*` cards are written
    straight into `dist/assets` by `write_og_image` and are not copied here.
    """
    source = ROOT / "assets"
    target = DIST / "assets"
    copied = 0
    for path in sorted(source.iterdir()):
        if not path.is_file() or path.name.startswith("og."):
            continue
        (target / path.name).write_bytes(path.read_bytes())
        copied += 1
    return copied


def main() -> int:
    # Rebuilt from empty each time so a route dropped from NAV cannot linger in
    # the publish root, and so `assert_publishable` judges this build alone.
    if DIST.exists():
        shutil.rmtree(DIST)
    (DIST / "assets").mkdir(parents=True)
    copied = copy_assets()
    # Written before the pages so the meta tags can name the PNG, and so a card
    # that failed to render is a visible warning rather than a preview silently
    # pointing at a file that was never written.
    og_image = write_og_image()

    rendered: list[str] = []
    for route, _label in NAV:
        source = PAGES / (route.strip("/").replace("/", "-") or "home")
        fragment_path = source.with_suffix(".html")
        if not fragment_path.is_file():
            raise SystemExit(f"missing page fragment for {route}: {fragment_path}")
        fragment = fragment_path.read_text(encoding="utf-8")
        if _unclosed_block(fragment, "rail"):
            raise SystemExit(
                f"{fragment_path}: <!-- block:rail --> is never closed with "
                "<!-- /block:rail -->. Fixing the build rather than silently "
                "dropping the rest of the page."
            )

        is_console = route in CONSOLE_ROUTES
        shell = DASHBOARD_SHELL if is_console else SHELL
        body = fragment if is_console else expand_data(strip_blocks(fragment, "rail"))
        page_path(route).parent.mkdir(parents=True, exist_ok=True)
        page_path(route).write_text(
            shell.format(
                title=html.escape(_meta(fragment, "title", route)),
                description=html.escape(
                    _meta(fragment, "description", "AIec — computers for AI agents.")
                ),
                canonical=canonical_url(route),
                robots="",
                verification=GOOGLE_SITE_VERIFICATION,
                og_image=og_image,
                nav=render_console_nav(route) if is_console else render_nav(route),
                footer_nav=render_footer_nav(),
                rail=render_rail(fragment) if not is_console else "",
                wide=content_variant(fragment),
                body=body,
            ),
            encoding="utf-8",
        )
        rendered.append(route)

    # Rendered after the hand-written pages so `/docs` can be written as an
    # index over documents that already exist, and after the copy so a
    # document that fails to render cannot leave a half-built publish root.
    doc_routes = render_doc_pages()
    rendered.extend(doc_routes)

    pages = render_error_pages()
    (DIST / "sitemap.xml").write_text(render_sitemap(rendered), encoding="utf-8")
    (DIST / "robots.txt").write_text(render_robots(), encoding="utf-8")
    assert_publishable(DIST)
    print(
        f"rendered {len(rendered) - len(doc_routes)} pages, "
        f"{len(doc_routes)} documents and {pages} error pages into {DIST}, "
        f"plus sitemap.xml, robots.txt, {copied} static assets and "
        f"{og_image.rsplit('/', 1)[-1]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
