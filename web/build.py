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
import shutil
from pathlib import Path
ROOT = Path(__file__).resolve().parent
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

SOURCE_NAMES = ("build.py", "pages", "data", "src", "__pycache__")
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

CONSOLE_ROUTES: set[str] = set()

SITE_URL = "https://aiec.gobrowse.dev"
GITHUB_URL = "https://github.com/fedoragobrowse-design/AIec"


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
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{title} — AIec">
<meta property="og:description" content="{description}">
<meta property="og:type" content="website">
<meta property="og:url" content="{canonical}">
<meta property="og:site_name" content="AIec">
<meta property="og:image" content="{og_image}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="AIec — run agents safely, reproduce failures, compare versions.">
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
        title=html.escape(f"{status} {spec['title'].split('—')[0].strip()}"),
        description=html.escape(spec["headline"]),
        canonical=f"{SITE_URL}/{status}",
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
        f"  <url><loc>{SITE_URL}{route}</loc></url>\n" for route in routes
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
viewBox="0 0 1200 630" role="img" aria-label="AIec — run agents safely, reproduce \
failures, compare versions.">
  <rect width="1200" height="630" fill="#edf0f4"/>
  <rect x="0" y="0" width="1200" height="8" fill="#1b44e8"/>
  <g font-family="Archivo, Helvetica, Arial, sans-serif" fill="#0f1a2e">
    <text x="80" y="150" font-size="86" font-weight="700" letter-spacing="-2">AIec</text>
    <text x="80" y="240" font-size="52" font-weight="650" letter-spacing="-1">Run agents safely.</text>
    <text x="80" y="304" font-size="52" font-weight="650" letter-spacing="-1">Reproduce failures.</text>
    <text x="80" y="368" font-size="52" font-weight="650" letter-spacing="-1">Compare versions.</text>
    <text x="80" y="452" font-size="27" fill="#5b6b84" font-family="IBM Plex Mono, \
monospace">Disposable, isolated machines for AI agents.</text>
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
                canonical=f"{SITE_URL}{route}",
                og_image=og_image,
                nav=render_console_nav(route) if is_console else render_nav(route),
                footer_nav=render_footer_nav(),
                rail=render_rail(fragment) if not is_console else "",
                wide=" content--wide" if "<!-- wide -->" in fragment else "",
                body=body,
            ),
            encoding="utf-8",
        )
        rendered.append(route)

    pages = render_error_pages()
    (DIST / "sitemap.xml").write_text(render_sitemap(rendered), encoding="utf-8")
    (DIST / "robots.txt").write_text(render_robots(), encoding="utf-8")
    assert_publishable(DIST)
    print(
        f"rendered {len(rendered)} pages and {pages} error pages into {DIST}, "
        f"plus sitemap.xml, robots.txt, {copied} static assets and "
        f"{og_image.rsplit('/', 1)[-1]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
