# AIec website

Static HTML. No framework, no bundler, no client-side JavaScript on the public
pages — a stranger can read the markup, and a reviewer can change a page without
understanding a build system.

## Layout

    web/build.py      the renderer
    web/render.py     repository Markdown to site HTML
    web/pages/        one fragment per route (page content only)
    web/data/         hand-edited JSON the build renders from
    web/assets/       stylesheet, console script, favicon
    web/src/          the Cloudflare Worker that serves error pages
    web/dist/         build output — this is the publish root

## Documentation

`/docs/` is generated from the repository's own Markdown. There is no second
copy of the prose: `web/data/docs.json` names the documents to publish, in the
order and grouping they should appear, and `web/render.py` turns each one into a
page. Editing `docs/API.md` changes the website.

    web/data/docs.json    which documents, in which group, with what summary
    web/render.py         Mistune renderer: headings, links, code, tables, notes

Each entry needs a `source`, a `slug`, a `title` and a one-line `summary`. The
`title` must equal the document's first `#` heading; if the two disagree the
build fails rather than shipping a sidebar that labels a page differently from
the page itself.

Links inside a published document resolve against the document's own path, so
`[Guard](GUARD.md#privileges)` in `docs/API.md` becomes a link to the rendered
Guard page and the matching anchor. A link to a file that is *not* in the
manifest is rewritten to a GitHub blob URL rather than a route that does not
exist. A link whose target is missing from the repository entirely is a build
failure — the reader gets a 404 either way, but a 404 we can see at build time
is worth more than one we find in a bug report.

Heading anchors follow GitHub's slug rules, including the `-1`, `-2` suffix
for repeated headings, so existing cross-document deep links keep working.

Raw HTML in a published document is escaped rather than passed through, and
external links get `rel="noopener noreferrer"`. A repository document is an
input to the site, not a template for it.

### Reading the docs surface

Document pages are a three-column static layout: navigation, the document, and
an on-page contents list. A document with fewer than three `h2`/`h3` headings
is not given a contents list at all, so it renders as two columns rather than
reserving an empty rail that reads like a layout which failed to load. There is
no client-side JavaScript, so the navigation, contents, and previous/next pager
are all rendered at build time and the contents list is the page's own
`h2`/`h3` structure.

Both rails are sticky, and both cap themselves at the viewport height and
scroll inside themselves — a fifteen-document sidebar is taller than a laptop
screen, and a rail pinned with its last group below the fold is worse than one
that scrolls.

Prose is capped below the column width (about 75 characters) while code and
tables keep the full column — code and tables are scanned, running text is
read, and they want different measures.

Long inline code is allowed to wrap so it cannot push the page sideways, but
`web/render.py` marks the separators of path-shaped and JSON-shaped code spans
with `<wbr>` so the wrap lands between `/`, `,` or `:` rather than inside
`"message"`. Wide code blocks keep an always-painted horizontal scrollbar, so
a line that continues past the edge says so.

## Build and publish


The documentation section is the one part of the build that is not pure
standard library: it needs [Mistune](https://mistune.readthedocs.io/) pinned in
`web/requirements.txt`. Hand-rolling a Markdown parser to avoid one
dependency would mean shipping a subtly wrong one instead.

    python3 -m pip install -r web/requirements.txt
    python3 web/build.py     # writes web/dist/
    npx wrangler deploy     # uploads web/dist/

`web/dist/` is rebuilt from empty on every run and holds only rendered pages,
generated cards and the assets they link to. It is committed, so the deployed
site is reviewable in a diff rather than only on Cloudflare's side.

## Why output has its own directory

Output and source used to share `web/`, and `wrangler.toml` published `"./"`.
The publish root was therefore also the source root, and the deployed site
answered:

    https://aiec.gobrowse.dev/build.py          the renderer's source
    https://aiec.gobrowse.dev/src/worker.js     the worker's source
    https://aiec.gobrowse.dev/pages/home.html  an unrendered fragment,
                                                 <!-- meta: --> directives intact

Two changes close that, and both are load-bearing:

1. `[assets] directory` in `wrangler.toml` points at `./dist`.
2. `build.py` calls `assert_publishable(DIST)` before reporting success and
   refuses to finish if the publish root contains `build.py`, `pages/`, `data/`,
   `src/`, `__pycache__/` or any `.py`/`.pyc` file.

If you add a source directory, add it to `SOURCE_NAMES` in `build.py`.

## Adding a page

1. Write `web/pages/<route>.html` as a fragment — body content only, no shell.
2. Add `("<route>", "Label")` to `NAV` in `build.py`.

The shell, navigation, footer, telemetry rail and `<head>` metadata are applied
by the build, so a new page cannot ship with a stale menu or a missing
canonical URL. `NAV` also drives `sitemap.xml` and the footer, so a route that
exists but is not in `NAV` is not linked from anywhere.

A fragment may carry directives:

    <!-- meta:title=... -->            page title
    <!-- meta:description=... -->      meta description
    <!-- block:rail --> ... <!-- /block -->  override the telemetry rail
    <!-- data:benchmark_table -->      insert a renderer

An unclosed `block` or an unknown `data:` key is a build failure, not a
silently dropped page.

## Published numbers

`web/data/benchmarks.json` and `web/data/capabilities.json` are hand-edited
and reviewed. Nothing writes them — no build step, no benchmark harness. To
change a published number, change the artifact it comes from first, then update
the JSON. See [`../docs/BENCHMARKS.md`](../docs/BENCHMARKS.md).
