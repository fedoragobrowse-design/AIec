# AIec website

Static HTML. No framework, no bundler, no client-side JavaScript on the public
pages — a stranger can read the markup, and a reviewer can change a page without
understanding a build system.

## Layout

    web/build.py      the renderer
    web/pages/        one fragment per route (page content only)
    web/data/         hand-edited JSON the build renders from
    web/assets/       stylesheet, console script, favicon
    web/src/          the Cloudflare Worker that serves error pages
    web/dist/         build output — this is the publish root

## Build and publish

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
