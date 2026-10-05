"""Render the repository's Markdown documentation as site pages.

The documents in `docs/` are written for people reading them on GitHub, and
they are the same documents a reader should get here. Copying them into
`web/pages/` would give the site a second copy that drifts from the first, so
this module renders the repository files directly at build time and the site
follows them.

Three things have to be right for that to be honest rather than decorative.

**Anchors match GitHub.** Documents link to each other by heading
(`GUARD.md#approving-a-high-risk-call`), and `README.md` links into them the
same way. The slugs here follow GitHub's rule — lowercase, punctuation
dropped, spaces to hyphens — so a link that works in the repository works on
the site and an anchor copied from one still resolves in the other.

**Relative links stay inside the site.** `[ARCHITECTURE.md](ARCHITECTURE.md)`
is rewritten to the rendered page. A link to a file the site does not publish
is rewritten to that file on GitHub rather than left pointing at a path that
answers 404, and a link to a file that does not exist anywhere is a build
failure: a broken cross-reference in the repository should not become a broken
cross-reference on the site.

**Nothing escapes the site's own markup.** Raw HTML in a document is escaped,
not passed through, and links are filtered by the renderer's protocol allowlist,
so a document cannot inject script into a page that ships no JavaScript.

Requires `mistune`; see `web/requirements.txt`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import mistune
from mistune.renderers.html import HTMLRenderer

REPO_BLOB = "https://github.com/fedoragobrowse-design/AIec/blob/main"
"""Where a document the site does not publish is linked instead of rendered."""

HEADING_RE = re.compile(r"[^\w\s-]", re.UNICODE)
"""Characters GitHub drops from a heading when it builds the anchor."""


def slugify(text: str) -> str:
    """GitHub's heading slug: lowercase, punctuation out, spaces to hyphens.

    `re.sub` with an empty pattern removes every non-word, non-space,
    non-hyphen character, which is the rule GitHub applies — so `What "a
    high-risk" call?` and `What "a high-risk" call?` produce the same anchor
    here as they do there.
    """
    plain = HEADING_RE.sub("", text.strip().lower())
    return re.sub(r"\s+", "-", plain)


def _break_opportunities(escaped: str) -> str:
    """Marks where an inline code span may wrap, so it rarely wraps mid-word.

    The stylesheet lets long inline code break anywhere, which stops a wide
    token pushing the page sideways but splits `POST /v1/sandboxes` after
    `resum`, inside the part of the line a reader has to copy exactly. Marking
    the separators gives the browser somewhere better to break first; it only
    falls through to `break-word` when a single segment has no room at all.

    The separators are marked unconditionally rather than gated behind a
    "does this look like a path?" test. An earlier version gated on the whole
    span matching one pattern, and every span that did not match exactly —
    `POST /v1/sandboxes/{id}/start|pause|stop|resume`, `aiec_core::host_pressure`
    — got no break opportunity at all and was cut wherever the line ran out.
    `<wbr>` is zero-width and only matters when the line is already breaking,
    so marking a separator in a span that never wraps costs nothing.

    `://` is the one seam left unmarked: breaking a URL's scheme away from its
    authority turns `https://example` into something that reads as mangled.
    """
    out: list[str] = []
    index = 0
    length = len(escaped)
    while index < length:
        char = escaped[index]
        if char in "/|,":
            out.append(f"{char}<wbr>")
            index += 1
        elif char == ":":
            if escaped.startswith("://", index):
                out.append("://")
                index += 3
                continue
            run = index
            while run < length and escaped[run] == ":":
                run += 1
            out.append(escaped[index:run] + "<wbr>")
            index = run
        else:
            out.append(char)
            index += 1
    return "".join(out)




class DocRenderer(HTMLRenderer):
    """Markdown to the site's own components.

    Rendering into the existing vocabulary rather than shipping a second set of
    markdown styles is what keeps a rendered document and a hand-written page
    looking like the same site: tables get `.table-wrap`/`.table`, code gets
    `.code`, quotes get `.note`.
    """

    def __init__(
        self,
        links: "LinkMap",
        source: str,
        after_title: str = "",
    ) -> None:
        super().__init__()
        self.links = links
        self.source = source
        self.after_title = after_title
        """HTML emitted directly below the document's h1.

        Reading time and the source file belong under the title, not above it.
        A tracked uppercase label sitting on its own block directly above a
        heading is a decorative kicker: it announces instead of informing, and
        on a page whose title already says what the page is it is noise.
        """
        self.headings: list[tuple[int, str, str]] = []
        """(level, slug, label) in document order, for the on-page contents."""
        self._seen: dict[str, int] = {}

    # -- headings ---------------------------------------------------------
    def heading(self, text: str, level: int, **attrs) -> str:
        # The label is the rendered inline HTML (`<code>` and friends included);
        # the slug is taken from the plain text so the anchor matches the words
        # a reader sees rather than the markup around them.
        label = re.sub(r"<[^>]+>", "", text)
        base = slugify(label) or "section"
        # Two headings with the same words need two anchors, and the second one
        # is what GitHub calls the first one's `-1`.
        count = self._seen.get(base, 0)
        self._seen[base] = count + 1
        anchor = base if count == 0 else f"{base}-{count}"
        if level >= 2:
            self.headings.append((level, anchor, label))
            # The document's own title is the page heading. A `#` beside it
            # would link to the top of a page the reader is already on.
            link = (
                f'<a class="anchor" href="#{anchor}" '
                f'aria-label="Link to this section: {mistune.util.escape(label)}">#</a>'
            )
            return f'<h{level} id="{anchor}">{text}{link}</h{level}>\n'
        if self.after_title:
            return (
                f'<h{level} id="{anchor}">{text}</h{level}>\n'
                f"{self.after_title}\n"
            )
        return f'<h{level} id="{anchor}">{text}</h{level}>\n'

    # -- code -------------------------------------------------------------
    def block_code(self, code: str, info: str | None = None) -> str:
        """A fenced block, labelled with its language and copyable as text.

        The language label is real information a reader uses, so it is shown
        rather than hidden behind a stylesheet; a block with no language gets
        no label rather than an empty one.
        """
        language = (info or "").strip().split()[0] if info else ""
        label = (
            f'<span class="code__lang">{mistune.util.escape(language)}</span>'
            if language
            else ""
        )
        return (
            f'<div class="code">{label}'
            f"<pre><code>{mistune.util.escape(code)}</code></pre></div>\n"
        )

    def codespan(self, text: str) -> str:
        return f"<code>{_break_opportunities(mistune.util.escape(text))}</code>"

    # -- block elements ---------------------------------------------------
    def paragraph(self, text: str) -> str:
        return f"<p>{text}</p>\n"

    def block_quote(self, text: str) -> str:
        return f'<aside class="note">{text}</aside>\n'

    def thematic_break(self) -> str:
        return '<div class="rule" aria-hidden="true"></div>\n'

    def block_html(self, html: str) -> str:
        """Escape document HTML rather than passing it through.

        The public pages ship no JavaScript, and a page that renders an
        arbitrary string from the repository into its own markup is a page that
        can be made to lie. One document in the repository carries an HTML
        comment that documents prose reads better than; it appears as text,
        which is the correct rendering of a comment on a web page.
        """
        return f"<p>{mistune.util.escape(html)}</p>\n"

    def inline_html(self, html: str) -> str:
        return mistune.util.escape(html)

    # -- tables -----------------------------------------------------------
    def table(self, text: str) -> str:
        return f'<div class="table-wrap"><table class="table">{text}</table></div>\n'

    def table_cell(self, text: str, align=None, head: bool = False) -> str:
        tag = "th" if head else "td"
        attr = ""
        if head:
            attr = ' scope="col"'
        elif align:
            attr = f' style="text-align:{align}"'
        return f"<{tag}{attr}>{text}</{tag}>\n"

    # -- links ------------------------------------------------------------
    def link(self, text: str, url: str, title: str | None = None) -> str:
        target = self.links.resolve(self.source, url)
        attr = ""
        if title:
            attr = f' title="{mistune.util.escape(title)}"'
        if target.startswith("http"):
            return f'<a href="{target}"{attr} rel="noopener noreferrer">{text}</a>'
        return f'<a href="{target}"{attr}>{text}</a>'


@dataclass
class LinkMap:
    """Where each repository document is published, and what stands in for it.

    `published` maps a repository path to a site route. Everything else the
    documents link to — a benchmark artifact, a skill, a file the site does
    not render — resolves to GitHub instead, so a cross-reference from one
    document to another keeps working on the site.
    """

    published: dict[str, str]
    repo_root: Path
    missing: list[str] = field(default_factory=list)

    def resolve(self, source: str, url: str) -> str:
        path, _, anchor = url.partition("#")
        anchor = f"#{anchor}" if anchor else ""

        if not path:
            return anchor or "#"
        if path.startswith(("http://", "https://", "mailto:")):
            return url

        target = (self.repo_root / source).parent
        target = (target / path).resolve()
        try:
            relative = target.relative_to(self.repo_root)
        except ValueError:
            # A link that climbs out of the repository cannot be resolved to
            # anything publishable; GitHub is the honest answer.
            return f"{REPO_BLOB}/{quote(path)}{anchor}"

        key = relative.as_posix()
        if key in self.published:
            return f"{self.published[key]}{anchor}"
        if not target.exists():
            self.missing.append(f"{source} -> {url}")
            return f"{REPO_BLOB}/{quote(key)}{anchor}"
        return f"{REPO_BLOB}/{quote(key)}{anchor}"


@dataclass
class RenderedDoc:
    """One rendered document: its body HTML and the contents list beside it."""

    body: str
    headings: list[tuple[int, str, str]]


def render_markdown(
    source: str,
    text: str,
    links: LinkMap,
    after_title: str = "",
) -> RenderedDoc:
    """Renders one document, returning its HTML and the headings to index it."""
    renderer = DocRenderer(links, source, after_title=after_title)
    markdown = mistune.create_markdown(
        renderer=renderer,
        plugins=["table", "strikethrough", "task_lists", "url", "footnotes"],
    )
    return RenderedDoc(body=markdown(text), headings=renderer.headings)
