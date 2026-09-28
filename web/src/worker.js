// AIec website + Cloudflare Worker.
//
// AIec is open source: there is no hosted API. This Worker serves the
// documentation site and nothing else. A reader who wants sandboxes runs the
// control plane on their own hardware, which is the whole point of the project.
//
// Errors are part of the product, not an afterthought: a missing page serves the
// site's own 404 rather than a generic one, so a broken link still lands
// somewhere useful.

/** Human-readable cause and next step for each status this Worker can emit. */
const ERROR_COPY = {
  403: {
    headline: "You do not have access to this",
    detail: "The resource belongs to another tenant, or the key is not scoped for it.",
    retry: false,
  },
  404: {
    headline: "There is nothing at this address",
    detail: "The page moved, or the link was typed by hand.",
    retry: false,
  },
  500: {
    headline: "Something broke on our side",
    detail: "A fault in AIec, not in your request. Running sandboxes are unaffected.",
    retry: true,
  },
  503: {
    headline: "No local worker can take a sandbox right now",
    detail: "Every worker is at capacity or draining. Work is not moved to a cloud provider.",
    retry: true,
  },
};

/** Falls back to a real error page, then to a minimal styled document. */
async function siteError(env, status) {
  const copy = ERROR_COPY[status] || ERROR_COPY[500];
  if (env.ASSETS) {
    const page = await env.ASSETS.fetch(new Request(new URL(`/${status}.html`, "https://aiec.gobrowse.dev")));
    if (page.status === 200) {
      return new Response(page.body, { status, headers: page.headers });
    }
  }
  const retry = copy.retry
    ? '<p><a href="/status">Service status</a> · <a href="/">Home</a></p>'
    : '<p><a href="/docs">Docs</a> · <a href="/">Home</a></p>';
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
      `<meta name="viewport" content="width=device-width, initial-scale=1">` +
      `<title>${status} — AIec</title>` +
      `<link rel="stylesheet" href="/assets/site.css"></head><body>` +
      `<div class="shell"><main class="content"><h1>${status} — ${copy.headline}</h1>` +
      `<p class="lede">${copy.detail}</p>${retry}</main></div></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } },
  );
}

/** A JSON error envelope, for callers that are programs rather than readers. */


/**
 * Builds a Response that never caches and carries hardening headers.
 * Static assets are served by the assets binding, so this only shapes the
 * error and redirect paths.
 */
function withSecurityHeaders(response) {
  const out = new Response(response.body, response);
  out.headers.set("X-Content-Type-Options", "nosniff");
  out.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  out.headers.set("X-Frame-Options", "DENY");
  out.headers.set(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
  return out;
}

export default {
  /**
   * @param {Request} request
   * @param {Record<string, unknown>} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // The site itself. AIec is open source, so there is no API to proxy: a
    // reader who wants sandboxes runs the control plane on their own hardware.
    if (env.ASSETS) {
      const asset = await env.ASSETS.fetch(request);
      // Cloudflare answers a miss with its own 404 before this runs, so a real
      // error page is only reached through the configured 404 handling. A 5xx
      // from the asset store is ours to explain.
      if (asset.status >= 500) {
        return withSecurityHeaders(await siteError(env, asset.status));
      }
      return withSecurityHeaders(asset);
    }
    return withSecurityHeaders(await siteError(env, 503));
  },
};
