// AIec website + Cloudflare Worker.
//
// Serves the static site from the assets binding and proxies the public API
// hostname to the AIec control plane. Two hostnames, one Worker:
//
//   aiec.gobrowse.dev    -> the static site
//   api.aiec.gobrowse.dev -> proxy to the private AIec origin
//
// The origin is configured as a secret-bounded service binding or a custom
// domain; it is never exposed directly to the internet, which is the point.
//
// Errors are part of the product, not an afterthought: a missing page serves the
// site's own 404, and a failure at the edge serves a page that says what
// happened and what to try next. The API hostname keeps returning JSON, because
// its callers are programs.

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
  429: {
    headline: "You are going faster than the cluster can go",
    detail: "Public alpha meters per tenant, so a burst is refused rather than queued indefinitely.",
    retry: true,
  },
  500: {
    headline: "Something broke on our side",
    detail: "A fault in AIec, not in your request. Running sandboxes are unaffected.",
    retry: true,
  },
  502: {
    headline: "The API origin did not answer",
    detail: "The control plane is not responding through this edge right now.",
    retry: true,
  },
  503: {
    headline: "No local worker can take a sandbox right now",
    detail: "Every worker is at capacity or draining. Work is not moved to a cloud provider.",
    retry: true,
  },
  504: {
    headline: "The API origin took too long",
    detail: "The control plane accepted the connection but did not respond in time.",
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
function apiError(status, code, message) {
  return new Response(
    JSON.stringify({
      error: {
        code,
        message,
        request_id: crypto.randomUUID(),
        docs: "https://aiec.gobrowse.dev/docs",
      },
    }),
    {
      status,
      headers: { "content-type": "application/json; charset=utf-8" },
    },
  );
}

const DEFAULT_API_ORIGIN = "https://api.aiec.gobrowse.dev";

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
    const isApi = url.hostname.startsWith("api.");

    if (isApi) {
      const origin = (env.AIEC_API_ORIGIN || DEFAULT_API_ORIGIN).replace(/\/+$/, "");
      // Fail closed rather than proxying to an unset or obviously wrong origin.
      if (!/^https:\/\//.test(origin)) {
        return withSecurityHeaders(
          apiError(503, "api_unavailable", "API origin is not configured"),
        );
      }
      const target = origin + url.pathname + url.search;
      const headers = new Headers(request.headers);
      // Trust Cloudflare's edge, and preserve the real client address upstream.
      headers.set("x-forwarded-proto", "https");
      const clientIp = request.headers.get("cf-connecting-ip");
      if (clientIp) headers.set("x-real-ip", clientIp);
      headers.delete("host");

      // A network failure or an origin timeout must not surface as a bare
      // "error 1101": both are reported in the shape a caller can branch on.
      let upstream;
      try {
        upstream = await fetch(new Request(target, {
          method: request.method,
          headers,
          body: request.method === "GET" || request.method === "HEAD"
            ? undefined
            : request.body,
          redirect: "manual",
        }));
      } catch (cause) {
        const timedOut = cause instanceof Error && /timeout/i.test(cause.message);
        return withSecurityHeaders(
          apiError(
            timedOut ? 504 : 502,
            timedOut ? "upstream_timeout" : "upstream_unreachable",
            timedOut
              ? "The AIec control plane accepted the connection but did not respond in time."
              : "The AIec control plane could not be reached from this edge.",
          ),
        );
      }

      // An unreachable origin comes back as a 530 carrying Cloudflare's own
      // HTML, not as a thrown error, so it has to be caught here or a JSON
      // caller receives a web page. A 5xx from the origin is passed through,
      // since that is the control plane's own answer about the request.
      if (upstream.status === 530 || upstream.status === 522) {
        return withSecurityHeaders(
          apiError(
            502,
            "upstream_unreachable",
            "The AIec control plane could not be reached from this edge.",
          ),
        );
      }

      // Do not let the origin overwrite edge security headers.
      const out = new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: new Headers(upstream.headers),
      });
      out.headers.set("X-Content-Type-Options", "nosniff");
      out.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
      return out;
    }

    // Website: hand off to the assets binding, which serves the static build.
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
