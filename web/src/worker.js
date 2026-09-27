// AgentForge website + Cloudflare Worker.
//
// Serves the static site from the assets binding and proxies the public API
// hostname to the AgentForge control plane. Two hostnames, one Worker:
//
//   aiec.gobrowse.dev    -> the static site
//   api.aiec.gobrowse.dev -> proxy to the private AgentForge origin
//
// The origin is configured as a secret-bounded service binding or a custom
// domain; it is never exposed directly to the internet, which is the point.

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
      const origin = (env.AGENTFORGE_API_ORIGIN || DEFAULT_API_ORIGIN).replace(/\/+$/, "");
      // Fail closed rather than proxying to an unset or obviously wrong origin.
      if (!/^https:\/\//.test(origin)) {
        return withSecurityHeaders(
          new Response("API origin is not configured", { status: 503 }),
        );
      }
      const target = origin + url.pathname + url.search;
      const headers = new Headers(request.headers);
      // Trust Cloudflare's edge, and preserve the real client address upstream.
      headers.set("x-forwarded-proto", "https");
      const clientIp = request.headers.get("cf-connecting-ip");
      if (clientIp) headers.set("x-real-ip", clientIp);
      headers.delete("host");

      const upstream = await fetch(new Request(target, {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD"
          ? undefined
          : request.body,
        redirect: "manual",
      }));

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
      return withSecurityHeaders(await env.ASSETS.fetch(request));
    }
    return withSecurityHeaders(
      new Response("Site assets are not bound", { status: 503 }),
    );
  },
};
