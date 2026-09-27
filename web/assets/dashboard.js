/* Cloud dashboard behaviour.
 *
 * Talks to the same public API an SDK would use, through the same origin, so
 * nothing here is a privileged back door. The session token is kept in
 * sessionStorage only: this is an operator console for one tenant, not a
 * long-lived login, and there is no cookie to steal cross-site.
 */
(() => {
  "use strict";

  const API = "/v1";
  const TOKEN_KEY = "agentforge.session";

  const $ = (selector) => document.querySelector(selector);
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const token = () => sessionStorage.getItem(TOKEN_KEY);

  async function call(method, path, body) {
    const headers = { "content-type": "application/json" };
    const current = token();
    if (current) headers.authorization = `Bearer ${current}`;
    const response = await fetch(API + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { error: { message: text } };
      }
    }
    if (!response.ok) {
      const error = new Error(
        (payload && payload.error && payload.error.message) ||
          `Request failed (${response.status})`,
      );
      error.status = response.status;
      error.code = payload && payload.error && payload.error.code;
      throw error;
    }
    return payload;
  }

  function say(target, message, kind) {
    target.innerHTML = "";
    if (!message) return;
    target.appendChild(el("div", `msg msg--${kind}`, message));
  }

  function shortTime(value) {
    if (!value) return "—";
    const when = new Date(value);
    return Number.isNaN(when.getTime()) ? "—" : when.toISOString().replace("T", " ").slice(0, 16);
  }

  /* ------------------------------------------------------------- session */

  function signedIn(account) {
    $("#auth-panel").hidden = true;
    $("#dash-panel").hidden = false;
    $("#who").textContent = `${account.name} · ${account.id.slice(0, 8)}`;
    refresh();
  }

  function signedOut(message) {
    $("#dash-panel").hidden = true;
    $("#auth-panel").hidden = false;
    sessionStorage.removeItem(TOKEN_KEY);
    if (message) say($("#auth-message"), message, "err");
  }

  /* -------------------------------------------------------------- signup */

  $("#signup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const target = $("#auth-message");
    say(target, "");
    try {
      const result = await call("POST", "/account", {
        invite: $("#invite").value,
        name: $("#account-name").value,
      });
      sessionStorage.setItem(TOKEN_KEY, result.key.key);
      signedIn(result.account);
    } catch (error) {
      signedOut(error.message);
    }
  });

  /* ------------------------------------------------------ key management */

  async function loadKeys() {
    const list = $("#key-rows");
    list.innerHTML = "";
    let result;
    try {
      result = await call("GET", "/keys");
    } catch (error) {
      if (error.status === 401) return signedOut("Your session key is no longer valid.");
      list.appendChild(el("p", "empty", error.message));
      return;
    }
    const keys = (result && result.keys) || [];
    $("#key-count").textContent = `${keys.length} key${keys.length === 1 ? "" : "s"}`;
    if (!keys.length) {
      list.appendChild(el("p", "empty", "No keys yet. Create one to get started."));
      return;
    }
    for (const key of keys) {
      const row = el("div", "row-i");
      const main = el("div", "row-i__main");
      main.appendChild(el("div", "row-i__name", key.name || "unnamed key"));
      const state = key.active ? "active" : key.revoked_at ? "revoked" : "expired";
      main.appendChild(
        el(
          "div",
          "row-i__meta",
          `${state} · ${(key.scopes || []).join(", ")} · created ${shortTime(key.created_at)}`,
        ),
      );
      row.appendChild(main);
      if (key.active) {
        const revoke = el("button", "linkbtn", "Revoke");
        revoke.type = "button";
        revoke.addEventListener("click", async () => {
          revoke.disabled = true;
          try {
            await call("DELETE", `/keys/${key.id}`);
            await loadKeys();
          } catch (error) {
            say($("#key-message"), error.message, "err");
            revoke.disabled = false;
          }
        });
        const act = el("div", "row-i__act");
        act.appendChild(revoke);
        row.appendChild(act);
      }
      list.appendChild(row);
    }
  }

  $("#create-key-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const target = $("#key-message");
    say(target, "");
    const reveal = $("#key-reveal");
    reveal.innerHTML = "";
    try {
      const created = await call("POST", "/keys", { name: $("#key-name").value || "unnamed key" });
      reveal.appendChild(el("span", "reveal__head", "Copy this key now"));
      const value = el("code", "reveal__value", created.key);
      reveal.appendChild(value);
      const copy = el("button", "btn", "Copy key");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(created.key);
          say(target, "Key copied to the clipboard.", "ok");
        } catch {
          say(target, "Copy the key above manually.", "err");
        }
      });
      reveal.appendChild(copy);
      reveal.appendChild(
        el("p", "", "AgentForge stores only a hash, so this is the only time it is shown."),
      );
      $("#key-name").value = "";
      await loadKeys();
    } catch (error) {
      say(target, error.message, "err");
    }
  });

  /* --------------------------------------------------- sandboxes / usage */

  async function loadSandboxes() {
    const list = $("#box-rows");
    list.innerHTML = "";
    let sandboxes = [];
    try {
      sandboxes = (await call("GET", "/sandboxes")) || [];
    } catch (error) {
      if (error.status === 401) return signedOut("Your session key is no longer valid.");
      list.appendChild(el("p", "empty", error.message));
      return;
    }
    const rows = Array.isArray(sandboxes) ? sandboxes : sandboxes.sandboxes || [];
    // The API returns a tenant's full history; the console shows what is
    // actually running, which is what someone checking for leaks needs.
    const sandboxes_ = rows.filter((row) => row.state !== "destroyed" && row.state !== "failed");
    $("#box-count").textContent = `${sandboxes_.length} live`;
    if (!sandboxes_.length) {
      list.appendChild(
        el("p", "empty", "No sandboxes. Create one with the SDK or the API — that is the normal path."),
      );
      return;
    }
    for (const box of sandboxes_) {
      const row = el("div", "row-i");
      const main = el("div", "row-i__main");
      main.appendChild(el("div", "row-i__name", box.id.slice(0, 8)));
      main.appendChild(
        el(
          "div",
          "row-i__meta",
          `${box.runtime} · ${box.cpu} vCPU · ${box.memory_mb} MB · ${box.state} · ${shortTime(box.created_at)}`,
        ),
      );
      row.appendChild(main);
      const destroy = el("button", "linkbtn", "Destroy");
      destroy.type = "button";
      destroy.addEventListener("click", async () => {
        destroy.disabled = true;
        try {
          await call("DELETE", `/sandboxes/${box.id}`);
          await refresh();
        } catch (error) {
          say($("#box-message"), error.message, "err");
          destroy.disabled = false;
        }
      });
      const act = el("div", "row-i__act");
      act.appendChild(destroy);
      row.appendChild(act);
      list.appendChild(row);
    }
  }

  async function loadUsage() {
    const target = $("#usage-meters");
    try {
      const usage = await call("GET", "/usage");
      const rows = usage && (usage.usage || usage) || [];
      const list = Array.isArray(rows) ? rows : [];
      target.innerHTML = "";
      if (!list.length) {
        target.appendChild(el("p", "empty", "No usage recorded yet."));
        return;
      }
      for (const entry of list.slice(0, 20)) {
        const row = el("div", "row-i");
        const main = el("div", "row-i__main");
        main.appendChild(el("div", "row-i__name", entry.metric || "usage"));
        main.appendChild(
          el("div", "row-i__meta", `${entry.quantity ?? 0} ${entry.unit || ""}`.trim()),
        );
        row.appendChild(main);
        target.appendChild(row);
      }
    } catch (error) {
      if (error.status === 401) return signedOut("Your session key is no longer valid.");
      target.innerHTML = "";
      target.appendChild(el("p", "empty", error.message));
    }
  }

  async function loadHealth() {
    const target = $("#health-rows");
    try {
      const response = await fetch("/ready", { cache: "no-store" });
      const payload = await response.json();
      target.innerHTML = "";
      const checks = (payload && payload.checks) || {};
      const row = el("div", "row-i");
      const main = el("div", "row-i__main");
      main.appendChild(el("div", "row-i__name", "control plane"));
      main.appendChild(
        el("div", "row-i__meta", Object.entries(checks).map(([k, v]) => `${k}: ${v}`).join(" · ")),
      );
      row.appendChild(main);
      const badge = el(
        "div",
        `row-i__meta ${response.ok ? "state--on" : "state--off"}`,
        response.ok ? "ready" : "not ready",
      );
      row.appendChild(badge);
      target.appendChild(row);
    } catch {
      target.innerHTML = "";
      target.appendChild(el("p", "empty", "Service status is unavailable."));
    }
  }

  async function refresh() {
    await Promise.all([loadKeys(), loadSandboxes(), loadUsage(), loadHealth()]);
  }

  $("#signout").addEventListener("click", () => signedOut());

  /* Resume an existing session on reload. */
  (async () => {
    if (!token()) return signedOut();
    try {
      const account = await call("GET", "/account");
      signedIn(account);
    } catch {
      signedOut();
    }
  })();
})();
