#!/usr/bin/env python3
"""Live §27–32 acceptance against the shipped API, worker, Firecracker and gateway.

Run: python3 scripts/guard-phase3-acceptance.py
Requires prebuilt target/release/{aiec,aiec-server}, PostgreSQL (psycopg), KVM,
unshare, ip, nft, openssl and the deployed guest images. P3_BIN, P3_IMAGES,
P3_FIRECRACKER, P3_PG_ADMIN_URL, P3_ROOT and P3_REPORT override their local
defaults. P3_ROOT ($HOME/aiec/phase3) is where the run's scratch tree is
created and removed; a failed run's report, service logs and Guard journals
are copied to a subdirectory there and the rest of the tree is discarded. It
must be short enough for a Unix socket path (about 100 bytes to the database's
socket), because everything inside is derived from it.
The provider is deliberately permissive: only the production gateway denies.
All runtime networking is confined to a disposable user/network namespace.
Successful reports replace P3_REPORT atomically; failed runs never replace it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROVIDER_IP = "198.18.0.10"
PROVIDER_PORT = 18880
HOSTS = ["mcp.guard.test", "graphql.guard.test", "api.guard.test", "safe.guard.test",
         "unsafe.guard.test"]
# The model endpoint is named on a host of its own. Pointing it at one of the
# probed hosts makes Guard treat that host's traffic as model traffic - "model
# destination requires broker" - which refuses the very Layer 7 rules under
# test before the request is ever inspected.
MODEL_HOST = "model.guard.test"
CASES: list[dict] = []
CLEANUP: list[str] = []
SECRETS: list[str] = []
ROOT: Path
BIN: Path
CP = "https://127.0.0.1:18744"
WORKER = "https://127.0.0.1:19744"
TOKEN = ""
CTX: ssl.SSLContext
PROCESSES: list[tuple[str, subprocess.Popen]] = []
SANDBOXES: list[str] = []
RECEIPTS: list[dict] = []
RECEIPT_LOCK = threading.Lock()


def case(name, ok, evidence, provenance="host/control-plane", samples=1):
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence,
                  "observation_provenance": provenance, "samples": samples})
    print(f"{'PASS' if ok else 'FAIL'} {name}", flush=True)


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def private(path, data):
    path.write_text(data)
    path.chmod(0o600)


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          **kwargs)


def api(method, path, body=None, token=None, base=CP, timeout=120):
    request = urllib.request.Request(base + path, method=method,
                                    data=json.dumps(body).encode() if body is not None else None)
    request.add_header("authorization", "Bearer " + (TOKEN if token is None else token))
    request.add_header("content-type", "application/json")
    try:
        response = urllib.request.urlopen(request, context=CTX, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return response.status if hasattr(response, "status") else response.code, parsed


def spawn(name, argv, env):
    with (ROOT / (name + ".log")).open("wb") as log:
        process = subprocess.Popen(argv, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    PROCESSES.append((name, process))
    return process


def ready(process, base, token):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and process.poll() is None:
        try:
            status, _ = api("GET", "/health", base=base, token=token, timeout=3)
            if status == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.3)
    raise RuntimeError("isolated service failed to become healthy; private log retained")


class Provider(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def serve(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            pieces = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not size:
                    while self.rfile.readline() != b"\r\n":
                        pass
                    break
                pieces.append(self.rfile.read(size))
                require(self.rfile.read(2) == b"\r\n", "invalid provider framing")
            body = b"".join(pieces)
        else:
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
        receipt = {"nonce": self.headers.get("x-acceptance-nonce"), "method": self.command,
                   "path": self.path, "host": self.headers.get("host"),
                   "body_sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
        with RECEIPT_LOCK:
            RECEIPTS.append(receipt)
        payload = json.dumps({"provider_receipt": receipt}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_DELETE = do_OPTIONS = do_HEAD = serve


def hits(nonce):
    with RECEIPT_LOCK:
        return [r.copy() for r in RECEIPTS if r["nonce"] == nonce]


def provider_control(method, path, body, nonce):
    connection = http.client.HTTPConnection(PROVIDER_IP, PROVIDER_PORT, timeout=10)
    connection.request(method, path, body, {"content-type": "application/json",
                                           "x-acceptance-nonce": nonce})
    response = connection.getresponse()
    result = response.status, response.read()
    connection.close()
    return result


def journal(identifier):
    path = ROOT / "vms" / "guard" / identifier / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def heartbeat(identifier):
    status, _ = api("POST", f"/v1/sandboxes/{identifier}/guard/heartbeat", {})
    require(status == 204, "production heartbeat rejected")


def snapshot(identifier):
    status, view = api("GET", f"/v1/sandboxes/{identifier}/guard/telemetry")
    require(status == 200, "production telemetry unavailable")
    return view


def recorded_hash(identifier):
    status, view = api("GET", f"/v1/sandboxes/{identifier}")
    require(status == 200, "sandbox read unavailable")
    view = view.get("sandbox", view)
    return view["environment"]["guard_policy_hash"]


def create(guard, name):
    # The Guard specification travels in `environment.guard`, which is where
    # `POST /v1/sandboxes` reads it from. `resources` is the runs shape, and
    # `CreateSandboxRequest` neither has that field nor rejects unknown ones, so
    # a request that puts the policy there is accepted, boots a real guest, and
    # silently runs it against the default empty policy - which denies every
    # probe below for reasons that have nothing to do with the rule under test.
    # The echoed environment is therefore asserted, not assumed.
    status, view = api("POST", "/v1/sandboxes", {
        "image": "python:3.13", "runtime": "firecracker", "cpu": 1, "memory_mb": 768,
        "disk_mb": 2048, "timeout_seconds": 1200, "name": name,
        "environment": {"guard": guard}})
    view = (view or {}).get("sandbox", view or {})
    identifier = view.get("id")
    if identifier:
        SANDBOXES.append(identifier)
    require(status == 200 and view.get("state") == "running", "live guarded guest did not start")
    # The control plane fills in the specification's defaults - topology,
    # policy template, per-endpoint method and path lists - so the echoed
    # configuration is compared on what was asked for rather than field by
    # field: the Layer 7 rules verbatim, the destinations the probes use, the
    # DNS zones, and the request limit.
    echoed = (view.get("environment") or {}).get("guard") or {}
    asked_policy = guard.get("policy", {})
    echoed_policy = echoed.get("policy", {})

    def destinations(policy):
        return sorted((entry.get("host"), entry.get("port"))
                      for entry in policy.get("network", {}).get("egress", []))

    # Round-tripping is compared on the fields that were requested: the control
    # plane fills in its own defaults (`intercept_ack`, and so on), and a
    # default it added is not evidence that a requested rule was dropped.
    echoed_l7 = echoed.get("l7") or {}
    require(all(echoed_l7.get(key) == value for key, value in (guard.get("l7") or {}).items()),
            "the Layer 7 rules were not the ones applied")
    require(echoed.get("watchdog_timeout_ms") == guard.get("watchdog_timeout_ms"),
            "the watchdog timeout was not the one applied")
    require(destinations(echoed_policy) == destinations(asked_policy),
            "the egress destinations were not the ones applied")
    require(echoed_policy.get("network", {}).get("dns", {}).get("allowed_zones")
            == asked_policy.get("network", {}).get("dns", {}).get("allowed_zones"),
            "the DNS zones were not the ones applied")
    require(echoed_policy.get("limits", {}).get("requests_per_minute")
            == asked_policy.get("limits", {}).get("requests_per_minute"),
            "the request limit was not the one applied")
    require((view.get("environment") or {}).get("guard_policy_hash"),
            "the sandbox was governed by no effective policy")
    heartbeat(identifier)
    return identifier


# The guest uses a raw proxy request so HTTP libraries cannot silently bypass
# the proxy for a .test destination. It returns response status/body only; those
# are advisory until paired with the provider receipt and host event journal.
GUEST_REQUEST = '''import base64,http.client,json
cfg=json.loads(base64.b64decode("CONFIG"))
c=http.client.HTTPConnection(cfg['gateway'],cfg['port'],timeout=12)
c.request(cfg['method'],cfg['target'],base64.b64decode(cfg['body']),
 {'content-type':cfg['type'],'x-acceptance-nonce':cfg['nonce']})
r=c.getresponse();raw=r.read()
print(json.dumps({'status':r.status,'body':raw.decode(errors='replace')}))
c.close()
'''


def guest_request(identifier, host, path, method, body, nonce, content_type="application/json",
                  refresh=True):
    if refresh:
        heartbeat(identifier)
    attachment = json.loads((ROOT / "vms" / "guard" / identifier / "attachment.json").read_text())["attachment"]
    config = {"gateway": attachment["gateway_ip"], "port": attachment["broker_port"],
              "method": method, "target": f"http://{host}:{PROVIDER_PORT}{path}",
              "body": base64.b64encode(body).decode(), "nonce": nonce, "type": content_type}
    code = GUEST_REQUEST.replace("CONFIG", base64.b64encode(json.dumps(config).encode()).decode())
    status, view = api("POST", f"/v1/sandboxes/{identifier}/exec",
                        {"command": ["/usr/bin/python3", "-c", code], "timeout_seconds": 20})
    require(status == 200 and view.get("exit_code") == 0, "live guest request failed")
    return json.loads(view["stdout"])


def probe(identifier, name, host, path, method, body, expected, reason=None,
          content_type="application/json"):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    nonce = uuid.uuid4().hex
    direct_nonce = "host-" + nonce
    direct_status, _ = provider_control(method, path, body, direct_nonce)
    before = len(journal(identifier))
    started = time.monotonic()
    result = guest_request(identifier, host, path, method, body, nonce, content_type)
    events = journal(identifier)[before:]
    receipts = hits(nonce)
    matching = [e for e in events if e.get("decision") == "deny" and
                (reason is None or reason in e.get("reason", ""))]
    expected_hash = hashlib.sha256(body).hexdigest()
    ok = direct_status == 200 and len(hits(direct_nonce)) == 1 and result["status"] == expected
    if expected == 200:
        ok = ok and len(receipts) == 1 and receipts[0]["body_sha256"] == expected_hash
        try:
            ok = ok and json.loads(result["body"])["provider_receipt"]["nonce"] == nonce
        except (ValueError, KeyError):
            ok = False
    else:
        ok = ok and not receipts and bool(matching)
    case(name, ok, {"guest_response_status": result["status"], "expected_status": expected,
                   "provider_hits": len(receipts), "provider_direct_control_status": direct_status,
                   "provider_direct_control_hits": len(hits(direct_nonce)),
                   "request_sha256": expected_hash, "provider_receipts": receipts,
                   "deny_events": [{k: e.get(k) for k in ("sequence", "category", "decision", "reason", "policy_hash")}
                                   for e in matching],
                   "elapsed_seconds": round(time.monotonic() - started, 3)},
         "provider socket receipt + runtime host journal; guest status advisory", 1)
    return result


def mint(scopes):
    status, view = api("POST", "/v1/keys", {"name": "phase3-" + uuid.uuid4().hex,
                                            "scopes": scopes})
    require(status == 200 and view.get("key"), "isolated scoped key mint failed")
    SECRETS.append(view["key"])
    return view["key"]


def submit(identifier, token, host):
    status, view = api("POST", f"/v1/sandboxes/{identifier}/guard/proposals", {"request": {
        "summary": "Allow read-only GET to acceptance provider", "allow": [{
            "host": host, "port": PROVIDER_PORT, "methods": ["GET"], "paths": ["/v1/"]}]}}, token)
    require(status == 200 and view.get("state") == "pending", "authenticated proposal not pending")
    return view


def importer():
    source = ROOT / "openshell.yaml"
    out = ROOT / "imported.yaml"
    source.write_text(f'''version: 1
network_policies:
  api:
    endpoints:
      - host: api.guard.test
        port: {PROVIDER_PORT}
        protocol: rest
        enforcement: enforce
        access: read-only
''')
    argv = [str(BIN / "aiec"), "guard", "import-openshell", "--input", str(source),
            "--out", str(out)]
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    report = json.loads(result.stdout) if result.returncode == 0 else {}
    case("openshell-supported-fields-and-semantic-report", result.returncode == 0 and
         out.is_file() and bool(report.get("converted")) and bool(report.get("unsupported")),
         {"exit": result.returncode, "report": report}, "production CLI", 1)
    require(result.returncode == 0, "supported OpenShell import failed")
    # Use the production verifier to parse imported YAML, and the exact imported
    # bytes to boot a guest below. PyYAML is a harness dependency, not a converter.
    import yaml
    policy = yaml.safe_load(out.read_text())
    previous = out.read_bytes()
    for name, document in [
        ("unknown-semantics", source.read_text() + "unknown_authority: true\n"),
        ("binary-scoped-authority", source.read_text() + "    binaries:\n      - path: /usr/bin/curl\n"),
        ("oversized-document", "#" + "x" * (4 * 1024 * 1024))]:
        source.write_text(document)
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        case("openshell-" + name + "-refused", result.returncode != 0 and out.read_bytes() == previous,
             {"exit": result.returncode, "previous_output_preserved": out.read_bytes() == previous,
              "input_bytes": source.stat().st_size}, "production CLI + host output bytes", 1)
    return policy


def exercise():
    # The model endpoint is what makes Guard's own broker reachable: the
    # enforcement ruleset permits guest-to-gateway traffic on the broker port
    # exactly when the policy configures one, and drops everything else on the
    # attachment. A policy with Layer 7 rules and no model endpoint therefore
    # never gets a guest request as far as the interception point, and every
    # probe below would be testing a timeout rather than a rule.
    policy = {"version": 1, "network": {"dns": {"allowed_zones": HOSTS[:3] + [MODEL_HOST],
               "allowed_record_types": ["A"]}, "egress": [
                   {"host": h, "port": PROVIDER_PORT, "protocol": "tcp"}
                   for h in HOSTS[:3] + [MODEL_HOST]]},
              "model": {"host": MODEL_HOST, "port": PROVIDER_PORT, "scheme": "http",
                        "allowed_methods": ["POST"], "allowed_paths": ["/v1/"],
                        "credential": "model-main"},
              # A model endpoint names a credential binding and Guard refuses an
              # unbound one. The binding's host is the model's, and no probe
              # targets it: every probe below carries its own non-secret
              # acceptance nonce instead of a credential.
              "credentials": [{"name": "model-main", "host": MODEL_HOST, "port": PROVIDER_PORT}],
              "limits": {"requests_per_minute": 1000, "dns_queries_per_minute": 1000}}
    l7 = {"mode": "sni", "http": [{"host": h, "methods": ["POST"] if h != "api.guard.test" else ["GET"],
                                    "paths": ["/v1/"]} for h in HOSTS[:3]],
          "mcp": {"allowed_methods": ["tools/list", "tools/call"],
                  "allowed_tools": ["read_file", "search"], "denied_tools": ["delete_repository"]},
          "graphql": {"allow_mutations": False, "operations": ["ReadUser"], "root_fields": ["user"]}}
    sid = create({"policy": policy, "l7": l7, "watchdog_timeout_ms": 60000}, "phase3-l7")
    case("production-guest-gateway-and-nftables-attached", bool(snapshot(sid).get("event_head")),
         {"sandbox_id": sid, "effective_policy_hash": recorded_hash(sid),
          "kernel_table": snapshot(sid).get("counters", {}).get("table")})
    rpc = lambda method, tool=None: {"jsonrpc": "2.0", "id": 1, "method": method,
                                    **({"params": {"name": tool, "arguments": {"path": "/workspace/input"}}} if tool else {})}
    probe(sid, "mcp-tools-list-allowed", HOSTS[0], "/v1/mcp", "POST", rpc("tools/list"), 200)
    probe(sid, "mcp-read-only-tool-allowed", HOSTS[0], "/v1/mcp", "POST", rpc("tools/call", "read_file"), 200)
    for name, body in [("write-tool", rpc("tools/call", "delete_repository")),
                       ("unknown-tool", rpc("tools/call", "rotate_key")),
                       ("unknown-method", rpc("admin/reset"))]:
        probe(sid, "mcp-" + name + "-denied", HOSTS[0], "/v1/mcp", "POST", body, 403, "l7 mcp")
    probe(sid, "mcp-positive-control-after-denials", HOSTS[0], "/v1/mcp", "POST", rpc("tools/call", "search"), 200)
    query = {"query": "query ReadUser { user { id } }", "operationName": "ReadUser"}
    probe(sid, "graphql-query-allowed", HOSTS[1], "/v1/graphql", "POST", query, 200)
    probe(sid, "graphql-allowed-root-alias-allowed", HOSTS[1], "/v1/graphql", "POST",
          {"query": "query ReadUser { account: user { id } }"}, 200)
    for name, document, expected in [
        ("mutation", "mutation ReadUser { user { id } }", 403),
        ("unknown-operation", "query Other { user { id } }", 403),
        ("unknown-root", "query ReadUser { admin { id } }", 403),
        ("alias-cannot-hide-root", "query ReadUser { user: admin { id } }", 403),
        ("selected-query-cannot-hide-mutation", "query ReadUser { user { id } } mutation Write { user { id } }", 403),
        ("depth-bound", "query ReadUser { " + "user { " * 14 + "id" + " }" * 15, 403),
        ("field-bound", "query ReadUser { user { " + " ".join(f"f{i}" for i in range(257)) + " } }", 403),
        ("operation-bound", " ".join("query ReadUser { user { id } }" for _ in range(9)), 403),
        ("fragment-unsupported", "query ReadUser { user { ...Frag } } fragment Frag on User { id }", 403),
        ("malformed", "query ReadUser { user", 400)]:
        probe(sid, "graphql-" + name + "-denied", HOSTS[1], "/v1/graphql", "POST",
              {"query": document, "operationName": "ReadUser"}, expected, "l7 graphql")
    probe(sid, "graphql-body-bound-denied", HOSTS[1], "/v1/graphql", "POST",
          {"query": "query ReadUser { user { id } }", "padding": "x" * 65536}, 413)
    probe(sid, "graphql-positive-control-after-bounds", HOSTS[1], "/v1/graphql", "POST", query, 200)
    probe(sid, "visible-http-method-path-allowed", HOSTS[2], "/v1/item", "GET", b"", 200)
    probe(sid, "visible-http-write-method-denied", HOSTS[2], "/v1/item", "POST", b"", 403, "l7 http")
    probe(sid, "visible-http-unlisted-path-denied", HOSTS[2], "/admin", "GET", b"", 403, "l7 http")
    probe(sid, "visible-http-prefix-boundary-denied", HOSTS[2], "/v10/item", "GET", b"", 403, "l7 http")
    # Opaque CONNECT must not erase method/path authority; no TLS interception
    # is requested by any fixture. Observe the real production tunnel refusal.
    attachment = json.loads((ROOT / "vms" / "guard" / sid / "attachment.json").read_text())["attachment"]
    before = len(journal(sid))
    tunnel_code = f'''import socket,json
s=socket.create_connection(({attachment['gateway_ip']!r},{attachment['broker_port']}),10)
s.sendall(b"CONNECT api.guard.test:{PROVIDER_PORT} HTTP/1.1\\r\\nHost: api.guard.test:{PROVIDER_PORT}\\r\\n\\r\\n")
print(json.dumps({{'status':int(s.recv(4096).split(b' ')[1])}}));s.close()
'''
    status, view = api("POST", f"/v1/sandboxes/{sid}/exec", {"command": ["/usr/bin/python3", "-c", tunnel_code], "timeout_seconds": 15})
    tunnel_result = json.loads(view.get("stdout", "{}")) if status == 200 else {}
    case("opaque-tunnel-cannot-bypass-visible-rules", tunnel_result.get("status") == 403 and
         any(e.get("decision") == "deny" for e in journal(sid)[before:]),
         {"guest_response_status": tunnel_result.get("status"), "mode": "sni", "interception_requested": False},
         "runtime host journal + advisory guest CONNECT response")
    agent = mint(["guard:propose", "guard:read"])
    human = mint(["guard:approve", "guard:read"])
    both = mint(["guard:propose", "guard:approve", "guard:read"])
    initial = recorded_hash(sid)
    pending = submit(sid, agent, HOSTS[3])
    probe(sid, "pending-proposal-destination-still-denied", HOSTS[3], "/v1/item", "GET", b"", 403)
    case("pending-proposal-preserves-effective-policy", recorded_hash(sid) == initial and
         snapshot(sid)["identity"]["policy_hash"] == initial,
         {"proposal_id": pending["id"], "state": pending["state"], "effective_hash": initial})
    status, _ = api("POST", f"/v1/sandboxes/{sid}/guard/proposals/{pending['id']}/approve", {}, agent)
    case("proposal-agent-cannot-approve", status == 403, {"status": status})
    self_ask = submit(sid, both, HOSTS[3])
    for decision in ("approve", "deny"):
        status, _ = api("POST", f"/v1/sandboxes/{sid}/guard/proposals/{self_ask['id']}/{decision}",
                         {"operator_label": "different-human-label"}, both)
        read_status, unchanged = api("GET", f"/v1/sandboxes/{sid}/guard/proposals/{self_ask['id']}", token=both)
        case("proposal-self-principal-cannot-" + decision, status == 403 and read_status == 200 and
             unchanged.get("state") == "pending" and recorded_hash(sid) == initial,
             {"status": status, "pending_state_preserved": unchanged.get("state") == "pending",
              "effective_hash": recorded_hash(sid)})
    status, denied = api("POST", f"/v1/sandboxes/{sid}/guard/proposals/{self_ask['id']}/deny",
                          {"note": "separate human denies duplicate ask"}, human)
    case("proposal-independent-human-can-deny", status == 200 and
         isinstance(denied.get("state"), dict) and "denied" in denied["state"] and recorded_hash(sid) == initial,
         {"status": status, "state": denied.get("state"), "effective_hash": recorded_hash(sid)})
    before = len(journal(sid))
    status, approved = api("POST", f"/v1/sandboxes/{sid}/guard/proposals/{pending['id']}/approve", {}, human)
    new_hash = recorded_hash(sid)
    apply_events = [e for e in journal(sid)[before:] if e.get("category") == "policy" and
                    e.get("decision") == "allow" and e.get("policy_hash") == new_hash]
    case("separate-human-safe-proposal-applies-new-hash-and-audit", status == 200 and new_hash != initial and
         approved.get("state", {}).get("approved", {}).get("policy_hash") == new_hash and bool(apply_events) and
         snapshot(sid)["identity"]["policy_hash"] == new_hash,
         {"status": status, "previous_hash": initial, "effective_hash": new_hash,
          "decided_by": approved.get("decided_by"), "events": apply_events})
    probe(sid, "approved-destination-live-through-gateway", HOSTS[3], "/v1/item", "GET", b"", 200)
    probe(sid, "approved-grant-remains-read-only", HOSTS[3], "/v1/item", "POST", b"", 403)
    probe(sid, "atomic-apply-keeps-existing-mcp-authority", HOSTS[0], "/v1/mcp", "POST", rpc("tools/list"), 200)
    unsafe = submit(sid, agent, HOSTS[4])
    before = len(journal(sid))
    status, refusal = api("POST", f"/v1/sandboxes/{sid}/guard/proposals/{unsafe['id']}/approve", {}, human)
    refusals = [e for e in journal(sid)[before:] if e.get("decision") == "deny" and
                "verifier refused the proposal" in e.get("reason", "")]
    case("human-approval-runs-verifier-and-unsafe-change-is-rejected", status >= 400 and
         bool(refusals) and recorded_hash(sid) == new_hash and snapshot(sid)["identity"]["policy_hash"] == new_hash,
         {"status": status, "effective_hash": recorded_hash(sid), "verifier_events": refusals,
          "error_code": (refusal or {}).get("error", {}).get("code")})
    probe(sid, "unsafe-destination-no-provider-hit", HOSTS[4], "/v1/item", "GET", b"", 403)
    probe(sid, "safe-destination-survives-unsafe-refusal", HOSTS[3], "/v1/item", "GET", b"", 200)
    imported_policy = importer()
    imported = create({"policy": imported_policy, "watchdog_timeout_ms": 60000}, "phase3-imported")
    probe(imported, "openshell-imported-read-authority-live", HOSTS[2], "/anything", "GET", b"", 200)
    probe(imported, "openshell-imported-write-authority-denied", HOSTS[2], "/anything", "POST", b"", 403)


def inside():
    global ROOT, BIN, TOKEN, CTX
    ROOT = Path(os.environ["P3_SCRATCH"])
    BIN = Path(os.environ.get("P3_BIN", str(REPO / "target/release")))
    require(os.getuid() == 0 and os.readlink("/proc/self/ns/net") != os.environ["P3_HOST_NETNS"],
            "refusing non-isolated runtime")
    os.umask(0o077)
    images = Path(os.environ.get("P3_IMAGES", "/home/gobrowse/ga/images"))
    TOKEN = "af_live_" + secrets.token_hex(24)
    worker_token = "af_live_" + secrets.token_hex(24)
    guest_secret, image_secret = secrets.token_hex(32), secrets.token_hex(32)
    SECRETS.extend([TOKEN, worker_token, guest_secret, image_secret])
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "addr", "add", PROVIDER_IP + "/32", "dev", "lo"])
    command(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    tls = ROOT / "tls"
    tls.mkdir()
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.crt"), "-subj", "/CN=aiec-phase3-ca"])
    command(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tls / "api.key"),
             "-out", str(tls / "api.csr"), "-subj", "/CN=127.0.0.1"])
    private(tls / "ext.cnf", "subjectAltName=IP:127.0.0.1,DNS:localhost\n")
    command(["openssl", "x509", "-req", "-in", str(tls / "api.csr"), "-CA", str(tls / "ca.crt"),
             "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "2", "-out", str(tls / "api.crt"),
             "-extfile", str(tls / "ext.cnf")])
    CTX = ssl.create_default_context(cafile=str(tls / "ca.crt"))
    hasher = hashlib.sha256()
    with (images / "aiec-rootfs.ext4").open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 << 20), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    signature = hmac.new(image_secret.encode(), b"python:3.13\0" + digest.encode(), hashlib.sha256).hexdigest()
    private(ROOT / "manifest.json", json.dumps({"reference": "python:3.13", "rootfs_sha256": digest,
                                                "signature": signature}))
    boundary_test_destinations = {f"{h}:{PROVIDER_PORT}": [PROVIDER_IP] for h in HOSTS[:4]}
    boundary_test_destinations[f"{MODEL_HOST}:{PROVIDER_PORT}"] = [PROVIDER_IP]
    private(ROOT / "boundary.json", json.dumps({"blocked_hosts": [HOSTS[4]],
                                                "test_destinations": boundary_test_destinations}))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AIEC_", "AGENTFORGE_"))}
    guard_credentials = ROOT / "guard-credentials.json"
    private(guard_credentials, json.dumps({"model-main": secrets.token_hex(32)}))
    SECRETS.append(json.loads(guard_credentials.read_text())["model-main"])
    env.update({"DATABASE_URL": os.environ["P3_DATABASE_URL"], "AIEC_RUNTIME": "firecracker",
                "AIEC_FIRECRACKER_BIN": os.environ.get("P3_FIRECRACKER", str(REPO / ".agentforge/bin/firecracker-v1.17.0-x86_64")),
                "AIEC_KERNEL": str(images / "vmlinux"), "AIEC_ROOTFS": str(images / "aiec-rootfs.ext4"),
                "AIEC_GUEST_SECRET": guest_secret, "AIEC_IMAGE_MANIFEST": str(ROOT / "manifest.json"),
                "AIEC_IMAGE_MANIFEST_SECRET": image_secret, "AIEC_STATE_DIR": str(ROOT / "vms"),
                # A policy that binds a model credential refuses to start an
                # attachment whose gateway cannot present it - fail-closed, and
                # correct. The binding is operator material, so this run mints
                # it: one owner-only file, one random secret, never printed and
                # never reused.
                "AIEC_GUARD_CREDENTIALS_FILE": str(guard_credentials),
                "AIEC_TLS_CERT_FILE": str(tls / "api.crt"), "AIEC_TLS_KEY_FILE": str(tls / "api.key"),
                "AIEC_TLS_CA_CERT": str(tls / "ca.crt"), "AIEC_S3_ENDPOINT": "http://127.0.0.1:9000",
                "AIEC_S3_REGION": "us-east-1", "AIEC_S3_BUCKET": "aiec",
                "AIEC_S3_ACCESS_KEY_ID": "acceptance", "AIEC_S3_SECRET_ACCESS_KEY": secrets.token_hex(24),
                "AIEC_S3_PREFIX": "phase3/" + ROOT.name + "/", "AIEC_TENANT_ID": str(uuid.uuid4()),
                "AIEC_TENANT_NAME": "phase3", "AIEC_API_KEY": TOKEN, "AIEC_WORKER_TOKEN": worker_token,
                "AIEC_LEASE_TTL_SECONDS": "300", "AIEC_GUARD_BOUNDARY_FILE": str(ROOT / "boundary.json"),
                # Mock destinations require proving this process is not on the
                # host's network. Inside a fresh user+network namespace PID 1's
                # namespace link is unreadable, so the launcher records the
                # inode it read before unsharing (P3_HOST_NETNS) and the worker
                # compares against it. The shipped worker only reads it in
                # local test mode.
                "AIEC_GUARD_TEST_MODE": "1",
                "AIEC_GUARD_ACCEPTANCE_HOST_NETNS": os.environ["P3_HOST_NETNS"]})
    SECRETS.append(env["AIEC_S3_SECRET_ACCESS_KEY"])
    provider = ThreadingHTTPServer((PROVIDER_IP, PROVIDER_PORT), Provider)
    provider.daemon_threads = True
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        server = spawn("control-plane", [str(BIN / "aiec-server")], {**env, "AIEC_BIND": "127.0.0.1:18744"})
        ready(server, CP, "")
        worker = spawn("worker", [str(BIN / "aiec"), "--url", CP, "worker", "--runtime", "firecracker",
                      "--state-dir", str(ROOT / "worker-state"), "--advertise-url", WORKER,
                      "--bind", "127.0.0.1:19744", "--name", "phase3", "--capacity", "4",
                      "--memory-reserve-mib", "256", "--disk-reserve-mib", "512"], env)
        ready(worker, WORKER, worker_token)
        exercise()
    except Exception as error:
        # Exception messages may include an environment/URL. Only the class is
        # public evidence; logs and scratch state stay owner-only.
        case("live-run-completes", False, {"exception_type": type(error).__name__})
    finally:
        for sid in reversed(SANDBOXES):
            try:
                status, _ = api("DELETE", f"/v1/sandboxes/{sid}")
                if status not in (200, 202, 204):
                    CLEANUP.append("sandbox deletion rejected: " + str(status))
            except Exception as error:
                CLEANUP.append("sandbox deletion: " + type(error).__name__)
        if SANDBOXES:
            try:
                tables = command(["nft", "list", "tables"]).stdout.decode()
                links = json.loads(command(["ip", "-j", "link", "show"]).stdout)
                case("live-teardown-removes-guard-tables-and-taps",
                     not any(s.replace("-", "") in tables for s in SANDBOXES) and
                     not any(row["ifname"].startswith("ag") for row in links),
                     {"remaining_tables": tables.strip(), "remaining_interfaces": [row["ifname"] for row in links]},
                     "namespace host kernel")
            except Exception as error:
                CLEANUP.append("kernel teardown census: " + type(error).__name__)
        for name, process in reversed(PROCESSES):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                CLEANUP.append(name + " required SIGKILL")
        provider.shutdown()
        provider.server_close()
        thread.join(timeout=5)
    logs = list(ROOT.glob("*.log"))
    leaked = [path.name for path in logs if any(s.encode() in path.read_bytes() for s in SECRETS)]
    case("no-credentials-in-service-logs", not leaked, {"files_scanned": len(logs), "leaking_files": leaked},
         "host private logs", len(logs))
    report = {"schema": "aiec.guard.phase3-acceptance.v1", "status": "PASS" if CASES and
              all(c["status"] == "PASS" for c in CASES) and not CLEANUP else "FAIL",
              "passed": sum(c["status"] == "PASS" for c in CASES), "cases": len(CASES),
              "cases_detail": CASES, "cleanup_errors": CLEANUP, "provider_requests": len(RECEIPTS),
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "finished_at": datetime.now(timezone.utc).isoformat(),
              "environment": {"runtime": "firecracker", "isolated_network_namespace": True,
                              "rootfs_sha256": digest, "provider": "permissive local socket server",
                              "tls_interception": False},
              "observation_provenance": {"authoritative": ["provider socket receipts", "runtime host event journal",
                                          "control-plane API", "namespace nftables"],
                                         "advisory": ["guest HTTP responses"]}}
    serialized = json.dumps(report, indent=2)
    require(not any(s in serialized for s in SECRETS), "credential in report")
    private(ROOT / "result.json", serialized)
    return 0 if report["status"] == "PASS" else 1


class DatabaseRelay:
    """Filesystem socket preserves database reachability across a netns."""
    def __init__(self, path, host, port):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(128)
        self.listener.settimeout(.2)
        self.host, self.port = host, port
        self.stop = threading.Event()
        self.clients = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.pipe, args=(client,), daemon=True).start()

    def pipe(self, client):
        upstream = None
        try:
            upstream = socket.create_connection((self.host, self.port), 10)
            with self.lock:
                self.clients.extend([client, upstream])
            with selectors.DefaultSelector() as selector:
                selector.register(client, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, client)
                while not self.stop.is_set():
                    for key, _ in selector.select(.2):
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        key.data.sendall(data)
        except OSError:
            pass
        finally:
            client.close()
            if upstream:
                upstream.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            for client in self.clients:
                client.close()
        self.thread.join(timeout=5)


LOG_TAIL_BYTES = 1024 * 1024


def outer():
    import psycopg
    from psycopg import sql
    from urllib.parse import urlsplit, quote
    # Disk-backed, operator-visible and bounded. The default temporary
    # directory is RAM-backed and far too small for a PostgreSQL data
    # directory plus the rootfs copies this run makes, and a failed run's
    # evidence has to outlive the tree that produced it, so both the scratch
    # parent and the failure evidence are pinned under P3_ROOT.
    parent = Path(os.environ.get("P3_ROOT") or Path.home() / "aiec" / "phase3")
    # Checked before anything is created. Every path this run derives from
    # P3_ROOT ends at a Unix socket, which is limited to about 107 bytes, and a
    # root that cannot hold one is an operator error worth naming - not a
    # failure to discover inside PostgreSQL, and not a directory left behind for
    # the operator to remove. The longest name mkdtemp can produce here is used
    # as the estimate, so every later run name fits if this one does.
    socket_path = parent.resolve() / ("aiec-p3-" + "x" * 8) / "pg" / ".s.PGSQL.5432"
    if len(os.fsencode(str(socket_path))) > 100:
        print(
            "P3_ROOT is too long for a Unix socket path; use a shorter one",
            file=sys.stderr,
        )
        sys.exit(2)
    # Only a directory this run created is tightened to 0700: P3_ROOT may name
    # a parent the operator shares with another suite, and quietly narrowing
    # its permissions is not this suite's to do.
    created_parent = not parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    if created_parent:
        parent.chmod(0o700)
    scratch = Path(tempfile.mkdtemp(prefix="aiec-p3-", dir=parent))
    database = "aiec_p3_" + uuid.uuid4().hex
    admin = os.environ.get("P3_PG_ADMIN_URL", "postgresql://aiec:aiec-dev-only@127.0.0.1:5432/aiec")
    parsed = urlsplit(admin)
    sock = scratch / "pg"
    sock.mkdir()
    require(len(os.fsencode(str(sock / ".s.PGSQL.5432"))) <= 100,
            "P3_ROOT is too long for a Unix socket path; use a shorter one")
    relay = None
    cleanup = []
    created = False
    result = {"schema": "aiec.guard.phase3-acceptance.v1", "status": "FAIL", "cases_detail": []}
    try:
        for executable in ["unshare", "ip", "nft", "sysctl", "openssl"]:
            require(shutil.which(executable), "missing required executable")
        require(os.access("/dev/kvm", os.W_OK), "KVM is not writable")
        with psycopg.connect(admin, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        created = True
        relay = DatabaseRelay(sock / ".s.PGSQL.5432", parsed.hostname or "127.0.0.1", parsed.port or 5432)
        env = dict(os.environ)
        env.update({"P3_SCRATCH": str(scratch), "P3_HOST_NETNS": os.readlink("/proc/self/ns/net"),
                    "P3_DATABASE_URL": f"postgresql://{quote(parsed.username or 'aiec')}:{quote(parsed.password or '')}@localhost/{database}?host={quote(str(sock))}"})
        process = subprocess.Popen(["unshare", "--user", "--map-root-user", "--net", "--fork", "--kill-child=KILL",
                                    sys.executable, str(Path(__file__).resolve()), "--inside"], env=env)
        try:
            process.wait()
        except BaseException:
            process.terminate()
            process.wait(timeout=20)
            raise
        if (scratch / "result.json").is_file():
            result = json.loads((scratch / "result.json").read_text())
        else:
            result["launch_failure"] = "isolated runtime produced no result"
        if process.returncode:
            result["status"] = "FAIL"
    except Exception as error:
        result["launch_failure"] = type(error).__name__
    finally:
        if relay:
            relay.close()
        if created:
            try:
                with psycopg.connect(admin, autocommit=True) as connection:
                    connection.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s", (database,))
                    connection.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))
            except Exception as error:
                cleanup.append("database teardown: " + type(error).__name__)
        result.setdefault("cleanup_errors", []).extend(cleanup)
        if cleanup:
            result["status"] = "FAIL"
    report = Path(os.environ.get("P3_REPORT", str(REPO / "benchmarks/guard-phase3-acceptance.json")))
    evidence, residue = None, None
    if result["status"] != "PASS":
        # The scratch tree is torn down either way, so what is worth keeping is
        # copied out of it first: the service logs and the host's own Guard
        # journals. Everything else in the tree is either regenerable
        # (manifests, TLS material, the database) or too large to keep (two
        # 4 GiB rootfs copies), and keeping those is the growth this directory
        # exists to avoid.
        evidence = parent / "failed" / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8])
        evidence.mkdir(parents=True, exist_ok=True)
        evidence.chmod(0o700)
        for log in sorted(scratch.glob("*.log")):
            # spawn() gives a service the log for the whole run, and a run that
            # fails late can leave a large one; the tail is what explains the
            # failure, and an unbounded copy is the problem being fixed.
            tail = log.read_bytes()[-LOG_TAIL_BYTES:]
            (evidence / log.name).write_bytes(tail)
            (evidence / log.name).chmod(0o600)
        for journal_path in sorted(scratch.glob("vms/guard/*/events.jsonl")):
            kept = evidence / journal_path.parent.name / journal_path.name
            kept.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(journal_path, kept)
        result["evidence_retained"] = sorted(path.name for path in evidence.iterdir())
    try:
        shutil.rmtree(scratch)
    except OSError as error:
        # Residue that outlives the run is a cleanup failure rather than a
        # silent leftover, and a run that passed while leaving a tree behind
        # has not cleaned up. The path goes in the message so the operator
        # knows which tree to look at, whatever else the report points at.
        residue = scratch
        result.setdefault("cleanup_errors", []).append(
            f"scratch teardown: {type(error).__name__} ({scratch})")
        result["status"] = "FAIL"
        if evidence is None:
            evidence = scratch
    destination = report if result["status"] == "PASS" else evidence / "failure.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".tmp")
    private(temporary, json.dumps(result, indent=2))
    os.replace(temporary, destination)
    print(json.dumps({"status": result["status"], "passed": result.get("passed", 0),
                      "cases": result.get("cases", 0), "cleanup_errors": result["cleanup_errors"],
                      "report": str(destination), "evidence": str(evidence) if evidence else None,
                      "residue": str(residue) if residue else None}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(inside() if "--inside" in sys.argv else outer())
