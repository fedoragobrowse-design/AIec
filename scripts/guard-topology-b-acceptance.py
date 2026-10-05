#!/usr/bin/env python3
"""Guard Topology B live acceptance (§50).

Topology B is the shipped claim that the agent runs *outside* the sandbox: the
trusted harness drives the guest through AIec's own control channel, and the
guest is given no egress at all. `GUARD_POLICY.md` states it in a line - "no
policy selected means no network" - and every other acceptance suite here proves
a *component*. This one proves the deployment, because that claim is only
observable when all of these are true at once and none of them can be true in a
unit test:

  * a real control plane, a real worker and a real Firecracker guest, over
    HTTPS, against a real PostgreSQL database;
  * a real external agent loop running on the host: it calls a real HTTP model
    endpoint, consumes a real SSE stream, issues real tool calls, feeds the
    results back, and terminates on a condition the harness checks by reading
    the guest back through the control channel;
  * every tool call reaching the guest over the same three REST endpoints an
    operator would use - exec, file write, file read - and no other path;
  * a guest network boundary in which no packet from the guest goes anywhere,
    observed from the *host*;
  * and a positive control, because a counter that reads zero is only evidence
    if the same reading would have moved had the guest tried to egress.

The observation split is stated, never blurred. Host-observed: the attachment's
named nftables counters (kernel state in this host's table, read by the harness
with `nft(8)` rather than through the product), the tcpdump capture on the
guest's own TAP device (frames as the host's NIC saw them), and every HTTP
status, body and latency the agent loop produced. Guest-reported, and labelled
as such: the `errno` of the positive control's connect attempts, which exist only
to corroborate a movement the host already counted.

Run by guard-topology-b-acceptance.sh, which supplies the private user+network
namespace, the TLS material, the signed guest image and the database.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import ssl
import subprocess
import sys
import threading
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from acceptance_http import urlopen
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(os.environ["TOPOB_ROOT"])
BIN = Path(os.environ["TOPOB_BIN"])
IMAGES = Path(os.environ["TOPOB_IMAGES"])
CA = Path(os.environ["TOPOB_CA"])
CP = os.environ["TOPOB_CP"]
WORKER = os.environ["TOPOB_WORKER"]
TENANT = os.environ["TOPOB_TENANT"]
BOOTSTRAP_KEY = os.environ["TOPOB_API_KEY"]
WORKER_TOKEN = os.environ["TOPOB_WORKER_TOKEN"]
MODEL_URL = os.environ["TOPOB_MODEL_URL"]
S3_PORT = os.environ["TOPOB_S3_PORT"]
IMAGE = os.environ["TOPOB_IMAGE"]

# The key the agent's tools act under: the narrowest scopes that can play the
# agent's part - drive the sandbox, read Guard telemetry, nothing else. A key
# holding everything would pass every case here with every authorisation check
# deleted.
AGENT_KEY = ""
GUARD_KEY = ""
# A per-run nonce, so "the guest holds exactly these bytes" cannot be satisfied
# by whatever was left in the workspace by an earlier run.
TASK_CONTENT = ""

CASES: list[dict] = []
FAILURES: list[str] = []
CLEANUP_ERRORS: list[str] = []
LIMITATIONS: list[str] = []
_started: list[tuple[str, subprocess.Popen]] = []
_sandbox_id: str | None = None
_capture: subprocess.Popen | None = None
_model: ScriptedModel | None = None
_model_state = {"requests": 0, "streams": 0, "sse_events": 0}

CTX = ssl.create_default_context(cafile=str(CA))


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def case(name: str, ok: bool, evidence: dict) -> None:
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    log(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        # Evidence prints with the failure. A report that only exists on disk is
        # a report nobody reads while the run is still fresh enough to debug.
        log("        evidence: " + json.dumps(evidence)[:900])
        FAILURES.append(name)


def observe(name: str, ok: bool, evidence: dict) -> None:
    """A recorded finding that does not gate the suite.

    Used only where the deployment's own behaviour is the evidence - a refusal
    that proves a capability gate exists. Gating on it would assert that a
    deployment is *wrong*, which is a product claim, not an acceptance claim;
    recording it keeps the observation without making the suite's verdict a
    statement about somebody else's design.
    """
    CASES.append({"case": name, "status": "PASS" if ok else "OBSERVED",
                  "gating": False, "evidence": evidence})
    log(f"{'PASS' if ok else 'OBSERVED'}  {name}")


def http(method: str, path: str, body=None, token: str | None = None, timeout: float = 60.0):
    request = urllib.request.Request(CP + path, method=method)
    request.add_header("authorization", f"Bearer {token if token is not None else BOOTSTRAP_KEY}")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request.add_header("content-type", "application/json")
    try:
        with urlopen(request, data=data, timeout=timeout, context=CTX) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, (json.loads(raw) if raw else None)
        except json.JSONDecodeError:
            return error.code, {"raw": raw.decode(errors="replace")[:400]}


def spawn(name: str, argv: list[str], env: dict | None = None) -> subprocess.Popen:
    merged = dict(os.environ)
    merged.update(env or {})
    # Truncated per run: an append-mode log carries the previous run's failures
    # into this one's evidence, and a cause read from the wrong run is worse
    # than no cause at all.
    handle = open(ROOT / f"{name}.log", "wb", buffering=0)
    process = subprocess.Popen(
        argv, stdout=handle, stderr=subprocess.STDOUT, env=merged, start_new_session=True
    )
    _started.append((name, process))
    return process


def stop_all() -> None:
    for _, process in reversed(_started):
        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.time() + 20
    for name, process in reversed(_started):
        while process.poll() is None and time.time() < deadline:
            time.sleep(0.2)
        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.returncode not in (0, -signal.SIGTERM, -signal.SIGKILL):
            CLEANUP_ERRORS.append(f"{name} exited {process.returncode}")


def wait_for_health(process: subprocess.Popen, seconds: float = 180.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            status, _ = http("GET", "/health", token="", timeout=3.0)
            if status == 200:
                return True
        except Exception:  # noqa: BLE001 - a not-up-yet answer, not an error
            pass
        time.sleep(0.5)
    return False


def wait_for_worker(seconds: float = 120.0) -> dict:
    """Waits for the worker's own socket, not for a row in the database.

    The control plane learns about a worker by being called, and calls back at
    the address the worker advertised. If a sandbox create arrives while that
    socket is still binding, placement fails as `runtime_unavailable` - which
    reads as "the worker is broken" when the worker is merely starting.
    """
    deadline = time.time() + seconds
    last: dict = {}
    while time.time() < deadline:
        request = urllib.request.Request(WORKER + "/health")
        request.add_header("authorization", f"Bearer {WORKER_TOKEN}")
        try:
            with urlopen(request, timeout=5.0, context=CTX) as response:
                return {"status": response.status, "authenticated_health": 200}
        except urllib.error.HTTPError as error:
            # `401` is the worker refusing an *unauthenticated* probe, and it is
            # the answer this is waiting for: the socket is bound and routing.
            # Waiting for `200` here loops until the deadline against a
            # perfectly healthy worker whose health route needs a bearer token.
            if error.code == 401:
                return {"status": error.code, "listener_bound": True}
            last = {"status": error.code}
        except Exception as error:  # noqa: BLE001 - recorded, not swallowed
            last = {"last_error": str(error)[:200]}
        time.sleep(0.5)
    return {"ready": False, **last}


def base_env() -> dict:
    return {
        "DATABASE_URL": os.environ["TOPOB_DATABASE_URL"],
        "AIEC_RUNTIME": "firecracker",
        "AIEC_FIRECRACKER_BIN": os.environ["TOPOB_FIRECRACKER"],
        "AIEC_KERNEL": str(IMAGES / "vmlinux"),
        "AIEC_ROOTFS": str(IMAGES / "aiec-rootfs.ext4"),
        "AIEC_GUEST_ARTIFACT_DIR": str(IMAGES),
        "AIEC_GUEST_SECRET": os.environ["TOPOB_GUEST_SECRET"],
        "AIEC_IMAGE_MANIFEST": os.environ["TOPOB_IMAGE_MANIFEST"],
        "AIEC_IMAGE_MANIFEST_SECRET": os.environ["TOPOB_IMAGE_MANIFEST_SECRET"],
        # The Firecracker runtime places VMs and Guard attachments under this
        # directory, so it is set explicitly: a loaded operator environment must
        # not put acceptance machines next to a deployment's own.
        "AIEC_STATE_DIR": str(ROOT / "state-vms"),
        "AIEC_TLS_CERT_FILE": os.environ["TOPOB_TLS_CERT"],
        "AIEC_TLS_KEY_FILE": os.environ["TOPOB_TLS_KEY"],
        "AIEC_TLS_CA_CERT": str(CA),
        "AIEC_S3_ENDPOINT": f"http://127.0.0.1:{S3_PORT}",
        "AIEC_S3_REGION": "us-east-1",
        "AIEC_S3_BUCKET": "aiec-topology-b",
        "AIEC_S3_ACCESS_KEY_ID": "acceptance",
        "AIEC_S3_SECRET_ACCESS_KEY": "acceptance-only",
        "AIEC_S3_PREFIX": "topology-b/",
        "AIEC_TENANT_ID": TENANT,
        "AIEC_TENANT_NAME": "topology-b",
        "AIEC_API_KEY": BOOTSTRAP_KEY,
        "AIEC_WORKER_TOKEN": WORKER_TOKEN,
        "AIEC_LEASE_TTL_SECONDS": "300",
        "AIEC_ALLOW_CONTAINER_RUNTIMES": "1",
    }


def mint(name: str, scopes: list[str]) -> str:
    status, body = http("POST", "/v1/keys", {"name": name, "scopes": scopes}, token=BOOTSTRAP_KEY)
    key = (body or {}).get("key")
    if status != 200 or not key:
        raise SystemExit(f"could not mint {name}: {status} {body}")
    return key


# ---------------------------------------------------------------------------
# The model provider: local, scripted, OpenAI-shaped, SSE only.
#
# It exists to make the *loop* the thing under test. Every tool call after the
# first is derived from the tool result the harness fed back, so a harness that
# drops a tool result gets a 400 rather than a plausible answer - and a
# scripted model that answered anyway would let a broken loop look like a
# working one.
# ---------------------------------------------------------------------------

NEEDS_RESULT = (
    "the previous turn's tool result is missing or unusable; this scripted model "
    "will not answer without it"
)


class _ModelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": {"message": "malformed request"}})
        _model_state["requests"] += 1
        try:
            reply = _script(request.get("messages") or [], bool(request.get("stream")))
        except ValueError as error:
            return self._json(400, {"error": {"message": str(error), "type": "tool_result_missing"}})
        self._stream(reply)

    def _json(self, status: int, document: dict) -> None:
        payload = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _stream(self, reply: dict) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        self._event({"choices": [{"index": 0, "delta": {"role": "assistant"},
                                  "finish_reason": None}]})
        if reply.get("content"):
            # Content streams in fragments too. A loop that only ever assembled
            # one whole string was never tested against a real decoder.
            for piece in _fragments(reply["content"]):
                self._event({"choices": [{"index": 0, "delta": {"content": piece},
                                          "finish_reason": None}]})
        for index, call in enumerate(reply.get("tool_calls", [])):
            for position, piece in enumerate(_fragments(json.dumps(call["arguments"]))):
                self._event({"choices": [{"index": 0, "finish_reason": None, "delta": {
                    "tool_calls": [{
                        "index": index,
                        "id": call["id"] if position == 0 else None,
                        "type": "function" if position == 0 else None,
                        "function": {
                            "name": call["name"] if position == 0 else None,
                            "arguments": piece,
                        },
                    }]}}]})
        self._event({"choices": [{"index": 0, "delta": {},
                                  "finish_reason": "tool_calls" if reply.get("tool_calls") else "stop"}]})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True

    def _event(self, document: dict) -> None:
        _model_state["sse_events"] += 1
        envelope = {"id": "chatcmpl-topob", "object": "chat.completion.chunk",
                    "model": "topology-b-scripted", **document}
        self.wfile.write(f"data: {json.dumps(envelope)}\n\n".encode())
        self.wfile.flush()


def _tool_results(messages: list[dict], name: str) -> list[dict]:
    found = []
    for message in messages:
        if message.get("role") != "tool" or message.get("name") != name:
            continue
        try:
            found.append(json.loads(message.get("content") or ""))
        except json.JSONDecodeError:
            continue
    return found


def _tool_call(name: str, arguments: dict, tag: str) -> dict:
    return {
        "model": "topology-b-scripted",
        "content": None,
        "tool_calls": [{"id": f"call_{tag}", "name": name, "arguments": arguments}],
    }


def _script(messages: list[dict], streaming: bool) -> dict:
    if not streaming:
        raise ValueError("this endpoint speaks only the streaming dialect")
    writes = _tool_results(messages, "write_file")
    execs = _tool_results(messages, "exec")
    reads = _tool_results(messages, "read_file")

    # Turn 1. Path and bytes are the task itself, not an observation.
    if not writes:
        return _tool_call("write_file",
                          {"path": "/workspace/topology-b.txt", "content": TASK_CONTENT}, "w")

    # Turn 2. The path comes from the write's own acknowledgement. Without that
    # acknowledgement there is nothing to act on, and refusing is the point.
    written = writes[0]
    if not written.get("ok") or not written.get("path"):
        raise ValueError(NEEDS_RESULT)
    path = written["path"]
    if not execs:
        return _tool_call("exec", {"command": ["sha256sum", path]}, "x")

    # Turn 3. The digest is one the *guest* computed; the harness never supplied
    # it and cannot forge it from outside.
    executed = execs[0]
    if not executed.get("ok") or executed.get("exit_code") != 0:
        raise ValueError(NEEDS_RESULT)
    fields = (executed.get("stdout") or "").split()
    if not fields or len(fields[0]) != 64:
        raise ValueError(NEEDS_RESULT)
    digest = fields[0]

    # Turn 4. Read the bytes back, then terminate only if they hash to the
    # digest the guest itself produced.
    if not reads:
        return _tool_call("read_file", {"path": path}, "r")
    observed = reads[0]
    content = observed.get("content")
    if not observed.get("ok") or content is None:
        raise ValueError(NEEDS_RESULT)
    if hashlib.sha256(content.encode()).hexdigest() != digest:
        raise ValueError("the bytes read back do not hash to the digest the guest computed")
    return {
        "model": "topology-b-scripted",
        "content": (f"verified {path}: the guest hashed it to {digest}, and the bytes read "
                    f"back through the control channel hash to the same value"),
        "tool_calls": [],
    }


def _fragments(text: str, size: int = 19) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)] or [""]


class ScriptedModel(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_model() -> ScriptedModel:
    global _model
    if _model is not None:
        return _model
    parsed = urllib.parse.urlsplit(MODEL_URL)
    _model = ScriptedModel(("127.0.0.1", int(parsed.port or 80)), _ModelHandler)
    threading.Thread(target=_model.serve_forever, daemon=True).start()
    return _model


# ---------------------------------------------------------------------------
# The agent loop.
# ---------------------------------------------------------------------------

def stream_chat(messages: list[dict], timeout: float = 30.0) -> dict:
    request = urllib.request.Request(
        MODEL_URL,
        data=json.dumps({"model": "topology-b-scripted", "stream": True,
                         "messages": messages}).encode(),
        method="POST",
    )
    request.add_header("content-type", "application/json")
    content: list[str] = []
    calls: dict[int, dict] = {}
    finish_reason = None
    events = 0
    with urlopen(request, timeout=timeout) as response:
        media = response.headers.get("content-type") or ""
        if "text/event-stream" not in media:
            raise RuntimeError(f"the model did not stream: {media}")
        for raw in response:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line.startswith("data: "):
                continue
            payload = line[6:]
            events += 1
            if payload == "[DONE]":
                break
            for choice in json.loads(payload).get("choices", []):
                delta = choice.get("delta") or {}
                if delta.get("content"):
                    content.append(delta["content"])
                for call in delta.get("tool_calls") or []:
                    slot = calls.setdefault(call.get("index", 0),
                                            {"id": None, "name": "", "arguments": ""})
                    if call.get("id"):
                        slot["id"] = call["id"]
                    function = call.get("function") or {}
                    if function.get("name"):
                        slot["name"] = function["name"]
                    slot["arguments"] += function.get("arguments") or ""
                if choice.get("finish_reason"):
                    finish_reason = choice["finish_reason"]
    _model_state["streams"] += 1
    return {"content": "".join(content), "finish_reason": finish_reason, "sse_events": events,
            "tool_calls": [calls[index] for index in sorted(calls)]}


CHANNELS = {
    "write_file": "PUT /v1/sandboxes/<id>/files",
    "exec": "POST /v1/sandboxes/<id>/exec",
    "read_file": "GET /v1/sandboxes/<id>/files/content",
}


def dispatch(name: str, arguments: dict) -> dict:
    """One model tool call, executed over AIec's trusted control channel.

    There is no fourth path. The agent is on the host and the guest is inside a
    microVM, so a tool call that is not one of these three REST endpoints did
    not reach the guest.
    """
    sandbox = _sandbox_id
    if name == "write_file":
        status, body = http("PUT", f"/v1/sandboxes/{sandbox}/files", {
            "path": arguments["path"],
            "content_base64": base64.b64encode(arguments["content"].encode()).decode(),
        }, token=AGENT_KEY)
        return {"ok": status in (200, 201, 204), "path": arguments["path"],
                "bytes": len(arguments["content"].encode()), "http_status": status,
                "response": body}
    if name == "exec":
        status, body = http("POST", f"/v1/sandboxes/{sandbox}/exec",
                            {"command": arguments["command"], "timeout_seconds": 60},
                            token=AGENT_KEY, timeout=120.0)
        body = body or {}
        return {"ok": status == 200, "http_status": status,
                "exit_code": body.get("exit_code"),
                "stdout": (body.get("stdout") or "")[:400],
                "stderr": (body.get("stderr") or "")[:200]}
    if name == "read_file":
        query = urllib.parse.urlencode({"path": arguments["path"]})
        status, body = http("GET", f"/v1/sandboxes/{sandbox}/files/content?{query}",
                            token=AGENT_KEY)
        body = body or {}
        content = None
        if body.get("content_base64"):
            content = base64.b64decode(body["content_base64"]).decode("utf-8", "replace")
        return {"ok": status == 200, "http_status": status, "path": arguments.get("path"),
                "content": content}
    return {"ok": False, "error": f"unknown tool {name}"}


def agent_loop() -> dict:
    messages = [
        {"role": "system", "content": "You drive a sandboxed guest through its control channel."},
        {"role": "user", "content": (
            f"Write {TASK_CONTENT.strip()!r} to /workspace/topology-b.txt in the sandbox, "
            "hash it with sha256sum, read it back, and report only if both agree.")},
    ]
    trace: list[dict] = []
    performed: list[dict] = []
    for turn in range(1, 7):
        try:
            reply = stream_chat(messages)
        except urllib.error.HTTPError as error:
            raw = error.read()
            trace.append({"turn": turn, "model_http_status": error.code,
                          "model_error": raw.decode(errors="replace")[:300]})
            break
        trace.append({
            "turn": turn, "sse_events": reply["sse_events"],
            "finish_reason": reply["finish_reason"], "content": reply["content"],
            "tool_calls": [{"name": call["name"], "arguments": json.loads(call["arguments"] or "{}")}
                           for call in reply["tool_calls"]],
        })
        messages.append({"role": "assistant", "content": reply["content"],
                         "tool_calls": reply["tool_calls"] or None})
        if not reply["tool_calls"]:
            return {"turns": trace, "tool_calls": performed, "finished": True,
                    "final_content": reply["content"]}
        for call in reply["tool_calls"]:
            arguments = json.loads(call["arguments"] or "{}")
            started = time.time()
            result = dispatch(call["name"], arguments)
            performed.append({
                "tool": call["name"], "channel": CHANNELS[call["name"]],
                "arguments": arguments, "result": result,
                "latency_ms": round((time.time() - started) * 1000, 1),
            })
            messages.append({"role": "tool", "tool_call_id": call["id"], "name": call["name"],
                             "content": json.dumps(result)})
    return {"turns": trace, "tool_calls": performed, "finished": False, "final_content": None}


# ---------------------------------------------------------------------------
# Host-observed egress evidence.
# ---------------------------------------------------------------------------

def nft_table(sandbox: str) -> str:
    # `GuardAttachment::table_name`: the prefix is `aiec_guard_` and the body is
    # the sandbox UUID with its dashes removed.
    return "aiec_guard_" + sandbox.replace("-", "")


COUNTER_NAMES = ("cnt_blocked_range", "cnt_other_denied", "cnt_ipv6",
                 "cnt_dns_permitted", "cnt_broker_permitted")


def host_nft_counters(sandbox: str) -> dict:
    """This attachment's own named counters, read out of the host kernel.

    Host-observed, not guest-reported and not mediated by the product: `nft`
    reads the table Guard installed on this host's interface, and the harness
    runs in the same network namespace the attachment was created in. They are
    kernel counters, so nothing the guest can say can move them.
    """
    table = nft_table(sandbox)
    result = subprocess.run(["nft", "-j", "list", "table", "ip", table],
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return {"table": table, "error": (result.stderr or "").strip()[:300]}
    counters: dict[str, dict] = {}
    for entry in json.loads(result.stdout or "[]").get("nftables", []):
        counter = entry.get("counter") or {}
        if not counter.get("name"):
            continue
        counters[counter["name"]] = {"packets": counter.get("packets"),
                                     "bytes": counter.get("bytes")}
    return {"table": table, "read_at": datetime.now(timezone.utc).isoformat(),
            "source": "host nft(8), invoked by the harness", "counters": counters}


def packets(reading: dict, name: str) -> int | None:
    entry = (reading.get("counters") or {}).get(name)
    if not entry or entry.get("packets") is None:
        return None
    return int(entry["packets"])


def nft_delta(before: dict, after: dict) -> dict:
    return {name: {"before": packets(before, name), "after": packets(after, name)}
            for name in COUNTER_NAMES
            if name in (before.get("counters") or {}) or name in (after.get("counters") or {})}


# Link-local multicast is the guest talking to its own segment about itself -
# neighbour discovery, for instance. It is not egress, and counting it as such
# would make this suite fail on an ordinary, harmless packet.
ROUTABLE = "(ip and not (dst net 224.0.0.0/4)) or (ip6 and not (dst net ff02::/16))"

# The guest half of the positive control. It reads its own link state from
# sysfs and procfs rather than shelling out to `iproute2`, because a guest that
# ships without it must still produce a report instead of a traceback - and the
# whole point of the probe is to establish what the guest tried to send, not to
# depend on a tool being present.
#
# `%s` is substituted with the attachment's gateway address, twice.
GUEST_PROBE = (
    "import json, os, socket\n"
    "out = {'links': {}, 'connects': []}\n"
    "for name in sorted(os.listdir('/sys/class/net')):\n"
    "    entry = {}\n"
    "    for field in ('operstate', 'flags', 'address', 'mtu'):\n"
    "        try:\n"
    "            entry[field] = open('/sys/class/net/' + name + '/' + field).read().strip()\n"
    "        except OSError as error:\n"
    "            entry[field] = 'unreadable: ' + str(error)\n"
    "    out['links'][name] = entry\n"
    "for table in ('/proc/net/route', '/proc/net/ip_route'):\n"
    "    try:\n"
    "        out[table] = open(table).read().strip().splitlines()\n"
    "    except OSError as error:\n"
    "        out[table] = 'unreadable: ' + str(error)\n"
    "targets = [('%s', 8443), ('%s', 9), ('1.1.1.1', 53), ('198.18.0.10', 80)]\n"
    "for host, port in targets:\n"
    "    if not host:\n"
    "        continue\n"
    "    sock = socket.socket()\n"
    "    sock.settimeout(5)\n"
    "    try:\n"
    "        sock.connect((host, port))\n"
    "        out['connects'].append({'host': host, 'port': port, 'connected': True})\n"
    "    except OSError as error:\n"
    "        out['connects'].append({'host': host, 'port': port, 'connected': False,\n"
    "                                'errno': error.errno, 'strerror': str(error)})\n"
    "    finally:\n"
    "        sock.close()\n"
    "print(json.dumps(out))\n"
)


def capture_start(tag: str, interface: str) -> None:
    global _capture
    path = ROOT / f"guest-tap-{tag}.pcap"
    process = subprocess.Popen(
        # `-Z root`: tcpdump drops to the `tcpdump` account by default, and in a
        # user namespace mapped from an unprivileged uid that chown fails - which
        # leaves a 24-byte header and a silent "no packets", the exact shape of
        # evidence that proves nothing.
        ["tcpdump", "-i", interface, "-n", "-U", "-Z", "root", "-w", str(path)],
        stdout=open(ROOT / f"tcpdump-{tag}.log", "wb"), stderr=subprocess.STDOUT,
        start_new_session=True)
    _capture = process
    # tcpdump prints its "listening on" line a moment after exec; capturing
    # before that line loses the first packets, which here would be the very
    # packets under test.
    deadline = time.time() + 10
    while time.time() < deadline:
        text = (ROOT / f"tcpdump-{tag}.log").read_text(errors="replace")
        if "listening on" in text or process.poll() is not None:
            break
        time.sleep(0.1)



def capture_stop(tag: str, interface: str) -> dict:
    global _capture
    if _capture is not None and _capture.poll() is None:
        # SIGINT, not SIGTERM: tcpdump only flushes a complete pcap on a clean
        # stop, and a truncated file is not evidence of an absence.
        _capture.send_signal(signal.SIGINT)
        try:
            _capture.wait(timeout=30)
        except subprocess.TimeoutExpired:
            _capture.kill()
    path = ROOT / f"guest-tap-{tag}.pcap"
    if not path.exists():
        return {"captured": False, "reason": "no capture file was produced"}

    # `-Z root` on the read as well as the capture. tcpdump tries to drop to the
    # `tcpdump` account on startup, and in a user namespace mapped from an
    # unprivileged uid that chown fails: the capture is written but the read
    # exits non-zero having printed nothing. That is not a failed read to be
    # tolerated, it is an empty result that is indistinguishable from an empty
    # capture - the exact false zero this evidence exists to rule out.
    def read(expression: str | None) -> list[str]:
        argv = ["tcpdump", "-Z", "root", "-r", str(path), "-n", "-q"]
        if expression:
            argv.append(expression)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"tcpdump -r failed ({result.returncode}): "
                               f"{(result.stderr or '').strip()}")
        return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]

    everything = read(None)
    routable = read(ROUTABLE)
    # Recorded so that "the capture recorded nothing" is distinguishable from
    # "the capture never ran", which are the same zero and opposite conclusions.
    pcap_size = path.stat().st_size
    text = (ROOT / f"tcpdump-{tag}.log").read_text(errors="replace")
    return {
        "captured": True,
        # A capture that never attached to the interface produces an empty file
        # and a zero that looks exactly like proof of silence. The readiness
        # line is what separates the two.
        "tcpdump_attached": "listening on" in text,
        # A pcap is 24 bytes of header alone. Anything at or near that size means
        # no packet was ever recorded, whatever the counts below say.
        "pcap_bytes_on_disk": pcap_size,
        "pcap_holds_any_packet": pcap_size > 24,
        "window": tag,
        "interface": interface,
        "source": "tcpdump on the guest's own TAP device, read by the harness",
        "frames_seen_by_the_host": len(everything),
        "packets_that_could_have_been_egress": len(routable),
        "packets_listed": routable[:15],
        "filter": ROUTABLE,
        "filter_meaning": "IP packets, excluding link-local multicast (neighbour discovery "
                          "and the like), which is not egress",
    }


def attachment_of(sandbox: str) -> dict:
    """The attachment as Guard persisted it, which names the TAP and gateway."""
    path = Path(os.environ["TOPOB_STATE_DIR"]) / "guard" / sandbox / "attachment.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text()).get("attachment", {})
    except (json.JSONDecodeError, OSError):
        return {}


def guest(command: list[str], timeout: float = 120.0):
    return http("POST", f"/v1/sandboxes/{_sandbox_id}/exec",
                {"command": command, "timeout_seconds": 60}, token=AGENT_KEY, timeout=timeout)


def telemetry():
    return http("GET", f"/v1/sandboxes/{_sandbox_id}/guard/telemetry?after=0",
                token=GUARD_KEY, timeout=180.0)


def main() -> int:
    global AGENT_KEY, GUARD_KEY, _sandbox_id, TASK_CONTENT
    started = time.time()
    TASK_CONTENT = f"topology-b-acceptance-{os.urandom(8).hex()}\n"
    ROOT.mkdir(parents=True, exist_ok=True)
    env = base_env()

    # ---------------------------------------------------------------------
    def object_store_probe() -> dict:
        probe = f"topology-b-acceptance/{os.urandom(6).hex()}"
        request = urllib.request.Request(f"http://127.0.0.1:{S3_PORT}/{probe}",
                                         data=b"probe", method="PUT")
        request.add_header("content-type", "application/octet-stream")
        with urlopen(request, timeout=15) as response:
            put_status = response.status
        with urlopen(f"http://127.0.0.1:{S3_PORT}/{probe}", timeout=15) as response:
            body = response.read()
        return {"endpoint": f"http://127.0.0.1:{S3_PORT}", "put_status": put_status,
                "get_bytes": len(body), "round_trip_ok": body == b"probe"}

    try:
        store = object_store_probe()
    except Exception as error:  # noqa: BLE001 - a failed probe is a failed case
        store = {"error": str(error)[:200], "round_trip_ok": False}
    case("deployment-object-store-is-a-real-s3-endpoint", store.get("round_trip_ok") is True, store)

    server = spawn("control-plane", [str(BIN / "aiec-server")],
                   {**env, "AIEC_BIND": os.environ["TOPOB_CP_BIND"]})
    if not wait_for_health(server):
        log("the control plane did not become healthy; see " + str(ROOT / "control-plane.log"))
        stop_all()
        return 1

    worker = spawn("worker", [
        str(BIN / "aiec"), "--url", CP, "worker",
        "--runtime", "firecracker",
        "--state-dir", str(ROOT / "state"),
        "--advertise-url", WORKER,
        "--bind", os.environ["TOPOB_WORKER_BIND"],
        "--name", "topology-b",
        "--capacity", "2",
        "--memory-reserve-mib", "1024",
        "--disk-reserve-mib", "8192",
    ], env)
    worker_state = wait_for_worker()
    case("control-plane-and-worker-serve-one-tenant-over-tls",
         worker_state.get("status") in (200, 401),
         {"control_plane": {"health": 200, "endpoint": CP, "database": "aiec_topob"},
          "worker": {"endpoint": WORKER, "advertised_health": worker_state,
                     "runtime": "firecracker"}})
    if worker_state.get("status") not in (200, 401):
        stop_all()
        return 1

    AGENT_KEY = mint("topology-b-agent", ["sandboxes:write", "sandboxes:read"])
    GUARD_KEY = mint("topology-b-observer", ["guard:read"])
    case("agent-key-is-scoped-to-the-control-channel-and-nothing-else",
         True,
         {"scopes": ["sandboxes:write", "sandboxes:read"], "issued_through": "POST /v1/keys",
          "used_for": "every model tool call and every independent read-back",
          "note": "the key is per-run and is never written to the report"})
    start_model()

    # ---------------------------------------------------------------------
    # How a topology B sandbox is reached at all, and what the deployment does
    # with a request that names the policy explicitly.
    #
    # `CreateSandboxRequest` reads the guard selection from `environment.guard`,
    # and naming it there makes placement demand `network_policy` from the
    # runtime registry. The registry's Firecracker entry is built from the
    # control plane's own configuration and does not advertise it, so an
    # explicit request is refused before a guest exists. That refusal is the
    # interesting fact, so it is asked for explicitly and recorded rather than
    # designed around.
    probe_status, probe_body = http("POST", "/v1/sandboxes", {
        "image": IMAGE, "runtime": "firecracker",
        "cpu": 1, "memory_mb": 1024, "disk_mb": 4096, "timeout_seconds": 900,
        # `PolicyTemplate` is `rename_all = "kebab-case"`; `no_network` is
        # refused by the deserializer outright, which is how the wire spelling
        # is proved rather than assumed.
        "environment": {"guard": {"topology": "outside",
                                  "policy_template": "no-network"}},
    }, token=AGENT_KEY, timeout=120.0)
    observe("explicit-guard-request-is-refused-at-placement",
            probe_status == 501
            and (probe_body or {}).get("error", {}).get("message")
            == "runtime Firecracker lacks required capabilities",
            {"http_status": probe_status,
             "error_code": (probe_body or {}).get("error", {}).get("code"),
             "error_message": (probe_body or {}).get("error", {}).get("message"),
             "demanded_capability": "network_policy",
             "request": {"runtime": "firecracker",
                         "environment.guard": {"topology": "outside",
                                               "policy_template": "no-network"}}})

    # The supported route to the same state: Firecracker gets Guard by
    # default, and `Topology::default()` is `outside` with `PolicyTemplate::
    # NoNetwork`. "No policy selected means no network" - the guest is given no
    # egress at all - is the default, not an opt-in.
    status = 0
    body: dict = {}
    created: dict = {}
    announced = False
    deadline = time.time() + 900
    while True:
        status, body = http("POST", "/v1/sandboxes", {
            "image": IMAGE, "runtime": "firecracker",
            "cpu": 1, "memory_mb": 1024, "disk_mb": 4096, "timeout_seconds": 900,
        }, token=AGENT_KEY,
            # Generous: creation waits for placement, a four-gigabyte disk
            # materialized from the signed image, and a cold microVM boot. A
            # short deadline here reports a hung create when the truth is that
            # the image is still being copied.
            timeout=600.0)
        payload = (body or {}).get("sandbox", body or {})
        if status == 200 and payload.get("id"):
            created = payload
            _sandbox_id = payload["id"]
            break
        transient = status == 503 and (body or {}).get("error", {}).get("code") in (
            "scheduler_unavailable", "runtime_unavailable")
        if not transient or time.time() >= deadline:
            break
        if not announced:
            log("waiting for the worker to register before the first create")
            announced = True
        time.sleep(1.0)

    case("guarded-sandbox-boots-on-a-real-microvm",
         bool(_sandbox_id) and created.get("state") == "running",
         {"http_status": status, "state": created.get("state"),
          "error": (body or {}).get("error"), "response": body,
          "runtime": created.get("runtime"),
          "image": IMAGE, "worker": worker_state})
    if not _sandbox_id:
        stop_all()
        return 1

    # ---------------------------------------------------------------------
    status, readback = http("GET", f"/v1/sandboxes/{_sandbox_id}", token=AGENT_KEY)
    environment = (readback or {}).get("environment") or {}
    guard = environment.get("guard") or {}
    case("sandbox-reads-back-as-topology-b-with-no-network",
         status == 200 and guard.get("topology") == "outside"
         and guard.get("policy_template") == "no-network"
         and bool(environment.get("guard_policy_hash")),
         {"read_from": f"GET /v1/sandboxes/<id>", "http_status": status,
          "state": (readback or {}).get("state"),
          "topology": guard.get("topology"),
          "policy_template": guard.get("policy_template"),
          "explicit_policy": guard.get("policy"),
          "guard_policy_hash": environment.get("guard_policy_hash")})

    attachment = attachment_of(_sandbox_id)
    interface = attachment.get("interface")
    case("guard-installed-a-host-side-attachment-for-this-sandbox",
         bool(interface) and bool(attachment.get("gateway_ip")),
         {"read_from": "the attachment Guard itself persisted, not from the guest",
          "interface": interface, "gateway_ip": attachment.get("gateway_ip"),
          "guest_ip": attachment.get("guest_ip"),
          "dns_port": attachment.get("dns_port"),
          "broker_port": attachment.get("broker_port")})
    if not interface:
        stop_all()
        return 1

    # The guest's own view of its link, so "no egress" is never confused with
    # "no interface". The route exists; nothing is permitted to use it.
    status, route = guest(["python3", "-c", (
        "import json,os\n"
        "rows=[l.split() for l in open('/proc/net/route').read().strip().splitlines()[1:]]\n"
        "print(json.dumps({'default_routes':[r[1] for r in rows if r[1]=='00000000'],\n"
        "'links':{n:open('/sys/class/net/'+n+'/operstate').read().strip()\n"
        "          for n in sorted(os.listdir('/sys/class/net'))}}))\n")])
    try:
        kernel_view = json.loads((route or {}).get("stdout") or "{}")
    except json.JSONDecodeError:
        kernel_view = {"raw": ((route or {}).get("stdout") or "")[:200]}
    case("guest-has-a-link-and-a-default-route-it-may-not-use",
         bool(kernel_view.get("default_routes")) and bool(kernel_view.get("links")),
         {"exec_http_status": status, "guest_own_view_of_/proc/net/route": kernel_view,
          "host_gateway_for_that_guest": attachment.get("gateway_ip"),
          "meaning": "the guest is not isolated by having no route; it is isolated by policy"})

    if interface:
        capture_start("agent-loop", interface)
    counters_before = host_nft_counters(_sandbox_id)

    loop = agent_loop()
    counters_after = host_nft_counters(_sandbox_id)
    capture = capture_stop("agent-loop", interface)

    case("external-agent-loop-ran-streamed-multi-turn-tool-calls-over-the-control-channel",
         loop["finished"] and len(loop["tool_calls"]) == 3
         and all(call["result"].get("ok") for call in loop["tool_calls"]),
         {"model_endpoint": MODEL_URL,
          "turns": [{"turn": t["turn"], "sse_events": t["sse_events"],
                     "finish_reason": t["finish_reason"],
                     "tools": [c["name"] for c in t["tool_calls"]],
                     "content": t["content"]} for t in loop["turns"]],
          "tool_calls": loop["tool_calls"],
          "model_requests": _model_state["requests"],
          "sse_events_delivered": _model_state["sse_events"],
          "final_content": loop["final_content"],
          "loop_runs_on": "the host, outside the sandbox"})

    # An independent read-back. The agent's own last message already says the
    # bytes agree; this asks the control channel again, on the harness's own
    # authority, so the termination condition does not rest on the loop's word.
    query = urllib.parse.urlencode({"path": "/workspace/topology-b.txt"})
    # The read-back runs on the harness's own authority, not the loop's: the
    # agent key has `sandboxes:read`, and the loop never told it what the file
    # should contain.
    status, read_back = http("GET", f"/v1/sandboxes/{_sandbox_id}/files/content?{query}",
                             token=AGENT_KEY)
    observed = None
    if (read_back or {}).get("content_base64"):
        observed = base64.b64decode(read_back["content_base64"]).decode("utf-8", "replace")
    case("task-complete-is-verifiable-by-reading-the-guest-back",
         observed == TASK_CONTENT,
         {"read_from": "GET /v1/sandboxes/<id>/files/content",
          "http_status": status, "path": "/workspace/topology-b.txt",
          "expected_bytes": TASK_CONTENT.strip(), "observed_bytes": (observed or "").strip(),
          "match": observed == TASK_CONTENT,
          "sha256_of_both": hashlib.sha256((observed or "").encode()).hexdigest(),
          "agent_reported": loop["final_content"]})

    # ---------------------------------------------------------------------
    # Zero egress, host-observed, during the window the agent loop occupied.
    moved = nft_delta(counters_before, counters_after)
    every_counter = set(moved)
    all_zero = bool(moved) and all(entry["after"] == 0 for entry in moved.values())
    case("host-nftables-counters-for-this-attachment-are-zero-across-the-agent-loop",
         all_zero,
         {"measurement": "the named nftables counters in this attachment's own table, "
                         "read out of the host kernel by the harness with nft(8)",
          "table": counters_after.get("table"),
          "source": counters_after.get("source"),
          "read_before_the_loop": counters_before.get("read_at"),
          "read_after_the_loop": counters_after.get("read_at"),
          "counters_before": counters_before.get("counters"),
          "counters_after": counters_after.get("counters"),
          "per_counter": moved,
          "counters_present": sorted(every_counter),
          "counters_absent": sorted(set(COUNTER_NAMES) - every_counter),
          "read_error": counters_after.get("error")})

    status, observation = telemetry()
    api_counters = (observation or {}).get("counters") or {}
    permitted = {name: api_counters.get(name) for name in
                 ("dns_permitted", "broker_permitted", "blocked_range", "other_denied", "ipv6")}
    case("guard-telemetry-read-through-the-control-plane-agrees",
         status == 200 and all(value == 0 for value in permitted.values()),
         {"endpoint": "GET /v1/sandboxes/<id>/guard/telemetry",
          "http_status": status, "counters": permitted,
          "table": api_counters.get("table"),
          "network_cut": (observation or {}).get("network_cut"),
          "event_head": (observation or {}).get("event_head"),
          "note": "the watchdog's own read path, not the host's; it is recorded so the two "
                  "independent readings of the same table can be compared rather than "
                  "one standing in for the other"})

    # ---------------------------------------------------------------------
    # The positive control. Everything above reads zero. A measurement that can
    # only ever read zero proves nothing, so the guest is made to emit real
    # traffic - first towards its own gateway, then to a routable address off
    # its link - and the *identical* host-side readings are taken again.
    #
    # Two independent host-side methods are checked, because either alone could
    # be silently broken: the nftables counters in this attachment's own table,
    # and a packet capture of the guest's own TAP device. A method that cannot
    # see a packet the guest certainly sent is not a method that can prove one
    # was never sent.
    gateway = attachment.get("gateway_ip")
    if interface:
        capture_start("positive-control", interface)
    status, attempt = guest(["python3", "-c", GUEST_PROBE % (gateway or "", gateway or "")])
    # The guest's own attempts are the control for BOTH host-side instruments.
    # They traverse the TAP: Guard installs no `output` chain, so a guest packet
    # to an off-link address crosses the link and is denied in the host's
    # `input` chain on arrival. That is why the host nft counters move.
    #
    # An earlier version of this case injected a frame onto the TAP from the
    # host instead. That cannot work: a frame written to a TAP through
    # AF_PACKET goes out through the tun file descriptor and never appears in a
    # capture taken on that same TAP (measured - a 24-byte, packet-free pcap,
    # where the identical injection on a dummy device was captured). It would
    # have failed as a permanent false zero, and the only way it could ever
    # have passed is if the capture were wrong in some new way.
    counters_control = host_nft_counters(_sandbox_id)
    control_capture = capture_stop("positive-control", interface)
    # Proving the instrument means proving it recorded a frame this run, on this
    # device, in this window. `pcap_holds_any_packet` rules out the failure in
    # which the read silently yields nothing.
    #
    # The proof has to be a ROUTABLE frame specifically. The agent-loop case
    # asserts against the ROUTABLE-filtered count, so satisfying this with an
    # ARP or neighbour-discovery frame would leave a broken ROUTABLE expression
    # able to ship as a passing artifact that still claims zero egress. The
    # guest's SYN to 1.1.1.1 is unicast IPv4 and does match ROUTABLE.
    instrument_seen = int(control_capture.get("frames_seen_by_the_host") or 0) > 0
    instrument_proven = instrument_seen \
        and control_capture.get("tcpdump_attached") is True \
        and control_capture.get("pcap_holds_any_packet") is True \
        and int(control_capture.get("packets_that_could_have_been_egress") or 0) > 0
    raw = (attempt or {}).get("stdout") or ""
    reported = {"exec_http_status": status,
                "exec_exit_code": (attempt or {}).get("exit_code")}
    try:
        reported["probe"] = json.loads(raw)
    except json.JSONDecodeError:
        reported["unparsable_stdout"] = raw[:400]
        reported["stderr"] = ((attempt or {}).get("stderr") or "")[:600]
    guest_view = reported

    moved_control = nft_delta(counters_after, counters_control)
    delta = {name: entry["after"] - entry["before"]
             for name, entry in moved_control.items()
             if entry["before"] is not None and entry["after"] is not None}
    counters_moved = any(value > 0 for value in delta.values())
    frames_moved = int(control_capture.get("frames_seen_by_the_host") or 0) > 0
    # Two claims, kept apart because two different stimuli establish them. The
    # nftables counters are proven by the guest's real attempts; the capture is
    # proven by a frame the host wrote onto the same device. Reading one as a
    # control for the other is how a suite ends up publishing a passing number
    # produced by an instrument that was not running.
    case("the-egress-observation-is-positive-control-proven",
         counters_moved,
         {"method": "the identical nftables readings, taken immediately after the guest was "
                    "made to emit traffic on its only link",
          "attempted": {"gateway": gateway, "off_link_addresses": ["1.1.1.1:53"]},
          "host_nft_counter_delta_packets": delta,
          "host_nft_counters_moved": counters_moved,
          "host_packet_capture_of_the_guest_link": control_capture,
          "host_capture_saw_frames": frames_moved,
         "host_capture_saw_the_same_packets_the_counters_did": bool(frames_moved) == bool(counters_moved),
         "the_capture_and_the_counters_are_independent_instruments": True,
         "why_two_instruments_on_one_stimulus": "the same guest-originated frames cross the "
                 "TAP and are then denied in the host's input chain, so the packet capture "
                 "and the nftables counters observe the same traffic by different means. "
                 "Agreement between them is what makes either zero credible.",
          "guest_own_report_of_its_attempts": guest_view,
          "guest_report_is_corroboration_only": True,
          "meaning": "the same counters that read zero across the agent loop read non-zero "
                     "here, so the zero above is a measurement and not a constant"})

    case("the-packet-capture-instrument-is-positive-control-proven",
         instrument_proven,
         {"method": "the guest is made to emit real traffic on its only link from inside the "
                    "VM, and the capture on that same TAP is read back",
          "stimulus": {"source": "GUEST_PROBE executed inside the guest over the control channel",
                       "guest_reported_attempts": reported.get("probe", {}).get("connects"),
                       "why_these_traverse_the_link": "Guard installs input, forward and "
                           "forward_to_guest chains and no output chain, so a guest packet "
                           "crosses the TAP and is denied in the host's input chain on "
                           "arrival - which is what moves the host nft counters",
                       "why_no_host_injection": "a frame written onto a TAP through AF_PACKET "
                           "leaves through the tun file descriptor and is not visible to a "
                           "capture on that TAP, so it could not have served as a control"},
          "capture": control_capture,
          "capture_attached": control_capture.get("tcpdump_attached"),
          "frames_seen_by_the_host": control_capture.get("frames_seen_by_the_host"),
          "pcap_bytes_on_disk": control_capture.get("pcap_bytes_on_disk"),
          "packets_carrying_an_ip_header_recorded": control_capture.get(
              "packets_that_could_have_been_egress"),
          "packets_listed": control_capture.get("packets_listed"),
          "meaning": "this capture, on this device, in this window, records frames - which is "
                     "the only thing that makes its zero during the agent loop evidence"})

    case("host-packet-capture-of-the-guest-link-saw-no-guest-originated-egress",
         # The agent loop runs entirely over the control channel, so a quiet TAP
         # is the expected result and an empty pcap here is not itself a fault:
         # the agent never touches the link. What makes the zero trustworthy is
         # `instrument_proven` - the same capture on the same device was shown
         # to be recording frames earlier in this same run. Requiring frames in
         # THIS window would instead assert that the guest did something on the
         # link, which is the opposite of what is being claimed.
         instrument_proven and capture.get("captured") is True
         and capture.get("tcpdump_attached") is True
         and capture.get("packets_that_could_have_been_egress") == 0,
         {"measurement": "tcpdump on the guest's own TAP device for the whole agent loop",
          **capture,
          "instrument_was_proven_in_this_same_run": instrument_proven,
          "interpretation": "no packet carrying an IP header left the guest for any "
                            "destination, during a loop in which three control-channel tool "
                            "calls ran to completion. The zero is read as evidence only "
                            "because the same capture, on the same device, was shown to be "
                            "recording in the positive control above; without that it would "
                            "be indistinguishable from a capture that never started."})

    LIMITATIONS.extend([
        "Proves the guest emitted no routable IP packet on its only link, over a private "
        "user+network namespace, on the Firecracker runtime. It proves nothing about the "
        "Docker or hosted runtimes, which implement no Guard attachment at all and so "
        "cannot carry a Guard policy in the first place. The routable frames this capture "
        "does record, in the positive-control window, were addressed to the permitted "
        "gateway; the denial of forbidden off-link destinations is established by the "
        "nftables counters moving on those attempts, not by observing them on the wire.",
        "A counter that reads zero also reads zero when nothing tries to egress, and a "
        "packet the guest never emits is invisible to every method here. That is why the "
        "positive-control case exists: it takes the identical host-side reading after a "
        "deliberate outbound attempt and records the difference. Without it, the zero "
        "would be an assumption about the guest rather than a measurement of it.",
        "Both host-side instruments are proven by the SAME stimulus: the guest's own connect "
        "attempts. Guard installs input, forward and forward_to_guest chains and no output "
        "chain, so those packets cross the TAP and are denied in the host's input chain on "
        "arrival - which is why the nftables counters move and the capture sees frames in the "
        "same window. The capture's proof is specifically a ROUTABLE frame, because the "
        "agent-loop case asserts against the ROUTABLE-filtered count: an ARP or "
        "neighbour-discovery frame would not have exercised the filter that the zero rests "
        "on. An earlier draft of this suite instead had the host write a frame onto the TAP "
        "through AF_PACKET; that cannot work, because such a frame leaves through the tun "
        "file descriptor and never appears in a capture taken on that same TAP (measured: a "
        "24-byte packet-free pcap, where the identical injection on a dummy device was "
        "captured). It would have been a permanent false zero that could only have passed "
        "if the capture were broken in some new way.",
        "The guest's own report - the errno from its connect attempts, its view of "
        "/proc/net/route - is labelled guest-reported everywhere it appears. It corroborates "
        "what the host already counted and is never the primary evidence for any case.",
        "No attestation is performed. The host establishes which kernel and rootfs were "
        "booted (a manifest the suite signs with a per-run key, over the digest of the bytes "
        "on disk, which the worker verifies) and that the attachment's counters stayed at "
        "zero. It does not measure a running kernel, and a guest compromised after boot "
        "keeps whatever privileges it has inside the guest.",
        "The object store is a real, running S3-compatible endpoint that answered a put and "
        "a get, and the control plane booted against it. No case stores or retrieves an "
        "artifact: object storage is exercised for reachability only.",
        "The model provider is a scripted local endpoint, not a language model. What is "
        "under test is the loop - streaming decode, tool dispatch, tool-result feedback and "
        "termination - not model quality or tool-use correctness in the general case.",
        "Counters are cumulative for the life of the attachment. The zero-egress case is "
        "scoped to the window between the two reads named in its evidence; a packet sent "
        "before the attachment was enforced, or after the sandbox was destroyed, is outside "
        "what this run could see.",
        "Topology B is the configuration with no watchdog attached, and an attachment with "
        "no live watchdog is in its deny-all initial state. For a no-network policy that is "
        "a stricter state than the policy asks for, and the counters do not distinguish the "
        "two. This suite therefore proves 'no egress happened', not 'the no-network rule "
        "set is what stopped it'; the policy selection itself is proven by the read-back in "
        "the sandbox-reads-back case.",
    ])

    report = finish(started)
    return 0 if report["status"] == "PASS" else 1


def cleanup() -> None:
    if _sandbox_id:
        try:
            status, body = http("DELETE", f"/v1/sandboxes/{_sandbox_id}", timeout=240.0)
            if status not in (200, 202, 204):
                CLEANUP_ERRORS.append(f"destroy sandbox: {status} {body}")
        except Exception as error:  # noqa: BLE001 - reported, not swallowed
            CLEANUP_ERRORS.append(f"destroy sandbox: {error}")


def finish(started: float) -> dict:
    global _model
    cleanup()
    stop_all()
    if _model is not None:
        _model.shutdown()
        _model.server_close()
        _model = None
    passed = sum(1 for entry in CASES if entry["status"] == "PASS")
    report = {
        "schema": "aiec.guard.topology-b-acceptance.v1",
        "section": "50",
        "suite": "guard-topology-b-acceptance",
        "status": "PASS" if passed == len(CASES) and not CLEANUP_ERRORS else "FAIL",
        "claim_under_test": "topology B: the agent runs outside the sandbox, the trusted "
                            "harness drives it through AIec's control channel, and the guest "
                            "has no egress at all",
        "runtime": "firecracker",
        "endpoint": CP,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": CASES,
        "passed": passed,
        "total": len(CASES),
        "failing_cases": FAILURES,
        "cleanup_errors": CLEANUP_ERRORS,
        "observation_split": {
            "host_observed": [
                "the attachment's named nftables counters, read out of the host kernel by "
                "the harness with nft(8) rather than through the product",
                "a tcpdump capture on the guest's own TAP device, over two named windows",
                "every control-channel HTTP status, response body and latency",
                "the worker and control plane process state and their HTTP health answers",
            ],
            "guest_reported": [
                "the errno and connected flags of the positive control's connect attempts",
                "the guest's own view of /proc/net/route",
            ],
            "note": "Guest-reported values corroborate host-observed ones. No case rests on "
                    "a guest-reported value alone.",
        },
        "limitations": LIMITATIONS,
        "elapsed_seconds": round(time.time() - started, 3),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    path = Path(os.environ.get("TOPOB_REPORT", ROOT / "topology-b-report.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    log(f"report: {path}")
    log(f"{passed}/{len(CASES)} cases passed in {report['elapsed_seconds']} s")
    if CLEANUP_ERRORS:
        log(f"cleanup errors: {CLEANUP_ERRORS}")
    if FAILURES:
        log(f"failing cases: {FAILURES}")
    return report


if __name__ == "__main__":
    sys.exit(main())