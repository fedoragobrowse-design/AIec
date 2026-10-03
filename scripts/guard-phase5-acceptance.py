#!/usr/bin/env python3
"""Disposable phase 5 acceptance: synthetic canaries, signed-image admission and
per-VM control identities.

Everything here runs against real components in a private user+network
namespace started by scripts/guard-phase5-acceptance.sh:

  * the signed-image and per-VM identity half is the shipped
    ``guard_phase5_acceptance`` example binary driving real local Firecracker
    guests over the authenticated vsock control channel;
  * the canary half is the real control plane and worker: a guarded sandbox
    with configurable synthetic file, hostname and credential canaries, a guest
    that actually reads/resolves/presents them, and the worker's authenticated
    quarantine callback latching durable state in the control plane.

No canary value, guest secret, identity key or signing key is ever written to a
report, a log or stdout. Reports carry digests, counts and event metadata only.
"""
from __future__ import annotations

import atexit
import base64
import json
import os
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid
from pathlib import Path

ROOT = Path(os.environ["P5_ROOT"])
SANDBOXES: set[str] = set()
BIN = Path(os.environ["P5_BIN"])
CA = Path(os.environ["P5_CA"])
CP = os.environ["P5_CP"]
WORKER = os.environ["P5_WORKER"]
TENANT = os.environ["P5_TENANT"]
API_KEY = os.environ["P5_API_KEY"]
WORKER_TOKEN = os.environ["P5_WORKER_TOKEN"]
DATABASE_URL = os.environ["DATABASE_URL"]
# The Guard journal read from the worker's runtime state is host-side
# observation of what the worker saw, not a summary the control plane composed.
# The Firecracker runtime keeps VM disks and Guard attachments under
# AIEC_STATE_DIR, which the launcher sets to a scratch directory next to the
# worker's own state. Reading the journal from the wrong root finds no file,
# which is indistinguishable from a canary that never fired.
WORKER_STATE = Path(os.environ.get("AIEC_STATE_DIR", str(ROOT / "state-vms")))

# A guarded attachment is deny-all until an independent watchdog heartbeats
# it, and the gateway latches a network cut when that heartbeat stops. Every
# case below therefore runs against a real `aiec-guard-watchdog` process, begun
# with the sandbox and stopped with it, rather than a heartbeat this driver
# could send on the watchdog's behalf.
WATCHDOG_TOKEN: str | None = None
WATCHDOG_SCOPES = ["guard:read", "guard:heartbeat", "guard:quarantine"]
_watchdogs: dict[str, subprocess.Popen] = {}

CANARY_LABEL = "phase5"
# The canary sits in a directory of its own because the tripwire fires on any
# read inside the directory that holds it, which is the point: an agent that
# lists the directory has learned the file exists. A control read placed beside
# it would therefore trip the tripwire it exists to show does not trip, so the
# controls live in `/workspace/plain` and the canary lives in `/workspace/secrets`.
CANARY_FILE_PATH = "/workspace/secrets/phase5-file-canary.txt"
CANARY_HOSTNAME = "phase5-canary.invalid"
CANARY_CREDENTIAL = "phase5-canary-credential"
CANARY_VALUE = f"aiec-canary:{CANARY_LABEL}-" + uuid.uuid4().hex
# The model route exists only to give the guest a broker address and a
# credential binding. Nothing ever answers on it: no case below depends on an
# upstream reply, only on what the gateway observes and decides.
MODEL_HOST = "model.phase5.invalid"
MODEL_PORT = 18080
MODEL_CREDENTIAL = "model-main"


CASES: list[dict] = []
FAILURES: list[str] = []
CLEANUP_ERRORS: list[str] = []
_started: list[tuple[str, subprocess.Popen]] = []


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def case(name: str, ok: bool, evidence: dict) -> bool:
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    log(f"{'PASS' if ok else 'FAIL'} {name}")
    if not ok:
        FAILURES.append(name)
    return ok


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def http(method: str, path: str, body=None, token: str = API_KEY, timeout: float = 90.0):
    request = urllib.request.Request(CP + path, method=method)
    request.add_header("authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(
            request, data=data, timeout=timeout,
            context=ssl.create_default_context(cafile=str(CA)),
        ) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, (json.loads(raw) if raw else None)
        except json.JSONDecodeError:
            return error.code, {"raw": raw[:400].decode(errors="replace")}


def spawn(name: str, argv: list[str], env: dict | None = None) -> subprocess.Popen:
    log_env = dict(os.environ)
    log_env.update(env or {})
    handle = open(ROOT / f"{name}.log", "wb", buffering=0)
    process = subprocess.Popen(
        argv, stdout=handle, stderr=subprocess.STDOUT, env=log_env, start_new_session=True
    )
    _started.append((name, process))
    # Recorded for the launcher as well as for this process. Every service here
    # is started in its own session so it survives nothing but being told to
    # stop, which means a driver that dies without running its teardown - a
    # killed harness job, an unhandled error between spawning the control plane
    # and reaching it - leaves a control plane running against a database the
    # launcher is about to stop. The launcher sweeps this file, so a lost
    # driver still cannot leave a service behind.
    record = ROOT / "services.pid"
    with open(record, "a", encoding="utf-8") as handle_pid:
        handle_pid.write(f"{name} {process.pid}\n")
    return process


def stop_all() -> None:
    for name, process in reversed(_started):
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=10)
                except Exception:
                    CLEANUP_ERRORS.append(f"{name} did not stop")
        log_path = ROOT / f"{name}.log"
        if log_path.exists():
            os.chmod(log_path, 0o600)
    log("stopped: " + ", ".join(name for name, _ in _started))
    if (ROOT / "services.pid").exists():
        (ROOT / "services.pid").unlink()


# Registered rather than called at the end of `main` alone: this is a process
# that has already started a database-backed control plane and a Firecracker
# worker, and every exit that is not the one it planned is a path that used to
# leave them running. The report is written from the teardown-free path as
# # before; this only adds the exits that had nothing running to stop.
atexit.register(stop_all)


def _signal_exit(number, _frame):
    """Turn a signal into an ordinary exit so the atexit teardown runs.

    `SIGKILL` cannot be caught and is handled by the launcher's sweep of
    `services.pid`; everything gentler ends up here.
    """
    sys.exit(128 + number)


signal.signal(signal.SIGTERM, _signal_exit)
signal.signal(signal.SIGINT, _signal_exit)


def wait_for_health(process: subprocess.Popen, url: str, token: str | None = None,
                    seconds: float = 90.0) -> tuple[bool, str]:
    """Polls until the endpoint answers 200, the process exits, or time runs
    out, and says why it stopped.

    A swallowed exception here costs the full ninety-second wait and reports
    nothing: a TLS mismatch, a refused connection and a wrong path all read as
    "not healthy". The reason travels back to the caller's evidence.
    """
    context = ssl.create_default_context(cafile=str(CA))
    deadline = time.time() + seconds
    last = "no attempt completed"
    while time.time() < deadline:
        if process.poll() is not None:
            return False, f"the process exited with {process.returncode}"
        try:
            request = urllib.request.Request(url)
            if token:
                request.add_header("authorization", f"Bearer {token}")
            with urllib.request.urlopen(request, timeout=5.0, context=context) as response:
                if response.status == 200:
                    return True, "200"
                last = f"HTTP {response.status}"
        except Exception as error:
            last = f"{type(error).__name__}: {error}"
        time.sleep(1.0)
    return False, f"still unhealthy after {seconds:.0f}s: {last}"


def base_env() -> dict:
    env = {
        # The harness and the shipped processes look up real tools on PATH. The
        # guest control identity is installed with `debugfs`, which lives in
        # /usr/sbin and is outside the default search path a child inherits
        # when it is handed a fresh environment. A run that boots a guest
        # without it fails at identity installation, which reads like a product
        # fault and is not one.
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
        "HOME": os.environ.get("HOME", str(ROOT)),
        "DATABASE_URL": DATABASE_URL,
        "AIEC_RUNTIME": "firecracker",
        "AIEC_FIRECRACKER_BIN": os.environ["AIEC_FIRECRACKER_BIN"],
        "AIEC_KERNEL": os.environ["AIEC_KERNEL"],
        "AIEC_ROOTFS": os.environ["AIEC_ROOTFS"],
        "AIEC_GUEST_ARTIFACT_DIR": os.environ["AIEC_GUEST_ARTIFACT_DIR"],
        "AIEC_GUEST_SECRET": os.environ["AIEC_GUEST_SECRET"],
        "AIEC_IMAGE_MANIFEST": os.environ["AIEC_IMAGE_MANIFEST"],
        "AIEC_IMAGE_MANIFEST_SECRET": os.environ["AIEC_IMAGE_MANIFEST_SECRET"],
        "AIEC_TLS_CERT_FILE": os.environ["P5_TLS_CERT"],
        "AIEC_TLS_KEY_FILE": os.environ["P5_TLS_KEY"],
        "AIEC_TLS_CA_CERT": str(CA),
        "AIEC_S3_ENDPOINT": os.environ["P5_S3_ENDPOINT"],
        "AIEC_S3_REGION": "us-east-1",
        "AIEC_S3_BUCKET": "aiec",
        "AIEC_S3_ACCESS_KEY_ID": os.environ["P5_S3_ACCESS_KEY_ID"],
        "AIEC_S3_SECRET_ACCESS_KEY": os.environ["P5_S3_SECRET_ACCESS_KEY"],
        "AIEC_S3_PREFIX": "phase5/",
        "AIEC_TENANT_ID": TENANT,
        "AIEC_TENANT_NAME": "phase5",
        "AIEC_API_KEY": API_KEY,
        "AIEC_WORKER_TOKEN": WORKER_TOKEN,
        "AIEC_LEASE_TTL_SECONDS": "300",
        # Verbosity for the control plane and the worker this run starts.
        # Defaults to the shipped default; `P5_LOG=aiec_runtime=debug,debug`
        # is how a boot failure is read at the level that produced it rather
        # than guessed at from the API's one-line error.
        "RUST_LOG": os.environ.get("P5_LOG", "info"),
    }
    for key in ("AIEC_FIRECRACKER_BIN", "AIEC_KERNEL", "AIEC_ROOTFS",
                "AIEC_GUEST_ARTIFACT_DIR", "AIEC_GUEST_SECRET",
                "AIEC_IMAGE_MANIFEST", "AIEC_IMAGE_MANIFEST_SECRET"):
        env.setdefault(key, os.environ.get(key, ""))
    return env


# ---------------------------------------------------------------- guest stimuli

# Each stimulus runs inside the real guest, over the control channel, and reads
# nothing from the host but the broker address the guest itself was given.
GUEST_DNS = """
import json, os, re, socket, sys

name = sys.argv[1]
report = {"queried": name, "resolvers": [], "direct": None}
try:
    with open("/etc/resolv.conf") as handle:
        report["resolvers"] = [line.split()[1] for line in handle
                               if line.strip().startswith("nameserver")]
except OSError as error:
    report["resolv_error"] = type(error).__name__
try:
    print(json.dumps({**report, "resolved":
                      sorted({r[4][0] for r in socket.getaddrinfo(name, None, socket.AF_INET)}),
                      "error": None}))
    raise SystemExit(0)
except OSError as error:
    pass
# The resolver path is the one under test; this says whether the attachment's
# own resolver answered at all, which separates "the guest is misconfigured"
# from "the gateway refused".
if report["resolvers"]:
    query = (b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
             + b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\\x00"
             + b"\\x00\\x01\\x00\\x01")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(3)
            probe.sendto(query, (report["resolvers"][0], 53))
            answer, _ = probe.recvfrom(4096)
        report["direct"] = {"bytes": len(answer), "rcode": answer[3] & 0x0F}
    except OSError as error:
        report["direct"] = {"error": type(error).__name__}
print(json.dumps({**report, "resolved": [], "error": "resolution failed"}))
"""

GUEST_PRESENT = """
import json, os, socket, sys
from urllib.parse import urlsplit

placeholder = sys.argv[1]
base = os.environ.get("AIEC_MODEL_BASE_URL") or os.environ.get("AIEC_AGENT_BASE_URL") or ""
target = urlsplit(base)
if not target.hostname:
    print(json.dumps({"error": "no broker address in the guest environment"}))
    raise SystemExit(0)
# The same endpoint and Host the guest's own SDK would use, with an arbitrary
# presented placeholder: nothing here depends on the policy naming the canary.
request = ("POST " + target.path + " HTTP/1.1\\r\\nHost: " + target.netloc +
           "\\r\\nAuthorization: Bearer " + placeholder +
           "\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n").encode()
try:
    with socket.create_connection((target.hostname, target.port or 80), timeout=5) as sock:
        sock.sendall(request)
        reply = sock.recv(64)
    print(json.dumps({"status": int(reply.split()[1]) if reply else None, "presented": placeholder}))
except OSError as error:
    print(json.dumps({"status": None, "error": type(error).__name__}))
"""


def guest(sandbox: str, command: list[str], timeout: float = 60.0):
    return http("POST", f"/v1/sandboxes/{sandbox}/exec",
                {"command": command, "timeout_seconds": 30}, timeout=timeout)

def journal(sandbox: str) -> list[dict]:
    """The host's own Guard journal for the attachment, read from the worker
    state directory. These are the events the worker observed, not a summary
    the control plane composed."""
    path = WORKER_STATE / "guard" / sandbox / "events.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def live_guest_processes(sandboxes: set[str]) -> dict[str, int]:
    """Firecracker processes still on the host for sandboxes this run made.

    The disk census above says a VM directory is gone; it says nothing about the
    process that was using it. Firecracker is exec'd with its `--api-sock`
    path as the only argument that names the machine, and that path carries
    the sandbox id, so the id is what ties a live process back to this run and
    keeps another run's guests out of the count. Without this the report has
    to infer guest survival from the mechanism that leaves one behind; with it
    the answer is read off the host.
    """
    found: dict[str, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        if "firecracker" not in argv:
            continue
        for sandbox in sandboxes:
            if sandbox in argv:
                found.setdefault(sandbox, int(entry.name))
    return found


def canary_events(sandbox: str, kind: str) -> list[dict]:
    """The trip records for one tripwire kind.

    Matched on the leading words of the reason, not on a category and not on a
    substring: a canary is journaled under the category its policy decision
    belongs to, so a hostname tripwire arrives as `dns` and a file or credential
    tripwire as `credential`, and the three differ only in the reason they
    state. The refusal a canary credential also produces is a network denial
    whose reason merely mentions the canary, so a substring match would count
    one trip as two and then fail the trip on the denial's decision.
    """
    return [row for row in journal(sandbox)
            if str(row.get("reason", "")).startswith(f"canary {kind}")]


def canary_severity(row: dict) -> str:
    """The severity a canary record states, or "" when it states none.

    The journal has no severity column: the record states it in its reason, so
    severity is read from there. Reading a `severity` field that does not exist
    would make every canary look unclassified and turn a real firing into a
    false negative.
    """
    reason = str(row.get("reason", ""))
    for level in ("critical", "high", "medium", "low"):
        if f"severity {level}" in reason:
            return level
    return ""


def canary_evidence(rows: list) -> list:
    """The journal fields a canary record actually carries."""
    return [{key: row.get(key) for key in
             ("category", "decision", "reason", "destination", "current_hash")}
            for row in rows]


def telemetry(sandbox: str) -> dict:
    status, view = http("GET", f"/v1/sandboxes/{sandbox}/guard/telemetry")
    return view if status == 200 and isinstance(view, dict) else {}


def incident(sandbox: str) -> dict:
    status, view = http("GET", f"/v1/sandboxes/{sandbox}/guard/incident", timeout=120.0)
    return view if status == 200 and isinstance(view, dict) else {}


def await_event(sandbox: str, kind: str, seconds: float = 20.0) -> list[dict]:
    deadline = time.time() + seconds
    fired: list[dict] = []
    while time.time() < deadline:
        fired = canary_events(sandbox, kind)
        if fired:
            return fired
        time.sleep(0.5)
    return fired

def guest_json(sandbox: str, source: str, argument: str) -> dict:
    status, view = guest(sandbox, ["/usr/bin/python3", "-c", source, argument])
    raw = ((view or {}).get("stdout") or "").strip().splitlines()
    require(status == 200 and raw, f"guest stimulus failed: {status}")
    return json.loads(raw[-1])

def attachment_record(sandbox: str) -> dict:
    """The host's own record of the attachment: interface, addresses, ports."""
    path = WORKER_STATE / "guard" / sandbox / "attachment.json"
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as error:
        return {"error": type(error).__name__}

def host_view(sandbox: str) -> str:
    """Host-side interface and nftables state for this attachment."""
    attachment = attachment_record(sandbox).get("attachment")
    if not isinstance(attachment, dict):
        return "no attachment record"
    interface = str(attachment.get("interface", ""))
    table = str(telemetry(sandbox).get("counters", {}).get("table", ""))
    def run(argv: list[str]) -> str:
        completed = subprocess.run(argv, capture_output=True, text=True)
        return (completed.stdout + completed.stderr).strip()
    return "\n".join([
        run(["ip", "-4", "addr", "show", "dev", interface]),
        run(["nft", "-a", "list", "table", "inet", table]),
    ])

def host_listeners() -> str:
    """What the host is actually listening on, from the host's own view."""
    completed = subprocess.run(["ss", "-lntup"], capture_output=True, text=True)
    return (completed.stdout + completed.stderr).strip()




def sandbox_view(sandbox: str) -> dict:
    status, view = http("GET", f"/v1/sandboxes/{sandbox}")
    return view if status == 200 and isinstance(view, dict) else {}


# ---------------------------------------------------------------- guard policy

def guard_spec(require_signed: bool) -> dict:
    """The shipped model-only template plus the three synthetic canaries.

    The template is used rather than an explicit policy because Guard refuses a
    policy and template inputs together, and because the template is the
    operator-facing configuration a deployment would use. It is what gives the
    guest a broker address and a credential binding, so both the ordinary and
    the canary credential presentation travel the same real path; the canary
    names appear nowhere in the request either one makes.
    """
    return {
        "topology": "inside",
        "policy_template": "model-only",
        "model_endpoint": {
            "host": MODEL_HOST, "port": MODEL_PORT, "scheme": "https",
            "allowed_methods": ["POST"], "allowed_paths": ["/v1/"],
            "credential": MODEL_CREDENTIAL,
        },
        "canaries": {
            "files": [{"path": CANARY_FILE_PATH, "value": CANARY_VALUE}],
            "hostnames": [CANARY_HOSTNAME],
            "credentials": [CANARY_CREDENTIAL],
        },
        "require_signed_image": require_signed,
    }

def mint_watchdog_key() -> None:
    """A key that carries only the Guard scopes the watchdog needs.

    It is refused for everything else, which is the property worth stating: the
    watchdog process can keep a machine alive and can ask for a quarantine, and
    it cannot create a sandbox, read one, or touch anything outside Guard.
    """
    global WATCHDOG_TOKEN
    status, view = http("POST", "/v1/keys", {"name": "phase5-watchdog",
                                             "scopes": WATCHDOG_SCOPES})
    WATCHDOG_TOKEN = (view or {}).get("key")
    case("watchdog key is narrowly scoped", status == 200 and bool(WATCHDOG_TOKEN),
         {"status": status, "scopes": WATCHDOG_SCOPES})
    if not WATCHDOG_TOKEN:
        raise RuntimeError("the watchdog key could not be minted")
    path = ROOT / "watchdog.token"
    path.write_text(WATCHDOG_TOKEN)
    os.chmod(path, 0o600)
    # Poll well inside the gateway's own deadline so a slow request cannot be
    # the thing that latches the cut the cases below are about.
    (ROOT / "watchdog.json").write_text(json.dumps({
        "poll_interval_ms": 400, "request_timeout_ms": 1000,
        "heartbeat_ttl_ms": 5000, "observation_max_age_ms": 5000,
        "denied_threshold": 3, "suspicious_dns_threshold": 3,
    }))


def start_watchdog(sandbox: str, policy_hash: str) -> None:
    """Runs the shipped watchdog against one attachment and waits until the
    gateway says the heartbeat is being honoured.

    The wait is on telemetry rather than a sleep: the attachment is deny-all
    until the first heartbeat lands, so a case that started stimuli earlier
    would be measuring a guest that cannot reach anything.
    """
    require(WATCHDOG_TOKEN, "no watchdog token was minted")
    process = spawn(f"watchdog-{sandbox[:8]}", [
        str(BIN / "aiec-guard-watchdog"),
        "--control-plane", CP,
        "--sandbox-id", sandbox,
        "--tenant-id", TENANT,
        "--policy-hash", policy_hash,
        "--token-file", str(ROOT / "watchdog.token"),
        "--config", str(ROOT / "watchdog.json"),
        "--control-plane-ca-cert", str(CA),
    ], base_env())
    _watchdogs[sandbox] = process
    deadline = time.time() + 30
    observation: dict = {}
    while time.time() < deadline:
        if process.poll() is not None:
            reason = (ROOT / f"watchdog-{sandbox[:8]}.log").read_text()[-300:]
            raise RuntimeError(f"the watchdog exited: {reason}")
        status, view = http("GET", f"/v1/sandboxes/{sandbox}/guard/telemetry",
                            token=WATCHDOG_TOKEN)
        if status == 200 and isinstance(view, dict):
            observation = view
            activated = any("activated" in str(row.get("reason", ""))
                            for row in (view.get("events") or []))
            if view.get("network_cut") is False and activated:
                break
        time.sleep(0.5)
    activated = any("activated" in str(row.get("reason", ""))
                    for row in (observation.get("events") or []))
    case("attachment is live under a real watchdog process",
         observation.get("network_cut") is False and activated,
         {"sandbox": sandbox, "pid": process.pid,
          "network_cut": observation.get("network_cut"),
          "lifecycle_events": [str(row.get("reason", "")) for row in
                              (observation.get("events") or [])]})


def stop_watchdog(sandbox: str) -> None:
    process = _watchdogs.pop(sandbox, None)
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except Exception:
            process.kill()
            CLEANUP_ERRORS.append(f"watchdog for {sandbox} did not stop")


def guarded_sandbox(name: str, require_signed: bool = False) -> str:
    """A guarded sandbox with a watchdog actually heartbeating it.

    The Guard specification travels in `environment.guard`, which is where
    `POST /v1/sandboxes` reads it from. `resources` is the runs shape, and
    `CreateSandboxRequest` neither has that field nor rejects unknown ones, so
    a request that puts the policy there is accepted, boots a real guest, and
    silently runs it against the default empty policy.
    """
    status, view = http("POST", "/v1/sandboxes", {
        "image": os.environ.get("P5_IMAGE", "python:3.13"), "runtime": "firecracker",
        "cpu": 1, "memory_mb": 512, "disk_mb": 4096, "timeout_seconds": 900,
        "environment": {"guard": guard_spec(require_signed)},
    })
    created = (view or {}).get("sandbox", view or {})
    require(status in (200, 201) and created.get("id"),
            f"{name} was not created: {status} {(view or {}).get('error')}")
    require(created.get("state") in ("running", "ready", "creating"),
            f"{name} did not start: {created.get('state')}")
    sandbox = created["id"]
    SANDBOXES.add(sandbox)
    policy_hash = (created.get("environment") or {}).get("guard_policy_hash")
    require(policy_hash, f"{name} was created without a policy hash")
    start_watchdog(sandbox, policy_hash)
    return sandbox


def retire(sandbox: str) -> None:
    stop_watchdog(sandbox)
    http("DELETE", f"/v1/sandboxes/{sandbox}")


# ---------------------------------------------------------------- phases

def identity_and_image_phase() -> None:
    log("signed-image and per-VM identity acceptance")
    report_path = ROOT / "identity-image-report.json"
    scratch = ROOT / "identity-scratch"
    environment = {
        **base_env(),
        "AIEC_STATE_DIR": str(ROOT / "identity-state-vms"),
        "P5_IDENTITY_REPORT": str(report_path),
        "P5_IDENTITY_STATE": str(scratch),
    }
    completed = subprocess.run(
        [str(BIN / "examples" / "guard_phase5_acceptance")], env=environment,
        capture_output=True, text=True, timeout=2400,
    )
    if completed.returncode != 0:
        # The harness's own message is the diagnosis, and the report is not
        # written when it fails, so it reaches the console now. Its stdout is
        # kept with its stderr for the same reason: a failure reported only as
        # "broken pipe" names a symptom the harness raised while talking to
        # something else, and the line before it is what says what.
        log("  identity harness: " + (completed.stderr or "<no stderr>").strip()[-400:])
        case("signed image admission and per-VM identity acceptance", False,
             {"exit": completed.returncode,
              "stderr": (completed.stderr or "")[-600:],
              "stdout_tail": (completed.stdout or "")[-600:],
              "note": "previous artifact preserved; no secret is emitted by the harness"})
        return
    report = json.loads(report_path.read_text())
    for row in report.get("cases", []):
        case(row["name"], row.get("status") == "PASS",
             {**row.get("evidence", {}), "samples": row.get("samples", 1),
              "provenance": row.get("provenance")})
    if report.get("cleanup_errors"):
        CLEANUP_ERRORS.extend(report["cleanup_errors"])
    case("identity scratch directory removed", not scratch.exists(),
         {"absent": not scratch.exists()})


def positive_controls(sandbox: str) -> None:
    """The zero-hit assertions need a control: ordinary reads, resolutions and
    presentations that must produce nothing and must keep working.

    The model hostname resolves to the attachment's own gateway address without
    any upstream, so a successful resolution here proves the path is live and
    not merely silent. The ordinary file read and the ordinary placeholder
    presentation travel the same code paths as the triggers below.

    The ordinary read lives in a sibling directory, not beside the canary,
    because a directory listing that shows a canary's entry is itself a read of
    it. A control file in the canary's own directory would trip the tripwire it
    exists to prove does not trip.
    """
    mkdir_status, _ = http("POST", f"/v1/sandboxes/{sandbox}/files/mkdir",
                           {"path": "/workspace/plain"})
    require(mkdir_status in (200, 201, 204, 409),
            f"the control directory was not created: {mkdir_status}")
    written, _ = http("PUT", f"/v1/sandboxes/{sandbox}/files",
                      {"path": "/workspace/plain/ordinary.txt",
                       "content_base64": base64.b64encode(b"ordinary").decode()})
    status, content = http(
        "GET", f"/v1/sandboxes/{sandbox}/files/content?path=/workspace/plain/ordinary.txt")
    fired_file = canary_events(sandbox, "file")
    case("ordinary workspace read is served and trips nothing",
         written in (200, 201, 204) and status == 200 and not fired_file,
         {"write_status": written, "read_status": status,
          "content_matches": (content or {}).get("content_base64") == base64.b64encode(b"ordinary").decode(),
          "file_canary_events": len(fired_file)})
    ordinary = guest_json(sandbox, GUEST_DNS, MODEL_HOST)
    after_dns = canary_events(sandbox, "hostname")
    case("ordinary guest resolution works and trips no hostname canary",
         len(ordinary.get("resolved", [])) == 1 and not after_dns,
         {"resolved_count": len(ordinary.get("resolved", [])),
          "resolved": ordinary.get("resolved"),
          "guest_resolvers": ordinary.get("resolvers"),
          "guest_error": ordinary.get("error"),
          "attachment_resolver": ordinary.get("direct"),
          "queried": MODEL_HOST,
          "dns_canary_events": len(after_dns)})
    ordinary_credential = guest_json(sandbox, GUEST_PRESENT, f"placeholder://{MODEL_CREDENTIAL}")
    after_credential = canary_events(sandbox, "credential")
    # The control is a presentation of a credential the policy does not name,
    # and what it has to show is that the credential path ran and matched
    # nothing. The broker refusing an unbound placeholder with 403 is the
    # gateway answering: a status line came back over the attachment. What
    # would make this control useless is a request that never got that far, so
    # the assertion is that the broker answered, not that it said yes.
    case("ordinary placeholder presentation reaches the broker and trips no credential canary",
         not after_credential and isinstance(ordinary_credential.get("status"), int),
         {"presented": f"placeholder://{MODEL_CREDENTIAL}",
          "presented_status": ordinary_credential.get("status"),
          "guest_error": ordinary_credential.get("error"),
          "credential_canary_events": len(after_credential)})

def file_canary_phase() -> None:
    """The canary file is planted in the sandbox workspace by the runtime at
    boot; the read below is an ordinary host control-channel file read."""
    sandbox = guarded_sandbox("file-canary")
    try:
        positive_controls(sandbox)
        status, view = http(
            "GET", f"/v1/sandboxes/{sandbox}/files/content?path={CANARY_FILE_PATH}")
        fired = await_event(sandbox, "file")
        # The configured response for a file canary is a cut, not a refused
        # read: the tripwire exists to be read, and what has to be proved is
        # that the host saw the read and cut the attachment. So the read's own
        # status is recorded rather than asserted - a 200 proves nothing about
        # detection, and a canary the host refused to serve would prove nothing
        # either.
        case("configured file canary read is observed by the host and journals a high-severity cut",
             bool(fired)
             and all(canary_severity(row) == "high" and row.get("decision") == "cut"
                     for row in fired),
             {"read_status": status,
              "read_body_code": (view or {}).get("error", {}).get("code"),
              "events": canary_evidence(fired),
              "planted_in": "sandbox workspace at boot; the base image is never written"})
        observation = telemetry(sandbox)
        case("file canary read cuts the attachment in host observation",
             bool(observation.get("network_cut")),
             {"network_cut": observation.get("network_cut"),
              "counters": observation.get("counters")})
        # A cut is not a destroy, and the durable quarantine that follows one
        # pauses the machine instead of deleting it. So the machine is either
        # still answering or held paused with its disk on the host; a machine
        # that is neither reachable nor preserved is the failure.
        after = guest(sandbox, ["/bin/sh", "-c", "printf still-alive"])
        record = incident(sandbox)
        held_state = sandbox_view(sandbox).get("state")
        disk = WORKER_STATE / "vms" / sandbox / "rootfs.ext4"
        # The state is read from the control plane and the incident from the
        # durable record, not inferred from the exec's own answer: a guest that
        # refuses to run because it is held is not evidence that it survived,
        # and the guest is the one party with an interest in the answer.
        preserved = (record.get("paused_at") or record.get("snapshot_id")) and disk.exists()
        case("the cut preserves the machine rather than destroying it",
             after[0] == 200
             or (held_state in ("paused", "quarantined", "quarantining")
                 and preserved),
             {"exec_status": after[0],
              "exec_code": (after[1] or {}).get("error", {}).get("code"),
              "sandbox_state": held_state,
              "incident_network_cut_at": record.get("network_cut_at"),
              "incident_paused_at": record.get("paused_at"),
              "incident_snapshot_id": record.get("snapshot_id"),
              "rootfs_present": disk.exists(),
              "rootfs": str(disk)})
    finally:
        retire(sandbox)


def hostname_canary_phase() -> None:
    """The guest resolves the canary hostname for real; the attachment's
    resolver is what observes it."""
    sandbox = guarded_sandbox("hostname-canary")
    try:
        net = guest(sandbox, ["/bin/sh", "-c",
                              "ip -4 addr show; echo ---; ip route; echo ---; cat /etc/resolv.conf"])
        probe = guest_json(sandbox, GUEST_DNS, CANARY_HOSTNAME)
        live = host_view(sandbox)
        live_journal = journal(sandbox)
        model_probe = guest_json(sandbox, GUEST_DNS, "api.example-model.com")
        fired = await_event(sandbox, "hostname")
        case("guest resolution of a canary hostname raises a host-observed cut",
             bool(fired) and all(canary_severity(row) == "high"
                                  and row.get("decision") == "cut"
                                  and row.get("category") == "dns" for row in fired),
             {"probe": probe, "model_probe": model_probe,
              "attachment": attachment_record(sandbox),
              "guest_net": (net[1] or {}).get("stdout"),
              "host_view": live,
              "live_journal": [{k: row.get(k) for k in ("category", "decision", "reason",
                                                         "destination")}
                               for row in live_journal],
              "listeners": host_listeners(),
              "counters": telemetry(sandbox).get("counters"),
              "all_events": [{k: row.get(k) for k in ("category", "decision", "reason",
                                                      "destination")}
                             for row in journal(sandbox)],
              "events": canary_evidence(fired)})
        deadline = time.time() + 20
        observation: dict = {}
        while time.time() < deadline:
            observation = telemetry(sandbox)
            if observation.get("network_cut"):
                break
            time.sleep(0.5)
        # A canary also drives the durable quarantine, which pauses the guest.
        # A paused guest is preserved for forensics, so refusing the exec is a
        # stronger outcome than answering it, not a failed measurement; what
        # must hold either way is that the name does not resolve.
        status, view = guest(sandbox, ["/usr/bin/python3", "-c", GUEST_DNS, "localhost"])
        raw = ((view or {}).get("stdout") or "").strip().splitlines()
        resolved = (json.loads(raw[-1]).get("resolved") if status == 200 and raw else None)
        held = sandbox_view(sandbox).get("state") in ("paused", "quarantined", "quarantining")
        case("canary hostname cut removes guest name resolution",
             bool(observation.get("network_cut"))
             and (resolved == [] if status == 200 else held),
             {"network_cut": observation.get("network_cut"),
              "post_cut_exec_status": status,
              "post_cut_resolution": resolved,
              "post_cut_sandbox_state": sandbox_view(sandbox).get("state")})
    finally:
        retire(sandbox)


def credential_canary_phase() -> None:
    """The guest presents an arbitrary placeholder credential directly to the
    worker gateway, so nothing here depends on the policy naming it."""
    sandbox = guarded_sandbox("credential-canary")
    try:
        presented = guest_json(sandbox, GUEST_PRESENT, f"placeholder://{CANARY_CREDENTIAL}")
        fired = await_event(sandbox, "credential", seconds=30.0)
        case("presented canary credential is refused and journals critical quarantine",
             presented.get("status") == 403 and bool(fired)
             and all(canary_severity(row) == "critical"
                     and row.get("decision") == "quarantine"
                     and row.get("category") == "credential" for row in fired),
             {"guest_observed_status": presented.get("status"),
              "guest_error": presented.get("error"),
              "events": canary_evidence(fired)})
        deadline = time.time() + 120
        record: dict = {}
        while time.time() < deadline:
            record = incident(sandbox)
            if record.get("network_cut_at") and record.get("completed_at"):
                break
            time.sleep(1.0)
        view = sandbox_view(sandbox)
        # A latched budget is not a finished quarantine. The durable record has
        # to show the cut, the pause, the forensic capture and the report, and
        # any stage that did not finish carries its reason in the record itself.
        case("worker callback latches a complete durable quarantine",
             bool(record.get("id")) and view.get("state") == "quarantined"
             and bool(record.get("completed_at"))
             and bool(record.get("paused_at"))
             and bool(record.get("snapshot_id")),
             {"sandbox_state": view.get("state"),
              "incident_id_present": bool(record.get("id")),
              "network_cut_at": record.get("network_cut_at"),
              "paused_at": record.get("paused_at"),
              "snapshot_id": record.get("snapshot_id"),
              "completed_at": record.get("completed_at"),
              "stage_errors": record.get("errors"),
              "rules": [r.get("rule") for r in (record.get("rules") or [])]})
        status, refused = http("POST", f"/v1/sandboxes/{sandbox}/resume", {})
        case("a quarantined sandbox cannot be resumed",
             status == 409,
             {"status": status, "code": (refused or {}).get("error", {}).get("code")})
    finally:
        retire(sandbox)



def signed_image_boot_phase() -> None:
    """This run's signed manifest admits a guarded sandbox that requires signed
    admission. The launcher mints that manifest per run over this run's own
    rootfs unless an operator supplied one, so no case here depends on a
    deployment's manifest being present. Every refusal case lives in the
    identity harness, which drives the same gate with unsigned, untrusted,
    tampered and expired manifests against scratch copies of the images."""
    sandbox = guarded_sandbox("signed-image", require_signed=True)
    try:
        status, view = guest(sandbox, ["/bin/sh", "-c", "printf signed-boot-ok"])
        case("guarded sandbox with signed admission boots and runs",
             status == 200 and "signed-boot-ok" in ((view or {}).get("stdout") or ""),
             {"status": status,
              "manifest": os.environ.get("AIEC_IMAGE_MANIFEST", "").rsplit("/", 1)[-1]})
    finally:
        retire(sandbox)


def publish(report, payload):
    """Copies a passing report into benchmarks/ so the evidence outlives the run.

    The run root is scratch that the next run reuses, so a report left only
    there is evidence nobody can find afterwards and that no later commit can
    quote. Publication happens on a pass alone: a failed or partial run must
    never be able to replace the authoritative artifact, which is the same
    rule the partial-evidence path above follows. The payload is checked
    against the run's own credentials first, on the same principle as the
    Phase 3 retained evidence.
    """
    if report["status"] != "PASS":
        return None
    # Everything this run mints, on the same principle as Phase 3's retained
    # evidence: the guest secret, the image-signing key, every value in the
    # guard credentials file, the manifest's HMAC secret (which the shared
    # helper writes under the run root) and the database password. The last two
    # are the ones a case's evidence is most likely to quote, since both
    # describe something the run actually connected to or signed.
    secrets = [os.environ.get("AIEC_GUEST_SECRET", "").strip(),
               os.environ.get("AIEC_IMAGE_MANIFEST_SECRET", "").strip(),
               (ROOT / "image-manifest" / "secret").read_text().strip()
               if (ROOT / "image-manifest" / "secret").exists() else "",
               (ROOT / "image-signing.key").read_text().strip() if (ROOT / "image-signing.key").exists() else ""]
    credentials = ROOT / "guard-credentials.json"
    if credentials.exists():
        secrets.extend(str(value).strip() for value in json.loads(credentials.read_text()).values())
    _password = urllib.parse.unquote(DATABASE_URL.split("://", 1)[1].split("@", 1)[0].partition(":")[2])
    if _password:
        secrets.append(_password)
    if any(secret and secret in payload for secret in secrets):
        return "withheld: the report contains a credential from this run"
    destination = Path(os.environ.get(
        "P5_REPORT", Path(__file__).resolve().parent.parent / "benchmarks" / "guard-phase5-acceptance.json"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_name(destination.name + ".tmp")
    staging.write_text(payload)
    os.chmod(staging, 0o600)
    os.replace(staging, destination)
    return str(destination)


def main() -> int:
    started_at = time.time()
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    state = ROOT / "state"
    state.mkdir(exist_ok=True)

    identity_and_image_phase()

    def abandoned(reason: str) -> int:
        """An aborted run leaves its evidence somewhere other than the report.

        The report is written only once every phase has run, so an early return
        - a control plane that never became healthy, for instance - discards
        the cases it had already decided. That evidence goes to its own file
        rather than into `phase5-report.json`, which stays the last valid
        artifact.
        """
        stop_all()
        partial = {
            "status": "ABORTED",
            "reason": reason,
            "passed": sum(1 for row in CASES if row["status"] == "PASS"),
            "cases": CASES,
            "cleanup_errors": CLEANUP_ERRORS,
        }
        path = ROOT / "phase5-aborted.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(partial, indent=2))
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        log(f"aborted: {reason}; partial evidence in {path.name}")
        return 1


    env = base_env()
    server = spawn("control-plane", [str(BIN / "aiec-server")],
                   {**env, "AIEC_BIND": os.environ["P5_CP_BIND"]})
    healthy, reason = wait_for_health(server, CP + "/health")
    if not healthy:
        case("control plane became healthy", False,
             {"exit": server.poll(), "reason": reason})
        return abandoned("the control plane never became healthy")
    worker = spawn("worker", [
        str(BIN / "aiec"), "--url", CP, "worker", "--runtime", "firecracker",
        "--state-dir", str(state), "--advertise-url", WORKER,
        "--bind", os.environ["P5_WORKER_BIND"], "--name", "phase5",
        "--capacity", "4", "--memory-reserve-mib", "256", "--disk-reserve-mib", "512",
    ], env)
    healthy, reason = wait_for_health(worker, WORKER + "/health", WORKER_TOKEN)
    if not healthy:
        case("worker registered and stayed healthy", False,
             {"exit": worker.poll(), "reason": reason})
        return abandoned("the worker never registered or stopped being healthy")
    case("control plane and worker are serving", True,
         {"cp": os.environ["P5_CP_BIND"], "worker": os.environ["P5_WORKER_BIND"]})

    try:
        mint_watchdog_key()
    except Exception as error:
        case("watchdog key was minted", False, {"error": str(error)[:200]})
        return abandoned("the watchdog key could not be minted")
    # A key that can heartbeat an attachment must not be able to read the
    # tenant's data, and the check belongs here rather than in the report.
    status, _ = http("GET", "/v1/sandboxes", token=WATCHDOG_TOKEN)
    case("the watchdog key cannot read the tenant's sandboxes", status == 403,
         {"status": status})

    phases = {
        "identity": signed_image_boot_phase,
        "file": file_canary_phase,
        "hostname": hostname_canary_phase,
        "credential": credential_canary_phase,
    }
    # `P5_PHASES` runs a subset, comma separated, in the order given. It exists
    # so one tripwire can be reproduced without paying for the whole suite; a
    # subset run is diagnostic and its report says so, because a suite that did
    # not run every phase cannot speak for the ones it skipped.
    selected = [name.strip() for name in
                os.environ.get("P5_PHASES", "").split(",") if name.strip()]
    subset = bool(selected)
    try:
        for name in (selected or list(phases)):
            phases[name]()
    except Exception as error:
        case("phase 5 canary phases ran", False, {"error": type(error).__name__})
        log(f"phase 5 driver error: {type(error).__name__}: {error}")

    stop_all()
    # The worker is stopped, so nothing can reach a VM directory left in its
    # state tree: no other process adopts one, and resume only ever finds a
    # machine in the process that is running. A quarantined sandbox is held
    # while its worker lives - the evidence an operator investigates is the
    # forensic copy under guard-forensics - but its writable disk does not
    # survive the worker, and a disk with no quarantine behind it never does.
    live_disks = list((ROOT / "state-vms").glob("vms/**/rootfs.ext4"))
    forensic = {path.parts[-3]: path for path in
                (ROOT / "state-vms").glob("guard-forensics/*/*/rootfs.ext4")}
    # A quarantined forensic capture is meant to outlive the run, so this
    # directory accumulates them across runs. Counting all of them as this
    # run's would report a number that grows by exactly the number of
    # quarantines every time the suite is re-run, which is evidence about the
    # past rather than about what this worker left behind.
    #
    # The invariant being checked - a surviving disk must have a quarantine
    # behind it - is a claim about this worker, so it is checked against the
    # captures whose ids this run was given. An earlier run's capture is
    # counted separately rather than judged here: this worker did not write it,
    # and failing the suite over it would make the run answer for state it does
    # not control.
    this_run = {sandbox: path for sandbox, path in forensic.items()
                if sandbox in SANDBOXES}
    unexplained = [sandbox for sandbox in this_run
                   if not any(row.get("category") == "quarantine"
                              for row in journal(sandbox))]
    case("worker left no VM disk behind",
         not live_disks and not unexplained,
         {"live_rootfs_copies": len(live_disks),
          "quarantined_forensics_retained": len(this_run) - len(unexplained),
          "quarantined_forensics_from_earlier_runs": len(forensic) - len(this_run),
          "forensics_without_a_quarantine": unexplained})

    # The disk census is not the process census. A guest whose directory has
    # been removed is still running, and the first run of this suite left four
    # Firecracker processes reparented to systemd --user on the host, hours
    # after the workers that started them had gone. So the processes are
    # counted, after the worker has stopped, and matched to this run's sandbox
    # ids: Firecracker is exec'd with only its `--api-sock` path to name the
    # machine, and that path carries the sandbox id. They are the ids this run
    # was given, not the ones a directory still happens to hold: a machine whose
    # directory has been reclaimed takes its id out of that glob with it, and a
    # census over an empty set reports zero survivors because it looked for
    # nothing. An empty id set fails the case rather than passing it vacuously.
    run_sandboxes = SANDBOXES | {path.name for path in (ROOT / "state-vms").glob("guard/*")}
    run_sandboxes |= {path.name for path in
                      (ROOT / "state-vms").glob("guard-forensics/*/*")}
    live = live_guest_processes(run_sandboxes)
    case("worker left no guest process behind", bool(run_sandboxes) and not live,
         {"live_guest_processes": len(live),
          "sandboxes_created": len(SANDBOXES),
          "sandboxes_censused": len(run_sandboxes),
          "pids": sorted(live.values())})

    report = {
        "status": "PASS" if not FAILURES and not CLEANUP_ERRORS else "FAIL",
        # A PASS says the phases this run executed passed. Only a full run can
        # stand as acceptance for the suite, so the scope is stated in the
        # report and in the line printed at the end rather than left to be
        # inferred from which phases happen to be listed.
        "acceptance_scope": "diagnostic_subset" if subset else "full_suite",
        "started_at": started_at,
        "elapsed_seconds": round(time.time() - started_at, 1),
        "passed": sum(1 for row in CASES if row["status"] == "PASS"),
        "phases_run": selected or list(phases),
        "diagnostic_subset_run": subset,
        "cases": CASES,
        "failing": FAILURES,
        "cleanup_errors": CLEANUP_ERRORS,
        "observation_provenance": {
            "canaries": "host-observed by the shipped Guard monitor: guest dns queries over the "
                        "attachment resolver, credential presentation on the worker gateway, and "
                        "control-channel file reads on the worker",
            "durable_quarantine": "control-plane state latched by the worker-authenticated "
                                  "quarantine endpoint, not a worker-local claim",
            "image_and_identity": "real local Firecracker guests, host filesystem digests and "
                                  "authenticated vsock control channel, driven by "
                                  "guard_phase5_acceptance",
            "out_of_scope": "arbitrary in-guest process file reads are not observable from "
                            "outside the guest without trusted in-guest instrumentation and are "
                            "not claimed here",
        },
    }
    path = ROOT / "phase5-report.json"
    payload = json.dumps(report, indent=2)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(payload)
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    print(json.dumps({key: report[key] for key in
                      ("status", "acceptance_scope", "passed", "failing", "cleanup_errors")}
                     | {"published": publish(report, payload)}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())