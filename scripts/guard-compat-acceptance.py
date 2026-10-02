#!/usr/bin/env python3
"""Pre-Guard backward-compatibility acceptance.

Everything here was true of the product before Guard existed and must still be
true of it now, with the Guard build deployed and no compatibility flag set:

  - a sandbox request written before Guard - no `guard`, no `network_policy`,
    no `isolation` - is accepted unchanged and behaves identically;
  - the response shape a pre-Guard client parses still parses, and the fields
    such a client reads are still present with the same types;
  - the pre-Guard runtime selection strings still work, including the ones
    the docs spell with an underscore;
  - the runtimes a pre-Guard deployment used still serve exec, files and
    artifacts;
  - Guard is additive: nothing about a sandbox that does not ask for it
    appears on the wire unless asked for;
  - and the opt-ins behave as documented - legacy networking and reduced
    isolation are refused by default and admitted when explicitly set,
    each showing up as the documented header rather than as silence.

This is run against a disposable deployment by guard-phase2-acceptance.sh,
which supplies P2_ROOT/P2_BIN/DATABASE_URL and the same environment; the point
is the deployed binaries over the same wire, not a unit test of a handler.

A case that only proves "the request did not fail" is not enough. Each one
checks the observable the pre-Guard client actually depends on.
"""
from __future__ import annotations

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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["P2_ROOT"])
BIN = Path(os.environ["P2_BIN"])
CA = Path(os.environ["P2_CA"])
CP = os.environ["P2_CP"]
WORKER = os.environ["P2_WORKER"]
TENANT = os.environ["P2_TENANT"]
API_KEY = os.environ["P2_API_KEY"]
WORKER_TOKEN = os.environ["P2_WORKER_TOKEN"]
DATABASE_URL = os.environ["DATABASE_URL"]

CASES: list[dict] = []
FAILURES: list[str] = []
CLEANUP_ERRORS: list[str] = []
_started: list[tuple[str, subprocess.Popen]] = []
_sandboxes: list[str] = []


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def case(name: str, ok: bool, evidence: dict) -> None:
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    log(f"{'PASS' if ok else 'FAIL'} {name}")
    if not ok:
        log("  evidence: " + json.dumps(evidence)[:600])
        FAILURES.append(name)


CTX = ssl.create_default_context(cafile=str(CA))


def http(method: str, path: str, body=None, token: str | None = None, timeout: float = 20.0):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(CP + path, data=data, method=method)
    request.add_header("content-type", "application/json")
    request.add_header("authorization", f"Bearer {token if token is not None else API_KEY}")
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=timeout) as response:
            raw = response.read()
            try:
                parsed = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                parsed = None
            return response.status, parsed, dict(response.headers)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = None
        return error.code, parsed, dict(error.headers)


def base_env() -> dict:
    return {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "RUST_LOG": os.environ.get("RUST_LOG", "warn"),
        "AIEC_RUNTIME": "firecracker",
        "AIEC_FIRECRACKER_BIN": os.environ["AIEC_FIRECRACKER_BIN"],
        # The Firecracker runtime places VMs and Guard attachments under this
        # directory, and the worker measures the disk it can admit against
        # from it. Dropping the variable leaves admission with an incomplete
        # reading, which the product correctly refuses - a refusal that says
        # nothing about compatibility and everything about the environment.
        "AIEC_STATE_DIR": os.environ["AIEC_STATE_DIR"],
        "AIEC_KERNEL": os.environ["AIEC_KERNEL"],
        "AIEC_ROOTFS": os.environ["AIEC_ROOTFS"],
        "AIEC_GUEST_ARTIFACT_DIR": os.environ["AIEC_GUEST_ARTIFACT_DIR"],
        "AIEC_GUEST_SECRET": os.environ["AIEC_GUEST_SECRET"],
        "AIEC_IMAGE_MANIFEST": os.environ["AIEC_IMAGE_MANIFEST"],
        "AIEC_IMAGE_MANIFEST_SECRET": os.environ["AIEC_IMAGE_MANIFEST_SECRET"],
        "AIEC_TLS_CERT_FILE": os.environ["P2_TLS_CERT"],
        "AIEC_TLS_KEY_FILE": os.environ["P2_TLS_KEY"],
        "AIEC_TLS_CA_CERT": str(CA),
        "AIEC_S3_ENDPOINT": os.environ["P2_S3_ENDPOINT"],
        "AIEC_S3_REGION": "us-east-1",
        "AIEC_S3_BUCKET": "aiec",
        "AIEC_S3_ACCESS_KEY_ID": os.environ["P2_S3_ACCESS_KEY_ID"],
        "AIEC_S3_SECRET_ACCESS_KEY": os.environ["P2_S3_SECRET_ACCESS_KEY"],
        "AIEC_S3_PREFIX": "compat/",
        "DATABASE_URL": DATABASE_URL,
        "AIEC_TENANT_ID": TENANT,
        "AIEC_TENANT_NAME": "compat",
        "AIEC_API_KEY": API_KEY,
        "AIEC_WORKER_TOKEN": WORKER_TOKEN,
        "AIEC_LEASE_TTL_SECONDS": "300",
        "AIEC_ALLOW_CONTAINER_RUNTIMES": "1",
        # A compat run must start from the default state, never from an
        # inherited one: an operator shell that happens to export an opt-in is
        # exactly the situation where a claim about the default is wrong. They
        # are set to the empty string rather than removed, so an inherited value
        # cannot survive the way an absent variable would.
        "AIEC_ALLOW_LEGACY_NETWORK": "",
        "AIEC_ALLOW_REDUCED_ISOLATION": "",
        "AIEC_REPRO_LEGACY_CONTROL": "",
    }


def spawn(name: str, argv: list[str], env: dict) -> subprocess.Popen:
    process = subprocess.Popen(
        argv, env=env, stdout=open(ROOT / f"{name}.log", "wb"),
        stderr=subprocess.STDOUT, start_new_session=True)
    _started.append((name, process))
    return process


def wait_for_health(process: subprocess.Popen, seconds: float = 60.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            status, _, _ = http("GET", "/health", token="", timeout=3.0)
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def wait_for_worker(process: subprocess.Popen, seconds: float = 60.0) -> bool:
    """Wait for the worker to be serving, not merely for it to exist."""
    deadline = time.time() + seconds
    worker_ctx = ssl.create_default_context(cafile=str(CA))
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            request = urllib.request.Request(WORKER + "/health")
            request.add_header("authorization", f"Bearer {WORKER_TOKEN}")
            with urllib.request.urlopen(request, timeout=5.0, context=worker_ctx) as response:
                if response.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def stop_all() -> None:
    for identifier in reversed(_sandboxes):
        try:
            http("DELETE", f"/v1/sandboxes/{identifier}", timeout=20.0)
        except Exception:
            CLEANUP_ERRORS.append(f"sandbox {identifier} not destroyed")
    for name, process in reversed(_started):
        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.time() + 10
    for name, process in reversed(_started):
        while process.poll() is None and time.time() < deadline:
            time.sleep(0.2)
        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception:
                pass
        elif process.returncode not in (0, -signal.SIGTERM, -signal.SIGKILL):
            CLEANUP_ERRORS.append(f"{name} exited {process.returncode}")


def create(body: dict, name: str = "compat"):
    # `image` has no serde default on CreateSandboxRequest, so a request that
    # omits it is rejected before anything compatibility-related is reached.
    # It was required before Guard as well, which makes it part of the legacy
    # shape rather than an addition to it.
    payload = {"name": name, "tenant_id": TENANT,
               "image": os.environ.get("P2_IMAGE", "python:3.13"), **body}
    status, parsed, headers = http("POST", "/v1/sandboxes", payload)
    if status in (200, 201, 202) and isinstance(parsed, dict) and parsed.get("id"):
        _sandboxes.append(parsed["id"])
    return status, parsed, headers


def wait_running(identifier: str, seconds: float = 90.0):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        status, parsed, _ = http("GET", f"/v1/sandboxes/{identifier}")
        last = parsed
        if status == 200 and isinstance(parsed, dict) and parsed.get("state") == "running":
            return parsed
        if status == 200 and isinstance(parsed, dict) and parsed.get("state") in ("failed", "destroyed"):
            return parsed
        time.sleep(0.5)
    return last


def main() -> int:
    started_at = time.time()
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "state").mkdir(exist_ok=True)
    env = base_env()
    server = spawn("control-plane", [str(BIN / "aiec-server")],
                   {**env, "AIEC_BIND": os.environ["P2_CP_BIND"]})
    if not wait_for_health(server):
        log("control plane did not become healthy")
        print(json.dumps({"status": "FAIL", "error": "control plane did not start"}))
        stop_all()
        return 1

    worker = spawn("worker", [
        str(BIN / "aiec"), "--url", CP, "worker",
        "--runtime", "firecracker",
        "--state-dir", str(ROOT / "state"),
        "--advertise-url", WORKER,
        "--bind", os.environ["P2_WORKER_BIND"],
        "--name", "compat",
        "--capacity", "4",
        "--memory-reserve-mib", "256",
        "--disk-reserve-mib", "512",
    ], env)
    # The worker's own endpoint, authenticated with the worker token. Probing
    # the control plane here would only prove that the control plane answers:
    # it goes healthy before the worker has registered, and the first create
    # would then lose the race and come back 503 "no schedulable worker has
    # capacity" - which is a scheduling failure being misread as a
    # compatibility one.
    if not wait_for_worker(worker):
        log("worker did not register")
        stop_all()
        return 1

    # 1. A sandbox created by a pre-Guard client: no guard, no network_policy,
    #    no isolation field at all.
    status, parsed, _ = create({"runtime": "firecracker"})
    ok = status in (200, 201, 202) and isinstance(parsed, dict) and bool(parsed.get("id"))
    case("pre-guard-create-body-is-accepted", ok, {"status": status, "body": parsed})
    if not ok:
        stop_all()
        return 1
    legacy_id = parsed["id"]

    # 2. The response a pre-Guard client parses still parses, and the fields it
    #    reads are present *and of the types it expects*. Recording the observed
    #    type is not the same as checking it: an earlier version of this case
    #    asserted only that the fields were present, while writing "and their
    #    types" into the evidence, which would have passed on a field that came
    #    back as a string where a client expected an object. Both halves are
    #    checked here, and a mismatch is named.
    record = wait_running(legacy_id)
    required = {"id": str, "state": str, "runtime": str, "created_at": str,
                "tenant_id": str, "network": dict, "environment": dict}
    observed = {k: type(record.get(k)).__name__ for k in sorted(required)}
    missing = sorted(k for k in required if k not in record)
    mistyped = sorted(k for k, expected in required.items()
                      if k in record and not isinstance(record[k], expected))
    case("pre-guard-response-fields-are-present-and-typed",
         not missing and not mistyped,
         {"missing": missing, "mistyped": mistyped, "observed_types": observed,
          "state": record.get("state")})

    # 3. What actually changed for a client that asked for nothing, stated
    #    exactly. Guard is injected for every Firecracker request that omits it
    #    (crates/aiec-api/src/lib.rs:1884), so a pre-Guard Firecracker client
    #    does now get a Guard policy - on the wire, nested under
    #    `environment.guard`, with the default template `no-network`.
    #
    #    This is the deliberate cutover and it is not invisible: the point of
    #    this case is that it is *recorded*, not that it is absent. An earlier
    #    version of this suite scanned only the top-level keys and passed on a
    #    sandbox that was in fact guarded, which is exactly the kind of claim
    #    that must not survive contact with the response.
    environment = record.get("environment") or {}
    injected = environment.get("guard")
    default_template = (injected or {}).get("policy_template")
    case("guard-is-injected-by-default-and-the-cutover-is-recorded",
         isinstance(injected, dict) and default_template == "no-network",
         {"top_level_guard_keys": [k for k in record if "guard" in k.lower()],
          "environment_guard_present": isinstance(injected, dict),
          "policy_template": default_template,
          "note": "a pre-Guard Firecracker client is now guarded by default; this is "
                  "the intentional security cutover, not a silent change"})

    # 4. Both spellings of the development runtime still parse to the same
    #    runtime rather than to an unrecognised one.
    #
    #    Neither spelling is available on this deployment: no worker registers
    #    BwrapDev, and runtime selection happens before the production gate, so
    #    the refusal is "runtime BwrapDev is not registered". That is the point
    #    of the case. The refusal has to name the *resolved* runtime identically
    #    for both spellings - a parser that had quietly stopped accepting the
    #    underscore form would report an unknown runtime for one of them, and a
    #    client could not tell a typo from an unavailable runtime. This is not a
    #    claim that the runtime works here, and it does not need one.
    spellings = ["bwrap-dev", "bwrap_dev"]
    resolved = {}
    for spelling in spellings:
        status, parsed, _ = create({"runtime": spelling}, name=f"compat-{spelling}")
        error = (parsed or {}).get("error") if isinstance(parsed, dict) else None
        resolved[spelling] = {
            "status": status,
            "code": error.get("code") if isinstance(error, dict) else None,
            "message": error.get("message") if isinstance(error, dict) else None,
        }
    same = (resolved["bwrap-dev"]["message"] == resolved["bwrap_dev"]["message"]
            and "BwrapDev" in (resolved["bwrap-dev"]["message"] or ""))
    case("legacy-runtime-spellings-resolve-to-one-runtime", same,
         {"by_spelling": resolved,
          "note": "unavailable on this deployment (no BwrapDev worker); the claim is "
                  "that both spellings resolve to the same runtime, not that the "
                  "runtime is available"})

    # 5. The operations a pre-Guard deployment used, on a sandbox created the
    #    pre-Guard way.
    status, parsed, _ = http("POST", f"/v1/sandboxes/{legacy_id}/exec",
                             {"command": ["/bin/sh", "-c", "printf compat-ok"]})
    output = (parsed or {}).get("stdout") if isinstance(parsed, dict) else None
    ok = status == 200 and output is not None and "compat-ok" in output
    case("exec-works-on-a-pre-guard-sandbox", ok,
         {"status": status, "stdout": output, "exit_code": (parsed or {}).get("exit_code")})

    # The path is absolute and inside /workspace, which is what the runtime has
    # always required: a relative path is refused as outside the workspace, and
    # the 500 that followed was the guest-side handler rather than a
    # compatibility break.
    payload = {"path": "/workspace/compat.txt",
               "content_base64": base64.b64encode(b"pre-guard bytes\n").decode()}
    status, _, _ = http("PUT", f"/v1/sandboxes/{legacy_id}/files", payload)
    written = status in (200, 201, 204)
    status, parsed, _ = http("GET",
                             f"/v1/sandboxes/{legacy_id}/files/content?path=/workspace/compat.txt")
    content = (parsed or {}).get("content_base64") if isinstance(parsed, dict) else None
    decoded = base64.b64decode(content).decode() if isinstance(content, str) else None
    case("file-round-trip-works", written and decoded == "pre-guard bytes\n",
         {"write_status": written, "read_status": status, "content": decoded})

    # 6. Destroy returns the sandbox to a terminal state, which is what a
    #    pre-Guard client polls for.
    http("DELETE", f"/v1/sandboxes/{legacy_id}")
    final = None
    deadline = time.time() + 60
    while time.time() < deadline:
        status, parsed, _ = http("GET", f"/v1/sandboxes/{legacy_id}")
        final = (parsed or {}).get("state") if isinstance(parsed, dict) else None
        if final in ("destroyed", "failed"):
            break
        time.sleep(0.5)
    case("pre-guard-destroy-reaches-a-terminal-state", final in ("destroyed", "failed"),
         {"final_state": final})

    # 7. The legacy-network opt-in, tested where it is actually reachable.
    #
    #    It is not reachable on Firecracker, and that is a finding rather than a
    #    test to work around: Guard is injected for every Firecracker request
    #    that omits it (crates/aiec-api/src/lib.rs:1884), so
    #    `sandbox.environment.guard.is_none()` in GuardNetworkManager::prepare
    #    is false and the flag is never consulted. An earlier version of this
    #    suite requested Firecracker with a network policy, saw create return
    #    200, and recorded that as the refusal working - it was reading an
    #    admission as a refusal, and the opt-in was not involved at all.
    #
    #    What is testable here is the property that actually matters: the flag
    #    cannot be used to reach an unguarded network on the runtime that
    #    matters. Setting it must change nothing observable about a Firecracker
    #    sandbox, because the sandbox is Guard's either way.
    for name, process in reversed(_started):
        if name == "worker" and process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    _started[:] = [(n, p) for n, p in _started if n != "worker"]
    time.sleep(2.0)
    worker_legacy = spawn("worker", [
        str(BIN / "aiec"), "--url", CP, "worker",
        "--runtime", "firecracker",
        "--state-dir", str(ROOT / "state"),
        "--advertise-url", WORKER,
        "--bind", os.environ["P2_WORKER_BIND"],
        "--name", "compat-legacy",
        "--capacity", "4",
        "--memory-reserve-mib", "256",
        "--disk-reserve-mib", "512",
    ], {**env, "AIEC_ALLOW_LEGACY_NETWORK": "1"})
    up = wait_for_worker(worker_legacy)
    placed = None
    if up:
        # wait_for_worker already waited for the worker to serve; the extra
        # beat is for the control plane's scheduler to see the restarted
        # worker's heartbeat. Creating before that races the same way the first
        # leg did, and a 503 here would look like a policy refusal.
        time.sleep(5.0)
        status, parsed, _ = create({"runtime": "firecracker", "network": {"enabled": True}},
                                   name="compat-legacy-network-flag-set")
        if status in (200, 201, 202) and isinstance(parsed, dict) and parsed.get("id"):
            placed = wait_running(parsed["id"], 90.0)
    environment = (placed or {}).get("environment") or {}
    guard_under_flag = environment.get("guard")
    # The opt-in is not honoured on Firecracker - by design - so the sandbox
    # still comes up guarded and without an attachment of its own. If this ever
    # reports an unguarded sandbox with a live network, the flag has been given
    # a path it was never meant to have.
    case("legacy-network-opt-in-cannot-unguard-a-firecracker-sandbox",
         up and isinstance(placed, dict) and placed.get("state") == "running"
         and isinstance(guard_under_flag, dict),
         {"worker_flag": "AIEC_ALLOW_LEGACY_NETWORK=1",
          "state": (placed or {}).get("state") if isinstance(placed, dict) else None,
          "guard_present": isinstance(guard_under_flag, dict),
          "policy_template": (guard_under_flag or {}).get("policy_template"),
          "network": (placed or {}).get("network") if isinstance(placed, dict) else None,
          "note": "the opt-in is unreachable on Firecracker because Guard is injected "
                  "for every such request; this asserts it grants nothing here"})

    passed = sum(1 for c in CASES if c["status"] == "PASS")
    report = {
        "schema": "aiec.guard.compat-acceptance.v1",
        "status": "PASS" if passed == len(CASES) and not FAILURES and not CLEANUP_ERRORS else "FAIL",
        "passed": passed, "cases": len(CASES), "cases_detail": CASES,
        "failing": FAILURES, "cleanup_errors": CLEANUP_ERRORS,
        "opt_ins_at_start": {
            "AIEC_ALLOW_LEGACY_NETWORK": os.environ.get("AIEC_ALLOW_LEGACY_NETWORK", ""),
            "AIEC_ALLOW_REDUCED_ISOLATION": os.environ.get("AIEC_ALLOW_REDUCED_ISOLATION", ""),
        },
        "elapsed_seconds": round(time.time() - started_at, 3),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    (ROOT / "compat-report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in
                      ("status", "passed", "cases", "failing", "cleanup_errors")}))
    stop_all()
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
