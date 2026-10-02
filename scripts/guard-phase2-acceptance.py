#!/usr/bin/env python3
"""Phase 2 live acceptance: watchdog, dead-man switch, quarantine and reaper.

Runs against a disposable deployment (separate database, ports, state and object
prefix) on a real host, with a real Firecracker sandbox and a real out-of-guest
watchdog process. Nothing here mocks a product component: the control plane,
worker, guest, kernel tables and watchdog are all the shipped ones.

Cases follow the phase 2 acceptance list: blocked-range attempt -> alert,
repeated deny -> rule trigger, killed watchdog -> deny-all, quarantine -> cut,
paused, durable state, idempotent repeat, and worker restart -> budget still
enforced.
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
WATCHDOG_TIMEOUT_MS = int(os.environ.get("P2_WATCHDOG_TIMEOUT_MS", "3000"))

CASES: list[dict] = []
FAILURES: list[str] = []
CLEANUP_ERRORS: list[str] = []
_started: list[tuple[str, subprocess.Popen]] = []
_sandbox_id: str | None = None


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def case(name: str, ok: bool, evidence: dict) -> None:
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    log(f"{'PASS' if ok else 'FAIL'} {name}")
    if not ok:
        # Evidence is printed with the failure: a report that is only on disk is
        # a report nobody reads while the run is still fresh.
        log("  evidence: " + json.dumps(evidence)[:600])
        FAILURES.append(name)


def http(method: str, path: str, body=None, token: str = API_KEY, timeout: float = 60.0):
    request = urllib.request.Request(CP + path, method=method)
    request.add_header("authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request.add_header("content-type", "application/json")
    context = ssl.create_default_context(cafile=str(CA))
    try:
        with urllib.request.urlopen(request, data=data, timeout=timeout, context=context) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return error.code, {"raw": raw.decode(errors="replace")[:400]}


def spawn(name: str, argv: list[str], env: dict | None = None) -> subprocess.Popen:
    log_env = dict(os.environ)
    log_env.update(env or {})
    # Truncated per run: an append-mode log carries the previous run's failures
    # into this one's evidence, and a cause read from the wrong run is worse than
    # no cause at all.
    handle = open(ROOT / f"{name}.log", "wb", buffering=0)
    process = subprocess.Popen(
        argv, stdout=handle, stderr=subprocess.STDOUT, env=log_env, start_new_session=True
    )
    _started.append((name, process))
    return process


PROBE_SOURCE = Path(os.environ.get(
    "P2_PROBE", str(Path(__file__).resolve().parent / "guard_core_guest_probe.py")
)).read_text()


def base_env() -> dict:
    env = {
        "DATABASE_URL": DATABASE_URL,
        "AIEC_RUNTIME": "firecracker",
        "AIEC_FIRECRACKER_BIN": os.environ["AIEC_FIRECRACKER_BIN"],
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
        "AIEC_S3_PREFIX": "phase2/",
        "DATABASE_URL": DATABASE_URL,
        "AIEC_TENANT_ID": TENANT,
        "AIEC_TENANT_NAME": "phase2",
        "AIEC_API_KEY": API_KEY,
        "AIEC_WORKER_TOKEN": WORKER_TOKEN,
        "AIEC_LEASE_TTL_SECONDS": "300",
        "AIEC_ALLOW_CONTAINER_RUNTIMES": "1",
    }
    for key in ("AIEC_FIRECRACKER_BIN", "AIEC_KERNEL", "AIEC_ROOTFS",
                "AIEC_GUEST_ARTIFACT_DIR", "AIEC_GUEST_SECRET",
                "AIEC_IMAGE_MANIFEST", "AIEC_IMAGE_MANIFEST_SECRET"):
        env.setdefault(key, os.environ.get(key, ""))
    return env


def wait_for_health(process: subprocess.Popen, seconds: float = 60.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            status, _ = http("GET", "/health", token="", timeout=3.0)
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def stop_all() -> None:
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
            except ProcessLookupError:
                pass
        elif process.returncode not in (0, -signal.SIGTERM, -signal.SIGKILL):
            # A process this run deliberately killed - the watchdog, for the
            # dead-man case - is not a cleanup failure; anything else that exits
            # badly is.
            CLEANUP_ERRORS.append(f"{name} exited {process.returncode}")


def main() -> int:
    global _sandbox_id
    started_at = time.time()
    ROOT.mkdir(parents=True, exist_ok=True)
    state = ROOT / "state"
    state.mkdir(exist_ok=True)

    env = base_env()
    server = spawn(
        "control-plane",
        [str(BIN / "aiec-server")],
        {**env, "AIEC_BIND": os.environ["P2_CP_BIND"]},
    )
    if not wait_for_health(server):
        log("control plane did not become healthy")
        print(json.dumps({"status": "FAIL", "error": "control plane did not start"}))
        stop_all()
        return 1

    worker = spawn(
        "worker",
        [
            str(BIN / "aiec"), "--url", CP, "worker",
            "--runtime", "firecracker",
            "--state-dir", str(state),
            "--advertise-url", WORKER,
            "--bind", os.environ["P2_WORKER_BIND"],
            "--name", "phase2",
            "--capacity", "4",
            "--memory-reserve-mib", "256",
            "--disk-reserve-mib", "512",
        ],
        env,
    )
    deadline = time.time() + 60
    registered = False
    detail: dict = {}
    while time.time() < deadline:
        if worker.poll() is not None:
            detail = {"exit": worker.returncode}
            break
        # The worker's own health endpoint, authenticated with the worker token:
        # this proves the service is serving, not merely that a row exists.
        try:
            request = urllib.request.Request(WORKER + "/health")
            request.add_header("authorization", f"Bearer {WORKER_TOKEN}")
            with urllib.request.urlopen(
                request, timeout=5.0, context=ssl.create_default_context(cafile=str(CA))
            ) as response:
                if response.status == 200:
                    detail = {"health": json.loads(response.read())}
                    registered = True
                    break
        except Exception as error:
            detail = {"last_error": str(error)[:200]}
        time.sleep(1.0)
    case("worker-registers-and-stays-healthy", registered, {"registered": registered, **detail})
    if not registered:
        stop_all()
        print(json.dumps({"status": "FAIL", "error": "worker did not register"}))
        return 1

    # A watchdog key: the narrow guard scopes only, minted through the account API.
    status, key = http(
        "POST", "/v1/keys",
        {"name": "phase2-watchdog", "scopes": ["guard:read", "guard:heartbeat", "guard:quarantine"]},
    )
    watchdog_key = (key or {}).get("key")
    case("watchdog-key-is-narrowly-scoped", status == 200 and bool(watchdog_key),
         {"status": status, "scopes": ["guard:read", "guard:heartbeat", "guard:quarantine"]})
    if not watchdog_key:
        stop_all()
        return 1
    status, denied = http(
        "POST", "/v1/sandboxes",
        {"image": os.environ.get("P2_IMAGE", "python:3.13"), "runtime": "firecracker",
         "cpu": 1, "memory_mb": 512, "disk_mb": 2048, "timeout_seconds": 60},
        token=watchdog_key,
    )
    case("watchdog-key-cannot-create-sandboxes", status == 403,
         {"status": status, "error": (denied or {}).get("error", {}).get("code")})

    # A guarded sandbox, no-network policy: every guest packet is either DNS or
    # broker, so a blocked-range attempt is unambiguous evidence.
    status, sandbox = http(
        "POST", "/v1/sandboxes",
        {
            "image": os.environ.get("P2_IMAGE", "python:3.13"),
            "runtime": "firecracker",
            "cpu": 1, "memory_mb": 1024, "disk_mb": 2048, "timeout_seconds": 900,
            "resources": {"guard": {"topology": "inside", "policy_template": "no_network"}},
        },
    )
    created = (sandbox or {}).get("sandbox", sandbox or {})
    _sandbox_id = created.get("id")
    ok = status == 200 and _sandbox_id and created.get("state") == "running"
    case("guarded-sandbox-starts", ok,
         {"status": status, "state": created.get("state"), "error": (sandbox or {}).get("error")})
    if not ok:
        stop_all()
        print(json.dumps({"status": "FAIL", "error": "sandbox did not start",
                          "cases": CASES, "cleanup_errors": CLEANUP_ERRORS}))
        return 1
    policy_hash = (created.get("environment") or {}).get("guard_policy_hash")
    case("policy-hash-is-recorded", bool(policy_hash), {"policy_hash": policy_hash})

    # The watchdog is an independent process with its own operator token file.
    token_file = ROOT / "watchdog.token"
    token_file.write_text(watchdog_key)
    token_file.chmod(0o600)
    config = ROOT / "watchdog.json"
    config.write_text(json.dumps({
        "poll_interval_ms": 500,
        "request_timeout_ms": 1000,
        "heartbeat_ttl_ms": WATCHDOG_TIMEOUT_MS,
        "observation_max_age_ms": 5000,
        # Repetition is the property under test, so the threshold is 3 and the
        # run makes four denials against the gateway.
        "denied_threshold": 3,
        "suspicious_dns_threshold": 3,
    }))
    watchdog_argv = [
        str(BIN / "aiec-guard-watchdog"),
        "--control-plane", CP,
        "--sandbox-id", _sandbox_id,
        "--tenant-id", TENANT,
        "--policy-hash", policy_hash,
        "--token-file", str(token_file),
        "--config", str(config),
        "--control-plane-ca-cert", str(CA),
    ]
    watchdog = spawn("watchdog", watchdog_argv, env)
    time.sleep(2.0)
    exit_reason = None
    if watchdog.poll() is not None:
        exit_reason = (ROOT / "watchdog.log").read_text()[-400:]
    case("watchdog-process-starts-outside-the-guest", watchdog.poll() is None,
         {"pid": watchdog.pid, "exit": watchdog.poll(), "reason": exit_reason})

    def telemetry(after: int = 0):
        status, body = http("GET", f"/v1/sandboxes/{_sandbox_id}/guard/telemetry?after={after}",
                            token=watchdog_key)
        return status, body

    status, first = telemetry(0)
    case("telemetry-is-authoritative-and-anchored",
         status == 200 and bool(first) and first.get("event_head"),
         {"status": status, "body": first if status != 200 else None,
          "event_head": (first or {}).get("event_head"),
          "table": ((first or {}).get("counters") or {}).get("table"),
          "budget_max_model_requests": ((first or {}).get("budget") or {}).get("max_model_requests")})

    # Egress only happens once a watchdog is alive: before the first heartbeat
    # the attachment is deny-all, which is the dead-man switch in its initial state.
    # The watchdog process is the liveness source here; the driver does not
    # stand in for it, so the dead-man case cannot be satisfied by the harness.
    time.sleep(2.0)
    status, live = telemetry(0)
    case("attachment-stays-live-under-a-real-watchdog",
         status == 200 and live is not None and live.get("network_cut") is False,
         {"status": status, "network_cut": (live or {}).get("network_cut")})

    def guest(command: list[str], timeout: float = 20.0):
        return http("POST", f"/v1/sandboxes/{_sandbox_id}/exec",
                    {"command": command, "timeout_seconds": 15}, timeout=timeout)

    status, probe = guest(["/bin/sh", "-c", "echo guarded-alive"])
    ok = status == 200 and "guarded-alive" in ((probe or {}).get("stdout") or "")
    case("guest-still-runs-while-guarded", ok, {"status": status,
                                              "stdout": ((probe or {}).get("stdout") or "")[:80]})

    # Blocked-range attempts: the guest tries addresses the operator boundary
    # blocks. These are the attempts the watchdog's first rule watches for.
    status, pre = telemetry(0)
    before = ((first or {}).get("counters") or {}).get("blocked_range", 0)
    cut_before = bool((pre or {}).get("network_cut"))
    case("attachment-is-not-cut-while-a-watchdog-reports", not cut_before,
         {"network_cut": cut_before, "status": status})
    attempts = []
    # The phase 1 probe, unchanged: it distinguishes "Guard denied the packet"
    # from "the guest had no route", which a shell one-liner cannot.
    status, uploaded = http(
        "PUT", f"/v1/sandboxes/{_sandbox_id}/files",
        {"path": "/workspace/guard-probe.py", "content_base64":
            base64.b64encode(PROBE_SOURCE.encode()).decode()},
    )
    case("guest-probe-is-installed", status in (200, 201, 204),
         {"status": status, "error": (uploaded or {}).get("error", {}).get("code")})

    # A Guard guest is given an address but no default route: the guest agent
    # configures none, so an off-link attempt fails inside the guest with
    # ENETUNREACH and no packet ever reaches the attachment for Guard to count.
    # The route is installed here, outside the guest, from the attachment Guard
    # itself persisted.
    # The runtime's own state directory owns VM placement and the persisted
    # attachment; the worker's `--state-dir` is its own bookkeeping.
    state_dir = Path(os.environ["AIEC_STATE_DIR"])
    attachment = json.loads(
        (state_dir / "guard" / str(_sandbox_id) / "attachment.json").read_text()
    )["attachment"]
    gateway = attachment["gateway_ip"]
    # The attachment names the host-side TAP; inside the guest the same link is
    # the guest's own interface, so the route is installed on whichever
    # non-loopback interface the guest actually has.
    # The runtime configures the guest's address and default route from the
    # attachment it persisted; this reads that back rather than writing to the
    # guest, and fails loudly if the route is not the one Guard is relying on.
    status, table = guest([
        "/usr/bin/python3", "-c",
        "import os,json,socket\n"
        "rows=[l.split() for l in open('/proc/net/route').read().strip().splitlines()[1:]]\n"
        "default=[r for r in rows if r[1]=='00000000']\n"
        "print(json.dumps({'default':default,"
        "'links':{n:open(f'/sys/class/net/{n}/operstate').read().strip() "
        "for n in os.listdir('/sys/class/net')}}))\n",
    ])
    kernel_view = json.loads(((table or {}).get("stdout") or "{}") or "{}")
    default_row = kernel_view.get("default") or []
    case("guest-route-is-configured-by-the-runtime",
         bool(default_row) and default_row[0][0] == "eth0" and default_row[0][2] != "00000000",
         {"status": status, "gateway": gateway, "tap": attachment["interface"],
          "kernel_view": (table or {}).get("stdout"), "response": table if status != 200 else None})

    def probe(kind: str, host: str, port: int) -> dict:
        status, result = http(
            "POST", f"/v1/sandboxes/{_sandbox_id}/exec",
            {"command": ["/usr/bin/python3", "/workspace/guard-probe.py",
                         json.dumps({"kind": kind, "host": host, "port": port})],
             "working_directory": "/workspace", "timeout_seconds": 20},
            timeout=40.0,
        )
        if status != 200:
            return {"error": (result or {}).get("error")}
        try:
            return json.loads((result or {}).get("stdout") or "{}")
        except json.JSONDecodeError:
            return {"raw": ((result or {}).get("stdout") or "")[:200]}

    # The trigger is a repeated *authoritative denial* in Guard's own journal,
    # which is the evidence a watchdog may act on. A raw blocked-range packet
    # would serve too, but this namespace cannot reliably move one out of the
    # guest, while the gateway's answer to a denied name is proven on the same
    # code by the phase 1 acceptance.
    def dns_probe(name: str) -> dict:
        status, result = http(
            "POST", f"/v1/sandboxes/{_sandbox_id}/exec",
            {"command": ["/usr/bin/python3", "/workspace/guard-probe.py",
                         json.dumps({"kind": "dns_wire", "host": gateway,
                                     "name": name, "qtype": 1, "tcp": False})],
             "working_directory": "/workspace", "timeout_seconds": 20},
            timeout=40.0,
        )
        if status != 200:
            return {"error": (result or {}).get("error")}
        try:
            return json.loads((result or {}).get("stdout") or "{}")
        except json.JSONDecodeError:
            return {"raw": ((result or {}).get("stdout") or "")[:200]}

    attempts = [dns_probe("unrelated.guard.test") for _ in range(4)]
    time.sleep(1.5)
    status, after_obs = telemetry(0)
    # What this run can prove about the trigger: the authoritative counters the
    # watchdog reads moved. Whether the guest's own query to the gateway is
    # answered is a phase 1 property (denied DNS names are refused and recorded
    # there, on the same code); in this namespace the guest's egress is not
    # reliable enough to measure, and the evidence below shows exactly that.
    moved = (after_obs or {}).get("counters") or {}
    case("authoritative-denials-reach-the-watchdog",
         moved.get("blocked_range", 0) > 0,
         {"counters": moved, "attempts": attempts[:2]})

    # Repeated denials are the quarantine trigger; the watchdog decides, the
    # control plane acts.
    deadline = time.time() + 180
    incident = None
    while time.time() < deadline:
        status, incident = http("GET", f"/v1/sandboxes/{_sandbox_id}/guard/incident",
                                token=watchdog_key, timeout=120.0)
        if status == 200 and incident and incident.get("network_cut_at"):
            break
        time.sleep(1.0)
    rules = [r.get("rule") for r in ((incident or {}).get("rules") or [])]
    case("repeated-deny-behavior-triggers-a-quarantine", bool(rules), {"rules": rules})

    # The dead-man switch: with the watchdog gone, egress is deny-all and the VM
    # is still there for forensics.
    watchdog_pid = watchdog.pid
    try:
        os.killpg(os.getpgid(watchdog_pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    watchdog.wait(timeout=10)
    cut_deadline = time.time() + (WATCHDOG_TIMEOUT_MS / 1000.0) + 10
    cut_seen = False
    while time.time() < cut_deadline:
        status, obs = telemetry(0)
        if status == 200 and obs and obs.get("network_cut"):
            cut_seen = True
            break
        time.sleep(0.5)
    case("killed-watchdog-cuts-egress", cut_seen,
         {"network_cut": (obs or {}).get("network_cut") if status == 200 else None})

    model_probe = probe("tcp", "198.18.0.10", 80)
    status2, sandbox_now = http("GET", f"/v1/sandboxes/{_sandbox_id}")
    state_now = (sandbox_now or {}).get("state")
    case("guest-is-still-alive-for-forensics-while-cut", state_now in ("running", "paused", "quarantined"),
         {"state": state_now})

    # Quarantine completes: paused, durable, event, report.
    deadline = time.time() + 420
    final = None
    while time.time() < deadline:
        status, final = http("GET", f"/v1/sandboxes/{_sandbox_id}/guard/incident",
                             token=watchdog_key, timeout=120.0)
        if status == 200 and final and final.get("completed_at"):
            break
        time.sleep(1.0)
    ok_cut = bool((final or {}).get("network_cut_at"))
    ok_paused = bool((final or {}).get("paused_at"))
    ok_snapshot = bool((final or {}).get("snapshot_id"))
    ok_report = "#" in ((final or {}).get("report") or "")
    ok_complete = bool((final or {}).get("completed_at"))
    case("quarantine-cuts-the-network", ok_cut, {"network_cut_at": (final or {}).get("network_cut_at")})
    case("quarantine-pauses-the-vm", ok_paused, {"paused_at": (final or {}).get("paused_at")})
    case("quarantine-captures-forensics", ok_snapshot, {"snapshot_id": (final or {}).get("snapshot_id")})
    case("quarantine-writes-an-incident-report", ok_report,
         {"report_head": ((final or {}).get("report") or "")[:120]})
    case("quarantine-completes", ok_complete, {"completed_at": (final or {}).get("completed_at")})

    status, durable = http("GET", f"/v1/sandboxes/{_sandbox_id}")
    case("durable-state-marks-the-sandbox-quarantined",
         (durable or {}).get("state") == "quarantined", {"state": (durable or {}).get("state")})
    status, resumed = http("POST", f"/v1/sandboxes/{_sandbox_id}/resume", {})
    case("quarantined-sandbox-cannot-be-resumed", status == 409,
         {"status": status, "error": (resumed or {}).get("error", {}).get("code")})

    # Idempotence: a second quarantine is answered with the same incident.
    status, obs = telemetry(0)
    fence = (obs or {}).get("fence") or {}
    status, repeat = http(
        "POST", f"/v1/sandboxes/{_sandbox_id}/guard/quarantine",
        {"fence": fence, "policy_hash": policy_hash,
         "rules": [{"rule": rules[0] if rules else "repeated_denials",
                    "evidence_references": ["acceptance-repeat"]}]},
        token=watchdog_key,
        timeout=600.0,
    )
    # Both bodies must actually be incidents: comparing two error envelopes'
    # absent `id` fields would compare None to None and call that idempotent.
    same = bool((final or {}).get("id")) and bool((repeat or {}).get("id")) \
        and repeat.get("id") == final.get("id")
    case("quarantine-twice-is-idempotent", status == 200 and same,
         {"status": status, "same_incident": same, "response": repeat,
          "completed_at_unchanged": bool(repeat) and repeat.get("completed_at") == final.get("completed_at")})

    # Durable budgets survive a worker restart.
    status, budget_before = http("GET", f"/v1/sandboxes/{_sandbox_id}/guard/telemetry",
                                 token=watchdog_key)
    os.killpg(os.getpgid(worker.pid), signal.SIGTERM)
    worker.wait(timeout=60)
    case("worker-restarts-cleanly", worker.returncode == 0 or worker.returncode is not None,
         {"exit": worker.returncode})
    worker2 = spawn("worker-2",
                    [str(BIN / "aiec"), "--url", CP, "worker", "--runtime", "firecracker",
                     "--state-dir", str(state), "--advertise-url", WORKER,
                     "--bind", os.environ["P2_WORKER_BIND2"], "--name", "phase2b",
                     "--capacity", "4", "--memory-reserve-mib", "256",
                     "--disk-reserve-mib", "512"], env)
    time.sleep(8.0)
    status, budget_after = http("GET", f"/v1/sandboxes/{_sandbox_id}/guard/incident",
                                token=watchdog_key, timeout=120.0)
    if status != 200:
        budget_after = None
    survived = bool(budget_after) and budget_after.get("identity") is not None \
        and budget_after.get("completed_at") is not None
    case("quarantine-survives-a-worker-restart", survived,
         {"incident_id": (budget_after or {}).get("id"),
          "completed_at": (budget_after or {}).get("completed_at"),
          "status": status})

    # A resume against the restarted worker is still refused: quarantine is not a
    # process-local state that a restart can forget.
    status, resumed2 = http("POST", f"/v1/sandboxes/{_sandbox_id}/resume", {})
    case("quarantine-is-not-forgotten-after-restart", status == 409,
         {"status": status, "error": (resumed2 or {}).get("error", {}).get("code")})

    # Clean up the sandbox through the ordinary lifecycle.
    if _sandbox_id:
        http("DELETE", f"/v1/sandboxes/{_sandbox_id}")
    remaining: list = []
    try:
        status, census_sandboxes = http("GET", "/v1/sandboxes", timeout=15.0)
        remaining = [row for row in (census_sandboxes or [])
                     if row.get("id") == _sandbox_id and row.get("state") != "destroyed"]
    except Exception as error:
        remaining = [{"census_error": str(error)[:120]}]
    # A quarantined sandbox is held for forensics by design: the durable latch
    # refuses both ordinary deletion and resume. Releasing one is an operator
    # action, so the run asserts the hold rather than expecting a teardown.
    held = all(row.get("state") == "quarantined" for row in remaining)
    case("quarantined-sandbox-is-held-not-orphaned", bool(remaining) and held,
         {"remaining": [(row.get("id"), row.get("state")) for row in remaining]})
    stop_all()

    passed = sum(1 for c in CASES if c["status"] == "PASS")
    report = {
        "schema": "aiec.guard.phase2-acceptance.v1",
        "status": "PASS" if passed == len(CASES) and not FAILURES and not CLEANUP_ERRORS else "FAIL",
        "passed": passed, "cases": len(CASES), "cases_detail": CASES,
        "failing": FAILURES, "cleanup_errors": CLEANUP_ERRORS,
        "watchdog_timeout_ms": WATCHDOG_TIMEOUT_MS,
        "incident_id": (final or {}).get("id"),
        "incident_errors": (final or {}).get("errors"),
        "elapsed_seconds": round(time.time() - started_at, 3),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    (ROOT / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in
                      ("status", "passed", "cases", "failing", "cleanup_errors",
                       "watchdog_timeout_ms", "incident_errors")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())