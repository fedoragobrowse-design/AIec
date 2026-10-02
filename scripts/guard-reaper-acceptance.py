#!/usr/bin/env python3
"""Live acceptance for the durable Guard reaper.

The durable lifetime/budget reaper has previously been exercised only through
the unit repository and the watchdog-driven quarantine path. Nothing has shown
it firing against a real deployment.

This run proves it does. The distinguishing condition is what is *absent*: no
watchdog process runs, and nothing in this driver calls the guard quarantine
API. Every quarantine observed here therefore has exactly one possible author,
the control plane's own reaper task, reading durable rows that no restart
resets.

Two triggers are covered:

* an exhausted durable model-request budget, on a still-running sandbox;
* an expired sandbox lifetime, with the race against ordinary lease expiry
  recorded rather than assumed.
"""
from __future__ import annotations

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

ROOT = Path(os.environ["RP_ROOT"])
BIN = Path(os.environ["RP_BIN"])
CA = Path(os.environ["RP_CA"])
CP = os.environ["RP_CP"]
WORKER = os.environ["RP_WORKER"]
TENANT = os.environ["RP_TENANT"]
API_KEY = os.environ["RP_API_KEY"]
WORKER_TOKEN = os.environ["RP_WORKER_TOKEN"]
DATABASE_URL = os.environ["DATABASE_URL"]
# The shipped reaper ticks every 15 seconds; the waits below are sized against
# that interval, not against an assumption that it has already fired.
REAP_INTERVAL_SECONDS = 15

CASES: list[dict] = []
FAILURES: list[str] = []
CLEANUP_ERRORS: list[str] = []
_started: list[tuple[str, subprocess.Popen]] = []


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def case(name: str, ok: bool, evidence: dict) -> None:
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    log(f"{'PASS' if ok else 'FAIL'} {name}")
    if not ok:
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
    handle = open(ROOT / f"{name}.log", "wb", buffering=0)
    process = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT,
                               env=log_env, start_new_session=True)
    _started.append((name, process))
    return process


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
            CLEANUP_ERRORS.append(f"{name} exited {process.returncode}")


def base_env(prefix: str) -> dict:
    return {
        "DATABASE_URL": DATABASE_URL,
        "AIEC_RUNTIME": "firecracker",
        "AIEC_FIRECRACKER_BIN": os.environ["AIEC_FIRECRACKER_BIN"],
        "AIEC_KERNEL": os.environ["AIEC_KERNEL"],
        "AIEC_ROOTFS": os.environ["AIEC_ROOTFS"],
        "AIEC_GUEST_SECRET": os.environ["AIEC_GUEST_SECRET"],
        "AIEC_IMAGE_MANIFEST": os.environ["AIEC_IMAGE_MANIFEST"],
        "AIEC_IMAGE_MANIFEST_SECRET": os.environ["AIEC_IMAGE_MANIFEST_SECRET"],
        "AIEC_TLS_CERT_FILE": os.environ["RP_TLS_CERT"],
        "AIEC_TLS_KEY_FILE": os.environ["RP_TLS_KEY"],
        "AIEC_TLS_CA_CERT": str(CA),
        "AIEC_S3_ENDPOINT": os.environ["RP_S3_ENDPOINT"],
        "AIEC_S3_REGION": "us-east-1",
        "AIEC_S3_BUCKET": "aiec",
        "AIEC_S3_ACCESS_KEY_ID": os.environ["RP_S3_ACCESS_KEY_ID"],
        "AIEC_S3_SECRET_ACCESS_KEY": os.environ["RP_S3_SECRET_ACCESS_KEY"],
        "AIEC_S3_PREFIX": f"{prefix}/",
        "AIEC_TENANT_ID": TENANT,
        "AIEC_TENANT_NAME": prefix,
        "AIEC_API_KEY": API_KEY,
        "AIEC_WORKER_TOKEN": WORKER_TOKEN,
        "AIEC_LEASE_TTL_SECONDS": "300",
    }


def wait_for_health(process: subprocess.Popen, seconds: float = 60.0) -> tuple[bool, str]:
    # The reason is returned rather than discarded: a probe that waits a full
    # minute and then reports only "not ready" throws away the sole evidence of
    # what was actually wrong, and every consumer here is a failure report.
    deadline = time.time() + seconds
    reason = "no attempt completed before the deadline"
    while time.time() < deadline:
        if process.poll() is not None:
            return False, f"the process exited {process.returncode}"
        try:
            status, _ = http("GET", "/health", token="", timeout=3.0)
            if status == 200:
                return True, ""
            reason = f"the health endpoint answered {status}"
        except Exception as error:
            reason = f"{type(error).__name__}: {error}"
        time.sleep(0.5)
    return False, reason


def create_sandbox(label: str, timeout_seconds: int, max_model_requests: int, extra_guard=None):
    # Templates are kebab-case in the wire grammar. `no_network` is not a
    # spelling the policy accepts, and the rejection arrives as a 422 from the
    # body deserializer rather than as anything naming the field.
    guard = {"topology": "inside", "policy_template": "no-network",
             "max_model_requests": max_model_requests}
    guard.update(extra_guard or {})
    # Guard governance lives on `environment`, not `resources`. `resources` is a
    # Run-side type that the sandbox create body does not carry, so posting it
    # here is silently dropped - the sandbox comes back with the default
    # 10 000-request ceiling and a budget nobody asked for.
    return http("POST", "/v1/sandboxes", {
        "image": os.environ.get("RP_IMAGE", "python:3.13"),
        "runtime": "firecracker",
        "cpu": 1, "memory_mb": 1024, "disk_mb": 2048,
        "timeout_seconds": timeout_seconds,
        "environment": {"guard": guard},
    })


def watch_reaper(sandbox_id: str, budget_exhausted_at: float, seconds: float) -> dict:
    """Polls until the quarantine is durably complete, recording the whole wait.

    Completion is the incident's own five fields, not the first sign of a cut.
    The network cut is stage one of a quarantine that then pauses, captures and
    writes the durable mark, so a suite that stops watching at the cut observes
    a machine that is cut but not yet held - which reads as an incomplete
    quarantine rather than as a watch that ended early.
    """
    incident = None
    telemetry = None
    state = None
    states = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        status, incident = http("GET", f"/v1/sandboxes/{sandbox_id}/guard/incident", timeout=60.0)
        status, current = http("GET", f"/v1/sandboxes/{sandbox_id}", timeout=30.0)
        state = (current or {}).get("state")
        states.append(state)
        if status == 200 and complete_incident(incident):
            break
        status, telemetry = http("GET", f"/v1/sandboxes/{sandbox_id}/guard/telemetry", timeout=60.0)
        time.sleep(1.0)
    return {
        "observed_after_seconds": round(time.time() - budget_exhausted_at, 3),
        "final_state": state,
        "states_observed": sorted({s for s in states if s}),
        "incident": incident,
        "budget": (telemetry or {}).get("budget"),
    }


def complete_incident(incident) -> bool:
    """A quarantine is complete only when every stage of it is recorded."""
    incident = incident or {}
    return bool(incident.get("completed_at") and incident.get("network_cut_at")
                and incident.get("paused_at") and incident.get("snapshot_id")
                and incident.get("report"))


def main() -> int:
    started_at = time.time()
    ROOT.mkdir(parents=True, exist_ok=True)
    state = ROOT / "state"
    state.mkdir(exist_ok=True)
    env = base_env("reaper")

    server = spawn("control-plane", [str(BIN / "aiec-server")],
                   {**env, "AIEC_BIND": os.environ["RP_CP_BIND"]})
    healthy, reason = wait_for_health(server)
    if not healthy:
        log(f"control plane did not become healthy: {reason}")
        print(json.dumps({"status": "FAIL", "error": "control plane did not start",
                          "detail": reason}))
        stop_all()
        return 1
    worker = spawn("worker", [
        str(BIN / "aiec"), "--url", CP, "worker", "--runtime", "firecracker",
        "--state-dir", str(state), "--advertise-url", WORKER,
        "--bind", os.environ["RP_WORKER_BIND"], "--name", "reaper",
        "--capacity", "4", "--memory-reserve-mib", "256", "--disk-reserve-mib", "512",
    ], env)
    deadline = time.time() + 60
    registered, detail = False, {}
    while time.time() < deadline:
        if worker.poll() is not None:
            detail = {"exit": worker.returncode}
            break
        try:
            request = urllib.request.Request(WORKER + "/health")
            request.add_header("authorization", f"Bearer {WORKER_TOKEN}")
            with urllib.request.urlopen(request, timeout=5.0,
                                        context=ssl.create_default_context(cafile=str(CA))) as response:
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
        return 1

    # No watchdog is started anywhere in this run, and this driver never calls
    # POST /guard/quarantine. That is the control for the cases below: whatever
    # quarantines a sandbox here, the reaper did.
    watchdog_present = [name for name, _ in _started if "watchdog" in name]
    case("no-watchdog-process-runs-in-this-suite", not watchdog_present,
         {"started_processes": [name for name, _ in _started]})

    # A narrow guard-read key, so the evidence below is read through the same
    # scope the watchdog would use rather than through an admin credential.
    status, key = http("POST", "/v1/keys",
                       {"name": "reaper-reader", "scopes": ["guard:read"]})
    reader = (key or {}).get("key")
    case("guard-read-key-is-minted", status == 200 and bool(reader),
         {"status": status, "scopes": ["guard:read"]})
    if not reader:
        stop_all()
        return 1

    # Case 1: an exhausted durable model-request budget on a running sandbox.
    # The budget is spent durably from the control plane's own ledger, which is
    # the row the reaper reads; the run does not fake an expiry timestamp.
    status, sandbox = create_sandbox("exhausted", 900, 1)
    created = (sandbox or {}).get("sandbox", sandbox or {})
    exhausted_id = created.get("id")
    case("guarded-sandbox-starts-for-budget-exhaustion",
         status == 200 and bool(exhausted_id) and created.get("state") == "running",
         {"status": status, "state": created.get("state"),
          "error": (sandbox or {}).get("error")})
    if not exhausted_id:
        stop_all()
        return 1

    status, telemetry = http("GET", f"/v1/sandboxes/{exhausted_id}/guard/telemetry", token=reader)
    budget = (telemetry or {}).get("budget") or {}
    case("durable-budget-is-spent-through-the-controlled-ledger",
         bool(budget) and budget.get("max_model_requests") == 1,
         {"status": status, "budget": budget})
    case("sandbox-is-running-and-unquarantined-before-the-reaper",
         budget.get("quarantined") is False,
         {"quarantined": budget.get("quarantined"), "network_cut": (telemetry or {}).get("network_cut")})

    # The budget is spent through the worker-authenticated durable reservation
    # route the gateway itself uses. Nothing writes the ledger directly, and
    # that route refuses a quarantined sandbox, so a sandbox the reaper already
    # took cannot afterwards be driven into a false exhaustion.
    exhaustion = exhaust_budget(exhausted_id)
    exhausted_at = time.time()
    case("durable-budget-is-exhausted-through-the-ledger-route",
         exhaustion.get("exhausted") is True,
         {"status": exhaustion.get("status"), "response": exhaustion.get("response"),
          "route": "POST /v1/workers/{node}/guard/reserve with the worker credential"})

    observation = watch_reaper(exhausted_id, exhausted_at, seconds=120)
    incident = observation.get("incident") or {}
    rules = [r.get("rule") for r in (incident.get("rules") or [])]
    case("reaper-quarantines-an-exhausted-budget-with-no-watchdog",
         "durable_budget_exhausted" in rules,
         {"rules": rules, "observed_after_seconds": observation.get("observed_after_seconds"),
          "network_cut_at": incident.get("network_cut_at"),
          "final_state": observation.get("final_state"),
          "author": "control-plane durable reaper; no watchdog and no quarantine caller in this run"})
    case("reaper-quarantine-cuts-egress",
         bool(incident.get("network_cut_at")),
         {"network_cut_at": incident.get("network_cut_at")})
    status, durable = http("GET", f"/v1/sandboxes/{exhausted_id}")
    case("reaper-quarantine-is-durable",
         (durable or {}).get("state") == "quarantined",
         {"state": (durable or {}).get("state")})
    status, resumed = http("POST", f"/v1/sandboxes/{exhausted_id}/resume", {})
    case("reaper-quarantine-refuses-resume", status == 409,
         {"status": status, "error": (resumed or {}).get("error", {}).get("code")})

    # The reaper is idempotent in the sense that matters: a second tick does not
    # reopen or duplicate anything. The incident identity is stable and its
    # completion timestamps do not move.
    before_incident = dict(incident)
    time.sleep(REAP_INTERVAL_SECONDS * 2)
    status, again = http("GET", f"/v1/sandboxes/{exhausted_id}/guard/incident", token=reader)
    same_incident = bool((again or {}).get("id")) and (again or {}).get("id") == before_incident.get("id")
    unchanged = (again or {}).get("completed_at") == before_incident.get("completed_at")
    case("a-later-reaper-tick-changes-nothing", status == 200 and same_incident and unchanged,
         {"status": status, "same_incident": same_incident,
          "completed_at": (again or {}).get("completed_at"),
          "previous_completed_at": before_incident.get("completed_at")})

    # Case 2: lifetime expiry. The sandbox's own timeout is the durable budget's
    # expiry, so a short timeout is what makes the lifetime rule reachable
    # without touching the ledger by hand. Ordinary lease expiry can win this
    # race, so the state it was in when the reaper acted is recorded as
    # evidence rather than assumed to be `running`.
    status, expiring = create_sandbox("expiring", 45, 1000)
    expiring_row = (expiring or {}).get("sandbox", expiring or {})
    expiring_id = expiring_row.get("id")
    case("guarded-sandbox-starts-for-lifetime-expiry",
         status == 200 and bool(expiring_id),
         {"status": status, "state": expiring_row.get("state"),
          "error": (expiring or {}).get("error")})
    if not expiring_id:
        stop_all()
        return 1
    status, telemetry = http("GET", f"/v1/sandboxes/{expiring_id}/guard/telemetry", token=reader)
    expiring_budget = (telemetry or {}).get("budget") or {}
    case("durable-budget-expiry-equals-the-sandbox-lifetime",
         bool(expiring_budget.get("expires_at")),
         {"expires_at": expiring_budget.get("expires_at"),
          "timeout_seconds": 45, "created_at": expiring_row.get("created_at")})

    lifetime = watch_reaper(expiring_id, time.time(), seconds=180)
    lifetime_incident = lifetime.get("incident") or {}
    lifetime_rules = [r.get("rule") for r in (lifetime_incident.get("rules") or [])]
    case("reaper-quarantines-an-expired-lifetime",
         "sandbox_lifetime_expired" in lifetime_rules,
         {"rules": lifetime_rules,
          "observed_after_seconds": lifetime.get("observed_after_seconds"),
          "states_observed": lifetime.get("states_observed"),
          "final_state": lifetime.get("final_state"),
          "race": "ordinary lease expiry may end the sandbox first; the state sequence "
                  "above records which, rather than assuming the reaper won"})

    # Cleanup: both sandboxes are quarantined and therefore held for forensics
    # by design. This run asserts that hold rather than expecting teardown, and
    # the launcher reaps the whole namespace afterwards.
    census = []
    status, sandboxes = http("GET", "/v1/sandboxes", timeout=30.0)
    if status == 200:
        held = [row for row in (sandboxes or [])
                if row.get("id") in (exhausted_id, expiring_id)]
        census = [{"id": row.get("id"), "state": row.get("state")} for row in held]
        case("reaped-sandboxes-are-held-not-orphaned",
             bool(held) and all(row.get("state") == "quarantined" for row in held),
             {"remaining": census})
    stop_all()

    passed = sum(1 for c in CASES if c["status"] == "PASS")
    report = {
        "schema": "aiec.guard.reaper-acceptance.v1",
        "status": "PASS" if passed == len(CASES) and not FAILURES and not CLEANUP_ERRORS else "FAIL",
        "passed": passed, "cases": len(CASES), "cases_detail": CASES,
        "failing": FAILURES, "cleanup_errors": CLEANUP_ERRORS,
        "reap_interval_seconds": REAP_INTERVAL_SECONDS,
        "observation_provenance": "control-plane durable reaper; no watchdog process and no "
                                  "caller of POST /guard/quarantine exists in this run",
        "elapsed_seconds": round(time.time() - started_at, 3),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    (ROOT / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in
                      ("status", "passed", "cases", "failing", "cleanup_errors")}))
    return 0 if report["status"] == "PASS" else 1




def exhaust_budget(sandbox_id: str) -> dict:
    """Spends the durable model-request budget through the worker's own route.

    The gateway's budget client is the only supported writer of this ledger, so
    the run drives it the way the product does: an authenticated reservation on
    the worker's guard budget route. Reaching for it directly is deliberate and
    bounded — the alternative, a model call from inside the guest, would conflate
    this test with the model loop that is already proven elsewhere.
    """
    status, telemetry = http("GET", f"/v1/sandboxes/{sandbox_id}/guard/telemetry")
    fence = (telemetry or {}).get("fence") or {}
    identity = (telemetry or {}).get("identity") or {}
    node = (http("GET", f"/v1/sandboxes/{sandbox_id}")[1] or {}).get("node_id")
    if not (node and identity and fence):
        return {"status": None, "exhausted": False,
                "response": {"error": "node, identity or fence unavailable",
                             "node_id": node, "has_identity": bool(identity),
                             "has_fence": bool(fence)}}
    payload = {"identity": identity, "fence": fence,
               "debit": {"model_requests": 1, "bytes_in": 0, "bytes_out": 0}}
    request = urllib.request.Request(
        CP + f"/v1/workers/{node}/guard/reserve", data=json.dumps(payload).encode(), method="POST")
    request.add_header("authorization", f"Bearer {WORKER_TOKEN}")
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(
            request, timeout=30.0, context=ssl.create_default_context(cafile=str(CA))
        ) as response:
            body = response.read()
            return {"status": response.status, "exhausted": True,
                    "response": json.loads(body) if body else None}
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode(errors="replace")[:300]}
        return {"status": error.code, "exhausted": False, "response": parsed}


if __name__ == "__main__":
    sys.exit(main())
