#!/usr/bin/env python3
"""Workspace snapshot round-trip acceptance.

Proves the one integration item that had no live artifact behind it: a snapshot
captured from a real Firecracker guest can be restored into a fresh machine and
still carries what was in it. The cycle is deliberately the whole cycle, because
half of it is not measurable:

1. create a machine and wait for it to be running;
2. write a marker file whose content is random for this run, so a restore that
   returned an empty workspace could not pass by finding a file left over from
   an earlier run;
3. capture a workspace snapshot;
4. destroy the machine the snapshot came from - a restore that quietly reads
   from the original would still pass, so the original has to be gone;
5. restore into a fresh machine;
6. read the marker back out of the restored machine.

Everything is observed from outside the guest. The guest's own account of what
happened is not evidence, so the running-state assertions are the control
plane's records of machines it placed and destroyed, and the census at the end
is a /proc walk for this run's sandbox IDs.

The recorded bench run this exists for reported the restore failing with
`500 backend io: No such file or directory`. A failure is not a result: if the
cycle fails, this suite says which step failed and why, and publishes nothing.
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
import urllib.parse
import urllib.request
import uuid
from acceptance_http import urlopen
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["SN_ROOT"])
BIN = Path(os.environ["SN_BIN"])
CA = Path(os.environ["SN_CA"])
CP = os.environ["SN_CP"]
WORKER = os.environ["SN_WORKER"]
TENANT = os.environ["SN_TENANT"]
API_KEY = os.environ["SN_API_KEY"]
WORKER_TOKEN = os.environ["SN_WORKER_TOKEN"]
DATABASE_URL = os.environ["DATABASE_URL"]

CASES: list[dict] = []
CLEANUP_ERRORS: list[str] = []
_started: list[tuple[str, subprocess.Popen]] = []
# Recorded as they are created, not discovered later: a census that walks the
# state directory would pass vacuously if cleanup had already removed it.
SANDBOXES: list[str] = []

# Everything this run mints. A report that quoted any of them would ship a
# credential: the same rule the reaper and Phase 5 publication paths apply.
SECRETS: list[str] = [
    value
    for value in (
        API_KEY,
        WORKER_TOKEN,
        os.environ.get("AIEC_GUEST_SECRET", "").strip(),
        os.environ.get("AIEC_IMAGE_MANIFEST_SECRET", "").strip(),
    )
    if value
]
_password = urllib.parse.unquote(
    DATABASE_URL.split("://", 1)[1].split("@", 1)[0].partition(":")[2]
)
if _password:
    SECRETS.append(_password)


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


def case(name: str, ok: bool, evidence: dict) -> None:
    CASES.append({"case": name, "status": "PASS" if ok else "FAIL", "evidence": evidence})
    log(("PASS " if ok else "FAIL ") + name)
    if not ok:
        print(json.dumps({"case": name, "evidence": evidence}), flush=True)


def http(method: str, path: str, body=None, token: str = API_KEY, timeout: float = 120.0):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(CP + path, data=data, method=method)
    request.add_header("authorization", f"Bearer {token}")
    request.add_header("content-type", "application/json")
    try:
        with urlopen(
            request, timeout=timeout, context=ssl.create_default_context(cafile=str(CA))
        ) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        # The body of a failed call goes to the console, never into the report:
        # it is the only place the real cause appears, and a published report
        # is not the place for a raw response body.
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {method} {path} -> "
              f"{error.code}: {raw[:400].decode('utf-8', 'replace')}", flush=True)
        try:
            return error.code, json.loads(raw)
        except Exception:
            return error.code, {"reason": raw[:200].decode("utf-8", "replace")}


def spawn(name: str, argv: list[str], env: dict | None = None) -> subprocess.Popen:
    log_env = dict(os.environ)
    log_env.update(env or {})
    # Truncated per run: an append-mode log carries the previous run's failures
    # into this one's evidence, and a cause read from the wrong run is worse
    # than no cause at all.
    handle = open(ROOT / f"{name}.log", "wb", buffering=0)
    process = subprocess.Popen(
        argv, stdout=handle, stderr=subprocess.STDOUT, env=log_env, start_new_session=True
    )
    _started.append((name, process))
    return process


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
        "AIEC_TLS_CERT_FILE": os.environ["SN_TLS_CERT"],
        "AIEC_TLS_KEY_FILE": os.environ["SN_TLS_KEY"],
        "AIEC_TLS_CA_CERT": str(CA),
        "AIEC_S3_ENDPOINT": os.environ["SN_S3_ENDPOINT"],
        "AIEC_S3_REGION": "us-east-1",
        "AIEC_S3_BUCKET": "aiec",
        "AIEC_S3_ACCESS_KEY_ID": os.environ["SN_S3_ACCESS_KEY_ID"],
        "AIEC_S3_SECRET_ACCESS_KEY": os.environ["SN_S3_SECRET_ACCESS_KEY"],
        "AIEC_S3_PREFIX": "snapshot/",
        "AIEC_TENANT_ID": TENANT,
        "AIEC_TENANT_NAME": "snapshot",
        "AIEC_API_KEY": API_KEY,
        "AIEC_WORKER_TOKEN": WORKER_TOKEN,
        "AIEC_LEASE_TTL_SECONDS": "300",
        "AIEC_ALLOW_CONTAINER_RUNTIMES": "1",
    }
    for key in (
        "AIEC_FIRECRACKER_BIN",
        "AIEC_KERNEL",
        "AIEC_ROOTFS",
        "AIEC_GUEST_ARTIFACT_DIR",
        "AIEC_GUEST_SECRET",
        "AIEC_IMAGE_MANIFEST",
        "AIEC_IMAGE_MANIFEST_SECRET",
    ):
        env.setdefault(key, os.environ.get(key, ""))
    return env


def wait_for_health(process: subprocess.Popen, seconds: float = 60.0) -> tuple[bool, str]:
    # The reason is returned rather than discarded: a probe that waits a full
    # minute and then reports only "not ready" has thrown away the sole evidence
    # of what was actually wrong.
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



def is_capacity_refusal(status: int, body) -> bool:
    """Whether this response is the documented transient capacity refusal.

    Placement answers 503 `scheduler_unavailable` when no worker both is
    healthy and has measured headroom, and the Run subsystem treats exactly
    that message as retryable. Anything else - a bad request, a conflict, an
    outage - is a different failure and must not be retried as if it were this.
    """
    if status != 503 or not isinstance(body, dict):
        return False
    error = body.get("error") or {}
    return error.get("code") == "scheduler_unavailable" and "capacity" in str(
        error.get("message", "")
    )


def node_capacity() -> list[dict]:
    """What admission saw, read from the scheduling tables themselves.

    Placement refuses with one message for every way a worker can be
    unschedulable - unhealthy, stale heartbeat, draining, short on a
    resource, missing a capability, or a host with no measured headroom - and
    that message alone does not say which. A capacity refusal is the likeliest
    way this suite fails, so the row the scheduler decided on is recorded with
    it rather than guessed at afterwards.
    """
    try:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            rows = connection.execute(
                "SELECT id, healthy, accepting_sandboxes, runtime, "
                "  available_vcpus, available_memory_bytes, available_disk_bytes, "
                "  total_vcpus, total_memory_bytes, total_disk_bytes, sandbox_count, "
                "  round(extract(epoch FROM (now() - last_heartbeat))) AS heartbeat_age_s, "
                "  metadata #>> '{pressure,host_id}' AS host_id, "
                "  metadata #>> '{pressure,memory_available_bytes}' AS pressure_memory, "
                "  metadata #>> '{pressure,disk_available_bytes}' AS pressure_disk "
                "FROM nodes ORDER BY name"
            ).fetchall()
        return [
            {
                "id": str(row[0]),
                "healthy": row[1],
                "accepting": row[2],
                "runtime": row[3],
                "available": {"vcpus": row[4], "memory_bytes": row[5], "disk_bytes": row[6]},
                "total": {"vcpus": row[7], "memory_bytes": row[8], "disk_bytes": row[9]},
                "sandbox_count": row[10],
                # Postgres numerics arrive as Decimal, which is not evidence
                # worth printing in any case: an age is reported in seconds.
                "heartbeat_age_s": float(row[11]) if row[11] is not None else None,
                "host_id": row[12],
                "pressure": {"memory_bytes": row[13], "disk_bytes": row[14]},
            }
            for row in rows
        ]
    except Exception as error:  # a diagnostic must never fail the run
        return [{"unavailable": type(error).__name__}]


def wait_for_state(sandbox_id: str, wanted: set[str], seconds: float = 180.0):
    """Polls the control plane's own record until the sandbox reaches a state.

    The control plane's record, not the guest's report, is the evidence: it is
    written by the thing that placed and fenced the machine.
    """
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        status, body = http("GET", f"/v1/sandboxes/{sandbox_id}")
        last = (status, (body or {}).get("state"))
        if status == 200 and (body or {}).get("state") in wanted:
            return True, last[1], body
        time.sleep(1.0)
    return False, last[1] if last else None, None


def guest_census() -> list[str]:
    """Live Firecracker processes for this run's sandbox IDs, read from /proc."""
    live = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        if "firecracker" in cmdline and any(sid in cmdline for sid in SANDBOXES):
            live.append(f"{entry.name}: {cmdline.replace(chr(0), ' ')[:160]}")
    return live


def stop_all() -> None:
    stopped = set(os.environ.get("SN_STOPPED", "").split())
    for _name, process in reversed(_started):
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
        elif name not in stopped and process.returncode not in (0, -signal.SIGTERM, -signal.SIGKILL):
            CLEANUP_ERRORS.append(f"{name} exited {process.returncode}")


def publish(report: dict, payload: str):
    """Publishes a passing report so the evidence is committed, not just left.

    A failed run publishes nothing: a diagnostic must not be able to replace an
    authoritative artifact. The payload is checked against the run's own
    credentials first, on the same principle as the retained service logs.
    """
    if report["status"] != "PASS":
        return None
    if any(secret and secret in payload for secret in SECRETS):
        print(json.dumps({"status": "PASS", "report_withheld_for_secrets": True}))
        return None
    destination = Path(os.environ.get(
        "SN_REPORT", Path(__file__).resolve().parent.parent / "benchmarks" / "snapshot-acceptance.json"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Written the same way the other suites publish: a reader must never see a
    # half-written artifact, and the file must not be world-readable, because a
    # report is an account of a run that used real credentials.
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(payload)
    temporary.chmod(0o600)
    os.replace(temporary, destination)
    print(json.dumps({"status": "PASS", "published": str(destination)}))
    return destination


def main() -> int:
    started_at = time.time()
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "state").mkdir(exist_ok=True)
    import atexit

    atexit.register(stop_all)

    env = base_env()
    server = spawn(
        "control-plane", [str(BIN / "aiec-server")], {**env, "AIEC_BIND": os.environ["SN_CP_BIND"]}
    )
    healthy, reason = wait_for_health(server)
    if not healthy:
        stop_all()
        print(json.dumps({"status": "FAIL", "error": "control plane did not start",
                          "reason": reason}))
        return 1

    worker = spawn(
        "worker",
        [
            str(BIN / "aiec"), "--url", CP, "worker",
            "--runtime", "firecracker",
            "--state-dir", str(ROOT / "state"),
            "--advertise-url", WORKER,
            "--bind", os.environ["SN_WORKER_BIND"],
            "--name", "snapshot",
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
            with urlopen(
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
        return 1

    # 1. A real machine, on the real runtime.
    status, sandbox = http(
        "POST",
        "/v1/sandboxes",
        {
            "image": "aiec/firecracker-acceptance",
            "cpu": 1,
            "memory_mb": 512,
            "disk_mb": 2048,
            "timeout_seconds": 600,
            "runtime": "firecracker",
            "network": {"enabled": False},
        },
    )
    original = (sandbox or {}).get("id")
    if original:
        SANDBOXES.append(original)
    case("a-sandbox-is-created-on-the-firecracker-runtime",
         status in (200, 201) and bool(original),
         {"status": status, "sandbox_id": original,
          "runtime": (sandbox or {}).get("runtime")})
    if not original:
        stop_all()
        return 1

    running, final_state, _ = wait_for_state(original, {"running", "ready"})
    case("the-sandbox-reaches-running", running,
         {"sandbox_id": original, "state": final_state})
    if not running:
        stop_all()
        return 1

    # 2. A marker whose content is random for this run.
    marker_value = "aiec-snapshot-marker:" + uuid.uuid4().hex
    marker_path = "/workspace/snapshot-marker.txt"
    status, body = http(
        "PUT",
        f"/v1/sandboxes/{original}/files",
        {
            "path": marker_path,
            "content_base64": base64.b64encode(marker_value.encode()).decode(),
        },
    )
    case("the-marker-is-written-into-the-workspace", status == 200,
         {"status": status, "path": marker_path, "response": body})

    status, body = http(
        "GET", f"/v1/sandboxes/{original}/files/content?path={urllib.parse.quote(marker_path)}"
    )
    read_back = ""
    if status == 200 and isinstance(body, dict):
        read_back = base64.b64decode(body.get("content_base64", "")).decode("utf-8", "replace")
    case("the-marker-is-readable-before-any-snapshot",
         read_back == marker_value,
         {"status": status, "matched": read_back == marker_value})

    # 3. Capture.
    capture_started = time.time()
    status, snapshot = http("POST", f"/v1/sandboxes/{original}/snapshots",
                           {"kind": "workspace"})
    snapshot_id = (snapshot or {}).get("id")
    case("a-workspace-snapshot-is-captured",
         status in (200, 201) and bool(snapshot_id),
         {"status": status, "snapshot_id": snapshot_id, "kind": (snapshot or {}).get("kind"),
          "error": (snapshot or {}).get("reason") if status >= 400 else None})
    if not snapshot_id:
        stop_all()
        return 1

    capture_seconds = time.time() - capture_started
    status, listed = http("GET", f"/v1/sandboxes/{original}/snapshots")
    # A page envelope, not a bare array: the listing is bounded and carries a
    # successor. This run creates a handful of snapshots, so one page is the
    # whole history and asserting that is what makes "the snapshot is in here"
    # mean "the snapshot is on this sandbox".
    entries = (listed or {}).get("snapshots") or []
    case("the-history-fits-one-page",
         (listed or {}).get("next") is None,
         {"entries": len(entries), "next": (listed or {}).get("next")})
    entry = next((e for e in entries if e.get("id") == snapshot_id), None)
    # The public listing is the thin `Snapshot` record - id, object key, size,
    # image and timestamp - and deliberately carries no completion flag; the
    # internal record's `complete` is what gates a restore. So what is asserted
    # here is that the capture is recorded at all and recorded with a real
    # object behind it, and completeness itself is proved by the restore below
    # either verifying the stored checksum or refusing.
    case("the-snapshot-is-recorded",
         bool(entry) and int((entry or {}).get("size_bytes") or 0) > 0,
         {"listed": bool(entry), "size_bytes": (entry or {}).get("size_bytes"),
          "object_key": bool((entry or {}).get("object_key")),
          "image_id": (entry or {}).get("image_id"),
          "capture_seconds": round(capture_seconds, 3)})

    # 4. The original must be gone, or a restore that read from it would pass
    #    without having restored anything.
    status, _ = http("DELETE", f"/v1/sandboxes/{original}")
    destroyed, destroyed_state, _ = wait_for_state(original, {"destroyed", "failed"}, 120.0)
    case("the-original-sandbox-is-destroyed-before-the-restore",
         status == 200 and destroyed and destroyed_state == "destroyed",
         {"status": status, "state": destroyed_state})

    # 5. Restore into a fresh machine.
    # A destroy returns the sandbox's reservation in the same transaction that
    # marks it destroyed, but admission also requires headroom the worker
    # measured and reported on its heartbeat, and that reading was taken while
    # the original machine was still holding memory. The refusal is therefore
    # expected until a heartbeat carries a reading from after the destroy, and
    # it is the same condition the Run subsystem classifies as retryable. So it
    # is retried on exactly that condition, bounded, and the attempt count is
    # recorded rather than hidden.
    restore_started = time.time()
    restore_attempts = 0
    capacity_refusals = 0
    while True:
        restore_attempts += 1
        status, restored = http("POST", f"/v1/snapshots/{snapshot_id}/restore", {})
        capacity_refusals += 1 if is_capacity_refusal(status, restored) else 0
        if not is_capacity_refusal(status, restored) or restore_attempts >= 20:
            break
        time.sleep(2)
    restored_id = (restored or {}).get("id")
    if restored_id:
        SANDBOXES.append(restored_id)
    case("the-snapshot-restores-into-a-new-sandbox",
         status in (200, 201) and bool(restored_id) and restored_id != original,
         {"status": status, "restored_id": restored_id, "original_id": original,
          "distinct": restored_id != original if restored_id else False,
          "restore_attempts": restore_attempts, "capacity_refusals": capacity_refusals,
          "error": (restored or {}).get("reason") if status >= 400 else None,
          **({"nodes": node_capacity()} if capacity_refusals else {})})
    if not restored_id:
        stop_all()
        return 1
    restore_seconds = time.time() - restore_started

    running, restored_state, _ = wait_for_state(restored_id, {"running", "ready"})
    case("the-restored-sandbox-reaches-running", running,
         {"sandbox_id": restored_id, "state": restored_state,
          "restore_seconds": round(restore_seconds, 3)})

    # 6. The correctness check: the restored machine carries what was captured.
    status, body = http(
        "GET",
        f"/v1/sandboxes/{restored_id}/files/content?path={urllib.parse.quote(marker_path)}",
    )
    restored_value = ""
    if status == 200 and isinstance(body, dict):
        restored_value = base64.b64decode(body.get("content_base64", "")).decode("utf-8", "replace")
    case("the-restored-workspace-carries-the-marker",
         restored_value == marker_value,
         {"status": status, "matched": restored_value == marker_value,
          "bytes": len(restored_value)})

    # Teardown, then a host-side census of this run's own machines.
    http("DELETE", f"/v1/sandboxes/{restored_id}")
    http("DELETE", f"/v1/snapshots/{snapshot_id}")
    for sandbox_id in (restored_id, original):
        wait_for_state(sandbox_id, {"destroyed", "failed"}, 120.0)

    # Give the worker a moment to finish reaping before the census, then census.
    deadline = time.time() + 30
    live: list[str] = []
    while time.time() < deadline:
        live = guest_census()
        if not live:
            break
        time.sleep(1.0)
    case("no-guest-process-for-this-run-survives", not live,
         {"censused_sandbox_ids": SANDBOXES, "live_guest_processes": live})

    stop_all()
    atexit.unregister(stop_all)

    report = {
        "schema": "aiec.snapshot.acceptance.v1",
        "status": "PASS" if all(c["status"] == "PASS" for c in CASES) and not CLEANUP_ERRORS
        else "FAIL",
        "suite": "snapshot-acceptance",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runtime": "firecracker",
        "elapsed_seconds": round(time.time() - started_at, 3),
        "cases": CASES,
        "passed": sum(1 for c in CASES if c["status"] == "PASS"),
        "cases_total": len(CASES),
        "failing": [c["case"] for c in CASES if c["status"] != "PASS"],
        "cleanup_errors": CLEANUP_ERRORS,
    }
    payload = json.dumps(report, indent=2, sort_keys=True)
    report_path = ROOT / "snapshot-report.json"
    report_path.write_text(payload)
    report_path.chmod(0o600)
    publish(report, payload)
    print(json.dumps({"status": report["status"], "passed": report["passed"],
                      "cases": report["cases_total"], "failing": report["failing"],
                      "cleanup_errors": CLEANUP_ERRORS,
                      "report": str(report_path)}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
