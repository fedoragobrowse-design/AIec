#!/usr/bin/env python3
"""Live check of the 2026-10-01 fixes against the deployed control plane.

Every assertion is about behaviour a unit test cannot reach: a real worker, a
real guest, a real PostgreSQL, a real object store. Run on the deployment host
with the service environment loaded.

    set -a; . ~/aiec/env.systemd; set +a
    python3 /tmp/aiec-bughunt-live.py
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None



BASE = os.environ.get("AIEC_BASE", "https://127.0.0.1:18443")
KEY = os.environ["AIEC_API_KEY"]
CTX = ssl.create_default_context(cafile=os.environ["AIEC_TLS_CA_CERT"])
# This driver is copied to the deployment host as a standalone file.
_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=CTX)
)
DOCKER_IMAGE = "python:3.13"

results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  :: {detail}" if detail else ""))


def call(method, path, body=None, timeout=300):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={
            "authorization": "Bearer " + KEY,
            "content-type": "application/json",
        },
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {"raw": raw.decode(errors="replace")}


def sandbox(runtime):
    status, body = call(
        "POST",
        "/v1/sandboxes",
        {
            "image": "aiec-coding:latest" if runtime == "firecracker" else DOCKER_IMAGE,
            "runtime": runtime,
            "cpu": 1,
            "memory_mb": 512,
            "disk_mb": 2048,
            "timeout_seconds": 600,
        },
    )
    if status not in (200, 201):
        raise SystemExit(f"could not create a {runtime} sandbox: {status} {body}")
    return body["id"]


def wait_running(identifier, runtime, tries=120):
    for _ in range(tries):
        status, body = call("GET", f"/v1/sandboxes/{identifier}")
        if status == 200 and body["state"] == "running":
            return body
        if body and body.get("state") in ("failed", "destroyed"):
            raise SystemExit(f"{runtime} sandbox {identifier} ended {body['state']}")
        time.sleep(1)
    raise SystemExit(f"{runtime} sandbox {identifier} never reached running")


def exec_in(identifier, command):
    status, body = call("POST", f"/v1/sandboxes/{identifier}/exec", {"command": command})
    if status != 200:
        raise SystemExit(f"exec failed: {status} {body}")
    return body


def entries_of(body):
    """A listing route returns a bare array; some return it wrapped."""
    if isinstance(body, list):
        return body
    return body.get("files", body.get("entries", []))


def cell(task, secrets=None, key=None, image=None):
    request = {
        "workload": {"command": ["true"], **({"image": image} if image else {})},
        "timeout_seconds": 120,
    }
    if secrets:
        request["workload"]["secrets"] = secrets
    if key:
        request["idempotency_key"] = key
    return {"axis": {"task": task}, "request": request}


# --------------------------------------------------------------------------
def check_symlink_listing():
    """A link must not empty the listing around it, on either runtime."""
    for runtime in ("docker", "firecracker"):
        identifier = sandbox(runtime)
        try:
            wait_running(identifier, runtime)
            exec_in(
                identifier,
                [
                    "/bin/sh",
                    "-lc",
                    "cd /workspace && mkdir -p sub && echo one > sub/a.txt "
                    "&& echo two > sub/b.txt && ln -sfn /etc sub/escape "
                    "&& ln -sfn ../../.. sub/up",
                ],
            )
            status, body = call(
                "GET",
                f"/v1/sandboxes/{identifier}/files/list?path=/workspace/sub",
            )
            if status != 200:
                record(f"{runtime}: a listing survives a link", False, f"{status} {body}")
                continue
            names = {entry["name"] for entry in entries_of(body)}
            record(
                f"{runtime}: a listing survives a link",
                {"a.txt", "b.txt", "escape"} <= names,
                f"{sorted(names)}",
            )
            status, body = call(
                "POST",
                f"/v1/sandboxes/{identifier}/read",
                {"path": "/workspace/sub/escape/passwd"},
            )
            record(
                f"{runtime}: reading through a link out of the workspace is refused",
                status >= 400,
                f"{status} {body}",
            )
        finally:
            call("DELETE", f"/v1/sandboxes/{identifier}")


def check_snapshot_key():
    """A snapshot key names its tenant, and the capture still restores."""
    identifier = sandbox("docker")
    try:
        wait_running(identifier, "docker")
        exec_in(identifier, ["/bin/sh", "-lc", "echo marker > /workspace/marker.txt"])
        status, body = call(
            "POST", f"/v1/sandboxes/{identifier}/snapshots", {"kind": "workspace"}
        )
        if status not in (200, 201):
            record("snapshot key names its tenant", False, f"{status} {body}")
            return
        key = body.get("object_key", "")
        record(
            "snapshot key names its tenant",
            key.startswith("tenants/") and key.count("/") >= 4,
            key,
        )
        # The restore route is addressed by snapshot id alone, not nested under
        # the sandbox it restores.
        status, restored = call("POST", f"/v1/snapshots/{body['id']}/restore", {})
        record(
            "a workspace snapshot restores into its own sandbox",
            status in (200, 201),
            f"{status} state={restored.get('state') if isinstance(restored, dict) else restored}",
        )
        # A restore creates a second machine. It belongs to this check, so this
        # check destroys it: leaving it behind is what makes the residue check at
        # the end report the script's own leftovers as the platform's.
        if status in (200, 201) and isinstance(restored, dict):
            wait_running(restored["id"], "docker")
            out = exec_in(
                restored["id"], ["/bin/sh", "-lc", "cat /workspace/marker.txt"]
            )
            record(
                "the restored workspace holds what was captured",
                "marker" in (out.get("stdout") or ""),
                (out.get("stdout") or "")[:60],
            )
            call("DELETE", f"/v1/sandboxes/{restored['id']}")
        call("DELETE", f"/v1/snapshots/{body['id']}")
    finally:
        call("DELETE", f"/v1/sandboxes/{identifier}")


def check_partial_matrix():
    """A refused cell is reported beside the cells that ran."""
    body = {
        "cells": [
            cell("ok-a", image=DOCKER_IMAGE),
            cell("refused", image=DOCKER_IMAGE, secrets=["NOT_HELD_SECRET"]),
            cell("ok-b", image=DOCKER_IMAGE),
        ],
        "options": {"max_parallel": 3},
    }
    status, matrix = call("POST", "/v1/eval/matrix", body)
    if status != 200:
        record(
            "a refused matrix cell is reported beside the cells that ran", False, f"{status} {matrix}"
        )
        return
    cells = matrix.get("results", [])
    record(
        "a refused matrix cell is reported beside the cells that ran",
        len(cells) == 3
        and not cells[1].get("run")
        and bool(cells[1].get("error"))
        and bool(cells[0].get("run"))
        and bool(cells[2].get("run")),
        json.dumps([{k: c.get(k) for k in ("axis", "error")} for c in cells])[:280],
    )
    status, page = call("GET", f"/v1/eval/matrix/{matrix['matrix_id']}?limit=10")
    recovered = len(page.get("cells", [])) if status == 200 else -1
    record(
        "the matrix id addresses the runs that executed",
        recovered == 2,
        f"{status} recovered={recovered}",
    )


def check_partly_keyed_matrix():
    body = {
        "cells": [
            cell("a", key="caller-key-0", image=DOCKER_IMAGE),
            cell("b", image=DOCKER_IMAGE),
        ],
        "options": {"max_parallel": 2},
    }
    status, refused = call("POST", "/v1/eval/matrix", body, timeout=120)
    message = (refused or {}).get("error", {}).get("message", "")
    record(
        "a partly-keyed matrix is refused with a count of what to fix",
        status == 400 and "every cell" in message and "no cell" in message,
        f"{status} {message[:160]}",
    )


def check_retention():
    """A failed run keeps a readable machine, and the sweeper takes it."""
    body = {
        "workload": {
            "command": ["/bin/sh", "-lc", "echo working; exit 3"],
            "image": DOCKER_IMAGE,
        },
        "timeout_seconds": 120,
        "retention": "keep_on_failure",
        "retained_seconds": 45,
    }
    status, run = call("POST", "/v1/runs", body)
    if status not in (200, 201):
        record("a failed run keeps its machine", False, f"{status} {run}")
        return
    retained = run.get("retained_sandbox_id")
    record(
        "a failed run keeps its machine for debugging",
        run.get("state") == "failed" and bool(retained) and bool(run.get("retained_until")),
        f"state={run.get('state')} failure={run.get('failure_reason')} "
        f"retained={retained} until={run.get('retained_until')}",
    )
    if not retained:
        return
    out = call(
        "POST",
        f"/v1/sandboxes/{retained}/exec",
        {"command": ["/bin/sh", "-lc", "echo RETAINED_READABLE"]},
    )[1]
    record("the retained machine is readable", "RETAINED_READABLE" in (out.get("stdout") or ""), "")
    # The sweeper owns this one: nothing here deletes it, and the window is 45 s.
    time.sleep(70)
    status, body = call("GET", f"/v1/sandboxes/{retained}")
    record(
        "the sweeper reclaims the retained machine after the window",
        status == 200 and body.get("state") == "destroyed",
        f"{status} {body.get('state') if isinstance(body, dict) else body}",
    )
    call("DELETE", f"/v1/sandboxes/{retained}")


def check_default_image():
    """A Run that names no image boots one the runtime can pull."""
    body = {
        "workload": {"command": ["true"]},
        "timeout_seconds": 180,
        "requested_runtime": "docker",
    }
    status, run = call("POST", "/v1/runs", body, timeout=300)
    ok = status in (200, 201) and run.get("state") == "succeeded"
    record(
        "a Run with no image boots one its runtime can pull",
        ok,
        f"{status} state={run.get('state')} failure={run.get('failure_reason')}",
    )


def check_no_residue():
    # The listing is paginated, and this used to ask for 256 while the control
    # plane serves at most 200. Reading page one and calling the result "no
    # residue" reports clean on the strength of a request that was silently
    # capped, so the cursor is followed and the result says how much it saw.
    items, pages, cursor = [], 0, None
    for _ in range(64):
        path = "/v1/sandboxes?limit=200"
        if cursor:
            # Percent-encoded, never interpolated: an RFC3339 timestamp can end
            # in "+00:00", and a bare "+" in a query decodes as a space.
            path += (
                f"&after_created_at={quote(cursor[0], safe='')}"
                f"&after_id={quote(cursor[1], safe='')}"
            )
        status, body = call("GET", path)
        if status != 200:
            record(
                "no sandbox left running by this round",
                False,
                f"{status} on page {pages + 1}",
            )
            return
        if not isinstance(body, dict) or not isinstance(body.get("sandboxes"), list):
            record(
                "no sandbox left running by this round",
                False,
                f"GET {path} did not return a sandbox page "
                f"(body was {type(body).__name__})",
            )
            return
        items.extend(body["sandboxes"])
        pages += 1
        nxt = body.get("next")
        if nxt is None:
            break
        if not isinstance(nxt, dict) or "created_at" not in nxt or "id" not in nxt:
            record(
                "no sandbox left running by this round",
                False,
                "a page carried a cursor that is not a cursor",
            )
            return
        position = (str(nxt["created_at"]), str(nxt["id"]))
        if position == cursor:
            record(
                "no sandbox left running by this round",
                False,
                "the control plane repeated a cursor, so the walk never ends",
            )
            return
        cursor = position
    else:
        record(
            "no sandbox left running by this round",
            False,
            "still paging after 64 pages; the walk was cut short",
        )
        return
    live = [
        s
        for s in items
        if isinstance(s, dict) and s.get("state") in ("running", "starting", "creating", "paused")
    ]
    record(
        "no sandbox left running by this round",
        not live,
        f"{len(live)} live across {pages} page(s), {len(items)} sandboxes: "
        f"{[s['id'] for s in live][:4]}",
    )


for check in (
    check_symlink_listing,
    check_snapshot_key,
    check_partial_matrix,
    check_partly_keyed_matrix,
    check_default_image,
    check_retention,
    check_no_residue,
):
    try:
        check()
    except SystemExit as error:
        record(f"{check.__name__} could not run", False, str(error))
    except Exception as error:  # noqa: BLE001 - a proof script reports, it does not raise
        record(f"{check.__name__} raised", False, repr(error))

failed = [name for name, ok, _ in results if not ok]
print()
print(f"{len(results) - len(failed)}/{len(results)} checks passed")
if failed:
    print("failed: " + ", ".join(failed))
sys.exit(1 if failed else 0)