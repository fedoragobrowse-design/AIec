"""Snapshot and workspace restore, measured where the API allows it.

The sandbox API can capture a workspace and restore it into a fresh machine, and
the specification wants both latencies. It also wants the answer to be honest
when a runtime cannot do it: a Docker worker without a snapshot provider answers
501, and the correct result is "unavailable, here is why" - not a zero, and not
a failure that looks like a performance problem.

Each sample does the whole cycle, because half of it is not measurable:

1. create a machine, timing create to running;
2. run a command, timing running to first successful exec;
3. write a marker file the snapshot must carry;
4. capture a workspace snapshot, timing it;
5. destroy the original machine, timing the destroy;
6. restore the snapshot into a new machine, timing the restore;
7. read the marker back - the correctness evidence that the restore restored
   something rather than merely returning a machine;
8. destroy the restored machine and delete the snapshot.

Every sandbox the harness creates is tracked before the first step that can
fail, so a half-finished sample is still cleaned up.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..client import TransportError
from ..harness import Bench
from ..stats import summarise, unavailable

NAME = "snapshot"
SUMMARY = "snapshot and workspace-restore latency, with a correctness check"
REQUIRES: tuple[str, ...] = ()

#: Written before the snapshot and read back after the restore. Random per
#: sample, so a restore that returns an empty workspace cannot accidentally pass
#: by finding a file left over from an earlier sample.
MARKER_PREFIX = "aiec-bench-marker"


def run(bench: Bench, args: Any) -> dict[str, Any]:
    create_body = {
        "image": args.image,
        "cpu": args.cpu,
        "memory_mb": args.memory_mb,
        "disk_mb": args.disk_mb,
        "timeout_seconds": int(args.sandbox_ttl),
        "network": {"enabled": False},
    }
    if args.runtime:
        create_body["runtime"] = args.runtime

    samples: list[dict[str, Any]] = []
    unsupported: dict[str, Any] | None = None

    for index in range(max(1, args.samples)):
        sample, unsupported = _one(bench, args, create_body, index)
        if sample is not None:
            samples.append(sample)
        if unsupported is not None:
            # One refusal is the whole answer: a runtime that cannot snapshot
            # will not start on the fifth sample either.
            break

    if unsupported is not None:
        bench.limit(unsupported["reason"])
        return {
            "available": False,
            "reason": unsupported["reason"],
            "refusal": unsupported,
            "samples_completed": len(samples),
        }

    return _report(bench, args, samples)


def _one(
    bench: Bench, args: Any, create_body: dict[str, Any], index: int
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """One create/snapshot/destroy/restore cycle."""
    client = bench.client
    sample: dict[str, Any] = {"index": index}
    sandbox_id: str | None = None
    restored_id: str | None = None
    snapshot_id: str | None = None

    try:
        created = client.request("POST", "/v1/sandboxes", create_body, timeout=args.sandbox_ttl)
        if not created.ok or not isinstance(created.body, dict) or not created.body.get("id"):
            reason = (
                f"the cluster refused to create a sandbox: {created.status} "
                f"{created.error_code()}"
            )
            bench.limit(reason)
            return None, {"step": "create", "status": created.status,
                          "code": created.error_code(), "reason": reason}
        sandbox_id = str(created.body["id"])
        bench.track(sandbox_id, f"snapshot scenario sample {index}")
        sample["create"] = {
            "seconds": round(created.seconds, 4),
            "state": created.body.get("state"),
            "runtime": created.body.get("runtime"),
        }

        first_exec = client.request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/exec",
            {"command": args.command_vector, "timeout_seconds": int(args.exec_timeout)},
            timeout=args.exec_timeout + 30,
        )
        sample["first_exec"] = _exec_result(first_exec, client)

        marker = f"{MARKER_PREFIX}-{uuid.uuid4().hex}"
        sample["marker_written"] = _write_marker(client, sandbox_id, marker, args)
        if not sample["marker_written"].get("written"):
            return sample, None

        captured = client.request(
            "POST",
            f"/v1/sandboxes/{sandbox_id}/snapshots",
            {"kind": args.snapshot_kind},
            timeout=args.snapshot_timeout,
        )
        if not captured.ok or not isinstance(captured.body, dict) or not captured.body.get("id"):
            reason = (
                f"this runtime does not provide a {args.snapshot_kind} snapshot: "
                f"{captured.status} {captured.error_code()} "
                f"{client.redact(captured.error_message())[:200]}"
            )
            bench.limit(reason)
            return None, {"step": "snapshot", "status": captured.status,
                          "code": captured.error_code(), "reason": reason}
        snapshot_id = str(captured.body["id"])
        sample["snapshot"] = {
            "seconds": round(captured.seconds, 4),
            "id": snapshot_id,
            "size_bytes": captured.body.get("size_bytes"),
            "object_key_present": bool(captured.body.get("object_key")),
        }

        destroyed = client.request("DELETE", f"/v1/sandboxes/{sandbox_id}",
                                   timeout=args.snapshot_timeout)
        sample["destroy"] = {
            "seconds": round(destroyed.seconds, 4),
            "status": destroyed.status,
        }
        if destroyed.ok or destroyed.status == 404:
            bench.release(sandbox_id)
            sandbox_id = None

        restored = client.request(
            "POST",
            f"/v1/snapshots/{snapshot_id}/restore",
            {
                "cpu": args.cpu,
                "memory_mb": args.memory_mb,
                "disk_mb": args.disk_mb,
                **({"runtime": args.runtime} if args.runtime else {}),
            },
            timeout=args.snapshot_timeout,
        )
        if not restored.ok or not isinstance(restored.body, dict) or not restored.body.get("id"):
            reason = (
                f"this runtime could not restore a workspace snapshot: {restored.status} "
                f"{restored.error_code()} "
                f"{client.redact(restored.error_message())[:200]}"
            )
            bench.limit(reason)
            return sample, {"step": "restore", "status": restored.status,
                            "code": restored.error_code(), "reason": reason}
        restored_id = str(restored.body["id"])
        bench.track(restored_id, f"snapshot scenario sample {index} (restored)")
        sample["restore"] = {
            "seconds": round(restored.seconds, 4),
            "state": restored.body.get("state"),
            "runtime": restored.body.get("runtime"),
        }

        verified = client.request(
            "POST",
            f"/v1/sandboxes/{restored_id}/exec",
            {"command": ["/bin/sh", "-c", f"cat /workspace/{marker}"],
             "timeout_seconds": int(args.exec_timeout)},
            timeout=args.exec_timeout + 30,
        )
        sample["restore_contents"] = _verify_marker(verified, marker, client)

        cleanup = client.request("DELETE", f"/v1/sandboxes/{restored_id}",
                                 timeout=args.snapshot_timeout)
        sample["destroy_restored"] = {"seconds": round(cleanup.seconds, 4),
                                      "status": cleanup.status}
        if cleanup.ok or cleanup.status == 404:
            bench.release(restored_id)
            restored_id = None

        deleted = client.request("DELETE", f"/v1/snapshots/{snapshot_id}", timeout=60)
        sample["snapshot_deleted"] = {"status": deleted.status}
        return sample, None

    except TransportError as error:
        reason = client.redact(str(error))
        bench.limit(f"transport failure during the snapshot scenario: {reason}")
        return None, {"step": "transport", "status": None, "reason": reason}


def _exec_result(response: Any, client: Any) -> dict[str, Any]:
    if not response.ok or not isinstance(response.body, dict):
        return {
            "available": False,
            "seconds": round(response.seconds, 4),
            "reason": f"{response.status} {response.error_code()}",
        }
    body = response.body
    return {
        "available": True,
        "seconds": round(response.seconds, 4),
        "exit_code": body.get("exit_code"),
        "timed_out": body.get("timed_out"),
    }


def _write_marker(client: Any, sandbox_id: str, marker: str, args: Any) -> dict[str, Any]:
    response = client.request(
        "POST",
        f"/v1/sandboxes/{sandbox_id}/exec",
        {"command": ["/bin/sh", "-c", f"printf '%s' {marker} > /workspace/{marker}"],
         "timeout_seconds": int(args.exec_timeout)},
        timeout=args.exec_timeout + 30,
    )
    if not response.ok or not isinstance(response.body, dict):
        return {
            "written": False,
            "reason": f"{response.status} {response.error_code()}: "
            f"{client.redact(response.error_message())[:200]}",
        }
    return {"written": response.body.get("exit_code") == 0, "path": f"/workspace/{marker}"}


def _verify_marker(response: Any, marker: str, client: Any) -> dict[str, Any]:
    """Did the restored workspace actually contain what was snapshotted?

    A restore that returns a running machine with an empty workspace would
    otherwise look exactly like a fast, successful restore.
    """
    if not response.ok or not isinstance(response.body, dict):
        return {
            "available": False,
            "reason": f"{response.status} {response.error_code()}: "
            f"{client.redact(response.error_message())[:200]}",
        }
    body = response.body
    stdout = str(body.get("stdout", ""))
    return {
        "available": True,
        "exit_code": body.get("exit_code"),
        "marker_present": marker in stdout,
        "stdout": stdout[:120],
    }


def _report(bench: Bench, args: Any, samples: list[dict[str, Any]]) -> dict[str, Any]:
    def _values(key: str, field: str = "seconds") -> list[float]:
        collected = []
        for sample in samples:
            step = sample.get(key)
            if isinstance(step, dict) and isinstance(step.get(field), (int, float)):
                collected.append(float(step[field]))
        return collected

    verified = [
        bool((sample.get("restore_contents") or {}).get("marker_present"))
        for sample in samples
        if (sample.get("restore_contents") or {}).get("available")
    ]
    report: dict[str, Any] = {
        "available": True,
        "samples": len(samples),
        "snapshot_kind": args.snapshot_kind,
        "workload": {"image": args.image, "runtime_requested": args.runtime,
                     "resources": {"cpu": args.cpu, "memory_mb": args.memory_mb,
                                   "disk_mb": args.disk_mb}},
        "create_to_running": summarise("create_to_running", _values("create")),
        "first_exec": summarise("first_exec", _values("first_exec")),
        "snapshot": summarise("snapshot", _values("snapshot")),
        "destroy": summarise("destroy", _values("destroy")),
        "workspace_restore": summarise("workspace_restore", _values("restore")),
        "destroy_restored": summarise("destroy_restored", _values("destroy_restored")),
        "per_sample": samples,
    }
    if verified:
        report["restore_correctness"] = {
            "available": True,
            "samples_checked": len(verified),
            "marker_restored": sum(1 for value in verified if value),
            "all_markers_restored": all(verified),
            "note": "each sample writes a unique marker before the snapshot and reads it back "
                    "after the restore, so an empty workspace cannot pass",
        }
    else:
        report["restore_correctness"] = unavailable(
            "restore_correctness", "no sample produced a readable restored workspace"
        )
        bench.limit(
            "the restored workspace could not be read back, so restore latency here is a "
            "machine-boot measurement and not evidence that a workspace was restored"
        )
    if len(samples) < max(1, args.samples):
        report["samples_planned"] = args.samples
        report["samples_completed"] = len(samples)
    return report
