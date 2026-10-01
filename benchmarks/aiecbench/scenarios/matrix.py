"""The server-side evaluation path: repetitions and matrices, under a bound.

The soak drives the API one run at a time, which measures the control plane
doing a single job well. This scenario measures the other thing the
specification asks about: what happens when a caller hands the control plane
several workloads at once and lets *it* decide how many machines to hold.

It uses the documented evaluation routes - ``/v1/eval/repetitions`` and
``/v1/eval/matrix`` - rather than a client-side loop, because the point is the
server's bounded executor: a batch whose ``max_parallel`` exceeds the cluster's
real capacity should leave the excess queued rather than spawn it, and the only
way to see that is to use the batch.

Two measurements come out of it:

* **repetitions** - one workload, N fresh machines, the same shape the
  specification calls for when it says an agent that passes twice by luck is not
  one that passes reliably. Per-run wall times are summarised, so a flaky agent
  is visible as a distribution rather than an average.
* **matrix** - the same repository at one pinned commit, across two axes (image
  and revision of the workload's command), which is the shape an evaluation
  matrix actually takes. Every cell is reported, including the cells that
  failed: a matrix that silently drops a failed cell reports a better number
  than one that ran it.
"""

from __future__ import annotations

from typing import Any

from ..harness import Bench, describe_outcomes, phase_durations, ref_kind, run_request
from ..stats import histogram, summarise, unavailable

NAME = "matrix"
SUMMARY = "server-side repetitions and matrices under a concurrency bound"
REQUIRES: tuple[str, ...] = ()

#: The API caps a matrix page; a caller asking for more cells than this is not
#: asking for a bigger benchmark, they are asking for a different tool.
MAX_CELLS = 64


def run(bench: Bench, args: Any) -> dict[str, Any]:
    repetitions = max(1, int(args.repetitions))
    cells = _cells(args, repetitions)
    if len(cells) > MAX_CELLS:
        return unavailable(
            "matrix", f"refused: {len(cells)} cells is above the harness cap of {MAX_CELLS}"
        )

    report: dict[str, Any] = {
        "conditions": {
            "repetitions": repetitions,
            "max_parallel": int(args.matrix_parallel),
            "repo": args.repo,
            "ref": args.ref,
            "ref_kind": ref_kind(args.ref or ""),
            "image": args.image,
            "runtime_requested": args.runtime,
            "resources": {"cpu": args.cpu, "memory_mb": args.memory_mb, "disk_mb": args.disk_mb},
            "command": args.command_vector,
        }
    }

    bench.observe("matrix-baseline", full=True)
    if args.repo:
        report["matrix"] = _matrix(bench, args, cells)
    else:
        report["matrix"] = unavailable(
            "matrix", "not run: pass --repo to measure a matrix over a real repository"
        )
    report["repetitions"] = _repetitions(bench, args, repetitions)
    return report


def _cells(args: Any, repetitions: int) -> list[dict[str, Any]]:
    """Two axes over one pinned commit: the workload, and the repetition.

    The matrix is deliberately small and explicit rather than a combinatorial
    sweep - the specification wants to know what a bounded executor does with a
    handful of cells, and a hundred-cell matrix on an eight-slot cluster measures
    the queue.
    """
    cells: list[dict[str, Any]] = []
    for repetition in range(repetitions):
        request = _request(args)
        cells.append(
            {
                "axis": {"repetition": str(repetition), "workload": "baseline"},
                "request": request,
            }
        )
    return cells


def _request(args: Any) -> dict[str, Any]:
    return run_request(
        image=args.image,
        command=args.command_vector,
        cpu=args.cpu,
        memory_mb=args.memory_mb,
        disk_mb=args.disk_mb,
        network=bool(args.repo),
        repo=args.repo,
        ref=args.ref,
        setup=args.setup_vectors,
        validations=args.validation_vectors,
        artifacts=args.artifacts,
        timeout_seconds=args.workload_timeout,
        git_evidence=bool(args.repo),
        runtime=args.runtime,
        retention="destroy",
    )


def _repetitions(bench: Bench, args: Any, repetitions: int) -> dict[str, Any]:
    """One workload, N fresh machines, through ``/v1/eval/repetitions``."""
    body = {"request": _request(args), "repetitions": repetitions,
            "options": {"max_parallel": int(args.matrix_parallel)}}
    response = bench.client.request("POST", "/v1/eval/repetitions", body,
                                    timeout=args.run_timeout)
    if not response.ok or not isinstance(response.body, list):
        return unavailable(
            "repetitions",
            f"POST /v1/eval/repetitions returned {response.status} "
            f"({response.error_code()}): {bench.client.redact(response.error_message())[:200]}",
        )
    runs = [item for item in response.body if isinstance(item, dict)]
    for run in runs:
        _note_leak(bench, run)
    return {
        "available": True,
        "endpoint": "POST /v1/eval/repetitions",
        "requested": repetitions,
        "returned": len(runs),
        "cell_seconds": summarise(
            "repetition_wall_time",
            [
                seconds
                for seconds in (_wall_time(run) for run in runs)
                if seconds is not None
            ],
        ),
        "outcomes": describe_outcomes([{"run": run, "state": run.get("state", "unknown"),
                                        "seconds": _wall_time(run)}
                                       for run in runs]),
    }


def _matrix(bench: Bench, args: Any, cells: list[dict[str, Any]]) -> dict[str, Any]:
    """A matrix over one repository, through ``/v1/eval/matrix``."""
    body = {"cells": cells, "options": {"max_parallel": int(args.matrix_parallel)}}
    response = bench.client.request("POST", "/v1/eval/matrix", body, timeout=args.run_timeout)
    if not response.ok or not isinstance(response.body, dict):
        return unavailable(
            "matrix",
            f"POST /v1/eval/matrix returned {response.status} ({response.error_code()}): "
            f"{bench.client.redact(response.error_message())[:200]}",
        )
    result = response.body
    results = [item for item in result.get("results") or [] if isinstance(item, dict)]
    for cell in results:
        _note_leak(bench, cell.get("run") or {})

    states = histogram(str((cell.get("run") or {}).get("state", "unknown")) for cell in results)
    wall_times = [
        seconds
        for seconds in (_wall_time(cell.get("run") or {}) for cell in results)
        if seconds is not None
    ]
    setup_phases = [
        value
        for cell in results
        for phase, value in phase_durations(cell.get("run") or {}).items()
        if phase == "setup"
    ]
    block: dict[str, Any] = {
        "available": True,
        "endpoint": "POST /v1/eval/matrix",
        "matrix_id": result.get("matrix_id"),
        "cells_requested": len(cells),
        "cells_returned": len(results),
        # A cell that vanished is a cell nobody measured. The count is reported
        # so a matrix cannot look better by dropping its failures.
        "cells_missing": len(cells) - len(results),
        "max_parallel_used": result.get("max_parallel"),
        "states": states,
        "cell_wall_time": summarise("matrix_cell_wall_time", wall_times),
    }
    if setup_phases:
        block["phase_setup"] = summarise("phase_setup", setup_phases)
    block["cells"] = [
        {
            "axis": cell.get("axis"),
            "run_id": str((cell.get("run") or {}).get("id", "")),
            "state": (cell.get("run") or {}).get("state"),
            "failure_reason": (cell.get("run") or {}).get("failure_reason"),
            "commit": ((cell.get("run") or {}).get("results") or {}).get("commit"),
        }
        for cell in results
    ]
    commits = {entry["commit"] for entry in block["cells"] if entry["commit"]}
    if commits:
        block["commits_observed"] = sorted(commits)
        block["commit_consistent"] = len(commits) == 1
    return block


def _wall_time(run: dict[str, Any]) -> float | None:
    from ..harness import elapsed_seconds

    return elapsed_seconds(run.get("completed_at"), run.get("requested_at"))


def _note_leak(bench: Bench, run: dict[str, Any]) -> None:
    """Record a cell whose machine outlived it, exactly as for a single run."""
    cleanup = (run.get("results") or {}).get("cleanup_failed")
    if isinstance(cleanup, dict):
        bench.note_leak(
            str(run.get("id", "")),
            str(cleanup.get("sandbox_id", "")),
            str(cleanup.get("error", "cleanup failed")),
        )
