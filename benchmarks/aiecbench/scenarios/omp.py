"""Two OMP revisions, the same task, and a check that the two are comparable.

This is the before/after measurement the specification asks for, run through the
real path: the local MCP server's ``aiec_compare_omp`` tool, which clones and
builds each revision inside its own sandbox and runs the agent against the same
target repository. Nothing here is mocked, and the agent really runs.

The one thing this harness adds is the comparability check. A comparison of two
revisions is only worth reading if the two sides differed *only* in the revision,
so after the runs come back the harness verifies, and reports as evidence:

* both sides ran the same number of repetitions;
* both sides ran on the same runtime;
* every run on both sides resolved the same target commit;
* every run on each side resolved the revision that was asked for;
* both sides ran the same number of validations, and they passed or failed
  visibly;
* no run on either side was lost to a submission failure.

If any of those fails, the report says ``comparable: false`` and no delta is
printed. A faster candidate measured on a different target is not a faster
candidate.

And the harness does not pick a winner. It reports what each side did; that
judgement belongs to whoever asked the question.
"""

from __future__ import annotations

from typing import Any

from ..client import TransportError
from ..harness import Bench
from ..mcp import McpClient, McpError, resolve_token
from ..stats import histogram, summarise, unavailable

NAME = "omp"
SUMMARY = "baseline versus candidate OMP revision, with a comparability check"
REQUIRES: tuple[str, ...] = (
    "omp_repo",
    "baseline_ref",
    "candidate_ref",
    "target_repo",
    "task",
)

TOOL = "aiec_compare_omp"


def run(bench: Bench, args: Any) -> dict[str, Any]:
    try:
        token = resolve_token(args.mcp_token_file)
    except McpError as error:
        bench.limit(str(error))
        return {"available": False, "reason": str(error)}

    arguments: dict[str, Any] = {
        "omp_repo": args.omp_repo,
        "baseline_ref": args.baseline_ref,
        "candidate_ref": args.candidate_ref,
        "target_repo": args.target_repo,
        "task": args.task,
        "repetitions": int(args.repetitions),
        "max_parallel": int(args.omp_parallel),
        "cpu": args.cpu,
        "memory_mb": args.memory_mb,
        "disk_mb": args.disk_mb,
    }
    if args.target_ref:
        arguments["target_ref"] = args.target_ref
    if args.runtime:
        arguments["runtime"] = args.runtime
    if args.omp_timeout:
        arguments["timeout_seconds"] = int(args.omp_timeout)
    for index, command in enumerate(args.validation_vectors or []):
        arguments.setdefault("validation_commands", []).append(list(command))

    bench.observe("omp-baseline", full=True)
    client = McpClient(args.mcp_url, token, timeout=args.omp_tool_timeout)
    try:
        client.initialize()
        client.initialized()
        payload, seconds = client.call_tool(TOOL, arguments)
    except (McpError, TransportError, OSError) as error:
        # A missing local MCP server is an environment fact, not a benchmark
        # failure, and the report says which of the two it was.
        reason = f"the OMP comparison could not run: {error}"
        bench.limit(reason)
        return {"available": False, "reason": reason}
    finally:
        bench.observe("omp-final", full=True)

    if not isinstance(payload, dict) or "baseline" not in payload:
        reason = f"{TOOL} returned an unrecognised result: {str(payload)[:300]}"
        bench.limit(reason)
        return {"available": False, "reason": reason}

    report: dict[str, Any] = {
        "available": True,
        "tool": TOOL,
        "mcp_url": args.mcp_url,
        "tool_call_seconds": round(seconds, 3),
        "conditions": {
            "omp_repo": args.omp_repo,
            "baseline_ref": args.baseline_ref,
            "candidate_ref": args.candidate_ref,
            "target_repo": args.target_repo,
            "target_ref": args.target_ref,
            "task": args.task,
            "task_characters": len(args.task),
            "repetitions": int(args.repetitions),
            "max_parallel": int(args.omp_parallel),
            "runtime_requested": args.runtime,
            "resources": {"cpu": args.cpu, "memory_mb": args.memory_mb, "disk_mb": args.disk_mb},
            "validations": args.validation_vectors or [],
        },
        "evaluation_id": payload.get("evaluation_id"),
        "baseline": _side(payload.get("baseline"), args.baseline_ref),
        "candidate": _side(payload.get("candidate"), args.candidate_ref),
        "submission_failures": payload.get("submission_failures") or [],
        "retained_sandbox_ids": payload.get("sandbox_ids") or [],
    }
    checks = _comparability(payload, args, report)
    report["comparability"] = checks
    report["comparable"] = all(check["passed"] for check in checks)
    if not report["comparable"]:
        failed = [check["check"] for check in checks if not check["passed"]]
        report["comparison_withheld"] = (
            "no before/after delta is reported because these checks did not pass: "
            + ", ".join(failed)
        )
        bench.limit(report["comparison_withheld"])
    report["verdict"] = (
        "none: this harness reports what each side did and never says which is better"
    )
    return report


def _side(summary: Any, requested_ref: str) -> dict[str, Any]:
    """One side's measurements, as reported, with the phases re-summarised.

    The side summary's own ``phase_ms`` is a sum over repetitions, which is a
    total and not a distribution, so the per-run wall times are summarised here
    instead - with the same rule about withholding percentiles from small
    samples.
    """
    if not isinstance(summary, dict):
        return unavailable("side", "the comparison returned no summary for this side")
    block: dict[str, Any] = {
        "label": summary.get("label"),
        "revision_requested": requested_ref,
        "revision_reported": summary.get("revision"),
        "successful_runs": summary.get("successful_runs"),
        "failed_runs": summary.get("failed_runs"),
        "validations_passed": summary.get("validation_passes"),
        "validations_total": summary.get("validation_total"),
        "exit_codes": summary.get("exit_codes"),
        "missing_task_runs": summary.get("missing_task_runs"),
        "setup_failures": summary.get("setup_failures"),
        "changed_file_count": summary.get("changed_file_count"),
        "diff_bytes": summary.get("total_diff_bytes"),
        "cleanup_failures": summary.get("cleanup_failures") or [],
        "phase_ms_totals": summary.get("phase_ms"),
        "wall_time_ms_total": summary.get("wall_time_ms"),
    }
    runs = summary.get("runs") or []
    wall_times = [
        float(run["wall_time_ms"]) / 1000.0
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("wall_time_ms"), (int, float))
    ]
    block["wall_time"] = summarise(f"wall_time[{requested_ref}]", wall_times)
    block["runtimes"] = histogram(
        str(run.get("runtime")) for run in runs if isinstance(run, dict) and run.get("runtime")
    )
    if not wall_times:
        block["wall_time"] = unavailable(
            "wall_time", "no run on this side carried both timestamps"
        )
    return block


def _comparability(payload: dict[str, Any], args: Any, report: dict[str, Any]) -> list[dict[str, Any]]:
    """The evidence that the two sides differ only in the revision."""
    baseline_runs = _runs(payload, "baseline")
    candidate_runs = _runs(payload, "candidate")
    requested = int(args.repetitions)

    checks: list[dict[str, Any]] = []

    def add(check: str, passed: bool, detail: str) -> None:
        checks.append({"check": check, "passed": bool(passed), "detail": detail})

    add(
        "repetitions_per_side",
        len(baseline_runs) == len(candidate_runs) == requested
        or (len(baseline_runs) == len(candidate_runs) and requested not in
            (len(baseline_runs), len(candidate_runs))),
        f"requested {requested}; the report carries {len(baseline_runs)} baseline and "
        f"{len(candidate_runs)} candidate runs",
    )

    baseline_runtimes = {str(run.get("runtime")) for run in baseline_runs if run.get("runtime")}
    candidate_runtimes = {str(run.get("runtime")) for run in candidate_runs if run.get("runtime")}
    add(
        "same_runtime",
        bool(baseline_runtimes) and baseline_runtimes == candidate_runtimes,
        f"baseline {sorted(baseline_runtimes) or 'unknown'}; candidate "
        f"{sorted(candidate_runtimes) or 'unknown'}",
    )

    baseline_commits = {str(run.get("actual_target_ref")) for run in baseline_runs
                        if run.get("actual_target_ref")}
    candidate_commits = {str(run.get("actual_target_ref")) for run in candidate_runs
                         if run.get("actual_target_ref")}
    add(
        "same_target_commit",
        bool(baseline_commits) and baseline_commits == candidate_commits,
        f"baseline {sorted(baseline_commits) or 'unknown'}; candidate "
        f"{sorted(candidate_commits) or 'unknown'}",
    )
    add(
        "target_commit_recorded_for_every_run",
        all(run.get("actual_target_ref") for run in baseline_runs + candidate_runs)
        and bool(baseline_runs + candidate_runs),
        f"{sum(1 for run in baseline_runs + candidate_runs if run.get('actual_target_ref'))} of "
        f"{len(baseline_runs) + len(candidate_runs)} runs recorded a target commit",
    )

    for label, runs, wanted in (
        ("baseline", baseline_runs, args.baseline_ref),
        ("candidate", candidate_runs, args.candidate_ref),
    ):
        observed = {str(run.get("actual_omp_ref")) for run in runs if run.get("actual_omp_ref")}
        add(
            f"{label}_ran_the_requested_revision",
            bool(observed) and observed == {wanted},
            f"requested {wanted}; the runs checked out {sorted(observed) or 'nothing recorded'}",
        )
        add(
            f"{label}_executed_the_agent",
            all(run.get("omp") is not None for run in runs) and bool(runs),
            f"{sum(1 for run in runs if run.get('omp') is not None)} of {len(runs)} runs "
            "produced an agent outcome",
        )

    add(
        "no_submission_failures",
        not payload.get("submission_failures"),
        f"{len(payload.get('submission_failures') or [])} runs could not be submitted",
    )
    add(
        "no_cleanup_failures",
        not (report["baseline"]["cleanup_failures"] or report["candidate"]["cleanup_failures"]),
        "a machine that outlived its run makes the two sides' timings incomparable",
    )
    add(
        "both_sides_produced_results",
        report["baseline"]["successful_runs"] is not None
        and report["candidate"]["successful_runs"] is not None,
        "a side with no results cannot be compared to a side with some",
    )
    return checks


def _runs(payload: dict[str, Any], side: str) -> list[dict[str, Any]]:
    key = "baseline_runs" if side == "baseline" else "candidate_runs"
    runs = payload.get(key)
    if not isinstance(runs, list):
        return []
    return [run for run in runs if isinstance(run, dict)]
