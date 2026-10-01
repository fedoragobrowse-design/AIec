"""A run that does nothing, measured so the cost of doing it is visible.

The specification's most useful question is "the run took 42 seconds - and 31 of
them were repository setup". This is the baseline that question is asked
against: a real run, on a real machine, whose command is ``true``. Everything in
its wall time is orchestration.

Three things it deliberately does not do:

* **No idempotency key.** Every sample must be a new run, or the second sample
  is the first run's row and the whole measurement is fiction.
* **No averaging failures into the timing.** A run that did not succeed is
  counted separately, with its reason, and excluded from the timing column.
* **No invention where the API is silent.** ``POST /v1/runs`` executes
  synchronously, so run-creation latency and end-to-end wall time are the same
  measurement here; the decomposition comes from the phase timings the run
  records, and the gap between them is reported as a residual rather than
  attributed to a phase nobody measured.
"""

from __future__ import annotations

from typing import Any

from ..harness import (
    Bench,
    describe_outcomes,
    elapsed_seconds,
    run_request,
    submit_run,
)
from ..stats import summarise, unavailable

NAME = "empty-exec"
SUMMARY = "end-to-end run cost and its per-phase breakdown, for a run that does nothing"
REQUIRES: tuple[str, ...] = ()


def run(bench: Bench, args: Any) -> dict[str, Any]:
    body = run_request(
        image=args.image,
        command=args.command_vector,
        cpu=args.cpu,
        memory_mb=args.memory_mb,
        disk_mb=args.disk_mb,
        network=False,
        runtime=args.runtime,
        timeout_seconds=args.workload_timeout,
        retention="destroy",
    )

    before = _request_counter(bench)
    outcomes = [
        submit_run(bench, body, timeout=args.run_timeout) for _ in range(max(1, args.samples))
    ]
    after = _request_counter(bench)

    report = describe_outcomes(outcomes)
    report["workload"] = {
        "image": args.image,
        "command": args.command_vector,
        "runtime_requested": args.runtime,
        "resources": {"cpu": args.cpu, "memory_mb": args.memory_mb, "disk_mb": args.disk_mb},
        "repo": None,
        "validations": [],
        "artifacts": [],
        "retention": "destroy",
    }
    report["first_sample"] = _first_sample(outcomes)
    report["api_request_accounting"] = _api_requests(before, after, len(outcomes))
    report["run_events"] = _event_timings(bench, outcomes, args.event_samples)
    report["rate_limit_429s"] = bench.client.denials
    if report.get("succeeded", 0) == 0:
        bench.limit(
            "no run in this scenario reached `succeeded`, so no timing was reported; "
            "the failure reasons above are the result"
        )
    return report


def _first_sample(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    """The first run on its own.

    The first sample pays for a cold image and a cold cache. Leaving it inside
    the sample is honest but muddies the steady state, so it is reported
    separately rather than dropped.
    """
    if not outcomes:
        return unavailable("first_sample", "no sample was taken")
    outcome = outcomes[0]
    if outcome.get("state") != "succeeded":
        return {"state": outcome.get("state"), "seconds": outcome.get("seconds")}
    return {"state": "succeeded", "seconds": round(outcome["seconds"], 4)}


def _request_counter(bench: Bench) -> float | None:
    """``aiec_api_requests_total``, which is the one control-plane counter the
    API exposes. It counts API requests, not database queries: the number of
    queries a run issues is not observable through the API, and is reported as
    such rather than inferred."""
    response = bench.client.request("GET", "/metrics", timeout=30, text=True)
    if not response.ok or not response.text:
        return None
    for line in response.text.splitlines():
        if line.startswith("aiec_api_requests_total"):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def _api_requests(before: float | None, after: float | None, runs: int) -> dict[str, Any]:
    if before is None or after is None or runs == 0:
        return unavailable(
            "api_requests",
            "GET /metrics exposed no aiec_api_requests_total counter on this control plane",
        )
    delta = after - before
    return {
        "available": True,
        "definition": "aiec_api_requests_total delta, which counts HTTP requests, "
                      "not database queries",
        "before": before,
        "after": after,
        "delta": delta,
        "per_run": round(delta / runs, 3),
    }


def _event_timings(bench: Bench, outcomes: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    """Where a run's own event log says each transition happened.

    Taken from a handful of runs, because it costs one request each. The event
    log is written as the run proceeds, so it is the closest thing to a phase
    trace the API offers without changing the server.
    """
    if limit <= 0:
        return unavailable("run_events", "disabled with --event-samples 0")
    samples: list[dict[str, Any]] = []
    for outcome in outcomes:
        if len(samples) >= limit:
            break
        run = outcome.get("run") or {}
        run_id = run.get("id")
        if not run_id or outcome.get("state") != "succeeded":
            continue
        response = bench.client.request("GET", f"/v1/runs/{run_id}/events", timeout=30)
        if not response.ok or not isinstance(response.body, list):
            continue
        timeline: list[dict[str, Any]] = []
        for event in response.body:
            if not isinstance(event, dict):
                continue
            offset = elapsed_seconds(event.get("occurred_at"), run.get("requested_at"))
            timeline.append(
                {
                    "event_type": str(event.get("event_type", "")),
                    "seconds_after_request": offset,
                }
            )
        if timeline:
            samples.append({"run_id": str(run_id), "timeline": timeline})
    if not samples:
        return unavailable("run_events", "no successful run returned an event log")
    first_events = [
        entry["timeline"][0]["seconds_after_request"]
        for entry in samples
        if entry["timeline"][0]["seconds_after_request"] is not None
    ]
    return {
        "available": True,
        "runs_sampled": len(samples),
        "first_event_after_request": summarise("first_event_after_request", first_events),
        "timelines": samples,
    }
