"""A bounded loop, watched for what it leaves behind.

The historical soak in ``benchmarks/SOAK.md`` found the worst leak in the system
by doing nothing clever: create, execute, destroy, repeat, and count what is
still there at the end. This is that loop as tooling, with the bounds written
down rather than remembered.

What it will not do:

* **Run unbounded.** Iterations and a wall-clock budget are both required to be
  explicit, and the concurrency the caller asks for is clamped to what a single
  self-hosted cluster can plausibly serve. Asking for a hundred machines is
  refused, not attempted.
* **Hide a leak.** The final observation is taken *before* any cleanup, and
  cleanup only ever destroys sandboxes this harness created through the sandbox
  API. Machines the platform leaked are reported with their ids.
* **Count a failure as a fast success.** Failures are counted, their reasons
  are histogrammed, and they are excluded from the timing column.

Sequential by default (``--max-parallel 1``). The parallel mode exists to answer
"does concurrency change the leak property", which is a different question from
"is the system fast".
"""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any

from ..harness import Bench, describe_outcomes, run_request, submit_run
from ..stats import histogram, summarise, unavailable

NAME = "soak"
SUMMARY = "bounded repeated runs, watching for accumulated state"
REQUIRES: tuple[str, ...] = ()

#: Above this the soak is refused outright. `scripts/load-soak-test.sh` uses the
#: same ceiling: a benchmark that takes the cluster down has measured the
#: cluster falling over, which is not a number anybody can act on.
HARD_PARALLELISM_CAP = 64


def run(bench: Bench, args: Any) -> dict[str, Any]:
    parallel = max(1, int(args.max_parallel))
    if parallel > HARD_PARALLELISM_CAP:
        return unavailable(
            "soak",
            f"refused: --max-parallel {parallel} is above the cap of {HARD_PARALLELISM_CAP}; "
            "a benchmark that takes the cluster down is not a measurement",
        )
    iterations = max(1, int(args.iterations))
    checkpoint_every = max(1, int(args.checkpoint_every))

    body = run_request(
        image=args.image,
        command=args.command_vector,
        cpu=args.cpu,
        memory_mb=args.memory_mb,
        disk_mb=args.disk_mb,
        network=False,
        runtime=args.runtime,
        timeout_seconds=args.workload_timeout,
        # No retention: a machine kept on purpose is not a leak, and a soak that
        # kept its failures could never see one.
        retention="destroy",
    )

    bench.observe("soak-baseline", full=True)
    started = time.monotonic()
    outcomes: list[dict[str, Any]] = []
    checkpoints: list[dict[str, Any]] = []
    stopped_early: str | None = None

    if parallel == 1:
        for index in range(1, iterations + 1):
            reason = _out_of_time(started, args.max_duration)
            if reason:
                stopped_early = reason
                break
            outcomes.append(submit_run(bench, body, timeout=args.run_timeout))
            if index % checkpoint_every == 0 or index == iterations:
                checkpoints.append(_checkpoint(bench, index, outcomes, elapsed(started)))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool:
            futures = []
            for index in range(1, iterations + 1):
                if _out_of_time(started, args.max_duration):
                    stopped_early = "the wall-clock budget was reached"
                    break
                futures.append(pool.submit(submit_run, bench, body, timeout=args.run_timeout))
                if len(futures) >= parallel:
                    outcomes.append(futures.pop(0).result())
                    checkpoints.append(
                        _checkpoint(bench, len(outcomes), outcomes, elapsed(started))
                    )
            for future in futures:
                outcomes.append(future.result())
        if not stopped_early:
            checkpoints.append(_checkpoint(bench, len(outcomes), outcomes, elapsed(started)))

    final = bench.observe("soak-final", full=True)
    duration = elapsed(started)

    report = describe_outcomes(outcomes)
    report["shape"] = {
        "iterations_requested": iterations,
        "iterations_executed": len(outcomes),
        "parallelism": parallel,
        "mode": "sequential" if parallel == 1 else "bounded parallel",
        "wall_clock_s": duration,
        "stopped_early": stopped_early
        or "no: every requested iteration was executed",
        "checkpoint_every": checkpoint_every,
    }
    report["throughput"] = (
        {
            "available": True,
            "runs_per_minute": round(
                sum(item.get("state") == "succeeded" for item in outcomes) / duration * 60, 3
            ),
            "note": "successful runs per minute of wall clock, including the time spent "
                    "waiting for machines; a queue that refuses work lowers this without "
                    "making the control plane slower",
        }
        if duration
        else unavailable("throughput", "the soak took no measurable time")
    )
    report["checkpoints"] = checkpoints
    report["census_at_end"] = {
        "sandboxes": final.get("sandboxes"),
        "node_capacity": final.get("node_capacity"),
        "containers": final.get("containers"),
        "postgres": final.get("postgres"),
    }
    report["rate_limit_429s"] = bench.client.denials
    report["sandbox_histogram"] = histogram(
        str(item.get("state")) for item in outcomes
    )
    if report.get("succeeded", 0) == 0:
        bench.limit("no soak iteration reached `succeeded`; the failure histogram is the result")
    return report


def elapsed(started: float) -> float:
    return round(time.monotonic() - started, 3)


def _out_of_time(started: float, budget: float) -> str | None:
    if budget <= 0:
        return None
    if time.monotonic() - started >= budget:
        return "the wall-clock budget was reached"
    return None


def _checkpoint(
    bench: Bench, index: int, outcomes: list[dict[str, Any]], duration: float
) -> dict[str, Any]:
    """One cheap observation, mid-loop.

    The cheap pass only: an observation that shells out to Docker and PostgreSQL
    every five iterations would itself become a load generator, and the thing
    being watched is the sandbox census.
    """
    snapshot = bench.observe(f"soak-checkpoint-{index}")
    sandboxes = snapshot.get("sandboxes", {})
    node_capacity = snapshot.get("node_capacity", {})
    states = histogram(str(item.get("state")) for item in outcomes)
    return {
        "at": snapshot.get("at"),
        "iterations": index,
        "wall_clock_s": duration,
        "succeeded": states.get("succeeded", 0),
        "not_succeeded": index - states.get("succeeded", 0),
        "run_states": states,
        "nonterminal_sandboxes": sandboxes.get("nonterminal_count")
        if sandboxes.get("available")
        else unavailable("nonterminal_sandboxes", sandboxes.get("reason", "census unavailable")),
        "available_vcpus": node_capacity.get("available_vcpus")
        if node_capacity.get("available")
        else unavailable("available_vcpus", node_capacity.get("reason", "capacity unavailable")),
        "summarise_run_total": summarise(
            "soak_run_total",
            [item["seconds"] for item in outcomes if item.get("state") == "succeeded"],
        ),
    }
