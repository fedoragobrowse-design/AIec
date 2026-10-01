"""How long the control plane takes to answer, with no work in the answer.

Read-only endpoints, so this can be run against a busy cluster without changing
anything. It is the cheapest way to see whether a latency change came from the
control plane or from the machines: if ``list_runs`` did not move and
``run_total`` did, the difference is a machine, not a database.

A 403 is a result, not a failure of the benchmark. A read-only key cannot call
every route, and the harness reports the refusal with its code instead of
quietly dropping the metric.
"""

from __future__ import annotations

from typing import Any

from ..client import TransportError
from ..harness import Bench
from ..stats import histogram, summarise, unavailable

NAME = "control-plane"
SUMMARY = "request latency for the endpoints that touch the database"
REQUIRES: tuple[str, ...] = ()

#: (metric, method, path). Every path is a documented route in docs/API.md.
ENDPOINTS: tuple[tuple[str, str, str], ...] = (
    ("health", "GET", "/health"),
    ("ready", "GET", "/ready"),
    ("list_sandboxes", "GET", "/v1/sandboxes"),
    ("list_runs", "GET", "/v1/runs?limit=20"),
    ("list_queued_runs", "GET", "/v1/runs?state=queued&limit=100"),
    ("current_account", "GET", "/v1/account"),
    ("usage", "GET", "/v1/usage"),
)


def run(bench: Bench, args: Any) -> dict[str, Any]:
    """Time each read endpoint ``--samples`` times.

    Every HTTP attempt is counted, not only the one the caller ended up with.
    The client retries 502/503/504 on an idempotent method, so a read answered
    ``503, 503, 200`` is one 200 to the caller and two refusals to the
    cluster. Reporting only the final status would let a control plane
    refusing two thirds of its reads print a healthy p50.
    """
    report: dict[str, Any] = {"endpoints": []}
    for label, method, path in ENDPOINTS:
        timings: list[float] = []
        statuses: list[int] = []
        retried: list[int] = []
        attempts: list[int] = []
        codes: list[str] = []
        transport: list[str] = []
        retried_samples = 0
        for _ in range(max(1, args.samples)):
            try:
                response = bench.client.request(method, path, timeout=30)
            except TransportError as error:
                transport.append(bench.client.redact(str(error)))
                continue
            attempts.append(response.attempts)
            retried.extend(response.retried_statuses)
            if response.retried_statuses:
                retried_samples += 1
            statuses.append(response.status)
            if response.status >= 400:
                codes.append(f"{response.status}/{response.error_code()}")
                continue
            timings.append(response.seconds)

        entry: dict[str, Any] = {
            "endpoint": label,
            "path": path,
            "samples": len(statuses) + len(transport),
            # Every request that left the harness, retries included.
            "requests": sum(attempts) + len(transport),
            "statuses": histogram(statuses) if statuses else {},
        }
        if attempts:
            entry["attempts_per_sample"] = summarise(
                f"{label}_attempts", attempts, unit="count"
            )
            entry["samples_that_retried"] = retried_samples
        if retried:
            entry["retried_away_statuses"] = histogram(retried)
        if timings:
            entry["latency"] = summarise(label, timings, note=_retry_note(retried_samples))
        else:
            entry["latency"] = unavailable(
                label,
                _reason(codes, transport) or "no successful response was observed",
            )
        if codes:
            entry["refusals"] = histogram(codes)
        report["endpoints"].append(entry)
    return report


def _retry_note(retried_samples: int) -> str | None:
    """Say that the latency sample is the last attempt, not the whole call."""
    if not retried_samples:
        return None
    return (
        f"{retried_samples} of the samples above needed a retry; the latency is "
        f"the final attempt only, so read it with attempts_per_sample and "
        f"retried_away_statuses"
    )


def _reason(codes: list[str], transport: list[str]) -> str:
    """Why there is no latency sample: a transport failure, or a refusal."""
    if transport:
        return f"transport failure: {transport[0]}"
    if codes:
        return f"every request was refused: {codes[0]}"
    return ""
