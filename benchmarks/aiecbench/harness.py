"""Shared state for a benchmark run, and the shapes every scenario measures.

One :class:`Bench` per invocation holds the client, the sandboxes the harness
itself created, the observations it took, and the limitations it knows about. It
also owns the rule that keeps a benchmark honest:

**Cleanup happens after the last observation, and never before.** A harness that
tidies up as it goes cannot see what the platform leaked, and a harness that

tidies up silently has destroyed its own evidence. So the sequence is: measure,
observe, then destroy only what this harness created - and report anything it
could not destroy.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
from typing import Any

from . import observe
from .client import Client, TransportError
from .stats import histogram, summarise, unavailable

#: ``results.phase_ms`` is a map of phase name to milliseconds. Every entry the
#: current control plane writes there is a duration - ``placement``,
#: ``placement.*``, ``setup``, ``task``, ``validation``, ``collection`` and
#: ``cleanup`` - so this set excludes nothing today. It is kept defensively: a
#: count-valued key in a map of durations would be summed as milliseconds and
#: add the count to every run's measured time, and that is a mistake worth
#: being immune to before a phase that needs it exists.
COUNT_PHASE_KEYS = frozenset({"attempts"})

#: The states :func:`submit_run` records for a request the control plane never
#: began executing. Classification is on the state that is actually written
#: rather than on a boolean flag, so a refusal and a task failure cannot be
#: confused for one another.
REJECTION_STATES = frozenset({"rejected", "transport_error"})

#: How long a failure reason may be before it is clipped into a histogram.
FAILURE_CLIP = 200


def _is_duration(value: Any) -> bool:
    """Whether this is a real measured number rather than a missing one.

    A run that succeeded but recorded no usable timestamp is still a success;
    it is left out of every time sum rather than contributing a fabricated
    zero, because a zero in a latency column is a claim nobody measured.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_timestamp(value: Any) -> _datetime.datetime | None:
    """An RFC 3339 timestamp, or ``None`` when the field is absent.

    ``Z`` is spelled out rather than left to ``fromisoformat``: the run document
    is produced by chrono and says ``Z``, and a timestamp that silently fails to
    parse would turn queue-wait time into a missing metric.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = _datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
    return parsed


def elapsed_seconds(later: Any, earlier: Any) -> float | None:
    """``later - earlier`` in seconds, or ``None`` if either is missing."""
    start, end = parse_timestamp(earlier), parse_timestamp(later)
    if start is None or end is None:
        return None
    return round((end - start).total_seconds(), 4)


def run_timings(run: dict[str, Any]) -> dict[str, float]:
    """The lifecycle gaps the run document records with real timestamps.

    The specification's phase list starts at admission and ends at cleanup; the
    gaps between the durable timestamps are what is left of it, taken from the
    run's own clock rather than from the harness's.
    """
    timings: dict[str, float] = {}
    for name, later, earlier in (
        ("admission", "queued_at", "requested_at"),
        ("queue_wait", "started_at", "queued_at"),
        ("start_latency", "started_at", "requested_at"),
        ("wall_time", "completed_at", "requested_at"),
    ):
        seconds = elapsed_seconds(run.get(later), run.get(earlier))
        if seconds is not None:
            timings[name] = seconds
    return timings


def phase_durations(run: dict[str, Any]) -> dict[str, float]:
    """The recorded phases, in seconds, with the count-valued entry removed."""
    results = run.get("results") or {}
    raw = results.get("phase_ms") or {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(name): float(value) / 1000.0
        for name, value in raw.items()
        if name not in COUNT_PHASE_KEYS
    }


def phase_counts(run: dict[str, Any]) -> dict[str, int]:
    """The count-valued phase entries, kept separate from the durations."""
    results = run.get("results") or {}
    raw = results.get("phase_ms") or {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(name): int(value)
        for name, value in raw.items()
        if name in COUNT_PHASE_KEYS
    }


def residual_seconds(total: float, phases: dict[str, float]) -> float:
    """What the client waited for that no phase claims.

    Clamped at zero: a phase can straddle the request boundary by a few
    milliseconds, and a negative residual is measurement noise rather than time
    saved. Computed per run and summarised afterwards, because a median of
    differences is not the difference of medians.
    Dotted names are subphases already included in their top-level phase; they
    remain reportable but must not be counted a second time.
    """
    return max(0.0, total - sum(value for name, value in phases.items() if "." not in name))


def failure_reason(run: dict[str, Any]) -> str:
    """Why a run did not succeed, in one clipped line."""
    reason = run.get("failure_reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()[:FAILURE_CLIP]
    return ""


def ref_kind(reference: str) -> str:
    """What sort of git reference this is.

    A commit is immutable and a branch is not, and the difference decides
    whether a repeated-run benchmark is measuring a cache or measuring whatever
    landed on the branch this morning. The harness reports which one it was
    given rather than assuming.
    """
    text = (reference or "").strip()
    if not text:
        return "unset"
    if len(text) == 40 and all(char in "0123456789abcdefABCDEF" for char in text):
        return "commit"
    if text.startswith("refs/"):
        return "ref"
    if text[:1].isdigit():
        return "tag-or-branch"
    return "branch-or-tag"


def run_request(
    *,
    image: str,
    command: list[str],
    cpu: int,
    memory_mb: int,
    disk_mb: int,
    network: bool = False,
    repo: str | None = None,
    ref: str | None = None,
    repo_path: str = "/workspace/repository",
    setup: list[list[str]] | None = None,
    validations: list[list[str]] | None = None,
    artifacts: list[str] | None = None,
    environment: dict[str, str] | None = None,
    secrets: list[str] | None = None,
    timeout_seconds: int | None = None,
    git_evidence: bool = False,
    runtime: str | None = None,
    retention: str = "destroy",
    idempotency_key: str | None = None,
    max_attempts: int | None = None,
) -> dict[str, Any]:
    """A ``POST /v1/runs`` body, in exactly the shape the API deserialises.

    Deliberately the canonical spelling rather than a convenient one: a run
    request that is missing ``resources.network`` means something different from
    one that says it, and the whole point of a reproducible empty run is that
    nothing about it is implicit.
    """
    workload: dict[str, Any] = {"image": image, "command": list(command)}
    if repo:
        workload["repo"] = {"url": repo, "path": repo_path}
        if ref:
            workload["repo"]["reference"] = ref
    if setup:
        workload["setup"] = [list(step) for step in setup]
    if validations:
        workload["validations"] = [list(step) for step in validations]
    if artifacts:
        workload["artifacts"] = list(artifacts)
    if environment:
        workload["environment"] = dict(environment)
    if secrets:
        workload["secrets"] = list(secrets)
    if timeout_seconds is not None:
        workload["timeout_seconds"] = int(timeout_seconds)
    if git_evidence:
        workload["git_evidence"] = True

    body: dict[str, Any] = {
        "workload": workload,
        "resources": {
            "cpu": int(cpu),
            "memory_mb": int(memory_mb),
            "disk_mb": int(disk_mb),
            "network": {"enabled": bool(network)},
        },
        "retention": retention,
    }
    if runtime:
        body["requested_runtime"] = runtime
    if idempotency_key:
        body["idempotency_key"] = idempotency_key
    if max_attempts is not None:
        body["max_attempts"] = int(max_attempts)
    return body


@dataclasses.dataclass
class Bench:
    """One benchmark invocation."""

    client: Client
    label: str
    #: Sandboxes this harness created, and why, so cleanup can be explained.
    owned: dict[str, str] = dataclasses.field(default_factory=dict)
    #: Sandboxes the platform retained past a run it had already finished.
    leaked: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    #: Observations in the order they were taken.
    observations: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    #: Things this run knows it did not measure.
    limitations: list[str] = dataclasses.field(default_factory=list)

    # -- ownership ------------------------------------------------------

    def track(self, sandbox_id: str, why: str) -> None:
        """Take responsibility for a sandbox the harness created."""
        self.owned[sandbox_id] = why

    def release(self, sandbox_id: str) -> None:
        """Stop tracking a sandbox because the harness destroyed it itself."""
        self.owned.pop(sandbox_id, None)

    def note_leak(self, run_id: str, sandbox_id: str, error: str) -> None:
        """Record a machine that outlived the run that owned it."""
        self.leaked.append(
            {"run_id": run_id, "sandbox_id": sandbox_id, "error": error[:FAILURE_CLIP]}
        )

    # -- observations ---------------------------------------------------

    def observe(self, label: str, *, full: bool = False) -> dict[str, Any]:
        """Take one observation pass and keep it in order."""
        snapshot = observe.take(self.client, full=full)
        snapshot["label"] = label
        snapshot["owned_sandboxes_alive"] = sorted(self.owned)
        self.observations.append(snapshot)
        return snapshot

    def limit(self, reason: str) -> None:
        """Record a limitation once, in the order it was discovered."""
        if reason not in self.limitations:
            self.limitations.append(reason)

    # -- cleanup --------------------------------------------------------

    def cleanup_owned(self, *, reclaim_leaked: bool = False) -> dict[str, Any]:
        """Destroy what this harness created, and report what it could not.

        Only sandboxes this harness created are destroyed. Sandboxes the
        *platform* leaked are listed, and destroyed only when the operator asks
        for it explicitly - a leaked machine is evidence, and a benchmark that
        quietly collects its own evidence is not measuring the thing that
        matters.
        """
        destroyed: list[str] = []
        already_gone: list[str] = []
        failed: list[dict[str, Any]] = []
        for sandbox_id, why in sorted(self.owned.items()):
            response = self.client.request("DELETE", f"/v1/sandboxes/{sandbox_id}", timeout=120)
            if response.status == 404:
                # The platform had already reclaimed it. Counted apart from the
                # ones this harness stopped, because "we destroyed it" and "it
                # was gone" are different claims.
                already_gone.append(sandbox_id)
            elif response.ok:
                destroyed.append(sandbox_id)
            else:
                failed.append(
                    {
                        "sandbox_id": sandbox_id,
                        "why": why,
                        "status": response.status,
                        "code": response.error_code(),
                        "message": self.client.redact(response.error_message())[:FAILURE_CLIP],
                    }
                )
        self.owned.clear()

        reclaimed: list[str] = []
        if reclaim_leaked:
            for leak in self.leaked:
                sandbox_id = str(leak.get("sandbox_id", ""))
                if not sandbox_id:
                    continue
                response = self.client.request("DELETE", f"/v1/sandboxes/{sandbox_id}", timeout=120)
                if response.ok or response.status == 404:
                    reclaimed.append(sandbox_id)
        return {
            "owned_at_end": len(destroyed) + len(already_gone) + len(failed),
            "destroyed": len(destroyed),
            "already_gone": len(already_gone),
            "failed": failed,
            "leaked_sandboxes_reported": [leak["sandbox_id"] for leak in self.leaked],
            "leaked_sandboxes_reclaimed": reclaimed,
            "note": (
                "only sandboxes this harness created are destroyed; leaked platform "
                "sandboxes are reported, and reclaimed only with --reclaim-leaked"
            ),
        }

    def leak_report(self) -> dict[str, Any]:
        """The leak evidence, whether or not the census was available."""
        report: dict[str, Any] = {"run_cleanup_failures": self.leaked}
        if len(self.observations) >= 2:
            report["sandbox_census_delta"] = observe.leak_delta(
                self.observations[0], self.observations[-1]
            )
        else:
            report["sandbox_census_delta"] = unavailable(
                "sandbox_census_delta", "fewer than two observations were taken"
            )
        return report


# -- shared measurement helpers --------------------------------------------


def submit_run(bench: Bench, body: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    """Submit one run and describe it, whether it worked or not.

    A transport failure is caught and reported rather than raised: a soak that
    dies on the first timeout has measured one timeout, and the interesting
    question is what the twentieth one did.
    """
    try:
        response = bench.client.request("POST", "/v1/runs", body, timeout=timeout)
    except TransportError as error:
        return {
            "transport_error": bench.client.redact(str(error)),
            "seconds": error.seconds,
            "state": "transport_error",
        }
    if not response.ok or not isinstance(response.body, dict):
        return {
            "http_status": response.status,
            "error_code": response.error_code(),
            "error_message": bench.client.redact(response.error_message())[:FAILURE_CLIP],
            "seconds": response.seconds,
            "state": "rejected",
        }
    run = response.body
    if (run.get("results") or {}).get("cleanup_failed"):
        cleanup = run["results"]["cleanup_failed"]
        bench.note_leak(
            str(run.get("id", "")),
            str(cleanup.get("sandbox_id", "")),
            str(cleanup.get("error", "cleanup failed")),
        )
    return {"run": run, "seconds": response.seconds, "state": str(run.get("state", "unknown"))}


def summarise_states(states: list[str]) -> dict[str, int]:
    return histogram(states)


def describe_outcomes(outcomes: list[dict[str, Any]], *, unit: str = "s") -> dict[str, Any]:
    """Aggregate a list of :func:`submit_run` results.

    Successes and failures are counted separately and never mixed into one
    timing column: a run that did not succeed has phases describing a different
    population from its total, and averaging them together makes the two columns
    disagree about what they are averages of.
    """
    # `timed` and `untimed` split the successes by whether they carry a real
    # duration, so `succeeded` stays a count of outcomes and every time sum
    # stays a sum of measurements.
    timed: list[dict[str, Any]] = []
    untimed = 0
    succeeded: list[dict[str, Any]] = []
    failures: list[str] = []
    phases: dict[str, list[float]] = {}
    residuals: list[float] = []
    timings: dict[str, list[float]] = {}
    rejected: list[dict[str, Any]] = []
    states: list[str] = []
    commits: list[str] = []
    attempt_counts: dict[str, list[int]] = {}

    for outcome in outcomes:
        state = outcome.get("state", "unknown")
        states.append(state)
        if state in REJECTION_STATES or outcome.get("transport_error"):
            rejected.append(
                {
                    "state": state,
                    "http_status": outcome.get("http_status"),
                    "error_code": outcome.get("error_code"),
                    "message": outcome.get("error_message")
                    or outcome.get("transport_error", ""),
                }
            )
            continue
        run = outcome.get("run") or {}
        if state != "succeeded":
            failures.append(failure_reason(run) or state)
            continue
        succeeded.append(outcome)
        if _is_duration(outcome.get("seconds")):
            timed.append(outcome)
        else:
            untimed += 1
        for phase, seconds in phase_durations(run).items():
            phases.setdefault(phase, []).append(seconds)
        if _is_duration(outcome.get("seconds")):
            residuals.append(residual_seconds(float(outcome["seconds"]), phase_durations(run)))
        for name, seconds in run_timings(run).items():
            timings.setdefault(name, []).append(seconds)
        for name, count in phase_counts(run).items():
            # A count-valued entry in a map of durations is reported as a count.
            # No phase the current control plane writes is one, so this is the
            # path that will carry an `attempts` key if a phase ever needs it -
            # and it must not be summed as milliseconds when it does.
            attempt_counts.setdefault(name, []).append(count)
        commit = (run.get("results") or {}).get("commit")
        if isinstance(commit, str) and commit:
            commits.append(commit)

    report: dict[str, Any] = {
        "succeeded": len(succeeded),
        "not_succeeded": len(failures),
        "rejected_before_execution": len(rejected),
        "states": summarise_states(states),
    }
    for name, counts in sorted(attempt_counts.items()):
        report[f"count_{name}"] = {
            "metric": f"count_{name}",
            "available": True,
            "unit": "count",
            "samples": len(counts),
            "max": max(counts),
            "mean": round(sum(counts) / len(counts), 4),
            "histogram": histogram(counts),
        }
    if timed:
        report["run_total"] = summarise("run_total", [item["seconds"] for item in timed],
                                        unit=unit)
        report["residual_unattributed"] = summarise("residual_unattributed", residuals, unit=unit)
        for name, values in sorted(timings.items()):
            report[name] = summarise(name, values, unit=unit)
    else:
        report["run_total"] = unavailable(
            "run_total",
            f"none of the {len(succeeded)} successful runs recorded a duration"
            if succeeded
            else "no run reached `succeeded`",
        )
    if untimed:
        report["succeeded_without_a_measured_duration"] = untimed
    for phase, values in sorted(phases.items()):
        report[f"phase_{phase}"] = summarise(f"phase_{phase}", values, unit=unit)
    if failures:
        report["failure_reasons"] = histogram(failures)
    if rejected:
        report["rejections"] = rejected[:20]
        report["rejections_truncated"] = len(rejected) > 20
    if commits:
        report["commits"] = sorted(set(commits))
        report["commit_consistent"] = len(set(commits)) == 1
    return report
