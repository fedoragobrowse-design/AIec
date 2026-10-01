"""Evals: many runs at once, executed by the control plane.

A batch, a set of repetitions and a matrix are the three routes the CLI and the
Rust client already use -- ``POST /v1/eval/batch``, ``/v1/eval/repetitions`` and
``/v1/eval/matrix`` -- and they are the only way this module runs anything. The
concurrency bound, the scheduling, the attempt handling and the cleanup
guarantees stay where they are; a second scheduler inside an SDK would only be a
second thing to disagree with the control plane about what a run is.

The suite helpers -- :meth:`Evals.run_suite` and :meth:`Evals.compare` -- take a
reviewable suite document and expand it into the matrix document those routes
already take: one cell per task, revision and repetition, each labelled by axis
so it can be argued with afterwards. The expansion is deliberately boring. It
turns ``tasks`` into ``cells`` and changes nothing else, so a suite means the
same thing here as it does to the CLI.

Comparison is a view, not a verdict. :meth:`Evals.compare` reports what the runs
produced -- states, exit codes, validation outcomes, runtimes, diffs, artifacts --
for the baseline and the candidate side by side, and stops there. What "better"
means depends on the metric the caller cares about, and choosing one for them
would invent a conclusion the evidence does not support.
"""

import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence
from urllib.parse import quote, urlencode

from .runs import RETENTIONS, _run_response_timeout

# An evaluation's wait is the sum of each run's, so the queue allowance in
# `_run_response_timeout` -- a bound on how long *one* run can sit queued before
# it starts executing -- is charged once per cell. That is the honest cost: each
# cell is admitted, queued and executed separately, so a cell late in the set
# waits its own turn rather than joining the first cell's queue.

#: The same bound the control plane puts on an evaluation. A client asking for
#: more is refused rather than quietly clamped, so a typo cannot read as a bound.
MAX_PARALLEL = 64

#: Fields that belong to the run request itself rather than to its workload.
#: Named here because ``runs.request_body`` collects anything it does not
#: recognise into the workload, and ``max_attempts`` is not a workload property:
#: dropped in there it would be silently ignored by the control plane.
_RUN_FIELDS = ("max_attempts", "retained_seconds")

#: The axis label every expanded cell carries, so a cell is identifiable from
#: the answer alone.
TASK_AXIS = "task"
REVISION_AXIS = "revision"
REPETITION_AXIS = "repetition"

#: The fields :meth:`Runs.request_body` always writes, which together identify a
#: run request that has already been built. A caller handing one over -- an
#: expanded suite does exactly that -- must not have it built a second time.
_REQUEST_FIELDS = frozenset({"workload", "resources", "retention"})


def _parallelism(value: Any) -> int:
    """The caller's concurrency bound, checked before it becomes machines."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"max_parallel is an integer, got {type(value).__name__}")
    if not 1 <= value <= MAX_PARALLEL:
        raise ValueError(f"max_parallel must be between 1 and {MAX_PARALLEL}")
    return value


def _repetitions(value: Any) -> int:
    """How many times to repeat, which is never zero."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"repetitions is an integer, got {type(value).__name__}")
    if value < 1:
        raise ValueError("repetitions must be at least 1")
    return value


def _attempts(value: Any) -> int:
    """How many fresh machines one cell may try, which is never zero."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"max_attempts is an integer, got {type(value).__name__}")
    if value < 1:
        raise ValueError("max_attempts must be at least 1")
    return value


def _instant(text: Any) -> datetime | None:
    """A timestamp as a moment, or ``None`` when it is missing or unreadable.

    Runs are dated by the control plane, so this only ever reads what the API
    wrote; a value it did not write is reported as unknown rather than guessed.
    """
    if not isinstance(text, str) or not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _duration_ms(run: Mapping[str, Any]) -> int | None:
    """How long a run took, as the record states it."""
    started = _instant(run.get("started_at"))
    completed = _instant(run.get("completed_at"))
    if started is None or completed is None:
        return None
    return max(0, int((completed - started).total_seconds() * 1000))


def _outcome(run: Mapping[str, Any]) -> dict:
    """What one run produced, measured rather than interpreted."""
    results = run.get("results") or {}
    task = results.get("task") or {}
    validations = results.get("validations") or []
    return {
        "run_id": run.get("id"),
        "state": run.get("state"),
        "failure_reason": run.get("failure_reason"),
        "task_exit_code": task.get("exit_code"),
        "validation_exit_codes": [item.get("exit_code") for item in validations],
        "duration_ms": _duration_ms(run),
        "phase_ms": dict(results.get("phase_ms") or {}),
        "changed_files": len(results.get("changed_files") or []),
        "diff_bytes": len((results.get("git_diff") or "").encode()),
        "git_evidence_truncated": bool(results.get("git_evidence_truncated")),
        "output_preview_truncations": sum(
            bool(command.get("output_preview_truncated"))
            for command in [*(results.get("setup") or []), task, *validations]
        ),
        "artifacts": len(results.get("artifacts") or []),
        "retained_sandbox_id": run.get("retained_sandbox_id"),
        "retained_until": run.get("retained_until"),
        "cleanup_failed": results.get("cleanup_failed"),
    }


def _aggregate(outcomes: Sequence[Mapping[str, Any]]) -> dict:
    """Several runs, counted.

    Only counts and measurements: no pass rate dressed up as a score, and no
    percentiles invented from a handful of samples.
    """
    states: dict[str, int] = {}
    for outcome in outcomes:
        state = outcome["state"]
        states[state] = states.get(state, 0) + 1
    durations = sorted(
        outcome["duration_ms"]
        for outcome in outcomes
        if outcome["duration_ms"] is not None
    )
    return {
        "runs": len(outcomes),
        "succeeded": states.get("succeeded", 0),
        "failed": states.get("failed", 0),
        "cancelled": states.get("cancelled", 0),
        "states": dict(sorted(states.items())),
        "task_exit_codes": [outcome["task_exit_code"] for outcome in outcomes],
        "validation_exit_codes": [outcome["validation_exit_codes"] for outcome in outcomes],
        "validations_failed": sum(
            1
            for outcome in outcomes
            if any(code not in (None, 0) for code in outcome["validation_exit_codes"])
        ),
        "duration_ms": (
            {
                "total": sum(durations),
                "min": durations[0],
                "max": durations[-1],
            }
            if durations
            else None
        ),
        "changed_files": sum(outcome["changed_files"] for outcome in outcomes),
        "diff_bytes": sum(outcome["diff_bytes"] for outcome in outcomes),
        "git_evidence_truncations": sum(outcome["git_evidence_truncated"] for outcome in outcomes),
        "output_preview_truncations": sum(outcome["output_preview_truncations"] for outcome in outcomes),
        "artifacts": sum(outcome["artifacts"] for outcome in outcomes),
        "run_ids": [outcome["run_id"] for outcome in outcomes],
    }


@dataclass(frozen=True)
class SuiteTask:
    """One task in a suite: a command against a repository."""

    name: str
    repo_url: str
    command: list[str]
    reference: str | None = None
    validations: list[list[str]] = field(default_factory=list)
    timeout_seconds: int | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "SuiteTask":
        """A task as written in the suite document, checked."""
        if not isinstance(raw, Mapping):
            raise ValueError(f"a suite task is an object, got {type(raw).__name__}")
        name = _required_text(raw.get("name"), "a suite task needs a name")
        repo_url = _required_text(raw.get("repo_url"), f"task {name!r} needs a repo_url")
        command = _argv(raw.get("command"), f"task {name!r}")
        validations = [
            _argv(item, f"a validation of task {name!r}")
            for item in raw.get("validations") or []
        ]
        reference = raw.get("reference")
        if reference is not None and not isinstance(reference, str):
            raise ValueError(f"task {name!r} has a reference that is not a string")
        timeout = raw.get("timeout_seconds")
        if timeout is not None:
            timeout = int(timeout)
            if timeout < 1:
                raise ValueError(f"task {name!r} has a timeout_seconds that is not positive")
        return cls(
            name=name,
            repo_url=repo_url,
            command=command,
            reference=reference or None,
            validations=validations,
            timeout_seconds=timeout,
        )


@dataclass(frozen=True)
class Suite:
    """A reusable evaluation suite: named tasks, in a reviewable document.

    Plain JSON, because a suite has to survive a pull-request review and a
    format nobody can read is a format nobody reviews. It is the same document
    ``aiec eval suite --suite`` takes.
    """

    name: str
    tasks: tuple[SuiteTask, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> "Suite":
        if not isinstance(raw, Mapping):
            raise ValueError(f"a suite is an object, got {type(raw).__name__}")
        name = _required_text(raw.get("name"), "a suite needs a name")
        tasks = raw.get("tasks")
        if not isinstance(tasks, Sequence) or isinstance(tasks, (str, bytes)):
            raise ValueError(f"suite {name!r} has no task list")
        if not tasks:
            raise ValueError(f"suite {name!r} has no tasks")
        parsed = tuple(SuiteTask.from_dict(task) for task in tasks)
        # Two tasks with one name would share an idempotency scope, so the second
        # would be handed the first's run and execute nothing at all.
        seen: set[str] = set()
        for task in parsed:
            if task.name in seen:
                raise ValueError(f"suite {name!r} has two tasks called {task.name!r}")
            seen.add(task.name)
        return cls(name=name, tasks=parsed)

    @classmethod
    def parse(cls, text: str) -> "Suite":
        """A suite from suite-document text."""
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid suite: {error}") from error
        return cls.from_dict(raw)


def _required_text(value: Any, complaint: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(complaint)
    return value


def _argv(value: Any, owner: str) -> list[str]:
    """One command, as an argument vector.

    A string is refused rather than split: a suite document is read by people,
    and a command that means different things to the reader and to the runner is
    worse than one that cannot be written at all. Use ``["pytest", "-q"]``.
    """
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(
            f"the command of {owner} must be a list of arguments, not "
            f"{type(value).__name__}"
        )
    argv = [str(part) for part in value]
    if not argv:
        raise ValueError(f"the command of {owner} is empty")
    return argv


@dataclass(frozen=True)
class Comparison:
    """What a baseline and a candidate each produced.

    ``matrix`` is the control plane's own answer, untouched: every cell, its
    axis and the whole run it produced. ``by_revision`` and ``by_task`` are
    counts and measurements laid over those same runs, never a replacement for
    them, so nothing here can hide a cell that failed.
    """

    suite: str
    baseline: str
    candidate: str
    repetitions: int
    matrix_id: str | None
    max_parallel: int
    matrix: dict
    by_revision: dict
    by_task: list

    @property
    def cells(self) -> list:
        """Every cell, axis and run, in the order the matrix reported them."""
        return self.matrix.get("results") or []

    def runs(self, revision: str) -> list:
        """The runs one revision produced, each kept whole."""
        return [
            cell["run"]
            for cell in self.cells
            if (cell.get("axis") or {}).get(REVISION_AXIS) == revision
        ]

    def success_count(self, revision: str) -> int:
        """How many of a revision's runs succeeded."""
        return self.by_revision.get(revision, {}).get("succeeded", 0)


class Evals:
    """The evaluation surface of the AIec API, exposed as ``af.evals``.

    Every call is tenant-scoped by the control plane from the API key the client
    was built with, so there is nothing here that can name another tenant. Each
    evaluation route needs the sandbox write scope, because each one starts
    machines.
    """

    def __init__(self, client: Any):
        self.client = client

    # -- the three server-side shapes -------------------------------------

    def batch(self, tasks: Sequence[Mapping[str, Any]], max_parallel: int = 2) -> list[dict]:
        """Run a list of workloads, at most ``max_parallel`` machines at a time.

        Each task is a set of keyword arguments for :meth:`Runs.create`, and the
        answer is the runs themselves, one per task in the order they were sent.
        The work, the bound and the scheduling all happen in the control plane.
        """
        limit = _parallelism(max_parallel)
        requests = [self._run_request(dict(task)) for task in tasks]
        if not requests:
            return []
        return self.client._request(
            "POST", "/v1/eval/batch", {"requests": requests, "options": {"max_parallel": limit}},
            timeout=sum(_run_response_timeout(request) for request in requests),
        )

    def repetitions(
        self, repetitions: int = 3, max_parallel: int = 2, **workload: Any
    ) -> list[dict]:
        """Run the same workload several times, each repetition on its own machine.

        Each repetition gets its own idempotency scope in the control plane, so
        the second is never handed the first's run and silently executes nothing:
        an agent that passes twice is not the same as one that passes reliably.
        """
        limit = _parallelism(max_parallel)
        count = _repetitions(repetitions)
        body = {
            "request": self._run_request(dict(workload)),
            "repetitions": count,
            "options": {"max_parallel": limit},
        }
        return self.client._request(
            "POST", "/v1/eval/repetitions", body,
            timeout=count * _run_response_timeout(body["request"]),
        )

    def matrix(self, cells: Sequence[Mapping[str, Any]], max_parallel: int = 2) -> dict:
        """Run a matrix of labelled cells and report every one of them.

        A cell is ``{"axis": {...}, **create arguments}``; the answer is the
        control plane's ``matrix_id``, its bound, and each cell's axis *and* the
        run it produced.
        """
        limit = _parallelism(max_parallel)
        spec = {
            "cells": [self._cell(cell) for cell in cells],
            "options": {"max_parallel": limit},
        }
        return self.client._request(
            "POST", "/v1/eval/matrix", spec,
            timeout=sum(_run_response_timeout(cell["request"]) for cell in spec["cells"]) or 900,
        )

    def matrix_page(
        self, matrix_id: str, limit: int = 50, after: Mapping[str, str] | None = None,
    ) -> dict:
        """Recover one bounded page. Pass the previous response's ``next`` cursor.

        ``successes`` and ``by_axis`` summarize this page, not the whole matrix.
        """
        query = {"limit": limit}
        if after is not None:
            query["after_requested_at"] = after["requested_at"]
            query["after_id"] = after["id"]
        path = f"/v1/eval/matrix/{quote(str(matrix_id), safe='')}?{urlencode(query)}"
        return self.client._request("GET", path)

    # -- suites -----------------------------------------------------------

    def load_suite(self, source: Any) -> Suite:
        """A suite from a JSON file, suite-document text, or a parsed object."""
        return _as_suite(source)

    def run_suite(
        self,
        suite: Any,
        revision: str | None = None,
        repetitions: int = 1,
        max_parallel: int = 2,
        **options: Any,
    ) -> dict:
        """Run a suite once per task and return the matrix the control plane ran.

        ``revision`` replaces the reference each task's repository is checked out
        at, which is how a suite is run against a candidate rather than the ref
        it was written for. The answer is the matrix result, whole.
        """
        parsed = _as_suite(suite)
        limit = _parallelism(max_parallel)
        count = _repetitions(repetitions)
        return self.matrix(
            self._cells(parsed, (revision,), count, _run_options(options)), limit
        )

    def compare(
        self,
        baseline: str,
        candidate: str,
        suite: Any,
        repetitions: int = 3,
        max_parallel: int = 2,
        **options: Any,
    ) -> Comparison:
        """Run a suite twice -- once at the baseline, once at the candidate.

        Every task gets its own machine for each revision and each repetition, so
        a baseline and a candidate are never compared through a shared result,
        and a fluke is visible as the third run that disagreed with the first
        two. The answer measures both sides and picks no winner.
        """
        parsed = _as_suite(suite)
        for label, revision in (("baseline", baseline), ("candidate", candidate)):
            _required_text(revision, f"the {label} is a git revision, as a string")
        if baseline == candidate:
            # Two cells that differ only in a label they share would share an
            # idempotency scope too, so the second would be handed the first's
            # run and nothing would be executed for it.
            raise ValueError(
                "baseline and candidate are the same revision, so there is nothing to compare"
            )
        limit = _parallelism(max_parallel)
        count = _repetitions(repetitions)
        result = self.matrix(
            self._cells(parsed, (baseline, candidate), count, _run_options(options)), limit
        )
        return _comparison(parsed.name, baseline, candidate, count, limit, result)

    # -- expansion --------------------------------------------------------

    def _cells(
        self,
        suite: Suite,
        revisions: Sequence[str | None],
        repetitions: int,
        options: Mapping[str, Any],
    ) -> list[dict]:
        """One cell per task, revision and repetition, in that order."""
        cells: list[dict] = []
        for task in suite.tasks:
            for revision in revisions:
                for index in range(repetitions):
                    axis = {TASK_AXIS: task.name, REPETITION_AXIS: str(index)}
                    if revision is not None:
                        axis[REVISION_AXIS] = revision
                    cells.append({"axis": axis, "request": self._task_request(task, revision, index, options)})
        return cells

    def _task_request(
        self,
        task: SuiteTask,
        revision: str | None,
        repetition: int,
        options: Mapping[str, Any],
    ) -> dict:
        """The run request for one expanded cell.

        The repository and the revision under test come from the suite and the
        comparison, never from a per-cell default, because a cell that quietly
        checked out the wrong ref would be evidence of nothing.
        """
        kwargs: dict[str, Any] = dict(options)
        key = kwargs.pop("idempotency_key", None)
        attempts = kwargs.pop("max_attempts", None)
        retained = kwargs.pop("retained_seconds", None)
        if key is not None:
            # A network retry must not quietly double the machines. With a
            # caller-stated key every cell's scope is derivable, so the retry
            # returns the runs that already exist instead of starting new ones.
            kwargs["idempotency_key"] = "-".join(
                (
                    str(key),
                    revision or task.reference or "head",
                    task.name,
                    str(repetition),
                )
            )
        timeout = kwargs.pop("timeout_seconds", None)
        if timeout is None:
            timeout = task.timeout_seconds
        body = self.client.runs.request_body(
            command=list(task.command),
            validations=[list(item) for item in task.validations] or None,
            repo=task.repo_url,
            ref=revision if revision is not None else task.reference,
            timeout_seconds=timeout,
            **kwargs,
        )
        # Lifted out of the workload above: these are properties of the run, and
        # a workload field of the same name is one the control plane ignores.
        if attempts is not None:
            body["max_attempts"] = _attempts(attempts)
        if retained is not None:
            body["retained_seconds"] = int(retained)
        return body

    def _cell(self, cell: Mapping[str, Any]) -> dict:
        """One caller's matrix cell, in the shape the route takes.

        A cell may state its run as ``create`` arguments, as a request it
        already built, or under ``request``. All three exist in practice --
        an expanded suite produces built requests -- and only one of them may
        be rebuilt, so each is routed to :meth:`_run_request` rather than
        interpreted here.
        """
        if not isinstance(cell, Mapping):
            raise ValueError(f"a matrix cell is an object, got {type(cell).__name__}")
        axis = _axis(cell.get("axis"))
        if "request" in cell:
            return {"axis": axis, "request": self._run_request({"request": cell["request"]})}
        body = {key: value for key, value in cell.items() if key != "axis"}
        return {"axis": axis, "request": self._run_request(body)}

    def _run_request(self, task: dict) -> dict:
        """A run request, in the one spelling both surfaces use.

        Both inputs are accepted, because both exist: ``create`` arguments are
        what a caller writes by hand, and a built request is what an expanded
        suite produces. A built request is passed through untouched, since
        building it a second time would bury it inside a workload -- where the
        control plane ignores it and the caller is left with runs that quietly
        did something else.

        ``max_attempts`` and ``retained_seconds`` belong to the run rather than
        to its workload, so they are lifted out before the workload is built;
        collected as workload fields they would be silently ignored.
        """
        if "request" in task:
            nested = task["request"]
            if not isinstance(nested, Mapping):
                raise ValueError("a cell's `request` is a run request, as an object")
            return dict(nested)
        if _REQUEST_FIELDS.issubset(task):
            return dict(task)
        overrides = {name: task.pop(name) for name in _RUN_FIELDS if name in task}
        body = self.client.runs.request_body(**task)
        if "max_attempts" in overrides:
            body["max_attempts"] = _attempts(overrides["max_attempts"])
        if "retained_seconds" in overrides:
            body["retained_seconds"] = int(overrides["retained_seconds"])
        return body


def _axis(value: Any) -> dict:
    """A cell's labels, which the control plane stores as strings.

    Numbers are written as strings because that is what a cell is keyed by; a
    list or an object is refused rather than stringified into a label nobody
    would recognise.
    """
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"a cell axis is an object, got {type(value).__name__}")
    labels = {}
    for key, label in value.items():
        if not isinstance(key, str) or not key:
            raise ValueError("a cell axis is keyed by names")
        if isinstance(label, bool) or not isinstance(label, (str, int, float)):
            raise ValueError(
                f"the axis value for {key!r} is a {type(label).__name__}, "
                "which is not a label"
            )
        labels[key] = str(label)
    return labels


def _run_options(options: Mapping[str, Any]) -> dict:
    """Run-level arguments, checked once and applied to every cell.

    A suite with fifty tasks should not discover a bad retention policy on its
    fortieth cell, and stating an option here must not change what a suite
    already says: anything the suite defines wins.
    """
    unknown = set(options) - {
        "image",
        "cpu",
        "memory_mb",
        "disk_mb",
        "requirements",
        "retention",
        "runtime",
        "network",
        "setup",
        "artifacts",
        "git_evidence",
        "timeout_seconds",
        "idempotency_key",
        "max_attempts",
        "retained_seconds",
    }
    if unknown:
        raise TypeError(f"unknown evaluation option(s): {', '.join(sorted(unknown))}")
    prepared: dict[str, Any] = {
        "cpu": int(options.get("cpu", 1)),
        "memory_mb": int(options.get("memory_mb", 1024)),
        "disk_mb": int(options.get("disk_mb", 2048)),
        "requirements": dict(options.get("requirements") or {}),
        "retention": options.get("retention", "destroy"),
        "network": options.get("network", False),
    }
    if prepared["retention"] not in RETENTIONS:
        raise ValueError(f"retention must be one of {', '.join(RETENTIONS)}")
    for name in ("image", "runtime", "setup", "artifacts", "idempotency_key"):
        if options.get(name) is not None:
            prepared[name] = options[name]
    if options.get("git_evidence"):
        prepared["git_evidence"] = True
    if options.get("max_attempts") is not None:
        prepared["max_attempts"] = _attempts(options["max_attempts"])
    if options.get("retained_seconds") is not None:
        prepared["retained_seconds"] = int(options["retained_seconds"])
    timeout = options.get("timeout_seconds")
    if timeout is not None:
        prepared["timeout_seconds"] = int(timeout)
    return prepared


def _as_suite(source: Any) -> Suite:
    """A suite from whatever the caller had to hand.

    A path, suite-document text and an already-parsed object are the three ways
    one exists in practice, and mistaking one for another is the mistake worth
    catching: a path that does not exist says so, and text that is not a suite
    says what was wrong with it.
    """
    if isinstance(source, Suite):
        return source
    if isinstance(source, Mapping):
        return Suite.from_dict(source)
    if not isinstance(source, (str, pathlib.PurePath)):
        raise TypeError(f"a suite is a Suite, an object or a path, got {type(source).__name__}")
    text = str(source)
    if text.lstrip().startswith("{"):
        return Suite.parse(text)
    path = pathlib.Path(text)
    if not path.exists():
        raise ValueError(f"no suite document at {path}")
    return Suite.parse(path.read_text(encoding="utf-8"))


def _comparison(
    suite: str,
    baseline: str,
    candidate: str,
    repetitions: int,
    max_parallel: int,
    result: Mapping[str, Any],
) -> Comparison:
    """Counts and measurements over the matrix, for both revisions."""
    cells = list(result.get("results") or [])

    def labelled(revision: str, task: str | None = None) -> list[dict]:
        selected = []
        for cell in cells:
            axis = cell.get("axis") or {}
            if axis.get(REVISION_AXIS) != revision:
                continue
            if task is not None and axis.get(TASK_AXIS) != task:
                continue
            selected.append(_outcome(cell.get("run") or {}))
        return selected

    revisions = (baseline, candidate)
    return Comparison(
        suite=suite,
        baseline=baseline,
        candidate=candidate,
        repetitions=repetitions,
        matrix_id=result.get("matrix_id"),
        max_parallel=int(result.get("max_parallel", max_parallel)),
        matrix=dict(result),
        by_revision={
            revision: _aggregate(labelled(revision)) for revision in revisions
        },
        by_task=[
            {
                "task": task,
                "revisions": {
                    revision: _aggregate(labelled(revision, task)) for revision in revisions
                },
            }
            for task in dict.fromkeys(
                (cell.get("axis") or {}).get(TASK_AXIS) for cell in cells
            )
        ],
    )
