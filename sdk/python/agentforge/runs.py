"""Runs: durable work, driven through the control plane.

A run is one piece of work with its own identity, history and results. The
control plane owns it: the API reserves the record, places a machine, runs the
command, collects the artifacts and destroys the machine before it answers, so
``create`` returns the settled run rather than a promise to look one up later.

The three workflow helpers here -- ``run_batch``, ``run_repetitions`` and
``run_matrix`` -- are client-side. The control plane's own batch, repetition and
matrix machinery exists and is not exposed over HTTP yet, so these issue bounded
concurrent ``create`` calls against ``POST /v1/runs`` instead. They are bounded
on purpose: asking for fifty simultaneous machines must not be a way to take the
whole cluster, so the limit is the caller's and it is enforced here.
"""

import shlex
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable, Sequence
from urllib.parse import urlencode

#: Where a repository clone lands. Fixed by the control plane rather than
#: caller-chosen, so a workload cannot point a clone at a path that shadows the
#: agent's own tooling.
REPO_PATH = "/workspace/repository"

#: What happens to the machine when the run ends. ``destroy`` is the default
#: because a machine nobody is looking at is just capacity nobody is using.
RETENTIONS = ("destroy", "keep_on_failure", "keep_always")

#: The page size the control plane uses when a caller states none.
DEFAULT_LIST_LIMIT = 50

#: The same bound the control plane puts on a client-side batch.
MAX_BATCH_PARALLEL = 64


def _command(value: Any) -> list[str]:
    """One command as an argument vector.

    A string is split with shell quoting rules rather than handed over whole, so
    ``"pytest -q"`` and ``["pytest", "-q"]`` are the same command. The result
    is still a vector, never a string the sandbox has to re-parse, so a task
    cannot become a command injection by being quoted oddly.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, (list, tuple)):
        return [str(part) for part in value]
    raise TypeError(f"a command is a string or a list of arguments, got {type(value).__name__}")


def _commands(value: Any) -> list[list[str]]:
    """Several commands, each an argument vector.

    A bare string is one command; a list of strings is several; a list of lists
    is several commands already split.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [shlex.split(value)]
    if isinstance(value, (list, tuple)):
        return [_command(item) for item in value]
    raise TypeError(f"expected a command or a list of commands, got {type(value).__name__}")


def _network_policy(network: Any) -> dict:
    """The network policy, in the shape the API deserialises.

    A run that asks for isolation must not be handed a machine with a wider
    network than it expects, so this is a one-way statement: ``True`` means
    general outbound access, a list of host names means those hosts only, and
    anything else has to be spelled out as a policy.
    """
    if isinstance(network, bool):
        return {"enabled": network}
    if isinstance(network, str):
        named = network.strip().lower()
        if named in ("internet", "enabled", "on", "true"):
            return {"enabled": True}
        if named in ("disabled", "none", "off", "false"):
            return {"enabled": False}
        raise ValueError(
            f"unknown network policy `{network}`; use True, False or a list of allowed hosts"
        )
    if isinstance(network, (list, tuple)):
        return {"enabled": True, "allowed_hosts": [str(host) for host in network]}
    if isinstance(network, dict):
        return dict(network)
    raise TypeError(
        f"a network policy is a bool, a list of hosts or a dict, got {type(network).__name__}"
    )


def _repo(repo: Any, ref: str | None) -> dict | None:
    """The repository a run starts from."""
    if repo is None:
        return None
    if isinstance(repo, str):
        spec: dict = {"url": repo}
    elif isinstance(repo, dict):
        spec = dict(repo)
    else:
        raise TypeError("repo is a git URL or a dict describing one")
    if ref is not None:
        spec.setdefault("reference", ref)
    spec.setdefault("path", REPO_PATH)
    return spec


def _bounded(max_parallel: int) -> int:
    """Checks the caller's concurrency bound before it becomes fifty machines."""
    if isinstance(max_parallel, bool) or not isinstance(max_parallel, int):
        raise TypeError("max_parallel is an integer")
    if max_parallel < 1 or max_parallel > MAX_BATCH_PARALLEL:
        raise ValueError(f"max_parallel must be between 1 and {MAX_BATCH_PARALLEL}")
    return max_parallel


def _error_text(error: BaseException) -> str:
    """A failure as text a caller can log.

    A batch reports the runs it managed to start, so a cell that could not be
    submitted carries its reason instead of taking the whole batch down.
    """
    return f"{type(error).__name__}: {error}"


class Runs:
    """The run surface of the AIec API, exposed as ``af.runs``.

    Every call is tenant-scoped by the control plane from the API key the
    client was built with, so there is nothing here that can name another
    tenant.
    """

    def __init__(self, client: Any):
        self.client = client

    # -- one run ---------------------------------------------------------

    def create(
        self,
        workload: dict | None = None,
        image: str | None = None,
        repo: Any = None,
        ref: str | None = None,
        command: Any = None,
        validations: Any = None,
        setup: Any = None,
        artifacts: Any = None,
        cpu: int = 1,
        memory_mb: int = 1024,
        disk_mb: int = 2048,
        timeout_seconds: int | None = None,
        requirements: dict | None = None,
        retention: str = "destroy",
        network: Any = False,
        runtime: str | None = None,
        idempotency_key: str | None = None,
        parent_run_id: str | None = None,
        matrix_id: str | None = None,
        **extra: Any,
    ) -> dict:
        """Start a run and return it settled.

        The arguments are the ones a caller usually reaches for, and anything
        else the workload accepts arrives in ``**extra`` -- ``secrets``,
        ``environment``, ``git_evidence``, and whatever the API adds next. A
        failure *inside* the run is reported on the returned document
        (``state``/``failure_reason``) rather than raised, because "the work
        failed" is an outcome the caller asked for.
        """
        body = self.request_body(
            workload=workload,
            image=image,
            repo=repo,
            ref=ref,
            command=command,
            validations=validations,
            setup=setup,
            artifacts=artifacts,
            cpu=cpu,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            timeout_seconds=timeout_seconds,
            requirements=requirements,
            retention=retention,
            network=network,
            runtime=runtime,
            idempotency_key=idempotency_key,
            parent_run_id=parent_run_id,
            matrix_id=matrix_id,
            **extra,
        )
        return self.client._request("POST", "/v1/runs", body)

    def request_body(
        self,
        workload: dict | None = None,
        image: str | None = None,
        repo: Any = None,
        ref: str | None = None,
        command: Any = None,
        validations: Any = None,
        setup: Any = None,
        artifacts: Any = None,
        cpu: int = 1,
        memory_mb: int = 1024,
        disk_mb: int = 2048,
        timeout_seconds: int | None = None,
        requirements: dict | None = None,
        retention: str = "destroy",
        network: Any = False,
        runtime: str | None = None,
        idempotency_key: str | None = None,
        parent_run_id: str | None = None,
        matrix_id: str | None = None,
        **extra: Any,
    ) -> dict:
        """The request body ``create`` would send, without sending it.

        Exposed because a batch, a matrix, and a caller writing their own client
        all have to say the same thing, and a second spelling of this document
        is how a client and a control plane drift apart.
        """
        if retention not in RETENTIONS:
            raise ValueError(f"retention must be one of {', '.join(RETENTIONS)}")

        spec: dict = dict(workload or {})
        if image is not None:
            spec["image"] = image
        repository = _repo(repo, ref)
        if repository is not None:
            spec["repo"] = repository
        if command is not None:
            spec["command"] = _command(command)
        if setup is not None:
            spec["setup"] = _commands(setup)
        if validations is not None:
            spec["validations"] = _commands(validations)
        if artifacts is not None:
            if isinstance(artifacts, str):
                spec["artifacts"] = [artifacts]
            else:
                spec["artifacts"] = [str(path) for path in artifacts]
        if timeout_seconds is not None:
            spec["timeout_seconds"] = int(timeout_seconds)
        # Workload fields the convenience arguments do not name, so a caller is
        # never blocked on this SDK growing a new keyword.
        spec.update(extra)

        body: dict = {
            "workload": spec,
            "resources": {
                "cpu": int(cpu),
                "memory_mb": int(memory_mb),
                "disk_mb": int(disk_mb),
                "network": _network_policy(network),
            },
            "requirements": dict(requirements or {}),
            "retention": retention,
        }
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        if runtime is not None:
            body["requested_runtime"] = runtime
        if parent_run_id is not None:
            body["parent_run_id"] = parent_run_id
        if matrix_id is not None:
            body["matrix_id"] = matrix_id
        return body

    # -- reading runs ---------------------------------------------------

    def list(self, state: str | None = None, limit: int = DEFAULT_LIST_LIMIT) -> list:
        """The caller's runs, newest first."""
        query: dict[str, Any] = {"limit": int(limit)}
        if state is not None:
            query["state"] = state
        return self.client._request("GET", f"/v1/runs?{urlencode(query)}")

    def get(self, run_id: str) -> dict:
        """One run's authoritative document."""
        return self.client._request("GET", f"/v1/runs/{run_id}")

    def events(self, run_id: str) -> list:
        """A run's history, in the order it happened."""
        return self.client._request("GET", f"/v1/runs/{run_id}/events")

    def artifacts(self, run_id: str) -> list:
        """The artifacts a run collected, each with a ``download_url``."""
        return self.client._request("GET", f"/v1/runs/{run_id}/artifacts")

    def cancel(self, run_id: str) -> dict:
        """Stop a run and reclaim the machine it was holding.

        Cancelling a run that already finished is a success, not a failure: the
        caller's intent is already true, and a second cancel must not look like a
        mistake.
        """
        return self.client._request("POST", f"/v1/runs/{run_id}/cancel")

    # -- workflows ------------------------------------------------------

    def run_batch(self, tasks: Sequence[dict], max_parallel: int = 2) -> list[dict]:
        """Run several workloads, at most ``max_parallel`` at a time.

        Each task is a set of keyword arguments for :meth:`create`, and the
        result is one entry per task in submission order::

            [{"run": {...}, "error": None}, {"run": None, "error": "..."}]

        A task that could not be submitted is reported rather than raised, so
        one cell failing to schedule does not abandon the others -- that is the
        point of a batch. Client-side, because the control plane does not expose
        its batch route yet; the bound is still real.
        """
        return self._gather(tasks, _bounded(max_parallel))

    def run_repetitions(
        self, repetitions: int = 3, max_parallel: int = 2, **workload: Any
    ) -> list[dict]:
        """Run the same workload several times, each as its own run.

        Each repetition gets its own idempotency scope, so the second is never
        handed the first's run and silently executes nothing: an agent that
        passes twice is not the same as one that passes reliably.
        """
        limit = _bounded(max_parallel)
        if not isinstance(repetitions, int) or isinstance(repetitions, bool):
            raise TypeError("repetitions is an integer")
        if repetitions < 0:
            raise ValueError("repetitions cannot be negative")
        base_key = workload.get("idempotency_key")
        tasks = []
        for index in range(repetitions):
            task = dict(workload)
            if base_key is not None:
                task["idempotency_key"] = f"{base_key}-{index}"
            tasks.append(task)
        return self._gather(tasks, limit)

    def run_matrix(self, cells: Sequence[dict], max_parallel: int = 2) -> dict:
        """Run a matrix of cells, each with its own axes.

        A cell is ``{"axis": {"name": "a"}, ...create arguments}``. Every cell
        is given the same ``matrix_id`` and its own idempotency key, so the set
        is addressable as a group and running the same matrix again returns the
        runs that already exist instead of doing the work twice.

        The summary reports how many cells succeeded and breaks that down per
        axis value. It never says which cell was better, because what "better"
        means depends on the metric the caller cares about.
        """
        limit = _bounded(max_parallel)
        matrix_id = str(uuid.uuid4())
        tasks = []
        axes: list[dict] = []
        for index, cell in enumerate(cells):
            axes.append(dict(cell.get("axis") or {}))
            task = {key: value for key, value in cell.items() if key != "axis"}
            task["matrix_id"] = matrix_id
            task.setdefault("idempotency_key", f"matrix-{matrix_id}-{index}")
            tasks.append(task)

        results = self._gather(tasks, limit)
        by_axis: dict[str, list[int]] = {}
        successes = 0
        for axis, result in zip(axes, results):
            run = result["run"]
            succeeded = run is not None and run.get("state") == "succeeded"
            successes += int(succeeded)
            for key, value in axis.items():
                tally = by_axis.setdefault(f"{key}={value}", [0, 0])
                tally[0] += int(succeeded)
                tally[1] += 1

        return {
            "matrix_id": matrix_id,
            "max_parallel": limit,
            "results": [
                {"axis": axis, **result} for axis, result in zip(axes, results)
            ],
            "summary": {
                "cells": len(results),
                "successes": successes,
                "by_axis": {
                    key: {"successes": tally[0], "cells": tally[1]}
                    for key, tally in by_axis.items()
                },
            },
        }

    def _gather(self, tasks: Iterable[dict], limit: int) -> list[dict]:
        """Runs every task with bounded concurrency, in submission order."""
        pending = list(tasks)
        if not pending:
            return []
        with ThreadPoolExecutor(max_workers=min(limit, len(pending))) as pool:
            return list(pool.map(self._submit, pending))

    def _submit(self, task: dict) -> dict:
        try:
            return {"run": self.create(**task), "error": None}
        except Exception as error:  # noqa: BLE001 - reported to the caller, not hidden
            return {"run": None, "error": _error_text(error)}
