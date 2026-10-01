"""Contract tests for the evaluation surface, against a fake transport.

No live control plane: the client's `_request` is replaced, so these assert on
the documents the SDK would put on the wire and on the measurements it reports
back -- the two things that silently drift from the API.

The fake answers `/v1/eval/matrix` the way the control plane does, pairing each
cell's axis with the run it produced, because a comparison is only exercised
honestly when it is handed that shape.
"""

import json
import pathlib
import tempfile
import threading
import unittest

from agentforge import AIec, Comparison

SUITE = {
    "name": "nightly",
    "tasks": [
        {
            "name": "unit",
            "repo_url": "https://github.com/example/fixture.git",
            "reference": "main",
            "command": ["pytest", "-q"],
            "validations": [["pytest", "-q", "tests/"]],
            "timeout_seconds": 900,
        },
        {
            "name": "lint",
            "repo_url": "https://github.com/example/fixture.git",
            "command": ["ruff", "check"],
        },
    ],
}

#: How many cells the recovered matrix has, so a page double cannot invent more.
MATRIX_CELLS = 3

#: A run as the API serialises one: settled, with its timestamps and evidence.
RUN_FIELDS = (
    "id",
    "state",
    "failure_reason",
    "started_at",
    "completed_at",
    "retained_sandbox_id",
    "retained_until",
)


def settled_run(
    run_id,
    state="succeeded",
    exit_code=0,
    failure_reason=None,
    started="2026-07-28T12:00:00Z",
    completed="2026-07-28T12:00:42Z",
    validation_exit_codes=(0,),
    changed_files=("src/app.py",),
    git_diff="",
    artifacts=("report.txt",),
    retained_sandbox_id=None,
    retained_until=None,
):
    return {
        "id": run_id,
        "state": state,
        "requested_at": started,
        "started_at": started,
        "completed_at": completed,
        "failure_reason": failure_reason,
        "workload": {"command": ["true"]},
        "results": {
            "task": {"command": ["true"], "exit_code": exit_code, "stdout": "", "stderr": ""},
            "validations": [
                {"command": ["pytest"], "exit_code": code, "stdout": "", "stderr": ""}
                for code in validation_exit_codes
            ],
            "changed_files": list(changed_files),
            "git_diff": git_diff,
            "artifacts": [{"name": name, "object_key": name, "size_bytes": 1} for name in artifacts],
            "phase_ms": {"task": 42000},
        },
        "retained_sandbox_id": retained_sandbox_id,
        "retained_until": retained_until,
    }


class FakeTransport:
    """Records what the SDK asked for and answers with settled runs.

    ``states`` says which state a cell's run settles in, keyed by the cell's
    axis -- ``{("feature-x", "unit", "0"): "failed"}`` -- so a test states an
    outcome in the vocabulary the answer uses rather than in call order.
    """

    def __init__(self, states=None):
        self.calls = []
        self.states = states or {}
        self.lock = threading.Lock()
        self.timeouts = []

    def __call__(self, method, path, payload=None, *, timeout=120):
        with self.lock:
            self.calls.append((method, path, payload))
            self.timeouts.append(timeout)
        if path.startswith("/v1/eval/matrix/") and method == "GET":
            return self.matrix_page(path)
        if path == "/v1/eval/matrix":
            cells = payload["cells"]
            return {
                "matrix_id": "matrix-1",
                "requested_at": "2026-07-28T12:00:00Z",
                "max_parallel": payload["options"]["max_parallel"],
                "results": [self.cell(index, cell) for index, cell in enumerate(cells)],
            }
        if path == "/v1/eval/repetitions":
            return [settled_run(f"run-{index}") for index in range(payload["repetitions"])]
        return [settled_run(f"run-{index}") for index in range(len(payload["requests"]))]

    def matrix_page(self, path):
        """One bounded page, with a continuation cursor a caller can follow."""
        query = dict(part.split("=", 1) for part in path.split("?", 1)[1].split("&"))
        # The page cursor is opaque to a client, so the double follows it the
        # way a caller does: by handing the previous `next` straight back.
        start = int(query["after_id"].rsplit("-", 1)[1]) + 1 if "after_id" in query else 0
        limit = int(query["limit"])
        cells = [
            {
                "run": settled_run(f"run-{index}"),
                "index": index,
                "axis": {"task": f"cell-{index}"},
            }
            for index in range(start, min(start + limit, MATRIX_CELLS))
        ]
        return {
            "matrix_id": "matrix-1",
            "cells": cells,
            "successes": len(cells),
            "by_axis": {"task=cell-0": (1, 1)},
            # The cursor a caller hands back next: the last cell's identity,
            # which is what makes a page boundary resumable rather than a gap.
            "next": (
                {"requested_at": "2026-07-28T12:00:00Z", "id": f"run-{start + len(cells) - 1}"}
                if start + len(cells) < MATRIX_CELLS
                else None
            ),
        }

    def cell(self, index, cell):
        axis = cell["axis"]
        state = self.states.get(
            (axis.get("revision"), axis.get("task"), axis.get("repetition")), "succeeded"
        )
        return {
            "axis": axis,
            "run": settled_run(
                f"run-{index}",
                state=state,
                exit_code=0 if state == "succeeded" else 1,
                failure_reason=None if state == "succeeded" else "task exited 1",
            ),
        }

    def bodies(self):
        return [payload for _method, _path, payload in self.calls if payload is not None]


def client_with(transport):
    client = AIec(api_key="af_live_" + "0" * 48, base_url="http://control.invalid")
    client._request = transport
    return client


class EvalRouteTest(unittest.TestCase):
    """The three server-side shapes, as documents rather than as calls."""

    def setUp(self):
        self.transport = FakeTransport()
        self.evals = client_with(self.transport).evals

    def test_a_batch_is_one_bounded_request_rather_than_one_call_per_task(self):
        runs = self.evals.batch(
            [{"command": ["pytest", "-q"]}, {"command": ["ruff", "check"]}], max_parallel=2
        )

        method, path, body = self.transport.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/eval/batch"))
        self.assertEqual(body["options"], {"max_parallel": 2})
        self.assertEqual(
            [request["workload"]["command"] for request in body["requests"]],
            [["pytest", "-q"], ["ruff", "check"]],
        )
        # The bound is the control plane's to hold here; the SDK's job is to ask
        # for it in one request and keep every run it answers with.
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual([run["id"] for run in runs], ["run-0", "run-1"])

    def test_a_batch_keeps_the_fields_that_belong_to_the_run_out_of_the_workload(self):
        self.evals.batch(
            [{"command": ["true"], "max_attempts": 3, "retention": "keep_on_failure"}]
        )

        request = self.transport.bodies()[0]["requests"][0]
        self.assertEqual(request["max_attempts"], 3)
        self.assertEqual(request["retention"], "keep_on_failure")
        self.assertEqual(set(request["workload"]), {"command"})

    def test_repetitions_ask_for_several_machines_in_one_request(self):
        runs = self.evals.repetitions(repetitions=5, command=["pytest", "-q"])

        _method, path, body = self.transport.calls[0]
        self.assertEqual(path, "/v1/eval/repetitions")
        self.assertEqual(body["repetitions"], 5)
        self.assertEqual(body["request"]["workload"]["command"], ["pytest", "-q"])
        self.assertEqual(len(runs), 5)

    def test_a_matrix_carries_each_cell_axis_beside_the_request_under_test(self):
        self.evals.matrix(
            [{"axis": {"model": "a", "cpu": 2}, "command": ["pytest", "-q"]}], max_parallel=4
        )

        _method, path, body = self.transport.calls[0]
        self.assertEqual(path, "/v1/eval/matrix")
        self.assertEqual(body["options"], {"max_parallel": 4})
        # Axis values are labels, and the control plane keys cells by them, so a
        # number written as one is stored as the text it is read back as.
        self.assertEqual(body["cells"][0]["axis"], {"model": "a", "cpu": "2"})
        self.assertEqual(body["cells"][0]["request"]["workload"]["command"], ["pytest", "-q"])


    def test_a_lost_matrix_response_is_recovered_a_page_at_a_time(self):
        client = client_with(self.transport)

        first = client.evals.matrix_page("matrix-1", limit=2)
        second = client.evals.matrix_page("matrix-1", limit=2, after=first["next"])

        self.assertEqual([cell["index"] for cell in first["cells"]], [0, 1])
        self.assertIsNotNone(first["next"], "a page that is not the last one names the next")
        self.assertEqual([cell["index"] for cell in second["cells"]], [2])
        self.assertIsNone(second["next"], "the last page reports that it is the last one")
        recovered = {cell["run"]["id"] for cell in first["cells"] + second["cells"]}
        self.assertEqual(len(recovered), 3, "a cell was lost or repeated across the boundary")
        # The cursor is the server's, and it is handed back unexamined.
        _method, path, _payload = self.transport.calls[-1]
        self.assertIn(f"after_id={first['next']['id']}", path)
    def test_a_run_request_handed_over_is_used_as_it_is(self):
        client = client_with(self.transport)
        built = client.runs.request_body(command=["pytest", "-q"], retention="keep_on_failure")

        client.evals.matrix([{"axis": {"model": "a"}, "request": built}])

        posted = self.transport.bodies()[0]["cells"][0]["request"]
        self.assertEqual(posted["retention"], "keep_on_failure")
        # A request rebuilt from a request ends up nested inside a workload,
        # where the control plane ignores it and the run quietly does nothing.
        self.assertNotIn("request", posted["workload"])
        self.assertEqual(posted["workload"]["command"], ["pytest", "-q"])

    def test_an_empty_batch_runs_nothing_and_costs_nothing(self):
        self.assertEqual(self.evals.batch([]), [])
        self.assertEqual(self.transport.calls, [])

    def test_a_batch_waits_out_the_queue_for_every_cell_it_carries(self):
        # Each cell is a run the server may hold queued until
        # `now() + queue_timeout_seconds` before it even starts executing, so
        # the whole evaluation's wait is per-cell and has to cover each one.
        self.evals.batch(
            [{"command": ["true"], "timeout_seconds": 600},
             {"command": ["true"], "timeout_seconds": 1200}],
            max_parallel=2,
        )
        # Mirrors the `1..=86_400` queue ceiling and the server's grace of 120.
        per_run = 86_400 + 120
        self.assertEqual(self.transport.timeouts[0], (86_400 + 600 + 300) + (86_400 + 1200 + 300))
        self.assertGreaterEqual(self.transport.timeouts[0], per_run * 2)


class SuiteExpansionTest(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.evals = client_with(self.transport).evals

    def cells(self):
        return self.transport.bodies()[0]["cells"]

    def test_a_suite_expands_to_a_cell_per_task_revision_and_repetition(self):
        self.evals.compare("main", "feature-x", SUITE, repetitions=2, max_parallel=3)

        cells = self.cells()
        self.assertEqual(len(cells), 8, "two tasks, two revisions, two repetitions")
        self.assertEqual(
            [cell["axis"] for cell in cells[:4]],
            [
                {"task": "unit", "repetition": "0", "revision": "main"},
                {"task": "unit", "repetition": "1", "revision": "main"},
                {"task": "unit", "repetition": "0", "revision": "feature-x"},
                {"task": "unit", "repetition": "1", "revision": "feature-x"},
            ],
        )

    def test_every_cell_checks_out_the_revision_it_is_standing_for(self):
        self.evals.compare("main", "feature-x", SUITE)

        for cell in self.cells():
            repo = cell["request"]["workload"]["repo"]
            # The suite's own reference is only a default; a comparison replaces
            # it, so no cell can report evidence from the wrong revision.
            self.assertEqual(repo["reference"], cell["axis"]["revision"])
            self.assertEqual(repo["url"], "https://github.com/example/fixture.git")
        self.assertEqual(
            {cell["request"]["workload"]["repo"]["reference"] for cell in self.cells()},
            {"main", "feature-x"},
        )

    def test_a_task_keeps_its_command_validations_and_timeout(self):
        self.evals.run_suite(SUITE, revision="feature-x", image="aiec-coding:latest")

        by_task = {cell["axis"]["task"]: cell["request"]["workload"] for cell in self.cells()}
        self.assertEqual(by_task["unit"]["command"], ["pytest", "-q"])
        self.assertEqual(by_task["unit"]["validations"], [["pytest", "-q", "tests/"]])
        self.assertEqual(by_task["unit"]["timeout_seconds"], 900)
        self.assertNotIn("timeout_seconds", by_task["lint"])
        for workload in by_task.values():
            self.assertEqual(workload["image"], "aiec-coding:latest")

    def test_a_caller_key_gives_every_cell_its_own_idempotency_scope(self):
        self.evals.compare(
            "main", "feature-x", SUITE, repetitions=2, idempotency_key="nightly-1"
        )

        keys = [cell["request"]["idempotency_key"] for cell in self.cells()]
        # Two cells sharing a key would be the same run, and the second would be
        # handed the first's run and execute nothing at all.
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual(
            sorted(keys)[:2],
            ["nightly-1-feature-x-lint-0", "nightly-1-feature-x-lint-1"],
        )

    def test_without_a_key_the_control_plane_names_each_cell_itself(self):
        self.evals.compare("main", "feature-x", SUITE)

        for cell in self.cells():
            # Inventing a key would deduplicate an evaluation the caller meant to
            # run again, and the second attempt would return the first's runs.
            self.assertNotIn("idempotency_key", cell["request"])

    def test_run_level_options_reach_every_cell_as_run_fields(self):
        self.evals.compare(
            "main",
            "feature-x",
            SUITE,
            repetitions=1,
            retention="keep_on_failure",
            max_attempts=2,
            retained_seconds=900,
        )

        for cell in self.cells():
            request = cell["request"]
            self.assertEqual(request["retention"], "keep_on_failure")
            self.assertEqual(request["max_attempts"], 2)
            self.assertEqual(request["retained_seconds"], 900)
            for name in ("retention", "max_attempts", "retained_seconds"):
                self.assertNotIn(name, request["workload"])

    def test_a_suite_document_is_read_from_a_reviewable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "nightly.json"
            path.write_text(json.dumps(SUITE), encoding="utf-8")

            self.evals.run_suite(str(path))

        self.assertEqual(len(self.cells()), 2)


class SuiteRefusalTest(unittest.TestCase):
    """What the SDK refuses before it starts anything."""

    def setUp(self):
        self.transport = FakeTransport()
        self.evals = client_with(self.transport).evals

    def assertRefused(self, call, exception=ValueError):
        with self.assertRaises(exception):
            call()
        # Nothing half-started: a refused evaluation costs no machines.
        self.assertEqual(self.transport.calls, [])

    def test_a_suite_that_cannot_be_reviewed_is_refused(self):
        def suite(tasks, name="nightly"):
            return {"name": name, "tasks": tasks}

        one = {"name": "unit", "repo_url": "https://example/fixture", "command": ["pytest"]}
        # A command written as a line reads one way and runs another.
        self.assertRefused(
            lambda: self.evals.run_suite(suite([{**one, "command": "pytest -q"}]))
        )
        # Two tasks with one name would share an idempotency scope.
        self.assertRefused(lambda: self.evals.run_suite(suite([one, {**one, "command": ["ruff"]}])))
        self.assertRefused(lambda: self.evals.run_suite(suite([])))
        self.assertRefused(lambda: self.evals.run_suite("{not json"))
        self.assertRefused(lambda: self.evals.run_suite("evals/does-not-exist.json"))
        self.assertRefused(lambda: self.evals.run_suite({"tasks": [one]}))

    def test_a_revision_compared_with_itself_is_refused(self):
        self.assertRefused(lambda: self.evals.compare("main", "main", SUITE))
        self.assertRefused(lambda: self.evals.compare("", "feature-x", SUITE))

    def test_the_bounds_are_checked_before_anything_is_sent(self):
        self.assertRefused(lambda: self.evals.compare("main", "feature-x", SUITE, repetitions=0))
        self.assertRefused(lambda: self.evals.compare("main", "feature-x", SUITE, max_parallel=65))
        self.assertRefused(lambda: self.evals.compare("main", "feature-x", SUITE, max_parallel=0))
        self.assertRefused(
            lambda: self.evals.compare("main", "feature-x", SUITE, max_parallel="2"), TypeError
        )
        self.assertRefused(lambda: self.evals.run_suite(SUITE, max_attempts=0))
        self.assertRefused(lambda: self.evals.run_suite(SUITE, retention="keep_forever"))
        self.assertRefused(lambda: self.evals.run_suite(SUITE, parallelism=4), TypeError)
        self.assertRefused(
            lambda: self.evals.matrix([{"axis": {"a": ["x"]}, "command": ["true"]}])
        )


class ComparisonOutcomeTest(unittest.TestCase):
    """A comparison reports what the runs produced, and judges none of it."""

    def compare(self, states, **kwargs):
        transport = FakeTransport(states=states)
        comparison = client_with(transport).evals.compare(
            "main", "feature-x", SUITE, repetitions=2, **kwargs
        )
        return transport, comparison

    def test_a_comparison_reports_each_revision_as_it_came_out(self):
        _transport, comparison = self.compare({
            ("main", "unit", "0"): "failed",
            ("main", "unit", "1"): "failed",
            ("feature-x", "unit", "1"): "failed",
        })

        self.assertIsInstance(comparison, Comparison)
        self.assertEqual(comparison.suite, "nightly")
        self.assertEqual((comparison.baseline, comparison.candidate), ("main", "feature-x"))
        self.assertEqual(comparison.matrix_id, "matrix-1")
        self.assertEqual(comparison.max_parallel, 2)
        self.assertEqual(len(comparison.cells), 8)

        baseline = comparison.by_revision["main"]
        self.assertEqual(baseline["runs"], 4)
        self.assertEqual(baseline["succeeded"], 2)
        self.assertEqual(baseline["failed"], 2)
        self.assertEqual(baseline["states"], {"failed": 2, "succeeded": 2})
        # Every exit code is kept: a caller judging reliability needs the two
        # that passed as much as the two that did not.
        self.assertEqual(baseline["task_exit_codes"], [1, 1, 0, 0])
        self.assertEqual(comparison.by_revision["feature-x"]["succeeded"], 3)
        self.assertEqual(comparison.success_count("main"), 2)

    def test_a_comparison_measures_runtime_from_the_recorded_timestamps(self):
        _transport, comparison = self.compare({})

        self.assertEqual(
            comparison.by_revision["main"]["duration_ms"],
            {"total": 168000, "min": 42000, "max": 42000},
        )

    def test_each_task_is_reported_under_both_revisions(self):
        _transport, comparison = self.compare({("feature-x", "lint", "0"): "failed"})

        self.assertEqual([entry["task"] for entry in comparison.by_task], ["unit", "lint"])
        unit = comparison.by_task[0]["revisions"]
        self.assertEqual(unit["main"]["runs"], 2)
        self.assertEqual(unit["feature-x"]["runs"], 2)
        self.assertEqual(comparison.by_task[1]["revisions"]["feature-x"]["failed"], 1)

    def test_a_failed_cell_is_kept_as_evidence_rather_than_dropped(self):
        kept = settled_run(
            "run-failed",
            state="failed",
            exit_code=1,
            failure_reason="pytest exited 1",
            validation_exit_codes=(1,),
            retained_sandbox_id="sandbox-1",
            retained_until="2026-07-28T13:00:00Z",
        )

        class KeptFailureTransport(FakeTransport):
            """One cell failed and kept its machine for debugging."""

            def cell(self, index, cell):
                answered = super().cell(index, cell)
                if answered["run"]["state"] == "failed":
                    answered["run"] = kept
                return answered

        transport = KeptFailureTransport(states={("feature-x", "unit", "0"): "failed"})
        comparison = client_with(transport).evals.compare(
            "main", "feature-x", SUITE, repetitions=2
        )

        candidate = comparison.by_revision["feature-x"]
        self.assertEqual(candidate["failed"], 1)
        self.assertEqual(candidate["validations_failed"], 1)
        self.assertIn("run-failed", candidate["run_ids"])
        # The machine kept for debugging is part of the run's evidence, and the
        # run itself is handed back whole rather than summarised away.
        failed = [run for run in comparison.runs("feature-x") if run["id"] == "run-failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["failure_reason"], "pytest exited 1")
        self.assertEqual(failed[0]["retained_sandbox_id"], "sandbox-1")
        self.assertEqual(failed[0]["retained_until"], "2026-07-28T13:00:00Z")

    def test_every_run_a_comparison_counted_is_the_run_it_handed_back(self):
        _transport, comparison = self.compare({("main", "unit", "0"): "failed"})

        counted = []
        for summary in comparison.by_revision.values():
            counted.extend(summary["run_ids"])
        kept = [run["id"] for run in comparison.runs("main")]
        kept.extend(run["id"] for run in comparison.runs("feature-x"))
        self.assertEqual(sorted(counted), sorted(kept))
        self.assertEqual(len(kept), len(comparison.cells))
        # The runs are the records, so a caller can read a result off one.
        first = comparison.cells[0]["run"]
        self.assertEqual(set(RUN_FIELDS).issubset(first), True)
        self.assertIn("exit_code", first["results"]["task"])


if __name__ == "__main__":
    unittest.main()
