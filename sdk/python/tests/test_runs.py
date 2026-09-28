"""Contract tests for the run surface, against a fake transport.

No live control plane: the client's `_request` is replaced, so these assert on
the bytes the SDK would put on the wire -- which is the part that silently
drifts from the API.
"""

import threading
import time
import unittest

from agentforge import AIec, AIecError, Runs


class FakeTransport:
    """Records what the SDK asked for and answers with a settled run.

    Thread-safe because `run_batch` submits cells on a pool: a recorder that
    raced with itself would make the concurrency test meaningless.
    """

    def __init__(self, fail_paths=(), states=None):
        self.calls = []
        self.fail_paths = set(fail_paths)
        self.states = states or {}
        self.lock = threading.Lock()
        self.in_flight = 0
        self.peak_in_flight = 0
        self.delay = 0.0

    def __call__(self, method, path, payload=None):
        with self.lock:
            self.calls.append((method, path, payload))
            if path in self.fail_paths:
                raise AIecError(400, {"error": {"code": "invalid_request", "message": "refused"}})
            self.in_flight += 1
            self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            if self.delay:
                time.sleep(self.delay)
            if method == "GET" and path.startswith("/v1/runs?"):
                return [{"id": "run-1", "state": "succeeded"}]
            if method == "POST" and path.endswith("/cancel"):
                return {"id": path.split("/")[3], "state": "cancelled"}
            if method == "GET":
                return {"id": path.rsplit("/", 1)[-1], "events": []}
            state = self.states.get((payload or {}).get("workload", {}).get("command", [None])[0], "succeeded")
            return {"id": f"run-{len(self.calls)}", "state": state}
        finally:
            with self.lock:
                self.in_flight -= 1

    def bodies(self):
        return [payload for method, _path, payload in self.calls if payload is not None]


def client_with(transport):
    client = AIec(api_key="af_live_" + "0" * 48, base_url="http://control.invalid")
    client._request = transport
    return client


class RunRequestTest(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.runs = Runs(client_with(self.transport))

    def test_a_run_is_posted_with_the_shape_the_api_accepts(self):
        run = self.runs.create(
            image="aiec-coding:latest",
            repo="https://github.com/example/project.git",
            ref="main",
            setup=["pip install -e ."],
            command="pytest -q tests/",
            validations=[["pytest", "-q"], "cargo test"],
            artifacts="report.txt",
            timeout_seconds=900,
            cpu=2,
            memory_mb=2048,
            disk_mb=4096,
            network=True,
            requirements={"full_kernel_isolation": True},
            retention="keep_on_failure",
            runtime="firecracker",
            idempotency_key="nightly-42",
            git_evidence=True,
            secrets=["NPM_TOKEN"],
        )
        self.assertEqual(run["state"], "succeeded")

        method, path, body = self.transport.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/runs"))
        self.assertEqual(set(body), {
            "workload", "resources", "requirements", "retention",
            "idempotency_key", "requested_runtime",
        })
        workload = body["workload"]
        # Commands travel as argument vectors, never as strings a shell re-reads.
        self.assertEqual(workload["command"], ["pytest", "-q", "tests/"])
        self.assertEqual(workload["setup"], [["pip", "install", "-e", "."]])
        self.assertEqual(workload["validations"], [["pytest", "-q"], ["cargo", "test"]])
        self.assertEqual(workload["artifacts"], ["report.txt"])
        self.assertEqual(workload["timeout_seconds"], 900)
        self.assertEqual(workload["image"], "aiec-coding:latest")
        self.assertEqual(workload["git_evidence"], True)
        self.assertEqual(workload["secrets"], ["NPM_TOKEN"])
        self.assertEqual(workload["repo"], {
            "url": "https://github.com/example/project.git",
            "reference": "main",
            "path": "/workspace/repository",
        })
        self.assertEqual(body["resources"], {
            "cpu": 2, "memory_mb": 2048, "disk_mb": 4096, "network": {"enabled": True},
        })
        self.assertEqual(body["requirements"], {"full_kernel_isolation": True})
        self.assertEqual(body["retention"], "keep_on_failure")
        self.assertEqual(body["idempotency_key"], "nightly-42")
        self.assertEqual(body["requested_runtime"], "firecracker")

    def test_the_defaults_are_the_ones_the_control_plane_uses(self):
        self.runs.create(command=["true"])
        body = self.transport.calls[0][2]
        self.assertEqual(body["retention"], "destroy")
        self.assertEqual(body["resources"], {
            "cpu": 1, "memory_mb": 1024, "disk_mb": 2048, "network": {"enabled": False},
        })
        self.assertEqual(body["requirements"], {})
        # Nothing optional is invented, so the API is the one that decides.
        for optional in ("idempotency_key", "requested_runtime", "matrix_id", "parent_run_id"):
            self.assertNotIn(optional, body)
        self.assertEqual(set(body["workload"]), {"command"})

    def test_a_restricted_network_is_stated_as_allowed_hosts(self):
        self.runs.create(command=["true"], network=["pypi.org", "registry.npmjs.org"])
        body = self.transport.calls[0][2]
        self.assertEqual(body["resources"]["network"], {
            "enabled": True,
            "allowed_hosts": ["pypi.org", "registry.npmjs.org"],
        })

    def test_a_retention_the_api_does_not_have_is_refused_before_sending(self):
        with self.assertRaises(ValueError):
            self.runs.create(command=["true"], retention="keep_forever")
        self.assertEqual(self.transport.calls, [])

    def test_a_command_that_is_neither_a_string_nor_a_list_is_refused(self):
        with self.assertRaises(TypeError):
            self.runs.create(command={"cmd": "true"})
        self.assertEqual(self.transport.calls, [])


class RunReadTest(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.runs = Runs(client_with(self.transport))

    def test_a_run_page_carries_the_state_filter_and_the_limit(self):
        self.runs.list(state="running", limit=5)
        method, path, payload = self.transport.calls[0]
        self.assertEqual((method, payload), ("GET", None))
        self.assertEqual(path, "/v1/runs?limit=5&state=running")

    def test_each_read_uses_its_own_documented_route(self):
        self.runs.get("run-1")
        self.runs.events("run-1")
        self.runs.artifacts("run-1")
        self.runs.cancel("run-1")
        self.assertEqual(
            [(method, path) for method, path, _ in self.transport.calls],
            [
                ("GET", "/v1/runs/run-1"),
                ("GET", "/v1/runs/run-1/events"),
                ("GET", "/v1/runs/run-1/artifacts"),
                ("POST", "/v1/runs/run-1/cancel"),
            ],
        )


class RunWorkflowTest(unittest.TestCase):
    def test_a_batch_never_exceeds_the_parallelism_it_was_given(self):
        transport = FakeTransport()
        transport.delay = 0.02
        runs = Runs(client_with(transport))

        results = runs.run_batch(
            [{"command": ["true"]}, {"command": ["true"]}, {"command": ["true"]}, {"command": ["true"]}],
            max_parallel=2,
        )

        self.assertEqual(len(results), 4)
        self.assertTrue(all(result["run"] is not None for result in results))
        self.assertLessEqual(transport.peak_in_flight, 2)

    def test_a_cell_that_cannot_start_is_reported_without_abandoning_the_batch(self):
        transport = FakeTransport()
        seen = {"n": 0}

        def flaky(method, path, payload=None):
            # The second submission is refused, the other two are not.
            with transport.lock:
                seen["n"] += 1
                refuse = seen["n"] == 2
            if refuse:
                raise AIecError(
                    400, {"error": {"code": "invalid_request", "message": "refused"}}
                )
            return transport(method, path, payload)

        results = Runs(client_with(flaky)).run_batch(
            [{"command": ["one"]}, {"command": ["two"]}, {"command": ["three"]}], max_parallel=1
        )

        self.assertEqual([result["run"] is None for result in results], [False, True, False])
        self.assertIn("invalid_request", results[1]["error"])
        self.assertIsNone(results[0]["error"])
        self.assertIsNone(results[2]["error"])

    def test_repetitions_are_separate_runs_in_the_same_idempotency_scope(self):
        transport = FakeTransport()
        runs = Runs(client_with(transport))

        results = runs.run_repetitions(
            repetitions=3, command=["pytest", "-q"], idempotency_key="nightly"
        )

        self.assertEqual(len(results), 3)
        keys = [body["idempotency_key"] for body in transport.bodies()]
        # Two runs sharing a key would be the same run, and the second would
        # silently execute nothing.
        self.assertEqual(sorted(keys), ["nightly-0", "nightly-1", "nightly-2"])
        self.assertTrue(all(result["error"] is None for result in results))

    def test_no_repetitions_costs_nothing(self):
        transport = FakeTransport()
        results = Runs(client_with(transport)).run_repetitions(repetitions=0, command=["true"])
        self.assertEqual(results, [])
        self.assertEqual(transport.calls, [])

    def test_a_matrix_groups_its_cells_and_summarises_them_by_axis(self):
        transport = FakeTransport(states={"false": "failed"})
        runs = Runs(client_with(transport))

        matrix = runs.run_matrix([
            {"axis": {"model": "a"}, "command": ["true"]},
            {"axis": {"model": "a"}, "command": ["false"]},
            {"axis": {"model": "b"}, "command": ["true"]},
        ])

        bodies = transport.bodies()
        self.assertEqual(len(bodies), 3)
        matrix_id = matrix["matrix_id"]
        self.assertEqual({body["matrix_id"] for body in bodies}, {matrix_id})
        keys = [body["idempotency_key"] for body in bodies]
        self.assertEqual(len(set(keys)), 3, "each cell needs its own idempotency scope")
        self.assertEqual(
            [result["axis"] for result in matrix["results"]],
            [{"model": "a"}, {"model": "a"}, {"model": "b"}],
        )
        self.assertEqual(matrix["summary"], {
            "cells": 3,
            "successes": 2,
            "by_axis": {
                "model=a": {"successes": 1, "cells": 2},
                "model=b": {"successes": 1, "cells": 1},
            },
        })

    def test_a_caller_key_wins_over_the_generated_one(self):
        transport = FakeTransport()
        matrix = Runs(client_with(transport)).run_matrix([
            {"axis": {"model": "a"}, "command": ["true"], "idempotency_key": "mine"},
        ])
        self.assertEqual(transport.bodies()[0]["idempotency_key"], "mine")
        self.assertEqual(matrix["summary"]["successes"], 1)

    def test_a_batch_without_parallelism_cannot_start(self):
        runs = Runs(client_with(FakeTransport()))
        for invalid in (0, -1, 65):
            with self.assertRaises(ValueError):
                runs.run_batch([{"command": ["true"]}], max_parallel=invalid)
        with self.assertRaises(TypeError):
            runs.run_batch([{"command": ["true"]}], max_parallel="2")


if __name__ == "__main__":
    unittest.main()
