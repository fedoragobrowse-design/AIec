"""A refusal the API made before it executed anything is not a task failure.

The harness records an HTTP refusal with ``state: "rejected"`` and nothing
else, so the classification has to read that state. If it reads a flag nothing
sets, the refusal lands in the failure histogram as the string ``"rejected"``
and the ``rejections`` array - the only place ``http_status`` and
``error_code`` are ever surfaced - is never emitted at all.
"""

from __future__ import annotations

import unittest

from aiecbench.harness import Bench, describe_outcomes, submit_run
from tests.support import QueueClient, error_body, response


class RejectionClassificationTest(unittest.TestCase):
    def _bench(self, responses):
        return Bench(client=QueueClient(responses), label="test")

    def test_a_refused_submission_is_a_rejection_not_a_task_failure(self):
        """A 429 and a failed task land in different buckets, with evidence."""
        bench = self._bench(
            [
                response(429, error_body("rate_limited", "slow down"), method="POST"),
                response(
                    200,
                    {
                        "id": "run-1",
                        "state": "failed",
                        "failure_reason": "the task exited 1",
                        "results": {},
                    },
                    seconds=4.0,
                    method="POST",
                ),
            ]
        )
        body = {"workload": {"image": "python:3.13", "command": ["true"]}}
        outcomes = [
            submit_run(bench, body, timeout=30),
            submit_run(bench, body, timeout=30),
        ]

        # The refusal was refused before execution: it is counted as one, and it
        # is not a workload failure.
        self.assertEqual(outcomes[0]["state"], "rejected")

        report = describe_outcomes(outcomes)

        self.assertEqual(report["rejected_before_execution"], 1)
        self.assertEqual(report["not_succeeded"], 1)
        self.assertEqual(report["succeeded"], 0)
        self.assertEqual(
            report["failure_reasons"], {"the task exited 1": 1}, "a refusal is not a task failure"
        )

        # The evidence a reader needs to act on the refusal.
        self.assertEqual(len(report["rejections"]), 1)
        rejection = report["rejections"][0]
        self.assertEqual(rejection["state"], "rejected")
        self.assertEqual(rejection["http_status"], 429)
        self.assertEqual(rejection["error_code"], "rate_limited")
        self.assertEqual(rejection["message"], "slow down")

    def test_a_transport_failure_is_still_reported_as_a_refusal(self):
        """Transport errors keep their existing shape: no status, no code."""
        from aiecbench.client import TransportError

        class Broken(QueueClient):
            def request(self, method, path, body=None, *, timeout=None, text=False):
                raise TransportError("GET /v1/runs: timed out", 30.0)

        bench = Bench(client=Broken([]), label="test")
        outcome = submit_run(bench, {}, timeout=30)
        self.assertEqual(outcome["state"], "transport_error")
        self.assertIn("transport_error", outcome)

        report = describe_outcomes([outcome])
        self.assertEqual(report["rejected_before_execution"], 1)
        self.assertEqual(report["not_succeeded"], 0)
        self.assertNotIn("failure_reasons", report)
        rejection = report["rejections"][0]
        self.assertEqual(rejection["state"], "transport_error")
        self.assertIsNone(rejection["http_status"])
        self.assertIn("timed out", rejection["message"])

    def test_a_run_that_never_reached_the_api_is_not_silently_dropped(self):
        """Every outcome is accounted for: succeeded + failed + rejected."""
        bench = self._bench(
            [
                response(503, error_body("unavailable", "no capacity"), method="POST"),
                response(
                    200,
                    {"id": "run-1", "state": "succeeded", "results": {"phase_ms": {"task": 900}}},
                    seconds=3.0,
                    method="POST",
                ),
            ]
        )
        report = describe_outcomes(
            [submit_run(bench, {}, timeout=30) for _ in range(2)]
        )
        self.assertEqual(
            report["succeeded"] + report["not_succeeded"] + report["rejected_before_execution"],
            2,
        )
        self.assertEqual(report["states"], {"succeeded": 1, "rejected": 1})


if __name__ == "__main__":
    unittest.main()
