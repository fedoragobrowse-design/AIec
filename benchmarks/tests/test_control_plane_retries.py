"""A read the control plane refused twice is not one healthy sample.

The client retries 502/503/504 on an idempotent method, so ``503, 503, 200``
is a single 200 to the caller and two refusals to the cluster. The scenario has
to count every attempt that left the harness, and a sample that needed retries
must be distinguishable from one that did not.
"""

from __future__ import annotations

import types
import unittest

from aiecbench.harness import Bench
from aiecbench.scenarios import control_plane
from tests.support import ScriptedClient

RETRYING_PATH = control_plane.ENDPOINTS[0][2]
STRAIGHT_PATH = control_plane.ENDPOINTS[1][2]


def _run(samples: int = 1):
    script = {
        path: ([503, 503, 200] if path == RETRYING_PATH else [200])
        for _, _, path in control_plane.ENDPOINTS
    }
    client = ScriptedClient(script, max_retries=2)
    bench = Bench(client=client, label="test")
    report = control_plane.run(bench, types.SimpleNamespace(samples=samples))
    return client, {entry["path"]: entry for entry in report["endpoints"]}


class ControlPlaneRetryTest(unittest.TestCase):
    def test_a_503_503_200_read_reports_all_three_attempts(self):
        client, endpoints = _run()

        self.assertEqual(client.sent.count(503), 2, "the client really did retry twice")

        entry = endpoints[RETRYING_PATH]
        # One sample, one final status - the old view.
        self.assertEqual(entry["samples"], 1)
        self.assertEqual(entry["statuses"], {"200": 1})
        # And the whole call, which the old view threw away.
        self.assertEqual(entry["requests"], 3)
        self.assertEqual(entry["retried_away_statuses"], {"503": 2})
        self.assertEqual(entry["samples_that_retried"], 1)
        self.assertEqual(entry["attempts_per_sample"]["max_count"], 3)
        self.assertIn("retry", entry["latency"]["note"])

    def test_a_sample_that_retried_is_distinguishable_from_one_that_did_not(self):
        _, endpoints = _run()

        retried = endpoints[RETRYING_PATH]
        clean = endpoints[STRAIGHT_PATH]

        self.assertEqual(clean["requests"], 1)
        self.assertEqual(clean["samples_that_retried"], 0)
        self.assertNotIn("retried_away_statuses", clean)
        self.assertNotIn("note", clean["latency"])
        self.assertNotEqual(retried["requests"], clean["requests"])

    def test_the_final_latency_is_labelled_as_the_final_attempt(self):

        _, endpoints = _run()

        self.assertIn("final attempt only", endpoints[RETRYING_PATH]["latency"]["note"])
        self.assertEqual(endpoints[RETRYING_PATH]["latency"]["samples"], 1)

    def test_an_endpoint_that_refuses_every_sample_still_reports_why(self):
        """A read-only key that gets 403 everywhere must not crash the report."""
        script = {path: [403] * 4 for _, _, path in control_plane.ENDPOINTS}
        client = ScriptedClient(script, max_retries=2)
        bench = Bench(client=client, label="test")
        report = control_plane.run(bench, types.SimpleNamespace(samples=2))
        entries = {entry["path"]: entry for entry in report["endpoints"]}

        entry = entries[RETRYING_PATH]
        self.assertFalse(entry["latency"]["available"])
        self.assertIn("403/unavailable", entry["latency"]["reason"])
        self.assertEqual(entry["refusals"], {"403/unavailable": 2})
        # 403 is not retried, so each sample really was one request.
        self.assertEqual(entry["requests"], 2)
        self.assertNotIn("retried_away_statuses", entry)
        for block in entries.values():
            self.assertFalse(block["latency"]["available"])


if __name__ == "__main__":
    unittest.main()
