"""A repetition with no timestamps is not a 0.0 second repetition.

``/v1/eval/repetitions`` returns run documents, and a run whose
``completed_at`` is absent or unparseable has no measured duration. The
neighbouring ``cell_seconds`` block already drops those; ``run_total`` used to
receive a fabricated ``0.0`` from ``_wall_time(run) or 0.0``, so the two blocks
disagreed about the same population.
"""

from __future__ import annotations

import types
import unittest

from aiecbench.harness import Bench
from aiecbench.scenarios import matrix
from tests.support import ListClient

#: A run that lasted five seconds.
TIMED_RUN = {
    "id": "run-timed",
    "state": "succeeded",
    "requested_at": "2026-10-01T00:00:00Z",
    "completed_at": "2026-10-01T00:00:05Z",
    "results": {"phase_ms": {"task": 4000}},
}
#: A run that succeeded and recorded no usable completion time.
UNTIMED_RUN = {
    "id": "run-no-completion",
    "state": "succeeded",
    "requested_at": "2026-10-01T00:00:00Z",
    "results": {"phase_ms": {"task": 4000}},
}
#: A run whose timestamps are not timestamps.
UNPARSEABLE_RUN = {
    "id": "run-garbled",
    "state": "succeeded",
    "requested_at": "2026-10-01T00:00:00Z",
    "completed_at": "not a timestamp",
    "results": {"phase_ms": {"task": 4000}},
}


def _args() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        image="python:3.13",
        command_vector=["python", "-c", "pass"],
        cpu=1,
        memory_mb=512,
        disk_mb=2048,
        repo=None,
        ref=None,
        setup_vectors=[],
        validation_vectors=[],
        artifacts=[],
        workload_timeout=60,
        runtime=None,
        matrix_parallel=2,
        run_timeout=300,
    )


def _repetitions(runs):
    bench = Bench(client=ListClient(list(runs)), label="test")
    return matrix._repetitions(bench, _args(), len(runs))


class MatrixRepetitionTimingTest(unittest.TestCase):
    def test_an_untimed_success_is_excluded_from_both_latency_samples(self):
        block = _repetitions([TIMED_RUN, UNTIMED_RUN, UNPARSEABLE_RUN])

        self.assertEqual(block["returned"], 3)

        cell_samples = block["cell_seconds"]["samples"]
        total_samples = block["outcomes"]["run_total"]["samples"]
        self.assertEqual(cell_samples, 1)
        self.assertEqual(total_samples, 1)
        self.assertEqual(
            cell_samples,
            total_samples,
            "the two blocks summarise the same population and must agree on its size",
        )

        # The 0.0 s fabrication, whichever way the timestamp was missing.
        self.assertEqual(block["cell_seconds"]["min_s"], 5.0)
        self.assertEqual(block["outcomes"]["run_total"]["min_s"], 5.0)
        self.assertNotEqual(block["outcomes"]["run_total"]["max_s"], 0.0)

    def test_an_untimed_success_is_still_counted_as_a_success(self):
        block = _repetitions([TIMED_RUN, UNTIMED_RUN, UNPARSEABLE_RUN])

        outcomes = block["outcomes"]
        self.assertEqual(outcomes["succeeded"], 3)
        self.assertEqual(outcomes["not_succeeded"], 0)
        # ... and the report says which successes carry no time, rather than
        # leaving a reader to reconcile `succeeded: 3` with a sample of 1.
        self.assertEqual(outcomes["succeeded_without_a_measured_duration"], 2)
        # The phase it really did measure is still reported.
        self.assertEqual(outcomes["phase_task"]["samples"], 3)

    def test_every_repetition_timed_keeps_the_whole_population(self):
        block = _repetitions([TIMED_RUN, dict(TIMED_RUN, id="run-2")])

        outcomes = block["outcomes"]
        self.assertEqual(outcomes["succeeded"], 2)
        self.assertNotIn("succeeded_without_a_measured_duration", outcomes)
        self.assertEqual(outcomes["run_total"]["samples"], 2)
        self.assertEqual(block["cell_seconds"]["samples"], 2)

    def test_when_no_repetition_timed_the_total_says_why(self):
        block = _repetitions([UNTIMED_RUN, UNPARSEABLE_RUN])

        outcomes = block["outcomes"]
        self.assertEqual(outcomes["succeeded"], 2)
        self.assertFalse(outcomes["run_total"]["available"])
        self.assertIn("2 successful runs", outcomes["run_total"]["reason"])
        # ... while the block that already dropped them measures what it can.
        self.assertFalse(block["cell_seconds"]["available"])


if __name__ == "__main__":
    unittest.main()

