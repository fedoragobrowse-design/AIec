"""The new-leak set must never be derived from a truncated id list.

The census carries at most :data:`aiecbench.observe.CENSUS_ID_CAP` non-terminal
ids and a ``nonterminal_truncated`` flag. Subtracting two truncated lists does
not give the new sandboxes, it gives whatever survived the cap - and the report
used to print that as ``new non-terminal sandboxes: 0`` next to
``nonterminal_at_end: 70``.
"""

from __future__ import annotations

import io
import unittest
import unittest.mock

from aiecbench import observe
from aiecbench.observe import CENSUS_ID_CAP, leak_delta, sandbox_census
from aiecbench.report import render
from tests.support import ListClient, PagedSandboxClient, sandboxes

def _census(*ids: str) -> dict:
    return sandbox_census(ListClient(sandboxes(*ids)))


def _render(leak_accounting: dict) -> str:
    stream = io.StringIO()
    render(
        {
            "label": "test",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "target": {"base_url": "https://bench.invalid", "tls": "system-trust-store"},
            "conditions_fingerprint": "test",
            "scenarios": {},
            "scenario_errors": {},
            "leak_accounting": leak_accounting,
            "harness_cleanup": {},
            "limitations": [],
        },
        stream,
    )
    return stream.getvalue()


class LeakCensusTest(unittest.TestCase):
    def test_past_the_cap_the_new_leak_set_is_refused_not_reported_as_zero(self):
        before = _census(*[f"sbx-{index:03d}" for index in range(70)])
        after = _census(*[f"sbx-{index:03d}" for index in range(60, 130)])

        self.assertTrue(before["nonterminal_truncated"])
        self.assertEqual(before["nonterminal_count"], 70)
        self.assertEqual(len(before["nonterminal_sandbox_ids"]), CENSUS_ID_CAP)

        delta = leak_delta({"sandboxes": before}, {"sandboxes": after})

        # The full counts are still real numbers; only the set is refused.
        self.assertEqual(delta["nonterminal_at_end"], 70)
        new_ids = delta["new_nonterminal_sandbox_ids"]
        self.assertIsInstance(new_ids, dict)
        self.assertFalse(new_ids["available"])
        self.assertIn("truncated", new_ids["reason"])
        self.assertIn(str(CENSUS_ID_CAP), new_ids["reason"])

    def test_leaks_beyond_the_cap_printed_as_zero_are_not_zero(self):
        """The reported symptom: a 20-machine leak reported as ``0`` new."""
        held = [f"sbx-{index:03d}" for index in range(70)]
        before = _census(*held)
        # The twenty new machines are all past the cap, so the two truncated
        # id lists are identical and their difference is empty.
        after = _census(*held, *[f"sbx-new-{index:03d}" for index in range(20)])

        delta = leak_delta({"sandboxes": before}, {"sandboxes": after})

        self.assertEqual(delta["nonterminal_at_end"], 90)
        text = _render({"sandbox_census_delta": delta})
        self.assertIn("90 after", text)
        self.assertNotIn("new non-terminal sandboxes: 0", text)
        self.assertIn("new non-terminal sandboxes: not computed", text)

    def test_the_rendered_report_does_not_print_a_zero_beside_seventy(self):
        before = _census(*[f"sbx-{index:03d}" for index in range(70)])
        after = _census(*[f"sbx-{index:03d}" for index in range(60, 130)])
        text = _render({"sandbox_census_delta": leak_delta({"sandboxes": before},
                                                           {"sandboxes": after})})

        self.assertIn("70 after", text)
        self.assertIn("new non-terminal sandboxes: not computed", text)
        self.assertNotIn("new non-terminal sandboxes: 0", text)

    def test_truncation_at_one_end_is_enough_to_refuse_the_set(self):
        """A short list on either side makes the difference unsound."""
        before = _census("sbx-000", "sbx-001")
        after = _census(*[f"sbx-{index:03d}" for index in range(70)])

        delta = leak_delta({"sandboxes": before}, {"sandboxes": after})
        self.assertFalse(delta["new_nonterminal_sandbox_ids"]["available"])
        self.assertIn("after", delta["new_nonterminal_sandbox_ids"]["reason"])

    def test_under_the_cap_the_set_is_still_computed(self):
        before = _census("sbx-000", "sbx-001", "sbx-002")
        after = _census("sbx-001", "sbx-002", "sbx-003")

        delta = leak_delta({"sandboxes": before}, {"sandboxes": after})
        self.assertEqual(delta["new_nonterminal_sandbox_ids"], ["sbx-003"])
        self.assertEqual(delta["pre_existing_nonterminal"], 3)

    def test_a_census_that_was_unavailable_still_says_so(self):
        before = {"sandboxes": observe.unavailable("sandboxes", "GET /v1/sandboxes returned 403")}
        after = _census("sbx-000")
        delta = leak_delta(before, {"sandboxes": after})
        self.assertFalse(delta["available"])


class SandboxPagingTest(unittest.TestCase):
    """The census walks every page, and says so when it cannot."""

    @staticmethod
    def _page(rows: list[dict], created_at: str | None, sandbox_id: str | None) -> dict:
        nxt = None
        if sandbox_id is not None:
            nxt = {"created_at": created_at, "id": sandbox_id}
        return {"sandboxes": rows, "next": nxt}

    def test_a_tenant_with_more_sandboxes_than_fit_in_one_page_is_still_censused(self):
        """The bug this fixture change exists for: page one looked complete."""
        first = [{"id": f"sbx-{index:03d}", "state": "running"} for index in range(70)]
        second = [{"id": f"sbx-{index:03d}", "state": "destroyed"} for index in range(70, 100)]
        client = PagedSandboxClient(
            [
                self._page(first, "2026-01-02T00:00:00+00:00", "sbx-069"),
                self._page(second, None, None),
            ]
        )

        census = sandbox_census(client)

        self.assertTrue(census["available"])
        self.assertEqual(census["total"], 100, "one page was reported as the whole tenant")
        self.assertEqual(census["nonterminal_count"], 70)
        self.assertEqual(census["by_state"]["destroyed"], 30)
        self.assertEqual(census["pages"], 2)
        # The second request must carry the cursor, or the walk is a coincidence.
        self.assertNotIn("after_id", client.requests[0][1])
        self.assertIn("after_id=sbx-069", client.requests[1][1])
        self.assertIn("after_created_at=2026-01-02T00%3A00%3A00", client.requests[1][1])

    def test_a_control_plane_that_repeats_a_cursor_is_refused_not_counted_twice(self):
        page = self._page(
            [{"id": "sbx-000", "state": "running"}], "2026-01-02T00:00:00+00:00", "sbx-000"
        )

        census = sandbox_census(PagedSandboxClient([page]))

        self.assertFalse(census["available"])
        self.assertIn("repeated cursor", census["reason"])
        self.assertNotIn("nonterminal_count", census)

    def test_a_census_that_would_never_finish_is_refused_rather_than_looped(self):
        page = self._page(
            [{"id": "sbx-000", "state": "running"}], "2026-01-02T00:00:00+00:00", "sbx-000"
        )
        client = PagedSandboxClient([page], vary_cursor=True)

        with unittest.mock.patch.object(observe, "CENSUS_PAGE_LIMIT", 3):
            census = sandbox_census(client)

        self.assertFalse(census["available"])
        self.assertIn("still offered a next cursor", census["reason"])
        self.assertEqual(len(client.requests), 3)

    def test_the_pre_pagination_bare_list_is_refused_by_name(self):
        """An older control plane must not read as a working census."""
        census = sandbox_census(ListClient([{"id": "sbx-000", "state": "running"}]))

        self.assertFalse(census["available"])
        self.assertIn("did not return a sandbox page", census["reason"])


if __name__ == "__main__":
    unittest.main()
