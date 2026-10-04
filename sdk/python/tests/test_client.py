"""Contract tests for the sandbox surface and the transport under it.

The budget tests replace `_request` and read the `timeout` the SDK would have
waited, because the client timing out first is the failure that costs most: the
command keeps running inside a sandbox the caller was told was fine. The
transport tests go through a real socket, because that is the only place a
`URLError`/`OSError` ever appears.
"""

import base64
import http.server
import json
import socket
import threading
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from urllib.error import URLError

from agentforge import AIec, AIecError, Sandbox
from agentforge.client import (
    DEFAULT_EXEC_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DESTROY_TIMEOUT_SECONDS,
    EXEC_RESPONSE_SLACK_SECONDS,
    LIST_TIMEOUT_SECONDS,
    MAX_ARTIFACT_UPLOAD_SECONDS,
    MAX_EXEC_SECONDS,
    SANDBOX_PROVISION_TIMEOUT_SECONDS,
    SNAPSHOT_TIMEOUT_SECONDS,
)


def a_client(base_url="http://control.invalid"):
    return AIec(api_key="af_live_" + "0" * 48, base_url=base_url)


class RecordingTransport:
    """Answers everything and remembers the budget each call was given."""

    def __init__(self, fail=None):
        self.calls = []
        self.timeouts = []
        self.fail = fail

    def __call__(self, method, path, payload=None, *, timeout=120):
        self.calls.append((method, path, payload))
        self.timeouts.append(timeout)
        if self.fail is not None:
            raise self.fail
        return {"id": "sandbox-1"}

    @property
    def last_timeout(self):
        return self.timeouts[-1]


class SandboxPageTest(unittest.TestCase):
    """`GET /v1/sandboxes` answers a bounded page and names its successor.

    The SDK hands both back. A caller that stops reading has to be able to tell
    that it stopped at a page boundary it chose, rather than discovering later
    that a list it believed complete was not.
    """

    def paged(self, bodies):
        """A transport answering the given pages in order."""
        client = a_client()
        seen = []

        def request(method, path, payload=None, *, timeout=120):
            seen.append(path)
            return bodies[min(len(seen) - 1, len(bodies) - 1)]

        client._request = request
        return client, seen

    def test_the_page_carries_its_items_and_its_successor(self):
        client, _ = self.paged([
            {"sandboxes": [{"id": "a"}, {"id": "b"}],
             "next": {"created_at": "2024-01-01T00:00:00Z", "id": "b"}}
        ])
        page = client.sandboxes.list()
        self.assertEqual([s["id"] for s in page.sandboxes], ["a", "b"])
        self.assertEqual(page.next["id"], "b")
        self.assertEqual(len(page), 2)

    def test_the_last_page_says_there_is_no_next(self):
        client, _ = self.paged([{"sandboxes": [{"id": "a"}], "next": None}])
        self.assertIsNone(client.sandboxes.list().next)

    def test_a_page_beyond_what_the_control_plane_will_give_is_refused(self):
        # The route clamps to 200. Asking for a thousand and receiving two
        # hundred with no error is an answer that looks complete and is not.
        client, _ = self.paged([{"sandboxes": [], "next": None}])
        with self.assertRaises(ValueError):
            client.sandboxes.list(limit=1000)
        with self.assertRaises(ValueError):
            client.sandboxes.list(limit=0)

    def test_the_page_the_control_plane_will_still_give_is_accepted(self):
        client, seen = self.paged([{"sandboxes": [], "next": None}])
        client.sandboxes.list(limit=200)
        self.assertIn("limit=200", seen[0])

    def test_listing_the_whole_history_follows_the_cursor_until_it_runs_out(self):
        client, seen = self.paged([
            {"sandboxes": [{"id": "a"}],
             "next": {"created_at": "2024-01-01T00:00:00Z", "id": "a"}},
            {"sandboxes": [{"id": "b"}],
             "next": {"created_at": "2023-01-01T00:00:00Z", "id": "b"}},
            {"sandboxes": [{"id": "c"}], "next": None},
        ])
        self.assertEqual([s["id"] for s in client.sandboxes.list_all()], ["a", "b", "c"])
        self.assertEqual(len(seen), 3, "it must stop where the last page ends")
        self.assertIn("after_created_at=2024-01-01T00%3A00%3A00Z", seen[1])
        self.assertIn("after_id=a", seen[1])
        self.assertIn("after_created_at=2023-01-01T00%3A00%3A00Z", seen[2])

    def test_a_cursor_carrying_a_positive_offset_is_encoded_not_interpolated(self):
        """The cursor is not always ``Z``.

        A ``+00:00`` offset is what ``datetime.isoformat`` and most RFC3339
        writers produce, and a bare ``+`` in a query string decodes as a space.
        The page then arrives as ``2024-01-01T00:00:00 00:00``, the control
        plane refuses a cursor this caller never got wrong, and it does so on
        every page after the first -- so the walk that worked against a
        one-page tenant fails against a real history. Fixtures using ``Z`` pass
        through the same code without ever touching this.
        """
        client, seen = self.paged([
            {"sandboxes": [{"id": "a"}],
             "next": {"created_at": "2024-01-01T00:00:00+00:00", "id": "a"}},
            {"sandboxes": [{"id": "b"}], "next": None},
        ])

        self.assertEqual([s["id"] for s in client.sandboxes.list_all()], ["a", "b"])
        self.assertIn("after_created_at=2024-01-01T00%3A00%3A00%2B00%3A00", seen[1])
        self.assertNotIn(
            "+00:00", seen[1],
            "a raw plus in the query is a space by the time the server decodes it",
        )

    def test_a_control_plane_that_repeats_a_cursor_cannot_walk_forever(self):
        """A cursor the walk has already followed stops the walk.

        ``list_all`` ends when the server says there is no next page, so on its
        own it has no way to end. A control plane that keeps handing back the
        same cursor makes it fetch forever -- the same defect the paging was
        added to stop, one layer down. The stub refuses past a few requests so
        that a walk which does not stop fails here in a second instead of
        spinning until the suite is killed.
        """
        client = a_client()
        seen = []

        def request(method, path, payload=None, *, timeout=120):
            seen.append(path)
            if len(seen) > 5:
                raise AssertionError(
                    f"the walk made {len(seen)} requests without stopping"
                )
            return {"sandboxes": [{"id": "a"}],
                    "next": {"created_at": "2024-01-01T00:00:00Z", "id": "a"}}

        client._request = request
        with self.assertRaises(ValueError):
            client.sandboxes.list_all()
        self.assertEqual(len(seen), 2, "it must stop, not keep re-fetching")

    def test_an_empty_page_with_a_cursor_is_refused_not_repeated(self):
        """An empty page names nothing to advance past.

        A cursor describes where the next page begins. With nothing in this
        one, following it can only return the same nothing, so the walk would
        issue requests without ever making progress. As above, the stub refuses
        past a few requests so an unbounded walk fails here rather than
        spinning until the suite is killed.
        """
        client = a_client()
        seen = []

        def request(method, path, payload=None, *, timeout=120):
            seen.append(path)
            if len(seen) > 5:
                raise AssertionError(
                    f"the walk made {len(seen)} requests without stopping"
                )
            return {"sandboxes": [],
                    "next": {"created_at": "2024-01-01T00:00:00Z", "id": "a"}}

        client._request = request
        with self.assertRaises(ValueError):
            client.sandboxes.list_all()
        self.assertEqual(len(seen), 1, "the contradiction is the first page's")

    def test_a_cursor_without_both_halves_is_refused_before_the_request(self):
        client, seen = self.paged([{"sandboxes": [], "next": None}])
        for cursor in ({"created_at": "2024-01-01T00:00:00Z"}, {"id": "a"}, {}):
            with self.assertRaises(ValueError):
                client.sandboxes.list_after(cursor)
        self.assertEqual(seen, [], "a half cursor must not become a request")


class ClientContractTest(unittest.TestCase):
    def test_context_manager_and_file_operations_use_api_contract(self):
        client = AIec(api_key="af_live_" + "0" * 48, base_url="http://example")
        sandbox = Sandbox(client, {"id": "sandbox-1"})
        calls = []

        def request(method, path, payload=None, *, timeout=120):
            calls.append((method, path, payload))
            if method == "DELETE":
                return None
            if method == "GET" and path.endswith("/files/content?path=%2Fworkspace%2Fproof.txt"):
                return {"content_base64": base64.b64encode(b"proof").decode()}
            return {"ok": True}

        client._request = request
        with sandbox as box:
            box.write_file("/workspace/proof.txt", b"proof")
            self.assertEqual(box.read_file("/workspace/proof.txt"), b"proof")
            box.make_directory("/workspace/subdir")
            box.list_files()
            box.delete_file("/workspace/proof.txt")
        self.assertEqual(calls[0][:2], ("PUT", "/v1/sandboxes/sandbox-1/files"))
        self.assertEqual(calls[-2][:2], ("DELETE", "/v1/sandboxes/sandbox-1/files?path=%2Fworkspace%2Fproof.txt"))
        self.assertEqual(calls[-1][:2], ("DELETE", "/v1/sandboxes/sandbox-1"))
        self.assertEqual(json.loads(json.dumps(calls[0][2]))["path"], "/workspace/proof.txt")


class SandboxBudgetTest(unittest.TestCase):
    """A client that gives up first does not stop anything.

    The server's own bounds are the ceiling on each of these calls, and the
    budget has to be *above* the server's bound so the server is always the one
    that gives up -- otherwise the caller is told the work failed while it is
    still running inside a sandbox the caller believes is fine.
    """

    def setUp(self):
        self.transport = RecordingTransport()
        self.client = a_client()
        self.client._request = self.transport
        self.sandbox = Sandbox(self.client, {"id": "sandbox-1"})

    def test_a_command_given_fifteen_minutes_is_not_cut_at_the_general_default(self):
        # `validate_exec` accepts timeout_seconds up to MAX_EXEC_SECONDS
        # (crates/aiec-core/src/lib.rs), so 900 is a command the control plane
        # will happily run for a quarter of an hour.
        self.sandbox.exec("pytest -q", timeout_seconds=900)
        self.assertGreaterEqual(self.transport.last_timeout, 900)
        self.assertNotEqual(self.transport.last_timeout, DEFAULT_REQUEST_TIMEOUT_SECONDS)
        # The server kills the command at 900 and only then answers, so the wait
        # is the command's own budget plus slack.
        self.assertEqual(self.transport.last_timeout, 900 + EXEC_RESPONSE_SLACK_SECONDS)

    def test_a_command_with_no_timeout_of_its_own_waits_out_the_server_default(self):
        # `default_exec_timeout` is 60 s in crates/aiec-core/src/lib.rs. Absent
        # or zero falls back to that rather than to zero: `validate_exec`
        # refuses a zero timeout, so waiting zero seconds is wrong either way.
        self.sandbox.exec("true")
        absent = self.transport.last_timeout
        self.sandbox.exec("true", timeout_seconds=0)
        zero = self.transport.last_timeout
        self.assertEqual(absent, DEFAULT_EXEC_SECONDS + EXEC_RESPONSE_SLACK_SECONDS)
        self.assertEqual(zero, absent)

    def test_a_command_is_waited_out_for_the_ceiling_the_server_validates(self):
        # The ceiling, not the default: a caller who asked for the most the API
        # allows has to be waited out for all of it.
        self.sandbox.exec("true", timeout_seconds=MAX_EXEC_SECONDS)
        self.assertEqual(self.transport.last_timeout, MAX_EXEC_SECONDS + EXEC_RESPONSE_SLACK_SECONDS)

    def test_an_artifact_upload_outlasts_the_servers_upload_deadline(self):
        # artifact_gc::MAX_ARTIFACT_UPLOAD_SECONDS is the API's own deadline on
        # an upload (crates/aiec-api), so the client waits longer than that.
        self.sandbox.upload_artifact("report.txt", b"report")
        self.assertGreaterEqual(self.transport.last_timeout, MAX_ARTIFACT_UPLOAD_SECONDS)

    def test_a_snapshot_outlasts_the_general_default(self):
        # Capturing a snapshot freezes a machine and uploads it, which is longer
        # than anything else on the sandbox surface.
        self.sandbox.snapshot()
        self.assertGreaterEqual(self.transport.last_timeout, SNAPSHOT_TIMEOUT_SECONDS)
        self.assertGreater(SNAPSHOT_TIMEOUT_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS)

    def test_provisioning_listing_and_teardown_are_not_waits_of_the_default_length(self):
        # `POST /v1/sandboxes` blocks through placement, boot and a repository
        # clone; listing joins every machine's state; destroying reclaims a
        # machine. None of them is a short read.
        self.client.sandboxes.create(image="python:3.13")
        self.assertGreaterEqual(self.transport.last_timeout, SANDBOX_PROVISION_TIMEOUT_SECONDS)
        self.client.sandboxes.list()
        self.assertGreaterEqual(self.transport.last_timeout, LIST_TIMEOUT_SECONDS)
        self.sandbox.destroy()
        self.assertGreaterEqual(self.transport.last_timeout, DESTROY_TIMEOUT_SECONDS)


class SandboxTeardownTest(unittest.TestCase):
    """The body's failure is the one the caller's `except` has to see."""

    def sandbox_that_cannot_be_destroyed(self):
        client = a_client()
        client._request = RecordingTransport(
            fail=AIecError(500, {"error": {"code": "sandbox_gone", "message": "already gone"}})
        )
        return Sandbox(client, {"id": "sandbox-1"})

    def test_a_teardown_failure_does_not_replace_the_body_s_exception(self):
        sandbox = self.sandbox_that_cannot_be_destroyed()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(ValueError) as raised:
                with sandbox:
                    raise ValueError("the task failed")
        # The body raised, and the teardown failing on top of it must not become
        # the exception that propagates: that is the one the caller catches and
        # logs, and the sandbox that had already timed out explains nothing
        # about why the block failed.
        self.assertIsInstance(raised.exception, ValueError)
        self.assertEqual(str(raised.exception), "the task failed")
        # It is not hidden either: the teardown failure is recorded on the box
        # and warned about, so the lost machine is still visible.
        self.assertIsInstance(sandbox.teardown_error, AIecError)
        self.assertEqual(
            len([w for w in caught if issubclass(w.category, RuntimeWarning)]), 1
        )

    def test_a_teardown_failure_still_surfaces_when_the_body_succeeded(self):
        sandbox = self.sandbox_that_cannot_be_destroyed()
        with self.assertRaises(AIecError):
            with sandbox:
                pass


class TransportFailureTest(unittest.TestCase):
    """`except AIecError` is the documented contract, so it has to hold."""

    @staticmethod
    def a_closed_port():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        # Bound and released: nothing is listening, so the connect is refused
        # rather than the request hanging.
        return port

    def test_a_refused_connection_is_an_aiec_error_not_a_url_error(self):
        client = a_client(base_url=f"http://127.0.0.1:{self.a_closed_port()}")
        with self.assertRaises(AIecError) as raised:
            client.usage()
        self.assertNotIsInstance(raised.exception, URLError)
        # No response ever arrived, so there is no status to report.
        self.assertEqual(raised.exception.status, 0)
        self.assertEqual(raised.exception.code, "transport_error")
        # The transport failure itself is kept as the cause: for a connection
        # error that is the diagnostic.
        self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_an_unresolvable_host_is_also_an_aiec_error(self):
        client = a_client(base_url="http://control.invalid.test")
        with self.assertRaises(AIecError):
            client.usage()


def rate_limited_by(retry_after):
    """The error one 429 carrying this `Retry-After` produces.

    Served over a real socket, because the header has to survive the whole
    transport for the client to read it.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(
                {"error": {"code": "rate_limited", "message": "slow down"}}
            ).encode()
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            if retry_after is not None:
                self.send_header("Retry-After", retry_after)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = a_client(base_url=f"http://127.0.0.1:{server.server_port}")
        try:
            client.usage()
        except AIecError as error:
            return error
        raise AssertionError("a 429 must surface as an AIecError")
    finally:
        server.shutdown()
        server.server_close()


class RateLimitedRetryAfterTest(unittest.TestCase):
    """RFC 9110 lets a gateway answer a 429 with either form of Retry-After."""

    def test_delta_seconds_is_read_as_seconds(self):
        self.assertEqual(rate_limited_by("42").retry_after, 42.0)

    def test_an_http_date_retry_after_yields_a_backoff_rather_than_nothing(self):
        # float("Wed, 21 Oct 2026 07:28:00 GMT") is a ValueError, so a date-form
        # header used to leave retry_after at None and leave a rate-limited
        # client free to retry as fast as it likes.
        when = datetime.now(timezone.utc) + timedelta(seconds=120)
        backoff = rate_limited_by(format_datetime(when, usegmt=True)).retry_after
        self.assertIsNotNone(backoff)
        self.assertGreater(backoff, 0)
        self.assertAlmostEqual(backoff, 120, delta=5)

    def test_the_documented_date_form_is_read_rather_than_dropped(self):
        self.assertIsInstance(
            rate_limited_by("Wed, 21 Oct 2099 07:28:00 GMT").retry_after, float
        )

    def test_an_unreadable_retry_after_is_no_retry_after(self):
        self.assertIsNone(rate_limited_by("whenever").retry_after)


if __name__ == "__main__":
    unittest.main()
