"""Fakes shared by the harness tests.

A fake transport, not a mocked module: the retry loop, the response parsing and
the classification are the code under test, so the tests drive the real
:class:`~aiecbench.client.Client` and only replace the socket.
"""

from __future__ import annotations

import json
from typing import Any

from aiecbench.client import Client, Response

#: An error body in the shape the API documents.
ERROR_BODY: dict[str, Any] = {"error": {"code": "unavailable", "message": "try again later"}}


def error_body(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def response(
    status: int,
    body: Any,
    *,
    seconds: float = 0.01,
    method: str = "GET",
    path: str = "/v1/runs",
    attempts: int = 1,
    retried_statuses: list[int] | None = None,
) -> Response:
    return Response(
        status=status,
        body=body,
        seconds=seconds,
        headers={},
        method=method,
        path=path,
        attempts=attempts,
        retried_statuses=list(retried_statuses or []),
    )


class QueueClient:
    """A client that hands back prepared responses, in order.

    Used where the thing under test is the classification of a response, not
    the transport that produced it.
    """

    def __init__(self, responses: list[Response]) -> None:
        self._responses = list(responses)
        self.requests: list[tuple[str, str]] = []

    def request(self, method, path, body=None, *, timeout=None, text=False):  # noqa: ANN001
        self.requests.append((method, path))
        if not self._responses:
            raise AssertionError(f"no prepared response left for {method} {path}")
        return self._responses.pop(0)

    def redact(self, message: str) -> str:
        return message


class ScriptedClient(Client):
    """The real client, with ``_send`` replaced by a per-path script.

    Each path gets a list of statuses, consumed one per request; a path whose
    script runs out answers 200. Everything above the socket - the retry policy,
    the timing, the response fields - is the production code path.
    """

    def __init__(self, script: dict[str, list[int]], **kwargs: Any) -> None:
        # No backoff: a test should not sleep to prove a retry happened.
        kwargs.setdefault("backoff_cap", 0.0)
        super().__init__("https://bench.invalid", "test-key", **kwargs)
        self.script = {path: list(statuses) for path, statuses in script.items()}
        self.sent: list[int] = []

    def _send(self, method, path, body, timeout):  # noqa: ANN001
        remaining = self.script.get(path) or []
        status = remaining.pop(0) if remaining else 200
        self.sent.append(status)
        if status >= 400:
            return status, json.dumps(error_body("unavailable", "try again later")).encode(), {}
        return status, json.dumps([]).encode(), {}


class ListClient:
    """A client that answers every call with one prepared JSON body."""

    def __init__(self, body: Any, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.requests: list[tuple[str, str]] = []

    def request(self, method, path, body=None, *, timeout=None, text=False):  # noqa: ANN001
        self.requests.append((method, path))
        return response(self.status, self.body, method=method, path=path)

    def redact(self, message: str) -> str:
        return message


def sandboxes(*ids: str, state: str = "running") -> list[dict[str, Any]]:
    """A ``GET /v1/sandboxes`` body."""
    return [{"id": sandbox_id, "state": state} for sandbox_id in ids]
