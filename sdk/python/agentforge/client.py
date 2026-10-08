"""The sandbox surface of the AIec API, and the transport under it.

The budgets below are not tuning: each one is derived from a bound the control
plane itself enforces, and each is deliberately *longer* than that bound, so
the server is always the one that gives up first. A client that gives up first
does not cancel anything -- the command keeps running inside a sandbox the
caller has been told is fine, which is the expensive failure.
"""

import base64
import json
import os
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    """Refuse to follow a redirect, and say so as an API error.

    ``urllib``'s default handler forwards the ``Authorization`` header to
    whatever host a 30x names, across origins, and rewrites the method to GET
    while discarding the body. So a control plane that answers a redirect -- a
    compromised or misconfigured one, or one behind a proxy that rewrites a
    path to an SSO login -- is handed the caller's API key in full, and the
    caller receives a ``200`` from a host it never meant to talk to. Measured
    against a 302 to a second listener on the same machine: the token arrived
    verbatim, and ``HTTPRedirectHandler`` contains no ``Authorization``
    handling at all, so nothing in the stdlib would have stripped it.

    The API has no legitimate use for a redirect, so following one is never
    right here regardless of where it points.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _no_redirect_opener():
    """An opener that reports a redirect as a failure instead of following it.

    Returning ``None`` from ``redirect_request`` makes ``open`` raise
    ``HTTPError``, which ``_request`` already maps onto ``AIecError`` carrying
    the status, so the redirect is visible as a failed call rather than as a
    successful one from an unintended host.
    """
    return build_opener(_NoRedirect)


from .runs import MAX_LIST_LIMIT, Runs, _listed
from .evals import Evals

#: What the control plane gives a command that states no timeout of its own
#: (``default_exec_timeout`` in crates/aiec-core/src/lib.rs). An exec that
#: states none has to be waited out for this long.
DEFAULT_EXEC_SECONDS = 60

#: The ceiling on a command's own timeout, as the control plane validates it:
#: ``validate_exec`` refuses ``timeout_seconds`` of zero or above
#: ``MAX_EXEC_SECONDS`` (crates/aiec-core/src/lib.rs). This is the ceiling, not
#: the 60 s default, because a client cannot read the caller's intended budget
#: out of the request and would otherwise time out against a caller who asked
#: for an hour and got a validated one.
MAX_EXEC_SECONDS = 3_600

#: What the wait adds on top of the command's own timeout. The control plane
#: kills the command at its deadline and *then* has to answer, so the wait has
#: to exceed the timeout or the client abandons an exec the server is about to
#: report. Same reasoning as ``RUN_RESPONSE_SLACK_SECONDS`` in runs.py.
EXEC_RESPONSE_SLACK_SECONDS = 120

#: How long an artifact upload may take server-side, from
#: ``artifact_gc::MAX_ARTIFACT_UPLOAD_SECONDS`` (crates/aiec-api), which the
#: API's artifact routes apply as their own deadline.
MAX_ARTIFACT_UPLOAD_SECONDS = 300

#: ...plus the round trip and the storage write the handler does after the
#: upload itself, so the upload is never the thing that gives up first.
ARTIFACT_UPLOAD_SLACK_SECONDS = 60

#: ``POST /v1/sandboxes`` blocks through the whole of provisioning: placement,
#: boot, and the clone of the task's git repository when one is asked for.
#: There is no small deadline on it server-side, and a repository is exactly
#: the thing that takes minutes, so the budget is the longest single operation
#: the API allows plus the upload that may follow it.
SANDBOX_PROVISION_TIMEOUT_SECONDS = MAX_EXEC_SECONDS + MAX_ARTIFACT_UPLOAD_SECONDS

#: Capturing a snapshot freezes the sandbox and uploads what it froze, so it is
#: at least as long as the longest operation the API allows, with the same
#: slack above it.
SNAPSHOT_TIMEOUT_SECONDS = SANDBOX_PROVISION_TIMEOUT_SECONDS + EXEC_RESPONSE_SLACK_SECONDS

#: Teardown is a machine being reclaimed, not a command being run: the same
#: wait ``Runs.cancel`` takes for the same reason
#: (``CANCEL_TIMEOUT_SECONDS`` in runs.py).
DESTROY_TIMEOUT_SECONDS = 300

#: Listing a tenant's sandboxes joins each one's machine state, so it is a
#: query over the whole inventory rather than a single record. Bounded, but not
#: the budget for a call that reads one thing.
LIST_TIMEOUT_SECONDS = 300

#: The budget for the control-plane calls that are genuinely short: read one
#: run, write one file, read one file's content. Anything the server may hold
#: for minutes states its own budget above.
DEFAULT_REQUEST_TIMEOUT_SECONDS = 120


def _exec_timeout(stated: Any) -> float:
    """How long to wait for a command the caller may have given an hour to.

    The server kills a command at ``timeout_seconds`` and answers after that,
    so the wait is the command's own budget plus slack -- never the general
    default, which would cut a long command short and report a sandbox that is
    still running it. A stated value of zero (or none) falls back to the
    server's own default rather than to zero, because ``validate_exec`` refuses
    a zero timeout outright and a client waiting zero seconds is wrong either
    way.
    """
    try:
        execution = int(stated)
    except (TypeError, ValueError):
        execution = 0
    if execution <= 0:
        execution = DEFAULT_EXEC_SECONDS
    return min(MAX_EXEC_SECONDS, execution) + EXEC_RESPONSE_SLACK_SECONDS


def _retry_after_seconds(header: str | None) -> float | None:
    """The seconds a ``Retry-After`` header asks for, or ``None``.

    RFC 9110 permits two forms and a gateway uses both: delta-seconds and an
    HTTP-date. Parsing only the first drops the back-off exactly when the
    server gave the longest one -- a date is how a gateway says "not before
    this time" -- and a rate-limited client then retries as fast as it can,
    which is the opposite of what the header asked for. The date form is
    resolved with the stdlib's ``parsedate_to_datetime`` rather than by
    re-implementing the three accepted date spellings.
    """
    text = (header or "").strip()
    if not text:
        return None
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    # A date with no zone is GMT by definition (RFC 9110), and comparing a
    # naive datetime against an aware one raises rather than falling back.
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())

class AIecError(RuntimeError):
    """An error returned by the AIec API.

    ``code`` is stable and machine-readable; ``request_id`` is echoed in the
    server logs, so quoting it makes a support report actionable.
    A failure that never reached the control plane is raised as one of these
    as well -- a refused connection, an unresolvable host, a TLS failure, a
    reset or a socket timeout -- because a caller catching ``AIecError`` is
    catching this API's failures. Those carry ``status`` 0, since there was no
    response to carry a status, and keep the original error as their cause.
    """

    def __init__(self, status: int, payload: Any):
        self.status = status
        self.payload = payload
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        self.code: str | None = error.get("code")
        self.request_id: str | None = error.get("request_id")
        message = error.get("message", str(payload))
        super().__init__(message)
        # 429 carries a Retry-After so a client can back off without guessing.
        # Initialised here rather than read off an attribute nobody has set
        # yet: the header only arrives with the transport failure, so
        # `_request` writes it after construction.
        self.retry_after: float | None = None

    def __str__(self) -> str:
        base = super().__str__()
        parts = [base]
        if self.code:
            parts.append(f"code={self.code}")
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        return " | ".join(parts)


class AIec:
    """Client for the AIec API.

    AIec is open source and self-hosted, so the default points at a control
    plane on this machine. A control plane elsewhere is selected with
    ``base_url`` or the ``AIEC_URL`` environment variable; the API and the
    methods are the same either way.
    """

    #: A control plane on this machine. There is no hosted default, because
    #: there is no hosted AIec.
    DEFAULT_BASE_URL = "http://127.0.0.1:8080"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        resolved = base_url or os.environ.get("AIEC_URL") or self.DEFAULT_BASE_URL
        self.base_url = resolved.rstrip("/")
        self.api_key = api_key or os.environ.get("AIEC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "set api_key or AIEC_API_KEY; create a key against your own "
                "control plane with `aiec key create`"
            )
        self.sandboxes = _Sandboxes(self)
        self.runs = Runs(self)
        self.evals = Evals(self)

    def _request(
        self, method: str, path: str, payload: dict | None = None, *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ) -> Any:
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with _no_redirect_opener().open(request, timeout=timeout) as response:
                body = response.read()
                status = response.status
                if not body:
                    return None
                try:
                    return json.loads(body)
                except ValueError as error:
                    # A 2xx whose body is not JSON is not the caller's success,
                    # and letting `JSONDecodeError` out breaks the one
                    # guarantee the exception types exist to make: that a
                    # failure arrives as `AIecError`. `JSONDecodeError` is a
                    # `ValueError`, so `except AIecError` misses it entirely
                    # and a caller handling this API's failures watches it go
                    # past. An intermediary answering with an HTML page is the
                    # ordinary way to get here -- a captive portal or a proxy
                    # error page is a 200 with text in it. The body is left
                    # out of the message so arbitrary server text is not
                    # copied into the caller's logs.
                    raise AIecError(
                        status,
                        {
                            "error": {
                                "code": "invalid_response",
                                "message": (
                                    f"{method} {path}: the control plane "
                                    f"answered {status} with a body that is "
                                    f"not JSON"
                                ),
                            }
                        },
                    ) from error
        except HTTPError as error:
            try:
                error_payload = json.loads(error.read())
            except Exception:
                error_payload = {"error": {"message": str(error)}}
            failure = AIecError(error.code, error_payload)
            # A rate-limited client must be able to back off without guessing,
            # in either of the two forms RFC 9110 lets a gateway answer with.
            headers = error.headers
            failure.retry_after = _retry_after_seconds(
                headers.get("Retry-After") if headers else None
            )
            raise failure from error
        except (URLError, OSError) as error:
            # Connection refused, DNS failure, TLS failure, a reset and the
            # socket timeout `urlopen` raises are all `OSError`s and never an
            # `HTTPError`, so without this they escape the documented
            # `except AIecError` as an unrelated type while a caller believes
            # it is handling this API's failures. Status 0 says "never reached
            # the control plane": there was no response to carry one. The
            # original is kept as the cause, which is the diagnostic that
            # matters for a transport failure.
            raise AIecError(
                0,
                {
                    "error": {
                        "code": "transport_error",
                        "message": f"{method} {path}: {error}",
                    }
                },
            ) from error

    def usage(self) -> Any:
        return self._request("GET", "/v1/usage")

    def sandbox(self, image: str = "python:3.13", **kwargs: Any) -> "Sandbox":
        """Create a sandbox for use as a context manager."""
        return self.sandboxes.create(image=image, **kwargs)


@dataclass
class SandboxPage:
    """One bounded page of sandboxes, and where the next one starts.

    ``next`` is ``None`` exactly when this is the last page. A caller that
    stops reading has stopped where the page ended and can say so; there is no
    silent truncation to discover later.
    """

    client: "AIec"
    data: dict

    @property
    def sandboxes(self) -> list:
        return self.data["sandboxes"]

    @property
    def next(self) -> dict | None:
        return self.data.get("next")

    def __len__(self) -> int:
        return len(self.sandboxes)

    def __iter__(self):
        return iter(self.sandboxes)


class _Sandboxes:
    def __init__(self, client: AIec):
        self.client = client

    def create(self, **kwargs: Any) -> "Sandbox":
        # Provisioning, not a control-plane read: the server places a machine,
        # boots it and clones the repository before it answers.
        return Sandbox(
            self.client,
            self.client._request(
                "POST", "/v1/sandboxes", kwargs,
                timeout=SANDBOX_PROVISION_TIMEOUT_SECONDS,
            ),
        )

    def list(self, limit: int = MAX_LIST_LIMIT) -> "SandboxPage":
        """One page of the caller's sandboxes, newest first.

        The control plane answers a bounded page and names the cursor its
        successor starts at, so this hands both back: ``sandboxes`` is what the
        page held and ``next`` is where the rest begins. A ``limit`` the control
        plane would clamp is refused rather than quietly reduced -- a page
        smaller than asked for, with no error, is indistinguishable from a
        short history.
        """
        page = _listed(limit)
        return SandboxPage(
            self.client,
            self.client._request(
                "GET", f"/v1/sandboxes?limit={page}", timeout=LIST_TIMEOUT_SECONDS
            ),
        )

    def list_all(self, limit: int = MAX_LIST_LIMIT) -> list:
        """Every sandbox, following the cursor until the history is exhausted.

        Each request is bounded. The caller has asked for the whole list and is
        prepared to hold it, so the cost is their history rather than one
        response the control plane had to build in full.
        """
        collected: list = []
        cursor = None
        seen: list = []
        while True:
            page = (
                self.list(limit)
                if cursor is None
                else self.list_after(cursor, limit)
            )
            # The walk is bounded by the server saying it is done, so it needs
            # its own termination guarantee. A control plane that keeps offering
            # a cursor without advancing past it turns this into an unbounded
            # request loop -- the same defect the paging was added to stop, one
            # layer down, and it never ends on its own.
            nxt = page.next
            if nxt is not None:
                position = (nxt["created_at"], nxt["id"])
                if position in seen:
                    raise ValueError(
                        f"GET /v1/sandboxes returned the cursor {nxt['id']} twice; "
                        "the page walk was stopped rather than repeated"
                    )
                if not page.sandboxes:
                    raise ValueError(
                        "GET /v1/sandboxes returned an empty page and a cursor "
                        f"({nxt['id']}); there is nothing to advance past"
                    )
                seen.append(position)
            collected.extend(page.sandboxes)
            if nxt is None:
                return collected
            cursor = nxt

    def list_after(self, cursor: dict, limit: int = MAX_LIST_LIMIT) -> "SandboxPage":
        """The page starting where ``cursor`` says."""
        page = _listed(limit)
        if not isinstance(cursor, dict) or "created_at" not in cursor or "id" not in cursor:
            raise ValueError("cursor is a page's next value, with created_at and id")
        return SandboxPage(
            self.client,
            self.client._request(
                "GET",
                f"/v1/sandboxes?limit={page}"
                f"&after_created_at={quote(str(cursor['created_at']), safe='')}"
                f"&after_id={quote(str(cursor['id']), safe='')}",
                timeout=LIST_TIMEOUT_SECONDS,
            ),
        )


@dataclass
class Sandbox:
    client: AIec
    data: dict

    def __getattr__(self, name: str) -> Any:
        # `__getattr__` only runs when normal lookup failed, so a missing key
        # must raise AttributeError, not KeyError: KeyError breaks hasattr()
        # and getattr-with-default, which callers rely on for optional fields.
        try:
            return self.data[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        """Destroy the sandbox, without replacing the body's own failure.

        A body that raised has already failed, and a teardown failure on top of
        it replaces the exception the caller's `except` catches: the reason the
        block failed survives only as `__context__` and the caller logs the
        teardown instead -- a sandbox that had already timed out reporting 5xx
        on the way out. So when the body failed, teardown errors are recorded
        on ``teardown_error`` and warned about rather than raised, and the
        body's exception is the one that propagates. When the body succeeded
        there is nothing to displace, so a teardown failure surfaces.
        """
        try:
            self.destroy()
        except Exception as error:
            if exc_type is None:
                raise
            self.teardown_error = error
            warnings.warn(
                f"the body of the with block failed and destroying sandbox "
                f"{self.data.get('id')!r} failed too: {error!r}",
                RuntimeWarning,
                stacklevel=2,
            )
        return False

    def exec(self, command: list[str] | str, **kwargs: Any) -> Any:
        argv = ["/bin/sh", "-lc", command] if isinstance(command, str) else command
        return self.client._request(
            "POST", f"/v1/sandboxes/{self.data['id']}/exec", {"command": argv, **kwargs},
            timeout=_exec_timeout(kwargs.get("timeout_seconds")),
        )

    def write_file(self, path: str, content: str | bytes, mode: int | None = None) -> Any:
        raw = content if isinstance(content, bytes) else content.encode()
        payload: dict[str, Any] = {
            "path": path,
            "content_base64": base64.b64encode(raw).decode(),
        }
        if mode is not None:
            payload["mode"] = mode
        return self.client._request("PUT", f"/v1/sandboxes/{self.data['id']}/files", payload)

    def read_file(self, path: str) -> bytes:
        value = self.client._request(
            "GET",
            f"/v1/sandboxes/{self.data['id']}/files/content?path={quote(path, safe='')}",
        )
        return base64.b64decode(value["content_base64"])


    def upload_artifact(self, name: str, content: str | bytes) -> Any:
        raw = content if isinstance(content, bytes) else content.encode()
        return self.client._request(
            "POST",
            f"/v1/sandboxes/{self.data['id']}/artifacts/{quote(name, safe='')}",
            {"content_base64": base64.b64encode(raw).decode()},
            # The server gives an upload `MAX_ARTIFACT_UPLOAD_SECONDS` of its
            # own, so the client waits longer than that and the upload is never
            # reported as failed while the server is still storing it.
            timeout=MAX_ARTIFACT_UPLOAD_SECONDS + ARTIFACT_UPLOAD_SLACK_SECONDS,
        )

    def pause(self) -> Any:
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/pause", {})

    def download_artifact(self, name: str) -> bytes:
        value = self.client._request(
            "GET", f"/v1/sandboxes/{self.data['id']}/artifacts/{quote(name, safe='')}"
        )
        return base64.b64decode(value["content_base64"])

    def delete_artifact(self, name: str) -> Any:
        return self.client._request(
            "DELETE", f"/v1/sandboxes/{self.data['id']}/artifacts/{quote(name, safe='')}"
        )

    def git_diff(self) -> Any:
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/git/diff", {})
    def snapshot(self) -> Any:
        # Capturing a snapshot means freezing a machine and uploading it, so it
        # takes longer than anything else here and has to be waited out as such.
        return self.client._request(
            "POST", f"/v1/sandboxes/{self.data['id']}/snapshots", {},
            timeout=SNAPSHOT_TIMEOUT_SECONDS,
        )

    def stop(self) -> Any:
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/stop", {})

    def resume(self) -> Any:
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/resume", {})

    def destroy(self) -> Any:
        # Reclaiming a machine is a teardown, not a read: the reply is as slow
        # as the destruction the server had to do before it answered.
        return self.client._request(
            "DELETE", f"/v1/sandboxes/{self.data['id']}",
            timeout=DESTROY_TIMEOUT_SECONDS,
        )

    def delete_file(self, path: str) -> Any:
        return self.client._request(
            "DELETE", f"/v1/sandboxes/{self.data['id']}/files?path={quote(path, safe='')}"
        )

    def make_directory(self, path: str) -> Any:
        return self.client._request(
            "POST", f"/v1/sandboxes/{self.data['id']}/files/mkdir", {"path": path}
        )

    def list_files(self, path: str = "/workspace") -> Any:
        return self.client._request(
            "GET", f"/v1/sandboxes/{self.data['id']}/files?path={quote(path, safe='')}"
        )
