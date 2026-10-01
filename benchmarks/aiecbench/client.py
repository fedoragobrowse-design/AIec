"""The one HTTP client every scenario uses.

Why not the SDK: the SDK is the right thing for a program that wants sandboxes,
and the wrong thing for a stopwatch. Measurement needs three things the SDK does
not expose - per-request wall time, ``Retry-After`` handling at the transport
level, and the ability to pin a private CA. So the harness speaks the same wire
protocol the SDK speaks, to the same documented routes. Nothing here invents an
endpoint or a field; every path it calls is in ``docs/API.md``.

Three things it will not do:

* **Put a credential on a command line.** The key comes from a file, the
  environment, or an interactive prompt, and it is scrubbed out of every message
  the harness prints.
* **Retry a run submission.** ``POST /v1/runs`` carries no idempotency key here,
  so a transport failure after the body was sent is a run that may be running.
  Only the rate limiter's own 429 is retried automatically, because that is a
  rejection before any work happened.
* **Measure the limiter and call it the control plane.** A tenant is limited to a
  sustained request rate; the client can pace itself below it, and every 429 it
  absorbs is counted and reported.
"""

from __future__ import annotations

import dataclasses
import json
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "aiec-bench/1"


class TransportError(RuntimeError):
    """The request never produced a status line.

    Carries the elapsed time anyway: a run whose submission timed out took the
    whole timeout to fail, and dropping that number would quietly flatter the
    control plane.
    """

    def __init__(self, message: str, seconds: float) -> None:
        super().__init__(message)
        self.seconds = seconds


@dataclasses.dataclass
class Response:
    """One HTTP exchange, timed end to end including reading the body."""

    status: int
    body: Any
    seconds: float
    headers: dict[str, str]
    method: str
    path: str
    #: How many requests it took, including any rate-limited retry.
    attempts: int = 1
    #: A 429 was absorbed while producing this response.
    rate_limited: bool = False
    #: Every non-2xx status that was retried away rather than returned. A
    #: ``503, 503, 200`` read is one 200 to the caller, and without this the
    #: control plane's refusals are invisible to everything but the client.
    retried_statuses: list[int] = dataclasses.field(default_factory=list)
    #: The body as text, for endpoints that answer in Prometheus format rather
    #: than JSON. ``None`` unless the caller asked for it.
    text: str | None = None

    @property
    def ok(self) -> bool:
        return self.status < 400

    def error_code(self) -> str:
        """The machine-readable failure code, or ``unknown``."""
        if isinstance(self.body, dict):
            error = self.body.get("error")
            if isinstance(error, dict):
                code = error.get("code")
                if isinstance(code, str):
                    return code
        return "unknown"

    def error_message(self) -> str:
        if isinstance(self.body, dict):
            error = self.body.get("error")
            if isinstance(error, dict):
                message = error.get("message")
                if isinstance(message, str):
                    return message
        return ""


class Client:
    """An authenticated client for one control plane."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        ca: str | None = None,
        insecure: bool = False,
        timeout: float = 120.0,
        max_retries: int = 2,
        min_interval: float = 0.0,
        backoff_cap: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._secret = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_cap = backoff_cap
        # Pacing keeps the harness from measuring the tenant rate limiter. The
        # control plane admits 20 rps sustained by default; the harness runs
        # slower than that unless told otherwise.
        self.min_interval = max(0.0, min_interval)
        self.denials = 0
        self.requests = 0
        self._lock = threading.Lock()
        self._last_start = 0.0

        if insecure:
            # Opt-in, never the default, and said out loud. Python's TLS is
            # stricter than curl's about a self-signed CA with no keyUsage
            # extension, so a throwaway test cluster needs this; a real
            # deployment must not have it.
            print(
                "WARNING: TLS verification is disabled for this benchmark. Never use this "
                "against anything but a throwaway test cluster.",
                file=sys.stderr,
            )
            self.context: ssl.SSLContext | None = ssl._create_unverified_context()
            self.tls_mode = "insecure"
        elif ca:
            self.context = ssl.create_default_context(cafile=ca)
            self.tls_mode = f"ca:{ca}"
        else:
            self.context = None
            self.tls_mode = "system-trust-store"

    # -- credentials ----------------------------------------------------

    def redact(self, message: str) -> str:
        """Remove the API key from anything about to be printed or stored."""
        if not self._secret:
            return message
        return message.replace(self._secret, "***redacted***")

    def describe(self) -> dict[str, Any]:
        """How this client was configured, for the report header.

        The key itself is not here and never will be; only where it came from.
        """
        return {
            "base_url": self.base_url,
            "tls": self.tls_mode,
            "requests": self.requests,
            "rate_limit_429s": self.denials,
        }

    # -- requests -------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        text: bool = False,
    ) -> Response:
        """One call, retried only where retrying cannot duplicate work."""
        idempotent = method.upper() in {"GET", "HEAD", "DELETE"}
        attempt = 0
        #: The non-2xx statuses already retried away for this call, so they
        #: reach the report instead of vanishing with the loop.
        retried: list[int] = []
        rate_limited = False
        while True:
            attempt += 1
            self._pace()
            started = time.perf_counter()
            status, raw, headers = self._send(method, path, body, timeout or self.timeout)
            seconds = time.perf_counter() - started
            with self._lock:
                self.requests += 1
            response = Response(
                status=status,
                body=_parse(raw),
                seconds=seconds,
                headers=headers,
                method=method.upper(),
                path=path,
                attempts=attempt,
                rate_limited=rate_limited,
                retried_statuses=retried,
                text=raw.decode("utf-8", "replace") if text else None,
            )

            if response.status == 429 and attempt <= self.max_retries:
                # The limiter rejected the request before any work started, so
                # honouring it cannot duplicate a run. Anything else would be a
                # guess about work that may already be happening.
                wait = _retry_after(headers) or min(2.0 ** (attempt - 1), self.backoff_cap)
                with self._lock:
                    self.denials += 1
                retried.append(response.status)
                rate_limited = True
                time.sleep(min(wait, self.backoff_cap))
                continue
            if response.status in {502, 503, 504} and idempotent and attempt <= self.max_retries:
                retried.append(response.status)
                time.sleep(min(0.5 * attempt, self.backoff_cap))
                continue
            return response

    def _pace(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            wait = self._last_start + self.min_interval - time.perf_counter()
            if wait > 0:
                time.sleep(wait)
            self._last_start = time.perf_counter()

    def _send(
        self, method: str, path: str, body: dict[str, Any] | None, timeout: float
    ) -> tuple[int, bytes, dict[str, str]]:
        payload = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=payload,
            method=method.upper(),
            headers={
                "Authorization": f"Bearer {self._secret}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=self.context) as response:
                return response.status, response.read(), _headers(response)
        except urllib.error.HTTPError as error:
            # An HTTP status is a result, not an exception: a 429 or a 503 is
            # something the benchmark has to count.
            return error.code, error.read() or b"", _headers(error)
        except urllib.error.URLError as error:
            raise TransportError(
                self.redact(f"{method.upper()} {path}: {error.reason}"),
                time.perf_counter() - started,
            ) from error
        except (TimeoutError, OSError) as error:
            raise TransportError(
                self.redact(f"{method.upper()} {path}: {error}"),
                time.perf_counter() - started,
            ) from error

    def close(self) -> None:
        """Nothing is held open between calls; present so callers need not care."""

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _headers(source: Any) -> dict[str, str]:
    try:
        return {key.lower(): value for key, value in source.headers.items()}
    except AttributeError:
        return {}


def _parse(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _retry_after(headers: dict[str, str]) -> float | None:
    """The limiter's own back-off, in seconds."""
    value = headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
