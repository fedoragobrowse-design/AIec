import base64
import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
class AIecError(RuntimeError):
    """An error returned by the AIec API.

    ``code`` is stable and machine-readable; ``request_id`` is echoed in the
    server logs, so quoting it makes a support report actionable.
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
        self.retry_after: float | None = getattr(self, "_retry_after", None)

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

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
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
            with urlopen(request, timeout=120) as response:
                body = response.read()
                return json.loads(body) if body else None
        except HTTPError as error:
            try:
                error_payload = json.loads(error.read())
            except Exception:
                error_payload = {"error": {"message": str(error)}}
            failure = AIecError(error.code, error_payload)
            # A rate-limited client must be able to back off without guessing.
            retry_after = error.headers.get("Retry-After") if error.headers else None
            if retry_after:
                try:
                    failure.retry_after = float(retry_after)
                except ValueError:
                    failure.retry_after = None
            raise failure from error

    def usage(self) -> Any:
        return self._request("GET", "/v1/usage")

    def sandbox(self, image: str = "python:3.13", **kwargs: Any) -> "Sandbox":
        """Create a sandbox for use as a context manager."""
        return self.sandboxes.create(image=image, **kwargs)


class _Sandboxes:
    def __init__(self, client: AIec):
        self.client = client

    def create(self, **kwargs: Any) -> "Sandbox":
        return Sandbox(self.client, self.client._request("POST", "/v1/sandboxes", kwargs))

    def list(self) -> Any:
        return self.client._request("GET", "/v1/sandboxes")


@dataclass
class Sandbox:
    client: AIec
    data: dict

    def __getattr__(self, name: str) -> Any:
        return self.data[name]

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.destroy()

    def exec(self, command: list[str] | str, **kwargs: Any) -> Any:
        argv = ["/bin/sh", "-lc", command] if isinstance(command, str) else command
        return self.client._request(
            "POST", f"/v1/sandboxes/{self.data['id']}/exec", {"command": argv, **kwargs}
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
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/snapshots", {})

    def stop(self) -> Any:
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/stop", {})

    def resume(self) -> Any:
        return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/resume", {})

    def destroy(self) -> Any:
        return self.client._request("DELETE", f"/v1/sandboxes/{self.data['id']}")

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
