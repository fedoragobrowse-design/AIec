import base64
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class AgentForgeError(RuntimeError):
    def __init__(self, status: int, payload: Any):
        self.status = status
        self.payload = payload
        message = payload.get("error", {}).get("message", str(payload)) if isinstance(payload, dict) else str(payload)
        super().__init__(message)


class AgentForge:
    def __init__(self, api_key: str, base_url: str = "http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.sandboxes = _Sandboxes(self)

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
        data = None if payload is None else __import__("json").dumps(payload).encode()
        request = Request(self.base_url + path, data=data, method=method, headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=120) as response:
                return __import__("json").loads(response.read())
        except HTTPError as error:
            try:
                payload = __import__("json").loads(error.read())
            except Exception:
                payload = {"error": {"message": str(error)}}
            raise AgentForgeError(error.code, payload) from error

    def usage(self): return self._request("GET", "/v1/usage")


class _Sandboxes:
    def __init__(self, client: AgentForge): self.client = client
    def create(self, **kwargs): return Sandbox(self.client, self.client._request("POST", "/v1/sandboxes", kwargs))
    def list(self): return self.client._request("GET", "/v1/sandboxes")


@dataclass
class Sandbox:
    client: AgentForge
    data: dict

    def __getattr__(self, name: str) -> Any: return self.data[name]
    def exec(self, command: str, **kwargs): return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/exec", {"command": ["/bin/sh", "-lc", command], **kwargs})
    def write_file(self, path: str, content: str | bytes, mode: int | None = None):
        raw = content if isinstance(content, bytes) else content.encode()
        payload = {"path": path, "content_base64": base64.b64encode(raw).decode()}
        if mode is not None: payload["mode"] = mode
        return self.client._request("PUT", f"/v1/sandboxes/{self.data['id']}/files", payload)
    def read_file(self, path: str):
        from urllib.parse import quote
        value = self.client._request("GET", f"/v1/sandboxes/{self.data['id']}/files/content?path={quote(path)}")
        return base64.b64decode(value["content_base64"])
    def snapshot(self): return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/snapshots", {})
    def stop(self): return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/stop", {})
    def resume(self): return self.client._request("POST", f"/v1/sandboxes/{self.data['id']}/resume", {})
    def destroy(self): return self.client._request("DELETE", f"/v1/sandboxes/{self.data['id']}")
