"""A minimal MCP client, for the one measurement the HTTP API cannot make.

The OMP comparison lives behind the local MCP server's ``aiec_compare_omp``
tool, and that is where it belongs: the adapter that expands an OMP request into
ordinary runs is the same code an agent uses, and re-implementing it in a
benchmark would be measuring the benchmark.

The transport is Streamable HTTP with plain JSON replies, which the server
configures explicitly, so a call is one POST per JSON-RPC message. The session
header is carried if the server issues one, and notifications - which answer 202
with no body - are tolerated.

The bearer token is the MCP server's own local token: read from
``AIEC_MCP_TOKEN`` or ``~/.config/aiec/mcp-token``, never from a command-line
flag, and scrubbed out of any message before it is stored.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .client import TransportError

USER_AGENT = "aiec-bench/1"

#: Where `aiec-mcp` stores the token it generates on first run.
DEFAULT_TOKEN_PATH = Path("~/.config/aiec/mcp-token").expanduser()

PROTOCOL_VERSION = "2025-06-18"


class McpError(RuntimeError):
    """The MCP server refused the call, or answered with something unusable."""


def resolve_token(explicit: str | None = None) -> str:
    """The MCP token, from a file, the environment, or the default location.

    Resolution order is deliberate: an explicit file wins, then the environment,
    then the file the server wrote. A token is never read from a flag, because a
    flag is visible in every process listing on the host.
    """
    if explicit:
        path = Path(explicit).expanduser()
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise McpError(f"cannot read the MCP token from {path}: {error}") from error
    from_env = os.environ.get("AIEC_MCP_TOKEN", "").strip()
    if from_env:
        return from_env
    try:
        return DEFAULT_TOKEN_PATH.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise McpError(
            "no MCP token: set AIEC_MCP_TOKEN, or pass --mcp-token-file pointing at the "
            f"file aiec-mcp printed ({DEFAULT_TOKEN_PATH})"
        ) from error


class McpClient:
    """Just enough MCP to call one tool and read its structured result."""

    def __init__(self, url: str, token: str, *, timeout: float = 3600.0) -> None:
        self.url = url
        self._token = token
        self.timeout = timeout
        self.session_id: str | None = None
        self._next_id = 0

    def redact(self, message: str) -> str:
        return message.replace(self._token, "***redacted***") if self._token else message

    def initialize(self) -> dict[str, Any]:
        """The handshake, so the server knows which protocol version is speaking."""
        return self.rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "aiec-bench", "version": "1.0.0"},
            },
        )

    def initialized(self) -> None:
        """The notification that follows the handshake. No reply is expected."""
        self.notify("notifications/initialized")

    def call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[Any, float]:
        """Call a tool, returning its structured payload and how long it took."""
        started = time.perf_counter()
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        seconds = time.perf_counter() - started
        return _payload(result, name, self.redact), seconds

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}}, expect_reply=False)

    def rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        message = self._post(
            {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        )
        if "error" in message:
            raise McpError(f"{method} failed: {self.redact(json.dumps(message['error'])[:400])}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise McpError(f"{method} returned no result object")
        return result

    def _post(self, message: dict[str, Any], *, expect_reply: bool = True) -> dict[str, Any]:
        payload = json.dumps(message).encode()
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            # The protocol requires both: a client that accepts only JSON still
            # has to be willing to read the event stream the server may choose.
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "User-Agent": USER_AGENT,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        request = urllib.request.Request(self.url, data=payload, method="POST", headers=headers)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                session = response.headers.get("mcp-session-id")
                if session:
                    self.session_id = session
        except urllib.error.HTTPError as error:
            body = error.read()[:400]
            raise McpError(
                self.redact(f"MCP POST failed: {error.code} {body!r}")
            ) from error
        except (urllib.error.URLError, OSError) as error:
            raise TransportError(
                self.redact(f"MCP POST {self.url}: {error}"), time.perf_counter() - started
            ) from error

        if not expect_reply:
            return {}
        return _decode(raw, self.redact)


def _decode(raw: bytes, scrub) -> dict[str, Any]:
    """A JSON reply, or the first message of an event stream."""
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        raise McpError("the MCP server answered with an empty body")
    if text.startswith("{"):
        return _json(text, scrub)
    for line in text.splitlines():
        if line.startswith("data:"):
            return _json(line[5:].strip(), scrub)
    raise McpError(f"unrecognised MCP reply: {scrub(text[:200])}")


def _json(text: str, scrub) -> dict[str, Any]:
    try:
        message = json.loads(text)
    except json.JSONDecodeError as error:
        raise McpError(f"the MCP server sent invalid JSON: {scrub(text[:200])}") from error
    if not isinstance(message, dict):
        raise McpError("the MCP server sent a JSON value that was not an object")
    return message


def _payload(result: dict[str, Any], tool: str, scrub) -> Any:
    """The tool's own result, parsed out of the MCP envelope.

    The server renders structured results as pretty-printed JSON inside a text
    content block, which is what a benchmark can measure; anything else is
    returned verbatim so an unexpected shape is visible rather than swallowed.
    """
    if result.get("isError"):
        raise McpError(f"{tool} reported an error: {scrub(_text(result))[:600]}")
    text = _text(result)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw_text": text[:2000]}


def _text(result: dict[str, Any]) -> str:
    parts: list[str] = []
    for block in result.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "\n".join(parts)
