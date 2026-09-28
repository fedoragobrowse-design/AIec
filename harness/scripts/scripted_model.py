#!/usr/bin/env python3
"""A scripted OpenAI-compatible model, for exercising the harness end to end.

It speaks just enough of the chat-completions shape for a real session: it reads
the tool results it is given, and on the next turn it either issues a tool call
or finishes. It is not a model, and it makes no claim to be one. What it is for
is proving the LOOP works: that observations come back, that the harness acts
on them, that validation is independent, and that the result is honest.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        LOG.append(body)
        messages = body.get("messages", [])

        # The turn is decided by which tools have actually been CALLED, read
        # from this script's own assistant turns. Keying on file CONTENT is the
        # obvious shortcut and it is wrong: reading a file reveals the very
        # strings a later step was going to search for.
        called = {
            call["function"]["name"]
            for message in messages
            if message.get("role") == "assistant"
            for call in (message.get("tool_calls") or [])
        }
        tool_results = [m for m in messages if m.get("role") == "tool"]

        def seen(needle):
            return any(needle in (m.get("content") or "") for m in tool_results)

        seen_read = "read" in called
        seen_write = "write" in called
        ran_tests = seen("OK") or seen("Ran ")

        if not seen_read:
            reply = {
                "content": None,
                "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "read",
                                 "arguments": json.dumps({"path": "calc.py"})},
                }],
            }
        elif not seen_write:
            # The real fix: distribute the remainder instead of dropping it.
            new_body = (
                "def split_bill(total, shares):\n"
                "    cents = round(total * 100)\n"
                "    each = cents // shares\n"
                "    parts = [each] * shares\n"
                "    parts[-1] += cents - each * shares\n"
                "    return [p / 100 for p in parts]\n"
            )
            reply = {
                "content": None,
                "tool_calls": [{
                    "id": "c2", "type": "function",
                    "function": {"name": "write",
                                 "arguments": json.dumps({"path": "calc.py",
                                                          "content": new_body})},
                }],
            }
        elif not ran_tests:
            reply = {
                "content": None,
                "tool_calls": [{
                    "id": "c3", "type": "function",
                    "function": {"name": "bash",
                                 "arguments": json.dumps(
                                     {"command": ["python3", "-m", "unittest", "-q"]})},
                }],
            }
        else:
            reply = {"content": "split_bill now distributes the remainder; tests pass."}

        payload = json.dumps({
            "id": "cmpl-scripted",
            "object": "chat.completion",
            "model": body.get("model", "scripted"),
            "choices": [{"index": 0, "message": reply, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1200, "completion_tokens": 60,
                      "prompt_tokens_details": {"cached_tokens": 800}},
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8901
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
