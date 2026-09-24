#!/usr/bin/env python3
"""Minimal AgentForge API UX example.

Set AGENTFORGE_API_KEY and optionally AGENTFORGE_URL before running.
The example intentionally uses urllib so it has no third-party dependencies.
"""
import base64, json, os, urllib.request

BASE = os.getenv("AGENTFORGE_URL", "http://127.0.0.1:8080").rstrip("/")
KEY = os.environ["AGENTFORGE_API_KEY"]

def call(method, path, body=None):
    payload = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=payload, method=method,
        headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as response:
        return json.load(response)

sandbox = call("POST", "/v1/sandboxes", {"image":"python:3.13", "cpu":1, "memory_mb":512, "disk_mb":2048, "timeout_seconds":300, "network":{"enabled":False}})
print("created", sandbox["id"])
print(call("POST", f'/v1/sandboxes/{sandbox["id"]}/exec', {"command":["python", "-c", "print(6 * 7)"]})["stdout"])
content = base64.b64encode(b"print('hello from AgentForge')\n").decode()
call("PUT", f'/v1/sandboxes/{sandbox["id"]}/files', {"path":"/workspace/hello.py", "content_base64":content})
print(call("GET", f'/v1/sandboxes/{sandbox["id"]}/files?path=/workspace/hello.py')["content_base64"])
snapshot = call("POST", f'/v1/sandboxes/{sandbox["id"]}/snapshots', {})
print("snapshot", snapshot["id"])
restored = call("POST", f'/v1/snapshots/{snapshot["id"]}/restore', {})
print("restored", restored["id"])
call("DELETE", f'/v1/sandboxes/{restored["id"]}')
call("DELETE", f'/v1/sandboxes/{sandbox["id"]}')
