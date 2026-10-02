#!/usr/bin/env python3
"""A bidirectional relay between one listening socket and one upstream socket.

An acceptance run lives in its own network namespace, where the host's TCP
ports are unreachable, but the filesystem is shared. A Unix socket is a
filesystem object, so a listener on one side of the namespace boundary and the
run on the other can still meet.

    relay.py <listen unix|tcp> <listen address> <upstream unix|tcp> <upstream address>
"""
from __future__ import annotations

import os
import selectors
import socket
import sys

CHUNK = 65536


def open_listener(kind: str, address: str) -> socket.socket:
    if kind == "unix":
        if os.path.exists(address):
            os.unlink(address)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(address)
    else:
        host, port = address.split(":")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, int(port)))
    listener.listen(128)
    return listener


def open_upstream(kind: str, address: str) -> socket.socket:
    if kind == "unix":
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(address)
    else:
        host, port = address.split(":")
        upstream = socket.create_connection((host, int(port)), 10)
    return upstream


def main() -> int:
    listen_kind, listen_at, upstream_kind, upstream_at = sys.argv[1:5]
    listener = open_listener(listen_kind, listen_at)
    selector = selectors.DefaultSelector()
    selector.register(listener, selectors.EVENT_READ, None)
    while True:
        for key, _ in selector.select():
            if key.data is None:
                client, _ = listener.accept()
                try:
                    upstream = open_upstream(upstream_kind, upstream_at)
                except OSError:
                    # A client that cannot reach its upstream is closed, not
                    # held open: the caller is better served by a refused
                    # connection than by one that hangs until its own deadline.
                    client.close()
                    continue
                client.setblocking(False)
                upstream.setblocking(False)
                selector.register(client, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, client)
                continue
            peer = key.data
            try:
                chunk = key.fileobj.recv(CHUNK)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                chunk = b""
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                selector.unregister(peer)
                peer.close()
                continue
            try:
                peer.sendall(chunk)
            except OSError:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                selector.unregister(peer)
                peer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
