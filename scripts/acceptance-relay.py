#!/usr/bin/env python3
"""A bidirectional relay between one listening socket and one upstream socket.

An acceptance run lives in its own network namespace, where the host's TCP
ports are unreachable, but the filesystem is shared. A Unix socket is a
filesystem object, so a listener on one side of the namespace boundary and the
run on the other can still meet.

    relay.py <listen unix|tcp> <listen address> <upstream unix|tcp> <upstream address>
"""
from __future__ import annotations

import asyncio
import os
import sys

CHUNK = 65536


def tcp_address(address: str) -> tuple[str, int]:
    host, port = address.rsplit(":", 1)
    return host.removeprefix("[").removesuffix("]"), int(port)


async def copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while chunk := await reader.read(CHUNK):
        writer.write(chunk)
        # Backpressure pauses only this direction, not every relay connection.
        await writer.drain()
    # EOF closes one direction. The upstream can still send its final response.
    writer.write_eof()
    await writer.drain()


async def relay(client_reader, client_writer, upstream_kind, upstream_at) -> None:
    upstream_writer = None
    copies = []
    try:
        connection = (asyncio.open_unix_connection(upstream_at) if upstream_kind == "unix"
                      else asyncio.open_connection(*tcp_address(upstream_at)))
        upstream_reader, upstream_writer = await asyncio.wait_for(connection, 10)
        copies = [asyncio.create_task(copy_stream(client_reader, upstream_writer)),
                  asyncio.create_task(copy_stream(upstream_reader, client_writer))]
        await asyncio.gather(*copies)
    except (OSError, asyncio.TimeoutError):
        # A refused or broken upstream closes this client, not the listener.
        pass
    finally:
        for copy in copies:
            copy.cancel()
        await asyncio.gather(*copies, return_exceptions=True)
        for writer in (client_writer, upstream_writer):
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass


async def main() -> int:
    listen_kind, listen_at, upstream_kind, upstream_at = sys.argv[1:5]

    async def connected(reader, writer):
        await relay(reader, writer, upstream_kind, upstream_at)

    if listen_kind == "unix":
        if os.path.exists(listen_at):
            os.unlink(listen_at)
        server = await asyncio.start_unix_server(connected, listen_at)
    else:
        server = await asyncio.start_server(connected, *tcp_address(listen_at))
    async with server:
        await server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
