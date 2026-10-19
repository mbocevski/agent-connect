"""The loopback relay tap of the docker demos (``demo/``), one per host.

The daemon only speaks plain ``ws://`` and ``http://`` to a loopback relay
(``relay.url``, docs/config.md), so in docker each host reaches the relay
through this tap on ``127.0.0.1:8080`` inside the host's network
namespace. It forwards each TCP connection to the relay as it is, except
the WebSocket (``GET /v0/ws``), which goes through the harness's
:class:`~agentconnect_harness.proxy.RelayProxy`. The proxy records every
frame in both directions, and is the malicious relay double of the
integration suite: a control port (``127.0.0.1:8099``) forks, replays and
injects frames on request.

    python -m agentconnect_harness.tap serve --upstream relay:8080
    python -m agentconnect_harness.tap ctl frames
    python -m agentconnect_harness.tap ctl fork
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import secrets
import sys
from typing import Any

from agentconnect.relay import b64
from agentconnect_harness.proxy import Frame, RelayProxy

STREAM_LIMIT = 64 << 20  # a control answer holds every frame of the run
WS_REQUEST = b"GET /v0/ws"
CONTROL_PORT = 8099


class Tap:
    def __init__(self, upstream: str) -> None:
        host, _, port = upstream.rpartition(":")
        self.upstream = (host, int(port))
        self.proxy = RelayProxy(f"ws://{upstream}")
        self.frames: list[dict[str, Any]] = []
        self.proxy.client_filters.append(self._capture("out"))
        self.proxy.server_filters.insert(0, self._capture("in"))

    def _capture(self, direction: str) -> Any:
        def record(frame: Frame) -> list[Frame]:
            self.frames.append({"dir": direction, "frame": json.loads(json.dumps(frame))})
            return [frame]

        return record

    async def start(self, listen: int, control: int) -> None:
        await self.proxy.start()
        await asyncio.start_server(self._route, "127.0.0.1", listen)
        await asyncio.start_server(self._control, "127.0.0.1", control, limit=STREAM_LIMIT)

    async def _route(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            writer.close()
            return
        target = ("127.0.0.1", self.proxy.port) if head.startswith(WS_REQUEST) else self.upstream
        try:
            up_reader, up_writer = await asyncio.open_connection(*target)
        except OSError:
            writer.close()
            return
        up_writer.write(head)
        await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))

    async def _control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = json.loads(await reader.readline())
            answer = await self.handle(request)
        except Exception as e:
            answer = {"error": f"{type(e).__name__}: {e}"}
        writer.write(json.dumps(answer).encode() + b"\n")
        await writer.drain()
        writer.close()

    async def handle(self, request: dict[str, Any]) -> Any:
        op = request.get("op")
        proxy = self.proxy
        if op == "frames":
            return self.frames
        if op == "fork":
            proxy.fork_own_commits()
            return {"ok": True}
        if op == "forked":
            return proxy.forked
        if op == "inject":
            await proxy.inject(request["frame"])
            return {"ok": True}
        if op == "replay":
            frame = proxy.last_delivered(request["kind"])
            if request.get("rename"):
                frame = {**frame, "env": {**frame["env"], "msg_id": b64(secrets.token_bytes(16))}}
            await proxy.replay(frame)
            return frame
        if op == "last":
            return proxy.last_delivered(request["kind"])
        msg = f"unknown op {op!r}"
        raise ValueError(msg)


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            writer.close()


async def serve(upstream: str, listen: int, control: int) -> None:
    tap = Tap(upstream)
    await tap.start(listen, control)
    print(f"tap listening on 127.0.0.1:{listen}, relay {upstream}", flush=True)
    await asyncio.Event().wait()


async def ctl(request: dict[str, Any], port: int) -> Any:
    reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=STREAM_LIMIT)
    writer.write(json.dumps(request).encode() + b"\n")
    await writer.drain()
    answer = json.loads(await reader.readline())
    writer.close()
    return answer


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m agentconnect_harness.tap")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--upstream", required=True, help="the relay's host:port")
    s.add_argument("--listen", type=int, default=8080)
    s.add_argument("--control", type=int, default=CONTROL_PORT)
    c = sub.add_parser("ctl")
    c.add_argument("op")
    c.add_argument("args", nargs="?", default="{}", help="a JSON object of arguments")
    c.add_argument("--control", type=int, default=CONTROL_PORT)
    ns = parser.parse_args(argv)
    if ns.cmd == "serve":
        asyncio.run(serve(ns.upstream, ns.listen, ns.control))
        return
    answer = asyncio.run(ctl({"op": ns.op, **json.loads(ns.args)}, ns.control))
    json.dump(answer, sys.stdout)
    sys.stdout.write("\n")
    if isinstance(answer, dict) and "error" in answer:
        sys.exit(1)


if __name__ == "__main__":
    main()
