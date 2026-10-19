"""A WebSocket proxy in front of the real relay, one per daemon.

Honest by default. It can cut the daemon off (``partition``) and, as the
``malicious_relay``, drop, reorder, replay, inject, rewrite routing hints,
forge replies and fork the group (SPEC §12: a relay without the invite
link). Every rule is a filter over the JSON frames in one direction; a
filter returns the frames to pass on (possibly none, possibly more).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable
from typing import Any

import websockets
from websockets.asyncio.client import connect
from websockets.asyncio.server import Server, ServerConnection, serve

Frame = dict[str, Any]
Filter = Callable[[Frame], list[Frame]]


class _Session:
    def __init__(self, client: ServerConnection) -> None:
        self.client = client

    async def to_client(self, frame: Frame) -> None:
        with contextlib.suppress(websockets.WebSocketException):
            await self.client.send(json.dumps(frame))


class RelayProxy:
    def __init__(self, upstream: str) -> None:
        self.upstream = upstream.rstrip("/") + "/v0/ws"
        self.partitioned = False
        self.client_filters: list[Filter] = []
        self.server_filters: list[Filter] = []
        self.delivered: list[Frame] = []  # every deliver frame passed to the daemon
        self.forked: list[Frame] = []  # the daemon's commits withheld by fork_own_commits
        self._forged: list[Frame] = []  # replies forged to the daemon
        self._sessions: set[_Session] = set()
        self._gone = asyncio.Event()
        self._server: Server | None = None
        self.port = 0

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    async def start(self) -> None:
        self._server = await serve(self._handle, "127.0.0.1", 0, max_size=4 << 20, compression=None)
        self.port = int(next(iter(self._server.sockets)).getsockname()[1])

    async def wait_no_sessions(self) -> None:
        """Wait until every session has finished unwinding (for tests)."""
        while self._sessions:
            self._gone.clear()
            await self._gone.wait()

    async def stop(self) -> None:
        await self.cut()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # -- partitions ---------------------------------------------------------

    async def cut(self) -> None:
        """Partition: close the daemon's connection and refuse new ones."""
        self.partitioned = True
        for s in list(self._sessions):
            await s.client.close()

    def heal(self) -> None:
        self.partitioned = False

    # -- malicious behaviour --------------------------------------------------

    async def inject(self, frame: Frame) -> None:
        """Send a frame to the daemon as if from the relay."""
        for s in list(self._sessions):
            await s.to_client(frame)

    async def replay(self, frame: Frame) -> None:
        await self.inject(json.loads(json.dumps(frame)))

    def last_delivered(self, kind: str) -> Frame:
        return next(f for f in reversed(self.delivered) if f["env"].get("kind") == kind)

    def rewrite_routing(
        self, add: list[str] | None = None, remove: list[str] | None = None
    ) -> None:
        """Rewrite the routing hints of the next commit delivered."""
        done = False

        def f(frame: Frame) -> list[Frame]:
            nonlocal done
            env = frame.get("env") or {}
            if not done and frame.get("t") == "deliver" and env.get("kind") == "commit":
                done = True
                env["routing"] = {"add": add or [], "remove": remove or []}
            return [frame]

        self.server_filters.append(f)

    def drop_deliveries(self, predicate: Callable[[Frame], bool]) -> None:
        self.server_filters.append(
            lambda fr: [] if fr.get("t") == "deliver" and predicate(fr["env"]) else [fr]
        )

    def reorder_next(self, n: int) -> None:
        """Hold the next ``n`` deliver frames and release them reversed."""
        held: list[Frame] = []

        def f(frame: Frame) -> list[Frame]:
            if frame.get("t") != "deliver" or len(held) >= n:
                return [frame]
            held.append(frame)
            if len(held) == n:
                return list(reversed(held))
            return []

        self.server_filters.append(f)

    def lose_next_commit_confirmation(self) -> None:
        """Forward the daemon's next commit, but answer it with a forged
        ``epoch_conflict`` and hold the fan-out copy until after the forged
        reply, so the daemon discards a commit the relay really accepted."""
        state: dict[str, Any] = {"msg_id": None, "replied": False, "held": []}

        def client(frame: Frame) -> list[Frame]:
            env = frame.get("env") or {}
            if state["msg_id"] is None and frame.get("t") == "send" and env.get("kind") == "commit":
                state["msg_id"] = env["msg_id"]
                state["epoch"] = env["epoch"]
            return [frame]

        def server(frame: Frame) -> list[Frame]:
            target = state["msg_id"]
            if target is None:
                return [frame]
            env = frame.get("env") or {}
            if frame.get("t") == "deliver" and env.get("msg_id") == target and not state["replied"]:
                state["held"].append(frame)
                return []
            if frame.get("t") == "accepted" and frame.get("msg_id") == target:
                state["replied"] = True
                forged = {
                    "t": "error",
                    "msg_id": target,
                    "code": "epoch_conflict",
                    "detail": "forged",
                    "current_epoch": state["epoch"] + 1,
                }
                return [forged, *state["held"]]
            return [frame]

        self.client_filters.append(client)
        self.server_filters.append(server)

    def fail_next(self, t: str, code: str, kind: str | None = None, times: int = 1) -> None:
        """Answer the daemon's next ``times`` frames of type ``t`` (and
        envelope ``kind``) with an ``error`` without forwarding them."""
        left = times

        def client(frame: Frame) -> list[Frame]:
            nonlocal left
            env = frame.get("env") or {}
            if left > 0 and frame.get("t") == t and (kind is None or env.get("kind") == kind):
                left -= 1
                msg_id = env.get("msg_id") if t in ("send", "join") else frame.get("msg_id")
                error = {"t": "error", "msg_id": msg_id, "code": code, "detail": "forged"}
                if code == "epoch_conflict":
                    error["current_epoch"] = int(env.get("epoch", 0)) + 1
                self._forged.append(error)
                return []
            return [frame]

        self.client_filters.append(client)

    def hold_welcome_until_application(self) -> asyncio.Event:
        """Deliver the next Welcome only after the first application message
        that follows it, as a relay may (they are queued independently).
        The returned event is set once the Welcome is held: send the
        application message after that, or it may overtake the Welcome and
        leave it held."""
        state: dict[str, Any] = {"held": None, "done": False}
        holding = asyncio.Event()

        def server(frame: Frame) -> list[Frame]:
            env = frame.get("env") or {}
            if state["done"] or frame.get("t") != "deliver":
                return [frame]
            if env.get("kind") == "welcome_wrapped" and state["held"] is None:
                state["held"] = frame
                holding.set()
                return []
            if state["held"] is not None and env.get("kind") == "application":
                state["done"] = True
                return [frame, state["held"]]
            return [frame]

        self.server_filters.append(server)
        return holding

    def fork_own_commits(self) -> None:
        """Fork: confirm the daemon's commits locally without forwarding
        them, so it moves to an epoch nobody else is in. The withheld
        frames are kept in ``forked``, for the relay to show to some members
        (``inject`` a ``deliver`` of the envelope)."""

        def client(frame: Frame) -> list[Frame]:
            env = frame.get("env") or {}
            if frame.get("t") == "send" and env.get("kind") == "commit":
                self.forked.append(frame)
                self._forged.append({"t": "accepted", "msg_id": env["msg_id"]})
                return []
            return [frame]

        self.client_filters.append(client)

    # -- plumbing -------------------------------------------------------------

    @staticmethod
    def _apply(filters: list[Filter], frame: Frame) -> list[Frame]:
        frames = [frame]
        for f in filters:
            frames = [out for fr in frames for out in f(fr)]
        return frames

    async def _handle(self, client: ServerConnection) -> None:
        if self.partitioned:
            await client.close()
            return
        session = _Session(client)
        self._sessions.add(session)
        try:
            async with connect(self.upstream, max_size=4 << 20, compression=None) as upstream:

                async def c2s() -> None:
                    async for raw in client:
                        for fr in self._apply(self.client_filters, json.loads(raw)):
                            await upstream.send(json.dumps(fr))
                        while self._forged:
                            await session.to_client(self._forged.pop(0))

                async def s2c() -> None:
                    async for raw in upstream:
                        for fr in self._apply(self.server_filters, json.loads(raw)):
                            if fr.get("t") == "deliver":
                                self.delivered.append(fr)
                            await session.to_client(fr)

                tasks = [asyncio.ensure_future(c2s()), asyncio.ensure_future(s2c())]
                _, rest = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in rest:
                    t.cancel()
                for t in tasks:
                    with contextlib.suppress(asyncio.CancelledError, websockets.WebSocketException):
                        await t
        except (OSError, websockets.WebSocketException):
            pass
        finally:
            self._sessions.discard(session)
            await client.close()
            self._gone.set()
