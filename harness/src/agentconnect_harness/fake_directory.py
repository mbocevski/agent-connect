"""An in-process directory and a door registry on ``httpx.MockTransport``.

:class:`FakeDirectory` keeps the directory's publish and withdraw rules
(``directory/README.md``) with the core doing every check, as the real one
does: ``verify_listing``, the token under the pinned key, the publish time
rules and the core's ``NameRecord``. Time is the test's fake clock, so a
scenario can run a door's whole life in a few steps. :class:`FakeDoors`
answers the relay's ``POST /v0/doors`` and ``DELETE /v0/doors/{id}``.

Both can misbehave on request: :meth:`Faults.fail` queues an error answer
(or a dropped connection) for the next matching requests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

import agentconnect_core as ac
from agentconnect.clock import Clock, unix_seconds

DOWN = 0  # a status for `fail`: the connection drops, no answer


@dataclass
class Fault:
    method: str
    prefix: str
    status: int
    code: str
    detail: str
    times: int


@dataclass
class Faults:
    """Queued failures, matched by method and path prefix."""

    queued: list[Fault] = field(default_factory=list)

    def fail(  # noqa: PLR0913
        self,
        method: str,
        prefix: str,
        status: int,
        code: str = "",
        detail: str = "",
        *,
        times: int = 1,
    ) -> None:
        self.queued.append(Fault(method, prefix, status, code, detail, times))

    def take(self, request: httpx.Request) -> httpx.Response | None:
        for fault in self.queued:
            if request.method == fault.method and request.url.path.startswith(fault.prefix):
                fault.times -= 1
                if fault.times <= 0:
                    self.queued.remove(fault)
                if fault.status == DOWN:
                    msg = "connection dropped"
                    raise httpx.ConnectError(msg, request=request)
                return _error(fault.status, fault.code, fault.detail)
        return None


def _error(status: int, code: str, detail: str = "", kind: str | None = None) -> httpx.Response:
    body: dict[str, Any] = {"code": code, "detail": detail}
    if kind is not None:
        body["kind"] = kind
    return httpx.Response(status, json=body)


TOKEN_KINDS = {"unknown_key": (403, "unknown_key"), "revoked": (403, "token_revoked")}


class FakeDirectory:
    """One directory host with one pinned operator key."""

    def __init__(
        self,
        host: str,
        key: ac.DirectoryKey,
        relays: list[str],
        clock: Clock,
        *,
        log: list[str] | None = None,
    ) -> None:
        self.host, self.key, self.relays, self.clock = host, key, relays, clock
        # Every request as "METHOD path", shared with FakeDoors to check order.
        self.log = log if log is not None else []
        self.listed: dict[str, bytes] = {}
        self.withdrawn: set[str] = set()
        self.records: dict[str, ac.NameRecord] = {}
        self.revoked: list[bytes] = []
        # Every body posted to /v0/listings and /v0/withdrawals, answered or not.
        self.posts: list[bytes] = []
        self.withdrawals: list[bytes] = []
        self.faults = Faults()
        # Served for GET /a/<name>.json in place of what is listed (a lying directory).
        self.serve: dict[str, bytes] = {}
        self.transport = httpx.MockTransport(self.handle)

    def now(self) -> int:
        return unix_seconds(self.clock)

    def token(self, name: str, identity: str, *, lifetime: int = 30 * 86_400, **kw: Any) -> bytes:
        """A token for ``name`` issued now on the fake clock."""
        now = self.now()
        return self.key.issue_token(self.host, name, identity, now, now + lifetime, **kw)

    def listing(self, name: str) -> ac.Listing | None:
        data = self.listed.get(name)
        return None if data is None else ac.verify_listing(data)

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.log.append(f"{request.method} {request.url.path}")
        path, body = request.url.path, request.content
        # What was sent, whether or not a fault drops it.
        if request.method == "POST" and path == "/v0/listings":
            self.posts.append(body)
        if request.method == "POST" and path == "/v0/withdrawals":
            self.withdrawals.append(body)
        injected = self.faults.take(request)
        if injected is not None:
            return injected
        if request.method == "POST" and path == "/v0/listings":
            return self._publish(body)
        if request.method == "POST" and path == "/v0/withdrawals":
            return self._withdraw(body)
        if request.method == "GET" and path.startswith("/a/") and path.endswith(".json"):
            return self._card(path.removeprefix("/a/").removesuffix(".json"))
        return _error(404, "not_found", "no such endpoint")

    def _publish(self, body: bytes) -> httpx.Response:  # noqa: PLR0911
        now = self.now()
        try:
            listing = ac.verify_listing(body)
        except ac.AgentConnectError as e:
            return _error(400, "bad_listing", str(e), e.kind)
        if listing.directory != self.host:
            return _error(400, "wrong_directory", "listing is for another directory")
        if listing.relay not in self.relays:
            return _error(400, "wrong_relay", "the listing's relay isn't listed here")
        try:
            listing.check_token(self.host, [self.key.public_key], now, self.revoked)
        except ac.AgentConnectError as e:
            status, code = TOKEN_KINDS.get(e.kind, (403, "bad_token"))
            return _error(status, code, str(e), e.kind)
        try:
            listing.check_publish(now)
        except ac.AgentConnectError as e:
            code = {"door_expired": "bad_door", "stale_timestamp": "stale_ts"}.get(
                e.kind, "bad_listing"
            )
            return _error(400, code, str(e), e.kind)
        name = listing.name
        stored_bytes = self.listed.get(name)
        if stored_bytes == body:  # re-posting the same bytes is idempotent
            return self._published(listing, 200)
        stored = None if stored_bytes is None else ac.verify_listing(stored_bytes)
        record = self.records.setdefault(name, ac.NameRecord())
        try:
            record.admits(listing, stored)
        except ac.AgentConnectError as e:
            return _error(409, "name_held", str(e), e.kind)
        record.accept(listing)
        self.listed[name] = body
        self.withdrawn.discard(name)
        return self._published(listing, 201)

    def _published(self, listing: ac.Listing, status: int) -> httpx.Response:
        state = "unclaimed" if listing.owner_domain is None else "checking"
        answer = {"name": listing.name, "seq": listing.seq, "url": listing.url}
        return httpx.Response(status, json=answer | {"owner_state": state})

    def _withdraw(self, body: bytes) -> httpx.Response:
        try:
            w = ac.verify_withdrawal(body)
            ac.check_withdrawal_fresh(body, self.host, self.now())
        except ac.AgentConnectError as e:
            code = "stale_ts" if e.kind == "stale_timestamp" else "bad_request"
            return _error(400, code, str(e), e.kind)
        name = str(w["name"])
        stored = self.listing(name)
        if stored is not None and not ac.withdrawal_applies(body, stored):
            if stored.identity == w["identity"]:
                return _error(409, "stale_seq", "seq is below the listed seq")
            return _error(403, "wrong_identity", "the name is listed by another identity")
        self.records.setdefault(name, ac.NameRecord()).tombstone(body)
        changed = self.listed.pop(name, None) is not None
        self.withdrawn.add(name)
        return httpx.Response(200, json={"withdrawn": name, "seq": w["seq"], "changed": changed})

    def _card(self, name: str) -> httpx.Response:
        data = self.serve.get(name, self.listed.get(name))
        if data is not None:
            return httpx.Response(200, content=data, headers={"content-type": "application/json"})
        if name in self.withdrawn:
            return _error(410, "withdrawn", "this listing was withdrawn")
        return _error(404, "not_found", "nothing is listed under that name")


MAX_DOOR_SECS = 7 * 86_400


@dataclass
class DoorRecord:
    mailbox: str
    expires_at: int
    closed: bool = False


class FakeDoors:
    """The relay's door registry (``relay/README.md``): at most 4 open doors
    per mailbox, 7 days at most, ids never reused. Requests must be signed
    (the header is checked for presence only)."""

    def __init__(self, clock: Clock, max_open: int = 4, *, log: list[str] | None = None) -> None:
        self.clock, self.max_open = clock, max_open
        self.log = log if log is not None else []
        self.doors: dict[str, DoorRecord] = {}
        self.created: list[str] = []
        self.closed: list[str] = []
        # The ts of every signed request, in order; a repeated signature is
        # refused as the relay's replay cache does.
        self.stamps: list[int] = []
        self._seen: set[str] = set()
        self.faults = Faults()
        # Seconds the relay's clock runs behind the daemon's.
        self.behind = 0
        self.transport = httpx.MockTransport(self.handle)

    def now(self) -> int:
        return unix_seconds(self.clock) - self.behind

    def open_doors(self) -> list[str]:
        now = self.now()
        return [i for i, d in self.doors.items() if not d.closed and d.expires_at > now]

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.log.append(f"{request.method} {request.url.path}")
        injected = self.faults.take(request)
        if injected is not None:
            return injected
        auth = request.headers.get("authorization", "")
        if not auth.startswith("AgentConnect-Ed25519 "):
            return _error(401, "auth_failed", "missing Authorization header")
        self.stamps.append(int(auth.split(".")[1]))
        if auth in self._seen:
            return _error(401, "auth_failed", "signature already used")
        self._seen.add(auth)
        path = request.url.path
        if request.method == "POST" and path == "/v0/doors":
            return self._create(json.loads(request.content))
        if request.method == "DELETE" and path.startswith("/v0/doors/"):
            return self._close(path.removeprefix("/v0/doors/"))
        return _error(404, "not_found", "no such endpoint")

    def _create(self, body: dict[str, Any]) -> httpx.Response:
        now = self.now()
        door_id, expires_at, mailbox = body["door_id"], body["expires_at"], body["owner_mailbox"]
        if expires_at <= now or expires_at > now + MAX_DOOR_SECS:
            detail = "expires_at must be in the future and at most 7 days away"
            return _error(400, "bad_request", detail)
        if door_id in self.doors:
            return _error(400, "bad_request", "door already exists")
        mine = [i for i in self.open_doors() if self.doors[i].mailbox == mailbox]
        if len(mine) >= self.max_open:
            return _error(429, "quota_exceeded", "a mailbox holds at most 4 open doors")
        self.doors[door_id] = DoorRecord(mailbox, expires_at)
        self.created.append(door_id)
        return httpx.Response(201, json={"door_id": door_id, "expires_at": expires_at})

    def _close(self, door_id: str) -> httpx.Response:
        door = self.doors.get(door_id)
        if door is None:
            return _error(404, "door_not_open", "unknown door")
        door.closed = True
        self.closed.append(door_id)
        return httpx.Response(204)
