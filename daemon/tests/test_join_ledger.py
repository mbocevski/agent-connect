"""The inviter's join replay ledger in the daemon tier (SPEC 6.2 "Replays").

Runtimes are never started: the tests create invites with the relay call
stubbed, build JoinRequests with in-memory joiner clients, and drive the
inbound frames themselves on the fake clock. The core's clock is set to the
fake clock for every call, as the runtime does for knocks under test. The
end-to-end scenarios, on both hosts, are in ``harness/tests/test_join_replay.py``.
"""

from __future__ import annotations

import random
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.clock import FakeClock
from agentconnect.config import Config
from agentconnect.failpoints import FailpointError
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.relay import b64
from agentconnect.runtime import Options, Runtime
from agentconnect.runtime.engine import Engine

RELAY = "127.0.0.1:1"


class Owner:
    """An inviter whose runtime is never started."""

    def __init__(
        self, tmp: Path, rng: random.Random, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.tmp, self.rng, self.clock, self.monkeypatch = tmp, rng, clock, monkeypatch
        self.rt = self._runtime()

    def _runtime(self) -> Runtime:
        config = Config(
            relay_url=f"ws://{RELAY}",
            relay_host=RELAY,
            data_dir=self.tmp / "data",
            keystore="file",
            api_socket=self.tmp / "s.sock",
            auto_approve=False,
        )
        return Runtime(
            config,
            clock=self.clock,
            keystore=FileKeystore(self.tmp / "data" / "keys"),
            options=Options(testing=Seeded(self.rng.getrandbits(63))),
            serve_api=False,
        )

    @property
    def engine(self) -> Engine:
        return self.rt._engine

    @property
    def now(self) -> int:
        return self.clock.unix_millis() // 1000

    async def restart(self) -> None:
        await self.rt.stop(flush=0)
        self.rt = self._runtime()

    async def invite(self, ttl_secs: int = 7 * 86_400) -> str:
        async def registered(_meta: dict[str, Any]) -> dict[str, Any]:
            return {}

        self.engine.client._set_time_for_testing(self.now)
        gid = self.engine.create_group("Replay", "")
        self.monkeypatch.setattr(self.engine.rest, "create_invite", registered)
        out = await self.engine.create_invite(gid, ttl_secs=ttl_secs, max_uses=10)
        return str(out["url"])

    async def deliver(self, request: bytes, sender: str, msg_id: str | None = None) -> str:
        msg_id = msg_id or b64(self.rng.randbytes(16))
        env = {"v": 0, "kind": "join_request", "msg_id": msg_id, "sender": sender}
        self.engine.client._set_time_for_testing(self.now)
        await self.engine._handle_frame({"t": "deliver", "env": {**env, "ct": b64(request)}})
        return msg_id

    def audit(self) -> list[str]:
        rows = self.engine.store.audit(limit=10_000)
        return [r["reason"] for r in rows if r["kind"] == "join_request"]

    def ledger(self) -> int:
        return len(self.engine.store.ledger_rows(self.now, ledger="join"))


class Joiner:
    def __init__(self, rng: random.Random, now: int) -> None:
        identity = ac.Identity._generate_for_testing(rng.getrandbits(63))
        instance = identity._create_instance_for_testing(rng.getrandbits(63), now)
        self.client = ac.Client._for_testing(None, instance.to_secret_bytes(), rng.getrandbits(63))
        self.client._set_time_for_testing(now)

    def request(self, url: str) -> bytes:
        return self.client.create_join_request(ac.parse_invite_url(url), "bob")

    @property
    def mailbox(self) -> str:
        return self.client.mailbox_id


@pytest.fixture
async def owner(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Owner]:
    o = Owner(tmp_path, rng, fake_clock, monkeypatch)
    yield o
    await o.rt.stop(flush=0)


async def test_a_rejected_request_is_dropped_on_replay_and_after_a_restart(
    owner: Owner, rng: random.Random
) -> None:
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    await owner.deliver(request, bob.mailbox)
    (approval,) = owner.engine.join_approvals()
    owner.engine.reject(approval["request_id"])
    await owner.deliver(request, bob.mailbox)
    await owner.restart()
    await owner.deliver(request, bob.mailbox)
    assert owner.engine.join_approvals() == []
    assert owner.audit() == ["join_replay", "join_replay"]
    assert owner.ledger() == 1
    events = [e["type"] for e in owner.engine.store.events(limit=100)]
    assert events.count("pending_approval") == 1


async def test_a_failed_record_leaves_no_ledger_entry(owner: Owner, rng: random.Random) -> None:
    """The ledger row, the approval, its event and the inbox row commit
    together: a request whose record rolled back is new when redelivered."""
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    owner.engine.failpoints.arm("join_request.in_tx")
    with pytest.raises(FailpointError):
        await owner.deliver(request, bob.mailbox, msg_id="first")
    assert owner.ledger() == 0
    assert owner.engine.join_approvals() == []
    await owner.deliver(request, bob.mailbox, msg_id="first")
    assert len(owner.engine.join_approvals()) == 1
    assert owner.audit() == []
    assert owner.ledger() == 1


async def test_a_request_id_or_key_package_taken_is_dropped_past_the_ledger(
    owner: Owner, rng: random.Random
) -> None:
    """If the ledger forgot a request while its invite is still open (it
    was purged on a clock that ran ahead), the approvals still hold its id
    and KeyPackage: the request id stays taken, and the KeyPackage of a
    pending approval gets no second one."""
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    first = await owner.deliver(request, bob.mailbox)
    pending = bob.request(url)
    await owner.deliver(pending, bob.mailbox)
    owner.engine.reject(first)
    owner.engine.store.ledger_purge(owner.now + 30 * 86_400, ledger="join")
    owner.engine._join_ledger = ac.ReplayLedger()
    await owner.deliver(request, b64(rng.randbytes(16)), msg_id=first)
    await owner.deliver(pending, bob.mailbox)
    assert owner.audit() == ["join_replay", "join_replay"]
    assert len(owner.engine.join_approvals()) == 1


async def test_a_clock_that_jumped_ahead_doesnt_keep_purging_the_ledger(
    owner: Owner, rng: random.Random
) -> None:
    """The knock ledger's L2, for joins: a purge that ran during a forward
    jump leaves no mark that makes later purges forget live entries; and a
    jump past an hour (but short of the invite's expiry) forgets nothing."""
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    first = bob.request(url)
    await owner.deliver(first, bob.mailbox)
    start = owner.clock.now()
    owner.clock.advance(2 * 86_400)
    await owner.engine.expire()
    assert owner.ledger() == 1  # its invite has five days left
    owner.clock.set(start)
    second = bob.request(url)
    await owner.deliver(second, bob.mailbox)
    for approval in owner.engine.join_approvals():
        owner.engine.reject(approval["request_id"])
    await owner.engine.expire()
    assert owner.ledger() == 2
    await owner.deliver(second, bob.mailbox)
    await owner.deliver(first, bob.mailbox)
    assert owner.audit() == ["join_replay", "join_replay"]
    assert owner.engine.join_approvals() == []


async def test_the_join_ledger_is_purged_at_the_invites_expiry(
    owner: Owner, rng: random.Random
) -> None:
    url = await owner.invite(ttl_secs=600)
    bob = Joiner(rng, owner.now)
    await owner.deliver(bob.request(url), bob.mailbox)
    (row,) = owner.engine.store.ledger_rows(owner.now, ledger="join")
    assert row[2] == owner.now + 600 + ac.LEDGER_GRACE_SECS
    owner.clock.advance(600 + ac.LEDGER_GRACE_SECS)
    await owner.engine.expire()
    assert owner.ledger() == 1
    owner.clock.advance(1)
    await owner.engine.expire()
    assert owner.engine.store.ledger_rows(0, ledger="join") == []
    assert len(owner.engine._join_ledger) == 0
