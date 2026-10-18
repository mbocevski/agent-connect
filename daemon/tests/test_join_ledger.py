"""The inviter's join replay ledger in the daemon tier (SPEC 6.2 "Replays").

Runtimes are never started: the tests create invites with the relay call
stubbed, build JoinRequests with in-memory joiner clients, and drive the
inbound frames themselves on the fake clock. The core's clock is set to the
fake clock for every call, as the runtime does for knocks under test. The
end-to-end scenarios, on both hosts, are in ``harness/tests/test_join_replay.py``.
"""

from __future__ import annotations

import json
import random
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.clock import FakeClock
from agentconnect.config import Config
from agentconnect.failpoints import FailpointError, SimulatedCrash
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.relay import b64, unb64
from agentconnect.runtime import Options, Runtime
from agentconnect.runtime import ledger as replay
from agentconnect.runtime.engine import HUMAN_EVENTS, DaemonError, Engine

RELAY = "127.0.0.1:1"


class Owner:
    """An inviter whose runtime is never started."""

    def __init__(
        self, tmp: Path, rng: random.Random, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.tmp, self.rng, self.clock, self.monkeypatch = tmp, rng, clock, monkeypatch
        self.cfg: dict[str, Any] = {"auto_approve": False}
        self.rt = self._runtime()

    def _runtime(self) -> Runtime:
        config = Config(
            relay_url=f"ws://{RELAY}",
            relay_host=RELAY,
            data_dir=self.tmp / "data",
            keystore="file",
            api_socket=self.tmp / "s.sock",
            **self.cfg,
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

    async def restart(self, **cfg: Any) -> None:
        await self.rt.stop(flush=0)
        self.cfg |= cfg
        self.rt = self._runtime()

    async def invite(self, ttl_secs: int = 7 * 86_400, max_uses: int = 10) -> str:
        async def registered(_meta: dict[str, Any]) -> dict[str, Any]:
            return {}

        self.engine.client._set_time_for_testing(self.now)
        gid = self.engine.create_group("Replay", "")
        self.monkeypatch.setattr(self.engine.rest, "create_invite", registered)
        out = await self.engine.create_invite(gid, ttl_secs=ttl_secs, max_uses=max_uses)
        return str(out["url"])

    async def revoke(self, url: str) -> None:
        async def revoked(_invite_id: str) -> None:
            return None

        self.monkeypatch.setattr(self.engine.rest, "revoke_invite", revoked)
        await self.engine.revoke_invite(invite_id(url))

    def flooded(self) -> list[dict[str, Any]]:
        return [e for e in self.engine.store.events(limit=10_000) if e["type"] == "invite_flooded"]

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


def invite_id(url: str) -> str:
    return ac.parse_invite_url(url).invite_id_b64


class Joiner:
    def __init__(self, rng: random.Random, now: int) -> None:
        identity = ac.Identity._generate_for_testing(rng.getrandbits(63))
        instance = identity._create_instance_for_testing(rng.getrandbits(63), now)
        self.client = ac.Client._for_testing(None, instance.to_secret_bytes(), rng.getrandbits(63))
        self.client._set_time_for_testing(now)

    def request(self, url: str, name: str = "bob") -> bytes:
        return self.client.create_join_request(ac.parse_invite_url(url), name)

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


async def test_the_join_ledger_forgets_an_invites_requests_when_it_expires(
    owner: Owner, rng: random.Random
) -> None:
    url = await owner.invite(ttl_secs=600)
    bob = Joiner(rng, owner.now)
    await owner.deliver(bob.request(url), bob.mailbox)
    (row,) = owner.engine.store.ledger_rows(owner.now, ledger="join")
    assert row[2] == owner.now + 600 + ac.LEDGER_GRACE_SECS
    owner.clock.advance(599)
    await owner.engine.expire()
    assert owner.ledger() == 1
    owner.clock.advance(1)
    await owner.engine.expire()  # expired, which is final: step 1 refuses any copy
    assert owner.engine.store.invite(invite_id(url))["status"] == "expired"  # ty: ignore[not-subscriptable]
    assert owner.engine.store.ledger_rows(0, ledger="join") == []
    assert len(owner.engine._join_ledger) == 0


# -- F1: a leaked link floods only its own invite -----------------------------------


async def test_a_leaked_link_is_held_to_its_invites_quota(owner: Owner, rng: random.Random) -> None:
    """A link thief with fresh KeyPackages fills the invite's pending cap and
    then its ledger quota, never the daemon's ledger: another invite's
    joiner still reaches the human, and the human hears of the flood."""
    await owner.restart(policy_max_pending_joins_per_invite=2)
    leaked = await owner.invite(max_uses=1)
    quota = replay.join_quota(1, owner.engine.config.policy_join_ledger_per_invite)
    assert quota == 64
    thief = Joiner(rng, owner.now)
    for _ in range(quota + 1):
        await owner.deliver(thief.request(leaked), thief.mailbox)
    audit = owner.audit()
    assert audit.count("join_invite_full") == quota - 2
    assert audit[-1] == "join_invite_quota"
    assert len(owner.engine.join_approvals()) == 2
    assert owner.ledger() == quota
    # The human hears of it once per reason; the agent token never does.
    assert [(e["data"]["invite_id"], e["data"]["reason"]) for e in owner.flooded()] == [
        (invite_id(leaked), "join_invite_full"),
        (invite_id(leaked), "join_invite_quota"),
    ]
    assert "revoke" in owner.flooded()[0]["data"]["warning"]
    assert "invite_flooded" in HUMAN_EVENTS
    assert not [
        e for e in owner.engine.store.agent_events(limit=10_000) if e["type"] == "invite_flooded"
    ]
    # Another invite is unaffected.
    other = await owner.invite()
    bob = Joiner(rng, owner.now)
    await owner.deliver(bob.request(other), bob.mailbox)
    assert len(owner.engine.join_approvals()) == 3


async def test_revoking_or_expiring_an_invite_frees_its_entries(
    owner: Owner, rng: random.Random
) -> None:
    """Revoked and expired are final: step 1 refuses any copy, so their
    entries go at once and make room in a full ledger for other invites."""
    leaked = await owner.invite()
    short = await owner.invite(ttl_secs=600)
    other = await owner.invite()
    owner.engine._join_capacity = 2  # lowered after the invites: create_invite would refuse
    owner.engine._join_ledger = owner.engine._load_join_ledger()
    thief = Joiner(rng, owner.now)
    leaked_request = thief.request(leaked)
    await owner.deliver(leaked_request, thief.mailbox)
    await owner.deliver(thief.request(short), thief.mailbox)
    bob = Joiner(rng, owner.now)
    await owner.deliver(bob.request(other), bob.mailbox)
    assert owner.audit() == ["join_ledger_full"]
    assert owner.flooded() == []
    assert [e["type"] for e in owner.engine.store.events(limit=100)].count("join_ledger_full") == 1
    await owner.revoke(leaked)
    assert owner.ledger() == 1
    # The revoked invite refuses its copy before the ledger is asked.
    await owner.deliver(leaked_request, thief.mailbox)
    owner.clock.advance(600)
    await owner.engine.expire()
    assert owner.ledger() == 0
    late = bob.request(other)
    await owner.deliver(late, bob.mailbox)
    await owner.restart()
    await owner.deliver(late, bob.mailbox)
    assert owner.audit() == ["join_ledger_full", "join_replay"]
    mine = [a for a in owner.engine.join_approvals() if a["identity"] == bob.client.identity]
    assert len(mine) == 1


# -- F2: no purge before the invites are marked ------------------------------------


async def test_a_clock_ahead_at_boot_forgets_nothing(owner: Owner, rng: random.Random) -> None:
    """The load purges nothing: only ``expire()`` purges, right after it
    marks expired invites, so a clock that was ahead at start and is put
    right before the first frame can't reopen a rejected request."""
    url = await owner.invite(ttl_secs=600)
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    await owner.deliver(request, bob.mailbox)
    (approval,) = owner.engine.join_approvals()
    owner.engine.reject(approval["request_id"])
    start = owner.clock.now()
    await owner.rt.stop(flush=0)
    owner.clock.advance(86_400)
    owner.rt = owner._runtime()
    assert len(owner.engine._join_ledger) == 1
    owner.clock.set(start)
    await owner.deliver(request, bob.mailbox)
    assert owner.audit() == ["join_replay"]
    assert owner.engine.join_approvals() == []


# -- F3: a request refused at receipt is not remembered ------------------------------


async def test_a_request_refused_at_receipt_by_the_use_limit_is_not_remembered(
    owner: Owner, rng: random.Random
) -> None:
    """Only requests that pass steps 1-3 are remembered (SPEC 6.2). One
    that arrives while the invite's last use is taken is refused by step 1,
    and is shown once a failed Add gives the use back."""
    url = await owner.invite(max_uses=1)
    bob, carol = Joiner(rng, owner.now), Joiner(rng, owner.now)
    await owner.deliver(bob.request(url), bob.mailbox)
    (first,) = owner.engine.join_approvals()
    owner.engine.approve(first["request_id"])
    late = carol.request(url)
    await owner.deliver(late, carol.mailbox)
    assert owner.ledger() == 1
    owner.engine.store.set_approval_status(first["request_id"], "failed")
    await owner.deliver(late, carol.mailbox)
    assert [a["display_name"] for a in owner.engine.join_approvals()] == ["bob"]
    assert owner.audit() == []


# -- F4 and F5: crashes after the record, and a re-MACed request -------------------


@pytest.mark.parametrize("action", ["raise", "crash"])
async def test_auto_approve_survives_a_failure_after_the_record(
    owner: Owner, rng: random.Random, action: str
) -> None:
    """With ``auto_approve`` the approval is marked approving and its Add
    queued in the record's own transaction, so a failure or a crash right
    after it commits can't leave it pending until it lapses."""
    await owner.restart(auto_approve=True)
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    owner.engine.failpoints.arm("join_request.after_tx", action)  # ty: ignore[invalid-argument-type]
    with pytest.raises((FailpointError, SimulatedCrash)):
        await owner.deliver(request, bob.mailbox, msg_id="first")
    if action == "crash":
        await owner.restart()
    (approval,) = owner.engine.store.approvals("approving")
    assert approval["request_id"] == "first"
    intents = [r.payload.get("intent") for r in owner.engine.store.outbox()]
    assert {"type": "add", "request_id": "first"} in intents
    assert owner.ledger() == 1
    await owner.deliver(request, bob.mailbox, msg_id="first")  # the relay's redelivery
    await owner.deliver(request, bob.mailbox)
    assert owner.audit() == ["join_replay"]
    assert len(owner.engine.store.approvals("approving")) == 1


async def test_a_crash_after_the_record_keeps_the_approval_once(
    owner: Owner, rng: random.Random
) -> None:
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    owner.engine.failpoints.arm("join_request.after_tx", "crash")
    with pytest.raises(SimulatedCrash):
        await owner.deliver(request, bob.mailbox, msg_id="first")
    await owner.restart()
    await owner.deliver(request, bob.mailbox, msg_id="first")
    await owner.deliver(request, bob.mailbox)
    assert len(owner.engine.join_approvals()) == 1
    assert owner.audit() == ["join_replay"]
    assert owner.ledger() == 1


async def test_the_same_key_package_under_a_new_name_and_mac_is_a_replay(
    owner: Owner, rng: random.Random
) -> None:
    """Whoever holds the link can re-MAC a request. Keeping the KeyPackage
    and changing the name makes another request with the same
    KeyPackageRef: still a replay."""
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    await owner.deliver(request, bob.mailbox)
    (approval,) = owner.engine.join_approvals()
    owner.engine.reject(approval["request_id"])
    link = ac.parse_invite_url(url)
    body = json.loads(request)
    body["display_name"] = "bob, again"
    body["mac"] = b64(
        ac.join_request_mac(
            link.invite_id,
            link.secret_bytes(),
            unb64(body["key_package"]),
            body["mailbox_id"],
            body["display_name"],
        )
    )
    renamed = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    assert renamed != request
    await owner.deliver(renamed, bob.mailbox)
    assert owner.audit() == ["join_replay"]
    assert owner.engine.join_approvals() == []


# -- N1-N3: the quota, the global cap, and the cost of forgetting --------------------


async def test_approved_requests_dont_use_up_the_invites_quota(
    owner: Owner, rng: random.Random
) -> None:
    """A large multi-use invite fills its uses with no false drops: requests
    that are being added or were added are in the approvals table (and
    their KeyPackages are tracked once merged), so they don't count
    against the invite's share; only rejected, lapsed and dropped ones do."""
    await owner.restart(policy_join_ledger_per_invite=64)
    url = await owner.invite(max_uses=40)
    assert replay.join_quota(40, 64) == 64
    joiner = Joiner(rng, owner.now)
    for decide in [owner.engine.approve] * 30 + [owner.engine.reject] * 34:
        await owner.deliver(joiner.request(url), joiner.mailbox)
        (waiting,) = owner.engine.join_approvals()
        decide(waiting["request_id"])
    assert owner.ledger() == 64
    await owner.deliver(joiner.request(url), joiner.mailbox)
    assert owner.audit() == []
    assert len(owner.engine.join_approvals()) == 1
    assert owner.flooded() == []


async def test_open_invites_cant_reserve_more_than_the_join_ledger(
    owner: Owner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each open invite reserves its share plus its uses; an invite that
    would take the total past the ledger's capacity is refused, so the
    shares alone can't fill the ledger."""
    owner.engine._join_capacity = 2 * (1024 + 1000) + 100
    first = await owner.invite(max_uses=1000)
    await owner.invite(max_uses=1000)
    with pytest.raises(DaemonError) as e:
        await owner.invite(max_uses=1000)
    assert e.value.code == "too_many_invites"
    await owner.invite(max_uses=1)  # 64 + 1 still fit
    await owner.revoke(first)
    await owner.invite(max_uses=1000)  # the revoked invite's reserve is free again


async def test_a_full_join_ledger_tells_the_human_daemon_wide(
    owner: Owner, rng: random.Random
) -> None:
    """If the whole ledger is full (a lowered capacity, say), the request
    that finds it full is dropped and the human gets one daemon-wide
    event: it doesn't say the bystander invite leaked."""
    a, b = await owner.invite(), await owner.invite()
    owner.engine._join_capacity = 1
    owner.engine._join_ledger = owner.engine._load_join_ledger()
    thief, bob = Joiner(rng, owner.now), Joiner(rng, owner.now)
    await owner.deliver(thief.request(a), thief.mailbox)
    await owner.deliver(bob.request(b), bob.mailbox)
    await owner.deliver(bob.request(b), bob.mailbox)
    assert owner.audit() == ["join_ledger_full", "join_ledger_full"]
    assert owner.flooded() == []
    (full,) = [e for e in owner.engine.store.events(limit=100) if e["type"] == "join_ledger_full"]
    assert full["group_id"] is None
    assert "invite_id" not in full["data"]
    assert "revoke" in full["data"]["warning"].lower()
    assert "leaked" not in full["data"]["warning"]
    assert "join_ledger_full" in HUMAN_EVENTS


async def test_expiring_many_invites_reloads_the_ledger_once(
    owner: Owner, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    urls = [await owner.invite(ttl_secs=600) for _ in range(3)]
    bob = Joiner(rng, owner.now)
    for url in urls:
        await owner.deliver(bob.request(url), bob.mailbox)
    assert owner.ledger() == 3
    reloads: list[int] = []
    load = owner.engine._load_join_ledger

    def counted() -> ac.ReplayLedger:
        reloads.append(1)
        return load()

    monkeypatch.setattr(owner.engine, "_load_join_ledger", counted)
    owner.clock.advance(600)
    await owner.engine.expire()
    assert owner.ledger() == 0
    assert len(reloads) == 1
    await owner.engine.expire()
    assert len(reloads) == 1
