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
import string
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
from agentconnect.relay import RelayError, b64, unb64
from agentconnect.runtime import Options, Runtime
from agentconnect.runtime import ledger as replay
from agentconnect.runtime.engine import (
    HUMAN_EVENTS,
    JOIN_FAILURE_WINDOW_SECS,
    MAX_PENDING_PER_IDENTITY,
    DaemonError,
    Engine,
)

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
    first = b64(rng.randbytes(16))
    owner.engine.failpoints.arm("join_request.in_tx")
    with pytest.raises(FailpointError):
        await owner.deliver(request, bob.mailbox, msg_id=first)
    assert owner.ledger() == 0
    assert owner.engine.join_approvals() == []
    await owner.deliver(request, bob.mailbox, msg_id=first)
    assert len(owner.engine.join_approvals()) == 1
    assert owner.audit() == []
    assert owner.ledger() == 1


@pytest.mark.parametrize("shape", ["kn-prefixed", "knock_id", "short", "not_canonical"])
async def test_the_request_id_is_a_16_byte_msg_id(
    owner: Owner, rng: random.Random, shape: str
) -> None:
    """A join's request id is its msg_id, which SPEC 7.1 makes 16 bytes. Any
    such id is accepted, "kn-" at the start included (one random id in 64**3
    starts so); anything else is dropped, which keeps the 19-character knock
    request ids out of reach."""
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    good = b64(rng.randbytes(16))
    # The last of 22 characters carries 4 bits and 2 zero bits: the next
    # character of the alphabet decodes to the same bytes.
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
    msg_id = {
        "kn-prefixed": "kn-" + good[3:],
        "knock_id": "kn-" + b64(rng.randbytes(12)),
        "short": good[:-1],
        "not_canonical": good[:-1] + alphabet[alphabet.index(good[-1]) + 1],
    }[shape]
    await owner.deliver(request, bob.mailbox, msg_id=msg_id)
    approvals = [a["request_id"] for a in owner.engine.join_approvals()]
    assert approvals == ([msg_id] if shape == "kn-prefixed" else [])
    assert owner.engine.store.inbox_state(bob.mailbox, msg_id) is not None


async def test_a_request_id_or_key_package_taken_is_dropped_past_the_ledger(
    owner: Owner, rng: random.Random
) -> None:
    """If the ledger forgot a request while its invite is still open (it
    was purged on a clock that ran ahead), the approvals still hold its id
    and KeyPackage: the request id stays taken, and the KeyPackage of a
    pending approval gets no second one. The same request id redelivered
    under another sender (past the inbox's deduplication) is dropped by the
    sender check before it reaches them (SPEC 6.2 step 3)."""
    url = await owner.invite()
    bob, carol = Joiner(rng, owner.now), Joiner(rng, owner.now)
    request = bob.request(url)
    first = await owner.deliver(request, bob.mailbox)
    pending = carol.request(url)
    await owner.deliver(pending, carol.mailbox)
    owner.engine.reject(first)
    owner.engine.store.ledger_purge(owner.now + 30 * 86_400, ledger="join")
    owner.engine._join_ledger = ac.ReplayLedger()
    await owner.deliver(request, b64(rng.randbytes(16)), msg_id=first)
    assert owner.audit() == []
    await owner.deliver(pending, carol.mailbox)
    assert owner.audit() == ["join_replay"]
    assert len(owner.engine.join_approvals()) == 1


async def test_a_request_id_taken_from_the_holders_own_mailbox_is_a_replay(
    owner: Owner, rng: random.Random
) -> None:
    """Past the ledger's window a link holder may reuse a decided request's
    msg_id from its own mailbox, with a KeyPackage of its own: the request
    id stays taken, so it gets no approval."""
    url = await owner.invite()
    bob, carol = Joiner(rng, owner.now), Joiner(rng, owner.now)
    first = await owner.deliver(bob.request(url), bob.mailbox)
    owner.engine.reject(first)
    owner.engine.store.ledger_purge(owner.now + 30 * 86_400, ledger="join")
    owner.engine._join_ledger = ac.ReplayLedger()
    await owner.deliver(carol.request(url, "carol"), carol.mailbox, msg_id=first)
    assert owner.audit() == ["join_replay"]
    assert owner.engine.join_approvals() == []


async def test_an_approval_an_older_daemon_stored_from_another_sender_is_refused(
    owner: Owner, rng: random.Random
) -> None:
    """An older daemon didn't compare a request's mailbox with its envelope's
    sender (SPEC 6.2 step 3), so it may have stored an approval for a request
    a link holder built from someone else's KeyPackage. Its inbox row is
    keyed by the holder's mailbox, not the one the request names: neither the
    human's approval nor a rebuilt Add accepts it, and it expires."""
    url, elsewhere = await owner.invite(), await owner.invite()
    victim, attacker = Joiner(rng, owner.now), Joiner(rng, owner.now)
    forged = _forge(victim.request(elsewhere), url)
    inv = owner.engine.store.invite(invite_id(url))
    assert inv is not None
    obj = owner.engine._invite_object(inv)
    assert obj is not None
    v = owner.engine.client.verify_join_request(forged, obj, victim.mailbox)
    rid = b64(rng.randbytes(16))
    owner.engine.store.add_approval(
        {
            "request_id": rid,
            "invite_id": inv["invite_id"],
            "group_id": inv["group_id"],
            "request": b64(forged),
            "identity": v.identity,
            "display_name": v.display_name,
            "mailbox_id": v.mailbox_id,
            "received_at": owner.now,
            "kp_ref": b64(v.key_package_ref),
            "instance_id": None,
        }
    )
    owner.engine.store.record_inbox(attacker.mailbox, rid, None, "done", owner.now)
    with pytest.raises(DaemonError, match="mailbox it names"):
        owner.engine._build(unb64(inv["group_id"]), {"type": "add", "request_id": rid})
    assert (owner.engine.store.approval(rid) or {})["status"] == "expired"
    owner.engine.store.set_approval_status(rid, "pending")
    with pytest.raises(DaemonError, match="mailbox it names"):
        owner.engine._approve_join(rid)
    assert (owner.engine.store.approval(rid) or {})["status"] == "expired"
    assert not [r for r in owner.engine.store.outbox() if r.kind == "commit"]


def _bad_mac(request: bytes) -> bytes:
    """``request`` with its MAC broken: what someone without the link sends."""
    req = json.loads(request)
    mac = bytearray(unb64(req["mac"]))
    mac[0] ^= 1
    return json.dumps({**req, "mac": b64(bytes(mac))}).encode()


async def test_failed_requests_are_counted_to_tell_the_human_never_to_drop(
    owner: Owner, rng: random.Random
) -> None:
    """SPEC 6.2 steps 2 and 3: a request with a bad MAC, or from a mailbox
    other than the one it names, counts against its invite. At the limit
    within the window the human is told (``invite_flooded``, reason
    ``join_failures``), once per window: but nothing is dropped unchecked, so
    a stranger who knows only the invite id can't lock joiners out."""
    await owner.restart(policy_max_failed_joins_per_invite=3)
    url = await owner.invite(max_uses=50)
    carol, stranger = Joiner(rng, owner.now), Joiner(rng, owner.now)
    for _ in range(2):
        await owner.deliver(_bad_mac(stranger.request(url)), stranger.mailbox)
    assert owner.flooded() == []
    await owner.deliver(carol.request(url), stranger.mailbox)  # another sender's request
    (flood,) = [e["data"] for e in owner.flooded()]
    assert (flood["invite_id"], flood["reason"]) == (invite_id(url), "join_failures")
    assert "3 join requests" in flood["warning"]
    # The flood goes on: every legitimate request still reaches the human,
    # and the notice isn't repeated within the window.
    reached = set()
    for _ in range(5):
        await owner.deliver(_bad_mac(stranger.request(url)), stranger.mailbox)
        bob = Joiner(rng, owner.now)
        reached.add(await owner.deliver(bob.request(url), bob.mailbox))
        owner.clock.advance(60)
    assert reached <= {a["request_id"] for a in owner.engine.join_approvals()}
    assert len(owner.flooded()) == 1
    # A later burst, after the window, is told again.
    owner.clock.advance(JOIN_FAILURE_WINDOW_SECS)
    for _ in range(3):
        await owner.deliver(_bad_mac(stranger.request(url)), stranger.mailbox)
    assert len(owner.flooded()) == 2


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
    carol = Joiner(rng, owner.now)
    second = carol.request(url)
    await owner.deliver(second, carol.mailbox)
    for approval in owner.engine.join_approvals():
        owner.engine.reject(approval["request_id"])
    await owner.engine.expire()
    assert owner.ledger() == 2
    await owner.deliver(second, carol.mailbox)
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
    """A link thief with fresh identities fills the invite's pending cap and
    then its ledger quota, never the daemon's ledger: another invite's
    joiner still reaches the human, and the human hears of the flood."""
    await owner.restart(policy_max_pending_joins_per_invite=2)
    leaked = await owner.invite(max_uses=1)
    quota = replay.join_quota(1, owner.engine.config.policy_join_ledger_per_invite)
    assert quota == 64
    for _ in range(quota + 1):
        thief = Joiner(rng, owner.now)
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


def _forge(seen_request: bytes, url: str, name: str = "bob") -> bytes:
    """A link holder wraps a KeyPackage it saw elsewhere (a JoinRequest the
    victim sent to the holder's own invite) in a JoinRequest for ``url``:
    it knows the join key, so it can compute the MAC."""
    link = ac.parse_invite_url(url)
    seen = json.loads(seen_request)
    kp = unb64(seen["key_package"])
    mac = ac.join_request_mac(link.invite_id, link.secret_bytes(), kp, seen["mailbox_id"], name)
    forged = {**seen, "invite_id": link.invite_id_b64, "display_name": name, "mac": b64(mac)}
    return json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()


async def test_a_stale_key_package_doesnt_crowd_out_the_victims_own_request(
    owner: Owner, rng: random.Random
) -> None:
    """Review 52 F2: a link holder sends one of the victim's KeyPackages in
    its name. From the holder's own mailbox the sender check drops it
    (SPEC 6.2 step 3); a relay that lies about the sender gets it past
    that, and then the victim's own request still reaches the human, and
    both say how many requests claim the identity, so the human chooses."""
    url, elsewhere = await owner.invite(max_uses=5), await owner.invite()
    victim, attacker = Joiner(rng, owner.now), Joiner(rng, owner.now)
    stale = victim.request(elsewhere)  # stands for one sent to the holder's own invite
    await owner.deliver(_forge(stale, url), attacker.mailbox)
    assert owner.engine.join_approvals() == []
    forged_id = await owner.deliver(_forge(stale, url), victim.mailbox)
    real_id = await owner.deliver(victim.request(url), victim.mailbox)
    assert owner.audit() == []
    waiting = {w["request_id"]: w for w in owner.engine.join_approvals()}
    assert set(waiting) == {forged_id, real_id}
    assert {w["identity_requests"] for w in waiting.values()} == {2}
    events = [
        e["data"] for e in owner.engine.store.events(limit=100) if e["type"] == "pending_approval"
    ]
    assert [e["identity_requests"] for e in events] == [1, 2]
    owner.engine.reject(forged_id)
    (left,) = owner.engine.join_approvals()
    assert (left["request_id"], left["identity_requests"]) == (real_id, 1)
    # An exact copy of a waiting request is still dropped.
    await owner.deliver(_forge(stale, url), victim.mailbox)
    assert owner.audit() == ["join_replay"]


async def test_one_identity_has_a_few_requests_waiting_per_invite(
    owner: Owner, rng: random.Random
) -> None:
    """Fresh KeyPackages of one identity: at most MAX_PENDING_PER_IDENTITY
    wait per invite. The next is dropped and the human hears of it
    (``invite_flooded``); another invite has its own count, and once the
    human decided one, the identity may ask again."""
    url, other = await owner.invite(), await owner.invite()
    thief = Joiner(rng, owner.now)
    first = await owner.deliver(thief.request(url), thief.mailbox)
    for _ in range(MAX_PENDING_PER_IDENTITY):
        await owner.deliver(thief.request(url), thief.mailbox)
    await owner.deliver(thief.request(other), thief.mailbox)
    assert owner.audit() == ["join_identity_full"]
    assert [e["data"]["reason"] for e in owner.flooded()] == ["join_identity_full"]
    assert len(owner.engine.join_approvals()) == MAX_PENDING_PER_IDENTITY + 1
    owner.engine.reject(first)
    await owner.deliver(thief.request(url), thief.mailbox)
    assert len(owner.engine.join_approvals()) == MAX_PENDING_PER_IDENTITY + 1
    # Requests past the approval window no longer count.
    owner.clock.advance(3601)
    owner.engine.join_approvals()  # lapses them
    await owner.deliver(thief.request(url), thief.mailbox)
    assert [w["identity_requests"] for w in owner.engine.join_approvals()] == [1]


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
    first = b64(rng.randbytes(16))
    owner.engine.failpoints.arm("join_request.after_tx", action)  # ty: ignore[invalid-argument-type]
    with pytest.raises((FailpointError, SimulatedCrash)):
        await owner.deliver(request, bob.mailbox, msg_id=first)
    if action == "crash":
        await owner.restart()
    (approval,) = owner.engine.store.approvals("approving")
    assert approval["request_id"] == first
    intents = [r.payload.get("intent") for r in owner.engine.store.outbox()]
    assert {"type": "add", "request_id": first} in intents
    assert owner.ledger() == 1
    await owner.deliver(request, bob.mailbox, msg_id=first)  # the relay's redelivery
    await owner.deliver(request, bob.mailbox)
    assert owner.audit() == ["join_replay"]
    assert len(owner.engine.store.approvals("approving")) == 1


async def test_a_crash_after_the_record_keeps_the_approval_once(
    owner: Owner, rng: random.Random
) -> None:
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    request = bob.request(url)
    first = b64(rng.randbytes(16))
    owner.engine.failpoints.arm("join_request.after_tx", "crash")
    with pytest.raises(SimulatedCrash):
        await owner.deliver(request, bob.mailbox, msg_id=first)
    await owner.restart()
    await owner.deliver(request, bob.mailbox, msg_id=first)
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


# -- invites closed after a commit (docs/groups.md) ------------------------------------------


async def test_closed_invites_drop_their_secrets_and_are_revoked_when_the_relay_answers(
    owner: Owner, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed invite is `revoking` at once: its join requests are ignored
    and its secret goes, also while offline; the relay revocation is tried
    on every pass until the relay answers, whatever it answers."""
    url = await owner.invite()
    iid = invite_id(url)
    gid = owner.engine.store.invite(iid)["group_id"]  # ty: ignore[not-subscriptable]
    bob = Joiner(rng, owner.now)
    await owner.deliver(bob.request(url), bob.mailbox)
    groups = owner.engine.groups
    groups.close_invites(gid)
    groups.close_invites(gid)  # nothing left open: a no-op
    assert owner.engine.store.invite(iid)["status"] == "revoking"  # ty: ignore[not-subscriptable]
    # Offline: the secret goes, the row stays, and the reconnect tries again.
    assert await groups.revoke_closed_invites() is None
    assert owner.engine.keystore.get(f"invite/{iid}") is None
    assert owner.engine.store.invite(iid)["status"] == "revoking"  # ty: ignore[not-subscriptable]
    carol = Joiner(rng, owner.now)
    await owner.deliver(carol.request(url), carol.mailbox)
    assert len(owner.engine.join_approvals()) == 1  # the new request was ignored
    answers: list[Exception | None] = [
        RelayError("relay_unreachable", "down"),
        RelayError("invite_not_open", "gone"),
    ]

    async def revoke(_invite_id: str) -> None:
        answer = answers.pop(0)
        if answer is not None:
            raise answer

    monkeypatch.setattr(owner.engine.rest, "revoke_invite", revoke)
    monkeypatch.setattr(type(owner.engine.link), "connected", property(lambda _self: True))
    again = await groups.revoke_closed_invites()  # refused for now: after a backoff
    assert again is not None
    assert owner.now < again <= owner.now + 300
    assert owner.engine.store.invite(iid)["status"] == "revoking"  # ty: ignore[not-subscriptable]
    assert await groups.revoke_closed_invites() is None
    assert owner.engine.store.invite(iid)["status"] == "revoked"  # ty: ignore[not-subscriptable]
    assert answers == []


async def test_an_approval_for_a_group_already_left_is_not_held_back(
    owner: Owner, rng: random.Random
) -> None:
    """The size check needs an active group; one this instance left only
    fails its Add later, as before."""
    url = await owner.invite()
    bob = Joiner(rng, owner.now)
    first = await owner.deliver(bob.request(url), bob.mailbox)
    gid = owner.engine.store.approval(first)["group_id"]  # ty: ignore[not-subscriptable]
    owner.engine.store.update_group(gid, status="left")
    assert owner.engine.groups.room(gid) is None
    assert owner.engine.approve(first) == {"status": "approving"}


async def test_replayed_key_packages_that_fill_an_identitys_share_are_named(
    owner: Owner, rng: random.Random
) -> None:
    """Review 52 N3: four requests built from the victim's stale KeyPackages
    fill its share, and its own request is dropped. (A relay that lies
    about the sender delivers them; from the link holder's own mailbox the
    sender check drops them first, SPEC 6.2 step 3.) The human is told
    which identity and why (not the generic "the link may have leaked"),
    and the approvals view always has the current count, whatever each
    request's event said when it arrived."""
    url, elsewhere = await owner.invite(max_uses=5), await owner.invite()
    victim = Joiner(rng, owner.now)
    forged = [
        await owner.deliver(_forge(victim.request(elsewhere), url), victim.mailbox)
        for _ in range(MAX_PENDING_PER_IDENTITY)
    ]
    real_id = await owner.deliver(victim.request(url), victim.mailbox)
    assert owner.audit() == ["join_identity_full"]
    (flood,) = [e["data"] for e in owner.flooded()]
    assert (flood["reason"], flood["identity"]) == ("join_identity_full", victim.client.identity)
    assert victim.client.identity in flood["warning"]
    assert "replayed" in flood["warning"]
    assert "leaked" not in flood["warning"]
    events = [
        e["data"]["identity_requests"]
        for e in owner.engine.store.events(limit=100)
        if e["type"] == "pending_approval"
    ]
    assert events == [1, 2, 3, 4]  # each at its arrival
    waiting = owner.engine.join_approvals()
    assert sorted(w["request_id"] for w in waiting) == sorted(forged)
    assert real_id not in [w["request_id"] for w in waiting]
    assert {w["identity_requests"] for w in waiting} == {4}  # the view is current
    # Once the human rejects one, the victim's next request gets through.
    owner.engine.reject(forged[0])
    assert {w["identity_requests"] for w in owner.engine.join_approvals()} == {3}
    again = await owner.deliver(victim.request(url), victim.mailbox)
    assert again in [w["request_id"] for w in owner.engine.join_approvals()]
