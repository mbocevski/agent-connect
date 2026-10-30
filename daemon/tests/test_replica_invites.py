"""Replica invites in the daemon tier (docs/groups.md#replicas): the human
sees which instance each join request is for, a replica invite can be pinned
to the instance `identity import` printed, requests from anyone else never
use up its share of the join ledger, and an unpinned one is never approved
automatically.

Runtimes are never started, as in ``test_join_ledger.py``: invites are
created with the relay call stubbed and JoinRequests are built with
in-memory joiner clients. The end-to-end path is in
``harness/tests/test_replica_provisioning.py``.
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
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.relay import b64, unb64
from agentconnect.runtime import Options, Runtime
from agentconnect.runtime import ledger as replay
from agentconnect.runtime.engine import MAX_PENDING_PER_IDENTITY, DaemonError, Engine

RELAY = "127.0.0.1:1"


class Owner:
    """An inviter whose runtime is never started."""

    def __init__(
        self,
        tmp: Path,
        rng: random.Random,
        clock: FakeClock,
        monkeypatch: pytest.MonkeyPatch,
        *,
        auto_approve: bool = False,
    ) -> None:
        self.rng, self.clock, self.monkeypatch = rng, clock, monkeypatch
        config = Config(
            relay_url=f"ws://{RELAY}",
            relay_host=RELAY,
            data_dir=tmp / "data",
            keystore="file",
            api_socket=tmp / "s.sock",
            auto_approve=auto_approve,
        )
        self.rt = Runtime(
            config,
            clock=clock,
            keystore=FileKeystore(tmp / "data" / "keys"),
            options=Options(testing=Seeded(rng.getrandbits(63))),
            serve_api=False,
        )
        self.gid = self.engine.create_group("Replicas", "")

    @property
    def engine(self) -> Engine:
        return self.rt._engine

    @property
    def now(self) -> int:
        return self.clock.unix_millis() // 1000

    async def invite(self, *, max_uses: int = 1, **kind: Any) -> dict[str, Any]:
        async def registered(_meta: dict[str, Any]) -> dict[str, Any]:
            return {}

        self.engine.client._set_time_for_testing(self.now)
        self.monkeypatch.setattr(self.engine.rest, "create_invite", registered)
        return await self.engine.create_invite(
            self.gid, ttl_secs=7 * 86_400, max_uses=max_uses, **kind
        )

    async def deliver(self, request: bytes, sender: str) -> str:
        msg_id = b64(self.rng.randbytes(16))
        env = {"v": 0, "kind": "join_request", "msg_id": msg_id, "sender": sender}
        self.engine.client._set_time_for_testing(self.now)
        await self.engine._handle_frame({"t": "deliver", "env": {**env, "ct": b64(request)}})
        return msg_id

    def audit(self) -> list[str]:
        rows = self.engine.store.audit(limit=10_000)
        return [r["reason"] for r in rows if r["kind"] == "join_request"]

    def identity(self) -> ac.Identity:
        return ac.Identity.from_secret_bytes(self.engine.keystore.get("identity") or b"")


class Joiner:
    """A joiner's instance, in memory: of ``identity``, or of a new one."""

    def __init__(self, rng: random.Random, now: int, identity: ac.Identity | None = None) -> None:
        identity = identity or ac.Identity._generate_for_testing(rng.getrandbits(63))
        instance = identity._create_instance_for_testing(rng.getrandbits(63), now)
        self.instance_id = instance.instance_id_hex
        self.client = ac.Client._for_testing(None, instance.to_secret_bytes(), rng.getrandbits(63))
        self.client._set_time_for_testing(now)

    def request(self, url: str, name: str = "replica") -> bytes:
        return self.client.create_join_request(ac.parse_invite_url(url), name)

    @property
    def mailbox(self) -> str:
        return self.client.mailbox_id


def rewrapped(seen_request: bytes, url: str, name: str = "replica") -> bytes:
    """What a holder of ``url`` builds from a KeyPackage it saw elsewhere."""
    link = ac.parse_invite_url(url)
    seen = json.loads(seen_request)
    kp = unb64(seen["key_package"])
    mac = ac.join_request_mac(link.invite_id, link.secret_bytes(), kp, seen["mailbox_id"], name)
    forged = {**seen, "invite_id": link.invite_id_b64, "display_name": name, "mac": b64(mac)}
    return json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture
async def owner(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Owner]:
    o = Owner(tmp_path, rng, fake_clock, monkeypatch)
    yield o
    await o.rt.stop(flush=0)


async def stale_requests(owner: Owner, rng: random.Random, url: str, n: int) -> list[Joiner]:
    """``n`` requests for ``url`` built from KeyPackages of the owner's own
    identity that a link holder saw elsewhere (each sent to another invite),
    delivered by a relay that names each KeyPackage's own mailbox as the
    sender: from the holder's mailbox the sender check drops them first
    (SPEC 6.2 step 3)."""
    elsewhere = (await owner.invite(max_uses=n))["url"]
    stale = []
    for _ in range(n):
        old = Joiner(rng, owner.now, owner.identity())
        await owner.deliver(rewrapped(old.request(elsewhere), url), old.mailbox)
        stale.append(old)
    return stale


# -- F1: the human sees the instance ------------------------------------------------------


@pytest.mark.parametrize("replica", [False, True])
async def test_an_approval_shows_the_joiners_instance_and_mailbox(
    owner: Owner, rng: random.Random, replica: bool
) -> None:
    url = (await owner.invite(replica=replica))["url"]
    joiner = Joiner(rng, owner.now, owner.identity() if replica else None)
    rid = await owner.deliver(joiner.request(url), joiner.mailbox)
    (shown,) = owner.engine.join_approvals()
    assert shown["request_id"] == rid
    assert (shown["instance_id"], shown["mailbox_id"]) == (joiner.instance_id, joiner.mailbox)
    (event,) = [e for e in owner.engine.store.events() if e["type"] == "pending_approval"]
    assert (event["data"]["instance_id"], event["data"]["mailbox_id"]) == (
        joiner.instance_id,
        joiner.mailbox,
    )


async def test_two_requests_of_one_identity_differ_in_their_instance(
    owner: Owner, rng: random.Random
) -> None:
    """Review 55 F1: on an unpinned replica invite a rewrapped KeyPackage of
    another instance is told apart from the replica by its instance id."""
    url = (await owner.invite(replica=True))["url"]
    (stale,) = await stale_requests(owner, rng, url, 1)
    replica = Joiner(rng, owner.now, owner.identity())
    await owner.deliver(replica.request(url), replica.mailbox)
    shown = sorted(a["instance_id"] for a in owner.engine.join_approvals())
    assert shown == sorted([stale.instance_id, replica.instance_id])


async def test_a_pinned_replica_invite_admits_only_its_instance(
    owner: Owner, rng: random.Random
) -> None:
    """Review 55 F1 and F1b: pinned to the instance `identity import`
    printed, a replica invite drops every other instance of the identity,
    so stale KeyPackages can neither pass for the replica nor fill the
    identity's share of pending requests."""
    replica = Joiner(rng, owner.now, owner.identity())
    made = await owner.invite(replica=True, instance=replica.instance_id)
    assert owner.engine.store.invite(made["invite_id"])["instance"] == replica.instance_id  # ty: ignore[not-subscriptable]
    await stale_requests(owner, rng, made["url"], MAX_PENDING_PER_IDENTITY)
    assert owner.audit().count("join_not_replica") == MAX_PENDING_PER_IDENTITY
    rid = await owner.deliver(replica.request(made["url"]), replica.mailbox)
    pending = owner.engine.join_approvals()
    assert [(a["request_id"], a["instance_id"]) for a in pending] == [(rid, replica.instance_id)]


async def test_an_instance_pin_is_checked_when_the_invite_is_made(owner: Owner) -> None:
    with pytest.raises(DaemonError, match="--replica"):
        await owner.invite(instance="0" * 16)
    for bad in ("0" * 15, "G" * 16, "ABCDEF0123456789"):
        with pytest.raises(DaemonError, match="16 lowercase hex"):
            await owner.invite(replica=True, instance=bad)
    with pytest.raises(DaemonError, match="this instance"):
        await owner.invite(replica=True, instance=owner.engine.instance.instance_id_hex)
    assert owner.engine.store.invites("open") == []


# -- F2: other identities use none of the invite's share ---------------------------------


async def test_other_identities_use_none_of_a_replica_invites_quota(
    owner: Owner, rng: random.Random
) -> None:
    """Review 55 F2: requests a replica invite always drops are dropped
    before the quota and the ledger, so they can't crowd the replica out."""
    url = (await owner.invite(replica=True))["url"]
    quota = replay.join_quota(1, owner.engine.config.policy_join_ledger_per_invite)
    for _ in range(quota + 1):
        thief = Joiner(rng, owner.now)
        await owner.deliver(thief.request(url), thief.mailbox)
    assert owner.audit() == ["join_not_replica"] * (quota + 1)
    assert not [e for e in owner.engine.store.events() if e["type"] == "invite_flooded"]
    replica = Joiner(rng, owner.now, owner.identity())
    await owner.deliver(replica.request(url), replica.mailbox)
    assert [a["instance_id"] for a in owner.engine.join_approvals()] == [replica.instance_id]


# -- auto_approve -------------------------------------------------------------------------


async def test_auto_approve_waits_for_the_human_on_an_unpinned_replica_invite(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = Owner(tmp_path, rng, fake_clock, monkeypatch, auto_approve=True)
    try:
        unpinned = (await owner.invite(replica=True))["url"]
        first = Joiner(rng, owner.now, owner.identity())
        rid = await owner.deliver(first.request(unpinned), first.mailbox)
        assert (owner.engine.store.approval(rid) or {})["status"] == "pending"
        second = Joiner(rng, owner.now, owner.identity())
        pinned = (await owner.invite(replica=True, instance=second.instance_id))["url"]
        rid = await owner.deliver(second.request(pinned), second.mailbox)
        assert (owner.engine.store.approval(rid) or {})["status"] == "approving"
        # An ordinary invite is approved automatically as before.
        other = Joiner(rng, owner.now)
        plain = (await owner.invite())["url"]
        rid = await owner.deliver(other.request(plain), other.mailbox)
        assert (owner.engine.store.approval(rid) or {})["status"] == "approving"
    finally:
        await owner.rt.stop(flush=0)
