"""Approving a knock and joining from its Welcome, listing content and
renewal, through the bindings (SPEC 6.6.4, 6.6.5, 13.2.2)."""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

import agentconnect_core as ac

DIRECTORY = "directory.example.org"
RELAY = "relay.example.org"
NAME = "release-planner"
PURPOSE = "Plans release trains"
T0 = 1_792_497_600


def make_client(rng: random.Random, identity: ac.Identity | None = None) -> ac.Client:
    ik = identity or ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = ik._create_instance_for_testing(seed=rng.getrandbits(64), now=T0)
    client = ac.Client._for_testing(None, instance.to_secret_bytes(), rng.getrandbits(64))
    client._set_time_for_testing(T0)
    return client


class Pair:
    """An owner with a door and a knocker that knocked on it."""

    def __init__(self, rng: random.Random) -> None:
        self.owner = make_client(rng)
        self.knocker = make_client(rng)
        self.door = self.owner.generate_door(T0 + 7 * 86_400)
        self.sealed, self.pending = self.knocker.create_knock(
            self.door.id, self.door.public_key, "Bob's agent", "About 2.0", ts=T0
        )
        opened = self.door.open_knock(self.door.id, self.sealed, T0 + 60)
        self.verified = self.owner.verify_knock(opened)

    def approve(self, knock: ac.VerifiedKnock | None = None) -> tuple[bytes, dict[str, Any]]:
        gid = self.owner.create_group(NAME, PURPOSE)
        out = self.owner.add_knock(gid, knock or self.verified, T0 + 120)
        self.owner.confirm_pending_commit(gid, out["msg_id"])
        return gid, out

    def join(self, wrapped: bytes, key: str | None = None, context: bytes | None = None) -> bytes:
        return self.knocker.join_knock(
            self.pending, self.owner.identity, NAME, wrapped, key=key, context=context
        )


def test_an_approved_knock_joins_after_a_restart(rng: random.Random) -> None:
    p = Pair(rng)
    assert p.pending.ts == T0
    assert p.pending.key_package_ref == p.verified.key_package_ref
    stored = p.verified.to_secret_bytes()
    restored = p.owner.restore_knock(stored)
    assert restored.knock_id == p.verified.knock_id
    assert restored.identity == p.knocker.identity
    gid, out = p.approve(restored)
    assert out["routing"]["add"] == [p.knocker.mailbox_id]
    assert p.join(out["welcome"]) == gid
    assert p.owner.sas(gid) == p.knocker.sas(gid)
    meta = json.loads(p.knocker.meta(gid))
    assert (meta["name"], meta["created_by"]) == (NAME, p.owner.identity)
    # Nothing secret in the reprs.
    secret = json.loads(stored)["welcome_secret"]
    assert secret not in repr(p.verified) + repr(restored) + repr(p.pending)


def test_add_knock_refuses_a_lapsed_or_used_knock(rng: random.Random) -> None:
    p = Pair(rng)
    gid = p.owner.create_group(NAME, PURPOSE)
    with pytest.raises(ac.AgentConnectError) as e:
        p.owner.add_knock(gid, p.verified, p.verified.lapses_at + 1)
    assert e.value.kind == "expired"
    assert not p.owner.has_pending_commit(gid)
    p.owner._mark_key_package_used_for_testing(p.verified.key_package_ref)
    with pytest.raises(ac.AgentConnectError) as e:
        p.owner.add_knock(gid, p.verified, T0)
    assert e.value.kind == "key_package_reused"
    with pytest.raises(ac.AgentConnectError) as e:
        p.owner.restore_knock(p.verified.to_secret_bytes())
    assert e.value.kind == "key_package_reused"


def test_a_tampered_stored_knock_does_not_restore(rng: random.Random) -> None:
    p = Pair(rng)
    tampered = p.verified.to_secret_bytes().replace(b"Bob's agent", b"Mallory")
    with pytest.raises(ac.AgentConnectError) as e:
        p.owner.restore_knock(tampered)
    assert e.value.kind == "signature"
    with pytest.raises(ac.AgentConnectError) as e:
        p.owner.restore_knock(b"not json")
    assert e.value.kind == "malformed"


def test_a_welcome_for_another_listing_is_a_mismatch(rng: random.Random) -> None:
    p = Pair(rng)
    _, out = p.approve()
    with pytest.raises(ac.AgentConnectError) as e:
        p.knocker.join_knock(p.pending, p.owner.identity, "other-name", out["welcome"])
    assert e.value.kind == "welcome_mismatch"
    # The KeyPackage is spent: the right expectation fails now too.
    with pytest.raises(ac.AgentConnectError):
        p.join(out["welcome"])


def test_a_welcome_under_another_knock_does_not_open(rng: random.Random) -> None:
    p = Pair(rng)
    _, other = p.knocker.create_knock(p.door.id, p.door.public_key, "b", ts=T0)
    _, out = p.approve()
    with pytest.raises(ac.AgentConnectError) as e:
        p.knocker.join_knock(other, p.owner.identity, NAME, out["welcome"])
    assert e.value.kind == "authentication"
    p.join(out["welcome"])


def test_a_journalled_knock_join_replays(rng: random.Random) -> None:
    p = Pair(rng)
    gid, out = p.approve()
    assert p.join(out["welcome"], key="k1", context=b"c") == gid
    assert p.join(out["welcome"], key="k1", context=b"c") == gid
    [entry] = p.knocker.journal_pending()
    assert entry["welcome"]
    assert entry["context"] == b"c"
    assert p.knocker.journal_consume("k1")
    with pytest.raises(ac.AgentConnectError):
        p.join(out["welcome"], key="k1", context=b"c")


def test_generated_doors_follow_the_client_seed(rng: random.Random) -> None:
    seed = rng.getrandbits(64)
    ik = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = ik._create_instance_for_testing(seed=rng.getrandbits(64), now=T0)
    a = ac.Client._for_testing(None, instance.to_secret_bytes(), seed)
    b = ac.Client._for_testing(None, instance.to_secret_bytes(), seed)
    da, db = a.generate_door(T0 + 3600), b.generate_door(T0 + 3600)
    assert (da.id, da.public_key) == (db.id, db.public_key)
    assert da.expires_at == T0 + 3600


def test_the_ledger_capacity_refuses_loading_more(rng: random.Random) -> None:
    ledger = ac.KnockLedger(2)
    assert ledger.capacity == 2
    assert ac.KnockLedger().capacity == ac.DEFAULT_LEDGER_CAPACITY
    ids = [rng.randbytes(16) for _ in range(3)]
    for i in ids[:2]:
        ledger.insert(i, rng.randbytes(32), T0 + 3900)
    with pytest.raises(ac.AgentConnectError) as e:
        ledger.insert(ids[2], rng.randbytes(32), T0 + 3900)
    assert e.value.kind == "busy"
    assert len(ledger) == 2


def test_bad_arguments_raise_instead_of_panicking(rng: random.Random) -> None:
    p = Pair(rng)
    with pytest.raises(ac.AgentConnectError):
        p.knocker.create_knock(b"short", p.door.public_key, "b")
    with pytest.raises(ac.AgentConnectError):
        p.knocker.create_knock(p.door.id, p.door.public_key, "b", ts=2**53)
    with pytest.raises(ac.AgentConnectError):
        p.owner.add_knock(b"no such group", p.verified, T0)
    with pytest.raises(ac.AgentConnectError):
        p.join(b"")
    with pytest.raises(ac.AgentConnectError) as e:
        ac.is_public_address("not an address")
    assert e.value.kind == "malformed"


def test_constants_and_names() -> None:
    assert ac.MAX_LISTING_BYTES == 32 * 1024
    assert ac.MAX_OWNER_FILE_BYTES == 64 * 1024
    assert ac.MAX_DOOR_LIFETIME_SECS == 7 * 86_400
    assert (ac.DOOR_GRACE_SECS, ac.KNOCK_LIFETIME_SECS, ac.KNOCK_FUTURE_SECS) == (3600, 3600, 300)
    assert ac.is_listing_name(NAME)
    assert not ac.is_listing_name("Release-Planner")
    assert ac.is_public_address("1.1.1.1")
    assert not ac.is_public_address("::1")


CONTENT = {
    "name": "Release planner",
    "description": "Plans release trains.",
    "version": "1.0.0",
    "provider": {"organization": "Example Ltd", "url": "https://example.com"},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "plan", "name": "Planning", "description": "Plans.", "tags": ["planning"]}],
}


def test_sign_listing_content_and_renew(rng: random.Random) -> None:
    dk = ac.DirectoryKey._generate_for_testing(rng.getrandbits(64))
    ik = ac.Identity._generate_for_testing(rng.getrandbits(64))
    token = dk.issue_token(DIRECTORY, NAME, ik.id, T0, T0 + 86_400, owner_domain="example.com")
    owner = make_client(rng, ik)
    door = owner.generate_door(T0 + 86_400)
    content = json.dumps(CONTENT, indent=2).encode()
    canonical = ac.canonical_listing_content(content)
    listing = ac.sign_listing_content(
        content,
        ik,
        directory=DIRECTORY,
        relay=RELAY,
        seq=T0,
        issued_at=T0,
        token_json=token,
        door=door,
    )
    # The name and the owner domain come from the token.
    assert (listing.name, listing.owner_domain, listing.relay) == (NAME, "example.com", RELAY)
    assert listing.content == canonical
    assert listing.door == {"id": door.id, "key": door.public_key, "expires_at": door.expires_at}
    listing.check_token(DIRECTORY, [dk.public_key], T0)
    renewed = listing.renew(ik, T0 + 1, T0 + 60, owner.generate_door(T0 + 7 * 86_400))
    assert renewed.content == canonical
    assert renewed.token_id == listing.token_id
    assert renewed.replaces(listing)
    closed = renewed.renew(ik, T0 + 2, T0 + 120, None)
    assert closed.door is None
    with pytest.raises(ac.AgentConnectError) as e:
        listing.renew(ik, T0, T0 + 60, None)
    assert e.value.kind == "superseded"
    stranger = ac.Identity._generate_for_testing(rng.getrandbits(64))
    with pytest.raises(ac.AgentConnectError):
        listing.renew(stranger, T0 + 1, T0 + 60, None)
    # Another owner domain than the token pins doesn't bind.
    with pytest.raises(ac.AgentConnectError) as e:
        ac.sign_listing_content(
            content,
            ik,
            directory=DIRECTORY,
            relay=RELAY,
            seq=1,
            issued_at=T0,
            token_json=token,
            owner_domain="other.example",
        )
    assert e.value.kind == "token_mismatch"
    # A full card is not content.
    card = json.loads(listing.unsigned_card)
    with pytest.raises(ac.AgentConnectError) as e:
        ac.canonical_listing_content(json.dumps(card).encode())
    assert e.value.kind == "malformed"
