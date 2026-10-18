"""The owner's listing in the daemon tier: publish, renewal, withdraw
(docs/discovery.md). The directory and the relay's door registry are fakes
on ``httpx.MockTransport`` that check through the core, on the fake clock,
so a door's whole life runs in a few steps without the network."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import httpx
import pytest

import agentconnect_core as ac
from agentconnect.clock import FakeClock
from agentconnect.config import Config, DirectoryConfig
from agentconnect.failpoints import FailpointError, SimulatedCrash
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.ownerfile import OwnerFetch
from agentconnect.relay import b64
from agentconnect.runtime import ApiError, Options, Runtime
from agentconnect.runtime.api import ApiServer
from agentconnect.runtime.engine import Engine
from agentconnect.runtime.listing import ListingManager
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE
from agentconnect_harness.fake_directory import DOWN, FakeDirectory, FakeDoors

DIR = "directory.example.org"
RELAY = "127.0.0.1:1"
NAME = "release-planner"
DAY = 86_400
CARD: dict[str, Any] = {
    "name": "Release planner",
    "description": "Plans release trains.",
    "version": "1.0.0",
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "plan", "name": "Planning", "description": "Plans.", "tags": ["planning"]}],
}
PROVIDER = {"organization": "Example Ltd", "url": "https://example.com"}


class Owner:
    """An owner-file fetcher with canned answers."""

    def __init__(self) -> None:
        self.files: dict[str, OwnerFetch] = {}
        self.asked: list[str] = []

    async def fetch(self, domain: str) -> OwnerFetch:
        self.asked.append(domain)
        return self.files.get(domain, OwnerFetch(None, "unreachable"))


class World:
    """One runtime (never started: the test drives the worker's steps) with
    a fake directory and a fake door registry that outlive its restarts."""

    def __init__(self, tmp: Path, rng: random.Random, clock: FakeClock, lifetime: int | None):
        self.tmp, self.rng, self.clock, self.lifetime = tmp, rng, clock, lifetime
        self.dk = ac.DirectoryKey._generate_for_testing(rng.getrandbits(63))
        self.calls: list[str] = []
        self.directory = FakeDirectory(DIR, self.dk, [RELAY], clock, log=self.calls)
        self.doors = FakeDoors(clock, log=self.calls)
        self.owner = Owner()
        self.pinned = True  # whether the config still has the directory
        self.rt = self._runtime()

    def config(self) -> Config:
        return Config(
            relay_url=f"ws://{RELAY}",
            relay_host=RELAY,
            data_dir=self.tmp / "data",
            keystore="file",
            api_socket=self.tmp / "s.sock",
            directories=(DirectoryConfig(DIR, (self.dk.public_key,), f"https://{DIR}"),)
            if self.pinned
            else (),
        )

    def _runtime(self) -> Runtime:
        options = Options(
            testing=Seeded(self.rng.getrandbits(63)),
            relay_transport=self.doors.transport,
            directory_transport=self.directory.transport,
            owner_fetcher=self.owner,
            door_lifetime_secs=self.lifetime,
        )
        return Runtime(
            self.config(),
            clock=self.clock,
            keystore=FileKeystore(self.tmp / "data" / "keys"),
            options=options,
            serve_api=False,
        )

    @property
    def engine(self) -> Engine:
        return self.rt._engine

    @property
    def mgr(self) -> ListingManager:
        return self.engine.listings

    @property
    def now(self) -> int:
        return self.engine.now()

    async def restart(self) -> None:
        await self.rt.stop(flush=0)
        self.rt = self._runtime()

    def token(self, name: str = NAME, **kw: Any) -> dict[str, Any]:
        return json.loads(self.directory.token(name, self.engine.me, **kw))

    def body(
        self, name: str = NAME, card: dict[str, Any] | None = None, **kw: Any
    ) -> dict[str, Any]:
        return {"directory": DIR, "card": card or CARD, "token": self.token(name, **kw)}

    async def publish(self, body: dict[str, Any] | None = None) -> dict[str, Any]:
        body = body or self.body()
        shown = await self.mgr.preview(body)
        return await self.mgr.publish({**body, "content_sha256": shown["content_sha256"]})

    def row(self, name: str = NAME) -> dict[str, Any]:
        row = self.engine.store.listing(DIR, name)
        assert row is not None
        return row

    def corrupt_key(self, door_id: str) -> None:
        """Overwrite a door's stored key (no store method writes one)."""
        self.engine.store._db.execute(
            "UPDATE doors SET secret = ? WHERE door_id = ?", (b"not a key", door_id)
        )

    def door_rows(self) -> list[dict[str, Any]]:
        return self.engine.store.doors()

    def doors_in(self, state: str) -> list[str]:
        return [d["door_id"] for d in self.door_rows() if d["state"] == state]

    def events(self, kind: str) -> list[dict[str, Any]]:
        return [e["data"] for e in self.engine.store.events(limit=1000) if e["type"] == kind]

    def listed(self, name: str = NAME) -> ac.Listing:
        listing = self.directory.listing(name)
        assert listing is not None
        return listing

    async def at(self, when: int) -> float | None:
        """Move the clock to ``when`` and run one worker step."""
        self.clock.advance(when - self.now)
        return await self.mgr.step()


@pytest.fixture
async def world(tmp_path: Path, rng: random.Random, fake_clock: FakeClock) -> Any:
    w = World(tmp_path, rng, fake_clock, None)
    yield w
    await w.rt.stop(flush=0)


async def test_preview_shows_what_would_be_signed_and_sends_nothing(world: World) -> None:
    shown = await world.mgr.preview(world.body())
    assert shown["name"] == NAME
    assert shown["directory"] == DIR
    assert shown["identity"] == world.engine.me
    assert shown["content"] == json.loads(ac.canonical_listing_content(json.dumps(CARD).encode()))
    assert shown["owner_domain"] is None
    assert shown["owner_file_entry"] is None
    assert shown["warnings"] == []
    assert shown["token"]["expires_at"] == world.now + 30 * DAY
    assert world.calls == []
    assert world.door_rows() == []
    assert world.engine.store.listings() == []


async def test_preview_warns_about_groups_and_an_expiring_token(world: World) -> None:
    world.engine.create_group("Ops", "deploys")
    shown = await world.mgr.preview(world.body(lifetime=10 * DAY))
    assert [w["code"] for w in shown["warnings"]] == ["identity_in_groups", "token_expires_soon"]


def _foreign_token(world: World) -> dict[str, Any]:
    other = ac.DirectoryKey._generate_for_testing(world.rng.getrandbits(63))
    return json.loads(other.issue_token(DIR, NAME, world.engine.me, world.now, world.now + DAY))


def _other_identity_token(world: World) -> dict[str, Any]:
    other = ac.Identity._generate_for_testing(world.rng.getrandbits(63))
    return json.loads(world.directory.token(NAME, other.id))


@pytest.mark.parametrize(
    ("change", "status", "code"),
    [
        (lambda w, b: b | {"directory": "elsewhere.example"}, 400, "unknown_directory"),
        (lambda w, b: b | {"directory": 7}, 400, "bad_request"),
        (lambda w, b: b | {"card": "text"}, 400, "bad_request"),
        (lambda w, b: b | {"owner_domain": 3}, 400, "bad_request"),
        (lambda w, b: b | {"token": {"v": 0}}, 400, "bad_token"),
        (lambda w, b: b | {"token": _foreign_token(w)}, 403, "unknown_key"),
        (lambda w, b: b | {"token": _other_identity_token(w)}, 403, "token_not_for_identity"),
        (lambda w, b: b | {"card": {**CARD, "signatures": []}}, 400, "bad_card"),
        (lambda w, b: b | {"card": {**CARD, "skills": []}}, 400, "bad_card"),
        # A provider needs an owner domain its URL sits under.
        (lambda w, b: b | {"card": {**CARD, "provider": PROVIDER}}, 400, "bad_card"),
        (
            lambda w, b: (
                b | {"token": w.token(owner_domain="example.com"), "owner_domain": "x.org"}
            ),
            400,
            "bad_request",
        ),
    ],
)
async def test_preview_refusals(world: World, change: Any, status: int, code: str) -> None:
    with pytest.raises(ApiError) as e:
        await world.mgr.preview(change(world, world.body()))
    assert (e.value.status, e.value.code) == (status, code)
    assert world.calls == []


async def test_a_full_agent_card_is_refused_by_its_extra_fields(world: World) -> None:
    card = {**CARD, "supportedInterfaces": [], "signatures": []}
    with pytest.raises(ApiError, match="remove: signatures, supportedInterfaces"):
        await world.mgr.preview(world.body(card=card))


async def test_an_expired_token_is_invalid(world: World) -> None:
    body = world.body(lifetime=3600)
    world.clock.advance(3600)
    with pytest.raises(ApiError) as e:
        await world.mgr.preview(body)
    assert (e.value.status, e.value.code) == (403, "token_invalid")


async def test_the_owner_file_is_checked_and_its_entry_shown(world: World) -> None:
    body = world.body(card={**CARD, "provider": PROVIDER}, owner_domain="example.com")
    shown = await world.mgr.preview(body)
    assert shown["owner_domain"] == "example.com"
    assert shown["owner_file_entry"] == {
        "identity": world.engine.me,
        "fingerprint": world.engine.identity.fingerprint,
        "listings": [f"{DIR}/a/{NAME}"],
    }
    assert [w["code"] for w in shown["warnings"]] == ["owner_file_unreachable"]
    assert world.owner.asked == ["example.com"]
    others = json.dumps(
        {"v": 0, "identities": [{"identity": _other_identity_token(world)["identity"]}]}
    )
    world.owner.files["example.com"] = OwnerFetch(others.encode())
    shown = await world.mgr.preview(body)
    assert [w["code"] for w in shown["warnings"]] == ["owner_file_missing_identity"]
    ours = {"v": 0, "identities": [shown["owner_file_entry"]]}
    world.owner.files["example.com"] = OwnerFetch(json.dumps(ours).encode())
    assert (await world.mgr.preview(body))["warnings"] == []
    # The domain the token pins is used without being asked for.
    assert (await world.mgr.preview(body | {"owner_domain": "example.com"}))["warnings"] == []


async def test_publish_registers_a_door_signs_and_posts(world: World) -> None:
    out = await world.publish()
    listing = world.listed()
    (door_id,) = world.doors.created
    assert listing.door is not None
    assert b64(listing.door["id"]) == door_id
    assert listing.door["expires_at"] == world.now + 604_800 - 3600
    assert listing.identity == world.engine.me
    assert listing.relay == RELAY
    assert listing.seq == world.now
    assert world.calls == ["POST /v0/doors", "POST /v0/listings"]
    issued = listing.issued_at
    assert out == {
        "directory": DIR,
        "name": NAME,
        "url": listing.url,
        "seq": listing.seq,
        "state": "published",
        "door_expires_at": listing.door["expires_at"],
        "renews_at": issued + (listing.door["expires_at"] - issued) // 2,
        "token_expires_at": world.now + 30 * DAY,
        "owner_domain": None,
        "owner_state": "unclaimed",
        "warnings": [],
        "retrying": False,
    }
    assert world.doors_in("current") == [door_id]
    assert world.mgr.door(door_id) is not None
    (event,) = world.events("listing_published")
    assert event == {
        "directory": DIR,
        "name": NAME,
        "seq": listing.seq,
        "url": listing.url,
        "door_expires_at": listing.door["expires_at"],
        "token_expires_at": world.now + 30 * DAY,
    }
    # The agent sees listing events: they carry nothing about any peer.
    assert [e["type"] for e in (await world.rt.agent.events())["events"]] == ["listing_published"]
    status = (await world.rt.agent.listing_status())["listing"]
    assert status["state"] == "published"
    assert status["door"] == {
        "expires_at": out["door_expires_at"],
        "renews_at": out["renews_at"],
        "expiring": False,
    }
    assert status["retrying"] is None
    assert status["doors_open"] == 1
    assert status["token"]["warn_at"] == out["token_expires_at"] - 14 * DAY
    assert status["last_error"] is None
    assert status["url"] == listing.url


async def test_publish_needs_the_previewed_text(world: World) -> None:
    body = world.body()
    with pytest.raises(ApiError) as e:
        await world.mgr.publish({**body, "content_sha256": "0" * 64})
    assert e.value.code == "card_changed"
    with pytest.raises(ApiError, match="content_sha256"):
        await world.mgr.publish(body)
    assert world.calls == []


async def test_one_listing_per_runtime(world: World) -> None:
    await world.publish()
    other = world.body("other-name")
    with pytest.raises(ApiError) as e:
        await world.mgr.preview(other)
    assert e.value.code == "listing_exists"
    await world.mgr.withdraw()
    await world.publish(other)
    assert world.listed("other-name").seq > 0
    assert (await world.rt.agent.listing_status())["listing"]["name"] == "other-name"


async def test_a_door_is_never_longer_than_the_token(world: World) -> None:
    await world.publish(world.body(lifetime=3 * DAY))
    door = world.listed().door
    assert door is not None
    assert door["expires_at"] == world.now + 3 * DAY


@pytest.mark.parametrize(
    ("status", "code", "api_status", "api_code"),
    [
        (409, "name_held", 409, "name_held"),
        (403, "token_revoked", 403, "token_revoked"),
        (400, "bad_listing", 400, "bad_listing"),
        (413, "too_large", 413, "too_large"),
        (404, "something_else", 502, "directory"),
    ],
)
async def test_a_refused_first_publish_closes_its_door(
    world: World, status: int, code: str, api_status: int, api_code: str
) -> None:
    world.directory.faults.fail("POST", "/v0/listings", status, code, "no\x1b[2J")
    with pytest.raises(ApiError) as e:
        await world.publish()
    assert (e.value.status, e.value.code) == (api_status, api_code)
    assert "\x1b" not in str(e.value)
    assert world.doors.closed == world.doors.created
    assert world.door_rows() == []
    row = world.row()
    assert row["state"] == "refused"
    assert row["pending"] is None
    assert json.loads(row["last_error"])["code"] == (code if api_code != "directory" else api_code)
    # Nothing was published, so another listing may be.
    await world.publish(world.body("other-name"))


async def test_a_refused_republish_keeps_the_published_listing(world: World) -> None:
    await world.publish()
    first = world.listed()
    world.directory.faults.fail("POST", "/v0/listings", 409, "name_held")
    changed = {**CARD, "description": "Plans release trains, faster."}
    with pytest.raises(ApiError):
        await world.publish(world.body(card=changed))
    row = world.row()
    assert row["state"] == "published"
    assert row["content"] == first.content.decode()
    assert row["seq"] == first.seq
    assert first.door is not None
    assert world.doors_in("current") == [b64(first.door["id"])]
    assert len(world.doors.created) == 2
    assert world.doors.closed == world.doors.created[1:]


async def test_republishing_new_text_retires_the_old_door(world: World) -> None:
    await world.publish()
    first = world.listed()
    changed = {**CARD, "description": "Plans release trains, faster."}
    await world.publish(world.body(card=changed))
    second = world.listed()
    assert second.seq > first.seq
    assert second.description == "Plans release trains, faster."
    assert world.doors_in("retiring") == [world.doors.created[0]]
    assert world.doors_in("current") == [world.doors.created[1]]
    assert len(world.events("listing_published")) == 2


async def test_a_directory_that_doesnt_answer_gets_the_same_bytes_again(world: World) -> None:
    world.directory.faults.fail("POST", "/v0/listings", DOWN, times=2)
    out = await world.publish()
    assert (out["state"], out["retrying"]) == ("publishing", True)
    assert out["seq"] == world.row()["max_signed_seq"]
    assert world.directory.listing(NAME) is None
    assert await world.mgr.step() == world.now + 60
    await world.at(world.now + 59)
    assert len(world.directory.posts) == 1  # not due yet
    await world.at(world.now + 1)
    assert world.row()["attempts"] == 2  # down again: 120 s now
    await world.at(world.now + 120)
    assert world.row()["state"] == "published"
    assert world.directory.posts == [world.directory.posts[0]] * 3
    assert len(world.doors.created) == 1
    assert world.events("listing_published")


@pytest.mark.parametrize(
    ("status", "code"), [(500, "internal"), (429, "rate_limited"), (409, "conflict")]
)
async def test_not_now_answers_are_retried(world: World, status: int, code: str) -> None:
    world.directory.faults.fail("POST", "/v0/listings", status, code)
    assert (await world.publish())["retrying"]
    await world.at(world.now + 60)
    assert world.row()["state"] == "published"


async def test_a_relay_that_doesnt_register_the_door_publishes_nothing(world: World) -> None:
    world.doors.faults.fail("POST", "/v0/doors", DOWN)
    with pytest.raises(ApiError) as e:
        await world.publish()
    assert (e.value.status, e.value.code) == (502, "relay")
    # No answer: the relay may hold the door, so it is closed before it is forgotten.
    assert world.doors_in("closing") == [d["door_id"] for d in world.door_rows()]
    assert world.row()["state"] == "refused"
    assert world.directory.posts == []
    await world.mgr.step()
    assert world.door_rows() == []
    world.doors.faults.fail("POST", "/v0/doors", 400, "bad_request", "malformed door_id")
    with pytest.raises(ApiError):
        await world.publish()
    assert world.door_rows() == []  # a refusal: the relay doesn't hold it


async def test_a_relay_clock_behind_ours_gets_a_shorter_door(world: World) -> None:
    world.doors.behind = 7200
    await world.publish()
    door = world.listed().door
    assert door is not None
    assert door["expires_at"] == world.now + 604_800 - 2 * 3600
    assert len(world.doors.created) == 1
    assert len(world.door_rows()) == 1


async def test_a_full_door_quota_closes_the_oldest_retiring_door(world: World) -> None:
    world.doors.max_open = 2
    await world.publish()
    await world.publish(world.body(card={**CARD, "version": "1.0.1"}))
    first, second = world.doors.created
    await world.publish(world.body(card={**CARD, "version": "1.0.2"}))
    assert world.doors.closed == [first]
    assert world.doors_in("retiring") == [second]
    assert len(world.doors.open_doors()) == 2


async def test_renewal_at_exactly_half_life(world: World) -> None:
    await world.publish()
    first = world.listed()
    renews_at = world.row()["next_renewal_at"]
    assert await world.at(renews_at - 1) == renews_at
    assert len(world.directory.posts) == 1
    await world.at(renews_at)
    second = world.listed()
    assert second.seq > first.seq
    assert second.content == first.content
    assert second.token_id == first.token_id
    assert second.issued_at == renews_at
    assert second.door is not None
    assert first.door is not None
    assert second.door["id"] != first.door["id"]
    old, new = world.doors.created
    assert world.doors_in("retiring") == [old]
    assert world.doors_in("current") == [new]
    (renewed,) = world.events("listing_renewed")
    assert renewed == {
        "directory": DIR,
        "name": NAME,
        "seq": second.seq,
        "door_expires_at": second.door["expires_at"],
    }
    # The old door stays registered and its key kept until an hour after it expires.
    assert world.doors.closed == []
    expires = first.door["expires_at"]
    await world.at(expires + 3599)
    assert world.mgr.door(old) is not None
    await world.at(expires + 3600)
    assert world.mgr.door(old) is None
    assert old not in [d["door_id"] for d in world.door_rows()]
    assert world.events("listing_stale") == []


async def test_failing_renewals_keep_at_most_three_doors_and_report_stale_once(
    world: World,
) -> None:
    await world.publish()
    world.directory.faults.fail("POST", "/v0/listings", DOWN, times=10_000)
    start = world.row()["next_renewal_at"]
    for hour in range(0, 4 * 24):
        await world.at(start + hour * 3600)
        open_doors = [i for i in world.doors.open_doors() if i in world.doors.created]
        assert len(open_doors) <= 3
    stale = world.events("listing_stale")
    assert [s["reason"] for s in stale] == ["publish_failed", "door_expired"]
    assert stale[0]["since"] >= start + 3600
    assert world.row()["state"] == "stale"
    # Recovery clears the episode.
    world.directory.faults.queued.clear()
    await world.at(world.row()["retry_at"])
    assert world.row()["state"] == "published"
    assert world.row()["stale_since"] is None
    assert world.events("listing_renewed")


@pytest.mark.parametrize("code", ["token_revoked", "name_held", "bad_token"])
async def test_a_refused_renewal_stops_renewing(world: World, code: str) -> None:
    await world.publish()
    first = world.listed()
    world.directory.faults.fail("POST", "/v0/listings", 403, code)
    await world.at(world.row()["next_renewal_at"])
    row = world.row()
    assert (row["state"], row["next_renewal_at"]) == ("stale", None)
    (stale,) = world.events("listing_stale")
    assert (stale["reason"], stale["code"]) == ("refused", code)
    assert first.door is not None
    assert stale["door_expires_at"] == first.door["expires_at"]
    _, fresh = world.doors.created
    assert world.doors.closed == [fresh]
    # No more renewals; the door runs out, the human hears of it once.
    assert first.door is not None
    expiry = first.door["expires_at"]
    await world.at(expiry)
    await world.at(expiry + 60)
    assert [s["reason"] for s in world.events("listing_stale")] == ["refused", "door_expired"]
    assert len(world.directory.posts) == 2
    await world.at(expiry + 3600)
    assert world.door_rows() == []


async def test_the_token_warning_and_expiry(world: World) -> None:
    await world.publish(world.body(lifetime=20 * DAY))
    expires = world.row()["token_expires_at"]
    await world.at(expires - 14 * DAY - 1)
    assert world.events("listing_token_expiring") == []
    await world.at(expires - 14 * DAY)
    await world.at(expires - 13 * DAY)
    assert world.events("listing_token_expiring") == [
        {"directory": DIR, "name": NAME, "token_expires_at": expires}
    ]
    await world.at(expires)
    assert world.events("listing_token_expired") == [{"directory": DIR, "name": NAME}]
    assert world.row()["state"] == "expired"
    assert world.door_rows() == []
    assert set(world.doors.closed) <= set(world.doors.created)
    assert not [i for i in world.doors.open_doors() if i in world.doors.created]
    assert await world.mgr.step() is None  # nothing left to do


async def test_no_renewal_with_less_than_two_hours_of_token(world: World) -> None:
    await world.publish(world.body(lifetime=3 * DAY))
    renews_at = world.row()["next_renewal_at"]
    assert renews_at == world.now + 3 * DAY // 2
    await world.at(world.row()["token_expires_at"] - 7199)
    assert world.row()["next_renewal_at"] is None
    assert len(world.doors.created) == 1


async def test_catch_up_after_a_long_stop(world: World) -> None:
    await world.publish()
    first = world.listed()
    await world.restart()
    world.clock.advance(9 * DAY)
    await world.mgr.step()
    second = world.listed()
    assert second.seq > first.seq
    assert second.door is not None
    assert second.door["expires_at"] > world.now
    assert world.doors_in("current") == [b64(second.door["id"])]
    assert len(world.door_rows()) == 1  # the first door's key is gone


async def test_withdraw_closes_every_door_before_withdrawing(world: World) -> None:
    await world.publish()
    await world.at(world.row()["next_renewal_at"])
    world.calls.clear()
    out = await world.rt.agent.withdraw_listing()  # the agent token may
    kinds = [(m, p.split("/")[2]) for m, p in (c.split(" ") for c in world.calls)]
    assert kinds == [("DELETE", "doors"), ("DELETE", "doors"), ("POST", "withdrawals")]
    assert out == {
        "directory": DIR,
        "name": NAME,
        "seq": world.row()["max_signed_seq"],
        "state": "withdrawn",
        "doors_closed": 2,
        "doors_close_pending": 0,
    }
    assert world.door_rows() == []
    assert all(world.mgr.door(i) is None for i in world.doors.created)
    assert NAME in world.directory.withdrawn
    (event,) = world.events("listing_withdrawn")
    assert event == {
        "directory": DIR,
        "name": NAME,
        "seq": out["seq"],
        "doors_close_pending": 0,
        "forced": False,
    }
    assert (await world.rt.agent.listing_status())["listing"]["state"] == "withdrawn"
    with pytest.raises(ApiError) as e:
        await world.mgr.withdraw()
    assert e.value.code == "not_found"


async def test_withdraw_covers_a_publish_whose_answer_was_lost(world: World) -> None:
    await world.publish()
    world.directory.faults.fail("POST", "/v0/listings", DOWN)
    out = await world.publish(world.body(card={**CARD, "version": "2.0.0"}))
    assert out["retrying"]
    await world.mgr.withdraw()
    sent = ac.verify_withdrawal(world.directory.withdrawals[-1])
    assert sent["seq"] == out["seq"] > world.row()["seq"]


async def test_a_lost_seq_is_recovered_from_the_listing(world: World) -> None:
    await world.publish()
    listed = world.listed().seq
    world.engine.store.update_listing(DIR, NAME, max_signed_seq=1)  # a restored backup
    out = await world.mgr.withdraw()
    assert out["state"] == "withdrawn"
    assert out["seq"] == listed
    assert world.row()["max_signed_seq"] == listed
    assert len(world.directory.withdrawals) == 2


async def test_a_stale_seq_that_isnt_ours_is_not_chased(world: World) -> None:
    await world.publish()
    world.engine.store.update_listing(DIR, NAME, max_signed_seq=1)
    world.directory.serve[NAME] = b"{}"
    out = await world.mgr.withdraw()
    assert out["state"] == "withdrawn"
    assert json.loads(world.row()["last_error"])["code"] == "stale_seq"


async def test_a_withdrawal_without_answer_is_resent_with_a_fresh_ts(world: World) -> None:
    await world.publish()
    world.directory.faults.fail("POST", "/v0/withdrawals", DOWN)
    world.doors.faults.fail("DELETE", "/v0/doors/", DOWN)
    out = await world.mgr.withdraw()
    assert (out["state"], out["doors_closed"], out["doors_close_pending"]) == (
        "withdrawing",
        0,
        1,
    )
    assert all(world.mgr.door(i) is None for i in world.doors.created)  # keys gone at once
    first = ac.verify_withdrawal(world.directory.withdrawals[0])["ts"]
    await world.at(world.now + 60)
    assert world.row()["state"] == "withdrawn"
    assert ac.verify_withdrawal(world.directory.withdrawals[1])["ts"] == first + 60
    assert world.door_rows() == []
    assert world.events("listing_withdrawn")


async def test_a_withdrawal_the_directory_refuses_is_done_locally(world: World) -> None:
    await world.publish()
    world.directory.faults.fail("POST", "/v0/withdrawals", 403, "wrong_identity")
    out = await world.mgr.withdraw()
    assert out["state"] == "withdrawn"
    assert json.loads(world.row()["last_error"])["code"] == "wrong_identity"


async def test_withdrawing_what_was_never_signed_sends_nothing(world: World) -> None:
    world.doors.faults.fail("POST", "/v0/doors", DOWN)
    world.engine.store.put_listing(
        {
            "directory": DIR,
            "name": NAME,
            "state": "publishing",
            "content": "{}",
            "token": "{}",
            "token_expires_at": world.now + DAY,
            "created_at": world.now,
            "updated_at": world.now,
        }
    )
    out = await world.mgr.withdraw()
    assert (out["state"], out["seq"]) == ("withdrawn", 0)
    assert world.directory.withdrawals == []


async def test_publishing_again_after_withdrawing_uses_a_higher_seq(world: World) -> None:
    await world.publish()
    first = world.listed().seq
    await world.mgr.withdraw()
    await world.publish()
    assert world.listed().seq > first


async def test_a_door_whose_key_doesnt_load_is_dropped(world: World) -> None:
    await world.publish()
    (door_id,) = world.doors.created
    world.corrupt_key(door_id)
    await world.restart()
    assert world.mgr.door(door_id) is None
    assert world.doors_in("closing") == [door_id]  # the relay may hold it
    await world.mgr.step()
    assert world.doors.closed == [door_id]


@pytest.mark.parametrize(
    "point", ["door.after_register", "listing.after_sign", "listing.after_post"]
)
async def test_a_crash_while_publishing_resumes_on_restart(world: World, point: str) -> None:
    world.engine.failpoints.arm(point, "crash")
    with pytest.raises(SimulatedCrash):
        await world.publish()
    posted = list(world.directory.posts)
    await world.restart()
    await world.mgr.step()
    row = world.row()
    assert row["state"] == "published"
    listing = world.listed()
    assert listing.door is not None
    assert world.doors_in("current") == [b64(listing.door["id"])]
    assert world.doors.created == [b64(listing.door["id"])]  # registered once
    # Signed bytes are posted again byte for byte.
    assert all(p == listing.bytes for p in world.directory.posts)
    assert len(world.directory.posts) == len(posted) + 1
    assert len(world.events("listing_published")) == 1


@pytest.mark.parametrize(
    "point", ["door.after_register", "listing.after_sign", "listing.after_post"]
)
async def test_a_transient_failure_while_renewing_is_retried(world: World, point: str) -> None:
    await world.publish()
    world.engine.failpoints.arm(point, "raise")
    with pytest.raises(FailpointError):
        await world.at(world.row()["next_renewal_at"])
    await world.mgr.step()
    assert len(world.events("listing_renewed")) == 1
    assert len(world.doors.created) == 2


async def test_a_crash_while_withdrawing_resumes_on_restart(world: World) -> None:
    await world.publish()
    world.engine.failpoints.arm("withdraw.after_close", "crash")
    with pytest.raises(SimulatedCrash):
        await world.mgr.withdraw()
    assert world.door_rows() == []
    await world.restart()
    await world.mgr.step()
    assert world.row()["state"] == "withdrawn"
    assert len(world.directory.withdrawals) == 1
    assert len(world.events("listing_withdrawn")) == 1


async def test_the_worker_renews_on_its_own(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock
) -> None:
    w = World(tmp_path, rng, fake_clock, None)
    try:
        await w.rt.start()
        await w.publish()
        w.engine.failpoints.arm("listing.after_sign", "raise")  # one failed pass first
        renews_at = w.row()["next_renewal_at"]
        fake_clock.advance(renews_at - w.now)
        await w.engine.wait_until(lambda: "listing.after_sign" in w.engine.failpoints.fired)

        # Past the worker's backoff, wherever it was when the failure was seen:
        # its timer is set against the clock as it is when it sleeps.
        fake_clock.advance(2)
        await w.engine.wait_until(lambda: bool(w.events("listing_renewed")))
        assert w.row()["state"] == "published"
    finally:
        await w.rt.stop(flush=0)


async def test_publish_needs_the_human_token_and_withdraw_doesnt(world: World) -> None:
    server = ApiServer(world.engine)
    data = world.engine.config.data_dir
    tokens = {
        scope: (data / name).read_text(encoding="ascii").strip()
        for scope, name in (("agent", API_TOKEN_FILE), ("human", HUMAN_TOKEN_FILE))
    }

    def headers(scope: str) -> dict[str, str]:
        return {"authorization": f"Bearer {tokens[scope]}"}

    body = json.dumps(world.body()).encode()
    for path in ("/v0/listing/preview", "/v0/listing/publish"):
        with pytest.raises(ApiError) as e:
            await server.handle("POST", path, headers("agent"), body)
        assert (e.value.status, e.value.code) == (403, "human_only")
    status, shown = await server.handle("POST", "/v0/listing/preview", headers("human"), body)
    assert status == 200
    published = json.dumps({**json.loads(body), "content_sha256": shown["content_sha256"]})
    _, out = await server.handle(
        "POST", "/v0/listing/publish", headers("human"), published.encode()
    )
    assert out["state"] == "published"
    _, info = await server.handle("GET", "/v0/listing", headers("agent"), b"")
    assert info["listing"]["state"] == "published"
    _, gone = await server.handle("POST", "/v0/listing/withdraw", headers("agent"), b"")
    assert gone["state"] == "withdrawn"


async def test_a_directory_dropped_from_the_config_is_reported(world: World) -> None:
    await world.publish()
    world.pinned = False
    await world.restart()
    await world.at(world.row()["next_renewal_at"])
    row = world.row()
    assert row["state"] == "stale"
    assert row["retry_at"] is not None  # retried: the table may come back
    assert world.events("listing_stale")[0]["code"] == "unknown_directory"


async def test_a_door_the_relay_couldnt_close_is_closed_after_a_restart(world: World) -> None:
    await world.publish()
    world.doors.faults.fail("DELETE", "/v0/doors/", DOWN)
    world.directory.faults.fail("POST", "/v0/withdrawals", DOWN)
    assert (await world.mgr.withdraw())["doors_close_pending"] == 1
    # A second request while it is pending goes on from where it was.
    world.directory.faults.fail("POST", "/v0/withdrawals", DOWN)
    world.doors.faults.fail("DELETE", "/v0/doors/", DOWN)
    assert (await world.mgr.withdraw())["state"] == "withdrawing"
    await world.restart()
    assert world.doors_in("closing") == world.doors.created
    assert world.mgr.door(world.doors.created[0]) is None
    await world.mgr.step()
    assert world.doors_in("closing") == []
    assert world.doors.closed == world.doors.created
    await world.at(world.row()["retry_at"])
    assert world.row()["state"] == "withdrawn"


async def test_a_republish_drops_a_renewal_still_waiting(world: World) -> None:
    await world.publish()
    world.directory.faults.fail("POST", "/v0/listings", DOWN)
    await world.at(world.row()["next_renewal_at"])
    waiting = world.row()["pending_door"]
    assert waiting in world.doors_in("registered")
    await world.publish(world.body(card={**CARD, "version": "1.1.0"}))
    assert waiting in world.doors.closed
    assert world.listed().door is not None


async def test_a_signed_listing_whose_door_key_is_lost_is_signed_again(world: World) -> None:
    world.engine.failpoints.arm("listing.after_sign", "crash")
    with pytest.raises(SimulatedCrash):
        await world.publish()
    lost = world.row()["pending_door"]
    world.corrupt_key(lost)
    await world.restart()
    await world.mgr.step()
    listing = world.listed()
    assert listing.door is not None
    assert b64(listing.door["id"]) != lost
    assert world.row()["state"] == "published"


async def test_a_long_relay_outage_replaces_the_waiting_door(world: World) -> None:
    await world.publish()
    first = world.listed()
    world.doors.faults.fail("POST", "/v0/doors", DOWN, times=10_000)
    start = world.row()["next_renewal_at"]
    for hour in range(0, 5 * 24, 6):
        await world.at(start + hour * 3600)
    waiting = [d for d in world.door_rows() if d["state"] == "registering"]
    assert len(waiting) == 1
    assert world.now - waiting[0]["created_at"] <= 4 * DAY
    world.doors.faults.queued.clear()
    await world.at(world.row()["retry_at"])
    assert world.listed().seq > first.seq
    assert world.row()["state"] == "published"


async def test_status_without_a_listing(world: World) -> None:
    assert await world.rt.agent.listing_status() == {"listing": None}
    assert await world.mgr.step() is None


async def test_an_expired_token_closes_the_open_door(world: World) -> None:
    await world.publish(world.body(lifetime=3 * DAY))
    (door_id,) = world.doors.created
    await world.at(world.row()["token_expires_at"])
    assert world.doors.closed == [door_id]
    assert world.row()["state"] == "expired"


# -- review regressions ------------------------------------------------------------


@pytest.mark.parametrize("by", ["agent", "human"])
async def test_a_republish_that_fails_leaves_a_withdrawn_listing_withdrawn(
    world: World, by: str
) -> None:
    await world.publish()
    if by == "agent":
        await world.rt.agent.withdraw_listing()
    else:
        await world.mgr.withdraw()
    posts = len(world.directory.posts)
    world.doors.faults.fail("POST", "/v0/doors", DOWN)
    with pytest.raises(ApiError):
        await world.publish(world.body(card={**CARD, "version": "2.0.0"}))
    assert (world.row()["state"], world.row()["next_renewal_at"]) == ("withdrawn", None)
    world.directory.faults.fail("POST", "/v0/listings", 413, "too_large")
    with pytest.raises(ApiError):
        await world.publish(world.body(card={**CARD, "version": "2.0.0"}))
    assert world.row()["state"] == "withdrawn"
    for days in (1, 4, 8):
        await world.at(world.now + days * DAY)
    assert NAME in world.directory.withdrawn
    assert world.directory.listing(NAME) is None
    assert len(world.directory.posts) == posts + 1  # only the refused republish
    assert world.door_rows() == []
    assert not [i for i in world.doors.open_doors() if i in world.doors.created]


async def test_a_refused_republish_keeps_a_stale_or_expired_listing_as_it_was(
    world: World,
) -> None:
    await world.publish(world.body(lifetime=20 * DAY))
    world.directory.faults.fail("POST", "/v0/listings", 403, "token_revoked")
    await world.at(world.row()["next_renewal_at"])
    assert (world.row()["state"], world.row()["next_renewal_at"]) == ("stale", None)
    world.directory.faults.fail("POST", "/v0/listings", 409, "name_held")
    with pytest.raises(ApiError):
        await world.publish(world.body(card={**CARD, "version": "3.0.0"}))
    assert (world.row()["state"], world.row()["next_renewal_at"]) == ("stale", None)
    await world.at(world.row()["token_expires_at"])
    assert world.row()["state"] == "expired"
    world.directory.faults.fail("POST", "/v0/listings", 409, "name_held")
    with pytest.raises(ApiError):
        await world.publish(world.body(card={**CARD, "version": "3.0.0"}))
    assert world.row()["state"] == "expired"


def _odd_answer(world: World, *, store: bool) -> None:
    """The directory answers 201 with a body that isn't JSON (a proxy that
    rewrites bodies), having stored the listing or not."""
    publish = world.directory._publish

    def odd(body: bytes) -> httpx.Response:
        if store:
            publish(body)
        return httpx.Response(201, content=b"created")

    world.directory._publish = odd  # ty: ignore[invalid-assignment]


async def test_an_unreadable_accept_is_checked_against_the_listing(world: World) -> None:
    _odd_answer(world, store=True)
    out = await world.publish()
    assert out["state"] == "published"
    assert world.doors.closed == []
    assert world.listed().door is not None
    assert world.row()["owner_state"] is None


async def test_an_unreadable_accept_that_didnt_land_is_retried(world: World) -> None:
    _odd_answer(world, store=False)
    out = await world.publish()
    assert (out["state"], out["retrying"]) == ("publishing", True)
    assert world.doors.closed == []
    assert world.doors_in("registered") == world.doors.created


async def test_a_refused_listing_that_was_signed_can_be_withdrawn(world: World) -> None:
    world.directory.faults.fail("POST", "/v0/listings", 400, "bad_listing")
    with pytest.raises(ApiError):
        await world.publish()
    assert world.row()["state"] == "refused"
    out = await world.rt.agent.withdraw_listing()
    assert out["state"] == "withdrawn"
    assert len(world.directory.withdrawals) == 1


async def test_auth_failed_on_a_close_keeps_the_door_until_it_is_closed(world: World) -> None:
    await world.publish()
    (door_id,) = world.doors.created
    world.doors.faults.fail("DELETE", "/v0/doors/", 401, "auth_failed", "timestamp outside")
    out = await world.mgr.withdraw()
    assert (out["doors_closed"], out["doors_close_pending"]) == (0, 1)
    assert world.doors_in("closing") == [door_id]
    assert world.mgr.door(door_id) is None  # the key goes at once anyway
    await world.mgr.step()
    assert world.doors.closed == [door_id]
    assert world.door_rows() == []


async def test_a_lost_registration_answer_never_forgets_the_door(world: World) -> None:
    create = world.doors._create

    def create_then_drop(body: dict[str, Any]) -> httpx.Response:
        create(body)
        msg = "answer lost"
        raise httpx.ReadTimeout(msg)

    world.doors._create = create_then_drop  # ty: ignore[invalid-assignment]
    for _ in range(4):
        with pytest.raises(ApiError) as e:
            await world.publish()
        assert e.value.code == "relay"
    world.doors._create = create  # ty: ignore[invalid-assignment]
    assert sorted(world.doors_in("closing")) == sorted(world.doors.created)
    assert all(world.mgr.door(i) is None for i in world.doors.created)
    await world.mgr.step()
    assert world.doors.open_doors() == []
    assert (await world.publish())["state"] == "published"


EVIL = "\x1b]0;pwned\x07\x1b[2J" + "A" * 2000


async def test_directory_codes_and_owner_states_are_never_passed_through(world: World) -> None:
    published = world.directory._published

    def odd_state(listing: ac.Listing, status: int) -> httpx.Response:
        published(listing, status)
        return httpx.Response(status, json={"seq": listing.seq, "owner_state": EVIL})

    world.directory._published = odd_state  # ty: ignore[invalid-assignment]
    out = await world.publish()
    assert out["owner_state"] == "unknown"
    world.directory.faults.fail("POST", "/v0/listings", 400, EVIL, EVIL)
    with pytest.raises(ApiError) as e:
        await world.publish(world.body(card={**CARD, "version": "9"}))
    assert e.value.code == "directory"
    assert "\x1b" not in str(e.value)
    assert len(str(e.value)) < 400
    world.directory.faults.fail("POST", "/v0/listings", 400, EVIL, EVIL)
    await world.at(world.row()["next_renewal_at"])
    (stale,) = [
        e["data"] for e in (await world.rt.agent.events())["events"] if e["type"] == "listing_stale"
    ]
    assert stale["code"] == "directory"
    status = (await world.rt.agent.listing_status())["listing"]
    assert status["last_error"]["code"] == "directory"
    assert status["owner_state"] == "unknown"


@pytest.mark.parametrize("code", ["stale_ts", "bad_door", "wrong_relay", "something_new"])
async def test_a_renewal_refused_for_another_reason_is_retried(world: World, code: str) -> None:
    await world.publish()
    first = world.listed().seq
    world.directory.faults.fail("POST", "/v0/listings", 400, code)
    await world.at(world.row()["next_renewal_at"])
    row = world.row()
    assert row["next_renewal_at"] is not None
    assert row["retry_at"] is not None
    (stale,) = world.events("listing_stale")
    assert (stale["reason"], stale["code"]) == (
        "publish_failed",
        code if code != "something_new" else "directory",
    )
    await world.at(row["retry_at"])
    assert world.row()["state"] == "published"
    assert world.listed().seq > first


async def test_a_withdraw_for_a_directory_no_longer_configured_says_so(world: World) -> None:
    await world.publish()
    world.pinned = False
    await world.restart()
    with pytest.raises(ApiError) as e:
        await world.mgr.withdraw()
    assert e.value.code == "unknown_directory"
    assert world.row()["state"] == "withdrawing"
    assert NAME not in world.directory.withdrawn
    assert world.events("listing_withdrawn") == []


async def test_signed_relay_requests_never_repeat_across_restarts(world: World) -> None:
    world.engine.failpoints.arm("door.after_register", "crash")
    with pytest.raises(SimulatedCrash):
        await world.publish()
    await world.restart()
    await world.mgr.step()  # no time passes, and the relay still takes it
    assert world.row()["state"] == "published"
    stamps = world.doors.stamps
    assert len(stamps) == len(set(stamps)) >= 2
    assert stamps == sorted(stamps)


async def test_a_republish_that_keeps_failing_warns_before_the_old_door_expires(
    world: World,
) -> None:
    await world.publish()
    old = world.listed().door
    assert old is not None
    world.directory.faults.fail("POST", "/v0/listings", DOWN, times=10_000)
    assert (await world.publish(world.body(card={**CARD, "version": "4.0.0"})))["retrying"]
    await world.at(old["expires_at"] - DAY - 1)
    assert world.events("listing_stale") == []
    assert not (await world.rt.agent.listing_status())["listing"]["door"]["expiring"]
    await world.at(old["expires_at"] - DAY + 60)
    (warning,) = world.events("listing_stale")
    assert (warning["reason"], warning["door_expires_at"]) == ("door_expiring", old["expires_at"])
    status = (await world.rt.agent.listing_status())["listing"]
    assert status["door"]["expiring"]
    assert status["retrying"] == {"since": status["retrying"]["since"], "code": "unreachable"}
    await world.at(old["expires_at"] + 60)
    assert [s["reason"] for s in world.events("listing_stale")] == ["door_expiring", "door_expired"]


async def test_a_withdrawal_that_is_never_taken_stops_blocking_and_can_be_forced(
    world: World,
) -> None:
    await world.publish()
    world.directory.faults.fail("POST", "/v0/withdrawals", DOWN, times=10_000)
    assert (await world.mgr.withdraw())["state"] == "withdrawing"
    with pytest.raises(ApiError) as e:
        await world.mgr.preview(world.body("other-name"))
    assert e.value.code == "listing_exists"
    await world.at(world.now + 2 * 3600)
    assert [e["code"] for e in world.events("listing_withdraw_pending")] == ["unreachable"]
    for _ in range(9):
        await world.at(world.now + DAY)
    assert world.row()["state"] == "withdraw_failed"
    assert world.events("listing_withdraw_failed")
    await world.mgr.preview(world.body("other-name"))  # no longer blocks
    with pytest.raises(ApiError) as e:
        await world.mgr.withdraw(force=True, human=False)
    assert e.value.code == "human_only"
    out = await world.mgr.withdraw(force=True, human=True)
    assert out["state"] == "withdrawn"
    assert json.loads(world.row()["last_error"])["code"] == "forced"
    (event,) = world.events("listing_withdrawn")
    assert event["forced"] is True


async def test_overdue_work_runs_at_once(world: World) -> None:
    await world.publish()
    world.engine.store.update_listing(DIR, NAME, retry_at=world.now - 5)
    assert (world.mgr._next_due() or 0) <= world.now


async def test_door_queries_dont_read_private_keys(world: World) -> None:
    await world.publish()
    assert all("secret" not in d for d in world.engine.store.doors())
    (door_id,) = world.doors.created
    assert dict(world.engine.store.door_secrets())[door_id] is not None


async def test_the_preview_hash_covers_the_token_and_the_directory(world: World) -> None:
    shown = await world.mgr.preview(world.body())
    for other in (world.body("another-name"), world.body(lifetime=5 * DAY)):
        with pytest.raises(ApiError) as e:
            await world.mgr.publish({**other, "content_sha256": shown["content_sha256"]})
        assert e.value.code == "card_changed"
    assert world.calls == []
