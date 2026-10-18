"""Requests to a pinned directory: answers mapped, capped, never redirected."""

from __future__ import annotations

import random
from collections.abc import Callable

import httpx
import pytest

import agentconnect_core as ac
from agentconnect.config import DirectoryConfig
from agentconnect.directory_client import DirectoryClient, DirectoryError, owner_state

JSON = {"content-type": "application/json"}


def client(
    handler: Callable[[httpx.Request], httpx.Response], rng: random.Random
) -> DirectoryClient:
    key = ac.DirectoryKey._generate_for_testing(rng.getrandbits(63)).public_key
    entry = DirectoryConfig("directory.example.org", (key,), "https://directory.example.org")
    return DirectoryClient(entry, transport=httpx.MockTransport(handler))


def answer(status: int, **kw: object) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(status, **kw)  # ty: ignore[invalid-argument-type]


async def test_a_listing_is_fetched_as_its_exact_bytes(rng: random.Random) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'{"x":1}', headers=JSON)

    assert await client(handler, rng).fetch_listing("release-planner") == b'{"x":1}'
    (request,) = seen
    assert str(request.url) == "https://directory.example.org/a/release-planner.json"
    assert request.headers["accept-encoding"] == "identity"


@pytest.mark.parametrize(
    ("status", "kw", "code", "transient"),
    [
        (404, {"json": {"code": "not_found"}}, "not_found", False),
        (410, {"json": {"code": "withdrawn"}}, "listing_withdrawn", False),
        (500, {"content": b"<html>"}, "unreadable", True),
        (200, {"content": b"{}", "headers": {"content-type": "text/html"}}, "unreadable", True),
        (302, {"headers": {"location": "https://127.0.0.1/a/x.json"}}, "redirect", True),
        (
            200,
            {"content": b"x" * (ac.MAX_LISTING_BYTES + 1), "headers": JSON},
            "unreadable",
            True,
        ),
    ],
)
async def test_fetch_failures(
    rng: random.Random, status: int, kw: dict[str, object], code: str, transient: bool
) -> None:
    with pytest.raises(DirectoryError) as e:
        await client(answer(status, **kw), rng).fetch_listing("release-planner")
    assert e.value.code == code
    assert e.value.transient is transient


async def test_a_name_that_isnt_one_is_never_requested(rng: random.Random) -> None:
    with pytest.raises(DirectoryError) as e:
        await client(answer(200), rng).fetch_listing("../admin")
    assert e.value.code == "bad_request"


async def test_writes_return_the_answer_of_the_directory(rng: random.Random) -> None:
    c = client(answer(201, json={"name": "n", "seq": 3}), rng)
    assert await c.publish(b"{}") == {"name": "n", "seq": 3}
    assert await client(answer(200, json={"withdrawn": "n"}), rng).withdraw(b"{}") == {
        "withdrawn": "n"
    }
    with pytest.raises(DirectoryError) as e:
        await client(answer(200, json=[1]), rng).publish(b"{}")
    # Taken, perhaps: the answer can't be read, which is never a refusal.
    assert (e.value.code, e.value.maybe_accepted, e.value.transient) == ("unreadable", True, True)


@pytest.mark.parametrize(
    ("status", "body", "code", "transient"),
    [
        (
            409,
            {"code": "name_held", "detail": "older token", "kind": "superseded"},
            "name_held",
            False,
        ),
        (409, {"code": "conflict", "detail": "retry"}, "conflict", True),
        (429, {"code": "rate_limited"}, "rate_limited", True),
        (403, {"code": "token_revoked", "detail": 7}, "token_revoked", False),
        (400, {"detail": "no code"}, "unreadable", True),
        (503, {"code": "unavailable"}, "unavailable", True),
    ],
)
async def test_refusals_carry_the_code_of_the_directory(
    rng: random.Random, status: int, body: dict[str, object], code: str, transient: bool
) -> None:
    with pytest.raises(DirectoryError) as e:
        await client(answer(status, json=body), rng).publish(b"{}")
    assert (e.value.code, e.value.status, e.value.transient) == (code, status, transient)
    if code == "name_held":
        assert (e.value.detail, e.value.kind) == ("older token", "superseded")


async def test_no_answer_is_unreachable(rng: random.Random) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(DirectoryError) as e:
        await client(down, rng).publish(b"{}")
    assert (e.value.code, e.value.status, e.value.transient) == ("unreachable", 0, True)


async def test_an_https_directory_is_dialled_at_a_public_address_only(rng: random.Random) -> None:
    key = ac.DirectoryKey._generate_for_testing(rng.getrandbits(63)).public_key
    entry = DirectoryConfig("directory.example.org", (key,), "https://directory.example.org")
    dialled: list[str] = []

    def transport_for(address: str) -> httpx.AsyncBaseTransport:
        dialled.append(address)
        return httpx.MockTransport(answer(201, json={"seq": 1}))

    async def private(_host: str, _port: int) -> list[str]:
        return ["10.0.0.7"]

    async def public(host: str, port: int) -> list[str]:
        assert (host, port) == ("directory.example.org.", 443)
        return ["93.184.215.14"]

    with pytest.raises(DirectoryError) as e:
        await DirectoryClient(entry, resolver=private, transport_for=transport_for).publish(b"{}")
    assert e.value.code == "blocked"
    assert dialled == []
    got = await DirectoryClient(entry, resolver=public, transport_for=transport_for).publish(b"{}")
    assert got == {"seq": 1}
    assert dialled == ["93.184.215.14"]


@pytest.mark.parametrize(
    ("code", "seen"),
    [
        ("something_new", "directory"),
        ("\x1b]0;x\x07", "directory"),
        ("name_held" * 5, "directory"),
        ("owner_revoked", "owner_revoked"),
    ],
)
async def test_only_known_codes_come_through(rng: random.Random, code: str, seen: str) -> None:
    body = {"code": code, "detail": "\x1b[2J" + "x" * 1000, "kind": "Bad Kind!"}
    with pytest.raises(DirectoryError) as e:
        await client(answer(400, json=body), rng).publish(b"{}")
    assert e.value.code == seen
    assert e.value.detail.startswith("?[2J")
    assert len(e.value.detail) == 200
    assert e.value.kind is None
    assert not e.value.maybe_accepted


def test_owner_states_are_the_specs_or_unknown() -> None:
    assert owner_state({"owner_state": "verified"}) == "verified"
    assert owner_state({"owner_state": "\x1b]0;x"}) == "unknown"
    assert owner_state({"owner_state": 3}) == "unknown"
    assert owner_state({}) is None
