"""The guard on fetches whose host comes from listing text (SPEC 13.2.4)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterable
from typing import Any, override

import httpcore
import httpx
import pytest

import agentconnect_core as ac
from agentconnect.ownerfile import (
    OwnerFetch,
    OwnerFileFetcher,
    PinnedBackend,
    pinned_transport,
    public_addresses,
)

FILE = json.dumps({"v": 0, "identities": []}).encode()


class Resolver:
    def __init__(self, *addresses: str) -> None:
        self.addresses = list(addresses)
        self.asked: list[tuple[str, int]] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.asked.append((host, port))
        return self.addresses


class Chunks(httpx.AsyncByteStream):
    """A body that arrives in pieces (or never, with ``stall``)."""

    def __init__(self, chunks: Iterable[bytes], stall: bool = False) -> None:
        self.chunks, self.stall = list(chunks), stall

    @override
    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk
        if self.stall:
            await asyncio.Event().wait()


def serving(*responses: httpx.Response) -> tuple[list[str], Any]:
    """A ``transport_for`` that records the address it was given."""
    dialled: list[str] = []
    answers = list(responses)

    def transport_for(address: str) -> httpx.AsyncBaseTransport:
        dialled.append(address)
        return httpx.MockTransport(lambda _request: answers.pop(0))

    return dialled, transport_for


JSON = {"content-type": "application/json; charset=utf-8"}


async def fetch(resolver: Resolver, *responses: httpx.Response, **kw: Any) -> OwnerFetch:
    _, transport_for = serving(*responses)
    fetcher = OwnerFileFetcher(resolver=resolver, transport_for=transport_for, **kw)
    return await fetcher.fetch("example.com")


async def test_a_file_is_fetched_from_the_vetted_address_only() -> None:
    resolver = Resolver("192.0.2.1", "93.184.215.14", "93.184.215.14")
    dialled, transport_for = serving(httpx.Response(200, content=FILE, headers=JSON))
    got = await OwnerFileFetcher(resolver=resolver, transport_for=transport_for).fetch(
        "example.com"
    )
    assert got == OwnerFetch(FILE)
    # Resolved once, as an absolute name; the documentation range is skipped.
    assert resolver.asked == [("example.com.", 443)]
    assert dialled == ["93.184.215.14"]


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fe80::1%eth0",
        "fd00::1",
        "::ffff:127.0.0.1",
        "198.51.100.7",
        "0.0.0.0",  # noqa: S104
    ],
)
async def test_special_use_addresses_are_never_dialled(address: str) -> None:
    dialled, transport_for = serving()
    got = await OwnerFileFetcher(resolver=Resolver(address), transport_for=transport_for).fetch(
        "example.com"
    )
    assert got == OwnerFetch(None, "blocked")
    assert dialled == []


async def test_public_addresses_checks_an_ip_literal_without_resolving() -> None:
    resolver = Resolver()
    assert await public_addresses("10.0.0.1", 443, resolver) == []
    assert await public_addresses("93.184.215.14", 443, resolver) == ["93.184.215.14"]
    assert resolver.asked == []


@pytest.mark.parametrize(
    ("response", "failure"),
    [
        (httpx.Response(301, headers={"location": "https://127.0.0.1/"}), "redirect"),
        (httpx.Response(404, content=FILE, headers=JSON), "status"),
        (httpx.Response(200, content=FILE, headers={"content-type": "text/html"}), "content_type"),
        (
            httpx.Response(
                200, headers={**JSON, "content-encoding": "gzip"}, stream=Chunks([FILE])
            ),
            "encoding",
        ),
        (
            httpx.Response(
                200, headers={**JSON, "content-length": str(1 << 20)}, stream=Chunks([])
            ),
            "too_large",
        ),
        (
            httpx.Response(
                200, headers=JSON, stream=Chunks([b"x" * 40_000, b"x" * 40_000, b"never read"])
            ),
            "too_large",
        ),
        (
            httpx.Response(200, content=b"x" * (ac.MAX_OWNER_FILE_BYTES + 1), headers=JSON),
            "too_large",
        ),
    ],
)
async def test_answers_that_count_as_a_failed_fetch(response: httpx.Response, failure: str) -> None:
    assert await fetch(Resolver("93.184.215.14"), response) == OwnerFetch(None, failure)


async def test_a_streamed_file_within_the_cap_is_read_whole() -> None:
    response = httpx.Response(200, headers=JSON, stream=Chunks([FILE[:5], FILE[5:]]))
    assert await fetch(Resolver("93.184.215.14"), response) == OwnerFetch(FILE)


async def test_a_slow_body_runs_out_of_time() -> None:
    response = httpx.Response(200, headers=JSON, stream=Chunks([b"{"], stall=True))
    got = await fetch(Resolver("93.184.215.14"), response, timeout=0.001)
    assert got == OwnerFetch(None, "timeout")


async def test_resolution_failures_and_bad_domains() -> None:
    class Failing:
        async def __call__(self, host: str, port: int) -> list[str]:
            raise OSError(host)

    fetcher = OwnerFileFetcher(resolver=Failing())
    assert await fetcher.fetch("example.com") == OwnerFetch(None, "unreachable")
    assert await fetcher.fetch("127.0.0.1") == OwnerFetch(None, "bad_domain")
    assert await fetcher.fetch("Example.COM.") == OwnerFetch(None, "bad_domain")


class Recording(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self.dialled: list[tuple[str, int]] = []
        self.slept: list[float] = []

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.dialled.append((host, port))
        msg = "no network in tests"
        raise httpcore.ConnectError(msg)

    @override
    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)


async def test_the_pinned_transport_dials_the_vetted_address_whatever_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")  # never used
    inner = Recording()
    fetcher = OwnerFileFetcher(
        resolver=Resolver("93.184.215.14"),
        transport_for=lambda address: pinned_transport(address, inner),
    )
    assert await fetcher.fetch("example.com") == OwnerFetch(None, "unreachable")
    assert inner.dialled == [("93.184.215.14", 443)]
    backend = PinnedBackend("93.184.215.14", inner)
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_unix_socket("/run/x.sock")
    await backend.sleep(0.5)
    assert inner.slept == [0.5]
    assert PinnedBackend("93.184.215.14").address == "93.184.215.14"
