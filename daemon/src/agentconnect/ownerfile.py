"""Outbound fetches to hosts that untrusted text names (SPEC 13.2.4, docs/discovery.md).

An owner domain comes from listing text, so fetching its
``/.well-known/agentconnect.json`` must not become a way to reach this
machine's own network. :class:`OwnerFileFetcher` follows the rules the
directory follows (``directory/src/owner.rs``):

* the URL is ``agentconnect_core.owner_file_url(domain)``: HTTPS on port 443;
* the absolute name (``domain.``, so no resolver search domain applies) is
  resolved once, and only addresses ``agentconnect_core.is_public_address``
  accepts are kept: loopback, private, link-local, ULA and the other
  special-use ranges are never dialled;
* the connection goes to that vetted address and nowhere else (no second
  lookup, so no DNS rebinding), with TLS SNI and certificate checks on the
  host name against the system roots;
* no proxies, no redirects (any 3xx fails), status 200 and
  ``Content-Type: application/json`` only, no content encoding;
* the body is counted while it streams and capped at
  ``MAX_OWNER_FILE_BYTES``, and the whole exchange gets 5 seconds.

:func:`public_addresses` and :func:`pinned_transport` are the same guard for
the directory client's HTTPS requests.

Nothing here logs the domain or an address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Protocol, cast, override

import httpcore
import httpx

import agentconnect_core as ac

FETCH_TIMEOUT_SECS = 5.0
HTTPS_PORT = 443
HTTP_OK = 200
MULTIPLE_CHOICES = 300
BAD_REQUEST = 400
JSON_TYPE = "application/json"

#: ``(host, port)`` to the addresses it resolves to, as strings.
Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _public(address: str) -> bool:
    try:
        return ac.is_public_address(address)
    except ac.AgentConnectError:  # e.g. an IPv6 address with a zone
        return False


async def public_addresses(host: str, port: int, resolver: Resolver) -> list[str]:
    """The public addresses ``host`` resolves to, resolving it once as an
    absolute name. An IP literal is checked as is."""
    if _is_ip(host):
        candidates: Iterable[str] = [host]
    else:
        candidates = await resolver(host.rstrip(".") + ".", port)
    return list(dict.fromkeys(a for a in candidates if _public(a)))


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Dials one vetted address whatever host the request names; TLS still
    checks the certificate against the request's host name."""

    def __init__(self, address: str, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self.address = address
        self._inner = inner or cast("httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend())

    # The signatures are httpcore's, `timeout` included.
    @override
    async def connect_tcp(
        self,
        host: str,  # the vetted address is dialled instead
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_tcp(
            self.address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        msg = "only the vetted address is dialled"
        raise httpcore.ConnectError(msg)

    @override
    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def pinned_transport(
    address: str, inner: httpcore.AsyncNetworkBackend | None = None
) -> httpx.AsyncBaseTransport:
    """An HTTPS transport that only ever connects to ``address``: system
    roots and host name checks, HTTP/1.1, no proxy."""
    context = ssl.create_default_context()
    transport = httpx.AsyncHTTPTransport(verify=context, trust_env=False)
    # httpx takes no network backend, so its pool is replaced by one that
    # dials the vetted address (tests check the wiring).
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=context,
        network_backend=PinnedBackend(address, inner),
        max_connections=1,
        http1=True,
        http2=False,
    )
    return transport


def head_problem(resp: httpx.Response, cap: int) -> str | None:
    """Why a response's status and headers are refused, or None."""
    if MULTIPLE_CHOICES <= resp.status_code < BAD_REQUEST:
        return "redirect"
    if resp.status_code != HTTP_OK:
        return "status"
    media = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != JSON_TYPE:
        return "content_type"
    if resp.headers.get("content-encoding", "identity").strip().lower() != "identity":
        return "encoding"
    length = resp.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > cap):
        return "too_large"
    return None


async def read_capped(resp: httpx.Response, cap: int) -> bytes | None:
    """The raw body, or None once it passes ``cap`` bytes (it stops reading)."""
    if resp.is_stream_consumed:  # a transport that read the body already
        return resp.content if len(resp.content) <= cap else None
    body = bytearray()
    async for chunk in resp.aiter_raw():
        body += chunk
        if len(body) > cap:
            return None
    return bytes(body)


#: What every outbound request sends: no compressed bodies to inflate.
REQUEST_HEADERS = {"accept": JSON_TYPE, "accept-encoding": "identity"}


@dataclass(frozen=True)
class OwnerFetch:
    """The file's bytes, or why there are none (``blocked``, ``unreachable``,
    ``timeout``, ``redirect``, ``status``, ``content_type``, ``encoding``,
    ``too_large``, ``bad_domain``). Any failure counts as a failed fetch
    (SPEC 13.2.4)."""

    data: bytes | None
    failure: str | None = None


class Fetcher(Protocol):
    async def fetch(self, domain: str) -> OwnerFetch: ...


class OwnerFileFetcher:
    """Fetches ``https://<domain>/.well-known/agentconnect.json`` under the
    rules above. ``resolver`` and ``transport_for`` are test seams."""

    def __init__(
        self,
        resolver: Resolver = system_resolver,
        transport_for: Callable[[str], httpx.AsyncBaseTransport] = pinned_transport,
        timeout: float = FETCH_TIMEOUT_SECS,
    ) -> None:
        self._resolver = resolver
        self._transport_for = transport_for
        self._timeout = timeout

    async def fetch(self, domain: str) -> OwnerFetch:
        try:
            url = ac.owner_file_url(domain)
        except ac.AgentConnectError:
            return OwnerFetch(None, "bad_domain")
        try:
            async with asyncio.timeout(self._timeout):
                return await self._fetch(domain, url)
        except TimeoutError:
            return OwnerFetch(None, "timeout")
        except (httpx.HTTPError, OSError):
            return OwnerFetch(None, "unreachable")

    async def _fetch(self, domain: str, url: str) -> OwnerFetch:
        addresses = await public_addresses(domain, HTTPS_PORT, self._resolver)
        if not addresses:
            return OwnerFetch(None, "blocked")
        cap = ac.MAX_OWNER_FILE_BYTES
        async with (
            httpx.AsyncClient(
                transport=self._transport_for(addresses[0]),
                follow_redirects=False,
                trust_env=False,
                timeout=self._timeout,
            ) as http,
            http.stream("GET", url, headers=REQUEST_HEADERS) as resp,
        ):
            problem = head_problem(resp, cap)
            if problem is not None:
                return OwnerFetch(None, problem)
            data = await read_capped(resp, cap)
        if data is None:
            return OwnerFetch(None, "too_large")
        return OwnerFetch(data)
