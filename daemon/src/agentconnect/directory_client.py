"""Requests to a pinned directory (SPEC 13.2, docs/discovery.md).

A :class:`DirectoryClient` talks only to the ``url`` of one configured
``[[directory]]``, never to a URL a listing names. It follows no redirects,
sends no compressed bodies home, caps every answer while it streams, and
for an ``https`` directory dials only a public address its host resolved
to, once (the guard of :mod:`agentconnect.ownerfile`). A loopback
``http://`` directory (tests) is dialled directly.

Every answer is data from a party this daemon doesn't trust: the caller
verifies listings through the core and treats the directory's own fields
(such as ``owner_state``) as information only.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

import agentconnect_core as ac
from agentconnect.config import DirectoryConfig
from agentconnect.ownerfile import (
    REQUEST_HEADERS,
    Resolver,
    head_problem,
    pinned_transport,
    public_addresses,
    read_capped,
    system_resolver,
)

REQUEST_TIMEOUT_SECS = 10.0
MAX_ANSWER_BYTES = 64 << 10  # publish and withdraw answers, and error bodies
TOO_MANY_REQUESTS = 429
SERVER_ERROR = 500
NOT_FOUND = 404
GONE = 410
# Directory answers that say "not now" rather than "no" (directory/README.md).
TRANSIENT_CODES = frozenset({"conflict", "rate_limited", "unreachable", "timeout", "blocked"})


class DirectoryError(Exception):
    """A refused or failed directory request: the directory's ``code`` (or
    ours: ``unreachable``, ``timeout``, ``blocked``, ``redirect``,
    ``too_large``, ``bad_response``), its HTTP ``status`` (0 when there was
    no answer), and its ``detail`` and ``kind`` when it gave them."""

    def __init__(self, code: str, status: int = 0, detail: str = "", kind: str | None = None):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.status, self.detail, self.kind = code, status, detail, kind

    @property
    def transient(self) -> bool:
        """Whether the same request may succeed later (5xx, 429, a conflict,
        or no answer at all)."""
        return (
            self.status == 0
            or self.status >= SERVER_ERROR
            or self.status == TOO_MANY_REQUESTS
            or self.code in TRANSIENT_CODES
        )


class DirectoryClient:
    """One pinned directory. ``transport`` (tests) replaces the network,
    resolution included; ``resolver`` and ``transport_for`` replace the
    lookup and the pinned dial."""

    def __init__(
        self,
        entry: DirectoryConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver = system_resolver,
        transport_for: Callable[[str], httpx.AsyncBaseTransport] = pinned_transport,
    ) -> None:
        self.entry = entry
        self._transport = transport
        self._resolver = resolver
        self._transport_for = transport_for

    async def publish(self, listing: bytes) -> dict[str, Any]:
        """``POST /v0/listings``. Re-posting the same bytes is idempotent."""
        return await self._write("/v0/listings", listing)

    async def withdraw(self, withdrawal: bytes) -> dict[str, Any]:
        """``POST /v0/withdrawals``."""
        return await self._write("/v0/withdrawals", withdrawal)

    async def fetch_listing(self, name: str) -> bytes:
        """The exact signed bytes at ``/a/<name>.json``: ``not_found`` (404),
        ``listing_withdrawn`` (410), else what the directory said."""
        if not ac.is_listing_name(name):
            raise DirectoryError("bad_request", 0, "not a listing name")
        status, headers, body = await self._send("GET", f"/a/{name}.json", None)
        if status == NOT_FOUND:
            raise DirectoryError("not_found", status)
        if status == GONE:
            raise DirectoryError("listing_withdrawn", status)
        if status != httpx.codes.OK:
            raise _refusal(status, body)
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise DirectoryError("bad_response", status, "not application/json")
        return body

    async def _write(self, path: str, body: bytes) -> dict[str, Any]:
        status, _headers, answer = await self._send("POST", path, body)
        if status not in (httpx.codes.OK, httpx.codes.CREATED):
            raise _refusal(status, answer)
        data = _json_object(answer)
        if data is None:
            raise DirectoryError("bad_response", status, "not a JSON object")
        return data

    async def _send(
        self, method: str, path: str, body: bytes | None
    ) -> tuple[int, httpx.Headers, bytes]:
        cap = ac.MAX_LISTING_BYTES if method == "GET" else MAX_ANSWER_BYTES
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECS):
                transport = await self._transport_for_request()
                headers = dict(REQUEST_HEADERS)
                if body is not None:
                    headers["content-type"] = "application/json"
                async with (
                    httpx.AsyncClient(
                        transport=transport,
                        follow_redirects=False,
                        trust_env=False,
                        timeout=REQUEST_TIMEOUT_SECS,
                    ) as http,
                    http.stream(
                        method, self.entry.url + path, content=body, headers=headers
                    ) as resp,
                ):
                    problem = head_problem(resp, cap)
                    if problem in ("redirect", "encoding", "too_large"):
                        raise DirectoryError(problem, resp.status_code)
                    data = await read_capped(resp, cap)
                    if data is None:
                        raise DirectoryError("too_large", resp.status_code)
                    return resp.status_code, resp.headers, data
        except TimeoutError:
            raise DirectoryError("timeout") from None
        except (httpx.HTTPError, OSError) as e:
            raise DirectoryError("unreachable", 0, type(e).__name__) from None

    async def _transport_for_request(self) -> httpx.AsyncBaseTransport:
        if self._transport is not None:
            return self._transport
        parts = urlsplit(self.entry.url)
        host = parts.hostname or ""
        if parts.scheme == "http":  # a loopback directory (config.py allows no other)
            return httpx.AsyncHTTPTransport(trust_env=False)
        addresses = await public_addresses(host, parts.port or 443, self._resolver)
        if not addresses:
            raise DirectoryError("blocked", 0, "the directory host has no public address")
        return self._transport_for(addresses[0])


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _refusal(status: int, body: bytes) -> DirectoryError:
    """The directory's ``{"code", "detail", "kind"?}`` as an error; a body
    without one is ``bad_response`` (5xx stays transient by its status)."""
    data = _json_object(body) or {}
    code = data.get("code")
    detail = data.get("detail")
    kind = data.get("kind")
    return DirectoryError(
        code if isinstance(code, str) and code else "bad_response",
        status,
        detail if isinstance(detail, str) else "",
        kind if isinstance(kind, str) else None,
    )
