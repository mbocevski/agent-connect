"""The local control API: small JSON over HTTP/1.1.

Transport: a Unix socket in the data directory (mode 0600) by default, or
``127.0.0.1:<port>`` when configured. The server is a minimal asyncio
HTTP/1.1 implementation (one request per connection, ``Content-Length``
bodies only, 1 MiB cap), so the daemon needs no web framework.

Authentication: ``Authorization: Bearer <token>``. There are two tokens,
each in a 0600 file in the data directory:

* ``api-token`` (scope ``agent``): everything an agent integration may do;
* ``human-token`` (scope ``human``): additionally approving JoinRequests
  and marking members verified.

Approval and verification are human decisions (SPEC §6.2, §11). An agent
that could approve joins or mark the SAS as compared would defeat both
checks, so those endpoints refuse the agent token. Hand only ``api-token``
to agent tooling. (Both files are readable by the same OS user; the split
keeps agent integrations from holding the human capability by default, it is
not a sandbox.)
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import re
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agentconnect import log
from agentconnect.daemon import HUMAN_ONLY_KINDS, Daemon, DaemonError
from agentconnect.keystore import write_private
from agentconnect.relay import RelayError

LOG = log.get("agentconnect.api")

MAX_BODY = 1 << 20
MAX_HEADER = 16 << 10
API_TOKEN_FILE = "api-token"  # noqa: S105 - a file name
HUMAN_TOKEN_FILE = "human-token"  # noqa: S105 - a file name
SCOPE = "_scope"  # handler parameter carrying the request's token scope

STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
}
ERROR_STATUS = {
    "bad_request": 400,
    "forbidden": 403,
    "not_found": 404,
    "expired": 409,
    "stale_epoch": 409,
    "invite_not_open": 409,
    "too_large": 413,
    "rate_limited": 429,
    "relay": 502,
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code = status, code


def load_token(path: Path) -> str:
    """Read the token at ``path``, creating it (0600) if missing."""
    if path.exists():
        return path.read_text(encoding="ascii").strip()
    token = secrets.token_urlsafe(32)
    write_private(path, token.encode("ascii"))
    return token


Handler = Callable[[dict[str, str], dict[str, Any]], Awaitable[Any]]


class Route:
    def __init__(self, method: str, pattern: str, handler: Handler, human: bool = False) -> None:
        self.method = method
        self.regex = re.compile(
            "^" + re.sub(r"{(\w+)}", r"(?P<\1>[A-Za-z0-9_:.-]+)", pattern) + "$"
        )
        self.handler = handler
        self.human = human


def _str(body: dict[str, Any], key: str, default: str | None = None) -> str:
    value = body.get(key, default)
    if not isinstance(value, str):
        raise ApiError(400, "bad_request", f"{key} must be a string")
    return value


def _int(body: dict[str, Any], key: str, default: int) -> int:
    value = body.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ApiError(400, "bad_request", f"{key} must be an integer")
    return value


class ApiServer:
    """Serves the control API for one :class:`Daemon`."""

    def __init__(self, daemon: Daemon) -> None:
        self.daemon = daemon
        data_dir = daemon.config.data_dir
        self.tokens = {
            "agent": load_token(data_dir / API_TOKEN_FILE),
            "human": load_token(data_dir / HUMAN_TOKEN_FILE),
        }
        self._server: asyncio.Server | None = None
        self.address: str | Path | None = None
        d = daemon
        self.routes = [
            Route("GET", "/v0/status", lambda _p, _b: self._ok(d.status())),
            Route("GET", "/v0/groups", lambda _p, _b: self._ok({"groups": d.list_groups()})),
            Route("POST", "/v0/groups", self._create_group),
            Route("GET", "/v0/groups/{gid}", lambda p, _b: self._ok(d.group_info(p["gid"]))),
            Route("POST", "/v0/groups/{gid}/invites", self._create_invite),
            Route("DELETE", "/v0/invites/{invite_id}", self._revoke),
            Route("POST", "/v0/invites/inspect", self._inspect),
            Route("POST", "/v0/invites/accept", self._accept),
            Route("POST", "/v0/groups/{gid}/messages", self._send),
            Route("POST", "/v0/groups/{gid}/leave", self._leave),
            Route("GET", "/v0/approvals", lambda _p, _b: self._ok({"approvals": d.approvals()})),
            Route("POST", "/v0/approvals/{rid}/approve", self._approve, human=True),
            Route("POST", "/v0/approvals/{rid}/reject", self._reject, human=True),
            Route("POST", "/v0/groups/{gid}/members/{identity}/verify", self._verify, human=True),
            Route("POST", "/v0/groups/{gid}/sas/mismatch", self._sas_mismatch, human=True),
            Route("GET", "/v0/events", self._events),
        ]

    @staticmethod
    async def _ok(value: Any) -> Any:
        return value

    # -- handlers ----------------------------------------------------------

    async def _create_group(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return {"group_id": self.daemon.create_group(_str(b, "name"), _str(b, "purpose", ""))}

    async def _create_invite(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        name = b.get("inviter_name")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "inviter_name must be a string")
        return await self.daemon.create_invite(
            p["gid"], _int(b, "ttl_secs", 86_400), _int(b, "max_uses", 1), name
        )

    async def _revoke(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        await self.daemon.revoke_invite(p["invite_id"])
        return {"revoked": p["invite_id"]}

    async def _inspect(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return await self.daemon.inspect_invite(_str(b, "url"))

    async def _accept(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        name = b.get("display_name")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "display_name must be a string")
        return await self.daemon.accept_invite(_str(b, "url"), name)

    async def _send(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        body = b.get("body")
        if body is None:
            body = {"text": _str(b, "text")}
        if not isinstance(body, dict):
            raise ApiError(400, "bad_request", "body must be an object")
        to = b.get("to", ["*"])
        if not isinstance(to, list) or not all(isinstance(x, str) for x in to):
            raise ApiError(400, "bad_request", "to must be a list of strings")
        kind = _str(b, "kind", "a2a.message")
        reply_to = b.get("reply_to")
        if reply_to is not None and (
            not isinstance(reply_to, list) or not all(isinstance(x, str) for x in reply_to)
        ):
            raise ApiError(400, "bad_request", "reply_to must be a list of msg_ids")
        # SPEC 7.2/10.3: only the human's own requests are human-originated.
        # The agent token always sends as the agent, and can't send the
        # controls SPEC 7.3 reserves to humans.
        human = p.get(SCOPE) == "human"
        if kind in HUMAN_ONLY_KINDS and not human:
            raise ApiError(403, "human_only", f"{kind} needs the human token")
        msg_id = self.daemon.send_message(
            p["gid"],
            body,
            to=to,
            kind=kind,
            origin="human" if human else "agent",
            reply_to=reply_to,
        )
        return {"msg_id": msg_id}

    async def _leave(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return {"status": await self.daemon.leave(p["gid"])}

    async def _approve(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        self.daemon.approve(p["rid"])
        return {"status": "approving"}

    async def _reject(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        self.daemon.reject(p["rid"])
        return {"status": "rejected"}

    async def _verify(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        verified = b.get("verified", True)
        if not isinstance(verified, bool):
            raise ApiError(400, "bad_request", "verified must be a boolean")
        self.daemon.mark_verified(p["gid"], p["identity"], verified)
        return {"verified": verified}

    async def _sas_mismatch(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        epoch = b.get("epoch")
        if epoch is not None and (not isinstance(epoch, int) or isinstance(epoch, bool)):
            raise ApiError(400, "bad_request", "epoch must be an integer")
        return {"status": await self.daemon.sas_mismatch(p["gid"], epoch)}

    async def _events(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return {"events": self.daemon.store.events(int(p.get("after", "0") or 0))}

    # -- HTTP --------------------------------------------------------------

    def _authorize(self, headers: dict[str, str], human: bool) -> str:
        """Check the bearer token; returns the scope (``agent`` or ``human``)."""
        auth = headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ApiError(401, "auth_failed", "missing bearer token")
        is_human = hmac.compare_digest(token.encode(), self.tokens["human"].encode())
        is_agent = hmac.compare_digest(token.encode(), self.tokens["agent"].encode())
        if not (is_human or is_agent):
            raise ApiError(401, "auth_failed", "invalid token")
        if human and not is_human:
            raise ApiError(403, "human_only", "this operation needs the human token")
        return "human" if is_human else "agent"

    async def handle(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, Any]:
        path, _, query = target.partition("?")
        params = dict(
            (k, v) for k, _, v in (part.partition("=") for part in query.split("&") if part)
        )
        allowed = False
        for route in self.routes:
            m = route.regex.match(path)
            if m is None:
                continue
            allowed = True
            if route.method != method:
                continue
            scope = self._authorize(headers, route.human)
            try:
                data = json.loads(body) if body else {}
            except ValueError:
                raise ApiError(400, "bad_request", "body is not JSON") from None
            if not isinstance(data, dict):
                raise ApiError(400, "bad_request", "body must be a JSON object")
            return 200, await route.handler({**params, **m.groupdict(), SCOPE: scope}, data)
        if allowed:
            raise ApiError(405, "method_not_allowed", "method not allowed")
        raise ApiError(404, "not_found", "no such endpoint")

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        status, payload = 500, {"code": "internal", "message": "internal error"}
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            if len(head) > MAX_HEADER:
                raise ApiError(413, "too_large", "headers too large")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _version = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            length = int(headers.get("content-length", "0") or 0)
            if length < 0 or length > MAX_BODY:
                raise ApiError(413, "too_large", "body too large")
            body = await reader.readexactly(length) if length else b""
            status, payload = await self.handle(method, target, headers, body)
        except ApiError as e:
            status, payload = e.status, {"code": e.code, "message": str(e)}
        except DaemonError as e:
            status, payload = ERROR_STATUS.get(e.code, 409), {"code": e.code, "message": str(e)}
        except RelayError as e:
            status, payload = 502, {"code": e.code, "message": str(e)}
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            status, payload = 400, {"code": "bad_request", "message": "malformed request"}
        except Exception:
            LOG.exception("api_failed")
        data = json.dumps(payload).encode()
        writer.write(
            f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Error')}\r\n"
            f"content-type: application/json\r\ncontent-length: {len(data)}\r\n"
            "connection: close\r\n\r\n".encode()
            + data
        )
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        writer.close()

    async def start(self) -> None:
        cfg = self.daemon.config
        if cfg.api_tcp_port:
            port = cfg.api_tcp_port
            self._server = await asyncio.start_server(
                self._serve, "127.0.0.1", port, limit=MAX_HEADER
            )
            sock = self._server.sockets[0].getsockname()
            self.address = f"http://127.0.0.1:{sock[1]}"
        else:
            path = cfg.socket_path
            path.unlink(missing_ok=True)
            self._server = await asyncio.start_unix_server(self._serve, path, limit=MAX_HEADER)
            path.chmod(0o600)
            self.address = path
        LOG.info("api_listening", transport="tcp" if cfg.api_tcp_port else "unix")

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if isinstance(self.address, Path):
            self.address.unlink(missing_ok=True)
