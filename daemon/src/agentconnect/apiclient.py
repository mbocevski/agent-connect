"""A small client for the local control API (used by the CLI)."""

from __future__ import annotations

from typing import Any

import httpx

from agentconnect.config import Config
from agentconnect.sockets import (
    PeerMismatchError,
    local_tcp_transport,
    local_transport,
    tcp_base_url,
)
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE


class ApiClientError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.status, self.code, self.message = status, code, message


class ApiClient:
    """Talks to a running daemon over its Unix socket (or loopback TCP)."""

    def __init__(self, config: Config, human: bool = False) -> None:
        token_file = config.data_dir / (HUMAN_TOKEN_FILE if human else API_TOKEN_FILE)
        try:
            self._token = token_file.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            if human and (config.data_dir / API_TOKEN_FILE).exists():
                # An agent directory (docs/isolation.md): the daemon is running,
                # and the human token is deliberately not here.
                msg = "no human token in this data directory"
                raise ApiClientError(0, "human_only", msg) from None
            msg = "no API token: is the daemon running?"
            raise ApiClientError(0, "not_running", msg) from None
        except PermissionError:
            # The daemon's own data directory, as another OS user.
            msg = f"this OS user can't read {token_file.parent}"
            raise ApiClientError(0, "token_unreadable", msg) from None
        if config.api_tcp_port:
            # TLS with the certificate pinned in the data directory.
            self._transport: httpx.BaseTransport = local_tcp_transport(
                config.api_tcp_port, config.data_dir
            )
            self._base = tcp_base_url(config.api_tcp_port)
        else:
            self._transport = local_transport(config.socket_path, config.data_dir)
            self._base = "http://agentconnectd"

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        try:
            with httpx.Client(transport=self._transport, base_url=self._base, timeout=30) as c:
                resp = c.request(
                    method, path, json=body, headers={"authorization": f"Bearer {self._token}"}
                )
        except PeerMismatchError as e:
            raise ApiClientError(0, e.code, str(e)) from None
        except httpx.TransportError:
            msg = "cannot reach the daemon"
            raise ApiClientError(0, "not_running", msg) from None
        data = resp.json()
        if resp.status_code != 200:  # noqa: PLR2004
            raise ApiClientError(
                resp.status_code, data.get("code", "error"), data.get("message", "")
            )
        return data
