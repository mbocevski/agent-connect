"""A small client for the local control API (used by the CLI)."""

from __future__ import annotations

from typing import Any

import httpx

from agentconnect.config import Config
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
            msg = "no API token: is the daemon running?"
            raise ApiClientError(0, "not_running", msg) from None
        if config.api_tcp_port:
            self._transport: httpx.BaseTransport = httpx.HTTPTransport()
            self._base = f"http://127.0.0.1:{config.api_tcp_port}"
        else:
            self._transport = httpx.HTTPTransport(uds=str(config.socket_path))
            self._base = "http://agentconnectd"

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        try:
            with httpx.Client(transport=self._transport, base_url=self._base, timeout=30) as c:
                resp = c.request(
                    method, path, json=body, headers={"authorization": f"Bearer {self._token}"}
                )
        except httpx.TransportError:
            msg = "cannot reach the daemon"
            raise ApiClientError(0, "not_running", msg) from None
        data = resp.json()
        if resp.status_code != 200:  # noqa: PLR2004
            raise ApiClientError(
                resp.status_code, data.get("code", "error"), data.get("message", "")
            )
        return data
