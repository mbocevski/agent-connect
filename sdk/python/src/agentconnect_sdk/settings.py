"""Where the local daemon is: its data directory, socket and callback.

Resolved the way ``agentconnectd`` does (``docs/config.md``): the TOML file
at ``$AC_CONFIG`` or ``$XDG_CONFIG_HOME/agentconnect/config.toml``, with
``AC_DATA_DIR`` overriding the data directory. The SDK reads only the
agent-scope ``api-token`` and the ``webhook-secret`` from that directory.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentconnect.sockets import bind_path
from agentconnect_sdk.errors import AgentConnectError

API_TOKEN_FILE = "api-token"  # noqa: S105 - a file name
WEBHOOK_SECRET_FILE = "webhook-secret"  # noqa: S105 - a file name
SOCKET_FILE = "agentconnectd.sock"


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    socket: Path
    tcp_port: int
    callback_url: str | None

    @property
    def callback_port(self) -> int | None:
        if self.callback_url is None:
            return None
        return urlsplit(self.callback_url).port


def _xdg(environ: Mapping[str, str], var: str, fallback: str) -> Path:
    raw = environ.get(var, "").strip()
    base = Path(raw) if raw else Path(environ.get("HOME", str(Path.home()))) / fallback
    return base / "agentconnect"


def _table(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    return value if isinstance(value, dict) else {}


def load_settings(
    data_dir: Path | None = None,
    config_path: Path | None = None,
    environ: Mapping[str, str] = os.environ,
) -> Settings:
    if config_path is None:
        raw = environ.get("AC_CONFIG", "")
        config_path = (
            Path(raw) if raw else _xdg(environ, "XDG_CONFIG_HOME", ".config") / "config.toml"
        )
    data: dict[str, Any] = {}
    if config_path.exists():
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            raise AgentConnectError("bad_config", f"{config_path}: {e}") from None
    daemon, api, webhook = _table(data, "daemon"), _table(data, "api"), _table(data, "webhook")
    if data_dir is None:
        raw = environ.get("AC_DATA_DIR", "") or str(daemon.get("data_dir", ""))
        data_dir = Path(raw).expanduser() if raw else _xdg(environ, "XDG_DATA_HOME", ".local/share")
    socket = api.get("socket")
    port = api.get("tcp_port", 0)
    callback = webhook.get("callback_url")
    return Settings(
        data_dir=data_dir,
        # Where the daemon binds it: a path over the platform's limit is
        # bound at a short private one (agentconnect.sockets).
        socket=bind_path(
            Path(socket).expanduser()
            if isinstance(socket, str) and socket
            else data_dir / SOCKET_FILE
        ),
        tcp_port=port if isinstance(port, int) and not isinstance(port, bool) else 0,
        callback_url=callback if isinstance(callback, str) and callback else None,
    )


def read_secret(path: Path, what: str) -> str:
    """Read a 0600 token file written by the daemon."""
    try:
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        raise AgentConnectError(
            "not_running", f"no {what} at {path}: is the daemon running?"
        ) from None
