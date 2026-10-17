"""Daemon configuration: TOML at ``~/.config/agentconnect/config.toml``.

Every value can be overridden for tests, either by passing keyword
arguments to :func:`load_config` or through the environment::

    AC_CONFIG      path of the TOML file
    AC_DATA_DIR    data directory (default ~/.local/share/agentconnect)
    AC_RELAY_URL   relay base URL (ws:// or wss://)
    AC_RELAY_HOST  host string signed into relay authentication

Example file::

    [relay]
    url = "wss://relay.example.org"
    host = "relay.example.org"      # optional; defaults to the URL's host[:port]

    [daemon]
    data_dir = "~/.local/share/agentconnect"
    display_name = "build-bot"
    default_adapter = "webhook"
    keystore = "auto"               # auto | keyring | file

    [policy]
    auto_approve = false            # approve JoinRequests without a human

    [api]
    socket = "~/.local/share/agentconnect/agentconnectd.sock"
    tcp_port = 0                    # > 0 serves on 127.0.0.1:<port> instead
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_RELAY_URL = "wss://relay.agentconnect.dev"
KEYSTORES = ("auto", "keyring", "file")


class ConfigError(ValueError):
    """An invalid configuration value."""


def _xdg(environ: Mapping[str, str], var: str, fallback: str) -> Path:
    raw = environ.get(var, "").strip()
    base = Path(raw) if raw else Path(environ.get("HOME", str(Path.home()))) / fallback
    return base / "agentconnect"


def default_config_path(environ: Mapping[str, str] = os.environ) -> Path:
    """``$XDG_CONFIG_HOME/agentconnect/config.toml``."""
    return _xdg(environ, "XDG_CONFIG_HOME", ".config") / "config.toml"


def default_data_dir(environ: Mapping[str, str] = os.environ) -> Path:
    """``$XDG_DATA_HOME/agentconnect``."""
    return _xdg(environ, "XDG_DATA_HOME", ".local/share")


@dataclass(frozen=True)
class Config:
    """Resolved daemon configuration."""

    relay_url: str
    relay_host: str
    data_dir: Path
    display_name: str = "agent"
    default_adapter: str = "none"
    keystore: str = "auto"
    auto_approve: bool = False
    api_socket: Path | None = None
    api_tcp_port: int = 0
    relay_rest_url: str | None = None

    @property
    def relay_http(self) -> str:
        """The relay's REST base URL (``http(s)://host[:port]``), derived from
        the WebSocket URL unless ``relay_rest_url`` overrides it."""
        if self.relay_rest_url is not None:
            return self.relay_rest_url.rstrip("/")
        parts = urlsplit(self.relay_url)
        scheme = "https" if parts.scheme == "wss" else "http"
        return f"{scheme}://{parts.netloc}"

    @property
    def relay_ws(self) -> str:
        """The relay's WebSocket endpoint."""
        return self.relay_url.rstrip("/") + "/v0/ws"

    @property
    def socket_path(self) -> Path:
        return self.api_socket or self.data_dir / "agentconnectd.sock"

    def with_overrides(self, **kw: Any) -> Config:
        return replace(self, **kw)


def _check_relay_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss") or not parts.netloc:
        msg = f"relay url must be ws:// or wss://, got {url!r}"
        raise ConfigError(msg)
    if parts.scheme == "ws" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        msg = "plain ws:// is only allowed for loopback relays"
        raise ConfigError(msg)
    return url


def _section(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        msg = f"[{name}] must be a table"
        raise ConfigError(msg)
    return value


def _typed[T](table: Mapping[str, Any], key: str, kind: type[T], default: T) -> T:
    value = table.get(key, default)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        msg = f"{key} must be {kind.__name__}"
        raise ConfigError(msg)
    return value


def load_config(
    path: Path | None = None,
    environ: Mapping[str, str] = os.environ,
    **overrides: Any,
) -> Config:
    """Read the TOML file (if present), then apply env and keyword overrides."""
    if path is None:
        env_path = environ.get("AC_CONFIG", "")
        path = Path(env_path) if env_path else default_config_path(environ)
    data: dict[str, Any] = {}
    if path.exists():
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            msg = f"{path}: {e}"
            raise ConfigError(msg) from None
    relay = _section(data, "relay")
    daemon = _section(data, "daemon")
    policy = _section(data, "policy")
    api = _section(data, "api")

    relay_url = environ.get("AC_RELAY_URL") or _typed(relay, "url", str, DEFAULT_RELAY_URL)
    data_dir_raw = environ.get("AC_DATA_DIR") or _typed(daemon, "data_dir", str, "")
    socket_raw = _typed(api, "socket", str, "")
    keystore = _typed(daemon, "keystore", str, "auto")
    if keystore not in KEYSTORES:
        msg = f"keystore must be one of {KEYSTORES}"
        raise ConfigError(msg)
    port = _typed(api, "tcp_port", int, 0)
    if not 0 <= port <= 65535:  # noqa: PLR2004
        msg = "tcp_port must be 0..65535"
        raise ConfigError(msg)
    values: dict[str, Any] = {
        "relay_url": relay_url,
        "relay_host": environ.get("AC_RELAY_HOST") or _typed(relay, "host", str, ""),
        "data_dir": Path(data_dir_raw).expanduser() if data_dir_raw else default_data_dir(environ),
        "display_name": _typed(daemon, "display_name", str, "agent"),
        "default_adapter": _typed(daemon, "default_adapter", str, "none"),
        "keystore": keystore,
        "auto_approve": _typed(policy, "auto_approve", bool, False),
        "api_socket": Path(socket_raw).expanduser() if socket_raw else None,
        "api_tcp_port": port,
    }
    values.update(overrides)
    values["relay_url"] = _check_relay_url(values["relay_url"])
    if not values["relay_host"]:
        values["relay_host"] = urlsplit(values["relay_url"]).netloc
    return Config(**values)
