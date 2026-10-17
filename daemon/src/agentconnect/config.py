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

    [webhook]
    callback_url = "http://127.0.0.1:8808/"   # where the webhook adapter POSTs
    allow_remote = false            # opt in to a callback that isn't loopback
    timeout_secs = 120              # per request; an agent turn may be slow
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import agentconnect_core as ac

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
    webhook_url: str | None = None
    webhook_allow_remote: bool = False
    webhook_timeout: int = 120

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


@dataclass(frozen=True)
class ConfigKey:
    """A key of ``config.toml`` and the :class:`Config` field it fills.

    :data:`CONFIG_KEYS` is what ``docs/config.md`` is generated from
    (``scripts/gen_reference.py``): the type comes from the dataclass field,
    the rest is written here, next to the loader that gives it meaning.
    """

    key: str  # `section.name` in the TOML file
    field: str  # attribute of Config
    default: str  # as the docs show it
    doc: str
    env: str = ""  # environment variable that overrides it


CONFIG_KEYS: tuple[ConfigKey, ...] = (
    ConfigKey(
        "relay.url",
        "relay_url",
        f"`{DEFAULT_RELAY_URL}`",
        "Relay base URL. `wss://`, or `ws://` for a loopback relay only.",
        "AC_RELAY_URL",
    ),
    ConfigKey(
        "relay.host",
        "relay_host",
        "the URL's `host[:port]`",
        "The host string signed into relay authentication. It must match the "
        "relay's `AC_RELAY_HOST`.",
        "AC_RELAY_HOST",
    ),
    ConfigKey(
        "daemon.data_dir",
        "data_dir",
        "`$XDG_DATA_HOME/agentconnect`",
        "Keys, databases, API tokens and the API socket. Created 0700.",
        "AC_DATA_DIR",
    ),
    ConfigKey("daemon.display_name", "display_name", "`agent`", "The name other members see."),
    ConfigKey(
        "daemon.default_adapter",
        "default_adapter",
        "`none`",
        "The adapter that new groups deliver to: `webhook` "
        "([adapters/webhook.md](adapters/webhook.md)), `sse` (the event stream of "
        "`GET /v0/events`, see [api.md](api.md#event-stream)) or `none`. With "
        "`none`, received messages wait in the inbound queue. The A2A adapter is "
        "not written yet.",
    ),
    ConfigKey(
        "daemon.keystore",
        "keystore",
        "`auto`",
        "`keyring` (the OS keyring), `file` (0600 files in the data directory), or "
        "`auto` (the keyring when one is usable, files otherwise).",
    ),
    ConfigKey(
        "policy.auto_approve",
        "auto_approve",
        "`false`",
        "Approve JoinRequests without asking a human. Leave it off unless every "
        "holder of your invite links is trusted.",
    ),
    ConfigKey(
        "api.socket",
        "api_socket",
        "`<data_dir>/agentconnectd.sock`",
        "Unix socket for the local API.",
    ),
    ConfigKey(
        "api.tcp_port",
        "api_tcp_port",
        "`0`",
        "When greater than 0, serve the local API on `127.0.0.1:<port>` instead of "
        "the socket (0 to 65535).",
    ),
    ConfigKey(
        "webhook.callback_url",
        "webhook_url",
        "none",
        "Where the webhook adapter POSTs. Required when `default_adapter = "
        '"webhook"`. Loopback unless `webhook.allow_remote` is set.',
    ),
    ConfigKey(
        "webhook.allow_remote",
        "webhook_allow_remote",
        "`false`",
        "Allow a `callback_url` that is not loopback. It must then use `https`.",
    ),
    ConfigKey(
        "webhook.timeout_secs",
        "webhook_timeout",
        "`120`",
        "How long the daemon waits for each webhook response (1 to 3600). The SDK "
        "answers after your handler returns, so allow for a slow model call.",
    ),
)

# Environment variables that don't override a single key.
CONFIG_ENV_EXTRA: tuple[tuple[str, str], ...] = (("AC_CONFIG", "The path of the TOML file."),)

# Config fields with no key in the file (set in code, mostly by tests).
CONFIG_FIELDS_WITHOUT_KEY = frozenset({"relay_rest_url"})


def _check_relay_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss") or not parts.netloc:
        msg = f"relay url must be ws:// or wss://, got {url!r}"
        raise ConfigError(msg)
    if parts.scheme == "ws" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        msg = "plain ws:// is only allowed for loopback relays"
        raise ConfigError(msg)
    return url


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_callback_url(url: str, allow_remote: bool) -> str:
    """A webhook callback must be loopback unless ``allow_remote`` is set,
    and a remote one must use ``https`` (message text travels in the body)."""
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme not in ("http", "https") or host is None or host == "":
        msg = f"webhook callback_url must be http:// or https://, got {url!r}"
        raise ConfigError(msg)
    if "@" in parts.netloc:
        msg = "webhook callback_url must not carry credentials"
        raise ConfigError(msg)
    loopback = _is_loopback(host)
    if not loopback:
        if not allow_remote:
            msg = "webhook callback_url is not loopback; set webhook.allow_remote to allow it"
            raise ConfigError(msg)
        if parts.scheme != "https":
            msg = "a remote webhook callback_url must use https"
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
    webhook = _section(data, "webhook")

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
        "webhook_url": _typed(webhook, "callback_url", str, "") or None,
        "webhook_allow_remote": _typed(webhook, "allow_remote", bool, False),
        "webhook_timeout": _typed(webhook, "timeout_secs", int, 120),
    }
    values.update(overrides)
    if not 1 <= values["webhook_timeout"] <= 3600:  # noqa: PLR2004
        msg = "webhook timeout_secs must be 1..3600"
        raise ConfigError(msg)
    if values["webhook_url"] is not None:
        check_callback_url(values["webhook_url"], values["webhook_allow_remote"])
    elif values["default_adapter"] == "webhook":
        msg = 'default_adapter "webhook" needs webhook.callback_url'
        raise ConfigError(msg)
    values["relay_url"] = _check_relay_url(values["relay_url"])
    if not values["relay_host"]:
        # The URL's authority without any userinfo (SPEC 8.1.1).
        values["relay_host"] = urlsplit(values["relay_url"]).netloc.rpartition("@")[2]
    try:
        values["relay_host"] = ac.canonical_relay_host(values["relay_host"])
    except ac.AgentConnectError:
        msg = f"relay host {values['relay_host']!r} is not a valid host[:port]"
        raise ConfigError(msg) from None
    return Config(**values)
