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
    require_approval = "off"        # off | inbound | outbound | both
    frame_text = true               # the SPEC 10.1 notice for text consumers
    sender_per_minute = 30          # and the other limits: docs/safety.md
    transcript = false              # full transcript (encrypted), per group

    [api]
    socket = "~/.local/share/agentconnect/agentconnectd.sock"
    tcp_port = 0                    # > 0 serves on 127.0.0.1:<port> instead

    [sse]
    retention_secs = 3600           # how long the SSE feed keeps items for resume

    [webhook]
    callback_url = "http://127.0.0.1:8808/"   # where the webhook adapter POSTs
    allow_remote = false            # opt in to a callback that isn't loopback
    timeout_secs = 120              # per request; an agent turn may be slow
    [sdk]                           # the embedded SDK (docs/sdk.md)
    handler_timeout_secs = 120      # per handler call; then cancelled and retried
    [a2a]                           # optional: the A2A adapter (docs/adapters/a2a.md)
    local_agent_url = "http://127.0.0.1:9999/"
    local_agent_token_file = "~/.config/agentconnect/agent-token"
    card_keys_file = "~/.config/agentconnect/card-keys.json"
    facade_port = 8765              # 0: no facade
    context_messages = 20
    frame_text = true
    reply_timeout = 600
    [isolation]                     # optional: separate-OS-user mode (docs/isolation.md)
    enabled = false
    agent_dir = "/run/agentconnect"
    group = "agentconnect"
    agent_users = ["bot"]           # names or UIDs allowed on the socket
    human_users = []                # also allowed to use the human token
    [[directory]]                   # a directory you may list in (docs/discovery.md)
    host = "directory.example.org"
    keys = ["<the operator's DK.pub, base64url>"]
    [listing]
    door_lifetime_secs = 601200     # 7 days less 1 hour
    [knock]                         # knocking on listings (docs/discovery.md)
    agent_may_knock = true          # false: only the human token may knock
    domain_check = true             # fetch the owner's domain file before a knock
    [groups]                        # membership (docs/groups.md)
    leave_timeout_secs = 604800     # a leave nobody commits ends locally after this
    cleanup_departed_roles = true   # the owner drops departed admins and moderators
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import agentconnect_core as ac
from agentconnect.policy import (
    DEFAULT_AUDIT_GROUP_ROWS,
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_AUDIT_SENDER_ROWS,
    DEFAULT_TRANSCRIPT_MAX_BYTES,
    KNOB,
    KNOBS,
    MAX_PENDING_KNOCKS,
    PolicyError,
    Settings,
)

KEYSTORES = ("auto", "keyring", "file")
# SPEC 6.6.1: a door lives at most 7 days, measured on the relay's clock, so
# the default asks for an hour less.
MIN_DOOR_LIFETIME_SECS = 7200
DEFAULT_DOOR_LIFETIME_SECS = ac.MAX_DOOR_LIFETIME_SECS - 3600
MAX_DIRECTORY_KEYS = 2
# SPEC 6.6.2, 6.6.3 and 8.3: the knock limits a daemon may only lower.
MAX_OUTGOING_KNOCKS = 8
MAX_KNOCKS_PER_HOUR = 20
MAX_PENDING_KNOCKS_PER_DOOR = MAX_PENDING_KNOCKS
MAX_KNOCKS_OPENED_PER_MINUTE = 10
DEFAULT_KNOCK_FAILURES_PER_HOUR = 10
MAX_KNOCK_FAILURES_PER_HOUR = 100
MIN_LEDGER_CAPACITY = 1024
# An invite's share of the join replay ledger (SPEC 6.2 "Replays"):
# max(4 x max_uses, 64), at most policy.join_ledger_per_invite.
MIN_JOIN_LEDGER_PER_INVITE = 64
MAX_JOIN_LEDGER_PER_INVITE = 1024
# JoinRequests of one invite that may wait for the human at once (as knocks
# per door, SPEC 6.6.3 step 7).
MAX_PENDING_JOINS_PER_INVITE = 32
# How long a leave waits for a member to commit it (docs/groups.md): at most
# the relay's 7-day message lifetime, after which the proposal can't arrive.
MIN_LEAVE_TIMEOUT_SECS = 3600
MAX_LEAVE_TIMEOUT_SECS = 7 * 86_400


class ConfigError(ValueError):
    """An invalid configuration value."""


@dataclass(frozen=True)
class DirectoryConfig:
    """One pinned directory (a ``[[directory]]`` table): its canonical host,
    the operator token keys (``DK.pub``) pinned for it, never fetched (SPEC
    13.2.1), and the base URL requests go to."""

    host: str
    keys: tuple[bytes, ...]
    url: str


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
    sse_retention: int = 3600
    sdk_handler_timeout: int = 120
    a2a_local_agent_url: str | None = None
    a2a_local_agent_token_file: Path | None = None
    a2a_card_keys_file: Path | None = None
    a2a_facade_port: int = 0
    a2a_context_messages: int = 20
    a2a_frame_text: bool = True
    a2a_reply_timeout: int = 600
    isolation: bool = False
    isolation_agent_dir: Path = Path("/run/agentconnect")
    isolation_group: str = "agentconnect"
    isolation_agent_users: tuple[str, ...] = ()
    isolation_human_users: tuple[str, ...] = ()
    directories: tuple[DirectoryConfig, ...] = ()
    listing_card_file: Path | None = None
    listing_token_file: Path | None = None
    listing_door_lifetime_secs: int = DEFAULT_DOOR_LIFETIME_SECS
    knock_agent_may_knock: bool = True
    knock_domain_check: bool = True
    knock_max_outgoing: int = MAX_OUTGOING_KNOCKS
    knock_per_hour: int = MAX_KNOCKS_PER_HOUR
    knock_max_pending_per_door: int = MAX_PENDING_KNOCKS_PER_DOOR
    knock_opened_per_door_per_minute: int = MAX_KNOCKS_OPENED_PER_MINUTE
    knock_failures_per_sender_per_hour: int = DEFAULT_KNOCK_FAILURES_PER_HOUR
    knock_ledger_capacity: int = ac.DEFAULT_LEDGER_CAPACITY
    groups_leave_timeout_secs: int = MAX_LEAVE_TIMEOUT_SECS
    groups_cleanup_departed_roles: bool = True

    def directory(self, host: str) -> DirectoryConfig | None:
        """The pinned directory ``host`` names (in any host form), if any."""
        try:
            canonical = ac.canonical_relay_host(host)
        except ac.AgentConnectError:
            return None
        return next((d for d in self.directories if d.host == canonical), None)

    @property
    def a2a_enabled(self) -> bool:
        """Whether the daemon runs the A2A adapter: a local agent, a facade or both."""
        return self.a2a_local_agent_url is not None or self.a2a_facade_port > 0

    # [policy]: the safety policy's defaults (agentconnect.policy.KNOBS).
    policy_max_message_bytes: int = KNOB["max_message_bytes"].default
    policy_sender_per_minute: int = KNOB["sender_per_minute"].default
    policy_group_per_minute: int = KNOB["group_per_minute"].default
    policy_identity_rate_multiple: int = KNOB["identity_rate_multiple"].default
    policy_task_per_minute: int = KNOB["task_per_minute"].default
    policy_group_task_per_minute: int = KNOB["group_task_per_minute"].default
    policy_allow_files: bool = KNOB["allow_files"].default
    policy_max_file_bytes: int = KNOB["max_file_bytes"].default
    policy_frame_text: bool = KNOB["frame_text"].default
    policy_require_approval: str = KNOB["require_approval"].default
    policy_approval_ttl_secs: int = KNOB["approval_ttl_secs"].default
    policy_max_held_per_group: int = KNOB["max_held_per_group"].default
    policy_max_held_per_sender: int = KNOB["max_held_per_sender"].default
    policy_max_held_bytes: int = KNOB["max_held_bytes"].default
    policy_max_held_bytes_per_sender: int = KNOB["max_held_bytes_per_sender"].default
    policy_task_approval_window_secs: int = KNOB["task_approval_window_secs"].default
    policy_violation_threshold: int = KNOB["violation_threshold"].default
    policy_violation_window_secs: int = KNOB["violation_window_secs"].default
    policy_transcript: bool = KNOB["transcript"].default
    policy_transcript_retention_days: int = KNOB["transcript_retention_days"].default
    policy_transcript_max_rows: int = KNOB["transcript_max_rows"].default
    policy_transcript_max_bytes: int = DEFAULT_TRANSCRIPT_MAX_BYTES
    policy_audit_max_rows_per_group: int = DEFAULT_AUDIT_GROUP_ROWS
    policy_audit_max_rows_per_sender: int = DEFAULT_AUDIT_SENDER_ROWS
    policy_max_pending_joins_per_invite: int = MAX_PENDING_JOINS_PER_INVITE
    policy_join_ledger_per_invite: int = MAX_JOIN_LEDGER_PER_INVITE
    policy_transcript_max_rows_per_sender: int = KNOB["transcript_max_rows_per_sender"].default
    policy_transcript_max_group_bytes: int = KNOB["transcript_max_group_bytes"].default
    policy_audit_retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS

    def safety_defaults(self) -> Settings:
        """The safety policy every group starts from (docs/safety.md)."""
        return Settings.of({k.name: getattr(self, f"policy_{k.name}") for k in KNOBS})

    def require_relay(self) -> None:
        """Raise :class:`ConfigError` unless a relay is configured: there is no
        built-in default."""
        if not self.relay_url:
            msg = "relay.url is required (the relay this agent uses)"
            raise ConfigError(msg)

    @property
    def relay_http(self) -> str:
        """The relay's REST base URL (``http(s)://host[:port]``), derived from
        the WebSocket URL unless ``relay_rest_url`` overrides it."""
        if self.relay_rest_url is not None:
            return self.relay_rest_url.rstrip("/")
        self.require_relay()
        parts = urlsplit(self.relay_url)
        scheme = "https" if parts.scheme == "wss" else "http"
        return f"{scheme}://{parts.netloc}"

    @property
    def relay_ws(self) -> str:
        """The relay's WebSocket endpoint."""
        self.require_relay()
        return self.relay_url.rstrip("/") + "/v0/ws"

    @property
    def socket_path(self) -> Path:
        # Separate-OS-user mode: agents can't enter the data directory, so the
        # socket lives in the agent directory (docs/isolation.md).
        home = self.isolation_agent_dir if self.isolation else self.data_dir
        return self.api_socket or home / "agentconnectd.sock"

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
    # The TOML type, for a key of an array of tables (`[[directory]]`):
    # its tables together fill one field, so the field's type isn't the key's.
    kind: str = ""


def shown_default(value: object) -> str:
    """A default as the docs show it: TOML syntax in backticks."""
    if isinstance(value, bool):
        return "`true`" if value else "`false`"
    if isinstance(value, str):
        return f'`"{value}"`'
    return f"`{value}`"


_POLICY_KEYS: tuple[ConfigKey, ...] = (
    *(
        ConfigKey(f"policy.{k.name}", f"policy_{k.name}", shown_default(k.default), k.doc)
        for k in KNOBS
    ),
    ConfigKey(
        "policy.audit_retention_days",
        "policy_audit_retention_days",
        shown_default(DEFAULT_AUDIT_RETENTION_DAYS),
        "Days the metadata-only audit log keeps a row (1 to 365). Drops, routine rows and "
        "decisions also keep at most their newest 100000 rows each, 300000 in all; "
        "security rows have no total cap and are bounded per admitted sender instead "
        "(`policy.audit_max_rows_per_sender` per group and decision).",
    ),
    ConfigKey(
        "policy.transcript_max_bytes",
        "policy_transcript_max_bytes",
        shown_default(DEFAULT_TRANSCRIPT_MAX_BYTES),
        "Bytes all transcripts together keep at most (1048576 to 67108864, 64 MiB); the "
        "oldest entries go first.",
    ),
    ConfigKey(
        "policy.audit_max_rows_per_group",
        "policy_audit_max_rows_per_group",
        shown_default(DEFAULT_AUDIT_GROUP_ROWS),
        "Drops, routine rows and decisions one group keeps at most, each (1000 to 20000). "
        "Past that, the senders holding the most rows of the class give way, oldest "
        "first. Security rows don't count toward it.",
    ),
    ConfigKey(
        "policy.audit_max_rows_per_sender",
        "policy_audit_max_rows_per_sender",
        shown_default(DEFAULT_AUDIT_SENDER_ROWS),
        "Drops and routine rows one sender keeps in a group at most, each, the newest "
        "(100 to 2000), so a sender flooding the log with them pushes out only its own. "
        "Of its security rows (content that reached the agent or left it, holds and "
        "their outcomes, refusals of what it may not do) it keeps this many per "
        "decision, the oldest half and a rolling newest half, and counts the rows "
        "between. Decisions have no per-sender cap.",
    ),
    ConfigKey(
        "policy.max_pending_joins_per_invite",
        "policy_max_pending_joins_per_invite",
        shown_default(MAX_PENDING_JOINS_PER_INVITE),
        f"Join requests for one invite that may wait for your approval at once (1 to "
        f"{MAX_PENDING_JOINS_PER_INVITE}). The rest are dropped silently, and you get an "
        "`invite_flooded` event.",
    ),
    ConfigKey(
        "policy.join_ledger_per_invite",
        "policy_join_ledger_per_invite",
        shown_default(MAX_JOIN_LEDGER_PER_INVITE),
        f"The most join requests the replay ledger remembers for one invite "
        f"({MIN_JOIN_LEDGER_PER_INVITE} to {MAX_JOIN_LEDGER_PER_INVITE}). An invite's "
        f"share is 4 times its `max_uses`, at least {MIN_JOIN_LEDGER_PER_INVITE} and at "
        "most this. Past it, new requests for that invite are dropped and you get an "
        "`invite_flooded` event; other invites are unaffected.",
    ),
)

CONFIG_KEYS: tuple[ConfigKey, ...] = (
    ConfigKey(
        "relay.url",
        "relay_url",
        "required",
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
        "`GET /v0/events`, see [api.md](api.md#event-stream)), `mcp` (the queue MCP "
        "sessions attached to this daemon pull from, [adapters/mcp.md](adapters/mcp.md)) "
        "or `none`. With "
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
        "holder of your invite links is trusted. It never applies to knocks: every "
        "knock needs a person (SPEC 6.6.4), and no setting changes that.",
    ),
    *_POLICY_KEYS,
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
    ConfigKey(
        "sdk.handler_timeout_secs",
        "sdk_handler_timeout",
        "`120`",
        "Embedded SDK only: how long a message or event handler may run (1 to 3600). "
        "A handler still running then is cancelled and the delivery retried with "
        "backoff, as for a webhook that timed out. Allow for a slow model call.",
    ),
    ConfigKey(
        "sse.retention_secs",
        "sse_retention",
        "`3600`",
        "How long the SSE adapter keeps messages and events for `Last-Event-ID` "
        "resume (60 to 604800). After that the payloads are deleted and a consumer "
        "resuming from before the window gets an `sse_gap` event. Used only with "
        '`default_adapter = "sse"`.',
    ),
    ConfigKey(
        "a2a.local_agent_url",
        "a2a_local_agent_url",
        "none",
        "Base URL of the local A2A agent (`http://` or `https://`) that the A2A adapter "
        "hands group messages to ([adapters/a2a.md](adapters/a2a.md)).",
    ),
    ConfigKey(
        "a2a.local_agent_token_file",
        "a2a_local_agent_token_file",
        "none",
        "A file holding a bearer token the adapter sends to the local agent.",
    ),
    ConfigKey(
        "a2a.card_keys_file",
        "a2a_card_keys_file",
        "none",
        "A JWKS file with the public keys you trust to sign Agent Cards.",
    ),
    ConfigKey(
        "a2a.facade_port",
        "a2a_facade_port",
        "`0`",
        "The A2A facade's port on `127.0.0.1` (0 to 65535); `0` turns it off.",
    ),
    ConfigKey(
        "a2a.context_messages",
        "a2a_context_messages",
        "`20`",
        "Messages that didn't trigger the agent kept for its next call (0 to 100).",
    ),
    ConfigKey(
        "a2a.frame_text",
        "a2a_frame_text",
        "`true`",
        "Put the SPEC section 10.1 notice in front of each message as its first text part.",
    ),
    ConfigKey(
        "a2a.reply_timeout",
        "a2a_reply_timeout",
        "`600`",
        "Seconds a facade request waits for the first reply from the group.",
    ),
    ConfigKey(
        "isolation.enabled",
        "isolation",
        "`false`",
        "Separate-OS-user mode ([isolation.md](isolation.md)): the daemon runs as its "
        "own user, checks the peer's UID on every connection, and serves the socket "
        "and a copy of `api-token` from `isolation.agent_dir`. Needs the Unix socket "
        "(no `api.tcp_port`) and refuses to start as root or with a data directory, "
        "token or agent directory that others can read.",
    ),
    ConfigKey(
        "isolation.agent_dir",
        "isolation_agent_dir",
        "`/run/agentconnect`",
        "The directory agents use as their data directory (`AC_DATA_DIR`): the socket, "
        "`api-token` and `webhook-secret`, group-readable by `isolation.group`. It must "
        "be owned by the daemon's user, belong to that group and give others no access.",
    ),
    ConfigKey(
        "isolation.group",
        "isolation_group",
        "`agentconnect`",
        "The group (name or GID) that owns the socket and the agent directory. Agent "
        "users join it.",
    ),
    ConfigKey(
        "isolation.agent_users",
        "isolation_agent_users",
        "`[]`",
        "Users (names or UIDs) allowed to connect with the agent token, besides the "
        "daemon's own user. Any other UID is logged and refused.",
    ),
    ConfigKey(
        "isolation.human_users",
        "isolation_human_users",
        "`[]`",
        "Users (names or UIDs), besides the daemon's own user, from whom the human "
        "token is accepted, such as `0` for `sudo agentconnect ...`. The human token "
        "is still required. A user can't be in both lists.",
    ),
    ConfigKey(
        "directory.host",
        "directories",
        "required",
        "One `[[directory]]` table per directory you may publish a listing in "
        "([discovery.md](discovery.md)). Its host, e.g. `directory.example.org`, as "
        "listings and tokens name it. There is no default directory.",
        kind="string",
    ),
    ConfigKey(
        "directory.keys",
        "directories",
        "required",
        "The directory operator's token keys (`DK.pub`, base64url): one, or two while "
        "the operator rotates. They are pinned here and never fetched, not even from "
        "the directory's `/.well-known/agentconnect-directory.json`.",
        kind="array",
    ),
    ConfigKey(
        "directory.url",
        "directories",
        "`https://<host>`",
        "Where the daemon sends the directory's requests. `https://`, or `http://` "
        "for a loopback directory only. It is never taken from a listing.",
        kind="string",
    ),
    ConfigKey(
        "listing.card_file",
        "listing_card_file",
        "`$XDG_CONFIG_HOME/agentconnect/listing-card.json`",
        "The listing's card text, read by `agentconnect listing publish` as the "
        "calling user ([discovery.md](discovery.md#the-card-file)).",
    ),
    ConfigKey(
        "listing.token_file",
        "listing_token_file",
        "`$XDG_CONFIG_HOME/agentconnect/listing-token.json`",
        "The listing token from the directory's operator, read by "
        "`agentconnect listing publish`. It is not a secret.",
    ),
    ConfigKey(
        "listing.door_lifetime_secs",
        "listing_door_lifetime_secs",
        shown_default(DEFAULT_DOOR_LIFETIME_SECS),
        "How long each door lives (7200 to 604800). The relay counts the 7-day "
        "maximum on its own clock, so the default leaves an hour for clock skew. A "
        "door never outlives the listing token. The runtime renews the door at half "
        "its lifetime (SPEC 6.6.1).",
    ),
    ConfigKey(
        "knock.agent_may_knock",
        "knock_agent_may_knock",
        "`true`",
        "Whether the agent token may knock on a listing (`agentconnect knock`, `POST "
        "/v0/knocks`). `false` leaves knocking to the human token. Approving a knock is "
        "always the human's, whatever this says ([discovery.md](discovery.md#knocking)).",
    ),
    ConfigKey(
        "knock.domain_check",
        "knock_domain_check",
        "`true`",
        "Before a knock, fetch the listing owner's `/.well-known/agentconnect.json` to "
        "check the owner domain it claims. The domain's web server learns that someone "
        "is about to knock, and from which address. `agentconnect knock` asks unless "
        "`--yes` or `--json`; `--no-domain-check` skips it.",
    ),
    ConfigKey(
        "knock.max_outgoing",
        "knock_max_outgoing",
        shown_default(MAX_OUTGOING_KNOCKS),
        "Knocks this runtime may have waiting for an answer at once (1 to 8, SPEC 6.6.2).",
    ),
    ConfigKey(
        "knock.per_hour",
        "knock_per_hour",
        shown_default(MAX_KNOCKS_PER_HOUR),
        "Knocks this runtime sends in an hour at most (1 to 20, the relay's limit), and "
        "never more than one on the same door in 10 minutes.",
    ),
    ConfigKey(
        "knock.max_pending_per_door",
        "knock_max_pending_per_door",
        shown_default(MAX_PENDING_KNOCKS_PER_DOOR),
        "Knocks on one of your doors that may wait for your approval at once (1 to 32, "
        "SPEC 6.6.3); the rest are dropped. One per knocking identity.",
    ),
    ConfigKey(
        "knock.opened_per_door_per_minute",
        "knock_opened_per_door_per_minute",
        shown_default(MAX_KNOCKS_OPENED_PER_MINUTE),
        "Sealed knocks on one door the runtime opens in a minute (1 to 10); the rest are "
        "dropped unopened, so a flood can't spend the CPU that opening one takes.",
    ),
    ConfigKey(
        "knock.failures_per_sender_per_hour",
        "knock_failures_per_sender_per_hour",
        shown_default(DEFAULT_KNOCK_FAILURES_PER_HOUR),
        "Knocks from one sender mailbox that may fail the owner's checks in an hour "
        "(1 to 100). Past it, that mailbox's knocks are dropped unopened until the hour "
        "is over.",
    ),
    ConfigKey(
        "knock.ledger_capacity",
        "knock_ledger_capacity",
        shown_default(ac.DEFAULT_LEDGER_CAPACITY),
        f"Knocks the replay ledger remembers at most ({MIN_LEDGER_CAPACITY} to "
        f"{ac.DEFAULT_LEDGER_CAPACITY}). It forgets none early: when it is full, new "
        "knocks are dropped until old ones expire.",
    ),
    ConfigKey(
        "groups.leave_timeout_secs",
        "groups_leave_timeout_secs",
        shown_default(MAX_LEAVE_TIMEOUT_SECS),
        f"How long a leave waits for another member to commit it ({MIN_LEAVE_TIMEOUT_SECS} "
        f"to {MAX_LEAVE_TIMEOUT_SECS}). Then, once it has caught up with the relay, the runtime "
        "deletes the group's state and reports `left` with `confirmed: false`, unless this "
        "instance is the owner's: it keeps the group and reports `leave_blocked` "
        "([groups.md](groups.md#a-leave-nobody-commits)).",
    ),
    ConfigKey(
        "groups.cleanup_departed_roles",
        "groups_cleanup_departed_roles",
        "`true`",
        "Whether the owner's instance drops an identity that left the group from `admins` and "
        "`floor_moderator`, with a policy change that only narrows roles (SPEC 9.2). `false` "
        "leaves the roles in place, and the identity gets them back if it rejoins "
        "([groups.md](groups.md#departed-roles)).",
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


MAX_CONTEXT_MESSAGES = 100


def _path(table: Mapping[str, Any], key: str) -> Path | None:
    raw = _typed(table, key, str, "")
    return Path(raw).expanduser() if raw else None


def _a2a(data: Mapping[str, Any]) -> dict[str, Any]:
    table = _section(data, "a2a")
    url = _typed(table, "local_agent_url", str, "") or None
    if url is not None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            msg = f"a2a.local_agent_url must be http:// or https://, got {url!r}"
            raise ConfigError(msg)
    port = _typed(table, "facade_port", int, 0)
    if not 0 <= port <= 65535:  # noqa: PLR2004
        msg = "a2a.facade_port must be 0..65535"
        raise ConfigError(msg)
    context = _typed(table, "context_messages", int, 20)
    if not 0 <= context <= MAX_CONTEXT_MESSAGES:
        msg = f"a2a.context_messages must be 0..{MAX_CONTEXT_MESSAGES}"
        raise ConfigError(msg)
    timeout = _typed(table, "reply_timeout", int, 600)
    if timeout <= 0:
        msg = "a2a.reply_timeout must be a positive number of seconds"
        raise ConfigError(msg)
    return {
        "a2a_local_agent_url": url,
        "a2a_local_agent_token_file": _path(table, "local_agent_token_file"),
        "a2a_card_keys_file": _path(table, "card_keys_file"),
        "a2a_facade_port": port,
        "a2a_context_messages": context,
        "a2a_frame_text": _typed(table, "frame_text", bool, True),
        "a2a_reply_timeout": timeout,
    }


def _users(table: Mapping[str, Any], key: str) -> tuple[str, ...]:
    raw = _typed(table, key, list, [])
    if not all(isinstance(u, str | int) and not isinstance(u, bool) for u in raw):
        msg = f"isolation.{key} must be a list of user names or UIDs"
        raise ConfigError(msg)
    return tuple(str(u) for u in raw)


def _isolation(data: Mapping[str, Any]) -> dict[str, Any]:
    table = _section(data, "isolation")
    group = table.get("group", "agentconnect")
    if not isinstance(group, str | int) or isinstance(group, bool) or group == "":
        msg = "isolation.group must be a group name or GID"
        raise ConfigError(msg)
    return {
        "isolation": _typed(table, "enabled", bool, False),
        "isolation_agent_dir": _path(table, "agent_dir") or Path("/run/agentconnect"),
        "isolation_group": str(group),
        "isolation_agent_users": _users(table, "agent_users"),
        "isolation_human_users": _users(table, "human_users"),
    }


MAX_AUDIT_RETENTION_DAYS = 365
MIN_TRANSCRIPT_BYTES = 1024 * 1024


def _policy(table: Mapping[str, Any]) -> dict[str, Any]:
    """The safety policy keys of ``[policy]`` (agentconnect.policy.KNOBS)."""
    out: dict[str, Any] = {}
    for knob in KNOBS:
        if knob.name in table:
            try:
                out[f"policy_{knob.name}"] = knob.check(table[knob.name])
            except PolicyError as e:
                msg = f"policy.{e}"
                raise ConfigError(msg) from None
    days = _typed(table, "audit_retention_days", int, DEFAULT_AUDIT_RETENTION_DAYS)
    if not 1 <= days <= MAX_AUDIT_RETENTION_DAYS:
        msg = f"policy.audit_retention_days must be 1..{MAX_AUDIT_RETENTION_DAYS}"
        raise ConfigError(msg)
    out["policy_audit_retention_days"] = days
    size = _typed(table, "transcript_max_bytes", int, DEFAULT_TRANSCRIPT_MAX_BYTES)
    if not MIN_TRANSCRIPT_BYTES <= size <= DEFAULT_TRANSCRIPT_MAX_BYTES:
        msg = f"policy.transcript_max_bytes must be {MIN_TRANSCRIPT_BYTES}.."
        msg += str(DEFAULT_TRANSCRIPT_MAX_BYTES)
        raise ConfigError(msg)
    out["policy_transcript_max_bytes"] = size
    for key, lo, hi in (
        ("audit_max_rows_per_group", 1000, DEFAULT_AUDIT_GROUP_ROWS),
        ("audit_max_rows_per_sender", 100, DEFAULT_AUDIT_SENDER_ROWS),
        ("max_pending_joins_per_invite", 1, MAX_PENDING_JOINS_PER_INVITE),
        ("join_ledger_per_invite", MIN_JOIN_LEDGER_PER_INVITE, MAX_JOIN_LEDGER_PER_INVITE),
    ):
        value = _typed(table, key, int, hi)
        if not lo <= value <= hi:
            msg = f"policy.{key} must be {lo}..{hi}"
            raise ConfigError(msg)
        out[f"policy_{key}"] = value
    return out


NEVER_AUTO = (
    "auto_approve isn't a key of [{table}]: publishing a listing and approving a "
    "knock always need a human"
)


def _closed(table: Mapping[str, Any], name: str, allowed: frozenset[str]) -> None:
    """The discovery tables refuse keys they don't know (a typo would
    otherwise leave a default in force), ``auto_approve`` with a reason."""
    if "auto_approve" in table:
        raise ConfigError(NEVER_AUTO.format(table=name))
    unknown = sorted(set(table) - allowed)
    if unknown:
        msg = f"unknown key(s) in [{name}]: {', '.join(unknown)}"
        raise ConfigError(msg)


def _b64url(text: str) -> bytes | None:
    """Canonical unpadded base64url, or None."""
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error):
        return None
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return raw if canonical == text else None


def _directory_url(url: str, host: str) -> str:
    parts = urlsplit(url)
    plain = parts.scheme == "http" and parts.hostname is not None and _is_loopback(parts.hostname)
    if parts.scheme != "https" and not plain:
        msg = f"directory.url must be https:// (or http:// for a loopback directory), got {url!r}"
        raise ConfigError(msg)
    if parts.hostname in (None, "") or "@" in parts.netloc or parts.query or parts.fragment:
        msg = f"directory.url for {host} must be a plain base URL"
        raise ConfigError(msg)
    if parts.path not in ("", "/"):
        msg = f"directory.url for {host} must not have a path"
        raise ConfigError(msg)
    if parts.scheme == "https" and _never_dialled(str(parts.hostname)):
        # The client dials public addresses only (agentconnect.ownerfile);
        # a name must resolve to one too, or requests fail as `blocked`.
        msg = (
            f"directory.url for {host} names a loopback or private address; an https "
            "directory must be on a public address (http:// is for a loopback test directory)"
        )
        raise ConfigError(msg)
    return f"{parts.scheme}://{parts.netloc}"


def _never_dialled(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not ac.is_public_address(hostname)


def _directories(data: Mapping[str, Any]) -> tuple[DirectoryConfig, ...]:
    """The ``[[directory]]`` tables (none by default: ADR-006, decision D1)."""
    raw = data.get("directory", [])
    if not isinstance(raw, list) or not all(isinstance(t, dict) for t in raw):
        msg = "directories are [[directory]] tables (an array of tables)"
        raise ConfigError(msg)
    out: list[DirectoryConfig] = []
    for table in raw:
        _closed(table, "directory", frozenset({"host", "keys", "url"}))
        host_raw = _typed(table, "host", str, "")
        try:
            host = ac.canonical_relay_host(host_raw)
        except ac.AgentConnectError:
            msg = f"directory.host {host_raw!r} is not a valid host"
            raise ConfigError(msg) from None
        texts = _typed(table, "keys", list, [])
        if not 1 <= len(texts) <= MAX_DIRECTORY_KEYS or not all(isinstance(k, str) for k in texts):
            msg = f"directory.keys for {host} must list one or two DK.pub values"
            raise ConfigError(msg)
        keys = tuple(k for k in (_b64url(t) for t in texts) if k is not None)
        if len(keys) != len(texts):
            msg = f"directory.keys for {host} must be unpadded base64url"
            raise ConfigError(msg)
        try:
            ac.check_directory_keys(host, list(keys))
        except ac.AgentConnectError as e:
            msg = f"directory.keys for {host}: {e}"
            raise ConfigError(msg) from None
        if any(d.host == host for d in out):
            msg = f"directory {host} is configured twice"
            raise ConfigError(msg)
        url = _directory_url(_typed(table, "url", str, "") or f"https://{host}", host)
        out.append(DirectoryConfig(host, keys, url))
    return tuple(out)


def _listing(data: Mapping[str, Any], environ: Mapping[str, str]) -> dict[str, Any]:
    table = _section(data, "listing")
    _closed(table, "listing", frozenset({"card_file", "token_file", "door_lifetime_secs"}))
    lifetime = _typed(table, "door_lifetime_secs", int, DEFAULT_DOOR_LIFETIME_SECS)
    if not MIN_DOOR_LIFETIME_SECS <= lifetime <= ac.MAX_DOOR_LIFETIME_SECS:
        msg = (
            f"listing.door_lifetime_secs must be {MIN_DOOR_LIFETIME_SECS}.."
            f"{ac.MAX_DOOR_LIFETIME_SECS} (SPEC 6.6.1)"
        )
        raise ConfigError(msg)
    home = _xdg(environ, "XDG_CONFIG_HOME", ".config")
    return {
        "listing_card_file": _path(table, "card_file") or home / "listing-card.json",
        "listing_token_file": _path(table, "token_file") or home / "listing-token.json",
        "listing_door_lifetime_secs": lifetime,
    }


#: ``[knock]`` integer keys: (default, lowest, highest). The highest is the
#: SPEC's limit, so a setting can only tighten it.
_KNOCK_LIMITS: dict[str, tuple[int, int, int]] = {
    "max_outgoing": (MAX_OUTGOING_KNOCKS, 1, MAX_OUTGOING_KNOCKS),
    "per_hour": (MAX_KNOCKS_PER_HOUR, 1, MAX_KNOCKS_PER_HOUR),
    "max_pending_per_door": (MAX_PENDING_KNOCKS_PER_DOOR, 1, MAX_PENDING_KNOCKS_PER_DOOR),
    "opened_per_door_per_minute": (
        MAX_KNOCKS_OPENED_PER_MINUTE,
        1,
        MAX_KNOCKS_OPENED_PER_MINUTE,
    ),
    "failures_per_sender_per_hour": (
        DEFAULT_KNOCK_FAILURES_PER_HOUR,
        1,
        MAX_KNOCK_FAILURES_PER_HOUR,
    ),
    "ledger_capacity": (
        ac.DEFAULT_LEDGER_CAPACITY,
        MIN_LEDGER_CAPACITY,
        ac.DEFAULT_LEDGER_CAPACITY,
    ),
}


def _knock(data: Mapping[str, Any]) -> dict[str, Any]:
    """``[knock]``. There is no key that approves a knock (SPEC 6.6.4)."""
    table = _section(data, "knock")
    _closed(table, "knock", frozenset({"agent_may_knock", "domain_check", *_KNOCK_LIMITS}))
    out: dict[str, Any] = {
        "knock_agent_may_knock": _typed(table, "agent_may_knock", bool, True),
        "knock_domain_check": _typed(table, "domain_check", bool, True),
    }
    for key, (default, lo, hi) in _KNOCK_LIMITS.items():
        value = _typed(table, key, int, default)
        if not lo <= value <= hi:
            msg = f"knock.{key} must be {lo}..{hi} (a local limit may only be lower)"
            raise ConfigError(msg)
        out[f"knock_{key}"] = value
    return out


def _groups(data: Mapping[str, Any]) -> dict[str, Any]:
    """``[groups]``: membership (docs/groups.md). Every key can only tighten."""
    table = _section(data, "groups")
    unknown = sorted(set(table) - {"leave_timeout_secs", "cleanup_departed_roles"})
    if unknown:
        msg = f"unknown key(s) in [groups]: {', '.join(unknown)}"
        raise ConfigError(msg)
    timeout = _typed(table, "leave_timeout_secs", int, MAX_LEAVE_TIMEOUT_SECS)
    if not MIN_LEAVE_TIMEOUT_SECS <= timeout <= MAX_LEAVE_TIMEOUT_SECS:
        msg = (
            f"groups.leave_timeout_secs must be {MIN_LEAVE_TIMEOUT_SECS}..{MAX_LEAVE_TIMEOUT_SECS}"
        )
        raise ConfigError(msg)
    return {
        "groups_leave_timeout_secs": timeout,
        "groups_cleanup_departed_roles": _typed(table, "cleanup_departed_roles", bool, True),
    }


def _sdk(data: Mapping[str, Any]) -> dict[str, Any]:
    timeout = _typed(_section(data, "sdk"), "handler_timeout_secs", int, 120)
    if not 1 <= timeout <= 3600:  # noqa: PLR2004
        msg = "sdk handler_timeout_secs must be 1..3600"
        raise ConfigError(msg)
    return {"sdk_handler_timeout": timeout}


def _resolve_relay(values: dict[str, Any]) -> None:
    """Validate the relay URL and fill in its host. Both stay empty when no
    relay is configured (``Config.require_relay`` rejects that where one is needed)."""
    if values["relay_url"]:
        values["relay_url"] = _check_relay_url(values["relay_url"])
    if not values["relay_host"]:
        # The URL's authority without any userinfo (SPEC 8.1.1).
        values["relay_host"] = urlsplit(values["relay_url"]).netloc.rpartition("@")[2]
    if values["relay_host"]:
        try:
            values["relay_host"] = ac.canonical_relay_host(values["relay_host"])
        except ac.AgentConnectError:
            msg = f"relay host {values['relay_host']!r} is not a valid host[:port]"
            raise ConfigError(msg) from None


def load_config(
    path: Path | None = None,
    environ: Mapping[str, str] = os.environ,
    *,
    use_file: bool = True,
    **overrides: Any,
) -> Config:
    """Read the TOML file (if present), then apply env and keyword overrides.
    ``use_file=False`` reads no file at all (the embedded SDK, which never
    picks up the separate daemon's ``config.toml`` by accident)."""
    if path is None:
        env_path = environ.get("AC_CONFIG", "")
        path = Path(env_path) if env_path else default_config_path(environ)
    data: dict[str, Any] = {}
    if use_file and path.exists():
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
    sse = _section(data, "sse")

    relay_url = environ.get("AC_RELAY_URL") or _typed(relay, "url", str, "")
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
        "sse_retention": _typed(sse, "retention_secs", int, 3600),
    }
    values.update(_a2a(data) | _isolation(data) | _policy(policy) | _sdk(data))
    values.update(_listing(data, environ), directories=_directories(data))
    values.update(_knock(data) | _groups(data))
    values.update(overrides)
    if not 60 <= values["sse_retention"] <= 604_800:  # noqa: PLR2004
        msg = "sse retention_secs must be 60..604800"
        raise ConfigError(msg)
    if not 1 <= values["webhook_timeout"] <= 3600:  # noqa: PLR2004
        msg = "webhook timeout_secs must be 1..3600"
        raise ConfigError(msg)
    if values["webhook_url"] is not None:
        check_callback_url(values["webhook_url"], values["webhook_allow_remote"])
    elif values["default_adapter"] == "webhook":
        msg = 'default_adapter "webhook" needs webhook.callback_url'
        raise ConfigError(msg)
    _resolve_relay(values)
    return Config(**values)
