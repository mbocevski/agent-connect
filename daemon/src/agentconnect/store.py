"""The daemon's own database, separate from the core's MLS store.

Per group it keeps metadata, policy, members (with the local, human-set
``verified`` flag), trust state, the adapter binding, peer Agent Cards and an
``out_of_sync`` flag. It also holds the durable queues:

* **outbox**: everything to send, kept until the relay answers it;
* **inbox**: every received ``(sender, msg_id)``; a delivery stays
  ``pending`` until the adapter accepts it. This is the dedup table that
  makes delivery at-least-once without double processing.

The file is a SQLCipher database (:class:`agentconnect_core.Database`,
ADR-003) under a key the core derives from the keystore's ``db_key``: every
page, the journal and the WAL are encrypted and authenticated, and there is
no unencrypted mode. On top of that, plaintext is kept only while it is
needed: an outbox row keeps just its ids once the relay has answered it, an
inbox row drops its delivery once the adapter has it, and a decided
JoinRequest drops its body. ``secure_delete`` overwrites what is removed.
"""

from __future__ import annotations

import json
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import agentconnect_core as ac
from agentconnect.keystore import private_file
from agentconnect.limits import TASK_UPDATE_KINDS

SqlParam = None | int | float | str | bytes
HANDLED_KEEP = 50_000  # ids an in-process agent finished with (Runtime.handled, the MCP host)
#: The owner's replay ledgers (SPEC 6.2 "Replays", 6.6.3 step 6): table and id column.
Ledger = Literal["knock", "join"]
LEDGERS: dict[str, tuple[str, str]] = {
    "knock": ("knock_ledger", "knock_id"),
    "join": ("join_ledger", "request_id"),
}


class _Cursor:
    """The result of one statement: its rows, or its change count."""

    def __init__(self, rows: list[tuple[Any, ...]], rowcount: int, lastrowid: int) -> None:
        self._rows, self.rowcount, self.lastrowid = rows, rowcount, lastrowid

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def __iter__(self) -> Any:
        return iter(self._rows)


class _Connection:
    """A small ``sqlite3``-shaped facade over the encrypted database."""

    def __init__(self, path: Path, key: bytes) -> None:
        self._db = ac.Database(str(path), key)

    def execute(self, sql: str, params: Sequence[SqlParam] = ()) -> _Cursor:
        values = list(params)
        if sql.lstrip().upper().startswith("SELECT"):
            return _Cursor(self._db.query(sql, values), -1, 0)
        changes, rowid = self._db.execute(sql, values)
        return _Cursor([], changes, rowid)

    def executescript(self, sql: str) -> None:
        self._db.execute_script(sql)

    def close(self) -> None:
        self._db.close()


DELIVERED = frozenset({"deliver", "deliver_as_context"})
# Kinds whose parts reach the agent: what an injection would ride in.
CONTENT_KINDS = frozenset({"a2a.message"}) | TASK_UPDATE_KINDS
# Delivered kinds that change the group's or a task's state.
STATE_KINDS = frozenset(
    {"control.close", "control.pause", "control.resume", "control.floor", "a2a.task_cancel"}
)
# What closes a hold: the human's approval, rejection or cancellation, or
# its expiry.
HOLD_OUTCOMES = frozenset({"approved", "rejected", "cancelled", "expired"})
# Refusals that say a sender tried what it may not, rather than sent too
# much: a human's or the owner's control, a control or card from an agent,
# content smuggled into a control, card or cancel, a part the group doesn't
# allow, a card that fails its pinned key.
SECURITY_DROPS = frozenset(
    {"not_human", "not_owner", "not_for_agents", "malformed", "part_kind", "bad_signature"}
)


def audit_class(group_id: str, decision: str, kind: str, reason: str) -> str:
    """The audit row class (:meth:`Store.audit_add`).

    * ``security``: in a group, content that reached the agent or left it
      (a delivered message or task update, a changed Agent Card), a hold, a
      hold's outcome, and the refusals in :data:`SECURITY_DROPS`. For a
      knock (no group yet), the human's approval or rejection.
    * ``decision``: a delivered control that changes state (close, pause,
      resume, floor) or task cancel, and a knock's hold and expiry.
    * ``routine``: the other deliveries (an unchanged card, a leave notice,
      capabilities).
    * ``drop``: every other refusal.
    """
    if decision == "drop":
        return "security" if group_id and reason in SECURITY_DROPS else "drop"
    if decision in HOLD_OUTCOMES:
        return "security" if group_id or decision != "expired" else "decision"
    if decision == "hold_for_approval":
        return "security" if group_id else "decision"
    if decision in DELIVERED:
        if kind in CONTENT_KINDS or (kind == "a2a.agent_card" and reason == "card_changed"):
            return "security"
        return "decision" if kind in STATE_KINDS else "routine"
    return "decision"


def _water_level(counts: list[int], target: int) -> list[int]:
    """How many rows to take from each of ``counts`` (largest first) so
    that ``target`` go in all, taken from the top: every count above some
    level comes down to it, and the remainder comes from the first ones."""
    level, taken = counts[0], 0
    while taken < target and level > 0:
        level -= 1
        taken = sum(max(0, n - level) for n in counts)
    cut = [max(0, n - level) for n in counts]
    extra = taken - target  # the last step took one too many from each of these
    for i in reversed(range(len(cut))):
        if extra <= 0:
            break
        if cut[i] > 0 and counts[i] - cut[i] == level:
            cut[i] -= 1
            extra -= 1
    return cut


def _scrubbed(payload: dict[str, Any]) -> dict[str, Any]:
    """What an answered outbox row keeps: its ids, never message content."""
    out: dict[str, Any] = {}
    env = payload.get("env")
    msg_id = payload.get("msg_id") or (env.get("msg_id") if isinstance(env, dict) else None)
    if msg_id is not None:
        out["msg_id"] = msg_id
    frame = payload.get("frame")
    if isinstance(frame, dict) and "t" in frame:
        out["t"] = frame["t"]
    return out


SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    policy TEXT NOT NULL DEFAULT '{}',
    adapter TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    out_of_sync INTEGER NOT NULL DEFAULT 0,
    out_of_sync_reason TEXT,
    epoch INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_own_commit_at INTEGER NOT NULL,
    msgs_since_commit INTEGER NOT NULL DEFAULT 0,
    hidden INTEGER NOT NULL DEFAULT 0,
    origin TEXT,
    adapters TEXT
);
CREATE TABLE IF NOT EXISTS members (
    group_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'member',
    verified INTEGER NOT NULL DEFAULT 0,
    instances TEXT NOT NULL DEFAULT '[]',
    verified_epoch INTEGER,
    PRIMARY KEY (group_id, identity)
);
CREATE TABLE IF NOT EXISTS agent_cards (
    group_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    card TEXT NOT NULL,
    PRIMARY KEY (group_id, identity)
);
CREATE TABLE IF NOT EXISTS invites (
    invite_id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    max_uses INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    replica INTEGER NOT NULL DEFAULT 0,
    instance TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    request_id TEXT PRIMARY KEY,
    invite_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    request TEXT NOT NULL,
    identity TEXT NOT NULL,
    display_name TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    kp_ref TEXT,
    instance_id TEXT
);
CREATE TABLE IF NOT EXISTS joins (
    invite_id TEXT PRIMARY KEY,
    meta TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    group_id TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    group_id TEXT,
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    group_id TEXT,
    delivery TEXT,
    state TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    hop INTEGER,
    UNIQUE (sender, msg_id)
);
CREATE TABLE IF NOT EXISTS inbox_acks (
    inbox_seq INTEGER NOT NULL,
    adapter TEXT NOT NULL,
    PRIMARY KEY (inbox_seq, adapter)
);
CREATE TABLE IF NOT EXISTS event_acks (
    event_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    PRIMARY KEY (event_id, adapter)
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    at INTEGER NOT NULL,
    event_id TEXT,
    notified INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS feed (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    group_id TEXT,
    payload TEXT NOT NULL,
    at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hops (
    group_id TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    hop INTEGER NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (group_id, msg_id)
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS floor_state (
    group_id TEXT PRIMARY KEY,
    holder TEXT,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS floor_writes (
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    counter INTEGER NOT NULL,
    sender TEXT NOT NULL,
    instance TEXT NOT NULL,
    kind TEXT NOT NULL,
    holder TEXT,
    PRIMARY KEY (group_id, epoch, counter, sender, instance)
);
CREATE TABLE IF NOT EXISTS group_safety (
    group_id TEXT PRIMARY KEY,
    settings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS held (
    hold_id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    instance TEXT NOT NULL DEFAULT '',
    msg_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    task_id TEXT,
    inbox_seq INTEGER,
    payload TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS task_decisions (
    group_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    task_id TEXT NOT NULL,
    state TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (group_id, sender, task_id)
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    class TEXT NOT NULL DEFAULT 'decision'
);
CREATE TABLE IF NOT EXISTS audit_suppressed (
    group_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    decision TEXT NOT NULL,
    count INTEGER NOT NULL,
    first_at INTEGER NOT NULL,
    last_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, sender, decision)
);
CREATE TABLE IF NOT EXISTS transcript_bytes (
    group_id TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transcript (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    direction TEXT NOT NULL,
    sender TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    inner TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS adapter_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    adapter TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE (adapter, event_id)
);
CREATE TABLE IF NOT EXISTS handled (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS listings (
    directory TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    content TEXT NOT NULL,
    token TEXT NOT NULL,
    token_expires_at INTEGER NOT NULL,
    owner_domain TEXT,
    seq INTEGER NOT NULL DEFAULT 0,
    max_signed_seq INTEGER NOT NULL DEFAULT 0,
    published BLOB,
    published_sha256 TEXT,
    published_at INTEGER,
    pending BLOB,
    pending_door TEXT,
    owner_state TEXT,
    next_renewal_at INTEGER,
    retry_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    failing_since INTEGER,
    stale_since INTEGER,
    last_error TEXT,
    token_warned INTEGER NOT NULL DEFAULT 0,
    restore_state TEXT,
    restore_renewal_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (directory, name)
);
CREATE TABLE IF NOT EXISTS doors (
    door_id TEXT PRIMARY KEY,
    directory TEXT NOT NULL,
    name TEXT NOT NULL,
    secret BLOB,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS knock_ledger (
    knock_id TEXT PRIMARY KEY,
    kp_ref TEXT NOT NULL,
    forget_after INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS knock_ledger_until ON knock_ledger (forget_after);
CREATE TABLE IF NOT EXISTS join_ledger (
    request_id TEXT PRIMARY KEY,
    invite_id TEXT NOT NULL,
    kp_ref TEXT NOT NULL,
    forget_after INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS join_ledger_until ON join_ledger (forget_after);
CREATE INDEX IF NOT EXISTS join_ledger_invite ON join_ledger (invite_id);
CREATE TABLE IF NOT EXISTS knock_requests (
    request_id TEXT PRIMARY KEY,
    knock_id TEXT NOT NULL UNIQUE,
    door_id TEXT NOT NULL,
    directory TEXT NOT NULL,
    name TEXT NOT NULL,
    identity TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    kp_ref TEXT NOT NULL,
    display_name TEXT,
    note TEXT,
    ts INTEGER NOT NULL,
    lapses_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    knock BLOB,
    status TEXT NOT NULL,
    group_id TEXT,
    purpose TEXT,
    decided_at INTEGER
);
CREATE INDEX IF NOT EXISTS knock_requests_status ON knock_requests (status, lapses_at);
CREATE TABLE IF NOT EXISTS knocks (
    knock_id TEXT PRIMARY KEY,
    directory TEXT NOT NULL,
    name TEXT NOT NULL,
    identity TEXT NOT NULL,
    door_id TEXT NOT NULL,
    listing BLOB NOT NULL,
    listing_sha256 TEXT NOT NULL,
    owner_domain TEXT,
    owner_state TEXT NOT NULL,
    display_name TEXT NOT NULL,
    secret BLOB,
    msg_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    gives_up_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    sent_once INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    reason TEXT,
    group_id TEXT,
    ended_at INTEGER
);
CREATE TABLE IF NOT EXISTS listed_peers (
    group_id TEXT PRIMARY KEY,
    identity TEXT NOT NULL,
    directory TEXT NOT NULL,
    name TEXT NOT NULL,
    owner_domain TEXT,
    owner_state TEXT NOT NULL,
    listing_sha256 TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS listings_seen (
    directory TEXT NOT NULL,
    name TEXT NOT NULL,
    hw_issued_at INTEGER,
    hw_identity TEXT,
    last BLOB,
    last_vouched_at INTEGER,
    last_negative_at INTEGER,
    last_negative TEXT,
    latest_at INTEGER,
    latest TEXT,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (directory, name)
);
CREATE TABLE IF NOT EXISTS sas_answered (
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    commitment BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch, commitment)
);
CREATE TABLE IF NOT EXISTS sas_sent (
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    peer TEXT NOT NULL,
    commitment BLOB NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (group_id, commitment)
);
CREATE TABLE IF NOT EXISTS sas_warnings (
    group_id TEXT NOT NULL,
    peer TEXT NOT NULL,
    count INTEGER NOT NULL,
    committers TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (group_id, peer)
);
"""

# The one-time reset of verified flags (SPEC 11.8): flags recorded under the
# group-wide code rest on a code an attacker in the middle could choose.
SAS_RUN_MARKER = ("schema/sas_run", "1")
SAS_RESET_NOTICE = "notice/sas_reset"

GROUP_COLUMNS = (
    "group_id",
    "name",
    "purpose",
    "policy",
    "adapter",
    "status",
    "out_of_sync",
    "out_of_sync_reason",
    "epoch",
    "created_at",
    "last_own_commit_at",
    "msgs_since_commit",
    "hidden",
    "origin",
    "adapters",
)


LISTING_COLUMNS = (
    "directory",
    "name",
    "state",
    "content",
    "token",
    "token_expires_at",
    "owner_domain",
    "seq",
    "max_signed_seq",
    "published",
    "published_sha256",
    "published_at",
    "pending",
    "pending_door",
    "owner_state",
    "next_renewal_at",
    "retry_at",
    "attempts",
    "failing_since",
    "stale_since",
    "last_error",
    "token_warned",
    "restore_state",
    "restore_renewal_at",
    "created_at",
    "updated_at",
)
_LISTING_COUNTERS = frozenset({"seq", "max_signed_seq", "attempts", "token_warned"})
# Without `secret`: only door_secrets() reads the private keys.
DOOR_COLUMNS = ("door_id", "directory", "name", "expires_at", "created_at", "state")
# Without `knock` (the welcome_secret and KeyPackage): only knock_secret() reads it.
KNOCK_REQUEST_COLUMNS = (
    "request_id",
    "knock_id",
    "door_id",
    "directory",
    "name",
    "identity",
    "mailbox_id",
    "kp_ref",
    "display_name",
    "note",
    "ts",
    "lapses_at",
    "received_at",
    "status",
    "group_id",
    "purpose",
    "decided_at",
)
# Without `secret`: only knock_secret() reads it.
KNOCK_COLUMNS = (
    "knock_id",
    "directory",
    "name",
    "identity",
    "door_id",
    "listing",
    "listing_sha256",
    "owner_domain",
    "owner_state",
    "display_name",
    "msg_id",
    "ts",
    "gives_up_at",
    "created_at",
    "sent_once",
    "status",
    "reason",
    "group_id",
    "ended_at",
)
LISTED_PEER_COLUMNS = (
    "group_id",
    "identity",
    "directory",
    "name",
    "owner_domain",
    "owner_state",
    "listing_sha256",
    "recorded_at",
)
SEEN_COLUMNS = (
    "directory",
    "name",
    "hw_issued_at",
    "hw_identity",
    "last",
    "last_vouched_at",
    "last_negative_at",
    "last_negative",
    "latest_at",
    "latest",
    "seen_at",
)
MAX_LISTINGS_SEEN = 1024


@dataclass
class GroupRow:
    group_id: str
    name: str
    purpose: str
    policy: dict[str, Any]
    adapter: str
    status: str
    out_of_sync: bool
    out_of_sync_reason: str | None
    epoch: int
    created_at: int
    last_own_commit_at: int
    msgs_since_commit: int
    # Not the agent's to see (an approved knock's group until the knocker is in).
    hidden: bool = False
    # Where the group came from, kept with it: {"kind": "knock", "directory", "name"}.
    origin: dict[str, Any] | None = None
    # The adapters the human pinned it to; None: the config's (daemon.adapters).
    # (``adapter``, the one adapter a group was bound to before, is no longer read.)
    adapters: list[str] | None = None


@dataclass
class MemberRow:
    identity: str
    display_name: str | None
    role: str
    verified: bool
    instances: list[dict[str, Any]]
    # The epoch whose short code the human compared when marking it verified;
    # None while unverified, and for a member verified by a daemon that didn't
    # record it (unknown: its new instances can't be told).
    verified_epoch: int | None = None


@dataclass
class OutboxRow:
    seq: int
    kind: str
    group_id: str | None
    payload: dict[str, Any]
    state: str


@dataclass
class InboxRow:
    seq: int
    sender: str
    msg_id: str
    group_id: str | None
    delivery: dict[str, Any] | None
    state: str


def _payload_group(payload: dict[str, Any]) -> str | None:
    group = payload.get("group")
    return str(group["id"]) if isinstance(group, dict) and "id" in group else None


_QUEUE_ROWS = (
    "SELECT seq, payload FROM adapter_events WHERE adapter = ? "
    "AND (? IS NULL OR group_id = ?) "
    "AND seq NOT IN (SELECT value FROM json_each(?)) "
    "AND (? = 0 OR addressed = 1) "
    "AND (? IS NULL OR seq < ?) "
)


class Store:
    """Synchronous access to the daemon database (one connection)."""

    def __init__(self, path: Path, db_key: bytes) -> None:
        """Open (or create, 0600) the encrypted database at ``path``.

        ``db_key`` is the keystore's 32-byte key; a wrong key, or a file that
        isn't an encrypted database, raises ``AgentConnectError``.
        """
        private_file(path)
        self._db = _Connection(path, db_key)
        # FULL: a committed transaction survives a power loss. With NORMAL in
        # WAL mode the last commits can roll back after their effects (frames
        # sent, acks) went out (ADR-004).
        self._db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        self._db.executescript(SCHEMA)
        self._depth = 0
        # Columns added after the first schema (development files).
        columns = {r[0] for r in self._all("SELECT name FROM pragma_table_info('events')")}
        for column, decl in (
            ("event_id", "TEXT"),
            ("notified", "INTEGER NOT NULL DEFAULT 0"),
            ("agent_seq", "INTEGER"),
        ):
            if column not in columns:
                self._db.execute(f"ALTER TABLE events ADD COLUMN {column} {decl}")
        group_columns = {r[0] for r in self._all("SELECT name FROM pragma_table_info('groups')")}
        # `adapters` (a pinned list, NULL: follow the config) replaced the one
        # adapter a group was bound to when it was created: every group from
        # before follows the config.
        for column, decl in (
            ("hidden", "INTEGER NOT NULL DEFAULT 0"),
            ("origin", "TEXT"),
            ("adapters", "TEXT"),
        ):
            if column not in group_columns:
                self._db.execute(f"ALTER TABLE groups ADD COLUMN {column} {decl}")
        member_columns = {r[0] for r in self._all("SELECT name FROM pragma_table_info('members')")}
        if "verified_epoch" not in member_columns:
            self._db.execute("ALTER TABLE members ADD COLUMN verified_epoch INTEGER")
        invite_columns = {r[0] for r in self._all("SELECT name FROM pragma_table_info('invites')")}
        if "replica" not in invite_columns:
            self._db.execute("ALTER TABLE invites ADD COLUMN replica INTEGER NOT NULL DEFAULT 0")
        if "instance" not in invite_columns:
            self._db.execute("ALTER TABLE invites ADD COLUMN instance TEXT")
        approval_columns = {
            r[0] for r in self._all("SELECT name FROM pragma_table_info('approvals')")
        }
        if "instance_id" not in approval_columns:
            self._db.execute("ALTER TABLE approvals ADD COLUMN instance_id TEXT")
        feed_columns = {r[0] for r in self._all("SELECT name FROM pragma_table_info('feed')")}
        if "at" not in feed_columns:
            self._db.execute("ALTER TABLE feed ADD COLUMN at INTEGER NOT NULL DEFAULT 0")
        # Handled-id keys were bare ids before they were namespaced
        # (["msg", group, sender, msg_id] / ["event", event_id]). An old
        # row can't be migrated (it lacks the group and the sender) and,
        # being peer-chosen, could equal a new key and hide a delivery; so
        # old rows are cleared, once. At worst one delivery reaches its
        # handler again, which at-least-once allows.
        if self.kv_get("schema/handled_keys") != "namespaced":
            with self.tx():
                self._db.execute("DELETE FROM handled WHERE key NOT LIKE '[%'")
                self.kv_set("schema/handled_keys", "namespaced")
        self._reset_verified_once()
        # The in-process adapter's event queue is read per group.
        event_columns = {
            r[0] for r in self._all("SELECT name FROM pragma_table_info('adapter_events')")
        }
        if "group_id" not in event_columns:
            self._db.execute("ALTER TABLE adapter_events ADD COLUMN group_id TEXT")
            self._db.execute(
                "UPDATE adapter_events SET group_id = json_extract(payload, '$.group.id')"
            )
        # The delivery queue finds the messages that address this agent.
        if "addressed" not in event_columns:
            self._db.execute(
                "ALTER TABLE adapter_events ADD COLUMN addressed INTEGER NOT NULL DEFAULT 0"
            )
            self._db.execute(
                "UPDATE adapter_events SET addressed = 1 "
                "WHERE json_extract(payload, '$.addressed_to_me') = 1"
            )
        self._db.executescript(
            "CREATE UNIQUE INDEX IF NOT EXISTS events_event_id ON events (event_id);"
            "CREATE UNIQUE INDEX IF NOT EXISTS events_agent_seq ON events (agent_seq);"
            "CREATE INDEX IF NOT EXISTS inbox_pending ON inbox (state, group_id, seq);"
            "CREATE INDEX IF NOT EXISTS adapter_events_group "
            "ON adapter_events (adapter, group_id, seq);"
            "CREATE INDEX IF NOT EXISTS adapter_events_addressed "
            "ON adapter_events (adapter, addressed, group_id, seq);"
            "CREATE INDEX IF NOT EXISTS audit_class ON audit (class, seq);"
            "CREATE INDEX IF NOT EXISTS audit_group ON audit (group_id, class, seq);"
            "CREATE INDEX IF NOT EXISTS audit_sender ON audit (group_id, sender, class, seq);"
            "CREATE INDEX IF NOT EXISTS audit_security ON audit (group_id, sender, decision, seq) "
            "WHERE class = 'security';"
            "CREATE INDEX IF NOT EXISTS transcript_group ON transcript (group_id, seq);"
            "CREATE INDEX IF NOT EXISTS transcript_sender ON transcript (group_id, sender, seq);"
        )

    def close(self) -> None:
        self._db.close()

    def _reset_verified_once(self) -> None:
        """SPEC 11.8: reset every verified flag once, in one transaction with
        its persisted marker, before anything is delivered."""
        if self.kv_get(SAS_RUN_MARKER[0]) == SAS_RUN_MARKER[1]:
            return
        with self.tx():
            cur = self._db.execute(
                "UPDATE members SET verified = 0, verified_epoch = NULL WHERE verified = 1"
            )
            if cur.rowcount > 0:
                self.kv_set(SAS_RESET_NOTICE, str(cur.rowcount))
            self.kv_set(*SAS_RUN_MARKER)

    @contextmanager
    def tx(self) -> Generator[_Connection]:
        """One transaction; nested calls are savepoints inside it. Rolled
        back on any exception, a simulated crash included."""
        depth = self._depth
        self._db.execute("BEGIN IMMEDIATE" if depth == 0 else f"SAVEPOINT sp{depth}")
        self._depth += 1
        try:
            yield self._db
        except BaseException:
            self._depth = depth
            if depth == 0:
                self._db.execute("ROLLBACK")
            else:
                self._db.execute(f"ROLLBACK TO sp{depth}")
                self._db.execute(f"RELEASE sp{depth}")
            raise
        self._depth = depth
        self._db.execute("COMMIT" if depth == 0 else f"RELEASE sp{depth}")

    def _one(self, sql: str, *args: Any) -> tuple[Any, ...] | None:
        return self._db.execute(sql, args).fetchone()

    def _all(self, sql: str, *args: Any) -> list[tuple[Any, ...]]:
        return self._db.execute(sql, args).fetchall()

    # -- key/value ----------------------------------------------------------

    def kv_get(self, key: str) -> str | None:
        row = self._one("SELECT value FROM kv WHERE key = ?", key)
        return None if row is None else str(row[0])

    def kv_set(self, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO kv (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def next_seq(self) -> int:
        """The next per-instance inner ``seq`` (SPEC §7.2), persisted."""
        with self.tx():
            n = int(self.kv_get("inner_seq") or "0") + 1
            self.kv_set("inner_seq", str(n))
        return n

    # -- groups -------------------------------------------------------------

    def add_group(self, row: GroupRow) -> None:
        values = [getattr(row, c) for c in GROUP_COLUMNS]
        values[3] = json.dumps(row.policy)
        values[6] = int(row.out_of_sync)
        values[12] = int(row.hidden)
        values[13] = None if row.origin is None else json.dumps(row.origin)
        values[14] = None if row.adapters is None else json.dumps(row.adapters)
        self._db.execute(
            f"INSERT OR REPLACE INTO groups ({', '.join(GROUP_COLUMNS)}) "  # noqa: S608
            f"VALUES ({', '.join('?' * len(GROUP_COLUMNS))})",
            values,
        )

    @staticmethod
    def _group(row: tuple[Any, ...]) -> GroupRow:
        d = dict(zip(GROUP_COLUMNS, row, strict=True))
        d["policy"] = json.loads(d["policy"])
        d["out_of_sync"] = bool(d["out_of_sync"])
        d["hidden"] = bool(d["hidden"])
        d["origin"] = None if d["origin"] is None else json.loads(d["origin"])
        d["adapters"] = None if d["adapters"] is None else json.loads(d["adapters"])
        return GroupRow(**d)

    def group(self, group_id: str) -> GroupRow | None:
        row = self._one(
            f"SELECT {', '.join(GROUP_COLUMNS)} FROM groups WHERE group_id = ?",  # noqa: S608
            group_id,
        )
        return None if row is None else self._group(row)

    def groups(self) -> list[GroupRow]:
        rows = self._all(f"SELECT {', '.join(GROUP_COLUMNS)} FROM groups ORDER BY created_at")  # noqa: S608
        return [self._group(r) for r in rows]

    def update_group(self, group_id: str, **fields: Any) -> None:
        if not fields:
            return
        for key in fields:
            if key not in GROUP_COLUMNS or key == "group_id":
                msg = f"unknown group column {key}"
                raise ValueError(msg)
        values = [
            json.dumps(v)
            if k == "policy" or (k in ("origin", "adapters") and v is not None)
            else int(v)
            if isinstance(v, bool)
            else v
            for k, v in fields.items()
        ]
        sets = ", ".join(f"{k} = ?" for k in fields)
        self._db.execute(
            f"UPDATE groups SET {sets} WHERE group_id = ?",  # noqa: S608
            (*values, group_id),
        )

    def delete_group(self, group_id: str) -> None:
        """Forget a group entirely: its row and its data (for a group nobody
        but this instance was ever in, such as a failed knock approval's)."""
        with self.tx():
            self.delete_group_data(group_id)
            self._db.execute("DELETE FROM groups WHERE group_id = ?", (group_id,))

    def bump_messages(self, group_id: str) -> None:
        self._db.execute(
            "UPDATE groups SET msgs_since_commit = msgs_since_commit + 1 WHERE group_id = ?",
            (group_id,),
        )

    # -- members ------------------------------------------------------------

    def members(self, group_id: str) -> list[MemberRow]:
        rows = self._all(
            "SELECT identity, display_name, role, verified, instances, verified_epoch "
            "FROM members WHERE group_id = ? ORDER BY identity",
            group_id,
        )
        return [
            MemberRow(r[0], r[1], r[2], bool(r[3]), json.loads(r[4]), r[5] if r[3] else None)
            for r in rows
        ]

    def set_members(
        self, group_id: str, members: dict[str, tuple[str, list[dict[str, Any]]]]
    ) -> tuple[set[str], set[str]]:
        """Replace the member set: ``{identity: (role, instances)}``.

        Keeps display names and verified flags of members that stay.
        Returns ``(joined, gone)`` identities.
        """
        with self.tx() as db:
            rows = db.execute("SELECT identity FROM members WHERE group_id = ?", (group_id,))
            before = {str(r[0]) for r in rows}
            gone = before - members.keys()
            for identity in gone:
                db.execute(
                    "DELETE FROM members WHERE group_id = ? AND identity = ?", (group_id, identity)
                )
            for identity, (role, instances) in members.items():
                db.execute(
                    "INSERT INTO members (group_id, identity, role, instances) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(group_id, identity) DO UPDATE SET role = excluded.role, "
                    "instances = excluded.instances",
                    (group_id, identity, role, json.dumps(instances)),
                )
        return set(members) - before, gone

    def set_display_name(self, group_id: str, identity: str, name: str) -> None:
        self._db.execute(
            "UPDATE members SET display_name = ? WHERE group_id = ? AND identity = ?",
            (name, group_id, identity),
        )

    def set_verified(
        self, group_id: str, identity: str, verified: bool, epoch: int | None = None
    ) -> bool:
        """Set a member's verified flag. ``epoch`` is the epoch the human
        verified at: the member's instances that join after it are new
        since the verification."""
        cur = self._db.execute(
            "UPDATE members SET verified = ?, verified_epoch = ? "
            "WHERE group_id = ? AND identity = ?",
            (int(verified), epoch if verified else None, group_id, identity),
        )
        return cur.rowcount == 1

    # -- SAS runs (agentconnect.runtime.sas) ------------------------------------

    def sas_answered(self, group_id: str, epoch: int, commitment: bytes) -> bool:
        """Whether this instance answered ``commitment`` in ``epoch`` (SPEC 11.3)."""
        row = self._one(
            "SELECT 1 FROM sas_answered WHERE group_id = ? AND epoch = ? AND commitment = ?",
            group_id,
            epoch,
            commitment,
        )
        return row is not None

    def add_sas_answered(self, group_id: str, epoch: int, commitment: bytes) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO sas_answered (group_id, epoch, commitment) VALUES (?, ?, ?)",
            (group_id, epoch, commitment),
        )

    def forget_sas_answered(self, group_id: str, epoch: int) -> None:
        """Answered commitments are kept for the rest of their epoch only."""
        self._db.execute(
            "DELETE FROM sas_answered WHERE group_id = ? AND epoch < ?", (group_id, epoch)
        )

    def add_sas_sent(
        self, group_id: str, epoch: int, peer: str, commitment: bytes, at: int
    ) -> None:
        """This instance's commitment, unrevealed so far: a restart cancels
        it (SPEC 11.3)."""
        self._db.execute(
            "INSERT OR REPLACE INTO sas_sent (group_id, epoch, peer, commitment, at) "
            "VALUES (?, ?, ?, ?, ?)",
            (group_id, epoch, peer, commitment, at),
        )

    def forget_sas_sent(self, group_id: str, commitment: bytes) -> None:
        self._db.execute(
            "DELETE FROM sas_sent WHERE group_id = ? AND commitment = ?", (group_id, commitment)
        )

    def forget_sas_sent_before(self, group_id: str, epoch: int) -> None:
        self._db.execute("DELETE FROM sas_sent WHERE group_id = ? AND epoch < ?", (group_id, epoch))

    def forget_all_sas_sent(self) -> None:
        self._db.execute("DELETE FROM sas_sent")

    def sas_sent(self) -> list[dict[str, Any]]:
        rows = self._all("SELECT group_id, epoch, peer, commitment, at FROM sas_sent")
        return [
            {"group_id": r[0], "epoch": r[1], "peer": r[2], "commitment": bytes(r[3]), "at": r[4]}
            for r in rows
        ]

    def sas_warnings(self, group_id: str, peer: str) -> tuple[int, list[str]]:
        """The warning count with ``peer`` and the members whose commits
        ended those runs (SPEC 11.3)."""
        row = self._one(
            "SELECT count, committers FROM sas_warnings WHERE group_id = ? AND peer = ?",
            group_id,
            peer,
        )
        if row is None:
            return 0, []
        return int(row[0]), [str(c) for c in json.loads(row[1])]

    def set_sas_warnings(self, group_id: str, peer: str, count: int, committers: list[str]) -> None:
        if count <= 0:
            self._db.execute(
                "DELETE FROM sas_warnings WHERE group_id = ? AND peer = ?", (group_id, peer)
            )
            return
        self._db.execute(
            "INSERT INTO sas_warnings (group_id, peer, count, committers) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(group_id, peer) DO UPDATE SET count = excluded.count, "
            "committers = excluded.committers",
            (group_id, peer, count, json.dumps(committers[-16:])),
        )

    def drop_queued_sas(self) -> int:
        """Queued ceremony messages of runs a restart ended: never sent."""
        rows = self._all(
            "SELECT seq FROM outbox WHERE state = 'queued' AND kind = 'app' "
            "AND json_extract(payload, '$.sas') IS NOT NULL"
        )
        for (seq,) in rows:
            self.update_outbox(int(seq), state="failed")
        return len(rows)

    def put_card(self, group_id: str, identity: str, card: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO agent_cards (group_id, identity, card) VALUES (?, ?, ?)",
            (group_id, identity, json.dumps(card)),
        )

    def cards(self, group_id: str) -> dict[str, dict[str, Any]]:
        rows = self._all("SELECT identity, card FROM agent_cards WHERE group_id = ?", group_id)
        return {r[0]: json.loads(r[1]) for r in rows}

    # -- floor control (agentconnect.runtime.floor) --------------------------------

    def floor(self, group_id: str) -> tuple[str | None, dict[str, Any]] | None:
        """The group's floor holder and register state (``None``: no row)."""
        row = self._one("SELECT holder, state FROM floor_state WHERE group_id = ?", group_id)
        return None if row is None else (row[0], dict(json.loads(row[1])))

    def set_floor(self, group_id: str, holder: str | None, state: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO floor_state (group_id, holder, state) VALUES (?, ?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET holder = excluded.holder, state = excluded.state",
            (group_id, holder, json.dumps(state, sort_keys=True)),
        )

    def floor_writes(self, group_id: str) -> list[tuple[int, int, str, str, str, str | None]]:
        """The writes kept for the group's floor register, in key order:
        ``(epoch, counter, sender, instance, kind, holder)``."""
        rows = self._all(
            "SELECT epoch, counter, sender, instance, kind, holder FROM floor_writes "
            "WHERE group_id = ?",
            group_id,
        )
        return sorted((int(r[0]), int(r[1]), str(r[2]), str(r[3]), str(r[4]), r[5]) for r in rows)

    def add_floor_write(
        self,
        group_id: str,
        key: tuple[int, int, str, str],
        kind: str,
        holder: str | None,
    ) -> bool:
        """Keep a write; ``False`` if one with that key is kept already."""
        cur = self._db.execute(
            "INSERT OR IGNORE INTO floor_writes "
            "(group_id, epoch, counter, sender, instance, kind, holder) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (group_id, *key, kind, holder),
        )
        return cur.rowcount == 1

    def delete_floor_write(self, group_id: str, key: tuple[int, int, str, str]) -> None:
        self._db.execute(
            "DELETE FROM floor_writes WHERE group_id = ? AND epoch = ? AND counter = ? "
            "AND sender = ? AND instance = ?",
            (group_id, *key),
        )

    def drop_floor_writes(self, group_id: str, before_epoch: int) -> None:
        self._db.execute(
            "DELETE FROM floor_writes WHERE group_id = ? AND epoch < ?", (group_id, before_epoch)
        )

    def delete_group_data(self, group_id: str) -> None:
        """Forget a group's members, cards and safety settings; its held
        messages are dropped. Audit rows and transcript entries stay until
        their retention ends."""
        with self.tx() as db:
            for table in (
                "members",
                "agent_cards",
                "group_safety",
                "task_decisions",
                "listed_peers",
                "floor_state",
                "floor_writes",
                "sas_answered",
                "sas_sent",
                "sas_warnings",
            ):
                db.execute(f"DELETE FROM {table} WHERE group_id = ?", (group_id,))  # noqa: S608
            db.execute(
                "UPDATE inbox SET state = 'dropped', delivery = NULL "
                "WHERE group_id = ? AND state = 'held'",
                (group_id,),
            )
            db.execute(
                "UPDATE held SET status = 'dropped', payload = NULL "
                "WHERE group_id = ? AND status = 'pending'",
                (group_id,),
            )

    # -- safety policy (agentconnect.policy) ----------------------------------

    def safety_overrides(self, group_id: str) -> dict[str, Any]:
        """A group's policy overrides (``{}`` when it has none)."""
        row = self._one("SELECT settings FROM group_safety WHERE group_id = ?", group_id)
        return {} if row is None else dict(json.loads(row[0]))

    def set_safety_overrides(self, group_id: str, overrides: dict[str, Any]) -> None:
        if not overrides:
            self._db.execute("DELETE FROM group_safety WHERE group_id = ?", (group_id,))
            return
        self._db.execute(
            "INSERT INTO group_safety (group_id, settings) VALUES (?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET settings = excluded.settings",
            (group_id, json.dumps(overrides, sort_keys=True)),
        )

    def add_held(self, row: dict[str, Any]) -> None:
        """A message waiting for the human's approval. ``payload`` (outbound
        only) is the queued send; an inbound one waits in its inbox row."""
        payload = row.get("payload")
        self._db.execute(
            "INSERT OR IGNORE INTO held (hold_id, group_id, direction, sender, instance, msg_id, "
            "kind, size, task_id, inbox_seq, payload, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["hold_id"],
                row["group_id"],
                row["direction"],
                row["sender"],
                row.get("instance", ""),
                row["msg_id"],
                row["kind"],
                row["size"],
                row.get("task_id"),
                row.get("inbox_seq"),
                None if payload is None else json.dumps(payload),
                row["created_at"],
                row["expires_at"],
            ),
        )

    _HELD_COLUMNS = (
        "hold_id",
        "group_id",
        "direction",
        "sender",
        "instance",
        "msg_id",
        "kind",
        "size",
        "task_id",
        "inbox_seq",
        "payload",
        "created_at",
        "expires_at",
        "status",
    )

    def _held(self, row: tuple[Any, ...]) -> dict[str, Any]:
        d = dict(zip(self._HELD_COLUMNS, row, strict=True))
        d["payload"] = None if d["payload"] is None else json.loads(d["payload"])
        return d

    def held(self, hold_id: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(self._HELD_COLUMNS)} FROM held WHERE hold_id = ?",  # noqa: S608
            hold_id,
        )
        return None if row is None else self._held(row)

    def held_items(self, status: str = "pending") -> list[dict[str, Any]]:
        rows = self._all(
            f"SELECT {', '.join(self._HELD_COLUMNS)} FROM held "  # noqa: S608
            "WHERE status = ? ORDER BY created_at, hold_id",
            status,
        )
        return [self._held(r) for r in rows]

    def set_held_status(self, hold_id: str, status: str) -> bool:
        """Decide a pending held item; its payload (plaintext) is no longer
        needed. False if it was already decided (by a concurrent caller)."""
        cur = self._db.execute(
            "UPDATE held SET status = ?, payload = NULL WHERE hold_id = ? AND status = 'pending'",
            (status, hold_id),
        )
        return cur.rowcount == 1

    def held_load(
        self, group_id: str, direction: str, instance: str, identity: str
    ) -> tuple[int, int, int, int, int, int]:
        """Pending holds of a group in one direction: how many, how many from
        ``instance``, how many from ``identity`` (all its instances), their
        bytes, how many identities have one, and ``identity``'s bytes."""
        row = self._one(
            "SELECT COUNT(*), COALESCE(SUM(instance = ?), 0), COALESCE(SUM(sender = ?), 0), "
            "COALESCE(SUM(size), 0), COUNT(DISTINCT sender), "
            "COALESCE(SUM(CASE WHEN sender = ? THEN size ELSE 0 END), 0) FROM held "
            "WHERE group_id = ? AND direction = ? AND status = 'pending'",
            instance,
            identity,
            identity,
            group_id,
            direction,
        )
        if row is None:
            return 0, 0, 0, 0, 0, 0
        return int(row[0]), int(row[1]), int(row[2]), int(row[3]), int(row[4]), int(row[5])

    def task_decision(self, group_id: str, sender: str, task_id: str) -> tuple[str, int] | None:
        """A task's state (``pending``, ``approved``, ``rejected``) and when it
        was set, or None."""
        row = self._one(
            "SELECT state, at FROM task_decisions WHERE group_id = ? AND sender = ? "
            "AND task_id = ?",
            group_id,
            sender,
            task_id,
        )
        return None if row is None else (str(row[0]), int(row[1]))

    def forget_task(self, group_id: str, sender: str, task_id: str) -> None:
        self._db.execute(
            "DELETE FROM task_decisions WHERE group_id = ? AND sender = ? AND task_id = ?",
            (group_id, sender, task_id),
        )

    def task_state(self, group_id: str, sender: str, task_id: str) -> str | None:
        """``pending``, ``approved`` or ``rejected``: the human's decision on a
        task's first update (held with require_approval), or None."""
        row = self._one(
            "SELECT state FROM task_decisions WHERE group_id = ? AND sender = ? AND task_id = ?",
            group_id,
            sender,
            task_id,
        )
        return None if row is None else str(row[0])

    def set_task_state(
        self, group_id: str, sender: str, task_id: str, state: str, now: int
    ) -> None:
        self._db.execute(
            "INSERT INTO task_decisions (group_id, sender, task_id, state, at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(group_id, sender, task_id) "
            "DO UPDATE SET state = excluded.state, at = excluded.at",
            (group_id, sender, task_id, state, now),
        )

    def task_states_purge(self, before: int) -> None:
        """Forget decided tasks not touched since ``before``."""
        self._db.execute(
            "DELETE FROM task_decisions WHERE at < ? AND state != 'pending'", (before,)
        )

    def audit_add(  # noqa: PLR0913
        self,
        group_id: str,
        *,
        at: int,
        direction: str,
        sender: str,
        msg_id: str,
        kind: str,
        size: int,
        decision: str,
        reason: str,
        keep: int | None = None,
        keep_group: int | None = None,
        keep_sender: int | None = None,
    ) -> None:
        """One audit row, in one of four classes that never evict each other
        (:func:`audit_class`).

        * ``security`` rows are trimmed by age (:meth:`audit_purge`), and
          only a sender's own rows trim its own: of a decision it keeps
          ``keep_sender`` per group, the oldest half and a rolling newest
          half (:meth:`_trim_security`), and counts the rows between in
          ``audit_suppressed``. So no flood erases a sender's earliest
          record, nobody else's rows push out any of its own, and its
          latest rows stay visible.
        * ``drop`` and ``routine`` rows keep the newest ``keep_sender`` of
          their class from a sender in a group.
        * ``drop``, ``routine`` and ``decision`` rows each keep
          ``keep_group`` in a group (:meth:`_trim_audit_fairly`) and ``keep``
          in all.
        """
        row_class = audit_class(group_id, decision, kind, reason)
        self._db.execute(
            "INSERT INTO audit (group_id, at, direction, sender, msg_id, kind, size, decision, "
            "reason, class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (group_id, at, direction, sender, msg_id, kind, size, decision, reason, row_class),
        )
        if row_class == "security":
            if keep_sender is not None:
                self._trim_security(group_id, sender, decision, keep_sender)
            return
        if keep_sender is not None and row_class != "decision":
            self._trim_audit(
                "group_id = ? AND sender = ? AND class = ?",
                (group_id, sender, row_class),
                keep_sender,
            )
        if keep_group is not None:
            self._trim_audit_fairly(group_id, row_class, keep_group)
        if keep is not None:
            self._trim_audit("class = ?", (row_class,), keep)

    def _trim_security(self, group_id: str, sender: str, decision: str, keep: int) -> None:
        """Past ``keep`` security rows of one decision from a sender in a
        group, delete the oldest row after its oldest half (which stays until
        it ages out) and count it in ``audit_suppressed``, so the newest
        half rolls. Two indexed walks of at most ``keep`` rows."""
        where = "group_id = ? AND sender = ? AND decision = ? AND class = 'security'"
        over = self._one(
            f"SELECT 1 FROM audit WHERE {where} LIMIT 1 OFFSET ?",  # noqa: S608
            group_id,
            sender,
            decision,
            keep,
        )
        if over is None:
            return
        gap = self._one(
            f"SELECT seq, at FROM audit WHERE {where} ORDER BY seq LIMIT 1 OFFSET ?",  # noqa: S608
            group_id,
            sender,
            decision,
            (keep + 1) // 2,
        )
        if gap is None:
            return
        self._db.execute("DELETE FROM audit WHERE seq = ?", (gap[0],))
        self._db.execute(
            "INSERT INTO audit_suppressed (group_id, sender, decision, count, first_at, "
            "last_at) VALUES (?, ?, ?, 1, ?, ?) "
            "ON CONFLICT(group_id, sender, decision) "
            "DO UPDATE SET count = count + 1, first_at = MIN(first_at, excluded.first_at), "
            "last_at = MAX(last_at, excluded.last_at)",
            (group_id, sender, decision, gap[1], gap[1]),
        )

    def _trim_audit_fairly(self, group_id: str, row_class: str, keep: int) -> None:
        """Keep at most ``keep`` of a group's rows of a class. Past that, the
        rows go from the top: the senders holding the most give way down to
        a common level, oldest first, and at a tie the sender whose oldest
        row is oldest goes first. It trims 1% below ``keep`` at once, so the
        senders are counted once per hundred rows at the cap, not per row."""
        row = self._one(
            "SELECT COUNT(*) FROM audit WHERE group_id = ? AND class = ?", group_id, row_class
        )
        total = 0 if row is None else int(row[0])
        if total <= keep:
            return
        target = total - keep + keep // 100
        counts = [
            (str(r[0]), int(r[1]))
            for r in self._all(
                "SELECT sender, COUNT(*) AS n FROM audit WHERE group_id = ? AND class = ? "
                "GROUP BY sender ORDER BY n DESC, MIN(seq)",
                group_id,
                row_class,
            )
        ]
        cut = _water_level([n for _, n in counts], target)
        for (sender, _), n in zip(counts, cut, strict=True):
            if n > 0:
                self._db.execute(
                    "DELETE FROM audit WHERE seq IN (SELECT seq FROM audit WHERE group_id = ? "
                    "AND sender = ? AND class = ? ORDER BY seq LIMIT ?)",
                    (group_id, sender, row_class, n),
                )

    def _trim_audit(self, where: str, args: tuple[str, ...], keep: int) -> None:
        """Delete the audit rows matching ``where`` beyond the newest ``keep``
        (an indexed walk, not a table scan)."""
        edge = self._one(
            f"SELECT seq FROM audit WHERE {where} ORDER BY seq DESC LIMIT 1 OFFSET ?",  # noqa: S608
            *args,
            keep,
        )
        if edge is not None:
            self._db.execute(f"DELETE FROM audit WHERE {where} AND seq <= ?", (*args, edge[0]))  # noqa: S608

    _AUDIT_COLUMNS = (
        "seq",
        "group_id",
        "at",
        "direction",
        "sender",
        "msg_id",
        "kind",
        "size",
        "decision",
        "reason",
    )

    def audit(
        self, group_id: str | None = None, after: int = 0, limit: int = 200
    ) -> list[dict[str, Any]]:
        rows = self._all(
            f"SELECT {', '.join(self._AUDIT_COLUMNS)} FROM audit WHERE seq > ? "  # noqa: S608
            "AND (? IS NULL OR group_id = ?) ORDER BY seq LIMIT ?",
            after,
            group_id,
            group_id,
            limit,
        )
        return [dict(zip(self._AUDIT_COLUMNS, r, strict=True)) for r in rows]

    def audit_suppressed(self, group_id: str | None = None) -> list[dict[str, Any]]:
        """Security rows that fell between a sender's oldest and newest half
        of its share (:meth:`_trim_security`), counted instead of kept: per
        group, sender and decision."""
        rows = self._all(
            "SELECT group_id, sender, decision, count, first_at, last_at FROM audit_suppressed "
            "WHERE (? IS NULL OR group_id = ?) ORDER BY group_id, sender, decision",
            group_id,
            group_id,
        )
        keys = ("group_id", "sender", "decision", "count", "first_at", "last_at")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def audit_purge(self, before: int, keep: int) -> None:
        """Delete audit rows and suppressed counts older than ``before`` and,
        in each class but ``security``, all but the newest ``keep`` (one
        class never pushes out another, and volume never trims security
        rows)."""
        self._db.execute("DELETE FROM audit WHERE at < ?", (before,))
        self._db.execute("DELETE FROM audit_suppressed WHERE last_at < ?", (before,))
        for (row_class,) in self._all("SELECT DISTINCT class FROM audit"):
            if row_class != "security":
                self._trim_audit("class = ?", (str(row_class),), keep)

    def transcript_add(  # noqa: PLR0913
        self,
        group_id: str,
        *,
        at: int,
        direction: str,
        sender: str,
        msg_id: str,
        kind: str,
        inner: dict[str, Any],
        max_rows: int,
        max_sender_rows: int,
        max_group_bytes: int,
        max_bytes: int,
    ) -> None:
        """One transcript entry. Its sender keeps its newest ``max_sender_rows``
        in the group, the group its newest ``max_rows`` and ``max_group_bytes``,
        and over ``max_bytes`` for all groups the group holding the most gives
        way first, oldest entries first: one sender can't flush the record of
        the others. Every trim walks an index, and the byte totals are kept
        as they change (``transcript_bytes``), never summed over the table."""
        text = json.dumps(inner, sort_keys=True)
        self._db.execute(
            "INSERT INTO transcript (group_id, at, direction, sender, msg_id, kind, inner, size) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (group_id, at, direction, sender, msg_id, kind, text, len(text)),
        )
        self._add_transcript_bytes(group_id, len(text))
        self._trim_transcript(
            "group_id = ? AND sender = ?", (group_id, sender), max_sender_rows, group_id
        )
        self._trim_transcript("group_id = ?", (group_id,), max_rows, group_id)
        while self.transcript_bytes(group_id) > max_group_bytes:
            self._drop_oldest_transcript(group_id)
        while self.transcript_bytes() > max_bytes:
            biggest = self._one(
                "SELECT group_id FROM transcript_bytes ORDER BY bytes DESC, group_id LIMIT 1"
            )
            if biggest is None:
                break
            self._drop_oldest_transcript(str(biggest[0]))

    def _add_transcript_bytes(self, group_id: str, delta: int) -> None:
        self._db.execute(
            "INSERT INTO transcript_bytes (group_id, bytes) VALUES (?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET bytes = bytes + excluded.bytes",
            (group_id, delta),
        )
        self._db.execute("DELETE FROM transcript_bytes WHERE bytes <= 0")

    def _trim_transcript(self, where: str, args: tuple[str, ...], keep: int, group_id: str) -> None:
        """Delete the rows matching ``where`` beyond the newest ``keep``."""
        edge = self._one(
            f"SELECT seq FROM transcript WHERE {where} ORDER BY seq DESC LIMIT 1 OFFSET ?",  # noqa: S608
            *args,
            keep,
        )
        if edge is None:
            return
        cond = f"{where} AND seq <= ?"
        total = f"SELECT COALESCE(SUM(size), 0) FROM transcript WHERE {cond}"  # noqa: S608
        gone = self._one(total, *args, edge[0])
        self._db.execute(f"DELETE FROM transcript WHERE {cond}", (*args, edge[0]))  # noqa: S608
        self._add_transcript_bytes(group_id, -int(gone[0]) if gone is not None else 0)

    def _drop_oldest_transcript(self, group_id: str) -> None:
        row = self._one(
            "SELECT seq, size FROM transcript WHERE group_id = ? ORDER BY seq LIMIT 1", group_id
        )
        if row is None:
            self._db.execute("DELETE FROM transcript_bytes WHERE group_id = ?", (group_id,))
            return
        self._db.execute("DELETE FROM transcript WHERE seq = ?", (row[0],))
        self._add_transcript_bytes(group_id, -int(row[1]))

    def transcript_bytes(self, group_id: str | None = None) -> int:
        """Bytes kept in one group's transcript, or in all of them."""
        if group_id is None:
            row = self._one("SELECT COALESCE(SUM(bytes), 0) FROM transcript_bytes")
        else:
            row = self._one("SELECT bytes FROM transcript_bytes WHERE group_id = ?", group_id)
        return 0 if row is None else int(row[0])

    def transcript(self, group_id: str, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT seq, group_id, at, direction, sender, msg_id, kind, inner FROM transcript "
            "WHERE group_id = ? AND seq > ? ORDER BY seq LIMIT ?",
            group_id,
            after,
            limit,
        )
        keys = ("seq", "group_id", "at", "direction", "sender", "msg_id", "kind")
        return [dict(zip(keys, r[:7], strict=True)) | {"inner": json.loads(r[7])} for r in rows]

    def transcript_groups(self) -> list[str]:
        return [str(r[0]) for r in self._all("SELECT DISTINCT group_id FROM transcript")]

    def transcript_purge(self, group_id: str, before: int) -> None:
        gone = self._one(
            "SELECT COALESCE(SUM(size), 0) FROM transcript WHERE group_id = ? AND at < ?",
            group_id,
            before,
        )
        self._db.execute("DELETE FROM transcript WHERE group_id = ? AND at < ?", (group_id, before))
        self._add_transcript_bytes(group_id, -int(gone[0]) if gone is not None else 0)

    # -- listings and doors (the owner's side of discovery) -----------------

    def listing(self, directory: str, name: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(LISTING_COLUMNS)} FROM listings "  # noqa: S608
            "WHERE directory = ? AND name = ?",
            directory,
            name,
        )
        return None if row is None else dict(zip(LISTING_COLUMNS, row, strict=True))

    def listings(self) -> list[dict[str, Any]]:
        """Every listing row, the most recently changed first. Rows are
        never deleted: ``max_signed_seq`` must outlive a withdrawal."""
        rows = self._all(
            f"SELECT {', '.join(LISTING_COLUMNS)} FROM listings "  # noqa: S608
            "ORDER BY updated_at DESC, created_at DESC"
        )
        return [dict(zip(LISTING_COLUMNS, r, strict=True)) for r in rows]

    def put_listing(self, row: dict[str, Any]) -> None:
        """Insert or replace a whole listing row (missing counters are 0)."""
        self._db.execute(
            f"INSERT OR REPLACE INTO listings ({', '.join(LISTING_COLUMNS)}) "  # noqa: S608
            f"VALUES ({', '.join('?' for _ in LISTING_COLUMNS)})",
            [row.get(c, 0 if c in _LISTING_COUNTERS else None) for c in LISTING_COLUMNS],
        )

    def update_listing(self, directory: str, name: str, **fields: Any) -> None:
        for key in fields:
            if key not in LISTING_COLUMNS or key in ("directory", "name"):
                msg = f"unknown listing column {key}"
                raise ValueError(msg)
        sets = ", ".join(f"{k} = ?" for k in fields)
        self._db.execute(
            f"UPDATE listings SET {sets} WHERE directory = ? AND name = ?",  # noqa: S608
            (*fields.values(), directory, name),
        )

    def add_door(  # noqa: PLR0913
        self,
        *,
        door_id: str,
        directory: str,
        name: str,
        secret: bytes,
        expires_at: int,
        now: int,
    ) -> None:
        """A new door, ``registering`` until the relay has it."""
        self._db.execute(
            "INSERT INTO doors (door_id, directory, name, secret, expires_at, created_at, state) "
            "VALUES (?, ?, ?, ?, ?, ?, 'registering')",
            (door_id, directory, name, secret, expires_at, now),
        )

    def doors(self, directory: str | None = None, name: str | None = None) -> list[dict[str, Any]]:
        """Doors (of one listing, or all), the oldest first, without their
        private keys (see :meth:`door_secrets`)."""
        rows = self._all(
            f"SELECT {', '.join(DOOR_COLUMNS)} FROM doors "  # noqa: S608
            "WHERE (? IS NULL OR directory = ?) AND (? IS NULL OR name = ?) "
            "ORDER BY created_at, door_id",
            directory,
            directory,
            name,
            name,
        )
        return [dict(zip(DOOR_COLUMNS, r, strict=True)) for r in rows]

    def door_secrets(self) -> list[tuple[str, bytes]]:
        """Every door's private key that is still kept (encrypted at rest
        with the rest of this database), for loading them once at start."""
        rows = self._all("SELECT door_id, secret FROM doors WHERE secret IS NOT NULL")
        return [(str(r[0]), bytes(r[1])) for r in rows]

    def drop_door_secret(self, door_id: str, state: str) -> None:
        """Delete a door's private key and move it to ``state``."""
        self._db.execute(
            "UPDATE doors SET secret = NULL, state = ? WHERE door_id = ?", (state, door_id)
        )

    def update_door(self, door_id: str, **fields: Any) -> None:
        for key in fields:
            if key not in DOOR_COLUMNS or key == "door_id":
                msg = f"unknown door column {key}"
                raise ValueError(msg)
        sets = ", ".join(f"{k} = ?" for k in fields)
        self._db.execute(
            f"UPDATE doors SET {sets} WHERE door_id = ?",  # noqa: S608
            (*fields.values(), door_id),
        )

    def delete_door(self, door_id: str) -> None:
        self._db.execute("DELETE FROM doors WHERE door_id = ?", (door_id,))

    # -- knocks: the owner's ledger and approvals, the knocker's knocks -------

    def ledger_add(
        self,
        entry_id: str,
        kp_ref: str,
        forget_after: int,
        *,
        ledger: Ledger = "knock",
        invite_id: str | None = None,
    ) -> None:
        """Remember a request that passed the owner's checks (SPEC 6.2
        "Replays" for joins, with its ``invite_id``; 6.6.3 step 6 for
        knocks), in the transaction that records what happened to it. A row
        for the same id can only be one the ledger already forgot (a live one
        makes the request a replay), so it is replaced whole."""
        if ledger == "join":
            self._db.execute(
                "INSERT INTO join_ledger (request_id, invite_id, kp_ref, forget_after) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(request_id) DO UPDATE SET "
                "invite_id = excluded.invite_id, kp_ref = excluded.kp_ref, "
                "forget_after = excluded.forget_after",
                (entry_id, invite_id or "", kp_ref, forget_after),
            )
            return
        self._db.execute(
            "INSERT INTO knock_ledger (knock_id, kp_ref, forget_after) VALUES (?, ?, ?) "
            "ON CONFLICT(knock_id) DO UPDATE SET "
            "kp_ref = excluded.kp_ref, forget_after = excluded.forget_after",
            (entry_id, kp_ref, forget_after),
        )

    def join_ledger_count(self, invite_id: str) -> int:
        """How many join requests of this invite the ledger remembers that
        are not being added or added: those are in the approvals table, and
        their KeyPackages are tracked once merged, so they don't count
        against the invite's share."""
        row = self._one(
            "SELECT count(*) FROM join_ledger WHERE invite_id = ? AND request_id NOT IN "
            "(SELECT request_id FROM approvals WHERE status IN ('approving', 'approved'))",
            invite_id,
        )
        return 0 if row is None else int(row[0])

    def join_ledger_forget(self, invite_id: str) -> int:
        """Forget an invite's join requests: it was revoked or has expired,
        both final, so step 1 refuses any copy (SPEC 6.2 "Replays")."""
        return self._db.execute(
            "DELETE FROM join_ledger WHERE invite_id = ?", (invite_id,)
        ).rowcount

    def ledger_rows(self, now: int, *, ledger: Ledger = "knock") -> list[tuple[str, str, int]]:
        """``(id, kp_ref, forget_after)`` of every request still remembered at ``now``."""
        table, key = LEDGERS[ledger]
        rows = self._all(
            f"SELECT {key}, kp_ref, forget_after FROM {table} WHERE forget_after >= ? "  # noqa: S608
            f"ORDER BY forget_after, {key}",
            now,
        )
        return [(str(r[0]), str(r[1]), int(r[2])) for r in rows]

    def ledger_purge(self, now: int, *, ledger: Ledger = "knock") -> int:
        """Forget requests whose ``forget_after`` is before ``now``."""
        table, _ = LEDGERS[ledger]
        return self._db.execute(
            f"DELETE FROM {table} WHERE forget_after < ?",  # noqa: S608
            (now,),
        ).rowcount

    def add_knock_request(self, row: dict[str, Any], knock: bytes) -> None:
        """A knock waiting for the human (``pending``), with its secret."""
        columns = [c for c in KNOCK_REQUEST_COLUMNS if c in row]
        self._db.execute(
            f"INSERT INTO knock_requests ({', '.join(columns)}, knock) "  # noqa: S608
            f"VALUES ({', '.join('?' for _ in columns)}, ?)",
            [*(row[c] for c in columns), knock],
        )

    def knock_request(self, request_id: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(KNOCK_REQUEST_COLUMNS)} FROM knock_requests "  # noqa: S608
            "WHERE request_id = ?",
            request_id,
        )
        return None if row is None else dict(zip(KNOCK_REQUEST_COLUMNS, row, strict=True))

    def knock_requests(self, *statuses: str) -> list[dict[str, Any]]:
        """Knock requests in these states (all, without any), oldest first."""
        rows = self._all(
            f"SELECT {', '.join(KNOCK_REQUEST_COLUMNS)} FROM knock_requests "  # noqa: S608
            "WHERE ? = '[]' OR status IN (SELECT value FROM json_each(?)) "
            "ORDER BY received_at, request_id",
            json.dumps(list(statuses)),
            json.dumps(list(statuses)),
        )
        return [dict(zip(KNOCK_REQUEST_COLUMNS, r, strict=True)) for r in rows]

    def knock_request_secret(self, request_id: str) -> bytes | None:
        """The verified knock (welcome_secret and KeyPackage) of a request, while kept."""
        row = self._one("SELECT knock FROM knock_requests WHERE request_id = ?", request_id)
        return None if row is None or row[0] is None else bytes(row[0])

    def knock_request_for_group(self, group_id: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(KNOCK_REQUEST_COLUMNS)} FROM knock_requests "  # noqa: S608
            "WHERE group_id = ?",
            group_id,
        )
        return None if row is None else dict(zip(KNOCK_REQUEST_COLUMNS, row, strict=True))

    def open_knock_counts(
        self, door_id: str, directory: str, name: str, identity: str
    ) -> tuple[int, int]:
        """Knocks waiting for the human (``pending``) on ``door_id``, and
        those of ``identity`` on any door of the listing."""
        row = self._one(
            "SELECT COALESCE(SUM(door_id = ?), 0), "
            "COALESCE(SUM(identity = ? AND directory = ? AND name = ?), 0) "
            "FROM knock_requests WHERE status = 'pending'",
            door_id,
            identity,
            directory,
            name,
        )
        return (0, 0) if row is None else (int(row[0]), int(row[1]))

    def decide_knock_request(  # noqa: PLR0913
        self,
        request_id: str,
        status: str,
        now: int,
        *,
        expect: tuple[str, ...] = ("pending",),
        keep_secret: bool = False,
        keep_name: bool = False,
        group_id: str | None = None,
        purpose: str | None = None,
    ) -> bool:
        """Move a request from one of ``expect`` to ``status``. Unless kept,
        the knock's secret goes, and so do the knocker's name and note (the
        note always goes once a decision is made). False if it was in
        another state (a concurrent decision won)."""
        cur = self._db.execute(
            "UPDATE knock_requests SET status = ?, decided_at = ?, "
            "knock = CASE WHEN ? THEN knock ELSE NULL END, "
            "display_name = CASE WHEN ? THEN display_name ELSE NULL END, note = NULL, "
            "group_id = COALESCE(?, group_id), purpose = COALESCE(?, purpose) "
            "WHERE request_id = ? AND status IN (SELECT value FROM json_each(?))",
            (
                status,
                now,
                int(keep_secret),
                int(keep_name),
                group_id,
                purpose,
                request_id,
                json.dumps(list(expect)),
            ),
        )
        return cur.rowcount == 1

    def purge_knock_requests(self, before: int) -> None:
        """Forget decided requests decided before ``before``."""
        self._db.execute(
            "DELETE FROM knock_requests WHERE status NOT IN ('pending', 'approving') "
            "AND decided_at < ?",
            (before,),
        )

    def add_knock(self, row: dict[str, Any], secret: bytes) -> None:
        """A knock this runtime sent (``queued``), with its secret."""
        columns = [c for c in KNOCK_COLUMNS if c in row]
        self._db.execute(
            f"INSERT INTO knocks ({', '.join(columns)}, secret) "  # noqa: S608
            f"VALUES ({', '.join('?' for _ in columns)}, ?)",
            [*(row[c] for c in columns), secret],
        )

    def knock(self, knock_id: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(KNOCK_COLUMNS)} FROM knocks WHERE knock_id = ?",  # noqa: S608
            knock_id,
        )
        return None if row is None else dict(zip(KNOCK_COLUMNS, row, strict=True))

    def knocks(self, *statuses: str) -> list[dict[str, Any]]:
        """This runtime's knocks in these states (all, without any), oldest first."""
        rows = self._all(
            f"SELECT {', '.join(KNOCK_COLUMNS)} FROM knocks "  # noqa: S608
            "WHERE ? = '[]' OR status IN (SELECT value FROM json_each(?)) "
            "ORDER BY created_at, knock_id",
            json.dumps(list(statuses)),
            json.dumps(list(statuses)),
        )
        return [dict(zip(KNOCK_COLUMNS, r, strict=True)) for r in rows]

    def knock_secret(self, knock_id: str) -> bytes | None:
        """A sent knock's secret (welcome_secret and KeyPackage), while kept."""
        row = self._one("SELECT secret FROM knocks WHERE knock_id = ?", knock_id)
        return None if row is None or row[0] is None else bytes(row[0])

    def knocks_since(self, since: int, door_id: str | None = None) -> int:
        """Knocks created at or after ``since`` (on ``door_id``, or any)."""
        row = self._one(
            "SELECT COUNT(*) FROM knocks WHERE created_at >= ? AND (? IS NULL OR door_id = ?)",
            since,
            door_id,
            door_id,
        )
        return 0 if row is None else int(row[0])

    def update_knock(self, knock_id: str, **fields: Any) -> None:
        for key in fields:
            if key not in KNOCK_COLUMNS or key == "knock_id":
                msg = f"unknown knock column {key}"
                raise ValueError(msg)
        sets = ", ".join(f"{k} = ?" for k in fields)
        self._db.execute(
            f"UPDATE knocks SET {sets} WHERE knock_id = ?",  # noqa: S608
            (*fields.values(), knock_id),
        )

    def end_knock(
        self,
        knock_id: str,
        status: str,
        now: int,
        *,
        reason: str | None = None,
        group_id: str | None = None,
    ) -> bool:
        """A knock is over: joined, lapsed or failed. Its secret goes. False
        if it had ended already."""
        cur = self._db.execute(
            "UPDATE knocks SET status = ?, secret = NULL, reason = ?, ended_at = ?, "
            "group_id = COALESCE(?, group_id) "
            "WHERE knock_id = ? AND status IN ('queued', 'sent')",
            (status, reason, now, group_id, knock_id),
        )
        return cur.rowcount == 1

    def knock_joined(self, knock_id: str, group_id: str, now: int) -> None:
        """The knock's Welcome was joined: its secret goes. Recorded whatever
        the knock's state was (a journalled join is finished even if a lapse
        was recorded meanwhile)."""
        self._db.execute(
            "UPDATE knocks SET status = 'joined', secret = NULL, reason = NULL, "
            "group_id = ?, ended_at = ? WHERE knock_id = ?",
            (group_id, now, knock_id),
        )

    def purge_knocks(self, before: int) -> None:
        """Forget knocks that ended before ``before``."""
        self._db.execute("DELETE FROM knocks WHERE ended_at < ?", (before,))

    def add_listed_peer(self, row: dict[str, Any]) -> None:
        self._db.execute(
            f"INSERT OR REPLACE INTO listed_peers ({', '.join(LISTED_PEER_COLUMNS)}) "  # noqa: S608
            f"VALUES ({', '.join('?' for _ in LISTED_PEER_COLUMNS)})",
            [row[c] for c in LISTED_PEER_COLUMNS],
        )

    def listed_peer(self, group_id: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(LISTED_PEER_COLUMNS)} FROM listed_peers "  # noqa: S608
            "WHERE group_id = ?",
            group_id,
        )
        return None if row is None else dict(zip(LISTED_PEER_COLUMNS, row, strict=True))

    def listing_seen(self, directory: str, name: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(SEEN_COLUMNS)} FROM listings_seen "  # noqa: S608
            "WHERE directory = ? AND name = ?",
            directory,
            name,
        )
        return None if row is None else dict(zip(SEEN_COLUMNS, row, strict=True))

    def put_listing_seen(self, row: dict[str, Any], *, keep_since: int) -> None:
        """Record a listing this runtime saw. The listings it knocked on (a
        knock row is kept a week after it ends) or is in a group with are
        kept; of the others (inspected only) the :data:`MAX_LISTINGS_SEEN`
        most recent, none seen before ``keep_since``. So inspecting many
        listings can't push out the rollback mark of one that matters."""
        unpinned = (
            "NOT EXISTS (SELECT 1 FROM knocks k WHERE k.directory = listings_seen.directory "
            "AND k.name = listings_seen.name) AND NOT EXISTS (SELECT 1 FROM listed_peers p "
            "WHERE p.directory = listings_seen.directory AND p.name = listings_seen.name)"
        )
        with self.tx() as db:
            db.execute(
                f"INSERT OR REPLACE INTO listings_seen ({', '.join(SEEN_COLUMNS)}) "  # noqa: S608
                f"VALUES ({', '.join('?' for _ in SEEN_COLUMNS)})",
                [row.get(c) for c in SEEN_COLUMNS],
            )
            db.execute(
                f"DELETE FROM listings_seen WHERE seen_at < ? AND {unpinned}",  # noqa: S608
                (keep_since,),
            )
            db.execute(
                f"DELETE FROM listings_seen WHERE {unpinned} AND rowid NOT IN "  # noqa: S608
                f"(SELECT rowid FROM listings_seen WHERE {unpinned} "
                "ORDER BY seen_at DESC, rowid DESC LIMIT ?)",
                (MAX_LISTINGS_SEEN,),
            )

    # -- invites and approvals ---------------------------------------------

    def add_invite(  # noqa: PLR0913
        self,
        invite_id: str,
        group_id: str,
        expires_at: int,
        max_uses: int,
        now: int,
        *,
        status: str = "open",
        replica: bool = False,
        instance: str | None = None,
    ) -> None:
        self._db.execute(
            "INSERT INTO invites (invite_id, group_id, expires_at, max_uses, created_at, status, "
            "replica, instance) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (invite_id, group_id, expires_at, max_uses, now, status, int(replica), instance),
        )

    def delete_invite(self, invite_id: str) -> None:
        self._db.execute("DELETE FROM invites WHERE invite_id = ?", (invite_id,))

    def invite(self, invite_id: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT invite_id, group_id, expires_at, max_uses, status, replica, instance "
            "FROM invites WHERE invite_id = ?",
            invite_id,
        )
        return None if row is None else self._invite_row(row)

    def invites(self, status: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT invite_id, group_id, expires_at, max_uses, status, replica, instance "
            "FROM invites WHERE status = ? ORDER BY created_at",
            status,
        )
        return [self._invite_row(r) for r in rows]

    @staticmethod
    def _invite_row(row: tuple[Any, ...]) -> dict[str, Any]:
        keys = ("invite_id", "group_id", "expires_at", "max_uses", "status")
        out = dict(zip(keys, row[:5], strict=True))
        out["replica"] = bool(row[5])
        out["instance"] = row[6]
        return out

    def set_invite_status(self, invite_id: str, status: str) -> None:
        self._db.execute("UPDATE invites SET status = ? WHERE invite_id = ?", (status, invite_id))

    def add_approval(self, row: dict[str, Any]) -> bool:
        cur = self._db.execute(
            "INSERT OR IGNORE INTO approvals (request_id, invite_id, group_id, request, identity, "
            "display_name, mailbox_id, received_at, kp_ref, instance_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                *(row[k] for k in self._APPROVAL_KEYS[:8]),
                row.get("kp_ref"),
                row.get("instance_id"),
            ],
        )
        return cur.rowcount == 1

    _APPROVAL_KEYS = (
        "request_id",
        "invite_id",
        "group_id",
        "request",
        "identity",
        "display_name",
        "mailbox_id",
        "received_at",
        "status",
        "instance_id",
    )

    def approval(self, request_id: str) -> dict[str, Any] | None:
        row = self._one(
            f"SELECT {', '.join(self._APPROVAL_KEYS)} FROM approvals WHERE request_id = ?",  # noqa: S608
            request_id,
        )
        return None if row is None else dict(zip(self._APPROVAL_KEYS, row, strict=True))

    def approvals(self, status: str = "pending") -> list[dict[str, Any]]:
        rows = self._all(
            f"SELECT {', '.join(self._APPROVAL_KEYS)} FROM approvals "  # noqa: S608
            "WHERE status = ? ORDER BY received_at",
            status,
        )
        return [dict(zip(self._APPROVAL_KEYS, r, strict=True)) for r in rows]

    def open_approval_for(self, kp_ref: str) -> str | None:
        """A pending or approving request with this KeyPackageRef, if any."""
        row = self._one(
            "SELECT request_id FROM approvals WHERE kp_ref = ? "
            "AND status IN ('pending', 'approving')",
            kp_ref,
        )
        return None if row is None else str(row[0])

    def pending_approvals_for(self, invite_id: str, since: int) -> int:
        """Join requests of this invite waiting for the human, received at
        or after ``since`` (older ones have lapsed)."""
        row = self._one(
            "SELECT count(*) FROM approvals WHERE invite_id = ? AND status = 'pending' "
            "AND received_at >= ?",
            invite_id,
            since,
        )
        return 0 if row is None else int(row[0])

    def pending_approvals_of(self, invite_id: str, identity: str, since: int) -> int:
        """Join requests of this invite that claim ``identity`` and wait for
        the human, received at or after ``since`` (older ones have lapsed)."""
        row = self._one(
            "SELECT count(*) FROM approvals WHERE invite_id = ? AND identity = ? "
            "AND status = 'pending' AND received_at >= ?",
            invite_id,
            identity,
            since,
        )
        return 0 if row is None else int(row[0])

    def adding_to(self, group_id: str) -> list[str]:
        """The joiners' mailboxes of the approved joins of this group whose
        Add is under way (``approving`` until the Welcome went out)."""
        rows = self._all(
            "SELECT mailbox_id FROM approvals WHERE group_id = ? AND status = 'approving'",
            group_id,
        )
        return [str(r[0]) for r in rows]

    def uses_taken(self, invite_id: str) -> int:
        """Approvals that hold one of the invite's uses (approving or done)."""
        row = self._one(
            "SELECT count(*) FROM approvals WHERE invite_id = ? "
            "AND status IN ('approving', 'approved')",
            invite_id,
        )
        return 0 if row is None else int(row[0])

    def set_approval_status(self, request_id: str, status: str) -> None:
        # A decided request no longer needs its body (key package, name).
        keep = status in ("pending", "approving")
        self._db.execute(
            "UPDATE approvals SET status = ?, request = CASE WHEN ? THEN request ELSE '' END "
            "WHERE request_id = ?",
            (status, int(keep), request_id),
        )

    # -- joins (joiner side) -----------------------------------------------

    def add_join(self, invite_id: str, meta: dict[str, Any], display_name: str, now: int) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO joins (invite_id, meta, display_name, created_at) "
            "VALUES (?, ?, ?, ?)",
            (invite_id, json.dumps(meta), display_name, now),
        )

    def pending_joins(self) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT invite_id, meta, display_name FROM joins WHERE status = 'pending' "
            "ORDER BY created_at"
        )
        return [{"invite_id": r[0], "meta": json.loads(r[1]), "display_name": r[2]} for r in rows]

    def finish_join(self, invite_id: str, status: str, group_id: str | None = None) -> None:
        self._db.execute(
            "UPDATE joins SET status = ?, group_id = ? WHERE invite_id = ?",
            (status, group_id, invite_id),
        )

    def joined_invites(self) -> list[str]:
        """Invite ids of joins that ended (joined, failed or expired)."""
        rows = self._all("SELECT invite_id FROM joins WHERE status != 'pending'")
        return [str(r[0]) for r in rows]

    def join_name(self, invite_id: str) -> str | None:
        """The display name a join (in any state) was requested under."""
        row = self._one("SELECT display_name FROM joins WHERE invite_id = ?", invite_id)
        return None if row is None else str(row[0])

    def join_status(self, invite_id: str) -> tuple[str, str | None] | None:
        row = self._one("SELECT status, group_id FROM joins WHERE invite_id = ?", invite_id)
        return None if row is None else (str(row[0]), None if row[1] is None else str(row[1]))

    # -- outbox -------------------------------------------------------------

    def enqueue(self, kind: str, group_id: str | None, payload: dict[str, Any], now: int) -> int:
        cur = self._db.execute(
            "INSERT INTO outbox (kind, group_id, payload, created_at) VALUES (?, ?, ?, ?)",
            (kind, group_id, json.dumps(payload), now),
        )
        return int(cur.lastrowid or 0)

    def next_outbox(self) -> OutboxRow | None:
        row = self._one(
            "SELECT seq, kind, group_id, payload, state FROM outbox "
            "WHERE state = 'queued' ORDER BY seq LIMIT 1"
        )
        if row is None:
            return None
        return OutboxRow(row[0], row[1], row[2], json.loads(row[3]), row[4])

    def outbox_lanes(self) -> list[tuple[int, str | None]]:
        """Every queued row's ``seq``, in order, with its lane: the group it
        sends to (a frame's own group id when it names one, such as
        ``group.create`` or a proposal), or ``None`` for a frame of no group
        (a join, a knock, an invite's consumption)."""
        rows = self._all(
            "SELECT seq, COALESCE(group_id, json_extract(payload, '$.frame.group_id'), "
            "json_extract(payload, '$.frame.env.group_id')) "
            "FROM outbox WHERE state = 'queued' ORDER BY seq"
        )
        return [(int(r[0]), None if r[1] is None else str(r[1])) for r in rows]

    def outbox_row(self, seq: int) -> OutboxRow | None:
        row = self._one("SELECT seq, kind, group_id, payload, state FROM outbox WHERE seq = ?", seq)
        return (
            None if row is None else OutboxRow(row[0], row[1], row[2], json.loads(row[3]), row[4])
        )

    def outbox(self, state: str = "queued") -> list[OutboxRow]:
        rows = self._all(
            "SELECT seq, kind, group_id, payload, state FROM outbox WHERE state = ? ORDER BY seq",
            state,
        )
        return [OutboxRow(r[0], r[1], r[2], json.loads(r[3]), r[4]) for r in rows]

    def outbox_state_of(self, msg_id: str) -> str | None:
        """The state of the outbox row that sends ``msg_id``, if one is kept."""
        row = self._one(
            "SELECT state FROM outbox WHERE json_extract(payload, '$.msg_id') = ? "
            "ORDER BY seq DESC LIMIT 1",
            msg_id,
        )
        return None if row is None else str(row[0])

    def update_outbox(
        self, seq: int, payload: dict[str, Any] | None = None, state: str | None = None
    ) -> None:
        if state is not None and state != "queued":
            # Answered (or given up): keep the ids, drop inner plaintext,
            # envelopes and frames.
            if payload is None:
                row = self.outbox_row(seq)
                payload = {} if row is None else row.payload
            payload = _scrubbed(payload)
        if payload is not None:
            self._db.execute(
                "UPDATE outbox SET payload = ? WHERE seq = ?", (json.dumps(payload), seq)
            )
        if state is not None:
            self._db.execute("UPDATE outbox SET state = ? WHERE seq = ?", (state, seq))

    # -- inbox --------------------------------------------------------------

    def inbox_seq(self, sender: str, msg_id: str) -> int | None:
        row = self._one("SELECT seq FROM inbox WHERE sender = ? AND msg_id = ?", sender, msg_id)
        return None if row is None else int(row[0])

    def inbox_row(self, seq: int) -> InboxRow | None:
        row = self._one(
            "SELECT seq, sender, msg_id, group_id, delivery, state FROM inbox WHERE seq = ?", seq
        )
        if row is None:
            return None
        delivery = None if row[4] is None else json.loads(row[4])
        return InboxRow(row[0], row[1], row[2], row[3], delivery, row[5])

    def inbox_state(self, sender: str, msg_id: str) -> str | None:
        row = self._one("SELECT state FROM inbox WHERE sender = ? AND msg_id = ?", sender, msg_id)
        return None if row is None else str(row[0])

    def record_inbox(  # noqa: PLR0913
        self,
        sender: str,
        msg_id: str,
        group_id: str | None,
        state: str,
        now: int,
        *,
        delivery: dict[str, Any] | None = None,
        hop: int | None = None,
    ) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO inbox (sender, msg_id, group_id, delivery, state, received_at, "
            "hop) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sender,
                msg_id,
                group_id,
                None if delivery is None else json.dumps(delivery),
                state,
                now,
                hop,
            ),
        )

    def record_hop(self, group_id: str, msg_id: str, hop: int, now: int) -> None:
        """Remember the SPEC 10.3 ``hop`` of a message sent or received."""
        self._db.execute(
            "INSERT OR IGNORE INTO hops (group_id, msg_id, hop, at) VALUES (?, ?, ?, ?)",
            (group_id, msg_id, hop, now),
        )

    def inbox_hops(self, group_id: str, msg_ids: Sequence[str]) -> list[int]:
        """The known ``hop`` of messages (sent or received) in a group."""
        out: list[int] = []
        for msg_id in msg_ids:
            row = self._one(
                "SELECT hop FROM hops WHERE group_id = ? AND msg_id = ?", group_id, msg_id
            )
            if row is not None:
                out.append(int(row[0]))
        return out

    def forget_hops(self, before: int) -> None:
        self._db.execute("DELETE FROM hops WHERE at < ?", (before,))

    def pending_deliveries(
        self, group_id: str | None = None, limit: int = -1, *, adapter: str | None = None
    ) -> list[InboxRow]:
        """Pending inbox rows, oldest first; with ``group_id`` only that
        group's that can be handed over, at most ``limit`` of them (-1: all),
        and with ``adapter`` only those that adapter hasn't taken yet."""
        rows = self._all(
            "SELECT seq, sender, msg_id, group_id, delivery, state FROM inbox "
            "WHERE state = 'pending' AND (? IS NULL OR (group_id = ? AND delivery IS NOT NULL)) "
            "AND (? IS NULL OR NOT EXISTS (SELECT 1 FROM inbox_acks a "
            "WHERE a.inbox_seq = inbox.seq AND a.adapter = ?)) "
            "ORDER BY seq LIMIT ?",
            group_id,
            group_id,
            adapter,
            adapter,
            limit,
        )
        return [
            InboxRow(r[0], r[1], r[2], r[3], None if r[4] is None else json.loads(r[4]), r[5])
            for r in rows
        ]

    def pending_groups(self) -> list[str]:
        """The groups with pending deliveries that can be handed over."""
        rows = self._all(
            "SELECT group_id FROM inbox WHERE state = 'pending' AND group_id IS NOT NULL "
            "AND delivery IS NOT NULL GROUP BY group_id ORDER BY MIN(seq)"
        )
        return [str(r[0]) for r in rows]

    def mark_delivered(self, seq: int, adapter: str, targets: Sequence[str]) -> bool:
        """``adapter`` accepted inbox row ``seq``. Once every adapter of
        ``targets`` has, the row is done (and its plaintext goes); True then."""
        with self.tx():
            self._db.execute(
                "INSERT OR IGNORE INTO inbox_acks (inbox_seq, adapter) VALUES (?, ?)",
                (seq, adapter),
            )
            if self._missing_acks(seq, targets):
                return False
            self.set_inbox_state(seq, "done")
            return True

    def _missing_acks(self, seq: int, targets: Sequence[str]) -> bool:
        row = self._one(
            "SELECT COUNT(*) FROM json_each(?) j WHERE NOT EXISTS (SELECT 1 FROM inbox_acks a "
            "WHERE a.inbox_seq = ? AND a.adapter = j.value)",
            json.dumps(list(targets)),
            seq,
        )
        return row is not None and int(row[0]) > 0

    def settle_deliveries(self, group_id: str, targets: Sequence[str]) -> int:
        """Mark done the group's pending rows every one of ``targets`` has
        taken (the group's adapters changed since). None with no target."""
        if not targets:
            return 0
        done = 0
        with self.tx():
            for row in self._all(
                "SELECT DISTINCT a.inbox_seq FROM inbox_acks a JOIN inbox i ON i.seq = a.inbox_seq "
                "WHERE i.group_id = ? AND i.state = 'pending'",
                group_id,
            ):
                if not self._missing_acks(int(row[0]), targets):
                    self.set_inbox_state(int(row[0]), "done")
                    done += 1
        return done

    def set_inbox_state(self, seq: int, state: str) -> None:
        # A delivered row no longer needs its plaintext, nor its adapters'
        # markers.
        if state in ("done", "dropped"):
            self._db.execute(
                "UPDATE inbox SET state = ?, delivery = NULL WHERE seq = ?", (state, seq)
            )
            self._db.execute("DELETE FROM inbox_acks WHERE inbox_seq = ?", (seq,))
        else:
            self._db.execute("UPDATE inbox SET state = ? WHERE seq = ?", (state, seq))

    # -- events -------------------------------------------------------------

    def add_event(  # noqa: PLR0913
        self,
        group_id: str | None,
        kind: str,
        data: dict[str, Any],
        now: int,
        event_id: str,
        *,
        agent: bool = True,
    ) -> bool:
        """Record an event, not yet notified. ``False`` if an event with this
        id is already recorded (the same cause, regenerated after a crash).
        An event the agent may see (``agent``) also gets the next number of
        the agent's own sequence, so the events it may not see leave no gap
        in what it reads."""
        cur = self._db.execute(
            "INSERT OR IGNORE INTO events (group_id, type, data, at, event_id, agent_seq) "
            "VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN "
            "(SELECT COALESCE(MAX(agent_seq), 0) + 1 FROM events) END)",
            (group_id, kind, json.dumps(data), now, event_id, int(agent)),
        )
        return cur.rowcount == 1

    def number_agent_events(self, hidden: frozenset[str]) -> None:
        """Once, for a database from before the agent's own sequence: number
        the events the agent may see (every type but ``hidden``) in order."""
        if self.kv_get("schema/agent_seq") == "1":
            return
        with self.tx():
            rows = self._all(
                "SELECT seq FROM events WHERE agent_seq IS NULL "
                "AND type NOT IN (SELECT value FROM json_each(?)) ORDER BY seq",
                json.dumps(sorted(hidden)),
            )
            start = self._one("SELECT COALESCE(MAX(agent_seq), 0) FROM events")
            n = int(start[0]) if start is not None else 0
            for (seq,) in rows:
                n += 1
                self._db.execute("UPDATE events SET agent_seq = ? WHERE seq = ?", (n, seq))
            self.kv_set("schema/agent_seq", "1")

    def release_agent_events(self, group_id: str, hidden: frozenset[str]) -> list[dict[str, Any]]:
        """A group became the agent's to see: its events so far that the agent
        may see (every type but ``hidden``) get the next numbers of the
        agent's sequence, in order, and are to be told to the adapter again.
        Returns them."""
        rows = self._all(
            "SELECT seq FROM events WHERE group_id = ? AND agent_seq IS NULL "
            "AND type NOT IN (SELECT value FROM json_each(?)) ORDER BY seq",
            group_id,
            json.dumps(sorted(hidden)),
        )
        for (seq,) in rows:
            self._db.execute(
                "UPDATE events SET notified = 0, agent_seq = "
                "(SELECT COALESCE(MAX(agent_seq), 0) + 1 FROM events) WHERE seq = ?",
                (seq,),
            )
            self._db.execute(
                "DELETE FROM event_acks WHERE event_id = (SELECT event_id FROM events "
                "WHERE seq = ?)",
                (seq,),
            )
        out = self._all(
            "SELECT seq, group_id, type, data, at, event_id FROM events "
            "WHERE seq IN (SELECT value FROM json_each(?)) ORDER BY seq",
            json.dumps([int(r[0]) for r in rows]),
        )
        return [self._event(r) for r in out]

    def agent_visible(self, event_id: str) -> bool:
        """Whether the agent may see this event (it has an agent sequence number)."""
        row = self._one("SELECT agent_seq FROM events WHERE event_id = ?", event_id)
        return row is not None and row[0] is not None

    # -- SSE feed -----------------------------------------------------------

    def feed_add(
        self,
        key: str,
        group_id: str | None,
        payload: dict[str, Any],
        now: int,
        keep: int = 10_000,
    ) -> int | None:
        """Append to the SSE feed; its ``seq`` is the SSE event id. ``None``
        if ``key`` (a ``msg_id`` or ``event_id``) is already there. Only the
        newest ``keep`` items are retained; ``now`` stamps the row for
        :meth:`feed_purge`."""
        cur = self._db.execute(
            "INSERT OR IGNORE INTO feed (key, group_id, payload, at) VALUES (?, ?, ?, ?)",
            (key, group_id, json.dumps(payload, sort_keys=True), now),
        )
        if cur.rowcount != 1:
            return None
        seq = int(cur.lastrowid or 0)
        self._feed_drop_through(seq - keep)
        return seq

    def _feed_drop_through(self, seq: int) -> None:
        """Delete feed rows up to ``seq`` and remember it: a consumer resuming
        from before that point has missed items (:meth:`feed_purged`)."""
        row = self._one("SELECT MAX(seq) FROM feed WHERE seq <= ?", seq)
        if row is None or row[0] is None:
            return
        gone = int(row[0])
        self._db.execute("DELETE FROM feed WHERE seq <= ?", (gone,))
        if gone > self.feed_purged():
            self.kv_set("feed_purged", str(gone))

    def feed_purge(self, before: int) -> int:
        """Delete every feed item stamped before ``before`` (Unix seconds).
        Returns how many went."""
        row = self._one("SELECT MAX(seq), COUNT(*) FROM feed WHERE at < ?", before)
        if row is None or row[0] is None:
            return 0
        self._feed_drop_through(int(row[0]))
        return int(row[1])

    def feed_purged(self) -> int:
        """The highest ``seq`` ever removed from the feed (0: none)."""
        return int(self.kv_get("feed_purged") or "0")

    def feed_since(
        self, after: int, group_id: str | None = None, limit: int = 10_000
    ) -> list[tuple[int, str | None, dict[str, Any]]]:
        rows = self._all(
            "SELECT seq, group_id, payload FROM feed WHERE seq > ? "
            "AND (? IS NULL OR group_id = ?) ORDER BY seq LIMIT ?",
            after,
            group_id,
            group_id,
            limit,
        )
        return [(int(r[0]), r[1], json.loads(r[2])) for r in rows]

    def feed_last(self) -> int:
        row = self._one("SELECT seq FROM sqlite_sequence WHERE name = 'feed'")
        return 0 if row is None else int(row[0])

    # -- in-process adapters (agentconnect.callback) --------------------------

    def adapter_event_add(
        self,
        adapter: str,
        event_id: str,
        payload: dict[str, Any],
        keep: int = 10_000,
        *,
        addressed: bool = False,
    ) -> bool:
        """Queue an event for an in-process adapter; ``False`` if it is
        queued already. Only the newest ``keep`` per adapter are retained.
        ``addressed`` marks a message that addresses this agent (the
        delivery queue finds those directly)."""
        with self.tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO adapter_events "
                "(adapter, event_id, payload, group_id, addressed) VALUES (?, ?, ?, ?, ?)",
                (
                    adapter,
                    event_id,
                    json.dumps(payload, sort_keys=True),
                    _payload_group(payload),
                    int(addressed),
                ),
            )
            db.execute(
                "DELETE FROM adapter_events WHERE adapter = ? AND seq NOT IN "
                "(SELECT seq FROM adapter_events WHERE adapter = ? ORDER BY seq DESC LIMIT ?)",
                (adapter, adapter, keep),
            )
        return cur.rowcount == 1

    def adapter_events(
        self, adapter: str, group_id: str | None = None, limit: int = 100
    ) -> list[tuple[int, dict[str, Any]]]:
        """Queued events of ``adapter`` for ``group_id`` (``None``: events
        about no group), oldest first, at most ``limit``."""
        rows = self._all(
            "SELECT seq, payload FROM adapter_events WHERE adapter = ? AND group_id IS ? "
            "ORDER BY seq LIMIT ?",
            adapter,
            group_id,
            limit,
        )
        return [(int(r[0]), json.loads(r[1])) for r in rows]

    def adapter_event_groups(self, adapter: str) -> list[str | None]:
        """The groups (``None``: no group) with queued events for ``adapter``."""
        rows = self._all(
            "SELECT group_id FROM adapter_events WHERE adapter = ? "
            "GROUP BY group_id ORDER BY MIN(seq)",
            adapter,
        )
        return [None if r[0] is None else str(r[0]) for r in rows]

    def adapter_event_done(self, seq: int) -> None:
        self._db.execute("DELETE FROM adapter_events WHERE seq = ?", (seq,))

    def queue_rows(  # noqa: PLR0913
        self,
        adapter: str,
        *,
        group_id: str | None,
        skip: Sequence[int],
        limit: int,
        addressed: bool = False,
        before: int | None = None,
    ) -> list[tuple[int, dict[str, Any]]]:
        """Queued items of ``adapter`` (the delivery queue's), oldest first,
        without the ``skip`` seqs: of ``group_id`` (``None``: every group),
        only addressed ones with ``addressed``. With ``before``, the newest
        ``limit`` older than that seq instead, still oldest first."""
        args = (adapter, group_id, group_id, json.dumps(list(skip)), int(addressed))
        if before is None:
            rows = self._all(_QUEUE_ROWS + "ORDER BY seq LIMIT ?", *args, None, None, limit)
        else:
            rows = self._all(
                _QUEUE_ROWS + "ORDER BY seq DESC LIMIT ?", *args, before, before, limit
            )
            rows.reverse()
        return [(int(r[0]), json.loads(r[1])) for r in rows]

    def adapter_event_finish(self, adapter: str, seq: int) -> bool:
        """Take one queued item of ``adapter`` off the queue and remember its
        id as handled, in one transaction; ``False`` if it isn't queued."""
        with self.tx() as db:
            row = db.execute(
                "SELECT event_id FROM adapter_events WHERE seq = ? AND adapter = ?", (seq, adapter)
            ).fetchone()
            if row is None:
                return False
            db.execute("DELETE FROM adapter_events WHERE seq = ?", (seq,))
            self.handled_add(str(row[0]), HANDLED_KEEP)
        return True

    # -- ids an in-process agent's handlers finished with ---------------------

    def handled_has(self, key: str) -> bool:
        return self._one("SELECT 1 FROM handled WHERE key = ?", key) is not None

    def handled_add(self, key: str, keep: int) -> None:
        """Remember ``key``; only the newest ``keep`` keys are retained."""
        with self.tx() as db:
            cur = db.execute("INSERT OR IGNORE INTO handled (key) VALUES (?)", (key,))
            if cur.rowcount == 1:
                db.execute("DELETE FROM handled WHERE seq <= ?", (int(cur.lastrowid or 0) - keep,))

    def unnotified_events(self) -> list[dict[str, Any]]:
        """Recorded events the adapter has not accepted yet, oldest first."""
        rows = self._all(
            "SELECT seq, group_id, type, data, at, event_id FROM events "
            "WHERE notified = 0 ORDER BY seq"
        )
        return [self._event(r) for r in rows]

    def event_notified(self, event_id: str) -> bool:
        row = self._one("SELECT notified FROM events WHERE event_id = ?", event_id)
        return row is not None and bool(row[0])

    def mark_notified(self, event_id: str) -> None:
        """Every adapter has the event: its per-adapter markers go."""
        with self.tx():
            self._db.execute("UPDATE events SET notified = 1 WHERE event_id = ?", (event_id,))
            self._db.execute("DELETE FROM event_acks WHERE event_id = ?", (event_id,))

    def event_marked(self, event_id: str, adapter: str) -> bool:
        """Whether ``adapter`` accepted this event already."""
        row = self._one(
            "SELECT 1 FROM event_acks WHERE event_id = ? AND adapter = ?", event_id, adapter
        )
        return row is not None

    def mark_event(self, event_id: str, adapter: str) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO event_acks (event_id, adapter) VALUES (?, ?)",
            (event_id, adapter),
        )

    def set_group_adapters(self, group_id: str, adapters: list[str] | None) -> None:
        """Pin the group's adapters (``None``: follow the config)."""
        self.update_group(group_id, adapters=adapters)

    @staticmethod
    def _event(r: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "seq": r[0],
            "group_id": r[1],
            "type": r[2],
            "data": json.loads(r[3]),
            "at": r[4],
            "event_id": r[5],
        }

    def events(
        self, after: int = 0, limit: int = 200, group_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Every event after ``after`` (the human's view), oldest first."""
        rows = self._all(
            "SELECT seq, group_id, type, data, at, event_id FROM events WHERE seq > ? "
            "AND (? IS NULL OR group_id = ?) ORDER BY seq LIMIT ?",
            after,
            group_id,
            group_id,
            limit,
        )
        return [self._event(r) for r in rows]

    def agent_events(
        self, after: int = 0, limit: int = 200, group_id: str | None = None
    ) -> list[dict[str, Any]]:
        """The events the agent may see, by the agent's own sequence: ``seq``
        is that number, gap-free, so nothing tells it how many events it
        doesn't see."""
        rows = self._all(
            "SELECT agent_seq, group_id, type, data, at, event_id FROM events "
            "WHERE agent_seq > ? AND (? IS NULL OR group_id = ?) ORDER BY agent_seq LIMIT ?",
            after,
            group_id,
            group_id,
            limit,
        )
        return [self._event(r) for r in rows]
