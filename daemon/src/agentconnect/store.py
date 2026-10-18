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
from typing import Any

import agentconnect_core as ac
from agentconnect.keystore import private_file

SqlParam = None | int | float | str | bytes


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
    msgs_since_commit INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS members (
    group_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'member',
    verified INTEGER NOT NULL DEFAULT 0,
    instances TEXT NOT NULL DEFAULT '[]',
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
    status TEXT NOT NULL DEFAULT 'open'
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
    kp_ref TEXT
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
"""

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
)


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


@dataclass
class MemberRow:
    identity: str
    display_name: str | None
    role: str
    verified: bool
    instances: list[dict[str, Any]]


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
        for column, decl in (("event_id", "TEXT"), ("notified", "INTEGER NOT NULL DEFAULT 0")):
            if column not in columns:
                self._db.execute(f"ALTER TABLE events ADD COLUMN {column} {decl}")
        feed_columns = {r[0] for r in self._all("SELECT name FROM pragma_table_info('feed')")}
        if "at" not in feed_columns:
            self._db.execute("ALTER TABLE feed ADD COLUMN at INTEGER NOT NULL DEFAULT 0")
        self._db.executescript(
            "CREATE UNIQUE INDEX IF NOT EXISTS events_event_id ON events (event_id);"
            "CREATE INDEX IF NOT EXISTS audit_class ON audit (class, seq);"
            "CREATE INDEX IF NOT EXISTS audit_group ON audit (group_id, class, seq);"
            "CREATE INDEX IF NOT EXISTS audit_sender ON audit (group_id, sender, class, seq);"
            "CREATE INDEX IF NOT EXISTS transcript_group ON transcript (group_id, seq);"
            "CREATE INDEX IF NOT EXISTS transcript_sender ON transcript (group_id, sender, seq);"
        )

    def close(self) -> None:
        self._db.close()

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
            json.dumps(v) if k == "policy" else int(v) if isinstance(v, bool) else v
            for k, v in fields.items()
        ]
        sets = ", ".join(f"{k} = ?" for k in fields)
        self._db.execute(
            f"UPDATE groups SET {sets} WHERE group_id = ?",  # noqa: S608
            (*values, group_id),
        )

    def bump_messages(self, group_id: str) -> None:
        self._db.execute(
            "UPDATE groups SET msgs_since_commit = msgs_since_commit + 1 WHERE group_id = ?",
            (group_id,),
        )

    # -- members ------------------------------------------------------------

    def members(self, group_id: str) -> list[MemberRow]:
        rows = self._all(
            "SELECT identity, display_name, role, verified, instances FROM members "
            "WHERE group_id = ? ORDER BY identity",
            group_id,
        )
        return [MemberRow(r[0], r[1], r[2], bool(r[3]), json.loads(r[4])) for r in rows]

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

    def set_verified(self, group_id: str, identity: str, verified: bool) -> bool:
        cur = self._db.execute(
            "UPDATE members SET verified = ? WHERE group_id = ? AND identity = ?",
            (int(verified), group_id, identity),
        )
        return cur.rowcount == 1

    def put_card(self, group_id: str, identity: str, card: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO agent_cards (group_id, identity, card) VALUES (?, ?, ?)",
            (group_id, identity, json.dumps(card)),
        )

    def cards(self, group_id: str) -> dict[str, dict[str, Any]]:
        rows = self._all("SELECT identity, card FROM agent_cards WHERE group_id = ?", group_id)
        return {r[0]: json.loads(r[1]) for r in rows}

    def delete_group_data(self, group_id: str) -> None:
        """Forget a group's members, cards and safety settings; its held
        messages are dropped. Audit rows and transcript entries stay until
        their retention ends."""
        with self.tx() as db:
            for table in ("members", "agent_cards", "group_safety", "task_decisions"):
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
        """One audit row, in one of two classes that never evict each other:
        ``drop`` rows (what the policy refused) and ``decision`` rows (what
        it delivered, held, approved, rejected or expired). A drop row keeps
        only the newest ``keep_sender`` drops of its sender in the group, and
        ``keep_group`` and ``keep`` drops in the group and in all; a decision
        row is trimmed only by the group and daemon caps, across senders. So a
        sender flooding the log with drops can't erase what it got through,
        its own record included."""
        row_class = "drop" if decision == "drop" else "decision"
        self._db.execute(
            "INSERT INTO audit (group_id, at, direction, sender, msg_id, kind, size, decision, "
            "reason, class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (group_id, at, direction, sender, msg_id, kind, size, decision, reason, row_class),
        )
        if keep_sender is not None and row_class == "drop":
            self._trim_audit(
                "group_id = ? AND sender = ? AND class = ?",
                (group_id, sender, row_class),
                keep_sender,
            )
        if keep_group is not None:
            self._trim_audit("group_id = ? AND class = ?", (group_id, row_class), keep_group)
        if keep is not None:
            self._trim_audit("class = ?", (row_class,), keep)

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

    def audit_purge(self, before: int, keep: int) -> None:
        """Delete audit rows older than ``before`` and all but the newest ``keep``."""
        self._db.execute("DELETE FROM audit WHERE at < ?", (before,))
        row = self._one("SELECT MAX(seq) FROM audit")
        if row is not None and row[0] is not None:
            self._db.execute("DELETE FROM audit WHERE seq <= ?", (int(row[0]) - keep,))

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
    ) -> None:
        self._db.execute(
            "INSERT INTO invites (invite_id, group_id, expires_at, max_uses, created_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (invite_id, group_id, expires_at, max_uses, now, status),
        )

    def delete_invite(self, invite_id: str) -> None:
        self._db.execute("DELETE FROM invites WHERE invite_id = ?", (invite_id,))

    def invite(self, invite_id: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT invite_id, group_id, expires_at, max_uses, status FROM invites "
            "WHERE invite_id = ?",
            invite_id,
        )
        if row is None:
            return None
        keys = ("invite_id", "group_id", "expires_at", "max_uses", "status")
        return dict(zip(keys, row, strict=True))

    def invites(self, status: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT invite_id, group_id, expires_at, max_uses, status FROM invites "
            "WHERE status = ? ORDER BY created_at",
            status,
        )
        keys = ("invite_id", "group_id", "expires_at", "max_uses", "status")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def set_invite_status(self, invite_id: str, status: str) -> None:
        self._db.execute("UPDATE invites SET status = ? WHERE invite_id = ?", (status, invite_id))

    def add_approval(self, row: dict[str, Any]) -> bool:
        cur = self._db.execute(
            "INSERT OR IGNORE INTO approvals (request_id, invite_id, group_id, request, identity, "
            "display_name, mailbox_id, received_at, kp_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [*(row[k] for k in self._APPROVAL_KEYS[:-1]), row.get("kp_ref")],
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

    def pending_deliveries(self) -> list[InboxRow]:
        rows = self._all(
            "SELECT seq, sender, msg_id, group_id, delivery, state FROM inbox "
            "WHERE state = 'pending' ORDER BY seq"
        )
        return [
            InboxRow(r[0], r[1], r[2], r[3], None if r[4] is None else json.loads(r[4]), r[5])
            for r in rows
        ]

    def set_inbox_state(self, seq: int, state: str) -> None:
        # A delivered row no longer needs its plaintext.
        if state in ("done", "dropped"):
            self._db.execute(
                "UPDATE inbox SET state = ?, delivery = NULL WHERE seq = ?", (state, seq)
            )
        else:
            self._db.execute("UPDATE inbox SET state = ? WHERE seq = ?", (state, seq))

    # -- events -------------------------------------------------------------

    def add_event(
        self,
        group_id: str | None,
        kind: str,
        data: dict[str, Any],
        now: int,
        event_id: str,
    ) -> bool:
        """Record an event, not yet notified. ``False`` if an event with this
        id is already recorded (the same cause, regenerated after a crash)."""
        cur = self._db.execute(
            "INSERT OR IGNORE INTO events (group_id, type, data, at, event_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (group_id, kind, json.dumps(data), now, event_id),
        )
        return cur.rowcount == 1

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
        self, adapter: str, event_id: str, payload: dict[str, Any], keep: int = 10_000
    ) -> bool:
        """Queue an event for an in-process adapter; ``False`` if it is
        queued already. Only the newest ``keep`` per adapter are retained."""
        with self.tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO adapter_events (adapter, event_id, payload) "
                "VALUES (?, ?, ?)",
                (adapter, event_id, json.dumps(payload, sort_keys=True)),
            )
            db.execute(
                "DELETE FROM adapter_events WHERE adapter = ? AND seq NOT IN "
                "(SELECT seq FROM adapter_events WHERE adapter = ? ORDER BY seq DESC LIMIT ?)",
                (adapter, adapter, keep),
            )
        return cur.rowcount == 1

    def adapter_events(self, adapter: str, limit: int = 100) -> list[tuple[int, dict[str, Any]]]:
        """Queued events of ``adapter``, oldest first."""
        rows = self._all(
            "SELECT seq, payload FROM adapter_events WHERE adapter = ? ORDER BY seq LIMIT ?",
            adapter,
            limit,
        )
        return [(int(r[0]), json.loads(r[1])) for r in rows]

    def adapter_event_done(self, seq: int) -> None:
        self._db.execute("DELETE FROM adapter_events WHERE seq = ?", (seq,))

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
        self._db.execute("UPDATE events SET notified = 1 WHERE event_id = ?", (event_id,))

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
        self,
        after: int = 0,
        limit: int = 200,
        group_id: str | None = None,
        exclude: Sequence[str] = (),
    ) -> list[dict[str, Any]]:
        """Events after ``after``, oldest first; ``exclude`` leaves out types."""
        rows = self._all(
            "SELECT seq, group_id, type, data, at, event_id FROM events WHERE seq > ? "
            "AND (? IS NULL OR group_id = ?) "
            "AND type NOT IN (SELECT value FROM json_each(?)) ORDER BY seq LIMIT ?",
            after,
            group_id,
            group_id,
            json.dumps(list(exclude)),
            limit,
        )
        return [self._event(r) for r in rows]
