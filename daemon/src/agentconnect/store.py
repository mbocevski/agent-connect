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
    status TEXT NOT NULL DEFAULT 'pending'
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
    at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
        self._db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def tx(self) -> Generator[_Connection]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield self._db
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

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
        with self.tx() as db:
            for table in ("members", "agent_cards"):
                db.execute(f"DELETE FROM {table} WHERE group_id = ?", (group_id,))  # noqa: S608

    # -- invites and approvals ---------------------------------------------

    def add_invite(
        self, invite_id: str, group_id: str, expires_at: int, max_uses: int, now: int
    ) -> None:
        self._db.execute(
            "INSERT INTO invites (invite_id, group_id, expires_at, max_uses, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (invite_id, group_id, expires_at, max_uses, now),
        )

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

    def set_invite_status(self, invite_id: str, status: str) -> None:
        self._db.execute("UPDATE invites SET status = ? WHERE invite_id = ?", (status, invite_id))

    def add_approval(self, row: dict[str, Any]) -> bool:
        cur = self._db.execute(
            "INSERT OR IGNORE INTO approvals (request_id, invite_id, group_id, request, identity, "
            "display_name, mailbox_id, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [row[k] for k in self._APPROVAL_KEYS[:-1]],
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

    def inbox_hops(self, group_id: str, msg_ids: Sequence[str]) -> list[int]:
        """The SPEC 10.3 ``hop`` of received application messages in a group."""
        out: list[int] = []
        for msg_id in msg_ids:
            rows = self._all(
                "SELECT hop FROM inbox WHERE group_id = ? AND msg_id = ? AND hop IS NOT NULL",
                group_id,
                msg_id,
            )
            out.extend(int(r[0]) for r in rows)
        return out

    def pending_deliveries(self) -> list[InboxRow]:
        rows = self._all(
            "SELECT seq, sender, msg_id, group_id, delivery, state FROM inbox "
            "WHERE state IN ('pending', 'held') ORDER BY seq"
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

    def add_event(self, group_id: str | None, kind: str, data: dict[str, Any], now: int) -> int:
        cur = self._db.execute(
            "INSERT INTO events (group_id, type, data, at) VALUES (?, ?, ?, ?)",
            (group_id, kind, json.dumps(data), now),
        )
        return int(cur.lastrowid or 0)

    def events(self, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT seq, group_id, type, data, at FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
            after,
            limit,
        )
        return [
            {"seq": r[0], "group_id": r[1], "type": r[2], "data": json.loads(r[3]), "at": r[4]}
            for r in rows
        ]
