"""What the adapter has already handled, so at-least-once redelivery (ADR-004)
never reaches the A2A agent twice.

Keys are ``msg_id``s and ``event_id``s. Only their SHA-256 is stored, in the
daemon's encrypted database (SPEC 12: there is no unencrypted on-disk mode),
and the newest :data:`LIMIT` entries are kept. Without the daemon's database
(unit use) the set lives in memory. Older daemons kept it in a plain SQLite
file in the data directory: its entries move into the database and the file
is deleted.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentconnect.store import Store

LIMIT = 50_000
PRUNE_EVERY = 1_000


class Seen:
    def __init__(self, store: Store | None, legacy: Path | None = None) -> None:
        self._store = store
        self._memory: OrderedDict[str, None] = OrderedDict()
        self._n = 0 if store is None else store.a2a_seen_last()
        if store is not None and legacy is not None:
            self._import(legacy)

    def _import(self, legacy: Path) -> None:
        """Move an older daemon's plain file into the database, oldest
        first, then delete it with its journal files."""
        if legacy.exists():
            try:
                old = sqlite3.connect(f"file:{legacy}?mode=ro", uri=True)
                try:
                    rows = old.execute("SELECT h FROM seen ORDER BY n").fetchall()
                finally:
                    old.close()
            except sqlite3.Error:
                rows = []  # unreadable: at worst one redelivery reaches the agent
            for (h,) in rows[-LIMIT:]:
                self._put(str(h))
        for suffix in ("", "-wal", "-shm", "-journal"):
            legacy.with_name(legacy.name + suffix).unlink(missing_ok=True)

    @staticmethod
    def _h(kind: str, key: str) -> str:
        return hashlib.sha256(f"{kind}\0{key}".encode()).hexdigest()

    def has(self, kind: str, key: str) -> bool:
        h = self._h(kind, key)
        if self._store is None:
            return h in self._memory
        return self._store.a2a_seen_has(h)

    def add(self, kind: str, key: str) -> None:
        self._put(self._h(kind, key))

    def _put(self, h: str) -> None:
        self._n += 1
        if self._store is None:
            self._memory[h] = None
            while len(self._memory) > LIMIT:
                self._memory.popitem(last=False)
            return
        self._store.a2a_seen_add(h, self._n)
        if self._n % PRUNE_EVERY == 0:
            self._store.a2a_seen_prune(self._n - LIMIT)

    def close(self) -> None:
        """Nothing to close: the daemon owns its database."""
