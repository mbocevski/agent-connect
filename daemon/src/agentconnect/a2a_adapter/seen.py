"""What the adapter has already handled, so at-least-once redelivery (ADR-004)
never reaches the A2A agent twice.

Keys are ``msg_id``s and ``event_id``s. Only their SHA-256 is stored, so the
file (in the daemon's data directory, mode 0600) holds no group or member
identifiers. It keeps the most recent :data:`LIMIT` entries.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

LIMIT = 50_000
PRUNE_EVERY = 1_000


class Seen:
    def __init__(self, path: Path | None) -> None:
        target = ":memory:"
        if path is not None:
            if not path.exists():
                os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
            target = str(path)
        self._db = sqlite3.connect(target, isolation_level=None)
        self._db.execute("CREATE TABLE IF NOT EXISTS seen (h TEXT PRIMARY KEY, n INTEGER)")
        row = self._db.execute("SELECT COALESCE(MAX(n), 0) FROM seen").fetchone()
        self._n = int(row[0])

    @staticmethod
    def _h(kind: str, key: str) -> str:
        return hashlib.sha256(f"{kind}\0{key}".encode()).hexdigest()

    def has(self, kind: str, key: str) -> bool:
        row = self._db.execute("SELECT 1 FROM seen WHERE h = ?", (self._h(kind, key),)).fetchone()
        return row is not None

    def add(self, kind: str, key: str) -> None:
        self._n += 1
        self._db.execute(
            "INSERT OR IGNORE INTO seen (h, n) VALUES (?, ?)", (self._h(kind, key), self._n)
        )
        if self._n % PRUNE_EVERY == 0:
            self._db.execute("DELETE FROM seen WHERE n <= ?", (self._n - LIMIT,))

    def close(self) -> None:
        self._db.close()
