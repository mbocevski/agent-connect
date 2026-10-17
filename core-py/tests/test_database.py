"""``Database``: the daemon's SQLCipher database (ADR-003)."""

from __future__ import annotations

import random
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest

import agentconnect_core as ac

MARKER = "PLAINTEXT-MARKER-daemon-db"


def key(rng: random.Random) -> bytes:
    return rng.randbytes(ac.DB_KEY_LEN)


def disk(path: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(path.parent.iterdir()) if p.is_file())


def test_round_trip_and_value_types(tmp_path: Path, rng: random.Random) -> None:
    db = ac.Database(str(tmp_path / "d.db"), key(rng))
    db.execute_script("CREATE TABLE t (id INTEGER PRIMARY KEY, a, b, c, d)")
    assert db.execute("INSERT INTO t (a, b, c, d) VALUES (?, ?, ?, ?)", [None, 3, 1.5, "x"]) == (
        1,
        1,
    )
    db.execute("INSERT INTO t (a) VALUES (?)", (b"\x00raw",))
    assert db.query("SELECT a, b, c, d FROM t ORDER BY id") == [
        (None, 3, 1.5, "x"),
        (b"\x00raw", None, None, None),
    ]
    assert db.query("SELECT count(*) FROM t WHERE b = ?", [True]) == [(0,)]
    with pytest.raises(TypeError, match="SQL parameters"):
        db.execute("SELECT ?", cast("list[Any]", [[1]]))
    with pytest.raises(ac.AgentConnectError, match="storage error"):
        db.execute("NOT SQL")
    assert repr(db) == "Database(...)"
    db.close()
    with pytest.raises(ac.AgentConnectError, match="closed"):
        db.query("SELECT 1")


def test_the_file_holds_no_plaintext(tmp_path: Path, rng: random.Random) -> None:
    path = tmp_path / "enc" / "d.db"
    path.parent.mkdir()
    db = ac.Database(str(path), key(rng))
    db.execute_script("PRAGMA journal_mode=WAL; CREATE TABLE t (v TEXT)")
    for _ in range(50):
        db.execute("INSERT INTO t VALUES (?)", [MARKER])
    raw = disk(path)
    assert len(raw) > 4096
    assert MARKER.encode() not in raw
    db.close()
    # Control: the same rows through plain SQLite are visible on disk.
    plain = tmp_path / "plain" / "d.db"
    plain.parent.mkdir()
    conn = sqlite3.connect(plain)
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.executemany("INSERT INTO t VALUES (?)", [(MARKER,)] * 50)
    conn.commit()
    conn.close()
    assert MARKER.encode() in disk(plain)
    # A cleartext file is refused, not read or overwritten.
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        ac.Database(str(plain), key(rng))


def test_a_wrong_or_missing_key_fails_cleanly(tmp_path: Path, rng: random.Random) -> None:
    path = str(tmp_path / "d.db")
    k = key(rng)
    db = ac.Database(path, k)
    db.execute_script("CREATE TABLE t (v)")
    db.close()
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        ac.Database(path, key(rng))
    for bad in (b"", k[:31]):
        with pytest.raises(ac.AgentConnectError, match="32 bytes"):
            ac.Database(path, bad)
    assert ac.Database(path, k).query("SELECT count(*) FROM t") == [(0,)]


def test_the_key_is_derived_not_the_store_key(tmp_path: Path, rng: random.Random) -> None:
    # The same db_key keys the MLS store directly; the daemon database uses
    # a derived key, so a file keyed by one doesn't open as the other.
    k = key(rng)
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(64))
    mls = tmp_path / "mls.db"
    client = ac.Client._for_testing(str(mls), instance.to_secret_bytes(), rng.getrandbits(64), k)
    client.create_group("g", "p")
    del client
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        ac.Database(str(mls), k)
