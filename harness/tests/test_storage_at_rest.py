"""Nothing a daemon writes to its data directory is readable without the
keystore (SPEC §12, ADR-003), and plaintext is dropped once it is no longer
needed."""

from __future__ import annotations

import contextlib
import random
import sqlite3
from pathlib import Path

import pytest

import agentconnect_core as ac
from agentconnect.keystore import DataDirLockedError, FileKeystore, KeystoreError
from agentconnect_harness.cluster import Cluster, Node

MARKERS = (
    "PLAINTEXT-MARKER-message",
    "PLAINTEXT-MARKER-group",
    "PLAINTEXT-MARKER-purpose",
    "PLAINTEXT-MARKER-card",
)


def data_bytes(node: Node) -> bytes:
    """Every file under the data directory except the keystore."""
    keys = node.config.data_dir / "keys"
    return b"".join(
        p.read_bytes()
        for p in sorted(node.config.data_dir.rglob("*"))
        if p.is_file() and keys not in p.parents
    )


async def test_the_data_directory_holds_no_plaintext(cluster: Cluster, tmp_path: Path) -> None:
    a = await cluster.node("a")
    b = await cluster.node("b")
    b.adapter._card = {"name": MARKERS[3]}
    gid = a.daemon.create_group(MARKERS[1], MARKERS[2])
    await a.idle()
    await cluster.invite(a, b, gid)
    a.daemon.send_message(gid, {"text": MARKERS[0]})
    assert await b.wait_texts(gid, 1) == [MARKERS[0]]
    await a.wait(lambda: MARKERS[3] in str(a.daemon.store.cards(gid)))
    await a.idle()
    await b.idle()
    # Plaintext retention: answered outbox rows and delivered inbox rows
    # keep only their ids.
    for node in (a, b):
        for row in node.daemon.store.outbox("done") + node.daemon.store.outbox("failed"):
            assert set(row.payload) <= {"msg_id", "t"}, row.payload
        assert node.daemon.store.pending_deliveries() == []
    for node in (a, b):
        raw = data_bytes(node)
        assert len(raw) > 8192, "the databases were written"
        for marker in MARKERS:
            assert marker.encode() not in raw, (node.name, marker)
        # Plain SQLite can't read the daemon database.
        path = node.config.data_dir / "daemon.sqlite3"
        with (
            pytest.raises(sqlite3.DatabaseError),
            contextlib.closing(sqlite3.connect(path)) as db,
        ):
            db.execute("SELECT name FROM sqlite_master").fetchall()
    # Control: the same scan does find the markers in a cleartext SQLite
    # file holding the same kind of rows.
    plain = tmp_path / "plain.sqlite3"
    with contextlib.closing(sqlite3.connect(plain)) as db:
        db.execute("CREATE TABLE outbox (payload TEXT)")
        db.executemany("INSERT INTO outbox VALUES (?)", [(m,) for m in MARKERS])
        db.commit()
    assert all(m.encode() in plain.read_bytes() for m in MARKERS)


async def test_a_wrong_or_missing_key_fails_cleanly(cluster: Cluster, rng: random.Random) -> None:
    node = await cluster.node("k")
    node.daemon.create_group("g", "p")
    await node.idle()
    await node.daemon.stop()
    keys = FileKeystore(node.config.data_dir / "keys")
    original = keys.get("db_key")
    assert original is not None
    keys.put("db_key", rng.randbytes(32))
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        node._make()
    keys.delete("db_key")
    with pytest.raises(KeystoreError, match="database key is missing"):
        node._make()
    assert keys.get("db_key") is None, "no replacement key was written"
    keys.put("db_key", original)
    await node.start()
    assert [g["name"] for g in node.daemon.list_groups()] == ["g"]


async def test_a_second_daemon_on_the_same_data_dir_fails_fast(cluster: Cluster) -> None:
    node = await cluster.node("solo")
    with pytest.raises(DataDirLockedError, match="another agentconnect daemon"):
        node._make()
    # The running daemon is unaffected, and its keys weren't touched.
    gid = node.daemon.create_group("still mine", "")
    await node.idle()
    await node.restart()  # stop releases the lock
    assert [g["group_id"] for g in node.daemon.list_groups()] == [gid]
