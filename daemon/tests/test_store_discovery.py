"""The listings and doors tables of the daemon database (docs/discovery.md)."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

import agentconnect_core as ac
from agentconnect.store import Store


def test_the_tables_appear_in_an_existing_database_and_survive_reopening(
    tmp_path: Path, rng: random.Random
) -> None:
    path, key = tmp_path / "d.sqlite3", rng.randbytes(32)
    Store(path, key).close()  # a database from before discovery
    s = Store(path, key)
    assert s.listings() == []
    s.put_listing(
        {
            "directory": "directory.example.org",
            "name": "release-planner",
            "state": "publishing",
            "content": "{}",
            "token": "{}",
            "token_expires_at": 100,
            "created_at": 1,
            "updated_at": 1,
        }
    )
    secret = ac.Door.generate(10_000).to_secret_bytes()
    s.add_door(
        door_id="d1",
        directory="directory.example.org",
        name="release-planner",
        secret=secret,
        expires_at=50,
        now=1,
    )
    s.close()
    s = Store(path, key)
    row = s.listing("directory.example.org", "release-planner")
    assert row is not None
    assert (row["seq"], row["max_signed_seq"], row["attempts"], row["token_warned"]) == (0, 0, 0, 0)
    (door,) = s.doors("directory.example.org", "release-planner")
    assert (door["state"], bytes(door["secret"])) == ("registering", secret)
    assert s.doors("other.example") == []
    s.update_door("d1", state="current", secret=None)
    s.update_listing("directory.example.org", "release-planner", seq=7)
    assert s.doors()[0]["secret"] is None
    assert s.listings()[0]["seq"] == 7
    with pytest.raises(ValueError, match="unknown listing column"):
        s.update_listing("directory.example.org", "release-planner", bogus=1)
    with pytest.raises(ValueError, match="unknown door column"):
        s.update_door("d1", bogus=1)
    s.delete_door("d1")
    assert s.doors() == []
    assert s.listing("directory.example.org", "nothing") is None
    s.close()
