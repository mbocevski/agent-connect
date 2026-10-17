"""The daemon's identity, its instance, and the core MLS client.

One identity per agent and one instance per daemon (SPEC §2). Both are
created through the core bindings on first start and kept in the
:mod:`keystore`; nothing here ever logs or prints them.

Residual exposure: the identity secret, the instance (with its signing
key) and ``db_key`` are handled here as Python ``bytes`` to store them and
to open the core client, so they stay in the Python heap, which can't be
zeroized, for the life of the process. Signing itself happens in the core.

The core's MLS store is a SQLCipher database encrypted under a 32-byte
``db_key``, created on first start and kept in the keystore next to the
identity. :func:`open_core_client` is the one place that key reaches the
core. The data directory is 0700 and every database file 0600 on top.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import agentconnect_core as ac
from agentconnect.keystore import Keystore, KeystoreError, private_file

DB_KEY_LEN = ac.DB_KEY_LEN


@dataclass(frozen=True)
class Seeded:
    """Seeded randomness for tests (guessable keys: never in production)."""

    seed: int

    def derive(self, label: str) -> int:
        digest = hashlib.sha256(f"{self.seed}:{label}".encode()).digest()
        return int.from_bytes(digest[:8], "big")


def _load_or_create(store: Keystore, name: str, make: Callable[[], bytes]) -> bytes:
    value = store.get(name)
    if value is None:
        value = make()
        store.put(name, value)
    return value


def load_identity(store: Keystore, testing: Seeded | None = None) -> ac.Identity:
    def make() -> bytes:
        ident = (
            ac.Identity._generate_for_testing(testing.derive("identity"))
            if testing
            else ac.Identity.generate()
        )
        return ident.secret_bytes()

    return ac.Identity.from_secret_bytes(_load_or_create(store, "identity", make))


def load_instance(
    store: Keystore, identity: ac.Identity, testing: Seeded | None = None
) -> ac.Instance:
    def make() -> bytes:
        inst = (
            identity._create_instance_for_testing(seed=testing.derive("instance"))
            if testing
            else identity.create_instance()
        )
        return inst.to_secret_bytes()

    instance = ac.Instance.from_secret_bytes(_load_or_create(store, "instance", make))
    if instance.identity != identity.id:
        msg = "stored instance belongs to another identity"
        raise ValueError(msg)
    return instance


def load_db_key(store: Keystore, encrypted: Iterable[Path] = ()) -> bytes:
    """The database key, created on first use.

    encrypted lists the files the key protects. If any of them already
    has content, a missing key is an error: a fresh key could never open
    them, and writing it would only hide the problem.
    """
    value = store.get("db_key")
    if value is not None:
        return value
    if any(p.exists() and p.stat().st_size > 0 for p in encrypted):
        msg = "the database key is missing from the keystore; the encrypted stores can't be opened"
        raise KeystoreError(msg)
    return _load_or_create(store, "db_key", lambda: secrets.token_bytes(DB_KEY_LEN))


def open_core_client(
    path: Path,
    instance: ac.Instance,
    db_key: bytes,
    testing: Seeded | None = None,
) -> ac.Client:
    """The core client over its encrypted SQLite file (created 0600)."""
    if len(db_key) != DB_KEY_LEN:
        msg = "db key must be 32 bytes"
        raise ValueError(msg)
    private_file(path)
    secret = instance.to_secret_bytes()
    if testing:
        return ac.Client._for_testing(str(path), secret, testing.derive("client"), db_key=db_key)
    return ac.Client(str(path), secret, db_key=db_key)
