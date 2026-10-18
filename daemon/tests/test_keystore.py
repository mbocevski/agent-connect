import os
import random
import stat
from pathlib import Path
from typing import override

import keyring.backend
import keyring.backends.fail
import keyring.errors
import pytest

from agentconnect.keystore import (
    DataDirLock,
    DataDirLockedError,
    FileKeystore,
    KeyringKeystore,
    KeystoreError,
    keyring_usable,
    open_keystore,
    private_file,
    write_private,
)


class MemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self, fail: bool = False) -> None:
        super().__init__()
        self.data: dict[tuple[str, str], str] = {}
        self.fail = fail

    @override
    def get_password(self, service: str, username: str) -> str | None:
        if self.fail:
            raise keyring.errors.KeyringError
        return self.data.get((service, username))

    @override
    def set_password(self, service: str, username: str, password: str) -> None:
        if self.fail:
            raise keyring.errors.KeyringError
        self.data[(service, username)] = password

    @override
    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.data:
            raise keyring.errors.PasswordDeleteError
        del self.data[(service, username)]


class BrokenPriority(MemoryKeyring):
    @property
    @override
    def priority(self) -> float:  # ty: ignore[invalid-property-type-override]
        raise RuntimeError


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_file_keystore_is_private_and_round_trips(tmp_path: Path, rng: random.Random) -> None:
    ks = FileKeystore(tmp_path / "keys")
    secret = rng.randbytes(32)
    assert ks.get("identity") is None
    ks.put("identity", secret)
    ks.put("invite/AbC-_d", secret[:16])
    assert ks.get("identity") == secret
    assert ks.get("invite/AbC-_d") == secret[:16]
    assert mode(tmp_path / "keys") == 0o700
    for f in (tmp_path / "keys").iterdir():
        assert mode(f) == 0o600
    ks.delete("identity")
    ks.delete("identity")  # idempotent
    assert ks.get("identity") is None
    assert "keys" not in repr(ks)
    assert ks.kind == "file"


@pytest.mark.parametrize("name", ["", "../x", "UPPER", "a/b/c", "a/" + "x" * 65])
def test_secret_names_are_validated(tmp_path: Path, name: str) -> None:
    with pytest.raises(KeystoreError, match="invalid secret name"):
        FileKeystore(tmp_path).get(name)


def test_private_helpers_fix_modes(tmp_path: Path) -> None:
    f = tmp_path / "d" / "db"
    private_file(f)
    f.chmod(0o644)
    private_file(f)
    assert mode(f) == 0o600
    assert mode(f.parent) == 0o700
    write_private(tmp_path / "t", b"x")
    assert mode(tmp_path / "t") == 0o600


def test_keyring_keystore(tmp_path: Path, rng: random.Random) -> None:
    backend = MemoryKeyring()
    ks = KeyringKeystore(str(tmp_path), backend)
    other = KeyringKeystore(str(tmp_path / "other"), backend)
    secret = rng.randbytes(32)
    ks.put("db_key", secret)
    assert ks.get("db_key") == secret
    assert other.get("db_key") is None  # scoped per data directory
    ks.delete("db_key")
    ks.delete("db_key")
    assert ks.get("db_key") is None
    assert repr(ks) == "KeyringKeystore(...)"
    broken = KeyringKeystore(str(tmp_path), MemoryKeyring(fail=True))
    with pytest.raises(KeystoreError, match="read"):
        broken.get("db_key")
    with pytest.raises(KeystoreError, match="write"):
        broken.put("db_key", secret)


def test_open_keystore_selection(tmp_path: Path) -> None:
    good = MemoryKeyring()
    assert keyring_usable(good)
    assert not keyring_usable(BrokenPriority())
    fail = keyring.backends.fail.Keyring()
    assert not keyring_usable(fail)
    assert open_keystore("auto", tmp_path, good).kind == "keyring"
    assert open_keystore("keyring", tmp_path, good).kind == "keyring"
    assert open_keystore("auto", tmp_path, fail).kind == "file"
    assert open_keystore("file", tmp_path, good).kind == "file"
    with pytest.raises(KeystoreError, match="no usable"):
        open_keystore("keyring", tmp_path, fail)
    with pytest.raises(KeystoreError, match="unknown"):
        open_keystore("vault", tmp_path, good)


def test_write_private_is_atomic_and_leaves_no_temp_files(
    tmp_path: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k" / "secret"
    # A stale temp file from an old fixed-name scheme doesn't matter.
    target.parent.mkdir(mode=0o700)
    (target.parent / ".secret.tmp").write_bytes(b"stale")
    value = rng.randbytes(32)
    write_private(target, value)
    assert target.read_bytes() == value
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert sorted(p.name for p in target.parent.iterdir()) == [".secret.tmp", "secret"]

    # A failed write leaves the old value and no temp file behind.
    def boom(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("os.fsync", boom)
    with pytest.raises(OSError, match="disk full"):
        write_private(target, rng.randbytes(32))
    assert target.read_bytes() == value
    assert sorted(p.name for p in target.parent.iterdir()) == [".secret.tmp", "secret"]


def test_the_data_dir_lock_is_exclusive(tmp_path: Path) -> None:
    first = DataDirLock(tmp_path / "data")
    with pytest.raises(DataDirLockedError, match="another agentconnect runtime"):
        DataDirLock(tmp_path / "data")
    assert stat.S_IMODE((tmp_path / "data" / "daemon.lock").stat().st_mode) == 0o600
    first.release()
    first.release()  # idempotent
    DataDirLock(tmp_path / "data").release()


def test_the_data_dir_lock_names_its_holder(tmp_path: Path) -> None:
    first = DataDirLock(tmp_path / "data", "embedded")
    with pytest.raises(DataDirLockedError, match=rf"an embedded agent, pid {os.getpid()}"):
        DataDirLock(tmp_path / "data")
    first.release()
    daemon = DataDirLock(tmp_path / "data")  # the next holder rewrites the note
    with pytest.raises(DataDirLockedError, match=r"\(a daemon, pid \d+\)"):
        DataDirLock(tmp_path / "data", "embedded")
    daemon.release()


def test_the_data_dir_lock_note_is_informational(tmp_path: Path) -> None:
    held = DataDirLock(tmp_path / "data")
    (tmp_path / "data" / "daemon.lock").write_text("something else entirely")
    with pytest.raises(DataDirLockedError, match=r"\(unknown\)"):
        DataDirLock(tmp_path / "data")
    held.release()
