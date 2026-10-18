"""Secrets at rest: the OS keyring when available, else 0600 key files.

The keystore holds the identity key, the instance key, the DB key and
invite secrets. Values never appear in logs, ``repr`` or error messages.

Files and directories the daemon creates are private: directories 0700,
files 0600 (see :func:`private_dir` and :func:`private_file`).
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Protocol, override

import keyring
import keyring.backend
import keyring.errors

SERVICE = "agentconnect"
_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,40}(/[A-Za-z0-9_-]{1,64})?$")


class KeystoreError(RuntimeError):
    """The keystore could not read or write a secret."""


def private_dir(path: Path) -> Path:
    """Create ``path`` (and parents) and make it 0700."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def private_file(path: Path) -> Path:
    """Create ``path`` empty if missing and make it 0600."""
    private_dir(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    path.chmod(0o600)
    return path


def write_private(path: Path, data: bytes) -> None:
    """Atomically replace ``path`` with ``data``, mode 0600: write a fresh
    temporary file (unique name, created 0600) in the same directory, fsync
    it, then ``os.replace`` it into place."""
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class DataDirLockedError(RuntimeError):
    """Another runtime (a daemon or an embedded agent) holds the data directory."""


class DataDirLock:
    """An exclusive ``flock`` on ``<data_dir>/daemon.lock``, held for the
    runtime's lifetime, so two runtimes (a daemon, an embedded agent, or a
    tool that opens the same state) never share keys, databases or a mailbox.

    The holder writes ``<owner> <pid>`` into the file, so a second runtime
    can say who has the directory. That note is informational only: the
    ``flock`` is the lock."""

    FILE = "daemon.lock"

    def __init__(self, data_dir: Path, owner: str = "daemon") -> None:
        private_dir(data_dir)
        path = data_dir / self.FILE
        self._fd: int | None = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holder = self._holder(self._fd)
            os.close(self._fd)
            self._fd = None
            msg = (
                f"another agentconnect runtime ({holder}) is using {data_dir}: "
                "stop it, or use another data directory"
            )
            raise DataDirLockedError(msg) from None
        os.ftruncate(self._fd, 0)
        os.pwrite(self._fd, f"{owner} {os.getpid()}\n".encode("ascii"), 0)

    @staticmethod
    def _holder(fd: int) -> str:
        """``an embedded agent, pid 123`` from the holder's note, or
        ``unknown`` when it's missing or not ours."""
        words = os.pread(fd, 64, 0).decode("ascii", "replace").split()
        names = {"daemon": "a daemon", "embedded": "an embedded agent"}
        if len(words) != 2 or words[0] not in names or not words[1].isdigit():  # noqa: PLR2004
            return "unknown"
        return f"{names[words[0]]}, pid {words[1]}"

    def release(self) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


def _check_name(name: str) -> str:
    if not _NAME.match(name):
        msg = "invalid secret name"
        raise KeystoreError(msg)
    return name


class Keystore(Protocol):
    """Named secrets (bytes)."""

    kind: str

    def get(self, name: str) -> bytes | None: ...
    def put(self, name: str, value: bytes) -> None: ...
    def delete(self, name: str) -> None: ...


class FileKeystore:
    """One 0600 file per secret in a 0700 directory."""

    kind = "file"

    def __init__(self, directory: Path) -> None:
        self._dir = private_dir(directory)

    @override
    @override
    def __repr__(self) -> str:
        return "FileKeystore(...)"

    def _path(self, name: str) -> Path:
        return self._dir / _check_name(name).replace("/", "__")

    def get(self, name: str) -> bytes | None:
        p = self._path(name)
        try:
            return p.read_bytes()
        except FileNotFoundError:
            return None

    def put(self, name: str, value: bytes) -> None:
        write_private(self._path(name), value)

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)


class KeyringKeystore:
    """The OS keyring (Secret Service, macOS Keychain, Windows Credential Locker).

    Entries live under service ``agentconnect``, with a user name scoped to
    the data directory so several daemons on one host don't collide.
    """

    kind = "keyring"

    def __init__(self, scope: str, backend: keyring.backend.KeyringBackend | None = None) -> None:
        self._scope = hashlib.sha256(scope.encode()).hexdigest()[:16]
        self._backend = backend or keyring.get_keyring()

    @override
    @override
    def __repr__(self) -> str:
        return "KeyringKeystore(...)"

    def _user(self, name: str) -> str:
        return f"{self._scope}/{_check_name(name)}"

    def get(self, name: str) -> bytes | None:
        try:
            raw = self._backend.get_password(SERVICE, self._user(name))
        except keyring.errors.KeyringError:
            msg = "keyring read failed"
            raise KeystoreError(msg) from None
        return None if raw is None else base64.b64decode(raw)

    def put(self, name: str, value: bytes) -> None:
        try:
            self._backend.set_password(SERVICE, self._user(name), base64.b64encode(value).decode())
        except keyring.errors.KeyringError:
            msg = "keyring write failed"
            raise KeystoreError(msg) from None

    def delete(self, name: str) -> None:
        with contextlib.suppress(keyring.errors.PasswordDeleteError):
            self._backend.delete_password(SERVICE, self._user(name))


def keyring_usable(backend: keyring.backend.KeyringBackend | None = None) -> bool:
    """Whether a real keyring backend is configured (not the fail/null ones)."""
    backend = backend or keyring.get_keyring()
    module = type(backend).__module__
    if module.startswith(("keyring.backends.fail", "keyring.backends.null")):
        return False
    try:
        return float(backend.priority) > 0
    except Exception:
        return False


def open_keystore(
    kind: str,
    data_dir: Path,
    backend: keyring.backend.KeyringBackend | None = None,
) -> Keystore:
    """``auto`` picks the keyring when usable, otherwise key files."""
    if kind == "file" or (kind == "auto" and not keyring_usable(backend)):
        return FileKeystore(data_dir / "keys")
    if kind in ("keyring", "auto"):
        if not keyring_usable(backend):
            msg = "no usable OS keyring"
            raise KeystoreError(msg)
        return KeyringKeystore(str(data_dir.resolve()), backend)
    msg = f"unknown keystore {kind!r}"
    raise KeystoreError(msg)
