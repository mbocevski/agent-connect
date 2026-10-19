"""Provisioning a replica: the identity key from one data directory into a
fresh one, with a fresh instance (SPEC 9.4, ADR-005 Decision 5).

``agentconnect identity export`` and ``identity import`` are the only way
in. Both are human-only and CLI-only: no local API route, SDK call or MCP
tool reaches this module, because whoever holds the identity key can add
instances that every member accepts (SPEC 12).

- **Export** wraps ``IK``'s secret under a fresh random 32-byte key in the
  core (ChaCha20-Poly1305, AAD ``agentconnect/v0/identity-export``) and
  writes the file 0600, never over an existing one. The key is the export
  code: the CLI shows it once, and the human carries it apart from the file.
- **Import** opens the file with the code into a data directory that holds
  no identity, instance, database key or MLS store, and creates a fresh
  instance there: its own signing key and ``instance_id``, never the
  exporting instance's. A copied data directory has those, so it is refused:
  a copy is not a replica (two runtimes on one leaf break the group).

Both take the data directory's lock first, so they refuse to run while a
runtime (a daemon, an embedded agent, an MCP server) holds it, and nothing
starts on the directory meanwhile.

Nothing here logs. The secret is zeroized inside the core; in Python it
passes once as ``bytes`` into the keystore, and the code is a ``str``,
neither of which can be zeroized (the residual exposure noted in
:mod:`agentconnect.identity`).
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any

import agentconnect_core as ac
from agentconnect.config import Config
from agentconnect.keystore import DataDirLock, DataDirLockedError, Keystore, open_keystore

# What makes a data directory an instance already: its keys and databases.
STATE_KEYS = ("identity", "instance", "db_key")
STATE_FILES = ("mls.sqlite3", "daemon.sqlite3")

EXPORT_WARNING = (
    "Whoever has both this file and the code holds the identity: every host you "
    "import it on can speak as this agent in every group. Carry the code apart "
    "from the file (not in the same message or folder), import it once, then "
    "delete the file."
)


class ProvisionError(Exception):
    """A refused export or import: a machine-readable code and a message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


@contextlib.contextmanager
def _locked(data_dir: Path) -> Generator[None]:
    try:
        lock = DataDirLock(data_dir, note=False)
    except DataDirLockedError as e:
        msg = f"{e}; provisioning works only on a stopped runtime's data directory"
        raise ProvisionError("runtime_running", msg) from None
    try:
        yield
    finally:
        lock.release()


def _write_new(path: Path, data: bytes) -> None:
    """Write ``data`` to a new file created 0600; never replace or follow a
    link to an existing one."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        msg = f"{path} exists: an export never replaces a file, choose another path"
        raise ProvisionError("exists", msg) from None
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def export_identity(config: Config, out: Path, keystore: Keystore | None = None) -> dict[str, Any]:
    """Wrap this data directory's identity into ``out``: the file's path,
    the identity, its fingerprint and the code (to show once)."""
    with _locked(config.data_dir):
        store = keystore or open_keystore(config.keystore, config.data_dir)
        secret = store.get("identity")
        if secret is None:
            msg = f"{config.data_dir} has no identity to export"
            raise ProvisionError("no_identity", msg)
        identity = ac.Identity.from_secret_bytes(secret)
        file, code = ac.wrap_identity_export(identity)
        _write_new(out, file)
    return {
        "file": str(out),
        "identity": identity.id,
        "fingerprint": identity.fingerprint,
        "code": code,
        "warning": EXPORT_WARNING,
    }


def read_export(path: Path) -> bytes:
    """An export file's bytes (at most the core's limit)."""
    try:
        with path.open("rb") as f:
            data = f.read(ac.MAX_IDENTITY_EXPORT_LEN + 1)
    except OSError as e:
        msg = f"can't read {path}: {e.strerror}"
        raise ProvisionError("bad_export", msg) from None
    if len(data) > ac.MAX_IDENTITY_EXPORT_LEN:
        raise ProvisionError("bad_export", f"{path} is not an identity export (too large)")
    return data


def export_identity_id(data: bytes) -> str:
    """The identity an export file names, read without its code."""
    try:
        return ac.identity_export_identity(data)
    except ac.AgentConnectError as e:
        raise _open_error(e) from None


def _open_error(e: ac.AgentConnectError) -> ProvisionError:
    kind = getattr(e, "kind", None)
    if kind == "authentication":
        msg = "the code does not open this file: check the code, or export again"
        return ProvisionError("bad_code", msg)
    if kind == "unsupported_version":
        msg = (
            "the file is from another identity export format version: export it "
            "again with this version of agentconnect"
        )
        return ProvisionError("unsupported_version", msg)
    if "export code" in str(e):
        msg = "the code is not an export code: give the 43 characters export printed"
        return ProvisionError("bad_code", msg)
    msg = "the file is not an identity export, or it is damaged (cut short?)"
    return ProvisionError("bad_export", msg)


def _check_fresh(config: Config, store: Keystore) -> None:
    """Refuse a data directory that is an instance already, or a copy of one."""
    found = [name for name in STATE_KEYS if store.get(name) is not None]
    found += [name for name in STATE_FILES if (config.data_dir / name).exists()]
    keys = config.data_dir / "keys"
    if not found and keys.is_dir() and any(keys.iterdir()):
        found.append("keys/")
    if found:
        msg = (
            f"{config.data_dir} already holds an instance ({', '.join(found)}): import "
            "only into a new, empty data directory (a copied one is not a replica)"
        )
        raise ProvisionError("not_empty", msg)


def import_identity(
    config: Config, data: bytes, code: str, keystore: Keystore | None = None
) -> dict[str, Any]:
    """Open an export into this fresh data directory and create a new
    instance for it: the identity, its fingerprint and the new
    ``instance_id``."""
    with _locked(config.data_dir):
        store = keystore or open_keystore(config.keystore, config.data_dir)
        _check_fresh(config, store)
        try:
            identity = ac.unwrap_identity_export(data, code)
        except ac.AgentConnectError as e:
            raise _open_error(e) from None
        instance = identity.create_instance()
        store.put("identity", identity.secret_bytes())
        store.put("instance", instance.to_secret_bytes())
    return {
        "identity": identity.id,
        "fingerprint": identity.fingerprint,
        "instance_id": instance.instance_id_hex,
        "data_dir": str(config.data_dir),
    }
