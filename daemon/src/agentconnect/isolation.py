"""Separate-OS-user mode: the daemon under a user of its own (``docs/isolation.md``).

Code running as the daemon's OS user can read every file the daemon can,
``human-token`` included (ADR-005, Decision 4). With ``isolation.enabled`` the
daemon runs as its own user (``agentconnect``) and agents run as other users:

* The data directory (keys, databases, both tokens) stays private to the
  daemon's user, 0700 and 0600. The daemon refuses to start when it, a token
  or the agent directory is looser, when it runs as root, or when the API is
  on TCP (a TCP peer has no credentials to check).
* Agents use a separate **agent directory** (``isolation.agent_dir``, owned by
  the daemon's user and ``isolation.group``, no access for others). It holds
  only agent-scope material: the API socket (0660) and copies of ``api-token``
  and ``webhook-secret`` (0640). Agents point ``AC_DATA_DIR`` at it.
* Every connection's peer UID comes from the kernel (``SO_PEERCRED`` on
  Linux, ``getpeereid(2)`` on macOS and the BSDs, which reads
  ``LOCAL_PEERCRED``). A UID that is not the daemon's own, an agent user or
  a human user is logged and refused before the request is read.
* The human token is accepted only from the daemon's UID or a configured
  human UID. This is on top of the token, not instead of it.

The human reaches the human-only routes with ``sudo -u agentconnect
agentconnect ... --config /etc/agentconnect/config.toml``: the CLI then runs
as the daemon's user, reads ``human-token`` from the data directory and
connects with the daemon's UID. There is no second socket and no second copy
of the human token.

:class:`PeerGate` is the hook the API server calls; it is disabled (every
check passes) unless the mode is on. The credential provider is injectable,
so tests need no second OS user.
"""

from __future__ import annotations

import contextlib
import ctypes
import grp
import os
import pwd
import socket
import stat
import struct
import tempfile
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agentconnect import log
from agentconnect.config import Config

LOG = log.get("agentconnect.isolation")

# Files in the data directory that must stay private to the daemon's user.
PRIVATE_FILES = ("api-token", "human-token", "webhook-secret")
# Agent-scope files copied into the agent directory. Never the human token.
AGENT_FILES = ("api-token", "webhook-secret")
SOCKET_MODE = 0o660
AGENT_FILE_MODE = 0o640
AGENT_DIR_MODE = 0o750

_UCRED = struct.Struct("=iII")  # Linux struct ucred: pid_t pid, uid_t uid, gid_t gid


class IsolationError(RuntimeError):
    """The separate-OS-user mode can't start safely with this setup."""


@dataclass(frozen=True)
class PeerCred:
    """Who is on the other end of a Unix socket, as the kernel reports it."""

    uid: int
    gid: int
    pid: int | None = None


CredentialProvider = Callable[[Any], PeerCred]


def getpeereid(fd: int, libc: Any = None) -> PeerCred:
    """``getpeereid(2)``: macOS and the BSDs (built on ``LOCAL_PEERCRED``)."""
    if libc is None:
        libc = ctypes.CDLL(None, use_errno=True)
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    if libc.getpeereid(fd, ctypes.byref(uid), ctypes.byref(gid)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return PeerCred(uid=uid.value, gid=gid.value)


def peer_credentials(sock: Any) -> PeerCred:
    """The peer's credentials for a connected Unix socket. ``SO_PEERCRED``
    where the platform has it (Linux), ``getpeereid(2)`` otherwise."""
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred, _UCRED.size)
        pid, uid, gid = _UCRED.unpack(raw)
        return PeerCred(uid=uid, gid=gid, pid=pid)
    return getpeereid(sock.fileno())


def resolve_uid(user: str) -> int:
    """A user name or a decimal UID as a UID."""
    if user.isdigit():
        return int(user)
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        msg = f"isolation: no such user {user!r}"
        raise IsolationError(msg) from None


def resolve_gid(group: str) -> int:
    """A group name or a decimal GID as a GID."""
    if group.isdigit():
        return int(group)
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        msg = f"isolation: no such group {group!r}"
        raise IsolationError(msg) from None


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def check_private(path: Path, euid: int, *, directory: bool) -> None:
    """``path``, if it exists, is a real directory (or regular file) owned by
    ``euid`` with no group or other bits. Raises :class:`IsolationError`."""
    st = _lstat(path)
    if st is None:
        return
    kind_ok = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    want = "0700" if directory else "0600"
    if not kind_ok:
        msg = f"{path} must be a {'directory' if directory else 'regular file'}, not a link"
        raise IsolationError(msg)
    if st.st_uid != euid or st.st_mode & 0o077:
        msg = f"{path} must be owned by the daemon's user (UID {euid}) with mode {want}"
        raise IsolationError(msg)


def check_data_dir(data_dir: Path, euid: int) -> None:
    """The data directory and its secret files are private to the daemon's
    user. A missing directory is fine: the daemon creates it 0700."""
    check_private(data_dir, euid, directory=True)
    for name in PRIVATE_FILES:
        check_private(data_dir / name, euid, directory=False)


def check_agent_dir(agent_dir: Path, euid: int, gid: int) -> None:
    """The agent directory exists (it is created if its parent allows), is
    owned by the daemon's user and the agent group, and gives others nothing."""
    st = _lstat(agent_dir)
    if st is None:
        try:
            agent_dir.mkdir(mode=0o700)
            os.chown(agent_dir, -1, gid)
            agent_dir.chmod(AGENT_DIR_MODE)
        except OSError as e:
            msg = f"cannot create {agent_dir}: {e.strerror}; create it (see docs/isolation.md)"
            raise IsolationError(msg) from None
        st = agent_dir.lstat()
    if not stat.S_ISDIR(st.st_mode):
        msg = f"{agent_dir} must be a directory, not a link"
        raise IsolationError(msg)
    if st.st_uid != euid or st.st_gid != gid:
        msg = f"{agent_dir} must be owned by UID {euid} and GID {gid}"
        raise IsolationError(msg)
    if st.st_mode & 0o007 or not st.st_mode & 0o010:
        msg = f"{agent_dir} must have mode 0750 or 0710 (group access, none for others)"
        raise IsolationError(msg)


def _inside(a: Path, b: Path) -> bool:
    a, b = a.resolve(), b.resolve()
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def check_config(cfg: Config, euid: int, agent_uids: set[int], human_uids: set[int]) -> None:
    """The parts of the setup that don't need the filesystem."""
    if euid == 0:
        msg = "isolation: don't run the daemon as root; run it as its own user"
        raise IsolationError(msg)
    if cfg.api_tcp_port:
        msg = "isolation needs the Unix socket: a TCP peer's user can't be checked"
        raise IsolationError(msg)
    if agent_uids & human_uids:
        msg = "isolation: a user can't be both an agent user and a human user"
        raise IsolationError(msg)
    if euid in agent_uids:
        msg = "isolation: the daemon's own user can't be an agent user"
        raise IsolationError(msg)
    if cfg.socket_path.parent != cfg.isolation_agent_dir:
        msg = "isolation: api.socket must be in isolation.agent_dir"
        raise IsolationError(msg)
    if _inside(cfg.isolation_agent_dir, cfg.data_dir):
        msg = "isolation: agent_dir and data_dir must not contain each other"
        raise IsolationError(msg)


def _write_shared(path: Path, data: bytes, gid: int) -> None:
    """Atomically replace ``path`` with ``data``, mode 0640, group ``gid``.
    The temporary file is created 0600 and widened only after the chown."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        try:
            os.fchown(fd, -1, gid)
            os.fchmod(fd, AGENT_FILE_MODE)
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


class _Transport(Protocol):
    def get_extra_info(self, name: str, default: Any = None) -> Any: ...


# The peer of the connection being served. Each connection is its own task,
# so the value never leaks from one connection to another.
_PEER: ContextVar[PeerCred | None] = ContextVar("agentconnect_api_peer", default=None)


class PeerGate:
    """The API server's peer-credential checks. Every check passes when the
    separate-OS-user mode is off (the socket is 0600 then)."""

    def __init__(  # noqa: PLR0913 - keyword-only settings
        self,
        *,
        enabled: bool = False,
        runtime_uid: int = -1,
        agent_uids: Iterable[int] = (),
        human_uids: Iterable[int] = (),
        gid: int = -1,
        data_dir: Path | None = None,
        agent_dir: Path | None = None,
        credentials: CredentialProvider = peer_credentials,
    ) -> None:
        self.enabled = enabled
        self.runtime_uid = runtime_uid
        self.gid = gid
        self.data_dir, self.agent_dir = data_dir, agent_dir
        self._human = frozenset({runtime_uid, *human_uids})
        self._allowed = self._human | frozenset(agent_uids)
        self._credentials = credentials

    @classmethod
    def from_config(
        cls,
        cfg: Config,
        *,
        credentials: CredentialProvider = peer_credentials,
        euid: int | None = None,
    ) -> PeerGate:
        """The gate for ``cfg``. With the mode on, first checks the setup and
        raises :class:`IsolationError` if anything is unsafe."""
        if not cfg.isolation:
            return cls()
        euid = os.geteuid() if euid is None else euid
        agent_uids = {resolve_uid(u) for u in cfg.isolation_agent_users}
        human_uids = {resolve_uid(u) for u in cfg.isolation_human_users}
        gid = resolve_gid(cfg.isolation_group)
        check_config(cfg, euid, agent_uids, human_uids)
        check_data_dir(cfg.data_dir, euid)
        check_agent_dir(cfg.isolation_agent_dir, euid, gid)
        return cls(
            enabled=True,
            runtime_uid=euid,
            agent_uids=agent_uids,
            human_uids=human_uids,
            gid=gid,
            data_dir=cfg.data_dir,
            agent_dir=cfg.isolation_agent_dir,
            credentials=credentials,
        )

    def admit(self, transport: _Transport) -> bool:
        """Check the connection's peer. ``False``: refuse it unread."""
        if not self.enabled:
            return True
        sock = transport.get_extra_info("socket")
        try:
            if sock is None:
                raise OSError("no socket")
            cred = self._credentials(sock)
        except OSError:
            LOG.warning("api_peer_unknown")
            return False
        if cred.uid not in self._allowed:
            LOG.warning("api_peer_refused", uid=cred.uid, pid=cred.pid)
            return False
        _PEER.set(cred)
        return True

    def human_allowed(self) -> bool:
        """Whether the current connection's peer may use the human token."""
        if not self.enabled:
            return True
        cred = _PEER.get()
        if cred is not None and cred.uid in self._human:
            return True
        LOG.warning("api_human_refused", uid=None if cred is None else cred.uid)
        return False

    def publish(self, socket_path: Path) -> None:
        """Open the socket to the agent group and copy the agent-scope files
        into the agent directory."""
        if not self.enabled or self.data_dir is None or self.agent_dir is None:
            return
        os.chown(socket_path, -1, self.gid)  # group first, then widen the mode
        socket_path.chmod(SOCKET_MODE)
        for name in AGENT_FILES:
            with contextlib.suppress(FileNotFoundError):
                _write_shared(self.agent_dir / name, (self.data_dir / name).read_bytes(), self.gid)
        LOG.info("agent_dir_published")
