"""Where the local API's Unix socket is bound, when its path is too long.

A Unix socket path is limited by ``sun_path``: 104 bytes on macOS and the
BSDs, 108 on Linux, the terminating NUL included. macOS temporary and
``~/Library`` paths, deep ``$XDG_DATA_HOME`` directories and long agent
names can exceed it. A socket whose configured path is longer than
:data:`MAX_SOCKET_PATH` is bound at a short path instead:

    /tmp/agentconnect-<uid>/<16 hex digits of SHA-256(configured path)>.sock

The mapping is a pure function of the configured path, so the runtime that
binds and the CLI or SDK that connects compute the same short path from the
same data directory; nothing else needs to advertise it. The directory is
created 0700 and owned by the user, and refused when it is anything else (a
symlink, another owner, a group- or world-accessible mode), so the socket
keeps the protection of a private directory. ``/tmp`` rather than
``$TMPDIR``: the CLI must find the same directory from any shell, and macOS
gives ``$TMPDIR`` long per-session paths.

``/tmp`` cleaners such as systemd-tmpfiles remove entries that weren't used for
a while (10 days by default). The runtime refreshes the socket's times on
every connection; an agent nobody connects to for that long can lose its
socket (the CLI then reports it isn't running until the agent restarts).
Exclude the directory to avoid that, with a tmpfiles.d line
``x /tmp/agentconnect-*``.

Another local user can create ``/tmp/agentconnect-<uid>`` first; the runtime
then refuses to start with a clear error rather than use it.

Clients (the CLI, the SDK, ``agentconnect mcp`` attached to a runtime) reach
the socket only through :func:`local_transport` or
:func:`local_async_transport`, which check each connection before writing a
byte: a socket at the short path must sit in that same private directory and
be a socket (``lstat``), and on every path the server's UID, from the kernel,
must be the owner of the directory the token was read from
(:func:`token_owner`). Anything else is :class:`PeerMismatchError`, so a
squatter's socket gets no token and can't forge an answer.

Separate-OS-user mode needs the socket in its agent directory, where agents'
users can reach it; there the over-long path is refused at startup instead
(:func:`agentconnect.isolation.check_config`).
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, override

import httpcore
import httpx

if TYPE_CHECKING:
    from agentconnect.isolation import PeerCred

# The longest path the most restrictive supported platform (macOS, 104
# bytes with the NUL) can bind; Linux allows 107.
MAX_SOCKET_PATH = 103
PRIVATE_DIR = 0o700
SHORT_ROOT = Path("/tmp")  # noqa: S108 - a private 0700 directory under it, checked
SHORT_PREFIX = "agentconnect-"
# httpx's default pool limits, which the local transports keep.
_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=5.0)


class SocketPathError(OSError):
    """The short socket directory isn't safe to use."""


class PeerMismatchError(httpx.ConnectError):
    """The local API socket isn't the daemon's: another user serves it, or
    its short directory isn't private. Nothing was sent. The message names
    the path and the UIDs, never a token."""

    code = "peer_mismatch"


def too_long(path: Path) -> bool:
    return len(os.fsencode(path)) > MAX_SOCKET_PATH


def bind_path(path: Path) -> Path:
    """The path the socket configured at ``path`` is bound and reached at."""
    if not too_long(path):
        return path
    # resolve(): a symlinked or relative spelling of the same directory must
    # map to the same socket, or the CLI wouldn't find the runtime's.
    digest = hashlib.sha256(os.fsencode(path.resolve())).hexdigest()[:16]
    return SHORT_ROOT / f"{SHORT_PREFIX}{os.geteuid()}" / f"{digest}.sock"


def _private_dir_problem(directory: Path) -> str | None:
    """Why ``directory`` isn't a real directory, ours, with no group or
    other access; ``None`` when it is. Raises ``FileNotFoundError``."""
    st = directory.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return f"{directory} must be a directory, not a symlink or a file"
    if st.st_uid != os.geteuid():
        return f"{directory} must be owned by this user"
    if stat.S_IMODE(st.st_mode) != PRIVATE_DIR:
        return f"{directory} must have mode 0700"
    return None


def prepare_bind_dir(socket: Path) -> None:
    """Create the short socket directory (0700) if needed, and check that it
    is a real directory, ours, with no group or other access."""
    directory = socket.parent
    try:
        directory.mkdir(mode=PRIVATE_DIR)
    except FileExistsError:
        pass  # checked below; one someone else made is refused
    else:
        directory.chmod(PRIVATE_DIR)  # a strict umask mustn't leave it 0500
    problem = _private_dir_problem(directory)
    if problem is not None:
        raise SocketPathError(problem)


# -- the client side: every local-API client connects through these ----------

CredentialProvider = Callable[[Any], "PeerCred"]


def _system_credentials(sock: Any) -> PeerCred:
    # isolation imports this module, so it is imported here; looked up on
    # each call, so tests can replace it there.
    from agentconnect import isolation  # noqa: PLC0415

    return isolation.peer_credentials(sock)


def token_owner(token_dir: Path) -> int:
    """The UID the daemon must run as: the owner of the directory the token
    was read from. Whoever owns it already holds the token, so trusting that
    UID adds nothing. A directory that doesn't exist (a token passed in
    directly) means this user."""
    try:
        return token_dir.stat().st_uid
    except FileNotFoundError:
        return os.geteuid()


class _Check:
    """The checks around ``connect()``: the short directory before it, the
    server's UID after it, both before a byte is written."""

    def __init__(
        self, expected: Iterable[int], whose: str, credentials: CredentialProvider | None
    ) -> None:
        self.expected = frozenset(expected)
        self.whose = whose  # who the expected UIDs are, for the refusal
        self._credentials = credentials or _system_credentials

    @classmethod
    def token_dir_owner(cls, token_dir: Path, credentials: CredentialProvider | None) -> _Check:
        return cls({token_owner(token_dir)}, f"the owner of {token_dir}", credentials)

    @staticmethod
    def before(path: str) -> None:
        socket = Path(path)
        directory = socket.parent
        if directory.parent != SHORT_ROOT or not directory.name.startswith(SHORT_PREFIX):
            return  # a configured path: the UID check below covers it
        try:
            problem = _private_dir_problem(directory)
            if problem is None and not stat.S_ISSOCK(socket.lstat().st_mode):
                problem = f"{socket} is not a socket"
        except FileNotFoundError:
            msg = f"no socket at {socket}"
            raise httpcore.ConnectError(msg) from None
        if problem is not None:
            raise PeerMismatchError(f"{problem}; refusing to connect, nothing was sent")

    def after(self, sock: Any, path: str) -> None:
        try:
            if sock is None:
                raise OSError("no socket")
            uid = self._credentials(sock).uid
        except OSError:
            msg = f"cannot read the credentials of the server at {path}; nothing was sent"
            raise PeerMismatchError(msg) from None
        if uid not in self.expected:
            wanted = " or ".join(str(u) for u in sorted(self.expected)) or "none"
            msg = (
                f"the socket at {path} is served by uid {uid}, not uid {wanted} "
                f"({self.whose}); nothing was sent"
            )
            raise PeerMismatchError(msg)


_TCP_REFUSED = "only the Unix socket is dialled"


class _SyncBackend(httpcore.NetworkBackend):
    def __init__(self, check: _Check) -> None:
        self._inner = httpcore.SyncBackend()
        self._check = check

    # The signatures are httpcore's, `timeout` included.
    @override
    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        self._check.before(path)
        stream = self._inner.connect_unix_socket(path, timeout, socket_options)
        try:
            self._check.after(stream.get_extra_info("socket"), path)
        except BaseException:
            stream.close()
            raise
        return stream

    @override
    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError(_TCP_REFUSED)

    @override
    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _AsyncBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, check: _Check) -> None:
        self._inner = cast("httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend())
        self._check = check

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self._check.before(path)
        stream = await self._inner.connect_unix_socket(path, timeout, socket_options)
        try:
            self._check.after(stream.get_extra_info("socket"), path)
        except BaseException:
            await stream.aclose()
            raise
        return stream

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError(_TCP_REFUSED)

    @override
    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def local_transport(
    socket: Path, token_dir: Path, *, credentials: CredentialProvider | None = None
) -> httpx.BaseTransport:
    """The CLI's transport to the daemon's socket configured at ``socket``
    (mapped by :func:`bind_path`). Each connection is checked before a byte
    is written: the short directory with ``lstat``, then the server's UID
    against :func:`token_owner` of ``token_dir``; a failure is
    :class:`PeerMismatchError`. ``credentials`` replaces the kernel's
    answer in tests."""
    path = str(bind_path(socket))
    transport = httpx.HTTPTransport(uds=path, trust_env=False)
    # httpx takes no network backend, so its pool is replaced by one that
    # checks the server (as ownerfile.pinned_transport does).
    transport._pool = httpcore.ConnectionPool(
        max_connections=_LIMITS.max_connections,
        max_keepalive_connections=_LIMITS.max_keepalive_connections,
        keepalive_expiry=_LIMITS.keepalive_expiry,
        uds=path,
        network_backend=_SyncBackend(_Check.token_dir_owner(token_dir, credentials)),
    )
    return transport


def local_async_transport(
    socket: Path, token_dir: Path, *, credentials: CredentialProvider | None = None
) -> httpx.AsyncBaseTransport:
    """:func:`local_transport` for asyncio: the SDK and MCP attach."""
    path = str(bind_path(socket))
    transport = httpx.AsyncHTTPTransport(uds=path, trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(
        max_connections=_LIMITS.max_connections,
        max_keepalive_connections=_LIMITS.max_keepalive_connections,
        keepalive_expiry=_LIMITS.keepalive_expiry,
        uds=path,
        network_backend=_AsyncBackend(_Check.token_dir_owner(token_dir, credentials)),
    )
    return transport


def receiver_async_transport(
    socket: Path, uids: Iterable[int], *, credentials: CredentialProvider | None = None
) -> httpx.AsyncBaseTransport:
    """The daemon's transport to a receiver it delivers to (the webhook, the
    local A2A agent) on the Unix socket at ``socket``: every request goes
    there, whatever its URL names, and each connection's server must run as
    one of ``uids`` before a byte is written (:class:`PeerMismatchError`
    otherwise; the caller retries). ``credentials`` replaces the kernel's
    answer in tests."""
    path = str(socket)
    transport = httpx.AsyncHTTPTransport(uds=path, trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(
        max_connections=_LIMITS.max_connections,
        max_keepalive_connections=_LIMITS.max_keepalive_connections,
        keepalive_expiry=_LIMITS.keepalive_expiry,
        uds=path,
        network_backend=_AsyncBackend(_Check(uids, "a user this daemon delivers to", credentials)),
    )
    return transport
