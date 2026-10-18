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

Separate-OS-user mode needs the socket in its agent directory, where agents'
users can reach it; there the over-long path is refused at startup instead
(:func:`agentconnect.isolation.check_config`).
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

# The longest path the most restrictive supported platform (macOS, 104
# bytes with the NUL) can bind; Linux allows 107.
MAX_SOCKET_PATH = 103
PRIVATE_DIR = 0o700
SHORT_ROOT = Path("/tmp")  # noqa: S108 - a private 0700 directory under it, checked


class SocketPathError(OSError):
    """The short socket directory isn't safe to use."""


def too_long(path: Path) -> bool:
    return len(os.fsencode(path)) > MAX_SOCKET_PATH


def bind_path(path: Path) -> Path:
    """The path the socket configured at ``path`` is bound and reached at."""
    if not too_long(path):
        return path
    # resolve(): a symlinked or relative spelling of the same directory must
    # map to the same socket, or the CLI wouldn't find the runtime's.
    digest = hashlib.sha256(os.fsencode(path.resolve())).hexdigest()[:16]
    return SHORT_ROOT / f"agentconnect-{os.geteuid()}" / f"{digest}.sock"


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
    st = directory.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        msg = f"{directory} must be a directory, not a symlink or a file"
        raise SocketPathError(msg)
    if st.st_uid != os.geteuid():
        msg = f"{directory} must be owned by this user"
        raise SocketPathError(msg)
    if stat.S_IMODE(st.st_mode) != PRIVATE_DIR:
        msg = f"{directory} must have mode 0700"
        raise SocketPathError(msg)
