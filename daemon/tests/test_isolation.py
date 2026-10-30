"""Separate-OS-user mode: peer credentials, the UID gates and the permission checks.

No second OS user here: the credential provider is injected. The real
multi-user check is in ``test_isolation_multiuser.py`` (integration tier).
"""

from __future__ import annotations

import contextvars
import ctypes
import os
import pwd
import random
import shutil
import socket
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentconnect import isolation
from agentconnect.apiclient import ApiClientError
from agentconnect.cli import app
from agentconnect.cli_support import EXIT_REFUSED, EXIT_USAGE, map_api_error
from agentconnect.config import ConfigError, load_config
from agentconnect.isolation import (
    AGENT_DIR_MODE,
    IsolationError,
    PeerCred,
    PeerGate,
    check_agent_dir,
    check_config,
    check_data_dir,
    check_parents,
    getpeereid,
    peer_credentials,
    resolve_gid,
    resolve_uid,
)

EUID = os.geteuid()
GID = os.getgid()

pytestmark = pytest.mark.skipif(EUID == 0, reason="the mode refuses to run as root")


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short path: Unix socket paths are limited to about 100 bytes."""
    d = Path(tempfile.mkdtemp(prefix="ac-iso-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _uid(rng: random.Random, *avoid: int) -> int:
    """A UID nobody here runs as (agent UIDs are made up: no second user)."""
    while True:
        uid = rng.randrange(20_000, 60_000)
        if uid not in avoid and uid != EUID:
            return uid


def _secret(rng: random.Random) -> bytes:
    return rng.randbytes(24).hex().encode()


def _setup(short_dir: Path, rng: random.Random, **iso: Any) -> Any:
    data_dir = short_dir / "data"
    data_dir.mkdir(mode=0o700)
    agent_dir = short_dir / "agent"
    agent_dir.mkdir()
    agent_dir.chmod(AGENT_DIR_MODE)
    for name in ("api-token", "human-token", "webhook-secret"):
        (data_dir / name).write_bytes(_secret(rng))
        (data_dir / name).chmod(0o600)
    values: dict[str, Any] = {
        "isolation": True,
        "isolation_agent_dir": agent_dir,
        "isolation_group": str(GID),
    }
    values.update(iso)
    return load_config(
        short_dir / "absent.toml", environ={}, data_dir=data_dir, relay_url="ws://127.0.0.1:1"
    ).with_overrides(**values)


class FakeTransport:
    def __init__(self, sock: object) -> None:
        self.sock = sock

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self.sock if name == "socket" else default


def fixed(uid: int) -> Callable[[Any], PeerCred]:
    return lambda _sock: PeerCred(uid=uid, gid=GID, pid=1)


def in_connection[T](fn: Callable[[], T]) -> T:
    """Run ``fn`` in a fresh context, as each API connection is its own task."""
    return contextvars.copy_context().run(fn)


# -- peer credentials --------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux only")
def test_so_peercred_reports_the_connecting_process() -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a, b:
        cred = peer_credentials(a)
    assert (cred.uid, cred.gid, cred.pid) == (EUID, os.getegid(), os.getpid())


class FakeLibc:
    """``getpeereid`` as libc exposes it to ctypes (macOS and the BSDs)."""

    def __init__(self, uid: int, gid: int, result: int = 0) -> None:
        self.uid, self.gid, self.result = uid, gid, result
        self.fds: list[int] = []

    def getpeereid(self, fd: int, puid: Any, pgid: Any) -> int:
        self.fds.append(fd)
        puid._obj.value, pgid._obj.value = self.uid, self.gid
        return self.result


def test_getpeereid_reads_uid_and_gid(rng: random.Random) -> None:
    uid = _uid(rng)
    libc = FakeLibc(uid, GID)
    assert getpeereid(7, libc) == PeerCred(uid=uid, gid=GID)
    assert libc.fds == [7]
    with pytest.raises(OSError):  # noqa: PT011 - errno comes from libc
        getpeereid(7, FakeLibc(uid, GID, result=-1))


def test_getpeereid_falls_back_when_so_peercred_is_missing(
    monkeypatch: pytest.MonkeyPatch, rng: random.Random
) -> None:
    uid = _uid(rng)
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    monkeypatch.setattr(ctypes, "CDLL", lambda *_a, **_k: FakeLibc(uid, GID))

    class Sock:
        def fileno(self) -> int:
            return 3

    assert peer_credentials(Sock()).uid == uid


def test_users_and_groups_resolve_by_name_or_number(rng: random.Random) -> None:
    assert resolve_uid(str(EUID)) == EUID
    assert resolve_gid(str(GID)) == GID
    assert resolve_uid(pwd.getpwuid(EUID).pw_name) == EUID
    missing = f"ac-missing-{rng.getrandbits(32):08x}"
    with pytest.raises(IsolationError, match="no such user"):
        resolve_uid(missing)
    with pytest.raises(IsolationError, match="no such group"):
        resolve_gid(missing)


# -- data directory and tokens -------------------------------------------------------------


def test_data_dir_and_tokens_must_be_private(short_dir: Path, rng: random.Random) -> None:
    data_dir = short_dir / "data"
    check_data_dir(data_dir, EUID)  # missing: the daemon creates it 0700
    data_dir.mkdir(mode=0o700)
    token = data_dir / "human-token"
    token.write_bytes(_secret(rng))
    token.chmod(0o600)
    check_data_dir(data_dir, EUID)

    with pytest.raises(IsolationError, match="owned by the daemon's user"):
        check_data_dir(data_dir, _uid(rng))  # someone else's directory
    data_dir.chmod(0o750)
    with pytest.raises(IsolationError, match="mode 0700"):
        check_data_dir(data_dir, EUID)
    data_dir.chmod(0o700)
    for loose in (0o640, 0o604, 0o660):
        token.chmod(loose)
        with pytest.raises(IsolationError, match="mode 0600"):
            check_data_dir(data_dir, EUID)
    token.chmod(0o600)

    # A token that is a link (to anything) is refused, so is a linked data dir.
    token.unlink()
    token.symlink_to(short_dir / "elsewhere")
    with pytest.raises(IsolationError, match="regular file"):
        check_data_dir(data_dir, EUID)
    token.unlink()
    link = short_dir / "link"
    link.symlink_to(data_dir)
    with pytest.raises(IsolationError, match="directory"):
        check_data_dir(link, EUID)


def test_agent_dir_permissions(short_dir: Path, rng: random.Random) -> None:
    agent_dir = short_dir / "agent"
    check_agent_dir(agent_dir, EUID, GID)  # created when the parent allows
    st = agent_dir.lstat()
    assert (stat.S_IMODE(st.st_mode), st.st_gid) == (AGENT_DIR_MODE, GID)
    agent_dir.chmod(0o710)
    check_agent_dir(agent_dir, EUID, GID)

    for bad in (0o755, 0o751, 0o700):  # others get something, or the group nothing
        agent_dir.chmod(bad)
        with pytest.raises(IsolationError, match="mode 0750"):
            check_agent_dir(agent_dir, EUID, GID)
    agent_dir.chmod(AGENT_DIR_MODE)
    with pytest.raises(IsolationError, match="owned by"):
        check_agent_dir(agent_dir, _uid(rng), GID)
    with pytest.raises(IsolationError, match="owned by"):
        check_agent_dir(agent_dir, EUID, GID + 1)
    plain = short_dir / "file"
    plain.write_bytes(b"")
    with pytest.raises(IsolationError, match="directory"):
        check_agent_dir(plain, EUID, GID)
    with pytest.raises(IsolationError, match="cannot create"):
        check_agent_dir(short_dir / "no" / "parent", EUID, GID)


def _with_mode(
    monkeypatch: pytest.MonkeyPatch, path: Path, mode: int, uid: int | None = None
) -> None:
    """``path``'s lstat reports ``mode`` (and ``uid``): no chmod, so the
    test never makes anything writable for real."""
    real = isolation._lstat

    def lstat(p: Path) -> os.stat_result | None:
        st = real(p)
        if st is None or Path(p) != path:
            return st
        fields = list(st)
        fields[0] = stat.S_IFMT(st.st_mode) | mode
        if uid is not None:
            fields[4] = uid
        return os.stat_result(fields)

    monkeypatch.setattr(isolation, "_lstat", lstat)


@pytest.mark.parametrize("mode", [0o770, 0o730])
def test_a_group_writable_agent_dir_is_refused(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    # An agent user could replace the socket in it and show the human
    # forged approvals or a forged code (SR-29).
    agent_dir = short_dir / "agent"
    check_agent_dir(agent_dir, EUID, GID)
    _with_mode(monkeypatch, agent_dir, mode)
    with pytest.raises(IsolationError, match="mode 0750"):
        check_agent_dir(agent_dir, EUID, GID)


@pytest.mark.parametrize(
    ("mode", "uid", "refused"),
    [
        (0o775, None, "its owner only"),  # group-writable, not sticky
        (0o757, None, "its owner only"),  # other-writable, not sticky
        (0o1777, None, None),  # sticky, as /tmp
        (0o755, -1, "owned by"),  # another user's
        (0o755, 0, None),  # root's
    ],
)
def test_the_agent_dirs_parents_must_be_closed(  # noqa: PLR0913, PLR0917
    short_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    rng: random.Random,
    mode: int,
    uid: int | None,
    refused: str | None,
) -> None:
    # Whoever can change entries in a directory above the agent directory
    # can rename it away and put their own in its place (SR-29).
    parent = Path(os.path.realpath(short_dir / "up"))
    parent.mkdir(mode=0o700)
    agent_dir = parent / "agent"
    check_agent_dir(agent_dir, EUID, GID)
    _with_mode(monkeypatch, parent, mode, _uid(rng) if uid == -1 else uid)
    if refused is None:
        check_agent_dir(agent_dir, EUID, GID)
    else:
        with pytest.raises(IsolationError, match=refused) as e:
            check_agent_dir(agent_dir, EUID, GID)
        assert str(parent) in str(e.value)


def test_a_link_in_an_open_directory_is_refused(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The daemon keeps using the configured path, so whoever can write the
    # directory that holds a link on it can repoint the link later.
    base = Path(os.path.realpath(short_dir))
    shared, secure = base / "shared", base / "secure"
    shared.mkdir(mode=0o700)
    secure.mkdir(mode=0o700)
    (shared / "link").symlink_to(secure)
    agent_dir = shared / "link" / "agent"
    check_agent_dir(agent_dir, EUID, GID)
    _with_mode(monkeypatch, shared, 0o777)
    with pytest.raises(IsolationError, match="its owner only") as e:
        check_agent_dir(agent_dir, EUID, GID)
    assert str(shared) in str(e.value)


@pytest.mark.parametrize("target", ["../real", "{base}/real"])
def test_a_link_in_a_root_directory_is_followed(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch, rng: random.Random, target: str
) -> None:
    # As /var/run -> ../run: the link's directory is root's and closed, so
    # the link holds, and the walk goes on along its target.
    base = Path(os.path.realpath(short_dir))
    top, real = base / "var", base / "real"
    top.mkdir(mode=0o700)
    real.mkdir(mode=0o700)
    (top / "run").symlink_to(target.format(base=base))
    agent_dir = top / "run" / "agent"
    _with_mode(monkeypatch, top, 0o755, 0)
    check_agent_dir(agent_dir, EUID, GID)
    assert (real / "agent").is_dir()

    # The target's own chain is checked too.
    _with_mode(monkeypatch, real, 0o755, _uid(rng))
    with pytest.raises(IsolationError, match="owned by") as e:
        check_agent_dir(agent_dir, EUID, GID)
    assert str(real) in str(e.value)


def test_a_link_loop_is_refused(short_dir: Path) -> None:
    base = Path(os.path.realpath(short_dir))
    (base / "a").symlink_to(base / "b")
    (base / "b").symlink_to(base / "a")
    with pytest.raises(IsolationError, match="too many links"):
        check_parents(base / "a" / "agent", EUID)


def test_a_directory_that_cannot_be_read_is_refused(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = Path(os.path.realpath(short_dir))
    (base / "link").symlink_to(base)

    def readlink(p: object) -> str:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(isolation.os, "readlink", readlink)
    with pytest.raises(IsolationError, match="cannot check the directories above"):
        check_parents(base / "link" / "agent", EUID)


def test_the_data_dirs_parents_must_be_closed(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Whoever can rename entries above the data directory can swap in
    # their own keys and tokens.
    parent = Path(os.path.realpath(short_dir / "up"))
    parent.mkdir(mode=0o700)
    data_dir = parent / "data"
    check_data_dir(data_dir, EUID)
    check_data_dir(parent / "not" / "yet" / "data", EUID)  # the daemon creates them
    _with_mode(monkeypatch, parent, 0o757)
    for d in (data_dir, parent / "not" / "yet" / "data"):
        with pytest.raises(IsolationError, match="its owner only") as e:
            check_data_dir(d, EUID)
        assert str(parent) in str(e.value)


def test_setup_checks_that_need_no_filesystem(short_dir: Path, rng: random.Random) -> None:
    cfg = _setup(short_dir, rng)
    agent = _uid(rng)
    check_config(cfg, EUID, {agent}, set())
    with pytest.raises(IsolationError, match="root"):
        check_config(cfg, 0, set(), set())
    with pytest.raises(IsolationError, match="Unix socket"):
        check_config(cfg.with_overrides(api_tcp_port=8080), EUID, set(), set())
    with pytest.raises(IsolationError, match="both"):
        check_config(cfg, EUID, {agent}, {agent})
    with pytest.raises(IsolationError, match="own user"):
        check_config(cfg, EUID, {EUID}, set())
    with pytest.raises(IsolationError, match=r"api\.socket"):
        check_config(cfg.with_overrides(api_socket=short_dir / "x.sock"), EUID, set(), set())
    inner = cfg.data_dir / "agent"
    with pytest.raises(IsolationError, match="contain each other"):
        check_config(cfg.with_overrides(isolation_agent_dir=inner), EUID, set(), set())


# -- the gate ----------------------------------------------------------------------------


def test_disabled_gate_passes_everything(short_dir: Path, rng: random.Random) -> None:
    cfg = _setup(short_dir, rng).with_overrides(isolation=False)
    gate = PeerGate.from_config(cfg, credentials=fixed(_uid(rng)))
    assert not gate.enabled
    assert in_connection(lambda: gate.admit(FakeTransport(None)) and gate.human_allowed())
    gate.publish(short_dir / "nothing")  # nothing to do


def test_from_config_refuses_a_loose_setup(short_dir: Path, rng: random.Random) -> None:
    cfg = _setup(short_dir, rng)
    (cfg.data_dir / "human-token").chmod(0o644)
    with pytest.raises(IsolationError, match="human-token"):
        PeerGate.from_config(cfg)
    (cfg.data_dir / "human-token").chmod(0o600)
    with pytest.raises(IsolationError, match="root"):
        PeerGate.from_config(cfg, euid=0)
    PeerGate.from_config(cfg)


def test_unexpected_uids_are_logged_and_refused(
    short_dir: Path, rng: random.Random, capsys: pytest.CaptureFixture[str]
) -> None:
    agent, human, stranger = _uid(rng), _uid(rng), _uid(rng)
    while len({agent, human, stranger}) < 3:
        human, stranger = _uid(rng, agent), _uid(rng, agent)
    cfg = _setup(
        short_dir,
        rng,
        isolation_agent_users=(str(agent),),
        isolation_human_users=(str(human),),
    )
    peer = {"uid": agent}
    gate = PeerGate.from_config(cfg, credentials=lambda _s: PeerCred(peer["uid"], GID, 42))
    sock = object()

    def connect(uid: int) -> tuple[bool, bool]:
        peer["uid"] = uid
        return in_connection(lambda: (gate.admit(FakeTransport(sock)), gate.human_allowed()))

    # The agent user reaches the socket, but the human token isn't accepted from it.
    assert connect(agent) == (True, False)
    # The daemon's own user (`sudo -u agentconnect agentconnect ...`) and a
    # configured human user may present the human token.
    assert connect(EUID) == (True, True)
    assert connect(human) == (True, True)
    # Anyone else is refused before the request is read, and logged with the UID.
    assert connect(stranger)[0] is False
    err = capsys.readouterr().err
    assert "api_peer_refused" in err
    assert str(stranger) in err
    for name in ("api-token", "human-token"):
        assert (cfg.data_dir / name).read_text() not in err  # never a token in a log line


def test_unknown_peer_is_refused(short_dir: Path, rng: random.Random) -> None:
    cfg = _setup(short_dir, rng)

    def broken(_sock: Any) -> PeerCred:
        raise OSError("no credentials")

    gate = PeerGate.from_config(cfg, credentials=broken)
    assert in_connection(lambda: gate.admit(FakeTransport(object()))) is False
    assert in_connection(lambda: gate.admit(FakeTransport(None))) is False
    # Without an admitted peer (fail closed) the human token is never accepted.
    assert in_connection(gate.human_allowed) is False


def test_publish_opens_only_agent_scope_files_to_the_group(
    short_dir: Path, rng: random.Random
) -> None:
    cfg = _setup(short_dir, rng)
    gate = PeerGate.from_config(cfg)
    path = cfg.socket_path
    assert path.parent == cfg.isolation_agent_dir
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with srv:
        srv.bind(str(path))
        path.chmod(0o600)
        gate.publish(path)
        st = path.lstat()
        assert (stat.S_IMODE(st.st_mode), st.st_gid) == (0o660, GID)
    agent_dir = cfg.isolation_agent_dir
    assert sorted(p.name for p in agent_dir.iterdir()) == [
        "agentconnectd.sock",
        "api-token",
        "webhook-secret",
    ]
    for name in ("api-token", "webhook-secret"):
        copy = agent_dir / name
        assert copy.read_bytes() == (cfg.data_dir / name).read_bytes()
        st = copy.lstat()
        assert (stat.S_IMODE(st.st_mode), st.st_gid) == (0o640, GID)
    # A restart replaces the copies; a missing webhook secret is skipped.
    (cfg.data_dir / "webhook-secret").unlink()
    (cfg.data_dir / "api-token").write_bytes(_secret(rng))
    gate.publish(path)
    assert (agent_dir / "api-token").read_bytes() == (cfg.data_dir / "api-token").read_bytes()
    assert not (agent_dir / "human-token").exists()


def test_publish_leaves_no_temporary_file_on_failure(
    short_dir: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _setup(short_dir, rng)
    gate = PeerGate.from_config(cfg)
    path = cfg.socket_path
    path.write_bytes(b"")

    def fail(*_a: Any) -> None:
        raise OSError("fsync failed")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="fsync"):
        gate.publish(path)
    assert sorted(p.name for p in cfg.isolation_agent_dir.iterdir()) == ["agentconnectd.sock"]


# -- configuration -----------------------------------------------------------------------


def test_isolation_keys_load(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[daemon]\ndata_dir = "/var/lib/agentconnect"\n'
        '[isolation]\nenabled = true\nagent_dir = "/run/ac"\ngroup = 990\n'
        'agent_users = ["bot", 1001]\nhuman_users = [0]\n',
        encoding="utf-8",
    )
    cfg = load_config(path, environ={})
    assert cfg.isolation
    assert cfg.isolation_agent_dir == Path("/run/ac")
    assert cfg.isolation_group == "990"
    assert cfg.isolation_agent_users == ("bot", "1001")
    assert cfg.isolation_human_users == ("0",)
    assert cfg.socket_path == Path("/run/ac/agentconnectd.sock")

    default = load_config(tmp_path / "absent.toml", environ={"HOME": str(tmp_path)})
    assert not default.isolation
    assert default.isolation_agent_dir == Path("/run/agentconnect")
    assert default.socket_path == default.data_dir / "agentconnectd.sock"


@pytest.mark.parametrize(
    "body",
    [
        "enabled = 1",
        'agent_users = "bot"',
        "agent_users = [true]",
        "human_users = [1.5]",
        'group = ""',
        "group = false",
    ],
)
def test_bad_isolation_keys_are_refused(tmp_path: Path, body: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(f"[isolation]\n{body}\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, environ={})


def test_packaged_config_turns_the_mode_on() -> None:
    root = Path(__file__).resolve().parents[2] / "packaging"
    cfg = load_config(root / "config.toml", environ={})
    assert cfg.isolation
    assert cfg.keystore == "file"
    assert cfg.data_dir == Path("/var/lib/agentconnect")
    assert cfg.socket_path == Path("/run/agentconnect/agentconnectd.sock")
    unit = (root / "systemd" / "agentconnectd.service").read_text(encoding="utf-8")
    for line in (
        "User=agentconnect",
        "Environment=AC_CONFIG=/etc/agentconnect/config.toml",
        "StateDirectoryMode=0700",
        "RuntimeDirectoryMode=0750",
        "UMask=0077",
    ):
        assert line in unit.splitlines()


# -- the CLI -----------------------------------------------------------------------------


def test_daemon_run_refuses_an_unsafe_setup(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[relay]\nurl = "ws://127.0.0.1:1"\n[daemon]\ndata_dir = "{tmp_path / "data"}"\n'
        f'[api]\ntcp_port = 8080\n[isolation]\nenabled = true\ngroup = "{GID}"\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["daemon", "run", "--config", str(path)])
    assert result.exit_code == EXIT_USAGE
    assert "refusing to start" in result.output
    assert not (tmp_path / "data").exists()  # refused before anything was created


def test_peer_refused_is_explained_by_the_cli() -> None:
    err = map_api_error(ApiClientError(403, "peer_refused", "user refused"))
    assert err.exit_code == EXIT_REFUSED
    assert "isolation.md" in err.message
