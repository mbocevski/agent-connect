"""Provisioning a replica (agentconnect.provision, `identity export` and
`identity import`): the export file and its code, the refusals, and that a
replica always gets a fresh instance. The harness runs the whole path on
the real relay (harness/tests/test_replica_provisioning.py)."""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import stat
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import agentconnect_core as ac
from agentconnect import provision
from agentconnect.cli import app
from agentconnect.cli_json import SCHEMAS
from agentconnect.config import Config
from agentconnect.keystore import DataDirLock, FileKeystore, KeystoreError
from agentconnect.provision import ProvisionError
from agentconnect.shapes import conforms

runner = CliRunner()


def config(data_dir: Path) -> Config:
    return Config(relay_url="", relay_host="", data_dir=data_dir, keystore="file")


def keys(data_dir: Path) -> FileKeystore:
    return FileKeystore(data_dir / "keys")


@pytest.fixture
def source(tmp_path: Path, rng: random.Random) -> Config:
    """A stopped instance's data directory: an identity and an instance."""
    cfg = config(tmp_path / "source")
    identity = ac.Identity._generate_for_testing(rng.getrandbits(63))
    store = keys(cfg.data_dir)
    store.put("identity", identity.secret_bytes())
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(63))
    store.put("instance", instance.to_secret_bytes())
    return cfg


def exported(source: Config, tmp_path: Path) -> tuple[bytes, dict[str, Any]]:
    out = tmp_path / "id.export"
    made = provision.export_identity(source, out)
    return out.read_bytes(), made


def refusal(call: Any) -> str:
    with pytest.raises(ProvisionError) as e:
        call()
    return e.value.code


def test_an_export_imports_as_the_same_identity_with_a_fresh_instance(
    source: Config, tmp_path: Path
) -> None:
    data, made = exported(source, tmp_path)
    original = ac.Identity.from_secret_bytes(keys(source.data_dir).get("identity") or b"")
    assert (made["identity"], made["fingerprint"]) == (original.id, original.fingerprint)
    assert provision.export_identity_id(data) == original.id
    target = config(tmp_path / "replica")
    imported = provision.import_identity(target, data, made["code"])
    assert imported["identity"] == original.id
    store = keys(target.data_dir)
    assert store.get("identity") == original.secret_bytes()
    instance = ac.Instance.from_secret_bytes(store.get("instance") or b"")
    theirs = ac.Instance.from_secret_bytes(keys(source.data_dir).get("instance") or b"")
    assert instance.identity == original.id
    assert instance.instance_id_hex == imported["instance_id"]
    assert instance.instance_id_hex != theirs.instance_id_hex
    assert instance.public_key != theirs.public_key
    assert store.get("db_key") is None  # the runtime makes its own on first start


def test_the_export_is_written_private_and_never_over_a_file(
    source: Config, tmp_path: Path
) -> None:
    old = os.umask(0o000)  # the file is 0600 whatever the umask allows
    try:
        data, made = exported(source, tmp_path)
    finally:
        os.umask(old)
    out = tmp_path / "id.export"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert made["code"] not in data.decode()
    assert base64.urlsafe_b64decode(made["code"] + "=") not in data
    assert set(json.loads(data)) == {"v", "identity", "wrapped"}
    assert refusal(lambda: provision.export_identity(source, out)) == "exists"
    assert out.read_bytes() == data
    link = tmp_path / "link.export"
    link.symlink_to(tmp_path / "elsewhere")
    assert refusal(lambda: provision.export_identity(source, link)) == "exists"
    assert not (tmp_path / "elsewhere").exists()


def test_two_exports_share_no_code(source: Config, tmp_path: Path) -> None:
    first = provision.export_identity(source, tmp_path / "a")
    second = provision.export_identity(source, tmp_path / "b")
    assert first["code"] != second["code"]
    assert (tmp_path / "a").read_bytes() != (tmp_path / "b").read_bytes()


def test_nothing_is_exported_or_imported_while_a_runtime_holds_the_directory(
    source: Config, tmp_path: Path
) -> None:
    lock = DataDirLock(source.data_dir, "daemon")
    try:
        assert refusal(lambda: provision.export_identity(source, tmp_path / "x")) == (
            "runtime_running"
        )
    finally:
        lock.release()
    assert not (tmp_path / "x").exists()
    data, made = exported(source, tmp_path)
    target = config(tmp_path / "replica")
    lock = DataDirLock(target.data_dir, "mcp")
    try:
        assert refusal(lambda: provision.import_identity(target, data, made["code"])) == (
            "runtime_running"
        )
    finally:
        lock.release()
    assert keys(target.data_dir).get("identity") is None


def test_the_last_runtimes_lock_note_is_kept(source: Config, tmp_path: Path) -> None:
    DataDirLock(source.data_dir, "daemon").release()
    note = (source.data_dir / "daemon.lock").read_bytes()
    exported(source, tmp_path)
    assert (source.data_dir / "daemon.lock").read_bytes() == note
    assert DataDirLock.probe(source.data_dir) == (False, "daemon")


def test_a_directory_without_an_identity_has_nothing_to_export(tmp_path: Path) -> None:
    empty = config(tmp_path / "empty")
    assert refusal(lambda: provision.export_identity(empty, tmp_path / "x")) == "no_identity"
    assert not (tmp_path / "x").exists()


@pytest.mark.parametrize(
    "state", ["identity", "instance", "db_key", "mls.sqlite3", "daemon.sqlite3", "keys/"]
)
def test_an_import_refuses_a_directory_that_holds_an_instance(
    source: Config, tmp_path: Path, state: str
) -> None:
    data, made = exported(source, tmp_path)
    target = config(tmp_path / "replica")
    if state in provision.STATE_KEYS:
        keys(target.data_dir).put(state, os.urandom(32))
    elif state == "keys/":
        keys(target.data_dir).put("invite/abc", os.urandom(32))
    else:
        target.data_dir.mkdir(parents=True)
        (target.data_dir / state).touch()
    assert refusal(lambda: provision.import_identity(target, data, made["code"])) == "not_empty"
    if state != "identity":
        assert keys(target.data_dir).get("identity") is None


def test_an_import_refuses_the_exporting_directory_itself(source: Config, tmp_path: Path) -> None:
    data, made = exported(source, tmp_path)
    before = keys(source.data_dir).get("instance")
    assert refusal(lambda: provision.import_identity(source, data, made["code"])) == "not_empty"
    assert keys(source.data_dir).get("instance") == before


def _with(data: bytes, **fields: Any) -> bytes:
    v = json.loads(data)
    v.update(fields)
    return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()


def _flip_last(data: bytes) -> bytes:
    v = json.loads(data)
    raw = bytearray(base64.urlsafe_b64decode(v["wrapped"] + "=" * (-len(v["wrapped"]) % 4)))
    raw[-1] ^= 1
    return _with(data, wrapped=base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode())


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("wrong code", "bad_code"),
        ("malformed code", "bad_code"),
        ("tampered", "bad_code"),
        ("another identity named", "bad_code"),
        ("truncated", "bad_export"),
        ("format version 1", "unsupported_version"),
        ("not an export", "bad_export"),
    ],
)
def test_a_bad_code_or_file_imports_nothing(
    source: Config, tmp_path: Path, rng: random.Random, case: str, expected: str
) -> None:
    data, made = exported(source, tmp_path)
    code = made["code"]
    other = ac.Identity._generate_for_testing(rng.getrandbits(63))
    if case == "wrong code":
        code = provision.export_identity(source, tmp_path / "again")["code"]
    elif case == "malformed code":
        code = code[:-1]
    elif case == "tampered":
        data = _flip_last(data)
    elif case == "another identity named":
        data = _with(data, identity=other.id)
    elif case == "truncated":
        data = data[: len(data) // 2]
    elif case == "format version 1":
        data = _with(data, v=1)
    else:
        data = b'{"hello": "world"}'
    target = config(tmp_path / "replica")
    assert refusal(lambda: provision.import_identity(target, data, code)) == expected
    store = keys(target.data_dir)
    assert store.get("identity") is None
    assert store.get("instance") is None


def test_an_export_file_is_read_up_to_the_limit(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b" " * (ac.MAX_IDENTITY_EXPORT_LEN + 1))
    assert refusal(lambda: provision.read_export(big)) == "bad_export"
    assert refusal(lambda: provision.read_export(tmp_path / "missing")) == "bad_export"


# -- the CLI ---------------------------------------------------------------------------


def write_config(data_dir: Path) -> Path:
    path = data_dir.parent / f"{data_dir.name}.toml"
    path.write_text(f'[daemon]\ndata_dir = "{data_dir}"\nkeystore = "file"\n', encoding="utf-8")
    return path


def run(cfg: Path, *args: str, input: str | None = None) -> Any:
    return runner.invoke(app, [*args, "--config", str(cfg)], input=input)


def test_the_cli_shows_the_code_once_and_imports_with_a_prompt(
    source: Config, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    out = tmp_path / "id.export"
    result = run(write_config(source.data_dir), "identity", "export", "--out", str(out))
    assert result.exit_code == 0, result.output
    data = out.read_bytes()
    code = next(line.strip() for line in result.stdout.splitlines() if len(line.strip()) == 43)
    assert result.stdout.count(code) == 1
    assert "apart from the file" in result.stdout
    assert ac.unwrap_identity_export(data, code).id == provision.export_identity_id(data)

    target = tmp_path / "replica"
    result = run(write_config(target), "identity", "import", str(out), input=f"{code}\n")
    assert result.exit_code == 0, result.output
    assert code not in result.output  # the prompt doesn't echo it
    assert "invite create --group <group> --replica" in result.stdout
    assert keys(target).get("identity") == keys(source.data_dir).get("identity")
    assert code not in caplog.text


def test_the_cli_json_shapes_and_exit_codes(
    source: Config, tmp_path: Path, rng: random.Random
) -> None:
    out = tmp_path / "id.export"
    src = write_config(source.data_dir)
    result = run(src, "identity", "export", "--out", str(out), "--json")
    assert result.exit_code == 0
    made = json.loads(result.stdout)
    assert conforms(made, SCHEMAS["identity export"])
    again = json.loads(run(src, "identity", "export", "--out", str(out), "--json").stdout)
    assert again["error"]["code"] == "exists"

    target = write_config(tmp_path / "replica")
    result = run(target, "identity", "import", str(out), "--json", input="")
    assert (result.exit_code, json.loads(result.stdout)["error"]["code"]) == (2, "needs_code")
    wrong = base64.urlsafe_b64encode(rng.randbytes(32)).rstrip(b"=").decode()
    result = run(target, "identity", "import", str(out), "--code", wrong, "--json")
    assert (result.exit_code, json.loads(result.stdout)["error"]["code"]) == (1, "bad_code")
    # --json reads the code from stdin, so it stays off the command line.
    result = run(target, "identity", "import", str(out), "--json", input=f"{made['code']}\n")
    assert result.exit_code == 0, result.output
    imported = json.loads(result.stdout)
    assert made["code"] not in result.output
    assert conforms(imported, SCHEMAS["identity import"])
    result = run(target, "identity", "import", str(out), "--code", made["code"], "--json")
    assert (result.exit_code, json.loads(result.stdout)["error"]["code"]) == (2, "not_empty")


def test_a_failed_write_leaves_no_file(
    source: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full(_fd: int, _data: Any) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(provision.os, "write", full)
    with pytest.raises(ProvisionError, match="No space") as e:
        provision.export_identity(source, tmp_path / "id.export")
    assert e.value.code == "cannot_write"
    assert not (tmp_path / "id.export").exists()


def test_the_cli_refuses_a_file_that_is_no_export_before_asking(tmp_path: Path) -> None:
    junk = tmp_path / "junk"
    junk.write_bytes(b"not an export")
    result = run(write_config(tmp_path / "replica"), "identity", "import", str(junk))
    assert result.exit_code == 1
    assert "not an identity export" in result.output
    assert "Export code" not in result.output


def test_the_cli_reports_a_keystore_failure(
    source: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: Any) -> dict[str, Any]:
        msg = "keyring read failed"
        raise KeystoreError(msg)

    monkeypatch.setattr(provision, "export_identity", broken)
    result = run(write_config(source.data_dir), "identity", "export", "--out", "x", "--json")
    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["code"] == "keystore"


# -- review 55: a cut import, file errors ---------------------------------------------


class PowerCut(BaseException):
    """A crash between two keystore writes."""


def test_an_import_cut_between_its_writes_resumes_on_retry(
    source: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 55 F3: a crash after `identity` and before `instance` leaves
    a directory that holds that identity and nothing else; the retry with the
    same export finishes the import instead of refusing it."""
    data, made = exported(source, tmp_path)
    target = config(tmp_path / "replica")
    real_put = FileKeystore.put

    def cut_before_instance(self: FileKeystore, name: str, value: bytes) -> None:
        if name == "instance":
            raise PowerCut
        real_put(self, name, value)

    monkeypatch.setattr(FileKeystore, "put", cut_before_instance)
    with pytest.raises(PowerCut):
        provision.import_identity(target, data, made["code"])
    assert sorted(p.name for p in (target.data_dir / "keys").iterdir()) == ["identity"]
    monkeypatch.setattr(FileKeystore, "put", real_put)
    imported = provision.import_identity(target, data, made["code"])
    instance = ac.Instance.from_secret_bytes(keys(target.data_dir).get("instance") or b"")
    assert instance.instance_id_hex == imported["instance_id"]
    assert instance.identity == imported["identity"]
    # Done now: a third run refuses, the directory holds an instance.
    assert refusal(lambda: provision.import_identity(target, data, made["code"])) == "not_empty"


def test_a_cut_import_of_another_identity_or_with_more_state_is_not_resumed(
    source: Config, tmp_path: Path, rng: random.Random
) -> None:
    data, made = exported(source, tmp_path)
    other = config(tmp_path / "other")
    keys(other.data_dir).put(
        "identity", ac.Identity._generate_for_testing(rng.getrandbits(63)).secret_bytes()
    )
    assert refusal(lambda: provision.import_identity(other, data, made["code"])) == "not_empty"
    same = config(tmp_path / "same")
    keys(same.data_dir).put("identity", keys(source.data_dir).get("identity") or b"")
    keys(same.data_dir).put("invite/abc", os.urandom(32))
    assert refusal(lambda: provision.import_identity(same, data, made["code"])) == "not_empty"
    assert keys(same.data_dir).get("instance") is None


def no_traceback(result: Any) -> dict[str, Any]:
    """The JSON error of a command that failed cleanly."""
    assert isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code != 0
    return dict(json.loads(result.stdout)["error"])


def test_an_out_path_in_a_missing_directory_is_a_clean_error(
    source: Config, tmp_path: Path
) -> None:
    out = tmp_path / "missing" / "id.export"
    result = run(write_config(source.data_dir), "identity", "export", "--out", str(out), "--json")
    error = no_traceback(result)
    assert (result.exit_code, error["code"]) == (1, "cannot_write")
    assert str(out) in error["message"]
    assert not out.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
@pytest.mark.parametrize("command", ["export", "import"])
def test_a_data_directory_this_user_cannot_open_is_a_clean_error(
    source: Config, tmp_path: Path, command: str
) -> None:
    """Review 55 F4, as when the human runs the command against the daemon
    user's data directory in separate-OS-user mode."""
    data, made = exported(source, tmp_path)
    (tmp_path / "file").write_bytes(data)
    closed = tmp_path / "closed"
    closed.mkdir(mode=0o500)
    cfg = tmp_path / "closed.toml"
    cfg.write_text(
        f'[daemon]\ndata_dir = "{closed / "data"}"\nkeystore = "file"\n', encoding="utf-8"
    )
    try:
        args = (
            ["export", "--out", str(tmp_path / "x")]
            if command == "export"
            else ["import", str(tmp_path / "file"), "--code", made["code"]]
        )
        result = run(cfg, "identity", *args, "--json")
    finally:
        closed.chmod(0o700)
    error = no_traceback(result)
    assert (result.exit_code, error["code"]) == (2, "data_dir_access")
    assert "daemon's OS user" in error["message"]


def test_a_keystore_write_that_fails_is_a_clean_error(
    source: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, made = exported(source, tmp_path)
    (tmp_path / "file").write_bytes(data)

    def full(_self: FileKeystore, _name: str, _value: bytes) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(FileKeystore, "put", full)
    cfg = write_config(tmp_path / "replica")
    result = run(
        cfg, "identity", "import", str(tmp_path / "file"), "--code", made["code"], "--json"
    )
    error = no_traceback(result)
    assert (result.exit_code, error["code"]) == (1, "cannot_write")
    assert "No space" in error["message"]
    assert made["code"] not in result.output
