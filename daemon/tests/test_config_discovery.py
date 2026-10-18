"""The discovery config: ``[[directory]]`` and ``[listing]`` (docs/config.md)."""

from __future__ import annotations

import base64
import random
from pathlib import Path

import pytest

import agentconnect_core as ac
from agentconnect.config import (
    DEFAULT_DOOR_LIFETIME_SECS,
    Config,
    ConfigError,
    load_config,
)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _dk(rng: random.Random) -> str:
    return _b64(ac.DirectoryKey._generate_for_testing(rng.getrandbits(64)).public_key)


def _load(tmp_path: Path, text: str) -> Config:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, {"HOME": str(tmp_path)})


def test_defaults_list_no_directory_and_read_the_card_from_the_config_dir(
    tmp_path: Path,
) -> None:
    cfg = load_config(tmp_path / "none.toml", {"HOME": str(tmp_path)})
    assert cfg.directories == ()
    assert cfg.directory("directory.example.org") is None
    assert cfg.listing_card_file == tmp_path / ".config/agentconnect/listing-card.json"
    assert cfg.listing_token_file == tmp_path / ".config/agentconnect/listing-token.json"
    assert cfg.listing_door_lifetime_secs == DEFAULT_DOOR_LIFETIME_SECS == 604_800 - 3600
    xdg = load_config(tmp_path / "none.toml", {"XDG_CONFIG_HOME": str(tmp_path / "x")})
    assert xdg.listing_card_file == tmp_path / "x/agentconnect/listing-card.json"


def test_a_directory_is_pinned_with_its_keys(tmp_path: Path, rng: random.Random) -> None:
    a, b = _dk(rng), _dk(rng)
    cfg = _load(
        tmp_path,
        f'[[directory]]\nhost = "Directory.Example.ORG"\nkeys = ["{a}", "{b}"]\n'
        f'[[directory]]\nhost = "127.0.0.1:8090"\nkeys = ["{a}"]\nurl = "http://127.0.0.1:8090/"\n'
        '[listing]\ncard_file = "~/card.json"\ndoor_lifetime_secs = 7200\n',
    )
    first, second = cfg.directories
    assert first.host == "directory.example.org"
    assert first.url == "https://directory.example.org"
    assert [_b64(k) for k in first.keys] == [a, b]
    assert second.url == "http://127.0.0.1:8090"
    assert cfg.directory("DIRECTORY.example.org") is first
    assert cfg.directory("not a host!") is None
    assert cfg.listing_card_file == Path("~/card.json").expanduser()
    assert cfg.listing_door_lifetime_secs == 7200


@pytest.mark.parametrize(
    ("table", "match"),
    [
        ('[directory]\nhost = "d.example"\n', "array of tables"),
        ('[[directory]]\nhost = "d.example"\nkeys = []\n', "one or two"),
        ('[[directory]]\nhost = "d.example"\nkeys = ["{a}", "{a}", "{a}"]\n', "one or two"),
        ('[[directory]]\nhost = "d.example"\nkeys = ["{a}", "{a}"]\n', "duplicate"),
        ('[[directory]]\nhost = "d.example"\nkeys = ["{a}="]\n', "base64url"),
        ('[[directory]]\nhost = "d.example"\nkeys = ["{short}"]\n', "directory key"),
        ('[[directory]]\nhost = "d.example"\nkeys = ["{off_curve}"]\n', "directory key"),
        ('[[directory]]\nhost = "d.example"\nkeys = [1]\n', "one or two"),
        ('[[directory]]\nhost = "not a host"\nkeys = ["{a}"]\n', "valid host"),
        (
            '[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\n'
            '[[directory]]\nhost = "D.example"\nkeys = ["{a}"]\n',
            "twice",
        ),
        (
            '[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\nurl = "http://d.example"\n',
            "loopback",
        ),
        (
            '[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\nurl = "ftp://127.0.0.1"\n',
            "https",
        ),
        (
            '[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\nurl = "https://d.example/x"\n',
            "path",
        ),
        (
            '[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\nurl = "https://u@d.example"\n',
            "plain base URL",
        ),
        (
            '[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\nurl = "https://d.example?q"\n',
            "plain base URL",
        ),
        ('[[directory]]\nhost = "d.example"\nkeys = ["{a}"]\nport = 1\n', "unknown key"),
        *(
            (f'[[directory]]\nhost = "d.example"\nkeys = ["{{a}}"]\nurl = "{url}"\n', "public")
            for url in (
                "https://127.0.0.1",
                "https://localhost",
                "https://10.0.0.5:8443",
                "https://[::1]",
                "https://[fd00::1]",
                "https://169.254.169.254",
            )
        ),
        ("[listing]\ndoor_lifetime_secs = 604801\n", "7200..604800"),
        ("[listing]\ndoor_lifetime_secs = 7199\n", "7200..604800"),
        ("[listing]\ncolour = 1\n", "unknown key"),
    ],
)
def test_bad_discovery_config_is_refused(
    tmp_path: Path, rng: random.Random, table: str, match: str
) -> None:
    key = ac.DirectoryKey._generate_for_testing(rng.getrandbits(64)).public_key
    # y = 2 is not the y coordinate of any Ed25519 point.
    off_curve = _b64((2).to_bytes(32, "little"))
    text = table.format(a=_b64(key), short=_b64(key[:31]), off_curve=off_curve)
    with pytest.raises(ConfigError, match=match):
        _load(tmp_path, text)


@pytest.mark.parametrize("table", ["directory", "listing"])
def test_auto_approve_is_refused_with_its_reason(
    tmp_path: Path, rng: random.Random, table: str
) -> None:
    extra = f'host = "d.example"\nkeys = ["{_dk(rng)}"]\n' if table == "directory" else ""
    header = "[[directory]]" if table == "directory" else "[listing]"
    with pytest.raises(ConfigError, match="always need a human"):
        _load(tmp_path, f"{header}\n{extra}auto_approve = true\n")
