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


@pytest.mark.parametrize("table", ["directory", "listing", "knock"])
def test_auto_approve_is_refused_with_its_reason(
    tmp_path: Path, rng: random.Random, table: str
) -> None:
    extra = f'host = "d.example"\nkeys = ["{_dk(rng)}"]\n' if table == "directory" else ""
    header = "[[directory]]" if table == "directory" else f"[{table}]"
    with pytest.raises(ConfigError, match="always need a human"):
        _load(tmp_path, f"{header}\n{extra}auto_approve = true\n")


def test_knock_defaults_are_the_specs_limits(tmp_path: Path) -> None:
    cfg = load_config(tmp_path / "none.toml", {"HOME": str(tmp_path)})
    assert cfg.knock_agent_may_knock is True
    assert cfg.knock_domain_check is True
    assert (cfg.knock_max_outgoing, cfg.knock_per_hour) == (8, 20)
    assert (cfg.knock_max_pending_per_door, cfg.knock_opened_per_door_per_minute) == (32, 10)
    assert cfg.knock_failures_per_sender_per_hour == 10
    assert cfg.knock_ledger_capacity == ac.DEFAULT_LEDGER_CAPACITY
    assert cfg.auto_approve is False


def test_knock_limits_may_be_lowered(tmp_path: Path) -> None:
    cfg = _load(
        tmp_path,
        "[knock]\nagent_may_knock = false\ndomain_check = false\nmax_outgoing = 1\n"
        "per_hour = 1\nmax_pending_per_door = 1\nopened_per_door_per_minute = 1\n"
        "failures_per_sender_per_hour = 100\nledger_capacity = 1024\n",
    )
    assert (cfg.knock_agent_may_knock, cfg.knock_domain_check) == (False, False)
    assert (cfg.knock_max_outgoing, cfg.knock_per_hour, cfg.knock_max_pending_per_door) == (1, 1, 1)
    assert cfg.knock_opened_per_door_per_minute == 1
    assert cfg.knock_failures_per_sender_per_hour == 100
    assert cfg.knock_ledger_capacity == 1024


@pytest.mark.parametrize(
    ("line", "match"),
    [
        ("max_outgoing = 9", "1..8"),
        ("max_outgoing = 0", "1..8"),
        ("per_hour = 21", "1..20"),
        ("max_pending_per_door = 33", "1..32"),
        ("opened_per_door_per_minute = 11", "1..10"),
        ("failures_per_sender_per_hour = 101", "1..100"),
        ("ledger_capacity = 65537", "1024..65536"),
        ("ledger_capacity = 1023", "1024..65536"),
        ("agent_may_knock = 1", "must be bool"),
        ("max_outgoing = true", "must be int"),
        ("auto_approve_knocks = true", "unknown key"),
    ],
)
def test_knock_limits_may_only_be_lowered(tmp_path: Path, line: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        _load(tmp_path, f"[knock]\n{line}\n")


def test_join_limits_default_to_their_bounds_and_may_only_be_lowered(tmp_path: Path) -> None:
    """The join flood limits (SPEC 6.2 "Replays"): 32 pending requests and a
    ledger share of at most 1024 per invite, lowered but never raised."""
    cfg = load_config(tmp_path / "none.toml", {"HOME": str(tmp_path)})
    assert (cfg.policy_max_pending_joins_per_invite, cfg.policy_join_ledger_per_invite) == (
        32,
        1024,
    )
    cfg = _load(
        tmp_path, "[policy]\nmax_pending_joins_per_invite = 1\njoin_ledger_per_invite = 64\n"
    )
    assert (cfg.policy_max_pending_joins_per_invite, cfg.policy_join_ledger_per_invite) == (1, 64)
    for line, match in (
        ("max_pending_joins_per_invite = 33", "1..32"),
        ("max_pending_joins_per_invite = 0", "1..32"),
        ("join_ledger_per_invite = 1025", "64..1024"),
        ("join_ledger_per_invite = 63", "64..1024"),
    ):
        with pytest.raises(ConfigError, match=match):
            _load(tmp_path, f"[policy]\n{line}\n")
