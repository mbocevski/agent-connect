"""Embedded mode without a relay: configuration, and what needs a running
runtime or an attached daemon. The embedded runtime against the real relay
is in harness/tests/test_embedded.py and every harness scenario."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentconnect.runtime import Config
from agentconnect_sdk import AgentConnect, AgentConnectError, Deduper
from agentconnect_sdk.embedded import ADAPTER_NAME, EmbeddedHost, default_data_dir

DEFAULT_RELAY = "wss://connect.yggdrasill.network"


def configure(  # noqa: PLR0913
    name: str | None = "bot",
    env: dict[str, str] | None = None,
    *,
    data_dir: Path | str | None = None,
    relay: str | None = None,
    config: Path | None = None,
    display_name: str | None = None,
) -> Config:
    return EmbeddedHost.configure(
        name,
        data_dir=data_dir,
        relay=relay,
        config=config,
        display_name=display_name,
        environ=env or {"HOME": "/home/u"},
    )


def test_one_data_directory_per_name() -> None:
    cfg = configure("my-agent")
    assert cfg.data_dir == Path("/home/u/.local/share/agentconnect-my-agent")
    assert cfg.socket_path == cfg.data_dir / "agentconnectd.sock"
    assert cfg.relay_url == DEFAULT_RELAY
    assert cfg.default_adapter == ADAPTER_NAME
    assert cfg.display_name == "my-agent"
    xdg = configure("x", {"XDG_DATA_HOME": "/data", "HOME": "/home/u"})
    assert xdg.data_dir == Path("/data/agentconnect-x")


def test_a_name_or_a_data_dir_is_required() -> None:
    with pytest.raises(AgentConnectError, match="name=") as e:
        configure(None)
    assert e.value.code == "bad_config"
    for bad in ("", "../up", "-x", "a b", "x" * 65):
        with pytest.raises(AgentConnectError, match="name"):
            default_data_dir(bad, {"HOME": "/home/u"})


def test_data_dir_and_ac_data_dir_replace_the_default(tmp_path: Path) -> None:
    env = {"HOME": "/home/u", "AC_DATA_DIR": str(tmp_path / "env")}
    assert configure("bot", env, data_dir=tmp_path / "arg").data_dir == tmp_path / "arg"
    assert configure(None, data_dir="~/d").data_dir == Path.home() / "d"
    same = {"HOME": "/home/u", "AC_DATA_DIR": "/home/u/.local/share/agentconnect-bot"}
    assert configure("bot", same).data_dir == Path("/home/u/.local/share/agentconnect-bot")


def test_an_exported_ac_data_dir_never_gives_a_name_another_identity(tmp_path: Path) -> None:
    """The human exported AC_DATA_DIR for one bot's CLI; a second bot started
    from that shell must not take the first one's identity."""
    env = {"HOME": "/home/u", "AC_DATA_DIR": str(tmp_path / "first-bot")}
    with pytest.raises(AgentConnectError, match="AC_DATA_DIR") as e:
        configure("other-bot", env)
    assert e.value.code == "bad_config"


def test_relay_display_name_and_an_explicit_config_file(tmp_path: Path) -> None:
    cfg = configure(relay="wss://relay.example.org:8443", display_name="Bot One")
    assert cfg.relay_url == "wss://relay.example.org:8443"
    assert cfg.relay_host == "relay.example.org:8443"
    assert cfg.display_name == "Bot One"
    toml = tmp_path / "embedded.toml"
    toml.write_text(
        '[daemon]\ndisplay_name = "from-file"\ndefault_adapter = "webhook"\n'
        '[webhook]\ncallback_url = "http://127.0.0.1:9/"\n'
        "[policy]\nsender_per_minute = 5\n",
        encoding="utf-8",
    )
    cfg = configure(config=toml)
    assert cfg.policy_sender_per_minute == 5
    assert cfg.display_name == "from-file"
    assert cfg.default_adapter == ADAPTER_NAME  # deliveries stay in-process
    with pytest.raises(AgentConnectError, match="relay") as e:
        configure(relay="http://not-a-websocket")
    assert e.value.code == "bad_config"


def test_the_daemons_config_file_is_not_read(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".config/agentconnect").mkdir(parents=True)
    (home / ".config/agentconnect/config.toml").write_text(
        '[daemon]\ndisplay_name = "the-daemon"\n', encoding="utf-8"
    )
    assert configure("bot", {"HOME": str(home)}).display_name == "bot"


def test_isolation_is_for_a_separate_daemon_only() -> None:
    cfg = configure().with_overrides(isolation=True)
    with pytest.raises(AgentConnectError, match="separate daemon"):
        EmbeddedHost(cfg)


async def test_an_unstarted_embedded_client(tmp_path: Path) -> None:
    ac = AgentConnect.embedded("bot", data_dir=tmp_path / "bot", dedupe=Deduper())
    assert ac.mode == "embedded"
    assert ac.data_dir == tmp_path / "bot"
    with pytest.raises(AgentConnectError, match="isn't running") as e:
        await ac.status()
    assert e.value.code == "not_running"
    with pytest.raises(AgentConnectError, match="isn't running"):
        await ac.serve()
    with pytest.raises(AgentConnectError, match="mode must be auto"):
        await ac.serve("sse")
    # The webhook and the stream are an attached client's.
    with pytest.raises(AgentConnectError, match="attached") as e:
        ac.webhook_receiver(port=1)
    assert e.value.code == "embedded"
    with pytest.raises(AgentConnectError, match="attached"):
        await ac.stream()
    with pytest.raises(AgentConnectError, match="attached"):
        await ac.receive({}, b"{}")
    await ac.aclose()  # nothing started, nothing to stop
    assert not (tmp_path / "bot").exists()  # nothing was created


def test_attach_is_the_daemon_client(isolated_env: None, data_dir: Path) -> None:
    ac = AgentConnect.attach(data_dir=data_dir)
    assert ac.mode == "attach"
    assert ac.data_dir == data_dir
