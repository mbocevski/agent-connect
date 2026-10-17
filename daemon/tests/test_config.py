from pathlib import Path

import pytest

from agentconnect.config import (
    DEFAULT_RELAY_URL,
    ConfigError,
    default_config_path,
    default_data_dir,
    load_config,
)


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_defaults_follow_xdg(tmp_path: Path) -> None:
    env = {"HOME": str(tmp_path)}
    cfg = load_config(environ=env)
    assert cfg.relay_url == DEFAULT_RELAY_URL
    assert cfg.relay_host == "relay.agentconnect.dev"
    assert cfg.relay_http == "https://relay.agentconnect.dev"
    assert cfg.relay_ws == "wss://relay.agentconnect.dev/v0/ws"
    assert cfg.data_dir == tmp_path / ".local/share/agentconnect"
    assert cfg.socket_path == cfg.data_dir / "agentconnectd.sock"
    assert not cfg.auto_approve
    assert cfg.keystore == "auto"
    assert default_config_path(env) == tmp_path / ".config/agentconnect/config.toml"
    xdg = {"XDG_DATA_HOME": str(tmp_path / "d"), "XDG_CONFIG_HOME": str(tmp_path / "c")}
    assert default_data_dir(xdg) == tmp_path / "d/agentconnect"
    assert default_config_path(xdg) == tmp_path / "c/agentconnect/config.toml"


def test_file_values_and_overrides(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
[relay]
url = "ws://127.0.0.1:9000"
host = "relay.test"

[daemon]
data_dir = "~/ac"
display_name = "bot"
default_adapter = "webhook"
keystore = "file"

[policy]
auto_approve = true

[api]
socket = "/tmp/x.sock"
tcp_port = 7787
""",
    )
    env = {"HOME": str(tmp_path)}
    cfg = load_config(path, environ=env)
    assert cfg.relay_host == "relay.test"
    assert cfg.relay_http == "http://127.0.0.1:9000"
    assert cfg.display_name == "bot"
    assert cfg.default_adapter == "webhook"
    assert cfg.keystore == "file"
    assert cfg.auto_approve
    assert cfg.api_socket == Path("/tmp/x.sock")  # noqa: S108
    assert cfg.api_tcp_port == 7787
    # Environment beats the file, keyword arguments beat both.
    env |= {"AC_RELAY_URL": "ws://localhost:1", "AC_DATA_DIR": str(tmp_path / "e")}
    cfg = load_config(path, environ=env, display_name="kw")
    assert cfg.relay_url == "ws://localhost:1"
    assert cfg.data_dir == tmp_path / "e"
    assert cfg.display_name == "kw"
    assert cfg.with_overrides(relay_rest_url="http://x/").relay_http == "http://x"
    # AC_CONFIG names the file when no path is given.
    assert load_config(environ={**env, "AC_CONFIG": str(path)}).api_tcp_port == 7787


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ('[relay]\nurl = "http://x"', "ws:// or wss://"),
        ('[relay]\nurl = "ws://relay.example"', "loopback"),
        ('[daemon]\nkeystore = "vault"', "keystore"),
        ("[api]\ntcp_port = 70000", "tcp_port"),
        ("[api]\ntcp_port = true", "tcp_port must be int"),
        ('[policy]\nauto_approve = "yes"', "auto_approve"),
        ('relay = "x"', r"\[relay\] must be a table"),
        ("[relay", "config.toml"),
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, text), environ={"HOME": str(tmp_path)})
