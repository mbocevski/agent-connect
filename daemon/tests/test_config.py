import secrets
from pathlib import Path

import pytest

from agentconnect.a2a_adapter import A2AOptions
from agentconnect.config import (
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
    assert cfg.relay_url == ""
    assert cfg.relay_host == ""
    for attempt in (cfg.require_relay, lambda: cfg.relay_ws, lambda: cfg.relay_http):
        with pytest.raises(ConfigError, match=r"relay\.url is required"):
            attempt()
    assert cfg.data_dir == tmp_path / ".local/share/agentconnect"
    assert cfg.socket_path == cfg.data_dir / "agentconnectd.sock"
    assert not cfg.auto_approve
    assert cfg.keystore == "auto"
    assert default_config_path(env) == tmp_path / ".config/agentconnect/config.toml"
    xdg = {"XDG_DATA_HOME": str(tmp_path / "d"), "XDG_CONFIG_HOME": str(tmp_path / "c")}
    assert default_data_dir(xdg) == tmp_path / "d/agentconnect"
    assert default_config_path(xdg) == tmp_path / "c/agentconnect/config.toml"


def test_relay_url_from_the_environment(tmp_path: Path) -> None:
    cfg = load_config(environ={"HOME": str(tmp_path), "AC_RELAY_URL": "wss://relay.example.org"})
    cfg.require_relay()
    assert cfg.relay_host == "relay.example.org"
    assert cfg.relay_http == "https://relay.example.org"
    assert cfg.relay_ws == "wss://relay.example.org/v0/ws"


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

[webhook]
callback_url = "http://127.0.0.1:8808/"
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
        ('[relay]\nhost = "me@relay.test"', "not a valid host"),
        ('[relay]\nhost = "relay.test:0"', "not a valid host"),
        ('[a2a]\nlocal_agent_url = "ftp://agent"', "http:// or https://"),
        ("[a2a]\nfacade_port = 70000", "facade_port"),
        ("[a2a]\ncontext_messages = 101", "context_messages"),
        ("[a2a]\nreply_timeout = 0", "reply_timeout"),
        ("[a2a]\nreply_timeout = true", "reply_timeout"),
        ("[a2a]\nreply_timeout = 1.5", "reply_timeout"),
        ('a2a = "x"', r"\[a2a\] must be a table"),
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, text), environ={"HOME": str(tmp_path)})


def test_the_relay_host_is_canonical(tmp_path: Path) -> None:
    # SPEC 8.1.1: lower-cased, explicit port kept, userinfo never included;
    # the relay applies the same core function to its configured host.
    env = {"HOME": str(tmp_path)}
    cfg = load_config(write(tmp_path, '[relay]\nurl = "ws://User@LocalHost:8080"'), environ=env)
    assert cfg.relay_host == "localhost:8080"
    cfg = load_config(write(tmp_path, '[relay]\nhost = "Relay.TEST:8443"'), environ=env)
    assert cfg.relay_host == "relay.test:8443"


def test_the_a2a_section(tmp_path: Path) -> None:
    env = {"HOME": str(tmp_path)}
    assert not load_config(environ=env).a2a_enabled
    token = tmp_path / "agent-token"
    secret = secrets.token_urlsafe(16)
    token.write_text(secret + "\n", encoding="utf-8")
    keys = tmp_path / "keys.json"
    keys.write_text('{"keys": [{"kty": "oct", "kid": "sym", "k": "AA"}, "junk"]}')
    text = (
        "[a2a]\n"
        'local_agent_url = "http://127.0.0.1:9999/"\n'
        f'local_agent_token_file = "{token}"\n'
        f'card_keys_file = "{keys}"\n'
        "facade_port = 8765\n"
        "context_messages = 5\n"
        "frame_text = false\n"
        "reply_timeout = 30\n"
    )
    cfg = load_config(write(tmp_path, text), environ=env)
    assert cfg.a2a_enabled
    assert cfg.a2a_local_agent_url == "http://127.0.0.1:9999/"
    assert cfg.a2a_facade_port == 8765
    assert cfg.a2a_reply_timeout == 30
    options = A2AOptions.from_config(cfg)
    assert options.local_agent_token == secret
    assert options.card_keys == {}  # symmetric keys are refused
    assert options.facade_port == 8765
    assert (options.context_messages, options.frame_text) == (5, False)
    assert secret not in repr(options)
    off = load_config(write(tmp_path, "[a2a]\n"), environ=env)
    assert not off.a2a_enabled
    assert A2AOptions.from_config(off).facade_port is None
    assert A2AOptions.from_config(off).local_agent_url is None
    assert A2AOptions.from_config(load_config(environ=env)).local_agent_url is None
