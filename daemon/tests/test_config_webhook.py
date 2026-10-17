"""The ``[webhook]`` section: loopback by default, remote only by opt-in."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentconnect.config import Config, ConfigError, load_config


def load(tmp_path: Path, text: str) -> Config:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, environ={"HOME": str(tmp_path)})


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8808/",
        "http://localhost:8808/hook",
        "http://[::1]:9/",
        "https://127.0.0.2/",
    ],
)
def test_loopback_callbacks_are_allowed(tmp_path: Path, url: str) -> None:
    cfg = load(tmp_path, f'[webhook]\ncallback_url = "{url}"\n')
    assert cfg.webhook_url == url


def test_defaults(tmp_path: Path) -> None:
    cfg = load(tmp_path, "")
    assert (cfg.webhook_url, cfg.webhook_allow_remote, cfg.webhook_timeout) == (
        None,
        False,
        120,
    )


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ('[webhook]\ncallback_url = "http://agent.example/"', "allow_remote"),
        ('[webhook]\ncallback_url = "http://127.evil.example/"', "allow_remote"),
        ('[webhook]\ncallback_url = "http://10.0.0.5/"', "allow_remote"),
        (
            '[webhook]\ncallback_url = "http://agent.example/"\nallow_remote = true',
            "must use https",
        ),
        ('[webhook]\ncallback_url = "ftp://127.0.0.1/"', "http:// or https://"),
        ('[webhook]\ncallback_url = "http:///x"', "http:// or https://"),
        ('[webhook]\ncallback_url = "http://u:p@127.0.0.1/"', "credentials"),
        ('[daemon]\ndefault_adapter = "webhook"', "needs webhook.callback_url"),
        ("[webhook]\ncallback_url = 5", "callback_url must be str"),
        ('[webhook]\nallow_remote = "yes"', "allow_remote"),
        ("[webhook]\ntimeout_secs = 0", "timeout_secs"),
        ("[webhook]\ntimeout_secs = 4000", "timeout_secs"),
    ],
)
def test_invalid_webhook_settings_are_rejected(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load(tmp_path, text)


def test_a_remote_https_callback_needs_the_opt_in(tmp_path: Path) -> None:
    cfg = load(
        tmp_path,
        '[webhook]\ncallback_url = "https://agent.example/hook"\nallow_remote = true\n'
        'timeout_secs = 30\n[daemon]\ndefault_adapter = "webhook"\n',
    )
    assert cfg.webhook_url == "https://agent.example/hook"
    assert cfg.webhook_timeout == 30
