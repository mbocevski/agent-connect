"""Fixtures for the SDK's unit tests (no daemon: payloads are built by hand)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agentconnect_sdk import AgentConnect

Payload = Callable[..., dict[str, Any]]


@pytest.fixture
def secret() -> str:
    return secrets.token_hex(16)


@pytest.fixture
def api_token() -> str:
    return secrets.token_urlsafe(16)


@pytest.fixture
def human_token() -> str:
    return secrets.token_urlsafe(16)


@pytest.fixture
def data_dir(tmp_path: Path, api_token: str, human_token: str, secret: str) -> Path:
    """A daemon data directory as the daemon leaves it: both tokens, the
    webhook secret."""
    (tmp_path / "api-token").write_text(api_token + "\n")
    (tmp_path / "human-token").write_text(human_token + "\n")
    (tmp_path / "webhook-secret").write_text(secret + "\n")
    return tmp_path


@pytest.fixture
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the SDK from reading the developer's real config."""
    for var in ("AC_CONFIG", "AC_DATA_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "no-data"))


@pytest.fixture
def make_payload() -> Payload:
    """A webhook body for a message, as the daemon sends it."""

    def build(**overrides: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "event": "message",
            "msg_id": secrets.token_hex(8),
            "group": {"id": "g1", "name": "Ops", "purpose": "Deploys", "epoch": 2, "floor": "free"},
            "sender": {
                "identity": "ac:v0:peer",
                "instance_id": "i1",
                "display_name": "peer-bot",
                "verified": False,
            },
            "to": ["*"],
            "addressed_to_me": True,
            "scope": "Deploys",
            "untrusted": True,
            "trust_state": {"self": "unverified", "verified_members": 0, "members": 2},
            "origin": "agent",
            "hop": 1,
            "a2a": {"role": "ROLE_AGENT", "parts": [{"text": "hello"}]},
        }
        body.update(overrides)
        return body

    return build


@pytest.fixture
def make_event() -> Payload:
    def build(**overrides: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "event": "member_joined",
            "event_id": secrets.token_hex(8),
            "group": {"id": "g1", "name": "Ops", "purpose": "Deploys", "epoch": 2, "floor": "free"},
            "untrusted": True,
            "data": {"identity": "ac:v0:peer"},
        }
        body.update(overrides)
        return body

    return build


@pytest.fixture
def agent(isolated_env: None, data_dir: Path) -> AgentConnect:
    return AgentConnect(data_dir=data_dir)
