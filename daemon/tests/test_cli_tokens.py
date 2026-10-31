"""What the CLI says when it can't have the token it wants, as on a host in the
separate-OS-user mode (docs/isolation.md): the daemon is running, and this user
has only the agent directory, or nothing at all."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentconnect import cli
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.config import Config
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE

runner = CliRunner()


def config_file(tmp_path: Path, data_dir: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[relay]\nurl = "ws://127.0.0.1:1"\n[daemon]\ndata_dir = "{data_dir}"\n',
        encoding="utf-8",
    )
    return path


def config(data_dir: Path) -> Config:
    return Config(relay_url="ws://127.0.0.1:1", relay_host="127.0.0.1:1", data_dir=data_dir)


def test_no_tokens_at_all_means_the_daemon_isnt_running(tmp_path: Path) -> None:
    for human in (False, True):
        with pytest.raises(ApiClientError) as e:
            ApiClient(config(tmp_path), human=human)
        assert e.value.code == "not_running"


def test_the_agent_directory_has_no_human_token_and_says_so(tmp_path: Path) -> None:
    (tmp_path / API_TOKEN_FILE).write_text("agent-scope\n", encoding="ascii")
    with pytest.raises(ApiClientError) as e:
        ApiClient(config(tmp_path), human=True)
    assert e.value.code == "human_only"


@pytest.mark.parametrize("args", [("approvals", "approve", "r1", "--yes"), ("verify", "g1")])
def test_a_human_command_in_the_agent_directory_is_refused_as_one(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    (tmp_path / API_TOKEN_FILE).write_text("agent-scope\n", encoding="ascii")
    path = config_file(tmp_path, tmp_path)
    result = runner.invoke(cli.app, [*args, "--json", "--config", str(path)])
    assert result.exit_code == 3
    assert json.loads(result.stdout.splitlines()[-1])["error"]["code"] == "human_only"
    # Not "start the daemon": it is running, and this is the wrong user.
    assert "daemon run" not in result.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file")
@pytest.mark.parametrize("token", [API_TOKEN_FILE, HUMAN_TOKEN_FILE])
def test_the_daemons_own_directory_is_an_error_message_not_a_traceback(
    tmp_path: Path, token: str
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / token).write_text("secret\n", encoding="ascii")
    path = config_file(tmp_path, data_dir)
    human = token == HUMAN_TOKEN_FILE
    args = ["approvals", "approve", "r1", "--yes"] if human else ["status"]
    data_dir.chmod(0o000)
    try:
        with pytest.raises(ApiClientError) as e:
            ApiClient(config(data_dir), human=human)
        assert e.value.code == "token_unreadable"
        result = runner.invoke(cli.app, [*args, "--config", str(path)])
    finally:
        data_dir.chmod(0o700)
    assert result.exit_code == 3
    assert "AC_DATA_DIR" in result.output
    assert not isinstance(result.exception, PermissionError)


class ListOnly:
    """Answers the one route, for the token it was made with."""

    def __init__(self, human: bool) -> None:
        self.human = human

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        assert (method, path, body) == ("GET", "/v0/approvals", None)
        return {"approvals": [], "messages": [], "human": self.human}


def test_approvals_list_uses_the_agent_token_where_the_human_one_isnt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens: list[bool] = []

    def connect(_path: Path | None, *, human: bool = False) -> ListOnly:
        tokens.append(human)
        if human:
            raise ApiClientError(0, "human_only", "no human token in this data directory")
        return ListOnly(human)

    monkeypatch.setattr(cli, "connect", connect)
    result = runner.invoke(cli.app, ["approvals", "list", "--json"])
    assert result.exit_code == 0, result.output
    assert tokens == [True, False]
    assert json.loads(result.stdout) == {"scope": "agent", "approvals": [], "messages": []}


def test_approvals_list_says_when_it_shows_only_the_agents_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def connect(_path: Path | None, *, human: bool = False) -> ListOnly:
        if human:
            raise ApiClientError(0, "human_only", "no human token in this data directory")
        return ListOnly(human)

    monkeypatch.setattr(cli, "connect", connect)
    out = runner.invoke(cli.app, ["approvals", "list"]).stdout
    assert "agent token: your own held sends only" in out
    # An empty list here says nothing about what waits for the human.
    assert "No pending" not in out


def test_approvals_list_prefers_the_human_token(monkeypatch: pytest.MonkeyPatch) -> None:
    tokens: list[bool] = []

    def connect(_path: Path | None, *, human: bool = False) -> ListOnly:
        tokens.append(human)
        return ListOnly(human)

    monkeypatch.setattr(cli, "connect", connect)
    result = runner.invoke(cli.app, ["approvals", "list"])
    assert result.exit_code == 0
    assert tokens == [True]
    assert "No pending" in result.stdout
    assert "agent token" not in result.stdout
    assert (
        json.loads(runner.invoke(cli.app, ["approvals", "list", "--json"]).stdout)["scope"]
        == "human"
    )


def test_approvals_list_doesnt_hide_a_stopped_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    def connect(_path: Path | None, *, human: bool = False) -> ListOnly:
        raise ApiClientError(0, "not_running", f"no token (human={human})")

    monkeypatch.setattr(cli, "connect", connect)
    assert runner.invoke(cli.app, ["approvals", "list"]).exit_code == 5
