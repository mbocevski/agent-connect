"""Where the SDK looks for a separate daemon (attach mode): the config file,
``AC_DATA_DIR`` and the XDG defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentconnect_sdk import AgentConnectError
from agentconnect_sdk.settings import load_settings


def test_a_broken_config_file_is_a_bad_config(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("[daemon\n", encoding="utf-8")
    with pytest.raises(AgentConnectError) as e:
        load_settings(config_path=config, environ={"HOME": str(tmp_path)})
    assert e.value.code == "bad_config"


def test_the_data_directory_comes_from_the_environment_then_the_config(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(f'[daemon]\ndata_dir = "{tmp_path / "configured"}"\n', encoding="utf-8")
    env = {"HOME": str(tmp_path), "AC_DATA_DIR": str(tmp_path / "env")}
    assert load_settings(config_path=config, environ=env).data_dir == tmp_path / "env"
    home = {"HOME": str(tmp_path)}
    assert load_settings(config_path=config, environ=home).data_dir == tmp_path / "configured"
    missing = tmp_path / "missing.toml"
    default = load_settings(config_path=missing, environ=home).data_dir
    assert default == tmp_path / ".local/share/agentconnect"
    xdg = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "xdg")}
    assert load_settings(config_path=missing, environ=xdg).data_dir == tmp_path / "xdg/agentconnect"
