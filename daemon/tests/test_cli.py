import json

from typer.testing import CliRunner

from agentconnect import __version__
from agentconnect.cli import app

runner = CliRunner()


def test_version_human() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "protocol v0" in result.stdout


def test_version_flag_prints_what_the_command_prints_and_exits_0() -> None:
    flag = runner.invoke(app, ["--version"])
    assert flag.exit_code == 0
    assert flag.stdout == f"agentconnect {__version__} (protocol v0)\n"
    assert flag.stdout == runner.invoke(app, ["version"]).stdout


def test_version_flag_runs_no_command() -> None:
    result = runner.invoke(app, ["--version", "status"])
    assert result.exit_code == 0
    assert result.stdout == f"agentconnect {__version__} (protocol v0)\n"


def test_version_json_is_stable_contract() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "version": __version__,
        "protocol": 0,
        "ciphersuite": "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
    }
