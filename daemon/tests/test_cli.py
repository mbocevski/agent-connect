import json

from typer.testing import CliRunner

from agentconnect import __version__
from agentconnect.cli import app

runner = CliRunner()


def test_version_human() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "protocol v0" in result.stdout


def test_version_json_is_stable_contract() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "version": __version__,
        "protocol": 0,
        "ciphersuite": "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
    }
