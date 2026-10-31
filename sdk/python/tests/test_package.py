import tomllib
from pathlib import Path

import agentconnect_sdk

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_version() -> None:
    declared = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert agentconnect_sdk.__version__ == declared
