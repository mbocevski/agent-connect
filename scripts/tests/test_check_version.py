import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_version", Path(__file__).resolve().parents[1] / "check_version.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_version"] = module
    spec.loader.exec_module(module)
    return module


check_version = _load()
REPO = Path(__file__).resolve().parents[2]
FILES = [
    "Cargo.toml",
    "README.md",
    "core-py/pyproject.toml",
    "daemon/pyproject.toml",
    "daemon/src/agentconnect/__init__.py",
    "sdk/python/pyproject.toml",
    "sdk/python/src/agentconnect_sdk/__init__.py",
    "core-py/README.md",
    "daemon/README.md",
    "sdk/python/README.md",
]


@pytest.mark.parametrize(
    ("pep440", "cargo"),
    [
        ("0.1.0a1", "0.1.0-alpha.1"),
        ("0.1.0b2", "0.1.0-beta.2"),
        ("1.2.3rc10", "1.2.3-rc.10"),
        ("0.1.0", "0.1.0"),
    ],
)
def test_semver_spelling(pep440: str, cargo: str) -> None:
    assert check_version.semver(pep440) == cargo


@pytest.mark.parametrize("bad", ["0.1", "0.1.0.dev1", "0.1.0-alpha.1", "v0.1.0a1", "0.1.0a"])
def test_non_release_versions_are_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="not a release version"):
        check_version.semver(bad)


def test_the_repository_agrees_with_itself() -> None:
    assert check_version.main(["check_version.py"]) == 0


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for rel in FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, tmp_path / rel)
    monkeypatch.setattr(check_version, "ROOT", tmp_path)
    return tmp_path


def _version() -> str:
    return str(check_version.pyproject_version())


def test_a_copy_of_the_tree_passes(tree: Path) -> None:
    assert check_version.problems(_version()) == []


def test_another_version_fails_everywhere(tree: Path) -> None:
    found = check_version.problems("9.9.9")
    assert len(found) == 12, found


@pytest.mark.parametrize(
    ("rel", "old", "new", "needle"),
    [
        ("sdk/python/pyproject.toml", 'version = "{v}"', 'version = "0.0.1"', "sdk/python"),
        (
            "daemon/pyproject.toml",
            '"agentconnect-core=={v}"',
            '"agentconnect-core"',
            "on agentconnect-core",
        ),
        ("daemon/src/agentconnect/__init__.py", '"{v}"', '"0.0.1"', "daemon __version__"),
        ("Cargo.toml", 'version = "0.', 'version = "1.', "Cargo.toml"),
        (
            "README.md",
            "\nuv tool install agentconnect-cli=={v}\n",
            "\nuv tool install agentconnect-cli\n",
            "README.md",
        ),
        ("daemon/README.md", "/blob/v{v}/SPEC.md", "/blob/main/SPEC.md", "'main'"),
        (
            "sdk/python/README.md",
            "(https://github.com/mbocevski/agent-connect/blob/v{v}/docs/sdk.md)",
            "(../../docs/sdk.md)",
            "'../../docs/sdk.md'",
        ),
    ],
)
def test_one_drifted_place_is_named(tree: Path, rel: str, old: str, new: str, needle: str) -> None:
    v = _version()
    path = tree / rel
    text = path.read_text(encoding="utf-8")
    assert old.format(v=v) in text
    path.write_text(text.replace(old.format(v=v), new, 1), encoding="utf-8")
    found = check_version.problems(v)
    assert len(found) == 1, found
    assert needle in found[0]
