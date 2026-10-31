"""Tests for scripts/set_version.py: moving the version between a release and the
development version after it, with scripts/check_version.py agreeing at each step."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
REPO = SCRIPTS.parent


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check_version = _load("check_version")
set_version = _load("set_version")

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


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for rel in FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, tmp_path / rel)
    monkeypatch.setattr(check_version, "ROOT", tmp_path)
    # Start from the tree a release PR leaves, whether the checkout carries that
    # release or the development version after it: the version the README installs.
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    set_version.set_version(tmp_path, str(check_version.INSTALL.findall(readme)[0]))
    return tmp_path


def snapshot(tree: Path) -> dict[str, str]:
    return {rel: (tree / rel).read_text(encoding="utf-8") for rel in FILES}


@pytest.mark.parametrize(
    ("release", "dev"),
    [
        ("0.1.0a4", "0.1.0a5.dev0"),
        ("0.1.0a9", "0.1.0a10.dev0"),
        ("0.1.0b2", "0.1.0b3.dev0"),
        ("0.1.0rc1", "0.1.0rc2.dev0"),
        ("0.1.0", "0.1.1.dev0"),
        ("1.9.9", "1.9.10.dev0"),
    ],
)
def test_next_dev_follows_a_release(release: str, dev: str) -> None:
    assert set_version.next_dev(release) == dev


@pytest.mark.parametrize("bad", ["0.1.0a5.dev0", "0.1", "v0.1.0", "x"])
def test_next_dev_needs_a_release(bad: str) -> None:
    with pytest.raises(set_version.VersionError, match="not a release version"):
        set_version.next_dev(bad)


def test_a_release_moves_to_the_next_dev_and_back(tree: Path) -> None:
    start = snapshot(tree)
    release = check_version.pyproject_version()
    dev = set_version.next_dev(release)

    changed = set_version.set_version(tree, dev)
    assert check_version.problems(dev) == []
    # The README and the PyPI pages stay on the last release.
    for rel in ("README.md", "core-py/README.md", "daemon/README.md", "sdk/python/README.md"):
        assert (tree / rel).read_text(encoding="utf-8") == start[rel], rel
    assert "README.md" not in changed
    assert 'version = "0.1.0-alpha.' in (tree / "Cargo.toml").read_text(encoding="utf-8")
    assert check_version.semver(dev) in (tree / "Cargo.toml").read_text(encoding="utf-8")

    # The release PR: back to the release version, or on to the next one.
    set_version.set_version(tree, release)
    assert snapshot(tree) == start
    assert check_version.problems(release, release=True) == []


def test_the_next_release_moves_the_readme_and_the_pypi_pages(tree: Path) -> None:
    release = check_version.pyproject_version()
    dev = set_version.next_dev(release)
    set_version.set_version(tree, dev)
    final = dev.removesuffix(".dev0")

    changed = set_version.set_version(tree, final)
    assert check_version.problems(final, release=True) == []
    readme = (tree / "README.md").read_text(encoding="utf-8")
    assert f"uv tool install agentconnect-cli=={final}" in readme
    assert f"pip install agentconnect-cli=={final}" in readme
    assert f"latest pre-release is {final}" in readme
    assert release not in readme
    assert {"README.md", "daemon/README.md", "core-py/README.md", "sdk/python/README.md"} <= set(
        changed
    )
    for rel in ("core-py/README.md", "daemon/README.md", "sdk/python/README.md"):
        page = (tree / rel).read_text(encoding="utf-8")
        assert f"/blob/v{final}/" in page
        assert f"/blob/v{release}/" not in page


def test_main_is_used_by_the_recipes(tree: Path, capsys: pytest.CaptureFixture[str]) -> None:
    release = check_version.pyproject_version()
    assert set_version.main(["--next-dev"], tree) == 0
    out = capsys.readouterr().out
    assert f"version {set_version.next_dev(release)}:" in out
    assert "core-py/pyproject.toml" in out
    # --next-dev from a development version is an error, not a skip.
    assert set_version.main(["--next-dev"], tree) == 1
    assert "not a release version" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [[], ["a", "b"], ["-h"], ["--help"]])
def test_bad_usage_exits_2(tree: Path, argv: list[str]) -> None:
    assert set_version.main(argv, tree) == 2


def test_a_malformed_version_is_refused_and_nothing_changes(tree: Path) -> None:
    start = snapshot(tree)
    assert set_version.main(["0.1"], tree) == 1
    assert set_version.main(["v0.1.0a5"], tree) == 1
    assert snapshot(tree) == start


def test_a_file_without_the_expected_line_is_an_error(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tree / "daemon/src/agentconnect/__init__.py"
    path.write_text('"""No version here."""\n', encoding="utf-8")
    assert set_version.main(["0.1.0a9"], tree) == 1
    assert "__init__.py" in capsys.readouterr().err
