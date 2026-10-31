import importlib.util
import os
import shutil
import subprocess
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


def _load_set_version() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "set_version", Path(__file__).resolve().parents[1] / "set_version.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["set_version"] = module
    spec.loader.exec_module(module)
    return module


set_version = _load_set_version()
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


@pytest.mark.parametrize(
    ("pep440", "cargo"),
    [
        ("0.1.0a5.dev0", "0.1.0-alpha.5.dev.0"),
        ("0.2.0b1.dev3", "0.2.0-beta.1.dev.3"),
        ("1.0.0rc2.dev0", "1.0.0-rc.2.dev.0"),
        ("0.2.0.dev0", "0.2.0-dev.0"),
    ],
)
def test_development_versions_have_a_semver_spelling(pep440: str, cargo: str) -> None:
    assert check_version.semver(pep440) == cargo


@pytest.mark.parametrize(
    "bad",
    ["0.1", "0.1.0-alpha.1", "v0.1.0a1", "0.1.0a", "0.1.0.dev", "0.1.0.dev1.2", "0.1.0a1.dev0.1"],
)
def test_malformed_versions_are_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="not a version"):
        check_version.semver(bad)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("0.1.0a4", "0.1.0a5.dev0"),
        ("0.1.0a5.dev0", "0.1.0a5.dev1"),
        ("0.1.0a5.dev1", "0.1.0a5"),
        ("0.1.0a5", "0.1.0b1"),
        ("0.1.0rc1", "0.1.0"),
        ("0.1.0", "0.1.1.dev0"),
        ("0.2.0.dev0", "0.2.0a1"),
        ("0.1.9", "0.2.0.dev0"),
    ],
)
def test_versions_sort_as_pep_440_does(lower: str, higher: str) -> None:
    assert check_version.order(lower) < check_version.order(higher)


@pytest.mark.parametrize(
    ("version", "dev"),
    [("0.1.0a5.dev0", True), ("0.2.0.dev3", True), ("0.1.0a5", False), ("0.1.0", False)],
)
def test_is_dev(version: str, dev: bool) -> None:
    assert check_version.is_dev(version) is dev


def test_the_repository_agrees_with_itself() -> None:
    assert check_version.main(["check_version.py"]) == 0


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for rel in FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, tmp_path / rel)
    monkeypatch.setattr(check_version, "ROOT", tmp_path)
    # Whatever the checkout carries (a release or the development version after
    # it), the tests start from the tree a release PR leaves: the version the
    # README installs, everywhere.
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    set_version.set_version(tmp_path, str(check_version.INSTALL.findall(readme)[0]))
    return tmp_path


def _version() -> str:
    return str(check_version.pyproject_version())


def test_a_copy_of_the_tree_passes(tree: Path) -> None:
    assert check_version.problems(_version()) == []


def test_another_version_fails_everywhere(tree: Path) -> None:
    found = check_version.problems("9.9.9")
    assert len(found) == 12, found


# --- development versions ----------------------------------------------------


def _set_dev(tree: Path, version: str = "0.1.0a9.dev0") -> None:
    """The tree as `main` is between releases: the packages and Cargo.toml at
    ``version``, the README and the PyPI pages still on the last release."""
    old = _version()
    for rel, replacements in {
        "core-py/pyproject.toml": [(f'version = "{old}"', f'version = "{version}"')],
        "daemon/pyproject.toml": [
            (f'version = "{old}"', f'version = "{version}"'),
            (f"agentconnect-core=={old}", f"agentconnect-core=={version}"),
        ],
        "sdk/python/pyproject.toml": [
            (f'version = "{old}"', f'version = "{version}"'),
            (f"agentconnect-cli=={old}", f"agentconnect-cli=={version}"),
        ],
        "daemon/src/agentconnect/__init__.py": [(f'"{old}"', f'"{version}"')],
        "sdk/python/src/agentconnect_sdk/__init__.py": [(f'"{old}"', f'"{version}"')],
        "Cargo.toml": [
            (
                f'version = "{check_version.semver(old)}"',
                f'version = "{check_version.semver(version)}"',
            )
        ],
    }.items():
        text = (tree / rel).read_text(encoding="utf-8")
        for a, b in replacements:
            assert a in text, (rel, a)
            text = text.replace(a, b, 1)
        (tree / rel).write_text(text, encoding="utf-8")


def test_main_between_releases_passes_with_a_dev_version(tree: Path) -> None:
    last = _version()
    _set_dev(tree)
    assert check_version.pyproject_version() == "0.1.0a9.dev0"
    assert check_version.problems("0.1.0a9.dev0") == []
    # The README and the PyPI pages still name the last release.
    assert check_install(tree) == last


def check_install(tree: Path) -> str:
    return str(check_version.INSTALL.findall((tree / "README.md").read_text(encoding="utf-8"))[0])


def test_a_release_refuses_a_dev_version(tree: Path) -> None:
    _set_dev(tree)
    found = check_version.problems("0.1.0a9.dev0", release=True)
    assert len(found) == 1, found
    assert "development version" in found[0]


def test_a_readme_that_installs_the_dev_version_is_refused(tree: Path) -> None:
    # Users can't install a development version: the README names the last release.
    _set_dev(tree)
    readme = tree / "README.md"
    last = check_install(tree)
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(f"=={last}", "==0.1.0a9.dev0"), encoding="utf-8"
    )
    found = check_version.problems("0.1.0a9.dev0")
    assert any("last release" in f for f in found), found


def test_the_readme_must_install_a_version_below_the_dev_version(tree: Path) -> None:
    _set_dev(tree, "0.1.0a1.dev0")  # at or below the README's release
    found = check_version.problems("0.1.0a1.dev0")
    assert any("not below" in f for f in found), found


def test_the_pypi_pages_must_link_the_last_release_in_dev(tree: Path) -> None:
    _set_dev(tree)
    page = tree / "daemon/README.md"
    page.write_text(
        page.read_text(encoding="utf-8").replace("/blob/v", "/blob/main/v", 1), encoding="utf-8"
    )
    found = check_version.problems("0.1.0a9.dev0")
    assert len(found) == 1, found
    assert "daemon/README.md" in found[0]


def test_main_flags_work_on_the_command_line(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_dev(tree)
    assert check_version.main(["check_version.py"]) == 0
    assert capsys.readouterr().out.strip() == "0.1.0a9.dev0"
    assert check_version.main(["check_version.py", "--release"]) == 1
    assert "development version" in capsys.readouterr().err
    # A tag spelled as a dev version is refused too.
    assert check_version.main(["check_version.py", "--release", "0.1.0a9.dev0"]) == 1
    assert check_version.main(["check_version.py", "--nope"]) == 2
    assert check_version.main(["check_version.py", "1", "2"]) == 2


def test_post_release_flags_a_release_version_that_is_already_tagged(
    tree: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    release = _version()
    monkeypatch.setattr(check_version, "tagged", lambda v: v == release)
    assert check_version.main(["check_version.py", "--post-release"]) == 1
    assert f"tag v{release} exists" in capsys.readouterr().err
    # Before the tag exists, and once main has moved on, it passes.
    monkeypatch.setattr(check_version, "tagged", lambda _: False)
    assert check_version.main(["check_version.py", "--post-release"]) == 0
    _set_dev(tree)
    monkeypatch.setattr(check_version, "tagged", lambda _: True)
    assert check_version.main(["check_version.py", "--post-release"]) == 0


def test_tagged_asks_git_for_the_tag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": os.environ["PATH"],
    }
    cmds = [
        ["git", "init", "-q"],
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "x",
        ],
        ["git", "tag", "v1.2.3"],
    ]
    for cmd in cmds:
        subprocess.run(cmd, cwd=tmp_path, env=env, check=True, capture_output=True)
    monkeypatch.setattr(check_version, "ROOT", tmp_path)
    # A git hook runs with GIT_DIR pointing at the repository being pushed.
    monkeypatch.setenv("GIT_DIR", str(REPO / ".git"))
    assert check_version.tagged("1.2.3") is True
    assert check_version.tagged("1.2.4") is False


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
