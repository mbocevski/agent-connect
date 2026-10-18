import importlib.util
import subprocess
import sys
from collections.abc import Callable
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "check_docs", Path(__file__).resolve().parents[1] / "check_docs.py"
)
assert _spec is not None
assert _spec.loader is not None
check_docs = importlib.util.module_from_spec(_spec)
sys.modules["check_docs"] = check_docs
_spec.loader.exec_module(check_docs)

Commit = check_docs.Commit
Rule = check_docs.Rule
Component = check_docs.Component

CLI = Rule("cli", ("daemon/src/agentconnect/cli.py",), ("docs/cli.md",))
RELAY = Rule("relay", ("relay/src/ws.rs", "relay/src/rest.rs"), ("SPEC.md", "relay/README.md"))
WIRE = Rule("wire", ("testdata/*.json",), ("SPEC.md",), ("testdata/MANIFEST.json",))
RULES = [CLI, RELAY, WIRE]


def names(commits: list[Commit]) -> list[str]:
    return [v.rule.name for v in check_docs.check(RULES, commits)]


def test_code_without_docs_fails() -> None:
    commits = [Commit("feat(daemon): new flag", ("daemon/src/agentconnect/cli.py",))]
    [v] = check_docs.check(RULES, commits)
    assert v.rule is CLI
    assert v.code == ("daemon/src/agentconnect/cli.py",)


def test_docs_in_same_commit_pass() -> None:
    commits = [Commit("feat(daemon): x", ("daemon/src/agentconnect/cli.py", "docs/cli.md"))]
    assert names(commits) == []


def test_docs_in_a_later_docs_commit_pass() -> None:
    commits = [
        Commit("feat(daemon): x", ("daemon/src/agentconnect/cli.py",)),
        Commit("docs: describe x", ("docs/cli.md",)),
    ]
    assert names(commits) == []


def test_any_of_several_docs_is_enough() -> None:
    assert names([Commit("fix(relay): y", ("relay/src/ws.rs", "relay/README.md"))]) == []
    assert names([Commit("fix(relay): y", ("relay/src/rest.rs", "SPEC.md"))]) == []


@pytest.mark.parametrize("kind", ["docs", "test", "ci", "chore", "build", "style"])
def test_exempt_types(kind: str) -> None:
    assert names([Commit(f"{kind}(daemon): x", ("daemon/src/agentconnect/cli.py",))]) == []
    assert names([Commit(f"{kind}: x", ("relay/src/ws.rs",))]) == []


@pytest.mark.parametrize("kind", ["feat", "fix", "refactor", "perf", "revert"])
def test_non_exempt_types(kind: str) -> None:
    assert names([Commit(f"{kind}: x", ("relay/src/ws.rs",))]) == ["relay"]


def test_exempt_commit_does_not_hide_a_feat_commit() -> None:
    commits = [
        Commit("test: vectors", ("testdata/sas-vectors.json",)),
        Commit("feat(daemon): x", ("daemon/src/agentconnect/cli.py",)),
    ]
    assert names(commits) == ["cli"]


def test_globs_and_excludes() -> None:
    assert names([Commit("feat: v", ("testdata/new-vector.json",))]) == ["wire"]
    assert names([Commit("feat: v", ("testdata/MANIFEST.json",))]) == []
    assert names([Commit("feat: v", ("testdata/notes.txt",))]) == []


def test_unmapped_code_passes() -> None:
    assert names([Commit("feat(core): z", ("core/src/lib.rs",))]) == []


def test_parse_log() -> None:
    rs = check_docs.RECORD
    text = f"{rs}feat: a\n\nx.py\ny.py\n{rs}docs: b\n\nREADME.md\n{rs}chore: empty\n"
    assert check_docs.parse_log(text) == [
        Commit("feat: a", ("x.py", "y.py")),
        Commit("docs: b", ("README.md",)),
        Commit("chore: empty", ()),
    ]


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("[[rule]]\ncode = ['a']\ndocs = ['b']\n", "name"),
        ("[[rule]]\nname = 'x'\ndocs = ['b']\n", "code"),
        ("[[rule]]\nname = 'x'\ncode = ['a']\ndocs = []\n", "docs"),
        ("[[rule]]\nname = 'x'\ncode = ['a']\ndocs = ['b']\nextra = 1\n", "unknown"),
        ("[[rule]]\nname = 'x'\ncode = 'a'\ndocs = ['b']\n", "list"),
        ("rules = 1\n", "unknown"),
        ("[[rule]]\nname = 'x'\ncode = ['a']\ndocs = ['b']\n" * 2, "unique"),
        ("not toml", "MAP.toml"),
    ],
)
def test_parse_map_errors(text: str, error: str) -> None:
    with pytest.raises(check_docs.MapError, match=error):
        check_docs.parse_map(text)


def test_repository_map_is_valid_and_honest() -> None:
    """Every glob in docs/MAP.toml matches files that exist."""
    repo = check_docs.REPO
    docs_map = check_docs.parse_map((repo / check_docs.MAP_PATH).read_text(encoding="utf-8"))
    rules = docs_map.rules
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=repo,
        env=check_docs.git_env(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert rules
    for rule in rules:
        for glob in rule.code:
            probe = Rule(rule.name, (glob,), rule.docs, rule.exclude)
            assert any(probe.covers(f) for f in tracked), f"{rule.name}: {glob} matches nothing"
    for comp in docs_map.components:
        for glob in comp.paths:
            probe = Component(comp.name, (glob,), comp.doc)
            assert any(probe.covers(f) for f in tracked), f"{comp.name}: {glob} matches nothing"
    for glob in docs_map.internal:
        assert any(fnmatchcase(f, glob) for f in tracked), f"internal: {glob} matches nothing"


def test_repository_structure_is_consistent() -> None:
    """The README Status section, the components, the workspace members and
    the source tree agree."""
    repo = check_docs.REPO
    docs_map = check_docs.parse_map((repo / check_docs.MAP_PATH).read_text(encoding="utf-8"))
    assert check_docs.check_structure(docs_map, repo) == []


# A throwaway repository: real git, no network, no global hooks or signing.
GIT = [
    "git",
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "init.defaultBranch=main",
]


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        [*GIT, *args], cwd=repo, env=check_docs.git_env(), check=True, capture_output=True
    )


def commit(repo: Path, subject: str, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "--allow-empty", "-q", "-m", subject)


MAP = """
internal = ["core/src/lib.rs"]

[[rule]]
name = "cli"
code = ["cli.py"]
docs = ["docs/cli.md"]

[[component]]
name = "cli"
paths = ["cli.py"]
doc = "docs/cli.md"
"""

README_TEXT = """# T

## Status

- **CLI**: the commands ([docs/cli.md](docs/cli.md)).
  <!-- component: cli -->

## Development
"""

CHANGELOG_TEXT = """# Changelog

## [Unreleased]

### Added

- Old entry.

## [0.1.0]

### Added

- Released entry.
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    commit(
        tmp_path,
        "chore: init",
        {
            "docs/MAP.toml": MAP,
            "README.md": README_TEXT,
            "CHANGELOG.md": CHANGELOG_TEXT,
            "docs/cli.md": "cli\n",
            "cli.py": "v1\n",
        },
    )
    git(tmp_path, "branch", "base")
    git(tmp_path, "switch", "-q", "-c", "topic")
    return tmp_path


def test_main_fails_and_passes_on_a_real_branch(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "feat: new flag", {"cli.py": "v2\n"})
    assert check_docs.main(["base"], {}, repo) == 1
    assert "docs/cli.md" in capsys.readouterr().err
    assert check_docs.main(["base"], {"SKIP_DOCS": "true"}, repo) == 0
    commit(repo, "docs: describe the flag", {"docs/cli.md": "flag\n"})
    assert check_docs.main(["base"], {}, repo) == 0


def test_main_ignores_merge_commits(repo: Path) -> None:
    """CI checks out a synthetic merge of the PR into the base branch."""
    commit(repo, "feat: new flag", {"cli.py": "v2\n"})
    commit(repo, "docs: describe the flag", {"docs/cli.md": "flag\n"})
    git(repo, "switch", "-q", "base")
    commit(repo, "fix: unrelated", {"other.py": "x\n"})
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge topic into base", "topic")
    git(repo, "switch", "-q", "--detach", "HEAD")
    git(repo, "branch", "-f", "base", "HEAD~1")
    commits = check_docs.branch_commits("base", repo)
    assert commits is not None
    assert [c.subject for c in commits] == ["docs: describe the flag", "feat: new flag"]
    assert check_docs.main(["base"], {}, repo) == 0


def test_main_skips_without_a_base(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert check_docs.main(["origin/nope"], {}, repo) == 0
    assert "skipping" in capsys.readouterr().out


def test_main_no_commits(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert check_docs.main(["base"], {}, repo) == 0
    assert "no commits" in capsys.readouterr().out


def test_main_bad_map(repo: Path) -> None:
    commit(repo, "feat: break", {"docs/MAP.toml": "nope"})
    assert check_docs.main(["base"], {}, repo) == 2


def test_main_usage() -> None:
    assert check_docs.main(["a", "b"], {}) == 2


def test_main_ignores_git_dir_exported_by_hooks(
    repo: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hooks run with GIT_DIR set; the check must still read ``repo``."""
    other = tmp_path_factory.mktemp("other")
    git(other, "init", "-q")
    commit(repo, "feat: new flag", {"cli.py": "v2\n"})
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert check_docs.main(["base"], {}, repo) == 1


# --- README Status, components, workspace members, source files -------------

CLI_COMP = Component("cli", ("cli.py",), "docs/cli.md")
HARNESS = Component("harness", ("harness/**",), "TESTING.md", readme=False)


def everything_exists(_path: str) -> bool:
    return True


def status(
    readme: str,
    comps: tuple[Component, ...] = (CLI_COMP,),
    exists: Callable[[str], bool] = everything_exists,
) -> list[str]:
    return [str(e) for e in check_docs.check_status(comps, readme, exists)]


def test_status_consistent_readme_passes() -> None:
    assert status(README_TEXT) == []


def test_status_missing_bullet_fails() -> None:
    errors = status("# T\n\n## Status\n\nNothing here.\n\n## Development\n")
    assert errors == ["[cli] has no README Status bullet (<!-- component: cli -->)"]


def test_status_bullet_without_component_fails() -> None:
    text = README_TEXT.replace("## Development", "- **Extra**: a feature.\n\n## Development")
    [error] = status(text)
    assert "'- **Extra**: a feature.'" in error
    assert "has no component" in error


def test_status_bullet_naming_unknown_component_fails() -> None:
    text = README_TEXT.replace("component: cli", "component: cli, ghost")
    [error] = status(text)
    assert "unknown component 'ghost'" in error


def test_status_bullet_must_link_the_component_doc() -> None:
    [error] = status(README_TEXT.replace("(docs/cli.md)", "(docs/api.md)"))
    assert "does not link docs/cli.md" in error


def test_status_bullet_linking_a_missing_file_fails() -> None:
    errors = status(README_TEXT, exists=lambda p: p != "docs/cli.md")
    assert any("[cli] doc docs/cli.md does not exist" in e for e in errors)
    assert any("links docs/cli.md, which does not exist" in e for e in errors)


def test_status_ignores_external_and_anchor_links() -> None:
    text = README_TEXT.replace(
        "the commands", "[a](https://example.org/x) [b](#development) [c](docs/cli.md#top)"
    )
    assert status(text) == []


def test_status_bullet_may_cover_several_components() -> None:
    other = Component("api", ("api.py",), "docs/api.md")
    text = (
        "## Status\n\n- Both ([cli](docs/cli.md), [api](docs/api.md)).\n"
        "  <!-- component: cli, api -->\n"
    )
    assert status(text, (CLI_COMP, other)) == []


def test_status_readme_false_component_needs_no_bullet() -> None:
    assert status(README_TEXT, (CLI_COMP, HARNESS)) == []
    text = README_TEXT.replace(
        "## Development", "- T ([t](TESTING.md))\n  <!-- component: harness -->\n"
    )
    assert status(text, (CLI_COMP, HARNESS)) == [
        "[harness] is readme = false but has a README Status bullet"
    ]


def test_status_without_a_section() -> None:
    assert status("# T\n") == ["README.md has no '## Status' section"]
    assert check_docs.check_status([CLI_COMP], None, everything_exists) == ["README.md not found"]


def test_status_section_ends_at_the_next_heading() -> None:
    assert status(README_TEXT + "- **Later**: not a Status bullet.\n") == []


def write(root: Path, name: str, text: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")


def test_workspace_members_cargo_and_uv(tmp_path: Path) -> None:
    write(tmp_path, "Cargo.toml", '[workspace]\nmembers = ["core", "tools/*"]\n')
    write(tmp_path, "pyproject.toml", '[tool.uv.workspace]\nmembers = ["daemon", "sdk/python"]\n')
    write(tmp_path, "tools/a/Cargo.toml", "")
    write(tmp_path, "tools/note.txt", "not a directory")
    assert check_docs.workspace_members(tmp_path) == ["core", "daemon", "sdk/python", "tools/a"]
    assert check_docs.workspace_members(tmp_path / "missing") == []


def test_unclassified_member_fails_until_a_component_claims_it() -> None:
    comps = [Component("core", ("core/**",), "SPEC.md"), Component("sdk", ("sdk/python/**",), "x")]
    assert check_docs.check_members(comps, ["core", "sdk/python"]) == []
    [error] = check_docs.check_members(comps, ["core", "newcrate"])
    assert error.startswith("workspace member newcrate is not in any [[component]]")
    # A glob that covers only part of a member does not classify it.
    narrow = [Component("x", ("newcrate/src/**",), "x")]
    assert len(check_docs.check_members(narrow, ["newcrate"])) == 1


def test_unclassified_source_file_fails() -> None:
    docs_map = check_docs.parse_map(
        'internal = ["core/src/lib.rs", "harness/src/**"]\n'
        '[[rule]]\nname = "r"\ncode = ["relay/src/*.rs"]\ndocs = ["SPEC.md"]\n'
        'exclude = ["relay/src/main.rs"]\n'
    )
    files = [
        "core/src/lib.rs",  # internal
        "harness/src/pkg/a.py",  # internal glob
        "relay/src/ws.rs",  # rule
        "relay/src/main.rs",  # excluded from the rule, and not internal
        "daemon/src/agentconnect/new.py",  # nothing
        "core/src/data.json",  # not a source file
        "core/tests/t.rs",  # not under a source root
        "scripts/x.py",  # not under a source root
    ]
    errors = check_docs.check_coverage(docs_map, files)
    assert [e.split(" ", 1)[0] for e in errors] == [
        "daemon/src/agentconnect/new.py",
        "relay/src/main.rs",
    ]
    assert "internal" in errors[0]


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("[[component]]\npaths = ['a']\ndoc = 'd'\n", "name"),
        ("[[component]]\nname = 'Bad Name'\npaths = ['a']\ndoc = 'd'\n", "lowercase"),
        ("[[component]]\nname = 'x'\ndoc = 'd'\n", "paths"),
        ("[[component]]\nname = 'x'\npaths = ['a']\n", "doc"),
        ("[[component]]\nname = 'x'\npaths = ['a']\ndoc = 'd'\nreadme = 'no'\n", "readme"),
        ("[[component]]\nname = 'x'\npaths = ['a']\ndoc = 'd'\nextra = 1\n", "unknown"),
        ("[[component]]\nname = 'x'\npaths = ['a']\ndoc = 'd'\n" * 2, "unique"),
        ("internal = 'a'\n", "list"),
    ],
)
def test_parse_map_component_errors(text: str, error: str) -> None:
    with pytest.raises(check_docs.MapError, match=error):
        check_docs.parse_map(text)


def test_added_entries_reads_only_unreleased_added() -> None:
    text = (
        "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- One\n  continued.\n- Two\n\n"
        "### Fixed\n\n- Not an addition\n\n## [0.1.0]\n\n### Added\n\n- Released\n"
    )
    assert check_docs.added_entries(text) == {"- One continued.", "- Two"}
    assert check_docs.added_entries("") == set()


def test_feature_without_readme_change_fails() -> None:
    commits = [Commit("feat: x", ("cli.py",))]
    v = check_docs.check_readme([CLI_COMP], commits, {"- New"})
    assert v is not None
    assert [c.name for c in v.components] == ["cli"]
    assert v.code == ("cli.py",)


def test_feature_check_passes_when_it_should() -> None:
    entry = {"- New"}
    feat = Commit("feat: x", ("cli.py",))
    comps = [CLI_COMP, HARNESS]
    assert check_docs.check_readme(comps, [feat], set()) is None
    assert check_docs.check_readme(comps, [feat, Commit("docs: s", ("README.md",))], entry) is None
    assert check_docs.check_readme(comps, [Commit("ci: x", ("cli.py",))], entry) is None
    assert check_docs.check_readme(comps, [Commit("feat: x", ("other.py",))], entry) is None
    assert check_docs.check_readme(comps, [Commit("feat: x", ("harness/a.py",))], entry) is None


def add_changelog_entry(repo: Path) -> None:
    text = CHANGELOG_TEXT.replace("- Old entry.", "- Old entry.\n- A new feature.")
    commit(repo, "docs: changelog", {"CHANGELOG.md": text})


def test_main_added_entry_without_readme_fails_and_skip_readme_passes(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "feat: new flag", {"cli.py": "v2\n", "docs/cli.md": "flag\n"})
    add_changelog_entry(repo)
    assert check_docs.main(["base"], {}, repo) == 1
    err = capsys.readouterr().err
    assert "README.md did not" in err
    assert "skip-readme" in err
    assert check_docs.main(["base"], {"SKIP_README": "true"}, repo) == 0
    # skip-docs is a different escape hatch and does not skip the README check.
    assert check_docs.main(["base"], {"SKIP_DOCS": "true"}, repo) == 1


def test_main_added_entry_with_readme_change_passes(repo: Path) -> None:
    commit(repo, "feat: new flag", {"cli.py": "v2\n", "docs/cli.md": "flag\n"})
    add_changelog_entry(repo)
    commit(repo, "docs(readme): status", {"README.md": README_TEXT + "\nMore.\n"})
    assert check_docs.main(["base"], {}, repo) == 0


def test_main_without_a_new_added_entry_passes(repo: Path) -> None:
    commit(repo, "feat: new flag", {"cli.py": "v2\n", "docs/cli.md": "flag\n"})
    assert check_docs.main(["base"], {}, repo) == 0
    # An entry under Fixed is not a new feature.
    fixed = CHANGELOG_TEXT.replace("## [0.1.0]", "### Fixed\n\n- A fix.\n\n## [0.1.0]")
    commit(repo, "docs: changelog", {"CHANGELOG.md": fixed})
    assert check_docs.main(["base"], {}, repo) == 0


def test_main_added_entry_without_component_code_passes(repo: Path) -> None:
    commit(repo, "feat: elsewhere", {"other.py": "x\n"})
    add_changelog_entry(repo)
    assert check_docs.main(["base"], {}, repo) == 0


def test_main_fails_on_a_component_without_a_readme_bullet(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "docs: drop the bullet", {"README.md": "# T\n\n## Status\n\nNone.\n"})
    assert check_docs.main(["base"], {}, repo) == 1
    assert "[cli] has no README Status bullet" in capsys.readouterr().err


def test_main_fails_on_a_readme_bullet_without_a_component(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = README_TEXT.replace("## Development", "- **Extra**: a thing.\n\n## Development")
    commit(repo, "docs: add a bullet", {"README.md": text})
    assert check_docs.main(["base"], {}, repo) == 1
    assert "has no component" in capsys.readouterr().err


def test_main_fails_on_an_unclassified_workspace_member(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "build: add a crate", {"Cargo.toml": '[workspace]\nmembers = ["newcrate"]\n'})
    assert check_docs.main(["base"], {}, repo) == 1
    assert "workspace member newcrate" in capsys.readouterr().err
    commit(
        repo,
        "build: add a package",
        {
            "Cargo.toml": "[workspace]\nmembers = []\n",
            "pyproject.toml": '[tool.uv.workspace]\nmembers = ["pkg"]\n',
        },
    )
    assert check_docs.main(["base"], {}, repo) == 1
    assert "workspace member pkg" in capsys.readouterr().err


def test_main_fails_on_an_unclassified_source_file(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "chore: new module", {"core/src/new.rs": "// x\n"})
    assert check_docs.main(["base"], {"SKIP_DOCS": "true"}, repo) == 1
    assert "core/src/new.rs is not classified" in capsys.readouterr().err
    classified = MAP.replace('["core/src/lib.rs"]', '["core/src/*.rs"]')
    commit(repo, "chore: classify it", {"docs/MAP.toml": classified})
    assert check_docs.main(["base"], {}, repo) == 0


def test_main_structure_errors_survive_a_missing_base(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "docs: drop the bullet", {"README.md": "# T\n\n## Status\n\nNone.\n"})
    assert check_docs.main(["origin/nope"], {}, repo) == 1
    assert "skipping" in capsys.readouterr().out
