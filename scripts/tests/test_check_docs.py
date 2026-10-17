import importlib.util
import subprocess
import sys
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
    """Every rule in docs/MAP.toml watches files that exist."""
    repo = check_docs.REPO
    rules = check_docs.parse_map((repo / check_docs.MAP_PATH).read_text(encoding="utf-8"))
    tracked = subprocess.run(
        ["git", "ls-files"],  # noqa: S607
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
    subprocess.run(  # noqa: S603
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
[[rule]]
name = "cli"
code = ["cli.py"]
docs = ["docs/cli.md"]
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    commit(tmp_path, "chore: init", {"docs/MAP.toml": MAP, "cli.py": "v1\n"})
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
