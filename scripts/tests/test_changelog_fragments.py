"""Tests for changelog fragments: the cut and preview (scripts/changelog_fragments.py,
changelog-cut.sh), the changelog check (check-changelog.sh) and the release notes
that read the cut CHANGELOG (release-notes.sh)."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "changelog_fragments", SCRIPTS / "changelog_fragments.py"
)
assert _spec is not None
assert _spec.loader is not None
cf = importlib.util.module_from_spec(_spec)
sys.modules["changelog_fragments"] = cf
_spec.loader.exec_module(cf)

CHANGELOG = """# Changelog

Intro.

## [Unreleased]

### Added

- Existing added.

### Fixed

- Existing fix.

## [0.1.0] - 2026-10-20

### Added

- Released.
"""


def fragment(slug: str, section: str, text: str = "") -> tuple[str, str]:
    return f"{slug}.{section}.md", text or f"- {slug} {section}.\n"


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    (tmp_path / "changelog.d").mkdir()
    return tmp_path


def put(tree: Path, *fragments: tuple[str, str]) -> None:
    for name, text in fragments:
        (tree / "changelog.d" / name).write_text(text, encoding="utf-8")


def cut(tree: Path, version: str = "0.2.0", date: str = "2026-11-01") -> str:
    cf.cut(tree / "CHANGELOG.md", tree / "changelog.d", version, date)
    return (tree / "CHANGELOG.md").read_text(encoding="utf-8")


# --- parse_fragment ---------------------------------------------------------


def test_a_fragment_is_one_bullet_that_may_wrap() -> None:
    f = cf.parse_fragment("facade-socket.added.md", "- First line\n  second line.\n\n")
    assert (f.slug, f.section, f.text) == ("facade-socket", "added", "- First line\n  second line.")


@pytest.mark.parametrize(
    "name",
    [
        "x.md",
        "x.added.txt",
        "x.unknown.md",
        "X.added.md",
        "a_b.added.md",
        "-x.added.md",
        ".added.md",
        "a.b.added.md",
        "added.md",
    ],
)
def test_bad_names_are_refused(name: str) -> None:
    with pytest.raises(cf.ChangelogError, match=r"named <slug>\.<section>\.md"):
        cf.parse_fragment(name, "- ok\n")


@pytest.mark.parametrize(
    ("content", "error"),
    [
        ("", "starts with '- '"),
        ("   \n", "starts with '- '"),
        ("text\n", "starts with '- '"),
        ("-\n", "starts with '- '"),
        ("- \n", "starts with '- '"),
        ("- one\n- two\n", "indent the lines"),
        ("- one\ntwo\n", "indent the lines"),
        ("- one\n### Added\n", "indent the lines"),
        ("- one\n\n  more\n", "without blank lines"),
    ],
)
def test_bad_content_is_refused(content: str, error: str) -> None:
    with pytest.raises(cf.ChangelogError, match=error):
        cf.parse_fragment("x.added.md", content)


def test_a_nested_list_is_part_of_the_bullet() -> None:
    f = cf.parse_fragment("x.added.md", "- Top\n  - nested\n  - nested too\n")
    assert f.text == "- Top\n  - nested\n  - nested too"


# --- read_fragments ---------------------------------------------------------


def test_fragments_come_in_section_order_then_slug_order(tree: Path) -> None:
    put(
        tree,
        fragment("zeta", "added"),
        fragment("alpha", "security"),
        fragment("beta", "added"),
        fragment("mid", "fixed"),
        fragment("gone", "removed"),
        fragment("sunset", "deprecated"),
        fragment("tweak", "changed"),
    )
    got = [(f.section, f.slug) for f in cf.read_fragments(tree / "changelog.d")]
    assert got == [
        ("added", "beta"),
        ("added", "zeta"),
        ("changed", "tweak"),
        ("deprecated", "sunset"),
        ("removed", "gone"),
        ("fixed", "mid"),
        ("security", "alpha"),
    ]


def test_the_readme_and_gitkeep_are_not_fragments(tree: Path) -> None:
    (tree / "changelog.d" / "README.md").write_text("# About\n", encoding="utf-8")
    (tree / "changelog.d" / ".gitkeep").write_text("", encoding="utf-8")
    assert cf.read_fragments(tree / "changelog.d") == []


def test_a_missing_directory_has_no_fragments(tmp_path: Path) -> None:
    assert cf.read_fragments(tmp_path / "nothing") == []


def test_a_stray_file_is_an_error_not_a_silent_omission(tree: Path) -> None:
    put(tree, ("notes.md", "- x\n"))
    with pytest.raises(cf.ChangelogError, match=r"notes\.md"):
        cf.read_fragments(tree / "changelog.d")


def test_a_subdirectory_and_a_symlink_are_errors(tree: Path) -> None:
    (tree / "changelog.d" / "sub").mkdir()
    with pytest.raises(cf.ChangelogError, match="not a regular file"):
        cf.read_fragments(tree / "changelog.d")
    (tree / "changelog.d" / "sub").rmdir()
    (tree / "changelog.d" / "x.added.md").symlink_to(tree / "CHANGELOG.md")
    with pytest.raises(cf.ChangelogError, match="not a regular file"):
        cf.read_fragments(tree / "changelog.d")


# --- assemble and cut -------------------------------------------------------


def test_the_cut_adds_a_release_section_and_keeps_older_ones(tree: Path) -> None:
    put(tree, fragment("new-thing", "added", "- New thing.\n"))
    text = cut(tree)
    head, _, old = text.partition("## [0.1.0]")
    assert "## [Unreleased]\n\n## [0.2.0] - 2026-11-01\n\n### Added\n" in head
    assert old == " - 2026-10-20\n\n### Added\n\n- Released.\n"
    assert head.startswith("# Changelog\n\nIntro.\n\n")


def test_existing_entries_stay_above_the_fragments_of_their_section(tree: Path) -> None:
    put(tree, fragment("b", "added", "- B.\n"), fragment("a", "added", "- A.\n"))
    text = cut(tree)
    assert "### Added\n\n- Existing added.\n- A.\n- B.\n\n### Fixed\n\n- Existing fix.\n" in text


def test_sections_come_in_order_whatever_the_fragments_and_the_old_text_do(tree: Path) -> None:
    put(
        tree,
        fragment("s", "security"),
        fragment("c", "changed"),
        fragment("r", "removed"),
        fragment("d", "deprecated"),
    )
    text = cut(tree)
    section = text.split("## [0.2.0]")[1].split("## [0.1.0]")[0]
    order = [line for line in section.splitlines() if line.startswith("### ")]
    assert order == [
        "### Added",
        "### Changed",
        "### Deprecated",
        "### Removed",
        "### Fixed",
        "### Security",
    ]
    assert section.index("- s security.") > section.index("- Existing fix.")


def test_a_note_above_the_first_heading_moves_with_the_section(tree: Path) -> None:
    note = "This preview needs a data reset.\n\n"
    (tree / "CHANGELOG.md").write_text(
        CHANGELOG.replace("## [Unreleased]\n\n", f"## [Unreleased]\n\n{note}"), encoding="utf-8"
    )
    put(tree, fragment("x", "fixed", "- X.\n"))
    text = cut(tree)
    assert "## [0.2.0] - 2026-11-01\n\nThis preview needs a data reset.\n\n### Added\n" in text


def test_fragments_alone_make_a_release(tree: Path) -> None:
    (tree / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-10-20\n\n- Old.\n", encoding="utf-8"
    )
    put(tree, fragment("x", "fixed", "- X, wrapped\n  over two lines.\n"))
    assert cut(tree) == (
        "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-11-01\n\n### Fixed\n\n"
        "- X, wrapped\n  over two lines.\n\n## [0.1.0] - 2026-10-20\n\n- Old.\n"
    )


def test_a_changelog_without_older_releases_ends_cleanly(tree: Path) -> None:
    (tree / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n", encoding="utf-8")
    put(tree, fragment("x", "added", "- X.\n"))
    assert (
        cut(tree)
        == "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-11-01\n\n### Added\n\n- X.\n"
    )


def test_the_cut_deletes_the_fragments_and_nothing_else(tree: Path) -> None:
    (tree / "changelog.d" / "README.md").write_text("# About\n", encoding="utf-8")
    put(tree, fragment("a", "added"), fragment("b", "fixed"))
    cut(tree)
    assert sorted(p.name for p in (tree / "changelog.d").iterdir()) == ["README.md"]


def test_the_cut_without_fragments_still_cuts_the_old_text(tree: Path) -> None:
    text = cut(tree)
    assert (
        "## [0.2.0] - 2026-11-01\n\n### Added\n\n- Existing added.\n\n"
        "### Fixed\n\n- Existing fix.\n" in text
    )


def test_nothing_to_release_is_an_error(tree: Path) -> None:
    (tree / "CHANGELOG.md").write_text(
        "# C\n\n## [Unreleased]\n\n## [0.1.0]\n\n- Old.\n", encoding="utf-8"
    )
    with pytest.raises(cf.ChangelogError, match="nothing to release"):
        cut(tree)


def test_a_failed_cut_changes_nothing(tree: Path) -> None:
    put(tree, fragment("good", "added"), ("bad.md", "- x\n"))
    with pytest.raises(cf.ChangelogError):
        cut(tree)
    assert (tree / "CHANGELOG.md").read_text(encoding="utf-8") == CHANGELOG
    assert (tree / "changelog.d" / "good.added.md").exists()


@pytest.mark.parametrize(
    ("version", "date", "error"),
    [
        ("0.1.0", "2026-11-01", r"already has a \[0.1.0\]"),
        ("v0.2.0", "2026-11-01", "version must be"),
        ("0.2", "2026-11-01", "version must be"),
        ("0.2.0", "11/01/2026", "date must be"),
    ],
)
def test_a_bad_version_or_date_is_refused(tree: Path, version: str, date: str, error: str) -> None:
    put(tree, fragment("x", "added"))
    with pytest.raises(cf.ChangelogError, match=error):
        cut(tree, version, date)
    assert (tree / "changelog.d" / "x.added.md").exists()


def test_a_heading_outside_the_sections_is_an_error(tree: Path) -> None:
    (tree / "CHANGELOG.md").write_text(CHANGELOG.replace("### Fixed", "### Misc"), encoding="utf-8")
    with pytest.raises(cf.ChangelogError, match="Misc"):
        cut(tree)


def test_a_repeated_heading_is_an_error(tree: Path) -> None:
    (tree / "CHANGELOG.md").write_text(
        CHANGELOG.replace("### Fixed", "### Added"), encoding="utf-8"
    )
    with pytest.raises(cf.ChangelogError, match="two '### Added'"):
        cut(tree)


@pytest.mark.parametrize("changelog", ["# C\n", "# C\n\n## [Unreleased]\n\n## [Unreleased]\n"])
def test_the_changelog_needs_exactly_one_unreleased_heading(tree: Path, changelog: str) -> None:
    (tree / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    put(tree, fragment("x", "added"))
    with pytest.raises(cf.ChangelogError, match="exactly one"):
        cut(tree)


# --- the command line -------------------------------------------------------


def run_main(tree: Path, *argv: str) -> int:
    return int(cf.main(list(argv), {}, tree))


def test_preview_prints_what_the_cut_will_write(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    put(tree, fragment("new", "added", "- New.\n"))
    assert run_main(tree, "preview") == 0
    shown = capsys.readouterr().out
    assert shown.startswith("## [Unreleased]\n\n### Added\n\n- Existing added.\n- New.\n")
    assert (tree / "changelog.d" / "new.added.md").exists()
    assert (tree / "CHANGELOG.md").read_text(encoding="utf-8") == CHANGELOG
    run_main(tree, "cut", "0.2.0", "2026-11-01")
    assert "### Added\n\n- Existing added.\n- New.\n" in (tree / "CHANGELOG.md").read_text(
        encoding="utf-8"
    )


def test_preview_of_an_empty_unreleased_says_so(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tree / "CHANGELOG.md").write_text("# C\n\n## [Unreleased]\n", encoding="utf-8")
    assert run_main(tree, "preview") == 0
    assert "(nothing yet)" in capsys.readouterr().out


def test_validate_counts_fragments_and_fails_on_a_bad_one(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    put(tree, fragment("a", "added"))
    assert run_main(tree, "validate") == 0
    assert "1 fragment(s) valid" in capsys.readouterr().out
    put(tree, ("b.added.md", "not a bullet\n"))
    assert run_main(tree, "validate") == 1
    assert "b.added.md" in capsys.readouterr().err


def test_cut_defaults_the_date_to_today_utc(tree: Path) -> None:
    put(tree, fragment("x", "added"))
    assert run_main(tree, "cut", "0.2.0") == 0
    assert "## [0.2.0] - 20" in (tree / "CHANGELOG.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("argv", [[], ["cut"], ["preview", "x"], ["nope"], ["cut", "1", "2", "3"]])
def test_bad_usage_exits_2(tree: Path, argv: list[str]) -> None:
    assert run_main(tree, *argv) == 2


# --- the scripts, in a throwaway repository ---------------------------------

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


def env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def git(repo: Path, *args: str) -> None:
    subprocess.run([*GIT, *args], cwd=repo, env=env(), check=True, capture_output=True)


def commit(repo: Path, subject: str, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "--allow-empty", "-q", "-m", subject)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository with the changelog scripts, a base commit tagged `base`, and
    the branch `topic` checked out."""
    (tmp_path / "scripts").mkdir()
    for name in (
        "changelog_fragments.py",
        "check-changelog.sh",
        "changelog-cut.sh",
        "changelog-section.sh",
        "release-notes.sh",
    ):
        shutil.copy(SCRIPTS / name, tmp_path / "scripts" / name)
    git(tmp_path, "init", "-q")
    commit(
        tmp_path,
        "chore: init",
        {"CHANGELOG.md": CHANGELOG, "changelog.d/README.md": "# About\n", "code.py": "v1\n"},
    )
    git(tmp_path, "branch", "base")
    git(tmp_path, "switch", "-q", "-c", "topic")
    return tmp_path


def check(repo: Path, **environ: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(repo / "scripts" / "check-changelog.sh"), "base"],
        cwd=repo,
        env={**env(), **environ},
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_user_facing_commit_with_a_new_fragment_passes(repo: Path) -> None:
    commit(
        repo,
        "feat(daemon): a flag",
        {"code.py": "v2\n", "changelog.d/flag.added.md": "- A flag.\n"},
    )
    r = check(repo)
    assert r.returncode == 0, r.stderr
    assert "fragment added" in r.stdout


def test_a_fragment_in_a_later_commit_counts(repo: Path) -> None:
    commit(repo, "fix(relay): a bug", {"code.py": "v2\n"})
    commit(repo, "docs: note it", {"changelog.d/bug.fixed.md": "- A bug.\n"})
    assert check(repo).returncode == 0


def test_a_user_facing_commit_without_a_fragment_fails(repo: Path) -> None:
    commit(repo, "feat(daemon): a flag", {"code.py": "v2\n"})
    r = check(repo)
    assert r.returncode == 1
    assert "without a changelog fragment" in r.stderr
    assert "skip-changelog" in r.stderr


def test_editing_the_changelog_is_no_longer_enough(repo: Path) -> None:
    commit(
        repo,
        "feat(daemon): a flag",
        {
            "code.py": "v2\n",
            "CHANGELOG.md": CHANGELOG.replace("- Existing added.", "- Existing added.\n- Mine."),
        },
    )
    assert check(repo).returncode == 1


def test_a_changed_fragment_is_not_a_new_one(repo: Path) -> None:
    git(repo, "switch", "-q", "base")
    commit(repo, "chore: old fragment", {"changelog.d/old.added.md": "- Old.\n"})
    git(repo, "switch", "-q", "topic")
    git(repo, "rebase", "-q", "base")
    commit(
        repo,
        "feat(daemon): tweak",
        {"code.py": "v2\n", "changelog.d/old.added.md": "- Old, edited.\n"},
    )
    assert check(repo).returncode == 1


@pytest.mark.parametrize("kind", ["docs", "ci", "chore", "test", "build", "style"])
def test_exempt_commit_types_need_no_fragment(repo: Path, kind: str) -> None:
    commit(repo, f"{kind}(x): y", {"code.py": "v2\n"})
    r = check(repo)
    assert r.returncode == 0, r.stderr
    assert "not required" in r.stdout


def test_the_skip_label_skips_the_requirement(repo: Path) -> None:
    commit(repo, "feat(daemon): a flag", {"code.py": "v2\n"})
    r = check(repo, SKIP_CHANGELOG="true")
    assert r.returncode == 0
    assert "skipped" in r.stdout


def test_a_branch_with_no_commits_passes(repo: Path) -> None:
    assert check(repo).returncode == 0


@pytest.mark.parametrize("skip", ["false", "true"])
def test_a_malformed_fragment_fails_even_when_the_requirement_is_skipped(
    repo: Path, skip: str
) -> None:
    commit(
        repo,
        "feat(daemon): a flag",
        {"code.py": "v2\n", "changelog.d/flag.added.md": "no bullet\n"},
    )
    r = check(repo, SKIP_CHANGELOG=skip)
    assert r.returncode == 1
    assert "flag.added.md" in r.stderr


def test_a_misnamed_fragment_does_not_count_and_fails(repo: Path) -> None:
    commit(repo, "feat(daemon): a flag", {"code.py": "v2\n", "changelog.d/flag.md": "- A flag.\n"})
    r = check(repo)
    assert r.returncode == 1
    assert "flag.md" in r.stderr


def test_an_unknown_base_is_skipped(repo: Path) -> None:
    r = subprocess.run(
        ["bash", str(repo / "scripts" / "check-changelog.sh"), "nope"],
        cwd=repo,
        env=env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0
    assert "not found" in r.stdout


def test_the_cut_script_and_the_release_notes_read_the_same_changelog(repo: Path) -> None:
    (repo / "changelog.d" / "flag.added.md").write_text("- A flag.\n", encoding="utf-8")
    (repo / "changelog.d" / "bug.fixed.md").write_text("- A bug.\n", encoding="utf-8")
    cut_run = subprocess.run(
        ["bash", str(repo / "scripts" / "changelog-cut.sh"), "0.2.0", "2026-11-01"],
        cwd=repo,
        env=env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert cut_run.returncode == 0, cut_run.stderr
    assert sorted(p.name for p in (repo / "changelog.d").iterdir()) == ["README.md"]
    notes = subprocess.run(
        ["bash", str(repo / "scripts" / "release-notes.sh"), "0.2.0"],
        cwd=repo,
        env=env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert notes.returncode == 0, notes.stderr
    assert "### Added\n\n- Existing added.\n- A flag.\n" in notes.stdout
    assert "### Fixed\n\n- Existing fix.\n- A bug.\n" in notes.stdout
    assert "uv tool install agentconnect-cli==0.2.0" in notes.stdout
    assert "None: this is a dry run" in notes.stdout


def test_the_cut_script_requires_a_version(repo: Path) -> None:
    r = subprocess.run(
        ["bash", str(repo / "scripts" / "changelog-cut.sh")],
        cwd=repo,
        env=env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode != 0
    assert "usage" in r.stderr
