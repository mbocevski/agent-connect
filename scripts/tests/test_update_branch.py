"""Tests for scripts/update-branch.sh against local git repos.

A bare "origin", a clone and a fake `gh` on PATH stand in for GitHub. Signing
uses a throwaway ed25519 key in a temporary GNUPGHOME; the signing tests skip
when gpg isn't installed. The checks that don't sign (wrong branch, dirty
tree, closed PR) run everywhere.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "update-branch.sh"
HAVE_TOOLS = all(shutil.which(t) for t in ("git", "jq", "bash"))
pytestmark = pytest.mark.skipif(not HAVE_TOOLS, reason="needs git, jq and bash")

FAKE_GH = """#!/usr/bin/env bash
# Only `gh pr view <n> --json ...` is needed.
printf '%s\\n' "$FAKE_PR_JSON"
"""


@dataclass
class Env:
    origin: Path
    work: Path
    env: dict[str, str]
    signing: bool

    def git(self, *args: str, cwd: Path | None = None) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd or self.work,
            env=self.env,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def commit(self, name: str, text: str = "x\n", cwd: Path | None = None) -> None:
        path = (cwd or self.work) / name
        path.write_text(text, encoding="utf-8")
        self.git("add", name, cwd=cwd)
        self.git("commit", "-q", "-m", f"add {name}", cwd=cwd)

    def run(
        self, pr: str = "7", state: str = "OPEN", head: str = "feat"
    ) -> subprocess.CompletedProcess[str]:
        env = dict(self.env)
        env["FAKE_PR_JSON"] = (
            f'{{"state":"{state}","headRefName":"{head}","baseRefName":"main","isCrossRepository":false}}'
        )
        return subprocess.run(
            ["bash", str(SCRIPT), pr],
            cwd=self.work,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )


def _base_env() -> dict[str, str]:
    """The process environment without GIT_* (git exports GIT_DIR and friends to hooks)."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


@pytest.fixture(autouse=True)
def _hook_like_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run every test as if inside a git hook: bogus GIT_* must not leak into the temp repos."""
    monkeypatch.setenv("GIT_DIR", "/nonexistent/.git")
    monkeypatch.setenv("GIT_INDEX_FILE", "/nonexistent/index")
    monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent")


def _gpg_available() -> bool:
    return shutil.which("gpg") is not None


@pytest.fixture
def gnupghome() -> Iterator[Path | None]:
    if not _gpg_available():
        yield None
        return
    # Short path: gpg-agent sockets live in GNUPGHOME and have a length limit.
    home = Path(tempfile.mkdtemp(prefix="acgpg"))
    home.chmod(0o700)
    env = {**_base_env(), "GNUPGHOME": str(home)}
    gen = subprocess.run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Test <t@example.com>",
            "ed25519",
            "sign",
            "never",
        ],
        env=env,
        capture_output=True,
        check=False,
    )
    if gen.returncode != 0:
        shutil.rmtree(home, ignore_errors=True)
        yield None
        return
    yield home
    subprocess.run(["gpgconf", "--kill", "all"], env=env, check=False, capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


@pytest.fixture
def repo(tmp_path: Path, gnupghome: Path | None) -> Env:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH, encoding="utf-8")
    gh.chmod(0o755)

    env = {
        **_base_env(),
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"),
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    if gnupghome is not None:
        env["GNUPGHOME"] = str(gnupghome)
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    e = Env(origin, work, env, signing=gnupghome is not None)
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], env=env, check=True)
    subprocess.run(
        ["git", "clone", "-q", str(origin), str(work)], env=env, check=True, capture_output=True
    )
    e.git("switch", "-q", "-c", "main")
    if e.signing:
        e.git("config", "user.signingkey", "Test <t@example.com>")
        e.git("config", "gpg.program", shutil.which("gpg") or "gpg")
    e.commit("base.txt")
    e.git("push", "-q", "origin", "main")
    e.git("switch", "-q", "-c", "feat")
    e.commit("feat1.txt")
    e.commit("feat2.txt")
    e.git("push", "-q", "-u", "origin", "feat")
    return e


def _advance_main(e: Env, name: str, text: str = "m\n") -> None:
    e.git("switch", "-q", "main")
    e.commit(name, text)
    e.git("push", "-q", "origin", "main")
    e.git("switch", "-q", "feat")


def _statuses(e: Env) -> list[str]:
    return e.git("log", "--format=%G?", "origin/main..HEAD").split()


needs_gpg = pytest.mark.skipif(not _gpg_available(), reason="gpg not installed")


def test_refuses_when_on_another_branch(repo: Env) -> None:
    repo.git("switch", "-q", "main")
    result = repo.run()
    assert result.returncode != 0
    assert "git switch feat" in result.stderr


def test_refuses_dirty_tree(repo: Env) -> None:
    (repo.work / "feat1.txt").write_text("changed\n", encoding="utf-8")
    result = repo.run()
    assert result.returncode != 0
    assert "not clean" in result.stderr


def test_refuses_closed_pr(repo: Env) -> None:
    result = repo.run(state="MERGED")
    assert result.returncode != 0
    assert "MERGED" in result.stderr


def test_refuses_when_remote_has_commits_we_lack(repo: Env, tmp_path: Path) -> None:
    other = tmp_path / "other"
    subprocess.run(
        ["git", "clone", "-q", "-b", "feat", str(repo.origin), str(other)],
        env=repo.env,
        check=True,
        capture_output=True,
    )
    repo.commit("theirs.txt", cwd=other)
    repo.git("push", "-q", "origin", "feat", cwd=other)
    result = repo.run()
    assert result.returncode != 0
    assert "pull them first" in result.stderr


@needs_gpg
def test_rebases_resigns_and_pushes(repo: Env) -> None:
    _advance_main(repo, "main1.txt")
    before = repo.git("rev-parse", "origin/feat")
    result = repo.run()
    assert result.returncode == 0, result.stderr
    after = repo.git("rev-parse", "origin/feat")
    assert after != before
    assert after == repo.git("rev-parse", "HEAD")
    assert f"new head {after}" in result.stdout
    assert repo.git("merge-base", "origin/main", "HEAD") == repo.git("rev-parse", "origin/main")
    statuses = _statuses(repo)
    assert len(statuses) == 2
    assert set(statuses) <= {"G", "U"}


@needs_gpg
def test_resigns_unsigned_commits_when_main_has_not_moved(repo: Env) -> None:
    # Already based on main but unsigned: the script must not push them as-is.
    assert set(_statuses(repo)) == {"N"}
    result = repo.run()
    assert result.returncode == 0, result.stderr
    assert set(_statuses(repo)) <= {"G", "U"}
    assert repo.git("rev-parse", "origin/feat") == repo.git("rev-parse", "HEAD")


@needs_gpg
def test_conflict_stops_with_instructions_then_resumes(repo: Env) -> None:
    repo.git("switch", "-q", "main")
    repo.commit("clash.txt", "main\n")
    repo.git("push", "-q", "origin", "main")
    repo.git("switch", "-q", "feat")
    repo.commit("clash.txt", "feat\n")
    repo.git("push", "-q", "origin", "feat")
    before = repo.git("rev-parse", "origin/feat")

    result = repo.run()
    assert result.returncode != 0
    assert "git rebase --continue" in result.stderr
    assert repo.git("rev-parse", "origin/feat") == before  # nothing pushed
    assert (repo.work / ".git" / "rebase-merge").exists()

    again = repo.run()  # a rebase in progress is refused, not resumed blindly
    assert again.returncode != 0
    assert "already in progress" in again.stderr

    (repo.work / "clash.txt").write_text("resolved\n", encoding="utf-8")
    repo.git("add", "clash.txt")
    subprocess.run(
        ["git", "rebase", "--continue"],
        cwd=repo.work,
        env={**repo.env, "GIT_EDITOR": "true"},
        check=True,
        capture_output=True,
    )
    done = repo.run()
    assert done.returncode == 0, done.stderr
    assert repo.git("rev-parse", "origin/feat") == repo.git("rev-parse", "HEAD")
    assert set(_statuses(repo)) <= {"G", "U"}
