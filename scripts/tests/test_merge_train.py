"""Tests for scripts/merge-train.sh, against a local git repo.

A fake `gh`, `just` and `sleep` on PATH stand in for GitHub, the gated recipes
and the wait. They share a JSON state file and log every call, so a test can
say what the train did to each PR, and that it did nothing to the later ones.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "merge-train.sh"
JUSTFILE = Path(__file__).resolve().parents[2] / "justfile"
CONTRIBUTING = Path(__file__).resolve().parents[2] / "CONTRIBUTING.md"
pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("git", "jq", "bash", "python3")),
    reason="needs git, jq, bash and python3",
)

FAKE = """#!/usr/bin/env python3
import json, os, subprocess, sys

tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
state_path = os.environ["FAKE_STATE"]
with open(state_path, encoding="utf-8") as f:
    state = json.load(f)


def log(line):
    with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as f:
        f.write(line + "\\n")


def save():
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)


def git(*a):
    return subprocess.run(["git", *a], check=True, capture_output=True, text=True).stdout.strip()


def take(pr, key):
    seq = pr[key]
    value = seq.pop(0) if len(seq) > 1 else seq[0]
    save()
    return value


if tool == "sleep":
    log("sleep")
elif tool == "just":
    recipe, n = args
    pr = state[n]
    log(f"just {recipe} {n} {os.path.realpath(os.getcwd())}")
    if recipe == "update-branch":
        mode = pr.get("update", "ok")
        if mode == "conflict":
            print("update-branch: rebase stopped")
            subprocess.run(["git", "rebase", "main"], check=False, capture_output=True)
            sys.exit(1)
        if mode == "refuse":
            print("update-branch: working tree is not clean")
            sys.exit(1)
        git("commit", "-q", "--allow-empty", "-m", "rebased")
        pr["previous_head"] = pr["head"]
        pr["head"] = git("rev-parse", "HEAD")
        pr["behind"] = [0]
        save()
    elif recipe == "merge":
        if pr.get("merge") == "refuse":
            print(f"merge refused: PR #{n} has the do-not-merge label")
            sys.exit(1)
        pr["state"] = "MERGED"
        # As on GitHub: every other open PR is now behind main.
        for other_n, other in state.items():
            if other_n != n and other["state"] == "OPEN":
                other["behind"] = [1]
        save()
    else:
        sys.exit(99)
elif args[:2] == ["pr", "view"]:
    n = args[2]
    pr = state[n]
    log(f"gh pr view {n}")
    head = pr["head"]
    if pr.get("lag", 0) > 0 and "previous_head" in pr:
        pr["lag"] -= 1
        save()
        head = pr["previous_head"]
    elif pr.get("pushed_during_wait") is not None:
        pr["pushed_views"] = pr.get("pushed_views", 0) + 1
        save()
        if pr["pushed_views"] > pr["pushed_during_wait"]:
            head = "f" * 40
    print(json.dumps({
        "state": pr["state"], "isDraft": pr.get("draft", False), "baseRefName": "main",
        "headRefName": pr["branch"], "headRefOid": head,
        "mergeStateStatus": pr.get("merge_state", "CLEAN"),
    }))
elif args[:2] == ["pr", "checks"]:
    n = args[2]
    log(f"gh pr checks {n}")
    print(json.dumps(take(state[n], "checks")))
elif args[0] == "api" and "/compare/main..." in args[1]:
    sha = args[1].rsplit("...", 1)[1]
    for pr in state.values():
        if sha in (pr["head"], pr.get("previous_head")):
            print(take(pr, "behind"))
            sys.exit(0)
    print("no such commit", file=sys.stderr)
    sys.exit(1)
else:
    print(f"unexpected call: {tool} {args}", file=sys.stderr)
    sys.exit(99)
"""

GREEN = [{"name": "ci-ok", "bucket": "pass"}, {"name": "lint", "bucket": "pass"}]
PENDING = [{"name": "ci-ok", "bucket": "pending"}, {"name": "lint", "bucket": "pass"}]
FAILED = [{"name": "ci-ok", "bucket": "pending"}, {"name": "lint", "bucket": "fail"}]


@dataclass
class Train:
    repo: Path
    env: dict[str, str]
    state_path: Path
    log_path: Path

    def git(self, *args: str, cwd: Path | None = None, check: bool = True) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd or self.repo,
            env=self.env,
            check=check,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def branch(self, name: str, file: str | None = None, text: str = "x\n") -> str:
        """A pushed branch with one commit, not checked out anywhere."""
        self.git("switch", "-q", "-c", name, "main")
        path = self.repo / (file or f"{name}.txt")
        path.write_text(text, encoding="utf-8")
        self.git("add", path.name)
        self.git("commit", "-q", "-m", f"add {path.name}")
        self.git("push", "-q", "origin", name)
        head = self.git("rev-parse", "HEAD")
        self.git("switch", "-q", "main")
        return head

    def prs(self, **prs: dict[str, Any]) -> None:
        """Set the state of PRs named p<number>; each gets its own branch."""
        state: dict[str, dict[str, Any]] = {}
        for key, overrides in prs.items():
            n = key.removeprefix("p")
            branch = overrides.pop("branch", f"feat-{n}")
            head = overrides.pop("head", None) or self.branch(branch)
            state[n] = {
                "branch": branch,
                "head": head,
                "state": "OPEN",
                "behind": [0],
                "checks": [GREEN],
                **overrides,
            }
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def state(self) -> dict[str, dict[str, Any]]:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def calls(self) -> list[str]:
        if not self.log_path.exists():
            return []
        return self.log_path.read_text(encoding="utf-8").splitlines()

    def recipes(self) -> list[str]:
        """The gated recipes called, in order, without their directory."""
        return [" ".join(c.split()[1:3]) for c in self.calls() if c.startswith("just ")]

    def run(self, *prs: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *prs],
            cwd=self.repo,
            env={**self.env, "AC_TRAIN_TIMEOUT_SECS": str(timeout), "AC_TRAIN_POLL_SECS": "1"},
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.fixture
def train(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Train:
    # As inside a git hook: a stray GIT_* must not point at the wrong repo.
    monkeypatch.setenv("GIT_DIR", "/nonexistent/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("gh", "just", "sleep"):
        path = bin_dir / tool
        path.write_text(FAKE, encoding="utf-8")
        path.chmod(0o755)
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(
        "[user]\n\tname = T\n\temail = t@example.com\n"
        "[commit]\n\tgpgSign = false\n[init]\n\tdefaultBranch = main\n",
        encoding="utf-8",
    )
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GIT_CONFIG_GLOBAL": str(gitconfig),
        "GIT_CONFIG_NOSYSTEM": "1",
        "FAKE_STATE": str(tmp_path / "state.json"),
        "FAKE_LOG": str(tmp_path / "calls.log"),
    }
    origin = tmp_path / "origin.git"
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], env=env, check=True)
    subprocess.run(["git", "init", "-q", str(repo)], env=env, check=True)
    t = Train(repo, env, tmp_path / "state.json", tmp_path / "calls.log")
    (repo / ".github").mkdir()
    (repo / ".github" / "required-checks.txt").write_text("# comment\nci-ok\n", encoding="utf-8")
    (repo / ".gitignore").write_text("/target/\n", encoding="utf-8")
    (repo / "f.txt").write_text("base\n", encoding="utf-8")
    t.git("add", ".")
    t.git("commit", "-q", "-m", "base")
    t.git("remote", "add", "origin", str(origin))
    t.git("push", "-q", "origin", "main")
    return t


def test_a_green_run_merges_in_order_and_rebases_what_each_merge_left_behind(train: Train) -> None:
    train.prs(p1={}, p2={}, p3={})
    result = train.run("1", "2", "3")
    assert result.returncode == 0, result.stderr
    assert train.recipes() == [
        "merge 1",
        "update-branch 2",
        "merge 2",
        "update-branch 3",
        "merge 3",
    ]
    assert {pr["state"] for pr in train.state().values()} == {"MERGED"}


def test_each_step_prints_the_pr_the_head_and_the_result(train: Train) -> None:
    train.prs(p1={})
    head = train.state()["1"]["head"][:12]
    result = train.run("1")
    assert f"#1 {head} update-branch: not behind" in result.stdout
    assert f"#1 {head} checks: green" in result.stdout
    assert f"#1 {head} merge: merged" in result.stdout


def test_a_rebase_conflict_stops_the_train_and_leaves_the_pr_as_it_was(train: Train) -> None:
    conflicting = train.branch("feat-2", "f.txt", "conflict\n")
    (train.repo / "f.txt").write_text("main moved\n", encoding="utf-8")
    train.git("add", "f.txt")
    train.git("commit", "-q", "-m", "main moved")
    train.prs(
        p1={},
        p2={"branch": "feat-2", "head": conflicting, "update": "conflict"},
        p3={},
    )
    result = train.run("1", "2", "3")
    assert result.returncode == 1
    assert "stopped at #2" in result.stderr
    assert "conflict" in result.stderr
    assert "not started: #3" in result.stderr
    assert train.recipes() == ["merge 1", "update-branch 2"]
    assert train.state()["3"]["state"] == "OPEN"
    # Nothing is left of the attempt: no rebase, no checkout, the branch as it was.
    assert train.git("rev-parse", "feat-2") == conflicting
    assert str(train.repo / "target" / "merge-train") not in train.git("worktree", "list")


def test_a_conflict_github_already_reports_stops_before_any_local_rebase(train: Train) -> None:
    train.prs(p1={"merge_state": "DIRTY", "behind": [1]}, p2={})
    result = train.run("1", "2")
    assert result.returncode == 1
    assert "stopped at #1" in result.stderr
    assert "conflict" in result.stderr
    assert train.recipes() == []


def test_a_failed_check_stops_the_train_and_names_it(train: Train) -> None:
    train.prs(p1={"checks": [PENDING, FAILED]}, p2={})
    result = train.run("1", "2")
    assert result.returncode == 1
    assert "stopped at #1" in result.stderr
    assert "lint" in result.stderr
    assert "not started: #2" in result.stderr
    assert train.recipes() == []
    assert train.state()["1"]["state"] == "OPEN"


def test_a_cancelled_check_counts_as_failed(train: Train) -> None:
    train.prs(p1={"checks": [[{"name": "ci-ok", "bucket": "cancel"}]]})
    result = train.run("1")
    assert result.returncode == 1
    assert "ci-ok" in result.stderr
    assert train.recipes() == []


def test_a_timeout_stops_the_train(train: Train) -> None:
    train.prs(p1={"checks": [PENDING]}, p2={})
    result = train.run("1", "2", timeout=0)
    assert result.returncode == 1
    assert "stopped at #1" in result.stderr
    assert "timed out" in result.stderr
    assert "not started: #2" in result.stderr
    assert train.recipes() == []


def test_a_refused_merge_stops_the_train_with_the_reason(train: Train) -> None:
    train.prs(p1={"merge": "refuse"}, p2={})
    result = train.run("1", "2")
    assert result.returncode == 1
    assert "stopped at #1" in result.stderr
    assert "do-not-merge" in result.stderr
    assert train.recipes() == ["merge 1"]
    assert train.state()["1"]["state"] == "OPEN"


def test_a_refused_update_stops_the_train_with_the_reason(train: Train) -> None:
    train.prs(p1={"behind": [1], "update": "refuse"}, p2={})
    result = train.run("1", "2")
    assert result.returncode == 1
    assert "stopped at #1" in result.stderr
    assert "not clean" in result.stderr
    assert train.recipes() == ["update-branch 1"]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [({"state": "MERGED"}, "MERGED"), ({"draft": True}, "draft")],
)
def test_a_pr_that_cant_merge_stops_the_train_at_once(
    train: Train, overrides: dict[str, Any], reason: str
) -> None:
    train.prs(p1=overrides, p2={})
    result = train.run("1", "2")
    assert result.returncode == 1
    assert reason in result.stderr
    assert train.recipes() == []
    assert not [c for c in train.calls() if c.startswith("gh pr checks")]


def test_it_waits_for_checks_that_are_still_pending(train: Train) -> None:
    train.prs(p1={"checks": [PENDING, PENDING, GREEN]})
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    assert train.calls().count("sleep") == 2
    assert train.recipes() == ["merge 1"]


def test_green_checks_without_the_required_one_arent_enough(train: Train) -> None:
    """Just after a push only some checks exist, and those may all be green."""
    train.prs(p1={"checks": [[], [{"name": "lint", "bucket": "pass"}], GREEN]})
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    assert train.calls().count("sleep") == 2


def test_a_required_check_that_was_skipped_doesnt_pass(train: Train) -> None:
    train.prs(p1={"checks": [[{"name": "ci-ok", "bucket": "skipping"}]]})
    result = train.run("1", timeout=0)
    assert result.returncode == 1
    assert "timed out" in result.stderr
    assert train.recipes() == []


def test_after_a_rebase_it_waits_for_github_to_see_the_new_head(train: Train) -> None:
    """The old head's green checks say nothing about the rebased commits."""
    train.prs(p1={"behind": [1], "lag": 2, "checks": [GREEN]})
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    assert train.calls().count("sleep") == 2
    assert train.recipes() == ["update-branch 1", "merge 1"]


def test_if_main_moves_during_the_wait_it_rebases_again(train: Train) -> None:
    # Not behind at the start, behind after the wait and at the next round.
    train.prs(p1={"behind": [0, 1, 1]})
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    assert train.recipes() == ["update-branch 1", "merge 1"]


def test_if_main_keeps_moving_it_stops(train: Train) -> None:
    train.prs(p1={"behind": [1]})
    fake = Path(train.env["PATH"].split(os.pathsep)[0]) / "just"
    fake.write_text(
        fake.read_text(encoding="utf-8").replace('pr["behind"] = [0]', 'pr["behind"] = [1]'),
        encoding="utf-8",
    )
    result = train.run("1")
    assert result.returncode == 1
    assert "main kept moving" in result.stderr
    assert not [r for r in train.recipes() if r.startswith("merge")]


def test_a_push_by_someone_else_during_the_wait_stops_the_train(train: Train) -> None:
    train.prs(p1={"pushed_during_wait": 1, "checks": [PENDING, GREEN]}, p2={})
    result = train.run("1", "2")
    assert result.returncode == 1
    assert "stopped at #1" in result.stderr
    assert "head moved" in result.stderr
    assert train.recipes() == []


def test_the_rebase_runs_in_the_worktree_that_has_the_branch(train: Train, tmp_path: Path) -> None:
    head = train.branch("feat-1")
    worktree = tmp_path / "wt"
    train.git("worktree", "add", "-q", str(worktree), "feat-1")
    train.prs(p1={"branch": "feat-1", "head": head, "behind": [1]})
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    assert f"just update-branch 1 {worktree.resolve()}" in train.calls()
    assert worktree.is_dir()


def test_without_a_worktree_it_uses_a_temporary_one_on_disk_and_removes_it(train: Train) -> None:
    train.prs(p1={"behind": [1]})
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    (call,) = [c for c in train.calls() if c.startswith("just update-branch")]
    assert call.split()[-1] == str((train.repo / "target" / "merge-train" / "pr-1").resolve())
    assert "merge-train" not in train.git("worktree", "list")


def test_a_branch_with_no_local_copy_is_fetched_and_the_copy_removed(train: Train) -> None:
    train.prs(p1={"behind": [1]})
    train.git("branch", "-q", "-D", "feat-1")
    result = train.run("1")
    assert result.returncode == 0, result.stderr
    assert train.recipes() == ["update-branch 1", "merge 1"]
    assert train.git("branch", "--list", "feat-1") == ""


def test_a_rebase_already_under_way_is_left_alone(train: Train, tmp_path: Path) -> None:
    head = train.branch("feat-1", "f.txt", "theirs\n")
    (train.repo / "f.txt").write_text("main moved\n", encoding="utf-8")
    train.git("add", "f.txt")
    train.git("commit", "-q", "-m", "main moved")
    worktree = tmp_path / "wt"
    train.git("worktree", "add", "-q", str(worktree), "feat-1")
    train.git("rebase", "main", cwd=worktree, check=False)
    train.prs(p1={"branch": "feat-1", "head": head, "behind": [1]})
    result = train.run("1")
    assert result.returncode == 1
    # Git lists a worktree mid-rebase as detached, and refuses a second checkout.
    assert "stopped at #1" in result.stderr
    assert "already used by worktree" in result.stderr
    assert train.recipes() == []
    assert "rebase in progress" in train.git("status", cwd=worktree)


@pytest.mark.parametrize("args", [(), ("1", "x"), ("1", "--admin"), ("1", "-2")])
def test_bad_arguments_are_refused_before_anything_runs(
    train: Train, args: tuple[str, ...]
) -> None:
    train.prs(p1={})
    result = train.run(*args)
    assert result.returncode == 2
    assert train.calls() == []


def test_a_pr_named_twice_is_refused(train: Train) -> None:
    train.prs(p1={})
    result = train.run("1", "1")
    assert result.returncode == 2
    assert train.calls() == []


def test_the_script_never_calls_a_merge_or_a_bypass_itself() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "just merge" in code
    assert "just update-branch" in code
    for banned in ("gh pr merge", "--admin", "--no-verify", "update-branch --rebase"):
        assert banned not in code


def test_the_recipe_and_its_docs_exist() -> None:
    justfile = JUSTFILE.read_text(encoding="utf-8")
    assert "merge-train +prs:" in justfile
    assert "scripts/merge-train.sh {{ prs }}" in justfile
    assert "just merge-train" in CONTRIBUTING.read_text(encoding="utf-8")
