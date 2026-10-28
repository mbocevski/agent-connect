"""Tests for the early refusals in scripts/merge.sh, with a fake `gh` on PATH.

Only the gates before the title/hygiene/checks stages are covered: the BEHIND
hint and the signature-verification gate.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "merge.sh"
pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("git", "jq", "bash")), reason="needs git, jq and bash"
)

FAKE_GH = """#!/usr/bin/env bash
case "$1 $2" in
    "pr view") printf '%s\\n' "$FAKE_PR_JSON" ;;
    "repo view") echo "octo/repo" ;;
    "api graphql") printf '%s\\n' "$FAKE_SIG_JSON" ;;
    *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
"""


def _pr(
    state: str = "CLEAN",
    title: str = "nonsense title",
    body: str = "",
    author: str = "octocat",
) -> str:
    return json.dumps(
        {
            "state": "OPEN",
            "isDraft": False,
            "baseRefName": "main",
            "mergeStateStatus": state,
            "labels": [],
            "title": title,
            "body": body,
            "author": {"login": author},
        }
    )


def _sigs(*commits: tuple[str, dict[str, object] | None]) -> str:
    nodes = [{"commit": {"abbreviatedOid": oid, "signature": sig}} for oid, sig in commits]
    return json.dumps(
        {
            "data": {
                "repository": {
                    "pullRequest": {"commits": {"totalCount": len(nodes), "nodes": nodes}}
                }
            }
        }
    )


def _run(tmp_path: Path, pr_json: str, sig_json: str) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH, encoding="utf-8")
    gh.chmod(0o755)
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_PR_JSON": pr_json,
        "FAKE_SIG_JSON": sig_json,
    }
    return subprocess.run(
        ["bash", str(SCRIPT), "7"], cwd=REPO, env=env, capture_output=True, text=True, check=False
    )


GOOD: dict[str, object] = {"isValid": True, "state": "VALID"}


def test_behind_points_to_signed_update(tmp_path: Path) -> None:
    result = _run(tmp_path, _pr("BEHIND"), _sigs(("aaa1111", GOOD)))
    assert result.returncode != 0
    assert "just update-branch 7" in result.stderr
    assert "gh pr update-branch" not in result.stderr


def test_unsigned_commit_is_refused(tmp_path: Path) -> None:
    result = _run(tmp_path, _pr(), _sigs(("aaa1111", GOOD), ("bbb2222", None)))
    assert result.returncode != 0
    assert "bbb2222: UNSIGNED" in result.stderr
    assert "aaa1111" not in result.stderr
    assert "just update-branch 7" in result.stderr


def test_invalid_signature_is_refused(tmp_path: Path) -> None:
    result = _run(tmp_path, _pr(), _sigs(("ccc3333", {"isValid": False, "state": "UNKNOWN_KEY"})))
    assert result.returncode != 0
    assert "ccc3333: UNKNOWN_KEY" in result.stderr


def test_verified_commits_pass_the_signature_gate(tmp_path: Path) -> None:
    # The bad title is the next gate; reaching it shows the signature gate passed.
    result = _run(tmp_path, _pr(), _sigs(("aaa1111", GOOD)))
    assert result.returncode != 0
    assert "not a Conventional Commit" in result.stderr


FLAGGED = "Merge pull request #1 from someone/cl" + "aude/branch"


def test_a_flagged_body_on_a_human_pr_is_refused(tmp_path: Path) -> None:
    pr = _pr(title="build(deps): bump x", body=FLAGGED)
    result = _run(tmp_path, pr, _sigs(("aaa1111", GOOD)))
    assert result.returncode != 0
    assert "AI-tool attribution" in result.stderr


@pytest.mark.parametrize("login", ["app/dependabot", "dependabot[bot]"])
def test_a_flagged_body_on_a_dependabot_pr_is_not_checked(tmp_path: Path, login: str) -> None:
    pr = _pr(title="build(deps): bump x", body=FLAGGED, author=login)
    result = _run(tmp_path, pr, _sigs(("aaa1111", GOOD)))
    assert "AI-tool attribution" not in result.stderr


def test_a_flagged_title_on_a_dependabot_pr_is_refused(tmp_path: Path) -> None:
    pr = _pr(title="build(deps): bump x for " + "cl" + "aude", author="app/dependabot")
    result = _run(tmp_path, pr, _sigs(("aaa1111", GOOD)))
    assert result.returncode != 0
    assert "AI-tool attribution" in result.stderr
