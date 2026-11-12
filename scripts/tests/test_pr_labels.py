"""Opening a pull request with its labels (`just pr skip-changelog`), and the
CI jobs that read those labels when they run.

`gh pr create --label` creates the pull request and adds the labels in a
second call, so a workflow that started on `labeled` ran twice for every such
pull request and cancelled the first run. The changelog and docs jobs read
the labels from the API instead, and labels are no longer triggers."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CI = REPO / ".github" / "workflows" / "ci.yml"
PR_SH = REPO / "scripts" / "pr.sh"
JUSTFILE = REPO / "justfile"

FAKE_GIT = """#!/bin/sh
echo "git $*" >>"$LOG"
case "$1 $2" in
"rev-parse --abbrev-ref") echo "${BRANCH:-feat/x}" ;;
esac
"""

FAKE_GH = """#!/bin/sh
echo "gh $*" >>"$LOG"
case "$1 $2" in
"label list") printf 'skip-changelog\\nskip-docs\\nskip-readme\\ndo-not-merge\\n' ;;
"pr list") if [ -n "${OPEN_URL:-}" ]; then echo "$OPEN_URL"; fi ;;
"pr create") echo "https://example.com/pull/9" ;;
"api "*)
    if [ -n "${GH_FAIL:-}" ]; then echo "HTTP 500" >&2; exit 1; fi
    printf "%s" "${LABELS:-}" ;;
esac
"""


def _bin(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in (("git", FAKE_GIT), ("gh", FAKE_GH)):
        tool = bin_dir / name
        tool.write_text(body, encoding="utf-8")
        tool.chmod(0o700)
    return bin_dir


def _env(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PATH"] = f"{_bin(tmp_path)}{os.pathsep}{env['PATH']}"
    env["LOG"] = str(tmp_path / "calls")
    return env | extra


def _pr(tmp_path: Path, *labels: str, **extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PR_SH), *labels],
        capture_output=True,
        text=True,
        env=_env(tmp_path, **extra),
        check=False,
    )


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_a_pull_request_without_labels_is_opened_as_before(tmp_path: Path) -> None:
    result = _pr(tmp_path)
    assert result.returncode == 0, result.stderr
    calls = _calls(tmp_path)
    assert "git push -u origin feat/x" in calls
    assert "gh pr create --fill-first --base main --head feat/x" in calls
    assert not any(c.startswith("gh label list") for c in calls)
    assert result.stdout.strip() == "https://example.com/pull/9"


def test_every_label_goes_on_the_create_call(tmp_path: Path) -> None:
    result = _pr(tmp_path, "skip-changelog", "skip-docs")
    assert result.returncode == 0, result.stderr
    assert (
        "gh pr create --fill-first --base main --head feat/x"
        " --label skip-changelog --label skip-docs"
    ) in _calls(tmp_path)


def test_an_unknown_label_fails_before_anything_is_pushed(tmp_path: Path) -> None:
    result = _pr(tmp_path, "skip-changelog", "skip-everything")
    assert result.returncode == 1
    assert "no label 'skip-everything'" in result.stderr
    calls = _calls(tmp_path)
    assert not any(c.startswith("git push") for c in calls)
    assert not any(c.startswith("gh pr create") for c in calls)


def test_a_label_that_only_contains_a_known_one_is_unknown(tmp_path: Path) -> None:
    assert _pr(tmp_path, "skip").returncode == 1
    assert _pr(tmp_path, "skip-changelog-now").returncode == 1


def test_labels_are_added_to_a_pull_request_that_is_already_open(tmp_path: Path) -> None:
    url = "https://example.com/pull/7"
    result = _pr(tmp_path, "skip-readme", OPEN_URL=url)
    assert result.returncode == 0, result.stderr
    calls = _calls(tmp_path)
    assert f"gh pr edit {url} --add-label skip-readme" in calls
    assert not any(c.startswith("gh pr create") for c in calls)
    assert result.stdout.strip() == url
    assert "re-run" in result.stderr


def test_an_open_pull_request_without_labels_is_only_shown(tmp_path: Path) -> None:
    result = _pr(tmp_path, OPEN_URL="https://example.com/pull/7")
    assert result.returncode == 0, result.stderr
    assert not any(c.startswith("gh pr edit") for c in _calls(tmp_path))


def test_main_is_refused_before_anything_runs(tmp_path: Path) -> None:
    result = _pr(tmp_path, "skip-changelog", BRANCH="main")
    assert result.returncode == 1
    assert "create a branch first" in result.stderr
    assert not any(c.startswith(("git push", "gh ")) for c in _calls(tmp_path))


@pytest.mark.skipif(shutil.which("just") is None, reason="needs just")
def test_just_pr_passes_its_labels_on() -> None:
    result = subprocess.run(
        ["just", "--justfile", str(JUSTFILE), "--dry-run", "pr", "skip-changelog", "skip-docs"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "scripts/pr.sh skip-changelog skip-docs" in result.stderr


# --- the CI jobs read the labels when they run ---


def _jobs() -> dict[str, str]:
    body = CI.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z][a-z-]*):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def _label_step(job: str) -> str:
    """The first multi-line `run:` of the job: the one that reads the labels."""
    match = re.search(r"^ {8}run: \|\n((?: {10}.*\n|\n)+)", _jobs()[job], flags=re.MULTILINE)
    assert match is not None
    return "\n".join(line[10:] for line in match.group(1).splitlines())


def _read_labels(
    tmp_path: Path, job: str, labels: str, **extra: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    github_env = tmp_path / "github_env"
    result = subprocess.run(
        ["bash", "-e", "-c", _label_step(job)],
        capture_output=True,
        text=True,
        env=_env(
            tmp_path,
            LABELS=labels,
            GITHUB_ENV=str(github_env),
            REPO="o/r",
            PR="7",
            **extra,
        ),
        check=False,
    )
    text = github_env.read_text(encoding="utf-8") if github_env.exists() else ""
    return result, dict(line.split("=", 1) for line in text.splitlines())


def test_labels_are_not_triggers_and_the_payload_is_not_read() -> None:
    text = CI.read_text(encoding="utf-8")
    types = re.search(r"pull_request:\n(?:\s+#.*\n)*\s+types: \[([^\]]*)\]", text)
    assert types is not None
    assert {t.strip() for t in types.group(1).split(",")} == {"opened", "synchronize", "reopened"}
    assert "pull_request.labels" not in text


@pytest.mark.parametrize("job", ["changelog", "docs"])
def test_the_label_jobs_may_read_pull_requests(job: str) -> None:
    body = _jobs()[job]
    assert "pull-requests: read" in body
    assert "contents: read" in body, "a job's permissions replace the workflow's"
    assert 'gh api "repos/$REPO/issues/$PR/labels"' in body


def test_the_changelog_job_sets_skip_changelog_from_the_current_labels(tmp_path: Path) -> None:
    result, env = _read_labels(tmp_path, "changelog", "dependencies\nskip-changelog\n")
    assert result.returncode == 0, result.stderr
    assert env == {"SKIP_CHANGELOG": "true"}
    (tmp_path / "github_env").unlink()
    _, env = _read_labels(tmp_path, "changelog", "do-not-merge\n")
    assert env == {"SKIP_CHANGELOG": "false"}
    (tmp_path / "github_env").unlink()
    _, env = _read_labels(tmp_path, "changelog", "")
    assert env == {"SKIP_CHANGELOG": "false"}


def test_the_docs_job_reads_its_two_labels_apart(tmp_path: Path) -> None:
    _, env = _read_labels(tmp_path, "docs", "skip-readme\n")
    assert env == {"SKIP_DOCS": "false", "SKIP_README": "true"}
    (tmp_path / "github_env").unlink()
    _, env = _read_labels(tmp_path, "docs", "skip-docs\nskip-readme\n")
    assert env == {"SKIP_DOCS": "true", "SKIP_README": "true"}


def test_a_label_that_only_contains_a_skip_label_does_not_skip(tmp_path: Path) -> None:
    _, env = _read_labels(tmp_path, "changelog", "skip-changelog-later\nno-skip-changelog\n")
    assert env == {"SKIP_CHANGELOG": "false"}


@pytest.mark.parametrize("job", ["changelog", "docs"])
def test_an_api_failure_fails_the_job_instead_of_skipping_a_check(tmp_path: Path, job: str) -> None:
    result, env = _read_labels(tmp_path, job, "skip-changelog\n", GH_FAIL="1")
    assert result.returncode != 0
    assert env == {}
