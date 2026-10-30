import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "changes", Path(__file__).resolve().parents[1] / "changes.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["changes"] = module
    spec.loader.exec_module(module)
    return module


ch = _load()
REPO = Path(__file__).resolve().parents[2]
JOBS = tuple(ch.JOB_GROUPS)


def ran(*paths: str, everything: bool = False) -> set[str]:
    out = ch.classify(paths, everything=everything)
    return {job for job in JOBS if out[f"run_{job}"] == "true"}


def test_docs_only_skips_every_expensive_job() -> None:
    assert (
        ran("docs/groups.md", "docs/MAP.toml", "styles/AgentConnect/Terms.yml", "SPEC.md") == set()
    )
    assert ran("CHANGELOG.md", "changelog.d/x.fixed.md", "TESTING.md", "LICENSE") == set()


def test_python_only() -> None:
    assert ran("daemon/src/agentconnect/cli.py", "sdk/python/tests/test_x.py") == {
        "python",
        "licences",
        "contract",
        "platforms",
        "integration",
    }
    assert ran("uv.lock") == ran("harness/src/x.py")


def test_rust_only_runs_the_python_job_too_but_not_the_licence_check() -> None:
    got = ran("relay/src/lib.rs")
    assert got == {"rust", "python", "contract", "platforms", "image", "integration"}
    assert "licences" not in got
    assert ran("Cargo.lock") == got
    assert ran("core-py/src/lib.rs") == got
    assert ran("core/fuzz/Cargo.toml") == got


def test_testdata_runs_both_languages() -> None:
    got = ran("testdata/MANIFEST.json")
    assert {"rust", "python", "contract", "licences"} <= got
    assert "image" in got  # via rust: the images build the core


def test_images_only() -> None:
    assert ran(".dockerignore") == {"image", "integration"}
    assert ran("web/static/invite.css") >= {"image", "rust"}


def test_a_ci_change_runs_everything() -> None:
    for path in (
        ".github/workflows/ci.yml",
        "scripts/changes.py",
        "justfile",
        "rust-toolchain.toml",
        "coverage-baseline.json",
        ".pre-commit-config.yaml",
    ):
        assert ran(path) == set(JOBS), path


def test_a_pull_request_that_edits_the_classifier_runs_everything() -> None:
    # Whatever else it touches, and whether it is the script or its tests.
    assert ran("docs/api.md", "scripts/changes.py") == set(JOBS)
    assert ran("docs/groups.md", "scripts/tests/test_changes.py") == set(JOBS)


def test_generated_reference_docs_run_the_test_that_keeps_them_in_sync() -> None:
    # A hand edit of a generated section must reach test_gen_reference (python).
    for path in sorted(ch.GENERATED_DOCS):
        assert {"python", "licences"} <= ran(path), path
        assert "rust" not in ran(path), path
    assert ran("docs/groups.md") == set()


def test_the_generated_docs_are_the_ones_gen_reference_writes() -> None:
    source = (REPO / "scripts/gen_reference.py").read_text(encoding="utf-8")
    written = set(re.findall(r'Section\("[a-z-]+", "(docs/[a-z-]+\.md)"', source))
    assert written == set(ch.GENERATED_DOCS)


def test_an_unknown_path_runs_everything() -> None:
    assert ran("brand-new-dir/file.txt") == set(JOBS)
    assert ran("docs/api.md", "mystery") == set(JOBS)
    assert ch.classify(["mystery"])["unknown"] == "true"
    assert ch.classify(["docs/api.md"])["unknown"] == "false"


def test_a_root_file_the_rules_do_not_name_is_unknown() -> None:
    assert ch.groups_of("Makefile") is None
    assert ch.groups_of(".github") is None  # a bare name, not a directory entry


def test_markdown_inside_a_component_belongs_to_it() -> None:
    # directory/README.md is documented as the theming interface and read by
    # tests; the harness reads the root README.
    assert ch.groups_of("directory/README.md") == {"rust"}
    assert ch.groups_of("harness/README.md") == {"python"}
    assert ch.groups_of("README.md") == {"docs", "python"}
    assert "python" in ran("README.md")
    assert "rust" not in ran("README.md")


def test_a_mixed_change_unions_the_groups() -> None:
    assert ran("docs/api.md", "daemon/src/x.py") == ran("daemon/src/x.py")
    assert ran("daemon/src/x.py", "relay/src/lib.rs") == ran("daemon/src/x.py") | ran(
        "relay/src/lib.rs"
    )


def test_both_paths_of_a_rename_count() -> None:
    # `git diff --no-renames` lists the old and the new path.
    assert "rust" in ran("docs/relay.md", "relay/relay.md")


def test_nothing_changed_runs_nothing() -> None:
    assert ran() == set()
    assert ran("", "  ") == set()


def test_all_runs_everything_even_with_docs_only_paths() -> None:
    assert ran("docs/api.md", everything=True) == set(JOBS)
    assert ran(everything=True) == set(JOBS)


def test_group_outputs() -> None:
    out = ch.classify(["relay/src/lib.rs", "docs/x.md"])
    assert (out["rust"], out["python"], out["docs"], out["ci"]) == (
        "true",
        "false",
        "true",
        "false",
    )
    out = ch.classify(["justfile"])
    assert {out[g] for g in ch.GROUPS} == {"true"}


def test_classify_main_prints_github_outputs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("docs/api.md\n"))
    assert ch.main(["classify"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "run_rust=false" in lines
    assert "docs=true" in lines
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert ch.main(["classify", "--all"]) == 0
    assert "run_rust=true" in capsys.readouterr().out.splitlines()
    assert ch.main(["nonsense"]) == 2


# --- the ci-ok gate ---


def _needs(flags: dict[str, str] | None = None, **results: str) -> dict[str, dict[str, Any]]:
    base = {
        "changes": "success",
        "lint": "success",
        "rust": "success",
        "python": "success",
        "licences": "success",
        "contract": "success",
        "changelog": "success",
        "docs": "success",
        "hygiene": "success",
    }
    base.update(results)
    outputs = {f"run_{job}": "true" for job in JOBS} | {
        f"run_{job}": value for job, value in (flags or {}).items()
    }
    needs: dict[str, dict[str, Any]] = {
        job: {"result": r, "outputs": {}} for job, r in base.items()
    }
    needs["changes"]["outputs"] = outputs
    return needs


def test_gate_passes_when_everything_ran_and_passed() -> None:
    assert ch.gate(_needs(), "pull_request") == []


def test_gate_accepts_a_skip_the_classifier_asked_for() -> None:
    needs = _needs(
        {"rust": "false", "python": "false", "licences": "false", "contract": "false"},
        rust="skipped",
        python="skipped",
        licences="skipped",
        contract="skipped",
    )
    assert ch.gate(needs, "pull_request") == []


def test_gate_refuses_a_skip_the_classifier_did_not_ask_for() -> None:
    # `rust` was meant to run (flag true) but was skipped: a failed dependency.
    problems = ch.gate(_needs(rust="skipped"), "pull_request")
    assert len(problems) == 1
    assert problems[0].startswith("rust was skipped")


def test_gate_refuses_when_changes_failed() -> None:
    # Every dependent is then skipped, with no flags to excuse it.
    needs = _needs(changes="failure", rust="skipped", python="skipped")
    needs["changes"]["outputs"] = {}
    problems = ch.gate(needs, "pull_request")
    assert len(problems) == 1
    assert problems[0].startswith("changes did not succeed")
    assert ch.gate({}, "pull_request")


@pytest.mark.parametrize("result", ["failure", "cancelled"])
def test_gate_refuses_a_failed_or_cancelled_job(result: str) -> None:
    assert ch.gate(_needs(lint=result), "pull_request") == [f"lint: {result}"]


def test_gate_refuses_a_failure_even_when_its_flag_is_false() -> None:
    needs = _needs({"rust": "false"}, rust="failure")
    assert ch.gate(needs, "pull_request") == ["rust: failure"]


def test_pull_request_only_jobs_may_be_skipped_on_a_push_only() -> None:
    needs = _needs(changelog="skipped", docs="skipped", hygiene="skipped")
    assert ch.gate(needs, "push") == []
    assert len(ch.gate(needs, "pull_request")) == 3


def test_always_running_jobs_may_never_be_skipped() -> None:
    assert ch.gate(_needs(lint="skipped"), "push") == [
        "lint was skipped but nothing excused it (a failed dependency?)"
    ]


def test_gate_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("NEEDS", json.dumps(_needs()))
    monkeypatch.setenv("EVENT", "pull_request")
    assert ch.main(["gate"]) == 0
    monkeypatch.setenv("NEEDS", json.dumps(_needs(lint="failure")))
    assert ch.main(["gate"]) == 1
    assert "ci-ok: lint: failure" in capsys.readouterr().err


# --- the workflow and the classifier agree ---


def _jobs(text: str) -> dict[str, str]:
    """The text of each top-level job of a workflow file."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z][a-z-]*):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_every_filtered_job_in_ci_yml_uses_its_own_flag() -> None:
    jobs = _jobs((REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    for job in JOBS:
        assert job in jobs, f"{job} is classified but not in ci.yml"
        assert "needs: changes" in jobs[job], job
        assert f"if: needs.changes.outputs.run_{job} == 'true'" in jobs[job], job
    for job, body in jobs.items():
        flags = set(re.findall(r"needs\.changes\.outputs\.run_([a-z]+)", body))
        if job != "changes":
            assert flags <= {job}, f"{job} reads another job's flag: {flags}"
            assert (job in JOBS) == bool(flags), f"{job}: classified and filtered disagree"


def test_changes_exports_every_flag_and_ci_ok_waits_for_it() -> None:
    jobs = _jobs((REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    exported = set(re.findall(r"^\s+run_([a-z]+):", jobs["changes"], flags=re.M))
    assert exported == set(JOBS)
    needs = re.search(r"needs: \[([^\]]*)\]", jobs["ci-ok"])
    assert needs is not None
    gated = {name.strip() for name in needs.group(1).split(",")}
    assert "changes" in gated
    # Every filtered job that is a required one must be gated.
    assert {"rust", "python", "licences", "contract"} <= gated
    # The pull-request-only jobs the gate knows about exist.
    assert set(ch.PR_ONLY) <= set(jobs)


def test_the_real_gate_input_shape_is_what_the_workflow_feeds_it() -> None:
    text = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "NEEDS: ${{ toJSON(needs) }}" in text
    assert re.search(r'python3 "\$script" gate$', text, flags=re.M)


def test_both_jobs_run_the_base_branches_copy_of_the_script() -> None:
    jobs = _jobs((REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    for name in ("changes", "ci-ok"):
        assert 'git show "origin/$BASE:scripts/changes.py"' in jobs[name], name
        assert "fetch-depth: 0" in jobs[name], name
    # The pull request's own copy only ever runs with --all, or as the
    # fallback when the base has none (the pull request that adds it).
    assert "python3 scripts/changes.py classify --all" in jobs["changes"]
    assert re.search(r"python3 scripts/changes\.py classify(?! --all)", jobs["changes"]) is None


def _step(job: str, marker: str) -> str:
    """The `run:` script of the step of `job` that contains `marker`."""
    text = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(r"^ {8}run: \|\n((?: {10}.*\n|\n)+)", _jobs(text)[job], flags=re.M)
    assert match is not None
    assert marker in match.group(1)
    return "\n".join(line[10:] for line in match.group(1).splitlines())


def _sh(cwd: Path, script: str, **env: str) -> subprocess.CompletedProcess[str]:
    clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=cwd,
        env=clean | env,
        capture_output=True,
        text=True,
        check=False,
    )


def _git(cwd: Path, *args: str) -> None:
    clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd,
        env=clean,
        check=True,
        capture_output=True,
    )


FORGED = (
    "import sys\n"
    "sys.stdin.read()\n"
    "for job in ('rust', 'python', 'licences', 'contract', 'platforms', 'image', 'integration'):\n"
    "    print(f'run_{job}=false')\n"
)


def _pull_request(tmp_path: Path, *, base_has_script: bool, forged: bool) -> dict[str, str]:
    """Run the workflow's `changes` step on a pull request that edits the script."""
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "docs").mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "docs" / "groups.md").write_text("base\n", encoding="utf-8")
    if base_has_script:
        shutil.copy(REPO / "scripts" / "changes.py", repo / "scripts" / "changes.py")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(repo, "switch", "-q", "-c", "pr")
    script = repo / "scripts" / "changes.py"
    script.write_text(FORGED if forged else (REPO / "scripts/changes.py").read_text("utf-8"))
    (repo / "docs" / "groups.md").write_text("edited\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    out = tmp_path / "output"
    result = _sh(
        repo,
        _step("changes", "classify"),
        EVENT="pull_request",
        BASE="main",
        RUNNER_TEMP=str(tmp_path),
        GITHUB_OUTPUT=str(out),
    )
    assert result.returncode == 0, result.stderr
    return dict(line.split("=", 1) for line in out.read_text("utf-8").splitlines())


def test_a_forged_classifier_in_the_pull_request_is_not_the_one_that_runs(tmp_path: Path) -> None:
    flags = _pull_request(tmp_path, base_has_script=True, forged=True)
    assert {flags[f"run_{job}"] for job in JOBS} == {"true"}
    assert flags["ci"] == "true"


def test_the_pull_request_that_adds_the_script_runs_everything(tmp_path: Path) -> None:
    flags = _pull_request(tmp_path, base_has_script=False, forged=False)
    assert {flags[f"run_{job}"] for job in JOBS} == {"true"}


def test_a_push_runs_everything(tmp_path: Path) -> None:
    out = tmp_path / "output"
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(REPO / "scripts" / "changes.py", repo / "scripts" / "changes.py")
    result = _sh(
        repo,
        _step("changes", "classify"),
        EVENT="push",
        BASE="",
        RUNNER_TEMP=str(tmp_path),
        GITHUB_OUTPUT=str(out),
    )
    assert result.returncode == 0, result.stderr
    assert "run_rust=true" in out.read_text("utf-8").splitlines()
