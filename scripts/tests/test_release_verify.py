"""Signed releases are verified (security review SR-39): every file's cosign
bundle and both images' signatures are checked against the release
workflow's identity, by `just release-verify` and by the release workflow
itself right after it signs, and nothing is published before the tagged
commit's reproducibility check passes."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "verify-signatures.sh"
RELEASE = REPO / ".github" / "workflows" / "release.yml"
REPRO = REPO / ".github" / "workflows" / "repro.yml"
JUSTFILE = REPO / "justfile"

OWNER_REPO = "example/agent-connect"
REF = "refs/tags/v1.2.3"
IDENTITY = f"https://github.com/{OWNER_REPO}/.github/workflows/release.yml@{REF}"
ISSUER = "https://token.actions.githubusercontent.com"

# Stands in for cosign: records its arguments, and fails for a file or
# image named in $FAKE_BAD.
FAKE_COSIGN = """#!/bin/sh
echo "$*" >>"$FAKE_LOG"
for a in "$@"; do last="$a"; done
case " $FAKE_BAD " in *" $(basename "$last") "*) echo "bad signature" >&2; exit 1 ;; esac
"""


def _run(tmp_path: Path, *args: str, bad: str = "") -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    cosign = bin_dir / "cosign"
    cosign.write_text(FAKE_COSIGN, encoding="utf-8")
    cosign.chmod(0o700)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_LOG": str(tmp_path / "calls"),
        "FAKE_BAD": bad,
    }
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, check=False
    )


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _release(tmp_path: Path, *names: str, bundles: bool = True) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    for n in names:
        (dist / n).write_bytes(b"x")
        if bundles:
            (dist / f"{n}.sigstore.json").write_bytes(b"{}")
    return dist


def test_every_file_is_checked_against_the_release_workflow(tmp_path: Path) -> None:
    dist = _release(tmp_path, "agentconnect-relay-x86_64-linux", "SHA256SUMS-x86_64-linux")
    result = _run(tmp_path, "blobs", str(dist), OWNER_REPO, REF)
    assert result.returncode == 0, result.stderr
    calls = _calls(tmp_path)
    assert len(calls) == 2
    for name in ("agentconnect-relay-x86_64-linux", "SHA256SUMS-x86_64-linux"):
        (call,) = [c for c in calls if c.endswith(f"/{name}")]
        assert call.startswith(f"verify-blob --bundle {dist}/{name}.sigstore.json ")
        assert f"--certificate-identity {IDENTITY} " in call
        assert f"--certificate-oidc-issuer {ISSUER} " in call


@pytest.mark.parametrize(
    ("names", "bundles", "bad", "error"),
    [
        (("a.whl",), False, "", "no cosign bundle for a.whl"),
        ((), True, "", "nothing to verify"),
        (("a.whl", "b.whl"), True, "a.whl", "bad signature"),
    ],
)
def test_a_missing_or_bad_signature_fails(
    tmp_path: Path, names: tuple[str, ...], bundles: bool, bad: str, error: str
) -> None:
    dist = _release(tmp_path, *names, bundles=bundles)
    result = _run(tmp_path, "blobs", str(dist), OWNER_REPO, REF, bad=bad)
    assert result.returncode != 0
    assert error in result.stderr


@pytest.mark.parametrize("entry", [".hidden", "subdir"])
def test_an_unexpected_entry_fails(tmp_path: Path, entry: str) -> None:
    dist = _release(tmp_path, "a.whl")
    if entry == "subdir":
        (dist / entry).mkdir()
    else:
        (dist / entry).write_bytes(b"x")
    result = _run(tmp_path, "blobs", str(dist), OWNER_REPO, REF)
    assert result.returncode != 0
    assert f"unexpected entry {entry}" in result.stderr


def test_a_bundle_without_its_file_fails(tmp_path: Path) -> None:
    dist = _release(tmp_path, "a.whl")
    (dist / "gone.whl.sigstore.json").write_bytes(b"{}")
    result = _run(tmp_path, "blobs", str(dist), OWNER_REPO, REF)
    assert result.returncode != 0
    assert "gone.whl" in result.stderr


def test_an_image_is_checked_against_the_release_workflow(tmp_path: Path) -> None:
    image = "ghcr.io/example/agentconnect-relay:1.2.3"
    result = _run(tmp_path, "image", image, OWNER_REPO, REF)
    assert result.returncode == 0, result.stderr
    (call,) = _calls(tmp_path)
    assert call == (
        f"verify --certificate-identity {IDENTITY} --certificate-oidc-issuer {ISSUER} {image}"
    )


def _job(text: str, name: str) -> str:
    start = re.search(rf"^  {re.escape(name)}:\n", text, re.MULTILINE)
    assert start, f"no `{name}` job"
    rest = text[start.end() :]
    end = re.search(r"^  \S", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def _needs(job: str) -> set[str]:
    m = re.search(r"^    needs: \[([^\]]*)\]", job, re.MULTILINE)
    assert m, job
    return {n.strip() for n in m.group(1).split(",")}


def test_the_release_workflow_verifies_what_it_signs() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    build = _job(text, "build")
    assert build.index("cosign sign-blob") < build.index(
        'scripts/verify-signatures.sh blobs dist "$GITHUB_REPOSITORY" "$GITHUB_REF"'
    )
    publish = _job(text, "image-publish")
    assert publish.index("cosign sign --yes") < publish.index(
        'scripts/verify-signatures.sh image "$IMAGE@$DIGEST" "$GITHUB_REPOSITORY" "$GITHUB_REF"'
    )


def test_nothing_is_published_before_the_reproducibility_check() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    assert "uses: ./.github/workflows/repro.yml" in _job(text, "repro")
    for job in ("pypi", "image-publish", "release"):
        assert "repro" in _needs(_job(text, job)), job
    assert re.search(r"^  workflow_call:", REPRO.read_text(encoding="utf-8"), re.MULTILINE)


def test_release_verify_checks_the_signatures() -> None:
    text = JUSTFILE.read_text(encoding="utf-8")
    recipe = re.search(r"^release-verify [^\n]*:\n((?:    [^\n]*\n)+)", text, re.MULTILINE)
    assert recipe, "justfile has no release-verify recipe"
    body = recipe.group(1)
    assert "scripts/verify-signatures.sh blobs" in body
    assert "scripts/verify-signatures.sh image" in body
    assert "refs/tags/v{{ version }}" in body
    assert "gh attestation verify" in body
    # The identity is the project's, never that of whatever repository a
    # clone's gh defaults to (a fork's signatures would verify against it).
    assert "gh repo view" not in body
    pinned = 'release_repo := env("AC_RELEASE_REPO", "mbocevski/agent-connect")'
    assert pinned in text.splitlines()
    assert "{{ release_repo }}" in body


def _steps(job: str) -> list[str]:
    return [str(s) for s in re.split(r"^      - ", job, flags=re.MULTILINE)[1:]]


def test_every_job_that_runs_a_script_checks_the_repository_out_first() -> None:
    """A step that runs something from scripts/ needs the checkout before
    it: without one it exits 127, and in image-publish that would come after
    the image is pushed and signed (a half-published release)."""
    for workflow in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        jobs = re.findall(r"^  ([A-Za-z0-9_-]+):\n", text.split("\njobs:\n", 1)[1], re.MULTILINE)
        for name in jobs:
            checked_out = False
            for step in _steps(_job(text, name)):
                if "actions/checkout@" in step:
                    checked_out = True
                if re.search(r"^\s*(run:|-).*\bscripts/", step, re.MULTILINE) or step.startswith(
                    "run: scripts/"
                ):
                    assert checked_out, f"{workflow.name}: {name} runs scripts/ before a checkout"
