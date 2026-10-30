"""The nightly workflow runs every fuzz target (security review SR-40): one
matrix entry per fuzz crate in the repository, and a recipe that lists each
crate's targets with `cargo fuzz list`, so a new target is fuzzed without
touching CI."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NIGHTLY = REPO / ".github" / "workflows" / "nightly.yml"
JUSTFILE = REPO / "justfile"


def fuzz_crates() -> set[str]:
    """The crates with a cargo-fuzz project (`<crate>/fuzz/Cargo.toml`)."""
    crates = set()
    for manifest in REPO.glob("*/fuzz/Cargo.toml"):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        if data.get("package", {}).get("metadata", {}).get("cargo-fuzz"):
            crates.add(manifest.parent.parent.name)
    return crates


def fuzz_job() -> str:
    """The text of the nightly workflow's `fuzz` job."""
    text = NIGHTLY.read_text(encoding="utf-8")
    start = re.search(r"^  fuzz:\n", text, re.MULTILINE)
    assert start, "nightly.yml has no `fuzz` job"
    rest = text[start.end() :]
    end = re.search(r"^  \S", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def test_every_fuzz_crate_runs_nightly() -> None:
    crates = fuzz_crates()
    assert crates >= {"core", "relay", "directory"}
    job = fuzz_job()
    matrix = re.search(r"crate: \[([^\]]*)\]", job)
    assert matrix, job
    assert {c.strip() for c in matrix.group(1).split(",")} == crates
    assert "just nightly-fuzz ${{ matrix.crate }}" in job
    # The repository is public: a crashing input is a reproducer for an
    # undisclosed finding, so it is never uploaded.
    assert "upload-artifact" not in job


def test_the_recipe_fuzzes_every_target_for_a_bounded_time() -> None:
    text = JUSTFILE.read_text(encoding="utf-8")
    recipe = re.search(r"^nightly-fuzz [^\n]*:\n((?:    [^\n]*\n|\n)+)", text, re.MULTILINE)
    assert recipe, "justfile has no nightly-fuzz recipe"
    body = recipe.group(1)
    assert "cargo +nightly fuzz list" in body
    assert "-max_total_time=" in body


JUST = shutil.which("just")
needs_just = pytest.mark.skipif(JUST is None, reason="needs just")

# Stands in for `cargo +nightly fuzz`: two targets; `boom` crashes, printing
# its input and writing it under -artifact_prefix as libFuzzer does.
FAKE_CARGO = """#!/bin/sh
echo "$*" >>"$FAKE_LOG"
case "$3" in
list) printf 'boom\\nfine\\n' ;;
build) ;;
run)
    for a in "$@"; do case "$a" in -artifact_prefix=*) prefix="${a#-artifact_prefix=}" ;; esac; done
    if [ "$4" = boom ]; then
        printf 'SECRET-INPUT' >"${prefix}crash-1"
        echo "Base64: SECRET-INPUT" >&2
        exit 77
    fi
    echo "Done 5 runs in 1 second(s)" ;;
esac
"""


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    cargo = bin_dir / "cargo"
    cargo.write_text(FAKE_CARGO, encoding="utf-8")
    cargo.chmod(0o700)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_LOG": str(tmp_path / "calls"),
        "TMPDIR": str(tmp_path),
    }
    assert JUST is not None
    return subprocess.run(
        [JUST, "--justfile", str(JUSTFILE), "nightly-fuzz", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@needs_just
@pytest.mark.parametrize(
    "args",
    [
        ("core; touch {marker}",),
        ("$(touch {marker})",),
        ("../core",),
        ("core", "1; touch {marker}"),
    ],
)
def test_the_recipe_takes_only_a_known_crate_and_a_number(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    marker = tmp_path / "pwned"
    result = _run(tmp_path, *(a.format(marker=marker) for a in args))
    assert result.returncode == 2, result.stderr
    assert "nightly-fuzz:" in result.stderr
    assert not marker.exists()
    assert not (tmp_path / "calls").exists(), "cargo never ran"


@needs_just
def test_every_target_runs_and_a_crash_is_named_by_its_hash_only(tmp_path: Path) -> None:
    result = _run(tmp_path, "core", "3")
    assert result.returncode == 1
    calls = (tmp_path / "calls").read_text(encoding="utf-8")
    assert "fuzz run fine -- -max_total_time=3" in calls, "a crash doesn't stop the run"
    digest = hashlib.sha256(b"SECRET-INPUT").hexdigest()
    assert f"crash in core/boom: input sha256 {digest}" in result.stderr
    assert "fuzz targets that failed in core: boom" in result.stderr
    assert "Done 5 runs" in result.stdout
    assert "SECRET" not in result.stdout + result.stderr
