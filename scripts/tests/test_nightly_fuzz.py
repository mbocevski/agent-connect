"""The nightly workflow runs every fuzz target (security review SR-40): one
matrix entry per fuzz crate in the repository, and a recipe that lists each
crate's targets with `cargo fuzz list`, so a new target is fuzzed without
touching CI."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

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
    assert "artifacts" in job, "a crash's input is uploaded"


def test_the_recipe_fuzzes_every_target_for_a_bounded_time() -> None:
    text = JUSTFILE.read_text(encoding="utf-8")
    recipe = re.search(r"^nightly-fuzz [^\n]*:\n((?:    [^\n]*\n|\n)+)", text, re.MULTILINE)
    assert recipe, "justfile has no nightly-fuzz recipe"
    body = recipe.group(1)
    assert "cargo +nightly fuzz list" in body
    assert "-max_total_time=" in body
