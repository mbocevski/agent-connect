"""Check that `testdata/MANIFEST.json` and the test suites agree.

Fails when:

* a file in `testdata/` is missing from the manifest (or the reverse),
* an entry declares no suites or an unknown suite,
* a declared suite has no test source that mentions the file name
  (Rust: any `.rs` file; Python: any `test_*.py` or `conftest.py`).

usage: check_manifest.py [ROOT]    (default: the repository root)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SUITES = ("rust", "python")
MANIFEST = "MANIFEST.json"
_SKIP_DIRS = frozenset({".git", ".venv", "target", "node_modules", "testdata", "__pycache__"})


def _is_source(suite: str, name: str) -> bool:
    if suite == "rust":
        return name.endswith(".rs")
    return name.endswith(".py") and (name.startswith("test_") or name == "conftest.py")


def _walk_sources(root: Path, suite: str) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        found.extend(Path(dirpath, n) for n in filenames if _is_source(suite, n))
    return found


def _references(root: Path, suite: str, name: str) -> bool:
    return any(name in p.read_text(encoding="utf-8") for p in _walk_sources(root, suite))


def check(root: Path) -> list[str]:
    """Return a list of problems (empty when the manifest is consistent)."""
    testdata = root / "testdata"
    manifest_path = testdata / MANIFEST
    if not manifest_path.is_file():
        return [f"{manifest_path} is missing"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = dict(manifest["files"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return [f"{MANIFEST} is malformed: {exc!r}"]

    problems: list[str] = []
    on_disk = {
        p.relative_to(testdata).as_posix()
        for p in testdata.rglob("*")
        if p.is_file() and p.name != MANIFEST
    }
    problems.extend(
        f"{name}: in testdata/ but not listed in {MANIFEST}"
        for name in sorted(on_disk - entries.keys())
    )
    problems.extend(
        f"{name}: listed in {MANIFEST} but missing from testdata/"
        for name in sorted(entries.keys() - on_disk)
    )

    for name, entry in sorted(entries.items()):
        suites = entry.get("suites")
        if not isinstance(suites, list) or not suites:
            problems.append(f"{name}: 'suites' must be a non-empty list")
            continue
        for suite in suites:
            if suite not in SUITES:
                problems.append(f"{name}: unknown suite {suite!r} (expected one of {SUITES})")
            elif name in on_disk and not _references(root, suite, Path(name).name):
                problems.append(f"{name}: no {suite} test references it")
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[0]) if argv else Path(__file__).resolve().parent.parent
    problems = check(root)
    for problem in problems:
        print(f"check_manifest: {problem}", file=sys.stderr)
    if not problems:
        print("check_manifest: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
