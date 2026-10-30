"""Decide which CI jobs a pull request needs, and gate `ci-ok` on the result.

`classify` reads the changed paths (one per line, from `git diff --name-only
--no-renames`, so a rename lists both paths) and prints `name=value` lines for
`$GITHUB_OUTPUT`:

* the groups that changed: `rust`, `python`, `images`, `docs`, `ci`, `unknown`;
* one `run_<job>` flag for each job that is skipped when nothing it depends on
  changed.

A change to the `ci` group, or to a path no rule places, runs everything, and
so does `--all` (pushes to main, manual runs). Paths are placed by their top
directory or file name; a Markdown file inside a component directory belongs
to that component, because tests and builds read some of them.

`gate` is the body of `ci-ok`. It reads the `needs` context as JSON from
`$NEEDS` and the event name from `$EVENT`, and fails unless every job
succeeded or was skipped for a reason the classifier gave. A job skipped
because a dependency failed, or because `changes` itself failed, is a failure.

usage: changes.py classify [--all] < paths
       changes.py gate
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable, Mapping
from typing import Any

GROUPS = ("rust", "python", "images", "docs", "ci")

# Top directories -> groups.
DIRS: dict[str, frozenset[str]] = {
    "core": frozenset({"rust"}),
    "core-py": frozenset({"rust"}),
    "relay": frozenset({"rust"}),
    "directory": frozenset({"rust"}),
    "testdata": frozenset({"rust", "python"}),
    # `relay` embeds web/static/invite.css; the Dockerfiles copy it.
    "web": frozenset({"rust", "images"}),
    ".cargo": frozenset({"rust"}),
    ".config": frozenset({"rust"}),
    "daemon": frozenset({"python"}),
    "sdk": frozenset({"python"}),
    "harness": frozenset({"python"}),
    "examples": frozenset({"python"}),
    "packaging": frozenset({"python"}),
    # The integration tier builds the demo image and runs against the relay.
    "demo": frozenset({"python", "images"}),
    "integration": frozenset({"python", "images"}),
    "docs": frozenset({"docs"}),
    "styles": frozenset({"docs"}),
    "changelog.d": frozenset({"docs"}),
    ".github": frozenset({"ci"}),
    "scripts": frozenset({"ci"}),
}

# Files in the repository root -> groups.
ROOT_FILES: dict[str, frozenset[str]] = {
    "Cargo.toml": frozenset({"rust"}),
    "Cargo.lock": frozenset({"rust"}),
    "deny.toml": frozenset({"rust"}),
    "clippy.toml": frozenset({"rust"}),
    "pyproject.toml": frozenset({"python"}),
    "uv.lock": frozenset({"python"}),
    "licences-py.toml": frozenset({"python"}),
    "conftest.py": frozenset({"python"}),
    # The README's quickstart runs as a harness test.
    "README.md": frozenset({"docs", "python"}),
    "compose.test.yaml": frozenset({"python", "images"}),
    ".dockerignore": frozenset({"images"}),
    "LICENSE": frozenset({"docs"}),
    "NOTICE": frozenset({"docs"}),
    "justfile": frozenset({"ci"}),
    "rust-toolchain.toml": frozenset({"ci"}),
    "coverage-baseline.json": frozenset({"ci"}),
    ".pre-commit-config.yaml": frozenset({"ci"}),
    ".python-version": frozenset({"ci"}),
    ".editorconfig": frozenset({"ci"}),
    ".gitignore": frozenset({"ci"}),
    ".gitleaks.toml": frozenset({"ci"}),
    ".trivyignore.yaml": frozenset({"ci"}),
    ".rumdl.toml": frozenset({"ci"}),
    ".taplo.toml": frozenset({"ci"}),
    ".vale.ini": frozenset({"ci"}),
    "lychee.toml": frozenset({"ci"}),
    "_typos.toml": frozenset({"ci"}),
}

# Jobs that run only when a group they depend on changed. The rest of the
# workflow (lint, changelog, docs, hygiene) is cheap text checking and always
# runs. A Rust change reaches the Python tests through the native module and
# the relay binary, so it runs the Python job too.
JOB_GROUPS: dict[str, frozenset[str]] = {
    "rust": frozenset({"rust"}),
    "python": frozenset({"rust", "python"}),
    "licences": frozenset({"python"}),
    "contract": frozenset({"rust", "python"}),
    "platforms": frozenset({"rust", "python"}),
    "image": frozenset({"rust", "images"}),
    "integration": frozenset({"rust", "python", "images"}),
}

# Jobs that only exist on pull requests; on a push they are skipped by `if`.
PR_ONLY = frozenset({"changelog", "docs", "hygiene"})


def groups_of(path: str) -> frozenset[str] | None:
    """The groups a changed path belongs to, or None when no rule places it."""
    path = path.strip().removeprefix("./")
    if not path:
        return frozenset[str]()
    top, sep, _ = path.partition("/")
    if sep:
        return DIRS.get(top)
    if path in ROOT_FILES:
        return ROOT_FILES[path]
    if path.endswith(".md"):
        return frozenset({"docs"})
    return None


def classify(paths: Iterable[str], *, everything: bool = False) -> dict[str, str]:
    """The `name=value` outputs for a set of changed paths."""
    found: set[str] = set()
    unknown = False
    for path in paths:
        groups = groups_of(path)
        if groups is None:
            unknown = True
        else:
            found |= groups
    run_all = everything or unknown or "ci" in found
    out = {group: str(group in found or run_all).lower() for group in GROUPS}
    out["unknown"] = str(unknown).lower()
    for job, needs in JOB_GROUPS.items():
        out[f"run_{job}"] = str(run_all or bool(needs & found)).lower()
    return out


def gate(needs: Mapping[str, Any], event: str) -> list[str]:
    """Why `ci-ok` should fail (empty when it should pass)."""
    problems: list[str] = []
    changes = needs.get("changes")
    if changes is None or changes.get("result") != "success":
        return ["changes did not succeed, so no job can be trusted to have been skipped on purpose"]
    outputs = changes.get("outputs", {})
    for job, info in sorted(needs.items()):
        if job == "changes":
            continue
        result = info.get("result")
        if result == "success":
            continue
        if result == "skipped":
            if job in JOB_GROUPS and outputs.get(f"run_{job}") == "false":
                continue
            if job in PR_ONLY and event != "pull_request":
                continue
            problems.append(f"{job} was skipped but nothing excused it (a failed dependency?)")
            continue
        problems.append(f"{job}: {result}")
    return problems


def main(argv: list[str]) -> int:
    if argv[:1] == ["classify"] and set(argv[1:]) <= {"--all"}:
        paths = [line for line in sys.stdin.read().splitlines() if line.strip()]
        for name, value in classify(paths, everything="--all" in argv).items():
            print(f"{name}={value}")
        return 0
    if argv == ["gate"]:
        needs = json.loads(os.environ["NEEDS"])
        for job, info in sorted(needs.items()):
            print(f"{job}: {info.get('result')}")
        problems = gate(needs, os.environ.get("EVENT", ""))
        for problem in problems:
            print(f"ci-ok: {problem}", file=sys.stderr)
        return 1 if problems else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
