#!/usr/bin/env python3
"""Require docs to change with the user-facing code they describe.

``docs/MAP.toml`` maps code globs to docs. For a branch (``base..HEAD``,
default base ``origin/main``) this fails when a commit changes a mapped code
path and none of that rule's docs changed anywhere on the branch.

Exempt: commits whose type is docs, test, ci, chore, build or style, and the
whole check when ``SKIP_DOCS=true`` (CI sets it from the ``skip-docs`` PR
label). Merge commits are ignored (``--no-merges``): CI checks out GitHub's
synthetic "Merge X into Y" commit.

usage: scripts/check_docs.py [base-ref]
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MAP_PATH = Path("docs/MAP.toml")
EXEMPT = re.compile(r"^(docs|test|ci|chore|build|style)(\([a-z0-9,-]+\))?!?: ")
# Separates commits in `git log` output; never appears in a path or subject.
RECORD = "\x1e"


class MapError(ValueError):
    """``docs/MAP.toml`` is malformed."""


@dataclass(frozen=True)
class Rule:
    name: str
    code: tuple[str, ...]
    docs: tuple[str, ...]
    exclude: tuple[str, ...] = ()

    def covers(self, path: str) -> bool:
        """Whether ``path`` is code this rule watches."""
        return any(fnmatchcase(path, g) for g in self.code) and not any(
            fnmatchcase(path, g) for g in self.exclude
        )


@dataclass(frozen=True)
class Commit:
    subject: str
    files: tuple[str, ...]

    @property
    def exempt(self) -> bool:
        return EXEMPT.match(self.subject) is not None


@dataclass(frozen=True)
class Violation:
    rule: Rule
    code: tuple[str, ...]


def _strings(entry: Mapping[str, object], key: str, required: bool) -> tuple[str, ...]:
    value = entry.get(key, [] if not required else None)
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        msg = f"rule {entry.get('name')!r}: {key} must be a list of non-empty strings"
        raise MapError(msg)
    if required and not value:
        msg = f"rule {entry.get('name')!r}: {key} must not be empty"
        raise MapError(msg)
    return tuple(v for v in value if isinstance(v, str))


def parse_map(text: str) -> list[Rule]:
    """The rules in a ``MAP.toml`` document."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        msg = f"MAP.toml: {e}"
        raise MapError(msg) from None
    unknown = set(data) - {"rule"}
    if unknown:
        msg = f"MAP.toml: unknown keys {sorted(unknown)}"
        raise MapError(msg)
    entries = data.get("rule", [])
    if not isinstance(entries, list):
        msg = "MAP.toml: use [[rule]] tables"
        raise MapError(msg)
    rules: list[Rule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            msg = "MAP.toml: use [[rule]] tables"
            raise MapError(msg)
        extra = set(entry) - {"name", "code", "docs", "exclude"}
        if extra:
            msg = f"rule {entry.get('name')!r}: unknown keys {sorted(extra)}"
            raise MapError(msg)
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            msg = "every rule needs a name"
            raise MapError(msg)
        rules.append(
            Rule(
                name=name,
                code=_strings(entry, "code", required=True),
                docs=_strings(entry, "docs", required=True),
                exclude=_strings(entry, "exclude", required=False),
            )
        )
    names = [r.name for r in rules]
    if len(set(names)) != len(names):
        msg = "rule names must be unique"
        raise MapError(msg)
    return rules


def check(rules: Iterable[Rule], commits: Iterable[Commit]) -> list[Violation]:
    """Rules whose code changed in a non-exempt commit while none of their
    docs changed in any commit of the range."""
    commits = list(commits)
    touched = {f for c in commits for f in c.files}
    code = {f for c in commits if not c.exempt for f in c.files}
    out: list[Violation] = []
    for rule in rules:
        hits = tuple(sorted(f for f in code if rule.covers(f)))
        if hits and not touched.intersection(rule.docs):
            out.append(Violation(rule, hits))
    return out


def parse_log(text: str) -> list[Commit]:
    """Commits from ``git log --format=<RS>%s --name-only``."""
    commits: list[Commit] = []
    for record in text.split(RECORD):
        lines = [line for line in record.splitlines() if line.strip()]
        if lines:
            commits.append(Commit(lines[0], tuple(lines[1:])))
    return commits


def git_env() -> dict[str, str]:
    """The environment without ``GIT_*``: git exports ``GIT_DIR`` and friends
    to hooks, and they would override ``cwd``."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=cwd,
        env=git_env(),
        capture_output=True,
        text=True,
        check=False,
    )


def branch_commits(base: str, repo: Path = REPO) -> list[Commit] | None:
    """Non-merge commits in ``merge-base(base, HEAD)..HEAD``; ``None`` when
    there is no such base (no remote yet, or unrelated history)."""
    if _git(repo, "rev-parse", "--verify", "--quiet", base).returncode != 0:
        return None
    mb = _git(repo, "merge-base", base, "HEAD")
    if mb.returncode != 0:
        return None
    log = _git(
        repo,
        "log",
        "--no-merges",
        "--no-renames",
        f"--format={RECORD}%s",
        "--name-only",
        f"{mb.stdout.strip()}..HEAD",
    )
    if log.returncode != 0:
        raise RuntimeError(log.stderr.strip())
    return parse_log(log.stdout)


def main(argv: list[str], environ: Mapping[str, str] = os.environ, repo: Path = REPO) -> int:
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    base = argv[0] if argv else "origin/main"
    if environ.get("SKIP_DOCS", "false") == "true":
        print("docs: skipped (skip-docs label)")
        return 0
    try:
        rules = parse_map((repo / MAP_PATH).read_text(encoding="utf-8"))
    except (OSError, MapError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    commits = branch_commits(base, repo)
    if commits is None or len(commits) == 0:
        print(
            f"docs: base '{base}' not found or unrelated; skipping"
            if commits is None
            else f"docs: no commits ahead of {base}"
        )
        return 0
    violations = check(rules, commits)
    if not violations:
        print("docs: every mapped change has its docs")
        return 0
    for v in violations:
        print(
            f"error: [{v.rule.name}] {', '.join(v.code)} changed; "
            f"update one of: {', '.join(v.rule.docs)}",
            file=sys.stderr,
        )
    print(
        "       see docs/MAP.toml. If no doc needs to change, label the PR skip-docs.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
