#!/usr/bin/env python3
"""Require docs to change with the user-facing code they describe.

``docs/MAP.toml`` holds three things:

* ``[[rule]]``: code globs and the docs that must change with them. For a
  branch (``base..HEAD``, default base ``origin/main``) the check fails when a
  commit changes a rule's code and none of its docs changed anywhere on the
  branch.
* ``[[component]]``: the inventory behind the README's Status section. Each
  component (``name``, ``paths``, ``doc``) has one Status bullet in
  ``README.md`` marked ``<!-- component: <name> -->``. A branch that adds an
  ``added`` changelog fragment (``changelog.d/<slug>.added.md``) and changes a
  component's paths must also change ``README.md``.
* ``internal``: globs of source files that are not user-facing.

Structural checks run on every invocation: a component without a Status
bullet, a bullet without a component, a bullet linking a missing file, a
workspace member (Cargo or uv) no component claims, and a source file that
neither a rule nor ``internal`` covers.

Exempt from the branch checks: commits whose type is docs, test, ci, chore,
build or style. ``SKIP_DOCS=true`` (CI sets it from the ``skip-docs`` PR
label) skips the rule check and ``SKIP_README=true`` (``skip-readme``) skips
the README check. Merge commits are ignored (``--no-merges``): CI checks out
GitHub's synthetic "Merge X into Y" commit.

usage: scripts/check_docs.py [base-ref]
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from textwrap import shorten

REPO = Path(__file__).resolve().parents[1]
MAP_PATH = Path("docs/MAP.toml")
README = "README.md"
ADDED_FRAGMENT = re.compile(r"^changelog\.d/[a-z0-9][a-z0-9-]*\.added\.md$")
EXEMPT = re.compile(r"^(docs|test|ci|chore|build|style)(\([a-z0-9,-]+\))?!?: ")
# Separates commits in `git log` output; never appears in a path or subject.
RECORD = "\x1e"
# Every `.rs` and `.py` file under these must be covered by a rule or `internal`.
SOURCE_ROOTS = (
    "core/src",
    "core-py/src",
    "relay/src",
    "directory/src",
    "daemon/src",
    "sdk/python/src",
    "harness/src",
)
SOURCE_SUFFIXES = (".rs", ".py")
MARKER = re.compile(r"<!--\s*component:\s*([^>]*?)\s*-->")
LINK = re.compile(r"\]\(([^)\s]+)\)")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


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
class Component:
    """A part of the project with one README Status bullet.

    ``readme = false`` marks parts that have no Status bullet (test tooling,
    spikes); they still have to exist so that new workspace members are
    classified.
    """

    name: str
    paths: tuple[str, ...]
    doc: str
    readme: bool = True

    def covers(self, path: str) -> bool:
        return any(fnmatchcase(path, g) for g in self.paths)


@dataclass(frozen=True)
class DocsMap:
    rules: tuple[Rule, ...]
    components: tuple[Component, ...] = ()
    internal: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class ReadmeViolation:
    components: tuple[Component, ...]
    code: tuple[str, ...]
    entries: tuple[str, ...]


def _strings(
    entry: Mapping[str, object], key: str, required: bool, what: str = "rule"
) -> tuple[str, ...]:
    value = entry.get(key, [] if not required else None)
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        msg = f"{what} {entry.get('name')!r}: {key} must be a list of non-empty strings"
        raise MapError(msg)
    if required and not value:
        msg = f"{what} {entry.get('name')!r}: {key} must not be empty"
        raise MapError(msg)
    return tuple(v for v in value if isinstance(v, str))


def _tables(data: Mapping[str, object], key: str) -> list[dict[str, object]]:
    entries = data.get(key, [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        msg = f"MAP.toml: use [[{key}]] tables"
        raise MapError(msg)
    return [e for e in entries if isinstance(e, dict)]


def _name(entry: Mapping[str, object], what: str) -> str:
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        msg = f"every {what} needs a name"
        raise MapError(msg)
    return name


def _unique(names: list[str], what: str) -> None:
    if len(set(names)) != len(names):
        msg = f"{what} names must be unique"
        raise MapError(msg)


def parse_map(text: str) -> DocsMap:
    """The rules, components and internal globs of a ``MAP.toml`` document."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        msg = f"MAP.toml: {e}"
        raise MapError(msg) from None
    unknown = set(data) - {"rule", "component", "internal"}
    if unknown:
        msg = f"MAP.toml: unknown keys {sorted(unknown)}"
        raise MapError(msg)
    rules: list[Rule] = []
    for entry in _tables(data, "rule"):
        extra = set(entry) - {"name", "code", "docs", "exclude"}
        if extra:
            msg = f"rule {entry.get('name')!r}: unknown keys {sorted(extra)}"
            raise MapError(msg)
        rules.append(
            Rule(
                name=_name(entry, "rule"),
                code=_strings(entry, "code", required=True),
                docs=_strings(entry, "docs", required=True),
                exclude=_strings(entry, "exclude", required=False),
            )
        )
    _unique([r.name for r in rules], "rule")
    components: list[Component] = []
    for entry in _tables(data, "component"):
        extra = set(entry) - {"name", "paths", "doc", "readme"}
        if extra:
            msg = f"component {entry.get('name')!r}: unknown keys {sorted(extra)}"
            raise MapError(msg)
        name = _name(entry, "component")
        doc = entry.get("doc")
        readme = entry.get("readme", True)
        if not NAME.match(name):
            msg = f"component {name!r}: use lowercase letters, digits and dashes"
            raise MapError(msg)
        if not isinstance(doc, str) or not doc:
            msg = f"component {name!r}: doc must be a non-empty string"
            raise MapError(msg)
        if not isinstance(readme, bool):
            msg = f"component {name!r}: readme must be true or false"
            raise MapError(msg)
        components.append(
            Component(
                name=name,
                paths=_strings(entry, "paths", required=True, what="component"),
                doc=doc,
                readme=readme,
            )
        )
    _unique([c.name for c in components], "component")
    internal = _strings(data, "internal", required=False, what="MAP.toml")
    return DocsMap(tuple(rules), tuple(components), internal)


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


def check_readme(
    components: Iterable[Component], commits: Iterable[Commit], entries: Iterable[str]
) -> ReadmeViolation | None:
    """A branch with new ``added`` changelog fragments that changes a component's
    paths in a non-exempt commit must change the README."""
    commits = list(commits)
    entries = tuple(sorted(entries))
    if not entries or any(README in c.files for c in commits):
        return None
    code = {f for c in commits if not c.exempt for f in c.files}
    hit = [c for c in components if c.readme and any(c.covers(f) for f in code)]
    if not hit:
        return None
    files = tuple(sorted(f for f in code if any(c.covers(f) for c in hit)))
    return ReadmeViolation(tuple(hit), files, entries)


@dataclass(frozen=True)
class Bullet:
    text: str
    components: tuple[str, ...]
    links: tuple[str, ...]

    @property
    def title(self) -> str:
        return shorten(self.text.splitlines()[0], 60, placeholder="...")


def status_bullets(readme: str) -> list[Bullet] | None:
    """The top-level bullets of the README's ``## Status`` section, or ``None``
    when it has none."""
    lines = readme.splitlines()
    try:
        start = lines.index("## Status") + 1
    except ValueError:
        return None
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in lines[start:]:
        if line.startswith("## "):
            break
        if line.startswith("- "):
            current = [line]
            blocks.append(current)
        elif current is not None and (line.startswith(" ") or not line.strip()):
            current.append(line)
        else:
            # A paragraph or table ends the bullet that preceded it.
            current = None
    out: list[Bullet] = []
    for block in blocks:
        text = "\n".join(block).rstrip()
        names = tuple(
            n.strip() for m in MARKER.finditer(text) for n in m.group(1).split(",") if n.strip()
        )
        out.append(Bullet(text, names, tuple(LINK.findall(text))))
    return out


def _local_links(links: Iterable[str]) -> set[str]:
    """The repo-relative paths of the local files a bullet links to."""
    out: set[str] = set()
    for link in links:
        if re.match(r"^[a-z][a-z0-9+.-]*:", link) or link.startswith(("#", "/")):
            continue
        path = link.split("#", 1)[0]
        if path:
            out.add(str(PurePosixPath(path)))
    return out


def check_status(
    components: Iterable[Component], readme: str | None, exists: Callable[[str], bool]
) -> list[str]:
    """Problems between the component inventory and the README Status bullets."""
    components = list(components)
    by_name = {c.name: c for c in components}
    errors = [f"[{c.name}] doc {c.doc} does not exist" for c in components if not exists(c.doc)]
    if readme is None:
        return [*errors, f"{README} not found"]
    bullets = status_bullets(readme)
    if bullets is None:
        return [*errors, f"{README} has no '## Status' section"]
    seen: set[str] = set()
    for b in bullets:
        if not b.components:
            errors.append(
                f"README Status bullet '{b.title}' has no component; "
                "add <!-- component: <name> --> and a [[component]] in docs/MAP.toml"
            )
        for name in b.components:
            comp = by_name.get(name)
            if comp is None:
                errors.append(f"README Status bullet '{b.title}' names unknown component {name!r}")
                continue
            seen.add(name)
            if comp.doc not in _local_links(b.links):
                errors.append(f"[{name}] its README bullet does not link {comp.doc}")
        errors.extend(
            f"README Status bullet '{b.title}' links {p}, which does not exist"
            for p in sorted(_local_links(b.links))
            if not exists(p)
        )
    errors.extend(
        f"[{c.name}] has no README Status bullet (<!-- component: {c.name} -->)"
        for c in components
        if c.readme and c.name not in seen
    )
    errors.extend(
        f"[{c.name}] is readme = false but has a README Status bullet"
        for c in components
        if not c.readme and c.name in seen
    )
    return errors


def _expand(repo: Path, patterns: Iterable[str]) -> list[str]:
    out: list[str] = []
    for p in patterns:
        if any(ch in p for ch in "*?["):
            out.extend(sorted(m.relative_to(repo).as_posix() for m in repo.glob(p) if m.is_dir()))
        else:
            out.append(str(PurePosixPath(p)))
    return out


def workspace_members(repo: Path) -> list[str]:
    """Member directories of the Cargo workspace (root ``Cargo.toml``) and the
    uv workspace (root ``pyproject.toml``)."""
    members: list[str] = []
    for file, keys in (
        ("Cargo.toml", ("workspace", "members")),
        ("pyproject.toml", ("tool", "uv", "workspace", "members")),
    ):
        path = repo / file
        if not path.is_file():
            continue
        node: object = tomllib.loads(path.read_text(encoding="utf-8"))
        for key in keys:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, list):
            members.extend(_expand(repo, [m for m in node if isinstance(m, str)]))
    return sorted(set(members))


def check_members(components: Iterable[Component], members: Iterable[str]) -> list[str]:
    """Workspace members that no component claims. A component claims a member
    with a path glob that covers the member's whole directory (``dir/**``)."""
    components = list(components)
    return [
        f"workspace member {m} is not in any [[component]]; add one (or a path glob "
        f"like '{m}/**' to an existing one)"
        for m in members
        if not any(c.covers(f"{m}/x") for c in components)
    ]


def check_coverage(docs_map: DocsMap, files: Iterable[str]) -> list[str]:
    """Source files that neither a rule's ``code`` nor ``internal`` covers."""
    errors: list[str] = []
    for f in sorted(files):
        if not f.endswith(SOURCE_SUFFIXES) or not any(f.startswith(r + "/") for r in SOURCE_ROOTS):
            continue
        if any(r.covers(f) for r in docs_map.rules):
            continue
        if any(fnmatchcase(f, g) for g in docs_map.internal):
            continue
        errors.append(
            f"{f} is not classified: add it to a [[rule]] code list (user-facing) "
            "or to internal in docs/MAP.toml"
        )
    return errors


def tracked_files(repo: Path) -> list[str]:
    ls = _git(repo, "ls-files")
    if ls.returncode != 0:
        raise RuntimeError(ls.stderr.strip())
    return ls.stdout.splitlines()


def check_structure(docs_map: DocsMap, repo: Path) -> list[str]:
    """Every check that does not depend on the branch."""
    readme_path = repo / README
    readme = readme_path.read_text(encoding="utf-8") if readme_path.is_file() else None
    return [
        *check_status(docs_map.components, readme, lambda p: (repo / p).exists()),
        *check_members(docs_map.components, workspace_members(repo)),
        *check_coverage(docs_map, tracked_files(repo)),
    ]


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


def merge_base(base: str, repo: Path = REPO) -> str | None:
    """``merge-base(base, HEAD)``; ``None`` when there is none (no remote yet,
    or unrelated history)."""
    if _git(repo, "rev-parse", "--verify", "--quiet", base).returncode != 0:
        return None
    mb = _git(repo, "merge-base", base, "HEAD")
    return mb.stdout.strip() if mb.returncode == 0 else None


def branch_commits(base: str, repo: Path = REPO) -> list[Commit] | None:
    """Non-merge commits in ``merge-base(base, HEAD)..HEAD``; ``None`` when
    there is no such base."""
    mb = merge_base(base, repo)
    if mb is None:
        return None
    log = _git(
        repo,
        "log",
        "--no-merges",
        "--no-renames",
        f"--format={RECORD}%s",
        "--name-only",
        f"{mb}..HEAD",
    )
    if log.returncode != 0:
        raise RuntimeError(log.stderr.strip())
    return parse_log(log.stdout)


def branch_added_entries(base: str, repo: Path = REPO) -> set[str]:
    """The ``added`` changelog fragments the branch adds (``changelog.d/*.added.md``
    that the base lacks), each as its text on one line."""
    mb = merge_base(base, repo)
    if mb is None:
        return set()
    names = _git(
        repo,
        "diff",
        "--name-only",
        "--no-renames",
        "--diff-filter=A",
        f"{mb}..HEAD",
        "--",
        "changelog.d",
    )
    if names.returncode != 0:
        raise RuntimeError(names.stderr.strip())
    entries: set[str] = set()
    for name in names.stdout.splitlines():
        shown = _git(repo, "show", f"HEAD:{name}")
        if ADDED_FRAGMENT.match(name) and shown.returncode == 0:
            entries.add(" ".join(shown.stdout.split()))
    return entries


def report_rules(docs_map: DocsMap, commits: list[Commit]) -> bool:
    """Print the rule violations; whether there were any."""
    violations = check(docs_map.rules, commits)
    for v in violations:
        print(
            f"error: [{v.rule.name}] {', '.join(v.code)} changed; "
            f"update one of: {', '.join(v.rule.docs)}",
            file=sys.stderr,
        )
    if violations:
        print(
            "       see docs/MAP.toml. If no doc needs to change, label the PR skip-docs.",
            file=sys.stderr,
        )
    return bool(violations)


def report_readme(docs_map: DocsMap, commits: list[Commit], entries: set[str]) -> bool:
    """Print the README violation, if any; whether there was one."""
    feature = check_readme(docs_map.components, commits, entries)
    if feature is None:
        return False
    names = ", ".join(c.name for c in feature.components)
    print(
        f"error: the branch adds an `added` changelog fragment and [{names}] changed "
        f"({', '.join(feature.code)}), but {README} did not; update its Status section.",
        file=sys.stderr,
    )
    print("       If the README stays correct, label the PR skip-readme.", file=sys.stderr)
    return True


def main(argv: list[str], environ: Mapping[str, str] = os.environ, repo: Path = REPO) -> int:
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    base = argv[0] if argv else "origin/main"
    try:
        docs_map = parse_map((repo / MAP_PATH).read_text(encoding="utf-8"))
        problems = check_structure(docs_map, repo)
    except (OSError, MapError, RuntimeError, tomllib.TOMLDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    failed = bool(problems)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        print(
            "       see docs/MAP.toml: components and internal files must stay in step "
            "with the README Status section and the source tree.",
            file=sys.stderr,
        )
    commits = branch_commits(base, repo)
    if commits is None or len(commits) == 0:
        print(
            f"docs: base '{base}' not found or unrelated; skipping"
            if commits is None
            else f"docs: no commits ahead of {base}"
        )
        return 1 if failed else 0
    if environ.get("SKIP_DOCS", "false") == "true":
        print("docs: rule check skipped (skip-docs label)")
    else:
        failed = report_rules(docs_map, commits) or failed
    if environ.get("SKIP_README", "false") == "true":
        print("docs: README check skipped (skip-readme label)")
    else:
        entries = branch_added_entries(base, repo)
        failed = report_readme(docs_map, commits, entries) or failed
    if failed:
        return 1
    print("docs: every mapped change has its docs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
