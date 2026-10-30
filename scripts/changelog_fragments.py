#!/usr/bin/env python3
"""Changelog entries as per-PR fragments, assembled when a release is cut.

Every PR that needs a CHANGELOG entry adds one file under ``changelog.d/``,
named ``<slug>.<section>.md``, with one Markdown bullet in it (it may wrap).
``<section>`` is one of ``added``, ``changed``, ``deprecated``, ``removed``,
``fixed`` or ``security`` (Keep a Changelog), and ``<slug>`` is lowercase
letters, digits and hyphens. Two PRs never touch the same file, so they never
conflict over the CHANGELOG.

usage:
  changelog_fragments.py cut VERSION [DATE]   move [Unreleased] and every
        fragment into a new ``## [VERSION] - DATE`` section (DATE defaults to
        today, UTC) and delete the fragments
  changelog_fragments.py preview              print the [Unreleased] section as
        the cut would assemble it
  changelog_fragments.py validate             check every file in changelog.d/

The cut keeps what is already under ``## [Unreleased]`` in CHANGELOG.md (a note
above its first ``###`` heading and the entries under each heading) and puts
the fragments after them, section by section, in Keep a Changelog order and
sorted by slug within a section. Environment: ``CHANGELOG`` (default
``CHANGELOG.md``) and ``CHANGELOG_FRAGMENTS`` (default ``changelog.d``), both
relative to the repository root.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Keep a Changelog order.
SECTIONS = ("added", "changed", "deprecated", "removed", "fixed", "security")
FRAGMENT_NAME = re.compile(
    rf"^(?P<slug>[a-z0-9][a-z0-9-]*)\.(?P<section>{'|'.join(SECTIONS)})\.md$"
)
# Files in the fragments directory that are not fragments.
NOT_FRAGMENTS = frozenset({"README.md", ".gitkeep"})
UNRELEASED = "## [Unreleased]"
HEADING = re.compile(r"^### (?P<title>.+?)\s*$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


CUT_ARGS = 2  # `cut VERSION [DATE]`


class ChangelogError(Exception):
    """A fragment, the CHANGELOG or an argument is not usable."""


@dataclass(frozen=True)
class Fragment:
    slug: str
    section: str
    text: str  # one bullet, no trailing newline


def parse_fragment(name: str, content: str) -> Fragment:
    """The fragment a file holds, or ``ChangelogError`` naming the problem."""
    m = FRAGMENT_NAME.match(name)
    if m is None:
        msg = (
            f"{name}: a fragment is named <slug>.<section>.md, with a slug of lowercase "
            f"letters, digits and hyphens and a section of {', '.join(SECTIONS)}"
        )
        raise ChangelogError(msg)
    lines = [line.rstrip() for line in content.strip().splitlines()]
    if not lines or not lines[0].startswith("- ") or not lines[0][2:].strip():
        msg = f"{name}: a fragment is one Markdown bullet and starts with '- '"
        raise ChangelogError(msg)
    for line in lines[1:]:
        if not line:
            msg = f"{name}: a fragment is one bullet without blank lines"
            raise ChangelogError(msg)
        if not line.startswith(" "):
            msg = f"{name}: indent the lines that continue the bullet (found {line[:30]!r})"
            raise ChangelogError(msg)
    return Fragment(m["slug"], m["section"], "\n".join(lines))


def read_fragments(directory: Path) -> list[Fragment]:
    """Every fragment in ``directory``, in section order and sorted by slug.

    A missing directory has none. Anything in it that is neither a fragment nor
    one of ``NOT_FRAGMENTS`` is an error, so a typo in a name can't make an
    entry vanish from the release.
    """
    if not directory.is_dir():
        return []
    found: list[Fragment] = []
    for path in sorted(directory.iterdir()):
        if path.name in NOT_FRAGMENTS:
            continue
        if not path.is_file() or path.is_symlink():
            msg = f"{path.name}: not a regular file; changelog.d/ holds fragments only"
            raise ChangelogError(msg)
        found.append(parse_fragment(path.name, path.read_text(encoding="utf-8")))
    return sorted(found, key=lambda f: (SECTIONS.index(f.section), f.slug))


def split_body(body: str) -> tuple[str, dict[str, str]]:
    """The note above the first ``###`` heading of an [Unreleased] body and the
    text under each heading, keyed by the lowercase heading."""
    note: list[str] = []
    sections: dict[str, list[str]] = {}
    current: list[str] = note
    for line in body.splitlines():
        m = HEADING.match(line)
        if m is not None:
            key = m["title"].lower()
            if key not in SECTIONS:
                msg = f"[Unreleased] has a '### {m['title']}' heading; use {', '.join(SECTIONS)}"
                raise ChangelogError(msg)
            if key in sections:
                msg = f"[Unreleased] has two '### {m['title']}' headings"
                raise ChangelogError(msg)
            current = sections.setdefault(key, [])
        else:
            current.append(line)
    return "\n".join(note).strip(), {k: "\n".join(v).strip() for k, v in sections.items()}


def assemble(body: str, fragments: Iterable[Fragment]) -> str:
    """The text of a release section: what [Unreleased] holds in ``body``, then
    the fragments, under ``###`` headings in Keep a Changelog order. Empty when
    there is nothing to release."""
    note, existing = split_body(body)
    added: dict[str, list[str]] = {}
    for f in fragments:
        added.setdefault(f.section, []).append(f.text)
    parts = [note] if note else []
    for section in SECTIONS:
        entries = [existing.get(section, ""), *added.get(section, [])]
        text = "\n".join(e for e in entries if e)
        if text:
            parts.append(f"### {section.capitalize()}\n\n{text}")
    return "\n\n".join(parts) + "\n" if parts else ""


def find_unreleased(lines: list[str]) -> tuple[int, int]:
    """The index of the [Unreleased] heading and of the next ``## `` heading
    (or the end)."""
    starts = [i for i, line in enumerate(lines) if line.rstrip() == UNRELEASED]
    if len(starts) != 1:
        msg = f"CHANGELOG needs exactly one '{UNRELEASED}' heading"
        raise ChangelogError(msg)
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return start, end


def assembled_unreleased(changelog: str, fragments: Iterable[Fragment]) -> str:
    """The assembled [Unreleased] section of a changelog text."""
    lines = changelog.splitlines()
    start, end = find_unreleased(lines)
    return assemble("\n".join(lines[start + 1 : end]), fragments)


def cut(
    changelog_path: Path, fragments_dir: Path, version: str, date: str
) -> tuple[Path, list[Path]]:
    """Turn [Unreleased] and the fragments into a ``## [version] - date``
    section of the changelog, then delete the fragments; return the changelog
    and the deleted files."""
    if VERSION.match(version) is None:
        msg = f"version must be X.Y.Z with an optional aN, bN or rcN, not {version!r}"
        raise ChangelogError(msg)
    if DATE.match(date) is None:
        msg = f"date must be YYYY-MM-DD, got {date!r}"
        raise ChangelogError(msg)
    text = changelog_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if any(line.startswith(f"## [{version}]") for line in lines):
        msg = f"{changelog_path.name} already has a [{version}] section"
        raise ChangelogError(msg)
    start, end = find_unreleased(lines)
    fragments = read_fragments(fragments_dir)
    section = assemble("\n".join(lines[start + 1 : end]), fragments)
    if not section:
        msg = "[Unreleased] is empty and there are no fragments; nothing to release"
        raise ChangelogError(msg)
    out = [*lines[: start + 1], "", f"## [{version}] - {date}", "", *section.splitlines()]
    if end < len(lines):
        out += ["", *lines[end:]]
    tmp = changelog_path.with_name(changelog_path.name + ".tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    tmp.replace(changelog_path)
    removed = [fragments_dir / f"{f.slug}.{f.section}.md" for f in fragments]
    for path in removed:
        path.unlink()
    return changelog_path, removed


def main(argv: list[str], environ: Mapping[str, str] = os.environ, root: Path = ROOT) -> int:
    changelog = root / environ.get("CHANGELOG", "CHANGELOG.md")
    fragments = root / environ.get("CHANGELOG_FRAGMENTS", "changelog.d")
    command, args = (argv[0], argv[1:]) if argv else ("", [])
    try:
        if command == "cut" and args and len(args) <= CUT_ARGS:
            version, *rest = args
            date = rest[0] if rest else datetime.now(UTC).strftime("%Y-%m-%d")
            _, removed = cut(changelog, fragments, version, date)
            print(f"{changelog.name}: [Unreleased] is now [{version}] - {date}")
            if removed:
                print(f"removed {len(removed)} fragment(s) from {fragments.name}/")
            return 0
        if command == "preview" and not args:
            text = assembled_unreleased(
                changelog.read_text(encoding="utf-8"), read_fragments(fragments)
            )
            print(f"{UNRELEASED}\n\n{text}" if text else f"{UNRELEASED}\n\n(nothing yet)")
            return 0
        if command == "validate" and not args:
            found = read_fragments(fragments)
            print(f"changelog.d: {len(found)} fragment(s) valid")
            return 0
    except (ChangelogError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
