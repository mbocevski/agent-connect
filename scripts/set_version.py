#!/usr/bin/env python3
"""Set the version in every place that carries it (scripts/check_version.py
checks them).

usage: set_version.py <version>     e.g. 0.1.0a5 (a release) or 0.1.0a6.dev0
       set_version.py --next-dev    the development version after this release

`main` carries the next pre-release's development version between releases
(`0.1.0a5.dev0`), so a wheel built from it never shares a version with a
published one. A release PR sets the final version (`0.1.0a5`); after the tag,
a follow-up PR moves on to the next development version (`0.1.0a6.dev0`).

It edits the three packages' versions and the pins between them, both
`__version__` values and the Rust workspace version (the SemVer spelling).
For a release version it also moves the README's install command, its "latest
pre-release" sentence and the `blob/vX.Y.Z/` links of the packages' READMEs
(their PyPI pages) from the last release to the new one; a development version
leaves those on the last release, which is what users install. It does not
touch the lock files: `just set-version` and `just next-dev` run this and then
update them.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _check_version() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_version", Path(__file__).with_name("check_version.py")
    )
    if spec is None or spec.loader is None:
        msg = "scripts/check_version.py cannot be loaded"
        raise ImportError(msg)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("check_version", module)
    spec.loader.exec_module(module)
    return module


cv = _check_version()


class VersionError(Exception):
    """A version, or a file to edit, is not as this script expects."""


def next_dev(version: str) -> str:
    """The development version that follows the release ``version``.

    ``0.1.0a4`` is followed by ``0.1.0a5.dev0``, ``0.1.0rc1`` by
    ``0.1.0rc2.dev0`` and a final ``0.1.0`` by ``0.1.1.dev0``.
    """
    m = cv.PEP440.match(version)
    if m is None or cv.is_dev(version):
        msg = f"{version!r} is not a release version (X.Y.Z, optionally aN, bN or rcN)"
        raise VersionError(msg)
    base, pre, n = str(m.group(1)), m.group(2), m.group(3)
    if pre is not None:
        return f"{base}{pre}{int(n) + 1}.dev0"
    major, minor, patch = base.split(".")
    return f"{major}.{minor}.{int(patch) + 1}.dev0"


def _sub(path: Path, pattern: str, replacement: str, *, count: int = 1) -> None:
    """Replace ``pattern`` in ``path`` ``count`` times; it must be there."""
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, lambda _: replacement, text, count=count, flags=re.M)
    if n == 0:
        msg = f"{path.name}: nothing matches {pattern!r}"
        raise VersionError(msg)
    path.write_text(new, encoding="utf-8")


def set_version(root: Path, version: str) -> list[str]:
    """Write ``version`` into ``root``'s files; the paths changed, relative to it."""
    if cv.PEP440.match(version) is None:
        msg = f"{version!r} is not a version (X.Y.Z, optionally aN, bN or rcN, and .devN)"
        raise VersionError(msg)
    touched: list[str] = []

    def edit(rel: str, pattern: str, replacement: str) -> None:
        _sub(root / rel, pattern, replacement)
        if rel not in touched:
            touched.append(rel)

    version_line = r'^version = "[^"]*"$'
    edit("core-py/pyproject.toml", version_line, f'version = "{version}"')
    edit("daemon/pyproject.toml", version_line, f'version = "{version}"')
    edit("daemon/pyproject.toml", r'"agentconnect-core==[^"]*"', f'"agentconnect-core=={version}"')
    edit("sdk/python/pyproject.toml", version_line, f'version = "{version}"')
    edit(
        "sdk/python/pyproject.toml", r'"agentconnect-cli==[^"]*"', f'"agentconnect-cli=={version}"'
    )
    dunder = r'^__version__ = "[^"]*"$'
    edit("daemon/src/agentconnect/__init__.py", dunder, f'__version__ = "{version}"')
    edit("sdk/python/src/agentconnect_sdk/__init__.py", dunder, f'__version__ = "{version}"')
    edit("Cargo.toml", version_line, f'version = "{cv.semver(version)}"')
    if not cv.is_dev(version):
        touched += _move_docs(root, version)
    return touched


def _move_docs(root: Path, version: str) -> list[str]:
    """Point the README and the PyPI pages at the release ``version``."""
    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8")
    installs = cv.INSTALL.findall(text)
    if not installs:
        msg = "README.md has no 'uv tool install agentconnect-cli==<version>' line"
        raise VersionError(msg)
    old = installs[0]
    touched: list[str] = []
    if old != version:
        new = text.replace(f"agentconnect-cli=={old}", f"agentconnect-cli=={version}")
        new = new.replace(f"latest pre-release is {old}", f"latest pre-release is {version}")
        readme.write_text(new, encoding="utf-8")
        touched.append("README.md")
    for rel in cv.PYPI_READMES:
        path = root / rel
        page = path.read_text(encoding="utf-8")
        moved = re.sub(r"(/blob/)v[^/)\s]+/", rf"\g<1>v{version}/", page)
        if moved != page:
            path.write_text(moved, encoding="utf-8")
            touched.append(rel)
    return touched


def current_version(root: Path) -> str:
    text = (root / "daemon/pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version = "([^"]*)"$', text, re.M)
    if m is None:
        msg = "daemon/pyproject.toml has no version"
        raise VersionError(msg)
    return str(m.group(1))


def main(argv: list[str], root: Path = ROOT) -> int:
    if len(argv) != 1 or argv[0] in {"-h", "--help"}:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        version = argv[0]
        if version == "--next-dev":
            version = next_dev(current_version(root))
        touched = set_version(root, version)
    except (VersionError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"version {version}: {len(touched)} file(s) changed")
    for rel in touched:
        print(f"  {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
