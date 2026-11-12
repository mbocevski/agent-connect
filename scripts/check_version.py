#!/usr/bin/env python3
"""Check that every place that carries the version agrees.

usage: check_version.py [--release] [--post-release] [<version>]

<version> is the PEP 440 version (`0.1.0a1`, the tag without its `v`); it
defaults to the version in daemon/pyproject.toml. The script checks the
three published Python packages (their versions, the exact pins between
them and `__version__`), the Rust workspace version (the SemVer spelling,
`0.1.0-alpha.1`), the install command in the README, which the release
verification jobs run verbatim, and the packages' READMEs (their PyPI
pages), whose links must be absolute and point at a release tag. It prints
the version and exits 1 on any mismatch.

Between releases `main` carries the next pre-release's development version
(`0.1.0a5.dev0`, Cargo `0.1.0-alpha.5.dev.0`), so a wheel built from it never
shares a version with a published one. The README's install command and the
packages' links then name the last release (which is lower, and what users
install), not the development version. `scripts/set_version.py` moves the
version between the two forms.

--release  refuse a development version: a tag, a release PR and a publish
           carry the final version (release.yml passes it).
--post-release  also fail when the version is a release whose tag
           `v<version>` already exists, which means `main` was not moved on to
           the next development version after that release (the nightly runs
           it).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# PEP 440 versions: X.Y.Z with an optional aN, bN or rcN, and a `.devN` for the
# development version `main` carries between releases.
PEP440 = re.compile(r"^(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?(?:\.dev(\d+))?$")
SEMVER_PRE = {"a": "alpha", "b": "beta", "rc": "rc"}
# Orders a, b and rc below the final release, as PEP 440 does.
PRE_RANK = {"a": 0, "b": 1, "rc": 2}
# The packages' READMEs are their PyPI pages: relative links break there, so
# they link the repository at a release tag.
PYPI_READMES = ("core-py/README.md", "daemon/README.md", "sdk/python/README.md")
BLOB = re.compile(r"https://github\.com/mbocevski/agent-connect/blob/([^/)\s]+)/")
RELATIVE_LINK = re.compile(r"\]\((?!https?://|mailto:|#)([^)]*)\)")
INSTALL = re.compile(r"^uv tool install agentconnect-cli==(\S+)$", re.M)


def install_command(version: str) -> str:
    """The documented install command (README "Install", the release notes)."""
    return f"uv tool install agentconnect-cli=={version}"


def is_dev(version: str) -> bool:
    """Whether ``version`` is a development version (``.devN``)."""
    m = PEP440.match(version)
    return m is not None and m.group(4) is not None


def semver(version: str) -> str:
    """The Cargo (SemVer) spelling of a PEP 440 version.

    A development version keeps the PEP 440 order of its parts and joins them
    with dots: ``0.1.0a5.dev0`` is ``0.1.0-alpha.5.dev.0`` and ``0.2.0.dev0``
    is ``0.2.0-dev.0``. SemVer sorts the first after ``0.1.0-alpha.5``, where
    PEP 440 sorts it before; the workspace crates are unpublished and depend
    on each other by path, so nothing compares them.
    """
    m = PEP440.match(version)
    if m is None:
        msg = f"{version!r} is not a version (X.Y.Z, optionally aN, bN or rcN, and .devN)"
        raise ValueError(msg)
    base, pre, n, dev = str(m.group(1)), m.group(2), m.group(3), m.group(4)
    parts = [] if pre is None else [SEMVER_PRE[pre], n]
    if dev is not None:
        parts += ["dev", dev]
    return base if not parts else f"{base}-{'.'.join(parts)}"


def order(version: str) -> tuple[tuple[int, ...], int, int, int, int]:
    """A sort key that orders versions as PEP 440 does."""
    m = PEP440.match(version)
    if m is None:
        msg = f"{version!r} is not a version"
        raise ValueError(msg)
    base = tuple(int(x) for x in str(m.group(1)).split("."))
    pre, n, dev = m.group(2), m.group(3), m.group(4)
    # A development version of a final release sorts below its pre-releases.
    rank = PRE_RANK[pre] if pre else (-1 if dev is not None else 3)
    return (base, rank, int(n) if n else 0, 0 if dev is not None else 1, int(dev) if dev else 0)


def _toml(rel: str) -> dict[str, Any]:
    return tomllib.loads((ROOT / rel).read_text(encoding="utf-8"))


def _dunder(rel: str) -> str | None:
    m = re.search(r'^__version__ = "([^"]+)"$', (ROOT / rel).read_text(encoding="utf-8"), re.M)
    return str(m.group(1)) if m else None


def pyproject_version() -> str:
    """The version in daemon/pyproject.toml."""
    return str(_toml("daemon/pyproject.toml")["project"]["version"])


def _problems_of_places(version: str, found: list[str]) -> None:
    def expect(what: str, got: object, want: object) -> None:
        if got != want:
            found.append(f"{what}: {got!r}, expected {want!r}")

    packages = {
        "agentconnect-core": "core-py/pyproject.toml",
        "agentconnect-cli": "daemon/pyproject.toml",
        "agentconnect-sdk": "sdk/python/pyproject.toml",
    }
    deps: dict[str, list[str]] = {}
    for name, rel in packages.items():
        project = _toml(rel)["project"]
        expect(f"{rel} name", project["name"], name)
        expect(f"{rel} version", project["version"], version)
        deps[name] = project.get("dependencies", [])
    for pkg, dep in (
        ("agentconnect-cli", "agentconnect-core"),
        ("agentconnect-sdk", "agentconnect-cli"),
    ):
        pins = [d for d in deps[pkg] if re.match(rf"^{dep}\b(?!-)", d)]
        expect(f"{pkg}'s dependency on {dep}", pins, [f"{dep}=={version}"])
    expect("daemon __version__", _dunder("daemon/src/agentconnect/__init__.py"), version)
    expect("sdk __version__", _dunder("sdk/python/src/agentconnect_sdk/__init__.py"), version)
    try:
        expect(
            "Cargo.toml workspace version",
            _toml("Cargo.toml")["workspace"]["package"]["version"],
            semver(version),
        )
    except ValueError as e:
        found.append(str(e))


def _problems_of_docs(version: str, found: list[str]) -> None:
    """The README's install command and the PyPI pages' links.

    They name ``version`` itself for a release and the last release (the one
    the README installs, below ``version``) for a development version.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release = version
    if is_dev(version):
        installs = INSTALL.findall(readme)
        release = installs[0] if installs else ""
        if not PEP440.match(release) or is_dev(release):
            found.append(
                f"README.md installs {release!r}; a development version needs the last "
                "release there (uv tool install agentconnect-cli==<release>)"
            )
            return
        if order(release) >= order(version):
            found.append(f"README.md installs {release}, which is not below {version}")
    if install_command(release) not in readme.splitlines():
        found.append(f"README.md has no line {install_command(release)!r}")
    for rel in PYPI_READMES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        refs = sorted(set(BLOB.findall(text)) - {f"v{release}"})
        relative = RELATIVE_LINK.findall(text)
        if refs or relative:
            found.append(
                f"{rel} (a PyPI page) links {refs + relative}, expected only "
                f"absolute links to blob/v{release}/"
            )


def problems(version: str, *, release: bool = False) -> list[str]:
    """What disagrees with ``version``; with ``release``, a development version
    is a problem in itself."""
    found: list[str] = []
    if release and is_dev(version):
        found.append(
            f"{version} is a development version; a release carries the final version "
            "(scripts/set_version.py <version>, in the release PR)"
        )
    _problems_of_places(version, found)
    _problems_of_docs(version, found)
    return found


def tagged(version: str) -> bool:
    """Whether the repository has the tag ``v<version>``."""
    # Without GIT_*: git exports GIT_DIR and friends to hooks, and they would
    # override `cwd`.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    out = subprocess.run(  # noqa: S603
        ["git", "tag", "--list", f"v{version}"],  # noqa: S607
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(out.stdout.strip())


def main(argv: list[str]) -> int:
    flags = {a for a in argv[1:] if a.startswith("--")}
    args = [a for a in argv[1:] if not a.startswith("--")]
    if flags - {"--release", "--post-release"} or len(args) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    version = args[0] if args else pyproject_version()
    found = problems(version, release="--release" in flags)
    if "--post-release" in flags and not is_dev(version) and tagged(version):
        found.append(
            f"{version} is released (tag v{version} exists) but main still carries it; "
            "move main on to the next development version (scripts/set_version.py --next-dev)"
        )
    if found:
        for p in found:
            print(f"error: {p}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
