#!/usr/bin/env python3
"""Check that every place that carries the release version agrees.

usage: check_version.py [<version>]

<version> is the PEP 440 version (`0.1.0a1`, the tag without its `v`); it
defaults to the version in daemon/pyproject.toml. The script checks the
three published Python packages (their versions, the exact pins between
them and `__version__`), the Rust workspace version (the SemVer spelling,
`0.1.0-alpha.1`), the install command in the README, which the release
verification jobs run verbatim, and the packages' READMEs (their PyPI
pages), whose links must be absolute and point at the release tag. It
prints the version and exits 1 on any mismatch.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# PEP 440 versions the releases use: X.Y.Z with an optional aN, bN or rcN.
PEP440 = re.compile(r"^(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?$")
SEMVER_PRE = {"a": "alpha", "b": "beta", "rc": "rc"}
# The packages' READMEs are their PyPI pages: relative links break there, so
# they link the repository at the release tag.
PYPI_READMES = ("core-py/README.md", "daemon/README.md", "sdk/python/README.md")
BLOB = re.compile(r"https://github\.com/mbocevski/agent-connect/blob/([^/)\s]+)/")
RELATIVE_LINK = re.compile(r"\]\((?!https?://|mailto:|#)([^)]*)\)")


def install_command(version: str) -> str:
    """The documented install command (README "Install", the release notes)."""
    return f"uv tool install agentconnect-cli=={version}"


def semver(version: str) -> str:
    """The Cargo (SemVer) spelling of a PEP 440 release version."""
    m = PEP440.match(version)
    if m is None:
        msg = f"{version!r} is not a release version (X.Y.Z, optionally aN, bN or rcN)"
        raise ValueError(msg)
    base, pre, n = str(m.group(1)), m.group(2), m.group(3)
    return base if pre is None else f"{base}-{SEMVER_PRE[pre]}.{n}"


def _toml(rel: str) -> dict[str, Any]:
    return tomllib.loads((ROOT / rel).read_text(encoding="utf-8"))


def _dunder(rel: str) -> str | None:
    m = re.search(r'^__version__ = "([^"]+)"$', (ROOT / rel).read_text(encoding="utf-8"), re.M)
    return str(m.group(1)) if m else None


def pyproject_version() -> str:
    """The version in daemon/pyproject.toml."""
    return str(_toml("daemon/pyproject.toml")["project"]["version"])


def problems(version: str) -> list[str]:
    found: list[str] = []

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
    readme = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    if install_command(version) not in readme:
        found.append(f"README.md has no line {install_command(version)!r}")
    for rel in PYPI_READMES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        refs = sorted(set(BLOB.findall(text)) - {f"v{version}"})
        relative = RELATIVE_LINK.findall(text)
        if refs or relative:
            found.append(
                f"{rel} (a PyPI page) links {refs + relative}, expected only "
                f"absolute links to blob/v{version}/"
            )
    return found


def main(argv: list[str]) -> int:
    if len(argv) > 2:  # noqa: PLR2004 - one optional argument
        print(__doc__, file=sys.stderr)
        return 2
    version = argv[1] if len(argv) == 2 else pyproject_version()  # noqa: PLR2004
    if found := problems(version):
        for p in found:
            print(f"error: {p}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
