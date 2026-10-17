#!/usr/bin/env python3
"""Fail when a Python dependency's licence isn't allowed by licences-py.toml.

The Python counterpart of `cargo deny check licenses` (ADR-001 section 4).
It reads the JSON report of ``pip-licenses --format=json`` and the policy file.

usage: check_licences.py <report.json> [policy.toml]

Licence strings are SPDX expressions (``MIT OR Apache-2.0``) or classifier
names joined with ``;`` (older packages). ``OR`` needs one allowed
alternative, ``AND`` and ``;`` need all of them. Anything unknown is a
failure, so a new licence has to be a deliberate policy change. A policy
exception that no package uses is also a failure, so the list can't go stale.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

REPORT_ARGS, POLICY_ARGS = 2, 3
DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "licences-py.toml"

# Classifier-style names, as pip-licenses reports them for packages without an
# SPDX expression. The generic ones ("BSD License", "Apache Software License")
# don't name a version; they map to a licence that is on the allowlist, which
# is accepted because every BSD and Apache variant in use is permissive.
ALIASES = {
    "mit license": "MIT",
    "bsd license": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "apache software license": "Apache-2.0",
    "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "zlib/libpng license": "Zlib",
}
# Tags that say nothing about the licence itself.
NOISE = {"dfsg approved"}


class Policy:
    def __init__(self, allow: set[str], exceptions: dict[str, set[str]]) -> None:
        self.allow = allow
        self.exceptions = exceptions

    @classmethod
    def load(cls, path: Path) -> Policy:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return cls(
            set(data.get("allow", [])),
            {normalise_name(e["package"]): set(e["allow"]) for e in data.get("exceptions", [])},
        )


def normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def atoms(expression: str) -> list[list[str]]:
    """Split into alternatives (OR) of required licences (AND / ';')."""
    alternatives: list[list[str]] = []
    for alternative in re.split(r"\s+OR\s+", expression.strip(), flags=re.IGNORECASE):
        required: list[str] = []
        for part in re.split(r"\s+AND\s+|;", alternative, flags=re.IGNORECASE):
            token = part.strip()
            if token.startswith("(") and token.endswith(")") and token.count("(") == 1:
                token = token[1:-1].strip()
            if not token or token.lower() in NOISE:
                continue
            required.append(ALIASES.get(token.lower(), token))
        alternatives.append(required)
    return alternatives


def violations(package: str, expression: str, policy: Policy) -> tuple[list[str], bool]:
    """Return (disallowed licences of the best alternative, used_exception)."""
    permitted = policy.allow | policy.exceptions.get(normalise_name(package), set())
    best: list[str] | None = None
    for required in atoms(expression):
        bad = [lic for lic in required if lic not in permitted]
        if not required:
            bad = [expression]
        if best is None or len(bad) < len(best):
            best = bad
        if not bad:
            used = any(lic not in policy.allow for lic in required)
            return [], used
    return best or [expression], False


def check(report: list[dict[str, str]], policy: Policy) -> list[str]:
    problems = []
    used_exceptions: set[str] = set()
    for entry in report:
        name, licence = entry["Name"], entry["License"]
        bad, used = violations(name, licence, policy)
        if used:
            used_exceptions.add(normalise_name(name))
        if bad:
            problems.append(
                f"{name} {entry.get('Version', '')}: {licence!r} (not allowed: {', '.join(bad)})"
            )
    problems.extend(
        f"policy exception for {pkg!r} is unused; remove it from licences-py.toml"
        for pkg in sorted(set(policy.exceptions) - used_exceptions)
    )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) not in (REPORT_ARGS, POLICY_ARGS):
        print(__doc__, file=sys.stderr)
        return 2
    report = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    policy = Policy.load(Path(argv[2]) if len(argv) == POLICY_ARGS else DEFAULT_POLICY)
    problems = check(report, policy)
    for problem in problems:
        print(f"licence check: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"licence check: {len(report)} Python dependencies, all allowed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
