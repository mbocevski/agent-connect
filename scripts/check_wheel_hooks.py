#!/usr/bin/env python3
"""Fail if an agentconnect-core wheel contains a test-only hook.

The core's ``test-hooks`` cargo feature adds bindings that only tests may use
(``Client._add_knock_unchecked_for_testing``). Release and reproducible
builds leave the feature off; this checks the built extension, which names
every binding it exports.

usage: scripts/check_wheel_hooks.py WHEEL [WHEEL ...]
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

#: Bindings that exist only with the ``test-hooks`` feature.
TEST_HOOKS = (b"_add_knock_unchecked_for_testing",)


def hooks_in(wheel: Path) -> list[str]:
    """The test-only hooks the wheel's native extension exports."""
    found: list[str] = []
    with zipfile.ZipFile(wheel) as z:
        for name in z.namelist():
            if "_native" not in name or not name.endswith((".so", ".pyd", ".dylib")):
                continue
            data = z.read(name)
            found += [h.decode() for h in TEST_HOOKS if h in data]
    return found


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    bad = 0
    for arg in argv:
        found = hooks_in(Path(arg))
        if found:
            print(f"{arg}: has test-only hooks: {', '.join(found)}", file=sys.stderr)
            bad += 1
        else:
            print(f"{arg}: no test-only hooks")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
