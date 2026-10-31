"""The `agentconnect` command's entry point, before anything else is imported.

On macOS `getcwd` fails with a permission error when this user can't search the
path to the working directory, as with `sudo -u agentconnect` from a directory
only the human can enter (docs/isolation.md). rich, imported through httpx, calls
it on import and handles only a deleted directory, so the check has to come first:
keep this module's imports to the standard library. A program that embeds the SDK
owns its working directory, so nothing moves it at import.

After the move a relative path would quietly mean something under `/`, so
:func:`refused_relative` turns those away.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

CANT_SEARCH = "this user can't search the working directory; give an absolute path"

#: Paths in the environment that the CLI reads (the options have a callback).
PATH_VARIABLES = ("AC_CONFIG", "AC_DATA_DIR")

_moved = False


def moved() -> bool:
    """Whether this process left a working directory it could not search."""
    return _moved


def leave_an_unsearchable_cwd() -> None:
    global _moved  # noqa: PLW0603
    try:
        os.getcwd()
    except PermissionError:
        os.chdir("/")
        _moved = True


def refused_relative(path: Path | str | None) -> bool:
    """Whether this path can't be used, because the process moved."""
    return _moved and path is not None and not Path(path).expanduser().is_absolute()


def main() -> None:
    leave_an_unsearchable_cwd()
    for name in PATH_VARIABLES:
        if refused_relative(os.environ.get(name) or None):
            print(f"{name}: {CANT_SEARCH}", file=sys.stderr)
            sys.exit(2)
    from agentconnect.cli import app  # noqa: PLC0415

    app()
