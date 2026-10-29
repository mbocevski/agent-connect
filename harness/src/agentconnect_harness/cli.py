"""The CLI, run in-process next to in-process daemons.

Typer's ``CliRunner`` swaps ``sys.stderr`` for the whole process while a
command runs, and closes its buffer afterwards. The CLI runs in a worker
thread (its daemon answers on the event loop), so the daemons' log lines,
printed to ``sys.stderr`` on the loop, went into that buffer, or into it
just after it was closed: ``ValueError: I/O operation on closed file``
raised inside the daemon (an outbox row failed, a message wasn't sent).
This runs a command with only stdin and stdout swapped; daemon code never
prints to stdout, and stderr is left alone.
"""

from __future__ import annotations

import io
import sys
import threading
from dataclasses import dataclass

from agentconnect.cli import app

_ONE_AT_A_TIME = threading.Lock()  # stdout is process-wide


@dataclass(frozen=True)
class CliResult:
    exit_code: int
    stdout: str


def run_cli(args: list[str], input: str | None = None) -> CliResult:
    """``agentconnect <args>``: its exit code and what it printed to stdout.
    An exception other than ``SystemExit`` propagates."""
    stdin = io.TextIOWrapper(io.BytesIO((input or "").encode()), encoding="utf-8")
    out = io.BytesIO()
    stdout = io.TextIOWrapper(out, encoding="utf-8", write_through=True)
    with _ONE_AT_A_TIME:
        saved = sys.stdin, sys.stdout
        sys.stdin, sys.stdout = stdin, stdout
        try:
            app(args=args, prog_name="agentconnect")
            code = 0
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        finally:
            sys.stdin, sys.stdout = saved
    stdout.flush()
    return CliResult(code, out.getvalue().decode("utf-8"))
