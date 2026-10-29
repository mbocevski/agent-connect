"""The CLI, run in-process next to in-process daemons.

Typer's ``CliRunner`` swaps ``sys.stderr`` for the whole process while a
command runs, and closes its buffer afterwards. The CLI runs in a worker
thread (its daemon answers on the event loop), so the daemons' log lines,
printed to ``sys.stderr`` on the loop, went into that buffer, or into it
just after it was closed: ``ValueError: I/O operation on closed file``
raised inside the daemon (an outbox row failed, a message wasn't sent).

Here ``sys.stdin``, ``sys.stdout`` and ``sys.stderr`` are proxies while any
command runs: a thread running a command reads and writes that command's
buffers (the innermost one, when a command runs another), every other
thread the streams that were there before. Nothing is closed, and commands
in different threads, or one inside another, don't wait for each other.
"""

from __future__ import annotations

import io
import os
import sys
import threading
from collections.abc import Generator, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, TextIO, cast

from agentconnect.cli import app

_STDIN, _STDOUT, _STDERR = range(3)

_lock = threading.Lock()
_running = 0  # commands in progress, in any thread
_saved: tuple[TextIO, TextIO, TextIO] | None = None
# thread -> the buffers of the commands it runs, innermost last
_buffers: dict[int, list[tuple[TextIO, TextIO, TextIO]]] = {}


@dataclass(frozen=True)
class CliResult:
    exit_code: int
    stdout: str
    stderr: str = ""

    @property
    def output(self) -> str:
        """stdout, then stderr."""
        return self.stdout + self.stderr


class _PerThread:
    """A standard stream that is the current command's in its thread and
    ``fallback`` everywhere else."""

    def __init__(self, which: int, fallback: TextIO) -> None:
        self._which, self._fallback = which, fallback

    def _target(self) -> TextIO:
        stack = _buffers.get(threading.get_ident())  # never empty: emptied ones are removed
        return self._fallback if stack is None else stack[-1][self._which]

    def write(self, s: str) -> int:
        return self._target().write(s)

    def flush(self) -> None:
        self._target().flush()

    def readline(self, size: int = -1) -> str:
        return self._target().readline(size)

    def read(self, size: int = -1) -> str:
        return self._target().read(size)

    def __iter__(self) -> Iterator[str]:
        return iter(self._target())

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target(), name)


@contextmanager
def _streams(buffers: tuple[TextIO, TextIO, TextIO]) -> Generator[None]:
    global _running, _saved  # noqa: PLW0603 - one set of process-wide streams
    me = threading.get_ident()
    with _lock:
        if _running == 0:
            _saved = cast("tuple[TextIO, TextIO, TextIO]", (sys.stdin, sys.stdout, sys.stderr))
            sys.stdin, sys.stdout, sys.stderr = (  # type: ignore[assignment]
                _PerThread(i, s) for i, s in enumerate(_saved)
            )
        _running += 1
        _buffers.setdefault(me, []).append(buffers)
    try:
        yield
    finally:
        with _lock:
            stack = _buffers[me]
            stack.pop()
            if not stack:
                del _buffers[me]
            _running -= 1
            if _running == 0 and _saved is not None:
                sys.stdin, sys.stdout, sys.stderr = _saved
                _saved = None


@contextmanager
def _environ(env: Mapping[str, str | None]) -> Generator[None]:
    saved = {k: os.environ.get(k) for k in env}
    try:
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _text(raw: io.BytesIO) -> io.TextIOWrapper:
    return io.TextIOWrapper(raw, encoding="utf-8", write_through=True)


def run_cli(
    args: list[str], input: str | None = None, env: Mapping[str, str | None] | None = None
) -> CliResult:
    """``agentconnect <args>``: its exit code and what it printed. ``env``
    sets (or, with ``None``, unsets) variables for the command; the
    environment is process-wide, so don't run commands with different
    ``env`` at once. An exception other than ``SystemExit`` propagates."""
    out, err = io.BytesIO(), io.BytesIO()
    buffers = (_text(io.BytesIO((input or "").encode())), _text(out), _text(err))
    with _environ(env or {}), _streams(buffers):
        try:
            app(args=args, prog_name="agentconnect")
            code = 0
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    return CliResult(code, out.getvalue().decode(), err.getvalue().decode())
