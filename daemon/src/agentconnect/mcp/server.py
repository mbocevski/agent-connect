"""``agentconnect mcp``: the stdio MCP server an agent tool starts.

It hosts the runtime in this process or attaches to the one that holds the
data directory (:mod:`agentconnect.mcp.session`), answers ``tools/list``
and ``tools/call`` with :mod:`agentconnect.mcp.tools`, and stops on stdin
EOF (the agent tool ended the session) or SIGTERM/SIGINT. Stopping ends the
tool calls in flight, gives queued sends the runtime's bounded flush and
releases the lock (:meth:`Runtime.stop`).

stdout carries MCP only: the CLI moves the process's stdout to stderr before
anything runs (:func:`claim_stdio`), so stray output can't corrupt the
channel. Logs go to stderr (or a file), never a message body.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import re
import signal
import tomllib
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import anyio
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from agentconnect import __version__, log
from agentconnect.mcp.backend import ToolError
from agentconnect.mcp.session import Session, current_request
from agentconnect.mcp.tools import BY_NAME, HUMAN_ONLY_NOTE, INSTRUCTIONS, TOOLS, Tool, call
from agentconnect.runtime import (
    Clock,
    Config,
    ConfigError,
    IsolationError,
    Keystore,
    Options,
    SystemClock,
    load_config,
)

LOG = log.get("agentconnect.mcp")

SERVER_NAME = "agentconnect"
DEFAULT_AGENT = "mcp"
MAX_LINE = 4 << 20  # bytes of one JSON-RPC message from the client
SIGNALS = (signal.SIGINT, signal.SIGTERM)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")  # fullmatch: no newline


def default_data_dir(agent: str, environ: Mapping[str, str]) -> Path:
    """``$XDG_DATA_HOME/agentconnect-<agent>`` (``~/.local/share`` without it)."""
    raw = environ.get("XDG_DATA_HOME", "").strip()
    base = Path(raw) if raw else Path(environ.get("HOME", str(Path.home()))) / ".local/share"
    return base / f"agentconnect-{agent}"


def _file_data_dir(config: Path | None) -> Path | None:
    """``daemon.data_dir`` of a config file, if it sets one."""
    if config is None:
        return None
    try:
        data = tomllib.loads(config.expanduser().read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        msg = f"{config}: {e}"
        raise ConfigError(msg) from None
    daemon = data.get("daemon")
    raw = daemon.get("data_dir") if isinstance(daemon, dict) else None
    return Path(raw).expanduser() if isinstance(raw, str) and raw else None


def configure(  # noqa: PLR0913
    agent: str | None,
    *,
    data_dir: Path | None = None,
    relay: str | None = None,
    config: Path | None = None,
    display_name: str | None = None,
    environ: Mapping[str, str] = os.environ,
) -> Config:
    """The MCP host's :class:`Config` (ADR-005, Decision 2).

    The data directory is ``data_dir``, else ``AC_DATA_DIR``, else the
    ``config`` file's ``daemon.data_dir`` when no ``agent`` is given (to
    attach to the daemon that file configures), else
    ``$XDG_DATA_HOME/agentconnect-<agent>`` (``agent`` defaults to ``mcp``).
    An ``AC_DATA_DIR`` that disagrees with an explicit ``agent`` is refused,
    so a variable exported for one agent's CLI can't hand this one another
    agent's identity. Only the TOML file ``config`` is read, never the
    separate daemon's default file; ``AC_*`` variables apply on top."""
    name = DEFAULT_AGENT if agent is None else agent
    if not _NAME.fullmatch(name):
        msg = "--agent: 1 to 64 of A-Z a-z 0-9 . _ -, starting with a letter or digit"
        raise ConfigError(msg)
    env_dir = environ.get("AC_DATA_DIR", "")
    if data_dir is not None:
        where = data_dir.expanduser()
    elif env_dir:
        where = Path(env_dir).expanduser()
        if agent is not None and where != default_data_dir(agent, environ):
            msg = (
                f"AC_DATA_DIR is {env_dir}, not the data directory of --agent {agent} "
                f"({default_data_dir(agent, environ)}); unset it, or pass --data-dir"
            )
            raise ConfigError(msg)
    elif agent is None and (file_dir := _file_data_dir(config)) is not None:
        where = file_dir
    else:
        where = default_data_dir(name, environ)
    overrides: dict[str, Any] = {"data_dir": where, "default_adapter": "mcp"}
    if relay is not None:
        overrides |= {"relay_url": relay, "relay_host": ""}
    if display_name is not None or (agent is not None and config is None):
        overrides["display_name"] = display_name or agent
    cfg = load_config(config, environ, use_file=config is not None, **overrides)
    if cfg.isolation:
        msg = (
            "isolation.enabled is for a separate daemon only: an MCP server runs the "
            "runtime as the agent tool's own user (docs/isolation.md)"
        )
        raise IsolationError(msg)
    return cfg


def _annotations(tool: Tool) -> types.ToolAnnotations:
    return types.ToolAnnotations(
        read_only_hint=tool.read_only,
        destructive_hint=tool.destructive,
        **tool.hints,
    )


def mcp_tools(session: Session) -> list[types.Tool]:
    """The tools this session offers. A host session whose config keeps
    knocks to the human (``knock.agent_may_knock = false``) doesn't list
    ``agentconnect_knock``; the runtime refuses it either way."""
    hidden = set()
    host = session.backend is not None and session.mode == "host"
    if host and not session.config.knock_agent_may_knock:
        hidden.add("agentconnect_knock")
    return [
        types.Tool(
            name=t.name,
            description=t.description,
            input_schema=t.schema,
            annotations=_annotations(t),
        )
        for t in TOOLS
        if t.name not in hidden
    ]


def _result(data: dict[str, Any], *, error: bool = False) -> types.CallToolResult:
    text = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structured_content=data,
        is_error=error,
    )


async def call_tool(
    session: Session, name: str, args: Mapping[str, Any], request_id: object | None = None
) -> types.CallToolResult:
    """One ``tools/call``: the tool's result, or an error result with the
    runtime's code (``human_only`` with a pointer to the CLI). A refused
    call is logged with its code only. ``request_id`` ties a wait's batch
    to this request, to be acknowledged once its result is written."""
    token = current_request.set(request_id)
    finished = False
    try:
        result = _result(await call(session, name, args))
        finished = True
        return result
    except ToolError as e:
        LOG.info("mcp_tool_refused", tool=name if name in BY_NAME else "unknown", code=e.code)
        error: dict[str, Any] = {"code": e.code, "message": str(e)}
        if e.code == "human_only":
            error["hint"] = HUMAN_ONLY_NOTE
        finished = True
        return _result({"error": error}, error=True)
    finally:
        current_request.reset(token)
        if not finished and request_id is not None:
            # Cancelled (or failed) after a take: no result will be written,
            # so the batch goes back at once.
            await session.abandon(request_id)


def build_server(session: Session) -> Server[Any]:
    async def list_tools(
        _ctx: ServerRequestContext[Any], _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=mcp_tools(session))

    async def on_call(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await call_tool(session, params.name, params.arguments or {}, ctx.request_id)

    return Server(
        SERVER_NAME,
        version=__version__,
        instructions=INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=on_call,
    )


def _msg_ids(message: dict[str, Any]) -> list[str]:
    """The ``msg_id`` values a written tool result returned to the client."""
    result = message.get("result")
    content = result.get("structuredContent") if isinstance(result, dict) else None
    messages = content.get("messages") if isinstance(content, dict) else None
    if not isinstance(messages, list):
        return []
    return [str(m.get("msg_id")) for m in messages if isinstance(m, dict)]


class Written:
    """The server's stdout: once a response line is written and flushed,
    the session hears of it, and acknowledges the batch of a wait whose
    result that was (:meth:`Session.result_written`)."""

    def __init__(self, out: anyio.AsyncFile[str], session: Session) -> None:
        self._out, self._session = out, session
        self._lines: list[str] = []

    async def write(self, text: str) -> None:
        await self._out.write(text)
        if self._session.awaiting_write():
            self._lines.append(text)

    async def flush(self) -> None:
        await self._out.flush()
        lines, self._lines = self._lines, []
        for line in lines:
            with contextlib.suppress(ValueError):
                message = json.loads(line)
                if isinstance(message, dict) and "result" in message:
                    self._session.result_written_soon(message.get("id"), _msg_ids(message))


class LineReader:
    """The client's messages, one per line, from a pipe or terminal; closable
    from another task (a signal), which ends the iteration as EOF would."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._reader = asyncio.StreamReader(limit=MAX_LINE)
        self._transport: asyncio.ReadTransport | None = None

    async def open(self) -> None:
        loop = asyncio.get_running_loop()
        pipe = os.fdopen(self._fd, "rb", buffering=0, closefd=False)
        protocol = asyncio.StreamReaderProtocol(self._reader)
        self._transport, _ = await loop.connect_read_pipe(lambda: protocol, pipe)

    def close(self) -> None:
        """End the input now: the server sees EOF and stops."""
        if self._transport is not None:
            self._transport.close()
        self._reader.feed_eof()

    def __aiter__(self) -> AsyncIterator[str]:
        return self._lines()

    async def _lines(self) -> AsyncIterator[str]:
        while True:
            try:
                line = await self._reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                LOG.warning("mcp_line_too_long")
                return
            if not line:
                return
            if line.strip():
                yield line.decode("utf-8", "replace")


@dataclass
class StdioFds:
    """The MCP channel's file descriptors, after :func:`claim_stdio`."""

    stdin: int
    stdout: int


def claim_stdio() -> StdioFds:
    """Keep private copies of fd 0 and 1 for MCP, then point fd 0 at the
    null device and fd 1 at stderr, so nothing else in the process (or a
    child) reads the client's input or writes into the channel."""
    fds = StdioFds(os.dup(0), os.dup(1))
    devnull = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(devnull, 0)
    finally:
        os.close(devnull)
    os.dup2(2, 1)
    return fds


class McpServer:
    """One MCP session over two file descriptors (the CLI passes its
    claimed stdin and stdout; tests pass pipes)."""

    def __init__(  # noqa: PLR0913
        self,
        config: Config,
        *,
        clock: Clock | None = None,
        keystore: Keystore | None = None,
        options: Options | None = None,
        stdin: int = 0,
        stdout: int = 1,
    ) -> None:
        self.session = Session(config, clock or SystemClock(), keystore=keystore, options=options)
        self._stdin, self._stdout = stdin, stdout
        self._reader = LineReader(stdin)

    def stop(self) -> None:
        """Stop as on stdin EOF (signal handlers call this)."""
        self._reader.close()

    async def run(self, ready: asyncio.Event | None = None) -> None:
        """Open the session (host or attach), serve MCP until stdin EOF or
        :meth:`stop`, then close the session: tool calls in flight are
        cancelled first, then the runtime stops and releases the lock.
        Cancellation-safe: a cancelled run still closes the session."""
        await self.session.open()
        try:
            await self._reader.open()
            out = io.TextIOWrapper(
                os.fdopen(self._stdout, "wb", closefd=False), encoding="utf-8", newline="\n"
            )
            stdout = cast("anyio.AsyncFile[str]", Written(anyio.wrap_file(out), self.session))
            server = build_server(self.session)
            # The SDK reads the client's lines by iterating `stdin` only.
            stdin = cast("anyio.AsyncFile[str]", self._reader)
            async with stdio_server(stdin, stdout) as (read, write):
                if ready is not None:
                    ready.set()
                await server.run(read, write, server.create_initialization_options())
            with contextlib.suppress(ValueError):
                out.detach()  # the descriptor is the caller's
        finally:
            self._reader.close()
            await self.session.close()


async def serve(config: Config, fds: StdioFds) -> None:
    """The CLI's entry point: run until stdin EOF or a signal."""
    server = McpServer(config, stdin=fds.stdin, stdout=fds.stdout)
    loop = asyncio.get_running_loop()
    for sig in SIGNALS:
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, server.stop)
    try:
        await server.run()
    finally:
        for sig in SIGNALS:
            with contextlib.suppress(NotImplementedError):
                loop.remove_signal_handler(sig)
