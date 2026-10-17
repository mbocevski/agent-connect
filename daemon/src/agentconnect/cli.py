"""`agentconnect` command-line interface."""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
from pathlib import Path
from typing import Annotated

import typer

import agentconnect_core
from agentconnect import __version__, log
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.config import Config, ConfigError, load_config

# Pretty tracebacks with locals would print envelopes, plaintext and secrets.
app = typer.Typer(
    no_args_is_help=True,
    help="AgentConnect: E2E-encrypted agent-to-agent groups.",
    pretty_exceptions_show_locals=False,
)
daemon_app = typer.Typer(
    no_args_is_help=True,
    help="Run the daemon (agentconnectd).",
    pretty_exceptions_show_locals=False,
)
app.add_typer(daemon_app, name="daemon")

ConfigOpt = Annotated[Path | None, typer.Option("--config", help="Path of config.toml.")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output.")]


def _config(path: Path | None) -> Config:
    try:
        return load_config(path)
    except ConfigError as e:
        typer.echo(f"config error: {e}", err=True)
        raise typer.Exit(2) from None


@app.command()
def version(as_json: JsonOpt = False) -> None:
    """Show package and protocol versions."""
    info = {
        "version": __version__,
        "protocol": agentconnect_core.PROTOCOL_VERSION,
        "ciphersuite": agentconnect_core.CIPHERSUITE_V0,
    }
    if as_json:
        typer.echo(json.dumps(info))
    else:
        typer.echo(f"agentconnect {info['version']} (protocol v{info['protocol']})")


@app.command()
def status(config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """Show the running daemon's status (reads the local API)."""
    cfg = _config(config)
    try:
        info = ApiClient(cfg).request("GET", "/v0/status")
    except ApiClientError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None
    if as_json:
        typer.echo(json.dumps(info))
        return
    relay = "connected" if info["relay"]["connected"] else "disconnected"
    typer.echo(f"identity     {info['identity']}")
    typer.echo(f"fingerprint  {info['fingerprint']}")
    typer.echo(f"relay        {info['relay']['url']} ({relay})")
    typer.echo(f"groups       {info['groups']} active, {len(info['out_of_sync'])} out of sync")
    typer.echo(f"queues       {info['outbox_queued']} outbound, {info['inbox_pending']} inbound")
    typer.echo(f"approvals    {info['pending_approvals']} pending")


async def _run(cfg: Config, ready: asyncio.Event | None = None) -> None:
    from agentconnect.api import ApiServer  # noqa: PLC0415
    from agentconnect.daemon import Daemon  # noqa: PLC0415

    daemon = Daemon(cfg)
    api = ApiServer(daemon)
    await daemon.start()
    await api.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    if ready is not None:
        ready.set()
    try:
        await stop.wait()
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.remove_signal_handler(sig)
        await api.stop()
        await daemon.stop()


@daemon_app.command("run")
def daemon_run(
    config: ConfigOpt = None,
    tcp_port: Annotated[
        int, typer.Option("--tcp-port", help="Serve the API on 127.0.0.1:<port> instead.")
    ] = 0,
) -> None:
    """Run agentconnectd in the foreground (JSON logs on stderr)."""
    cfg = _config(config)
    if tcp_port:
        cfg = cfg.with_overrides(api_tcp_port=tcp_port)
    log.configure()
    asyncio.run(_run(cfg))


@app.callback()
def main() -> None:
    """AgentConnect CLI."""
