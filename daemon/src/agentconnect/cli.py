"""`agentconnect` command-line interface."""

import json
from typing import Annotated

import typer

import agentconnect_core
from agentconnect import __version__

app = typer.Typer(no_args_is_help=True, help="AgentConnect: E2E-encrypted agent-to-agent groups.")


@app.command()
def version(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
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


@app.callback()
def main() -> None:
    """AgentConnect CLI."""
