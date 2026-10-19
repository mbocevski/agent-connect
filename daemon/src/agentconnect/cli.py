"""`agentconnect` command-line interface.

A thin layer over the daemon's local API (``agentconnect.runtime.api``): it parses
arguments, calls the daemon, and renders the answer. Protocol decisions live
in the daemon. Every command takes ``--json`` for a stable machine-readable
shape (docs/cli.md); errors are then ``{"error": {"code", "message"}}`` on
stdout with a non-zero exit code.

``approve`` and ``reject`` (joins, knocks and held messages), ``verify`` (and
the mismatch path inside it), ``remove``, ``group role``, ``group transfer``,
``group policy`` (except turning ``--require-verified`` on) and ``group
create`` with a policy option, ``invite create --replica``, ``safety set``,
``audit``, ``transcript`` and ``listing publish`` use the **human token**.
They are decisions (or records) only a person may make or read (SPEC 6.2,
6.6.4, 9.2, 11): never give an agent the human token or let it run them for
the human.

``identity export`` and ``identity import`` (provisioning a replica, SPEC
9.4) don't use the API at all: they work on a stopped runtime's data
directory (:mod:`agentconnect.provision`), and nothing else offers them.
"""

from __future__ import annotations

import asyncio
import json
import math
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

import agentconnect_core
from agentconnect import __version__, cli_support, log, provision
from agentconnect import daemon as daemon_host
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.cli_support import (
    COMPARE_REMINDER,
    EXIT_CODES_HELP,
    EXIT_FAILED,
    EXIT_INTERCEPTED,
    EXIT_MISMATCH,
    EXIT_REFUSED,
    EXIT_USAGE,
    HUMAN_ONLY_HELP,
    INTERCEPTION_WARNING,
    LOCAL_ONLY_HELP,
    REPLICA_REMINDER,
    SHARE_REMINDER,
    CliError,
    IdArgsCommand,
    Sas,
    clean,
    connect,
    emit_json,
    events_after,
    group_view,
    guard,
    load,
    parse_ttl,
    resolve_group,
    unverified_hint,
)
from agentconnect.config import ConfigError
from agentconnect.isolation import IsolationError
from agentconnect.keystore import KeystoreError

# Pretty tracebacks with locals would print envelopes, plaintext and secrets.
app = typer.Typer(
    no_args_is_help=True,
    help="AgentConnect: E2E-encrypted agent-to-agent groups.\n\n"
    f"{EXIT_CODES_HELP}\n\n"
    "Approving joins and comparing short codes (approve, reject, verify) are "
    "decisions for a person and use the human token. Never give an agent the "
    "human token or let it run those commands for the human.",
    pretty_exceptions_show_locals=False,
)
daemon_app = typer.Typer(
    no_args_is_help=True,
    help="Run the daemon (agentconnectd).",
    pretty_exceptions_show_locals=False,
)
group_app = typer.Typer(
    no_args_is_help=True,
    help="Create groups, and change their policy, roles and owner (`policy` beyond "
    "turning --require-verified on, `role` and `transfer` are HUMAN ONLY: human token).",
    pretty_exceptions_show_locals=False,
)
invite_app = typer.Typer(
    no_args_is_help=True, help="Create and revoke invites.", pretty_exceptions_show_locals=False
)
groups_app = typer.Typer(
    invoke_without_command=True,
    help="List groups, or `show <id>` one.",
    pretty_exceptions_show_locals=False,
)
approvals_app = typer.Typer(
    invoke_without_command=True,
    help="Pending join requests, knocks and held messages. `approve` and `reject` are "
    "HUMAN ONLY (human token): never give an agent the human token or run them for the human.",
    pretty_exceptions_show_locals=False,
)
safety_app = typer.Typer(
    no_args_is_help=True,
    help="A group's safety policy (docs/safety.md). `set` is HUMAN ONLY (human token).",
    pretty_exceptions_show_locals=False,
)
listing_app = typer.Typer(
    no_args_is_help=True,
    help="Your agent's listing in a directory (docs/discovery.md). `publish` is HUMAN ONLY "
    "(human token): an agent can't put itself into a public directory. `withdraw` and "
    "`status` work with the agent token.",
    pretty_exceptions_show_locals=False,
)
identity_app = typer.Typer(
    no_args_is_help=True,
    help="Provision a replica: export this agent's identity key, and import it into a new "
    "data directory with a fresh instance. HUMAN ONLY, and local: no API route, SDK call "
    "or MCP tool does this, and both refuse to run while a runtime uses the data directory.",
    pretty_exceptions_show_locals=False,
)
app.add_typer(daemon_app, name="daemon")
app.add_typer(identity_app, name="identity")
app.add_typer(listing_app, name="listing")
app.add_typer(group_app, name="group")
app.add_typer(invite_app, name="invite")
app.add_typer(groups_app, name="groups")
app.add_typer(approvals_app, name="approvals")
app.add_typer(safety_app, name="safety")

ConfigOpt = Annotated[Path | None, typer.Option("--config", help="Path of config.toml.")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output.")]
YesOpt = Annotated[bool, typer.Option("--yes", "-y", help="Don't ask for confirmation.")]

WAIT_POLL_SECS = 1.0
FOLLOW_POLL_SECS = 1.0
MAX_NAME = 80  # SPEC 4.2: group names are 1 to 80 characters


def _say(text: str = "", *, as_json: bool = False) -> None:
    """Human-readable output; in ``--json`` mode it goes to stderr."""
    typer.echo(text, err=as_json)


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


def _require_yes(as_json: bool, yes: bool, what: str) -> None:
    if as_json and not yes:
        msg = f"--json can't prompt; pass --yes to {what}"
        raise CliError("needs_yes", msg, EXIT_USAGE)


def _confirm(question: str, *, yes: bool, as_json: bool) -> bool:
    return yes or typer.confirm(question, default=False, err=as_json)


# -- basics ---------------------------------------------------------------------


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
    with guard(as_json):
        info = connect(config).request("GET", "/v0/status")
        if as_json:
            emit_json(info)
            return
        relay = "connected" if info["relay"]["connected"] else "disconnected"
        typer.echo(f"identity     {info['identity']}")
        typer.echo(f"fingerprint  {info['fingerprint']}")
        typer.echo(f"relay        {info['relay']['url']} ({relay})")
        typer.echo(f"groups       {info['groups']} active, {len(info['out_of_sync'])} out of sync")
        typer.echo(
            f"queues       {info['outbox_queued']} outbound, {info['inbox_pending']} inbound"
        )
        typer.echo(f"approvals    {info['pending_approvals']} pending")
        typer.echo(f"held         {info.get('held_messages', 0)} message(s) waiting for approval")


@daemon_app.command("run")
def daemon_run(
    config: ConfigOpt = None,
    tcp_port: Annotated[
        int, typer.Option("--tcp-port", help="Serve the API on 127.0.0.1:<port> instead.")
    ] = 0,
) -> None:
    """Run agentconnectd in the foreground (JSON logs on stderr).

    Needs relay.url (AC_RELAY_URL): there is no built-in relay. Starts the
    adapter named by daemon.default_adapter (webhook or sse), and
    the A2A adapter when a2a.local_agent_url or a2a.facade_port is set. On
    SIGINT or SIGTERM, queued sends get up to 3 seconds to go out while the
    relay is connected; the rest stay in the encrypted outbox for the next
    start.
    """
    with guard(False):
        cfg = load(config, need_relay=True)
    if tcp_port:
        cfg = cfg.with_overrides(api_tcp_port=tcp_port)
    log.configure()
    with guard(False):
        try:
            asyncio.run(daemon_host.serve(cfg))
        except IsolationError as e:
            raise CliError("isolation", f"refusing to start: {e}", EXIT_USAGE) from None


@app.command("mcp")
def mcp_run(  # noqa: PLR0913, PLR0917
    agent: Annotated[
        str | None,
        typer.Option(
            "--agent",
            help="The agent's name: its data directory is $XDG_DATA_HOME/agentconnect-<name> "
            "(default: mcp). One name is one identity.",
        ),
    ] = None,
    data_dir: Annotated[
        Path | None, typer.Option("--data-dir", help="Another data directory instead.")
    ] = None,
    relay: Annotated[
        str | None, typer.Option("--relay", help="The relay's wss:// URL (AC_RELAY_URL).")
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="A config.toml for this agent (none is read by default)."),
    ] = None,
    display_name: Annotated[
        str | None, typer.Option("--display-name", help="What peers see (default: the name).")
    ] = None,
    log_file: Annotated[
        Path | None, typer.Option("--log-file", help="Append the logs here instead of stderr.")
    ] = None,
) -> None:
    """Run the MCP server on stdin and stdout (an agent tool starts it).

    It runs the runtime itself when the data directory is free, or attaches to
    the daemon or MCP session that runs on it. Its tools are agent-scope only;
    approvals, verify and safety stay CLI commands for the human
    (docs/adapters/mcp.md). stdout carries MCP only; logs go to stderr or
    --log-file. Stops on stdin EOF, SIGTERM or SIGINT.
    """
    from agentconnect import mcp as mcp_host  # noqa: PLC0415 - heavy, and this command only

    with guard(False):
        try:
            cfg = mcp_host.configure(
                agent, data_dir=data_dir, relay=relay, config=config, display_name=display_name
            )
        except (ConfigError, IsolationError) as e:
            raise CliError("bad_config", f"refusing to start: {e}", EXIT_USAGE) from None
    if log_file is not None:
        sys.stderr = log_file.expanduser().open("a", encoding="utf-8", buffering=1)
    log.configure()
    fds = mcp_host.claim_stdio()
    with guard(False):
        try:
            asyncio.run(mcp_host.serve(cfg, fds))
        except mcp_host.ToolError as e:
            raise CliError(e.code, f"refusing to start: {e}", EXIT_USAGE) from None


# -- identity: provisioning a replica ------------------------------------------------

# Refusals about where the command runs (exit 2); the rest are about the file (exit 1).
_PROVISION_USAGE = {"runtime_running", "exists", "not_empty", "no_identity", "data_dir_access"}
_NEXT_STEPS = (
    "Next: start the runtime on this data directory. Then, on a running instance of "
    "this identity, create an invite pinned to the instance above with `agentconnect "
    "invite create --group <group> --replica --instance <instance>` (human token) and "
    "accept it here, once per group."
)


def _provision[T](call: Callable[[], T]) -> T:
    try:
        return call()
    except provision.ProvisionError as e:
        code = EXIT_USAGE if e.code in _PROVISION_USAGE else EXIT_FAILED
        raise CliError(e.code, e.message, code) from None
    except KeystoreError as e:
        raise CliError("keystore", f"keystore: {e}", EXIT_FAILED) from None
    except OSError as e:
        where = f"{e.filename}: " if e.filename else ""
        raise CliError("os_error", f"{where}{e.strerror or e}", EXIT_FAILED) from None


@identity_app.command(
    "export",
    help="Export this agent's identity key for a replica, wrapped under a one-time code.\n\n"
    "Stop the runtime on the data directory first. The file is encrypted under a fresh "
    "random code that is printed once and stored nowhere: carry it to the new host apart "
    "from the file. Whoever has both holds the identity, and every host you import it on "
    f"can speak as this agent in every group. {LOCAL_ONLY_HELP}",
)
def identity_export(
    out: Annotated[
        Path,
        typer.Option("--out", help="The file to write: created 0600, never over an existing one."),
    ],
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        cfg = load(config)
        made = _provision(lambda: provision.export_identity(cfg, out.expanduser()))
        if as_json:
            emit_json(made)
            return
        typer.echo(f"Wrote {made['file']} for {made['identity']}")
        typer.echo(f"fingerprint  {made['fingerprint']}")
        typer.echo("")
        typer.echo("Export code (shown once, stored nowhere):")
        typer.echo("")
        typer.echo(f"    {made['code']}")
        typer.echo("")
        typer.echo(made["warning"])
        typer.echo(
            "On the new host, with a new data directory: agentconnect identity import <file>"
        )


@identity_app.command(
    "import",
    help="Import an exported identity into a new, empty data directory, as a replica.\n\n"
    "It creates a fresh instance (its own key and instance id) and refuses a data directory "
    "that already holds an identity, an instance or a database: a copied data directory is "
    f"not a replica. Stop any runtime on it first. {LOCAL_ONLY_HELP}",
)
def identity_import(
    file: Annotated[Path, typer.Argument(help="The file `identity export` wrote.")],
    code: Annotated[
        str | None,
        typer.Option(
            "--code",
            help="The export code. Without it you are asked for it (with --json it is "
            "read from one line on stdin), which keeps it out of your shell history and "
            "the process list.",
        ),
    ] = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        cfg = load(config)
        data = _provision(lambda: provision.read_export(file.expanduser()))
        identity = _provision(lambda: provision.export_identity_id(data))
        if code is None and as_json:
            # One line on stdin, so a script needn't put the code in argv.
            code = str(sys.stdin.readline()).strip()
            if not code:
                msg = "--json reads the code from stdin (one line), or pass --code"
                raise CliError("needs_code", msg, EXIT_USAGE)
        if code is None:
            typer.echo(f"Importing {identity} into {cfg.data_dir}.")
            code = str(typer.prompt("Export code", hide_input=True))
        given = code
        made = _provision(lambda: provision.import_identity(cfg, data, given))
        if as_json:
            emit_json({**made, "next": _NEXT_STEPS})
            return
        typer.echo(f"Imported {made['identity']} into {made['data_dir']}")
        typer.echo(f"fingerprint  {made['fingerprint']}")
        typer.echo(f"instance     {made['instance_id']} (new)")
        typer.echo("")
        typer.echo(_NEXT_STEPS)
        typer.echo("Delete the export file now that it is imported.")


# -- groups and invites ------------------------------------------------------------


def _new_group(
    api: ApiClient, purpose: str, name: str | None, policy: dict[str, Any] | None = None
) -> str:
    name = (name or purpose or "AgentConnect chat")[:MAX_NAME]
    body: dict[str, Any] = {"name": name, "purpose": purpose}
    if policy is not None and len(policy) > 0:
        body["policy"] = policy
    return str(api.request("POST", "/v0/groups", body)["group_id"])


InviteOpt = Annotated[
    str | None,
    typer.Option("--invite", help="Who may add members: owner, admins or members."),
]
RemoveOpt = Annotated[
    str | None, typer.Option("--remove", help="Who may remove members: owner or admins.")
]
MaxMembersOpt = Annotated[
    int | None,
    typer.Option("--max-members", min=1, max=50, help="Most instances the group may have."),
]
FloorOpt = Annotated[
    str | None,
    typer.Option(
        "--floor",
        help="Who is triggered: free, mention or moderated (SPEC 9.3). Pins the floor: it "
        "doesn't switch to mention when a third member joins.",
    ),
]
ModeratorOpt = Annotated[
    str | None,
    typer.Option("--moderator", help="The floor moderator's identity, or `none`."),
]


def _policy_fields(  # noqa: PLR0913, PLR0917
    invite: str | None,
    remove: str | None,
    max_members: int | None,
    floor: str | None,
    moderator: str | None,
    max_agent_turns: int | None = None,
) -> dict[str, Any]:
    """The given policy options as the fields of a policy change."""
    fields: dict[str, Any] = {}
    for key, value in (
        ("invite", invite),
        ("remove", remove),
        ("max_members", max_members),
        ("floor", floor),
        ("max_agent_turns", max_agent_turns),
    ):
        if value is not None:
            fields[key] = value
    if moderator is not None:
        fields["floor_moderator"] = None if moderator.lower() == "none" else moderator
    return fields


@group_app.command("create")
def group_create(  # noqa: PLR0913, PLR0917
    purpose: Annotated[
        str, typer.Option("--purpose", help="What the group is for (shown to joiners).")
    ],
    name: Annotated[
        str | None, typer.Option("--name", help="Group name (default: the purpose).")
    ] = None,
    invite: InviteOpt = None,
    remove: RemoveOpt = None,
    max_members: MaxMembersOpt = None,
    floor: FloorOpt = None,
    moderator: ModeratorOpt = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Create a group you own. Any policy option (--invite, --remove,
    --max-members, --floor, --moderator) uses the HUMAN token: a non-default
    policy is the human's decision."""
    with guard(as_json):
        policy = _policy_fields(invite, remove, max_members, floor, moderator)
        api = connect(config, human=bool(policy))
        gid = _new_group(api, purpose, name, policy)
        shown = (name or purpose or "AgentConnect chat")[:MAX_NAME]
        if as_json:
            emit_json({"group_id": gid, "name": shown, "purpose": purpose})
        else:
            typer.echo(f"Created group {clean(shown)} ({gid}).")
            typer.echo("Invite someone with: agentconnect invite create --group " + gid)


def _queued(status: str, event: str) -> str:
    if status == "unchanged":
        return "Nothing to change: the group's policy already says so."
    return (
        f"Change queued. `agentconnect events` reports `{event}` once it lands, or "
        "`commit_failed` if the group changed meanwhile."
    )


@group_app.command(
    "policy",
    cls=IdArgsCommand,
    help="Change a group's policy (a commit; give only what changes): who may invite and "
    "remove, the size limit, the floor and the loop guard. Turning --require-verified on "
    f"alone uses the agent token instead, since it only tightens the gate. {HUMAN_ONLY_HELP}",
)
def group_policy(  # noqa: PLR0913, PLR0917
    group: str,
    invite: InviteOpt = None,
    remove: RemoveOpt = None,
    max_members: MaxMembersOpt = None,
    floor: FloorOpt = None,
    moderator: ModeratorOpt = None,
    max_agent_turns: Annotated[
        int | None,
        typer.Option(
            "--max-agent-turns", min=0, max=100, help="Agent replies before the loop guard."
        ),
    ] = None,
    require_verified: Annotated[
        bool | None,
        typer.Option(
            "--require-verified/--no-require-verified",
            help="Hold deliveries until every member is verified (SPEC 10.4).",
        ),
    ] = None,
    floor_pinned: Annotated[
        bool | None,
        typer.Option(
            "--floor-pinned/--no-floor-pinned",
            help="Keep the floor when a third member joins (default with --floor).",
        ),
    ] = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        fields = _policy_fields(invite, remove, max_members, floor, moderator, max_agent_turns)
        if require_verified is not None:
            fields["require_verified"] = require_verified
        if floor_pinned is not None:
            fields["floor_pinned"] = floor_pinned
        if not fields:
            raise CliError("bad_args", "nothing to change: give at least one option", EXIT_USAGE)
        api = connect(config, human=fields != {"require_verified": True})
        gid = resolve_group(api, group)
        status = api.request("POST", f"/v0/groups/{gid}/policy", fields)["status"]
        if as_json:
            emit_json({"group_id": gid, "status": status, "changes": fields})
        else:
            typer.echo(_queued(status, "policy_changed"))


@group_app.command(
    "role",
    cls=IdArgsCommand,
    help="Make a member an admin or a plain member (owner only; a commit). The owner's "
    f"role changes with `group transfer`. {HUMAN_ONLY_HELP}",
)
def group_role(
    group: str,
    identity: str,
    role: Annotated[str, typer.Argument(help="admin or member.")],
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        if role not in ("admin", "member"):
            raise CliError("bad_args", "the role is admin or member", EXIT_USAGE)
        api = connect(config, human=True)
        gid = resolve_group(api, group)
        path = f"/v0/groups/{gid}/members/{identity}/role"
        status = api.request("POST", path, {"role": role})["status"]
        if as_json:
            emit_json({"group_id": gid, "identity": identity, "role": role, "status": status})
        else:
            typer.echo(_queued(status, "role_changed"))


@group_app.command(
    "transfer",
    cls=IdArgsCommand,
    help="Hand ownership of a group over to another member (owner only; a commit). You "
    "stay an admin unless --no-keep-admin. The owner's last instance must do this before "
    f"it can leave. {HUMAN_ONLY_HELP}",
)
def group_transfer(  # noqa: PLR0913, PLR0917
    group: str,
    identity: str,
    keep_admin: Annotated[
        bool, typer.Option("--keep-admin/--no-keep-admin", help="Stay an admin afterwards.")
    ] = True,
    yes: YesOpt = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        _require_yes(as_json, yes, "transfer ownership")
        api = connect(config, human=True)
        gid = resolve_group(api, group)
        info = api.request("GET", f"/v0/groups/{gid}")
        member = next((m for m in info["members"] if m["identity"] == identity), None)
        if member is None:
            raise CliError("not_found", f"{identity!r} is not a member", EXIT_FAILED)
        name = clean(member["display_name"] or identity)
        _say(f"Hand {clean(info['name'])} over to {name} ({identity})?", as_json=as_json)
        _say(
            "The new owner decides roles and the policy from then on; only it can hand the "
            "group back.",
            as_json=as_json,
        )
        if not _confirm("Transfer ownership?", yes=yes, as_json=as_json):
            raise CliError("declined", "ownership not transferred", EXIT_REFUSED)
        body = {"identity": identity, "keep_admin": keep_admin}
        status = api.request("POST", f"/v0/groups/{gid}/owner", body)["status"]
        if as_json:
            emit_json(
                {"group_id": gid, "identity": identity, "keep_admin": keep_admin, "status": status}
            )
        else:
            typer.echo(_queued(status, "role_changed"))


@group_app.command(
    "floor",
    cls=IdArgsCommand,
    help="Give the floor of a moderated group to a member, or take it back with --release "
    "(SPEC 9.3): the holder's instances and the moderator's are the ones triggered. Only "
    "the effective moderator or the owner may. Uses the agent token: an orchestrating "
    "agent may do this; the floor mode and the moderator are set with `group policy`.",
)
def group_floor(
    group: str,
    identity: Annotated[str | None, typer.Argument(help="The member to give the floor to.")] = None,
    release: Annotated[
        bool, typer.Option("--release", help="Nobody holds the floor afterwards.")
    ] = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        if (identity is None) != release:
            raise CliError("bad_args", "give a member's identity or --release", EXIT_USAGE)
        api = connect(config)
        gid = resolve_group(api, group)
        out = api.request("POST", f"/v0/groups/{gid}/floor", {"holder": identity})
        if as_json:
            emit_json({"group_id": gid, **out})
        elif out["holder"] is None:
            typer.echo("Floor released: only the moderator is triggered now.")
        else:
            typer.echo(f"Floor granted to {out['holder']}.")


@invite_app.command("create")
def invite_create(  # noqa: PLR0913, PLR0917
    group: Annotated[
        str | None, typer.Option("--group", help="Group id (default: a new group).")
    ] = None,
    purpose: Annotated[
        str | None, typer.Option("--purpose", help="Purpose for a new group.")
    ] = None,
    ttl: Annotated[str, typer.Option("--ttl", help="Lifetime: 30m, 24h, 7d (max 7d).")] = "24h",
    max_uses: Annotated[int, typer.Option("--max-uses", min=1, max=1000)] = 1,
    require_verified: Annotated[
        bool,
        typer.Option(
            "--require-verified", help="Hold deliveries until every member is verified (SPEC 10.4)."
        ),
    ] = False,
    instance: Annotated[
        str | None,
        typer.Option(
            "--instance",
            help="With --replica: the instance id `identity import` printed (16 hex "
            "characters). Only that instance can join, and only a pinned replica invite is "
            "approved automatically.",
        ),
    ] = None,
    replica: Annotated[
        bool,
        typer.Option(
            "--replica",
            help="An invite for another instance of your own identity (a replica, after "
            "`identity import`): only that identity may join through it, whatever the "
            "group's invite policy says. Needs --group. HUMAN ONLY: uses the human token.",
        ),
    ] = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Create an invite link. Without --group, a new group is created (1:1)."""
    with guard(as_json):
        secs = parse_ttl(ttl)
        if group is not None and purpose is not None:
            raise CliError(
                "bad_args", "--purpose only applies when creating a new group", EXIT_USAGE
            )
        if replica and group is None:
            msg = "--replica needs --group: the group to add the replica to"
            raise CliError("bad_args", msg, EXIT_USAGE)
        if instance is not None and not replica:
            raise CliError(
                "bad_args", "--instance pins a replica invite: add --replica", EXIT_USAGE
            )
        api = connect(config, human=replica)
        gid = (
            resolve_group(api, group) if group is not None else _new_group(api, purpose or "", None)
        )
        if require_verified:
            api.request("POST", f"/v0/groups/{gid}/policy", {"require_verified": True})
        body: dict[str, Any] = {"ttl_secs": secs, "max_uses": max_uses}
        if replica:
            body["replica"] = True
        if instance is not None:
            body["instance"] = instance
        made = api.request("POST", f"/v0/groups/{gid}/invites", body)
        reminder = REPLICA_REMINDER if replica else SHARE_REMINDER
        if as_json:
            emit_json(
                {
                    "url": made["url"],
                    "invite_id": made["invite_id"],
                    "group_id": gid,
                    "expires_at": made["expires_at"],
                    "max_uses": max_uses,
                    "require_verified": require_verified,
                    "replica": replica,
                    "instance": instance,
                    "reminder": reminder,
                }
            )
            return
        uses = f"{max_uses} use" + ("" if max_uses == 1 else "s")
        kind = "Replica invite" if replica else "Invite"
        if instance is not None:
            kind += f" for instance {instance}"
        typer.echo(f"{kind} for group {gid}, {uses}, expires {_when(made['expires_at'])}:")
        typer.echo("")
        typer.echo(made["url"])
        typer.echo("")
        typer.echo(reminder)


@invite_app.command("revoke", cls=IdArgsCommand)
def invite_revoke(invite_id: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """Revoke an invite you created; its link stops working."""
    with guard(as_json):
        connect(config).request("DELETE", f"/v0/invites/{invite_id}")
        if as_json:
            emit_json({"revoked": invite_id})
        else:
            typer.echo(f"Revoked invite {invite_id}.")


def _wait_for_join(api: ApiClient, invite_id: str, wait: int) -> dict[str, Any] | None:
    """Poll the event log for this join's outcome; ``None`` if it timed out."""
    after = 0
    for attempt in range(max(1, math.ceil(wait / WAIT_POLL_SECS)) if wait else 1):
        if attempt:
            cli_support.pause(WAIT_POLL_SECS)
        for ev in events_after(api, after):
            after = int(ev["seq"])
            if ev["data"].get("invite_id") == invite_id and ev["type"] in ("joined", "join_failed"):
                return ev
        if not wait:
            return None
    return None


@app.command()
def accept(  # noqa: PLR0913, PLR0917
    url: Annotated[str, typer.Argument(help="The invite link (quote it: it contains '#').")],
    yes: YesOpt = False,
    name: Annotated[str | None, typer.Option("--name", help="Display name to join as.")] = None,
    wait: Annotated[
        int, typer.Option("--wait", help="Seconds to wait for the inviter's approval (0: don't).")
    ] = 120,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Join a group from an invite link (never opens a browser).

    Shows who invited you and asks first (unless --yes). The invite secret is
    handled by the daemon; when an LLM agent runs this, the secret enters its
    context, which is acceptable only because invites are use-limited (SPEC 4.4).
    """
    with guard(as_json):
        _require_yes(as_json, yes, "join")
        api = connect(config)
        info = api.request("POST", "/v0/invites/inspect", {"url": url})
        meta = info["meta"]
        if info.get("warning") or meta.get("status") in ("exhausted", "revoked"):
            raise CliError("invite_not_open", INTERCEPTION_WARNING, EXIT_INTERCEPTED)
        if meta.get("status") != "open":
            msg = "this invite has expired; ask the sender for a new one"
            raise CliError("invite_expired", msg, EXIT_FAILED)
        count = meta.get("member_count")
        _say(f"Group      {clean(meta['group_name'])}", as_json=as_json)
        _say(f"Purpose    {clean(meta['purpose'])}", as_json=as_json)
        _say(f"Invited by {clean(meta['inviter_name'])} (as claimed by the link)", as_json=as_json)
        if count is not None:
            _say(f"Members    {count} (as claimed by the link)", as_json=as_json)
        if not _confirm("Join this group?", yes=yes, as_json=as_json):
            raise CliError("declined", "not joining; nothing was sent", EXIT_REFUSED)
        joined = api.request("POST", "/v0/invites/accept", {"url": url, "display_name": name})
        invite_id = joined["invite_id"]
        _say("Join request sent. Waiting for the inviter to approve...", as_json=as_json)
        ev = _wait_for_join(api, invite_id, wait)
        base = {
            "invite_id": invite_id,
            "name": meta["group_name"],
            "purpose": meta["purpose"],
            "inviter_name": meta["inviter_name"],
        }
        if ev is None:
            _finish_pending(base, as_json)
            return
        if ev["type"] == "join_failed":
            msg = f"the join failed: {clean(ev['data'].get('reason', 'unknown'))}"
            raise CliError("join_failed", msg, EXIT_FAILED)
        view = group_view(api, ev["group_id"])
        if as_json:
            emit_json({**base, **view, "status": "joined"})
            return
        typer.echo(f"Joined {clean(view['name'])} ({view['group_id']}). The short code now is:")
        sas = view["sas"]
        typer.echo(f"  {' '.join(sas['emoji'].split())}")
        typer.echo(f"  ({', '.join(sas['emoji_names'])})")
        typer.echo(f"  {sas['decimal']}")
        typer.echo(COMPARE_REMINDER.replace("<group>", view["group_id"]))


def _finish_pending(base: dict[str, Any], as_json: bool) -> None:
    if as_json:
        emit_json({"status": "pending", **base, "group_id": None})
    else:
        typer.echo("Not approved yet. The inviter must approve; you can leave this and check")
        typer.echo("later with `agentconnect groups`.")


# -- groups ----------------------------------------------------------------------------


@groups_app.callback()
def groups_default(ctx: typer.Context, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """List your groups (`show <id>` for one)."""
    if ctx.invoked_subcommand is None:
        groups_list(config, as_json)


@groups_app.command("list")
def groups_list(config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """List groups."""
    with guard(as_json):
        groups = connect(config).request("GET", "/v0/groups")["groups"]
        if as_json:
            emit_json({"groups": groups})
            return
        if not groups:
            typer.echo("No groups yet. Create one with `agentconnect invite create`.")
        for g in groups:
            flag = "  OUT OF SYNC" if g["out_of_sync"] else ""
            typer.echo(
                f"{g['group_id']}  {clean(g['name'])}  [{g['status']}, {g['members']} members, "
                f"epoch {g['epoch']}]{flag}"
            )


@groups_app.command("show", cls=IdArgsCommand)
def groups_show(group: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """Show a group: members, roles, verified flags, short code, pending approvals."""
    with guard(as_json):
        api = connect(config)
        view = group_view(api, resolve_group(api, group))
        if as_json:
            emit_json(view)
            return
        typer.echo(f"{clean(view['name'])}  ({view['group_id']})")
        typer.echo(f"Purpose   {clean(view['purpose'])}")
        sync = f"OUT OF SYNC ({view['out_of_sync_reason']})" if view["out_of_sync"] else "in sync"
        typer.echo(f"Status    {view['status']}, epoch {view['epoch']}, {sync}")
        typer.echo(
            f"Verified  {view['verified_summary']}"
            + ("  (required)" if view["require_verified"] else "")
        )
        if view["sas"]:
            typer.echo("Short code (compare it with the others over a call or in person):")
            typer.echo(f"  {view['sas']['emoji']}")
            typer.echo(f"  ({', '.join(view['sas']['emoji_names'])})")
            typer.echo(f"  {view['sas']['decimal']}")
        p, floor = view["policy_summary"], view["floor"]
        typer.echo(
            f"Policy    invite {p['invite']}, remove {p['remove']}, "
            f"at most {p['max_members']} instances, {p['max_agent_turns']} agent turns"
        )
        moderator = floor["moderator"] or "none"
        pinned = ", pinned" if floor["pinned"] else ""
        typer.echo(f"Floor     {floor['mode']}{pinned}, moderator {moderator}")
        if floor["mode"] == "moderated":
            typer.echo(
                f"  triggered: the moderator {floor['effective_moderator'] or 'none'} "
                f"and the holder {floor['holder'] or 'none'}"
            )
        if view["leaving"] is not None:
            typer.echo(f"Leaving   since {_when(view['leaving']['since'])}")
            if view["leaving"]["blocked"]:
                typer.echo("  This is the owner's last instance: hand ownership over to another")
                typer.echo("  member first (`agentconnect group transfer`), and the leave goes on.")
        typer.echo(f"Pending approvals  {view['pending_approvals']}")
        for leave in view["pending_leaves"]:
            typer.echo(f"Leaving   {leave['identity']} instance {leave['instance_id']}")
        typer.echo("Members (names are claimed by each member, not verified):")
        for m in view["members"]:
            mark = "verified" if m["verified"] else ("you" if m["self"] else "not verified")
            typer.echo(
                f"  {clean(m['display_name'] or '?')}  {m['role']}  "
                f"{len(m['instances'])} instance(s)  {mark}  {m['fingerprint']}"
            )
            for i in m["instances"]:
                notes = "  (this one)" if i["self"] else ""
                if i["new_since_verified"]:
                    notes += "  NEW since you verified this member: check it is theirs"
                elif i["new_since_verified"] is None:
                    notes += "  new since you verified? unknown: verify again"
                typer.echo(
                    f"    instance {i['instance_id']}  leaf {i['leaf_index']}  "
                    f"since epoch {i['joined_epoch']}{notes}"
                )


# -- approvals (human) -----------------------------------------------------------------------


def _approval_view(api: ApiClient, a: dict[str, Any]) -> dict[str, Any]:
    if a.get("kind") == "knock":
        # A knock has no group yet: approving creates one (SPEC 6.6.4).
        return {
            "kind": "knock",
            "request_id": a["request_id"],
            "group_id": None,
            "group_name": None,
            "display_name": a["display_name"],
            "display_name_verified": a["display_name_verified"],
            "identity": a["identity"],
            "fingerprint": a["fingerprint"],
            "received_at": a["received_at"],
            "group_sas": None,
            "listing": a["listing"],
            "note": a["note"],
            "note_verified": a["note_verified"],
            "lapses_at": a["lapses_at"],
            "known": a["known"],
        }
    info = api.request("GET", f"/v0/groups/{a['group_id']}")
    return {
        "kind": "join",
        "request_id": a["request_id"],
        "group_id": a["group_id"],
        "group_name": info["name"],
        "display_name": a["display_name"],
        "display_name_verified": a["display_name_verified"],
        "identity": a["identity"],
        "fingerprint": a["fingerprint"],
        "received_at": a["received_at"],
        "group_sas": Sas.of(info["sas"]).as_json() if "sas" in info else None,
        "identity_requests": int(a.get("identity_requests", 1)),
        "instance_id": a.get("instance_id"),
        "mailbox_id": a.get("mailbox_id", ""),
    }


def _history(known: dict[str, Any]) -> str:
    groups, verified = int(known["groups"]), [clean(n) for n in known["verified_in"]]
    if not groups:
        return "new to you"
    text = f"member of {groups} group(s) with you"
    if verified:
        text += ", verified in " + ", ".join(f'"{n}"' for n in verified)
    return text


def _print_knock_approval(v: dict[str, Any], *, as_json: bool = False) -> None:
    listing = v["listing"]
    _say(
        f"Knock {v['request_id']} on {clean(listing['name'])} ({clean(listing['directory'])})",
        as_json=as_json,
    )
    _say(
        f'  who          "{clean(v["display_name"])}" (a claimed name, not verified)',
        as_json=as_json,
    )
    if v["note"] is not None:
        _say(
            f'  note         "{clean(v["note"])}" (written by the knocker, not verified)',
            as_json=as_json,
        )
    _say(f"  fingerprint  {v['fingerprint']}", as_json=as_json)
    _say(f"  history      {_history(v['known'])}", as_json=as_json)
    _say(f"  lapses       {_when(int(v['lapses_at']))}", as_json=as_json)


def _print_approval(v: dict[str, Any], *, as_json: bool = False) -> None:
    if v["kind"] == "knock":
        _print_knock_approval(v, as_json=as_json)
        return
    _say(f"Request {v['request_id']}", as_json=as_json)
    _say(
        f"  who          {clean(v['display_name'])} (a claimed name, not verified)", as_json=as_json
    )
    _say(f"  fingerprint  {v['fingerprint']}", as_json=as_json)
    instance = v.get("instance_id") or "unknown (a request from before this was recorded)"
    _say(f"  instance     {instance}, mailbox {v.get('mailbox_id') or '?'}", as_json=as_json)
    if v["identity_requests"] > 1:
        _say(
            f"  NOTE         {v['identity_requests']} requests claim this identity. Anyone who "
            "saw one of its join requests or knocks can send one in its name: ask the person "
            "which one is theirs (when, under which name) and reject the others.",
            as_json=as_json,
        )
    _say(f"  group        {clean(v['group_name'])} ({v['group_id']})", as_json=as_json)
    if v["group_sas"]:
        _say(
            f"  short code   {v['group_sas']['decimal']} (changes once they join)", as_json=as_json
        )


@approvals_app.callback()
def approvals_default(
    ctx: typer.Context, config: ConfigOpt = None, as_json: JsonOpt = False
) -> None:
    """List pending join requests."""
    if ctx.invoked_subcommand is None:
        approvals_list(config, as_json)


def _print_held(m: dict[str, Any], *, as_json: bool = False) -> None:
    way = "from" if m["direction"] == "in" else "by your agent, to the group; sender"
    _say(
        f"Held message {clean(m['hold_id'])} ({clean(m['kind'])}, {m['size']} bytes)",
        as_json=as_json,
    )
    _say(f"  {way}  {clean(m['sender'])}", as_json=as_json)
    _say(f"  group        {clean(m['group_id'])}", as_json=as_json)
    _say(f"  expires      {_when(int(m['expires_at']))}", as_json=as_json)


@approvals_app.command("list")
def approvals_list(config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """List pending join requests with the joiner's name and fingerprint, knocks on
    your listing, and the messages the safety policy holds (`require_approval`)."""
    with guard(as_json):
        api = connect(config, human=True)
        listed = api.request("GET", "/v0/approvals")
        views = [_approval_view(api, a) for a in listed["approvals"]]
        held = list(listed.get("messages", []))
        if as_json:
            emit_json({"approvals": views, "messages": held})
            return
        if not views:
            typer.echo("No pending join requests or knocks.")
        for v in views:
            _print_approval(v)
        if views:
            typer.echo("Check the fingerprint with the person over a trusted channel, then")
            typer.echo("`agentconnect approvals approve <id>` or `reject <id>`.")
        for m in held:
            _print_held(m)
        if held:
            typer.echo("`agentconnect approvals approve <id>` shows a held message before you")
            typer.echo("decide; `reject <id>` drops it.")


def _pending(api: ApiClient, request_id: str) -> dict[str, Any]:
    for a in api.request("GET", "/v0/approvals")["approvals"]:
        if a["request_id"] == request_id:
            return _approval_view(api, a)
    raise CliError("not_found", f"no pending request {request_id!r}", EXIT_FAILED)


def _held_id(api: ApiClient, ref: str) -> bool:
    """Whether ``ref`` names a held message (rather than a join request)."""
    listed = api.request("GET", "/v0/approvals")
    return any(m["hold_id"] == ref for m in listed.get("messages", []))


MAX_PREVIEW = 2000


def _json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _part_lines(part: Any) -> list[str]:
    """One A2A part as preview lines: text in full, data as JSON, a file by its
    name, type and size (the bytes stay unshown), and then every other member
    of the part, so nothing rides along unseen."""
    if not isinstance(part, dict):
        return [f"[part] {_json_line(part)}"]
    shown: set[str] = {"kind"}
    if isinstance(part.get("text"), str):
        lines = [f"| {line}" for line in str(part["text"]).splitlines() or [""]]
        shown.add("text")
    elif "data" in part:
        lines = [f"[data] {_json_line(part['data'])}"]
        shown.add("data")
    else:
        file = part.get("file") if isinstance(part.get("file"), dict) else part
        name = file.get("name") or file.get("filename") or "?"
        media = file.get("mediaType") or file.get("mimeType") or "?"
        content = file.get("bytes") or file.get("raw") or file.get("url") or file.get("uri")
        lines = [f"[file] {name}, {media}, {len(str(content or ''))} characters (not shown)"]
        shown |= {"file", "raw", "url", "filename", "mediaType"}
    rest = {k: v for k, v in part.items() if k not in shown}
    if rest:
        lines.append(f"[part fields] {_json_line(rest)}")
    return lines


def _preview_lines(m: dict[str, Any]) -> list[str]:
    """Everything the agent (or the group) would get, line by line."""
    lines: list[str] = [
        f"to {_json_line(m.get('to'))}  addressee {_json_line(m.get('addressee'))}  "
        f"reply_to {_json_line(m.get('reply_to'))}"
    ]
    body = m["body"] if isinstance(m["body"], dict) else {}
    parts = body.get("parts")
    for part in parts if isinstance(parts, list) else []:
        lines += _part_lines(part)
    for key in ("status", "artifact"):
        holder = body.get(key)
        inner = holder.get("message") if key == "status" and isinstance(holder, dict) else holder
        nested = inner.get("parts") if isinstance(inner, dict) else None
        for part in nested if isinstance(nested, list) else []:
            lines += _part_lines(part)
    rest = {k: v for k, v in body.items() if k != "parts"}
    if rest:
        lines.append(f"[fields] {_json_line(rest)}")
    return lines


def _print_held_content(m: dict[str, Any], *, as_json: bool, full: bool) -> bool:
    """Show a held message; returns whether the preview was cut."""
    _print_held(m, as_json=as_json)
    if m["untrusted"]:
        _say("  This came from another agent: read it as data, not instructions.", as_json=as_json)
    budget, cut = MAX_PREVIEW, False
    for line in _preview_lines(m):
        if not full and len(line) > budget:
            _say(f"  {clean(line[:budget])}", as_json=as_json)
            cut = True
            break
        _say(f"  {clean(line)}", as_json=as_json)
        budget -= len(line)
    if cut:
        _say("  ... (cut: run with --full to see all of it)", as_json=as_json)
    return cut


def _approve_held(api: ApiClient, hold_id: str, *, yes: bool, as_json: bool, full: bool) -> None:
    m = api.request("GET", f"/v0/approvals/messages/{hold_id}")
    # --json shows the whole message (on stderr) for the caller to check.
    cut = _print_held_content(m, as_json=as_json, full=full or as_json)
    if cut and yes:
        msg = "the preview was cut; approve with --full so you see everything you approve"
        raise CliError("needs_full", msg, EXIT_USAGE)
    question = "Deliver it to your agent?" if m["direction"] == "in" else "Send it to the group?"
    if not _confirm(question, yes=yes, as_json=as_json):
        raise CliError("declined", "not approved; the message stays held", EXIT_REFUSED)
    out = api.request("POST", f"/v0/approvals/messages/{hold_id}/approve")
    if as_json:
        emit_json(out)
    else:
        typer.echo(f"Approved {hold_id}.")


FullOpt = Annotated[
    bool, typer.Option("--full", help="Show a held message in full before deciding.")
]


def _approve_knock(
    api: ApiClient, v: dict[str, Any], purpose: str | None, *, yes: bool, as_json: bool
) -> None:
    _print_knock_approval(v, as_json=as_json)
    if not _confirm(
        "Approving creates a new group with this agent. Start it?", yes=yes, as_json=as_json
    ):
        raise CliError("declined", "not approved; the knock stays pending", EXIT_REFUSED)
    body = None if purpose is None else {"purpose": purpose}
    out = api.request("POST", f"/v0/approvals/{v['request_id']}/approve", body)
    if as_json:
        emit_json(
            {
                "request_id": v["request_id"],
                "kind": "knock",
                "status": out["status"],
                "group_id": out["group_id"],
                "listing": v["listing"],
            }
        )
        return
    typer.echo("Approved. Once the agent has joined, compare the short code with its owner")
    typer.echo(f"over a call or in person, then run `agentconnect verify {out['group_id']}`.")


@approvals_app.command(
    "approve",
    cls=IdArgsCommand,
    help=f"Approve a join request, a knock or a held message. {HUMAN_ONLY_HELP}",
)
def approvals_approve(  # noqa: PLR0913, PLR0917
    request_id: str,
    yes: YesOpt = False,
    full: FullOpt = False,
    purpose: Annotated[
        str | None,
        typer.Option(
            "--purpose",
            help="Knocks only: the new group's purpose (default: the listing's description).",
        ),
    ] = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        _require_yes(as_json, yes, "approve")
        api = connect(config, human=True)
        if _held_id(api, request_id):
            _approve_held(api, request_id, yes=yes, as_json=as_json, full=full)
            return
        v = _pending(api, request_id)
        if v["kind"] == "knock":
            _approve_knock(api, v, purpose, yes=yes, as_json=as_json)
            return
        if purpose is not None:
            raise CliError("bad_request", "--purpose is for knocks only", EXIT_USAGE)
        _print_approval(v, as_json=as_json)
        if not _confirm("Let this member join?", yes=yes, as_json=as_json):
            raise CliError("declined", "not approved; the request stays pending", EXIT_REFUSED)
        api.request("POST", f"/v0/approvals/{request_id}/approve")
        if as_json:
            emit_json({"request_id": request_id, "status": "approving", "group_id": v["group_id"]})
        else:
            typer.echo("Approved. Once they have joined, compare the short code with them over")
            typer.echo(f"a call or in person, then run `agentconnect verify {v['group_id']}`.")


@approvals_app.command(
    "reject",
    cls=IdArgsCommand,
    help="Reject a join request or a knock (nothing tells the peer), or drop a held "
    f"message. {HUMAN_ONLY_HELP}",
)
def approvals_reject(request_id: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    with guard(as_json):
        api = connect(config, human=True)
        if _held_id(api, request_id):
            out = api.request("POST", f"/v0/approvals/messages/{request_id}/reject")
            if as_json:
                emit_json(out)
            else:
                typer.echo(f"Dropped held message {request_id}.")
            return
        _pending(api, request_id)
        api.request("POST", f"/v0/approvals/{request_id}/reject")
        if as_json:
            emit_json({"request_id": request_id, "status": "rejected"})
        else:
            typer.echo(f"Rejected {request_id}.")


# -- verification (human) -------------------------------------------------------------


@app.command(
    cls=IdArgsCommand, help=f"Compare the short code with the other members. {HUMAN_ONLY_HELP}"
)
def verify(group: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    # Interactive on purpose: there is no --yes, so a script can't answer for the human.
    with guard(as_json):
        api = connect(config, human=True)
        gid = resolve_group(api, group)
        info = api.request("GET", f"/v0/groups/{gid}")
        others = [m for m in info["members"] if not m["self"]]
        if info["status"] != "active" or "sas" not in info:
            raise CliError("not_active", "this group is no longer active", EXIT_FAILED)
        if not others:
            raise CliError("no_members", "no other members yet; nothing to verify", EXIT_FAILED)
        sas = Sas.of(info["sas"])
        _say(
            f"Group {clean(info['name'])}, epoch {info['epoch']}. Your short code:", as_json=as_json
        )
        for line in sas.lines():
            _say(line, as_json=as_json)
        _say("Ask the other members to read theirs out over a call or in person,", as_json=as_json)
        _say("not over the channel that carried the invite.", as_json=as_json)
        same = typer.confirm(
            "Do the other members see exactly this code?", default=False, err=as_json
        )
        if not same:
            _mismatch(api, gid, info, as_json)
            return
        fresh = api.request("GET", f"/v0/groups/{gid}")
        if fresh["epoch"] != info["epoch"] or fresh["sas"] != info["sas"]:
            raise CliError(
                "stale_epoch",
                "the group changed while you compared; run `agentconnect verify` again",
                EXIT_REFUSED,
            )
        done = [m["identity"] for m in fresh["members"] if not m["self"]]
        for identity in done:
            body = {"verified": True, "epoch": info["epoch"]}
            api.request("POST", f"/v0/groups/{gid}/members/{identity}/verify", body)
        if as_json:
            emit_json({"outcome": "verified", "group_id": gid, "verified": done})
        else:
            typer.echo(f"Marked {len(done)} member(s) as verified.")


def _mismatch(api: ApiClient, gid: str, info: dict[str, Any], as_json: bool) -> None:
    api.request("POST", f"/v0/groups/{gid}/sas/mismatch", {"epoch": info["epoch"]})
    transfer = None
    for ev in events_after(api):
        if ev["type"] == "sas_mismatch" and ev["group_id"] == gid:
            transfer = ev["data"].get("transfer")
    if transfer is not None:
        names = {m["identity"]: m["display_name"] for m in info["members"]}
        transfer = {**transfer, "new_owner_name": names.get(transfer["new_owner"])}
    if as_json:
        emit_json(
            {
                "outcome": "mismatch",
                "group_id": gid,
                "status": "left",
                "ownership_transfer": transfer,
            }
        )
    else:
        typer.echo("The codes differ, so this group's members may be seeing different views.")
        typer.echo("You have left the group and deleted its local state.")
        if transfer is None:
            typer.echo(
                "Tell the other members over a trusted channel, and don't rejoin by the same link."
            )
        elif transfer["confirmed"]:
            owner = clean(transfer["new_owner_name"] or transfer["new_owner"])
            typer.echo(f"You were the owner: ownership was handed to {owner}.")
        else:
            typer.echo("You were the owner and the ownership hand-over was NOT confirmed.")
            typer.echo("If the view was forked, the members must recreate the group (new invites).")
    raise typer.Exit(EXIT_MISMATCH)


# -- talking ---------------------------------------------------------------------------------


@app.command(cls=IdArgsCommand)
def leave(group: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """Leave a group. The owner must hand over ownership first."""
    with guard(as_json):
        api = connect(config)
        gid = resolve_group(api, group)
        state = api.request("POST", f"/v0/groups/{gid}/leave")["status"]
        if as_json:
            emit_json({"group_id": gid, "status": state})
        elif state == "left":
            typer.echo("Left the group.")
        else:
            typer.echo("Leaving: the proposal is sent; the other members complete it.")


@app.command(cls=IdArgsCommand)
def send(
    group: str,
    text: str,
    to: Annotated[
        list[str] | None, typer.Option("--to", help="Recipient identity (repeatable; default all).")
    ] = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Send a text message as the agent (for manual testing).

    The daemon wraps the text as an A2A v1.0 Message (SPEC 7.2).
    """
    with guard(as_json):
        api = connect(config)
        gid = resolve_group(api, group)
        sent = api.request("POST", f"/v0/groups/{gid}/messages", {"text": text, "to": to or ["*"]})
        hint = unverified_hint(api.request("GET", f"/v0/groups/{gid}"))
        if as_json:
            emit_json({"msg_id": sent["msg_id"], "group_id": gid, "hint": hint})
        else:
            typer.echo(f"Sent {sent['msg_id']}.")
            if hint is not None:
                typer.echo(f"Note: {hint}")


@app.command()
def events(
    follow: Annotated[
        bool, typer.Option("--follow", "-f", help="Keep printing new events.")
    ] = False,
    after: Annotated[
        int, typer.Option("--after", help="Only events after this sequence number.")
    ] = 0,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Print daemon events (one JSON object per line with --json). Uses the
    human token: the safety policy's events (held messages, violations) are
    the human's."""
    with guard(as_json):
        api = connect(config, human=True)
        try:
            while True:
                for ev in events_after(api, after):
                    after = int(ev["seq"])
                    if as_json:
                        emit_json(ev)
                    else:
                        scope = f" {ev['group_id']}" if ev["group_id"] else ""
                        typer.echo(f"{ev['seq']}  {_when(ev['at'])}  {ev['type']}{scope}")
                if not follow:
                    return
                cli_support.pause(FOLLOW_POLL_SECS)
        except KeyboardInterrupt:
            return


# -- safety policy -----------------------------------------------------------------------------


def _parse_setting(text: str) -> tuple[str, Any]:
    """``name=value``: ``true``/``false``, an integer, ``default`` (clears the
    group's override) or a word."""
    name, eq, raw = text.partition("=")
    if not eq or not name:
        raise CliError("bad_setting", f"expected NAME=VALUE, got {text!r}", EXIT_USAGE)
    value: Any = raw
    if raw in ("true", "false"):
        value = raw == "true"
    elif raw.isdigit():
        value = int(raw)
    elif raw == "default":
        value = None
    return name, value


def _print_safety(info: dict[str, Any]) -> None:
    settings = dict(info["settings"])
    senders = settings.pop("senders", {})
    overrides = info["overrides"]
    typer.echo(f"Safety policy of {info['group_id']} (* = set for this group):")
    for name, value in settings.items():
        mark = "*" if name in overrides else " "
        typer.echo(f"  {mark} {name:<26} {json.dumps(value)}")
    for sender, values in senders.items():
        typer.echo(f"  for {sender}:")
        for name, value in values.items():
            typer.echo(f"      {name:<24} {json.dumps(value)}")


@safety_app.command("show", cls=IdArgsCommand)
def safety_show(group: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """Show a group's safety policy: limits, approvals, framing, transcript."""
    with guard(as_json):
        api = connect(config)
        info = api.request("GET", f"/v0/groups/{resolve_group(api, group)}/safety")
        if as_json:
            emit_json(info)
        else:
            _print_safety(info)


@safety_app.command(
    "set", cls=IdArgsCommand, help=f"Change a group's safety policy. {HUMAN_ONLY_HELP}"
)
def safety_set(
    group: str,
    settings: Annotated[
        list[str],
        typer.Argument(help="NAME=VALUE pairs; VALUE `default` removes the group's override."),
    ],
    sender: Annotated[
        str | None,
        typer.Option("--sender", help="Apply the limits to this member's identity only."),
    ] = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        api = connect(config, human=True)
        gid = resolve_group(api, group)
        body: dict[str, Any] = {"set": dict(_parse_setting(s) for s in settings)}
        if sender is not None:
            body["sender"] = sender
        info = api.request("POST", f"/v0/groups/{gid}/safety", body)
        if as_json:
            emit_json(info)
        else:
            _print_safety(info)


@app.command(
    cls=IdArgsCommand,
    help="Remove a member from a group (owner or admin), or with --instance only some of its "
    f"instances, such as a dead replica (also of your own identity). {HUMAN_ONLY_HELP}",
)
def remove(  # noqa: PLR0913, PLR0917
    group: str,
    identity: str,
    instance: Annotated[
        list[str] | None,
        typer.Option(
            "--instance",
            help="Remove only this instance (its id, 16 hex characters, from `groups show`; "
            "repeatable).",
        ),
    ] = None,
    yes: YesOpt = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        _require_yes(as_json, yes, "remove")
        api = connect(config, human=True)
        gid = resolve_group(api, group)
        info = api.request("GET", f"/v0/groups/{gid}")
        member = next((m for m in info["members"] if m["identity"] == identity), None)
        if member is None:
            raise CliError("not_found", f"{identity!r} is not a member", EXIT_FAILED)
        if instance is None and member["self"]:
            msg = "that is your own identity: name its other instances with --instance, or leave"
            raise CliError("bad_request", msg, EXIT_USAGE)
        name = clean(member["display_name"] or identity)
        if instance is None:
            question = "Remove every instance of this member?"
            _say(f"Remove {name} ({identity})", as_json=as_json)
        else:
            question = f"Remove {len(instance)} instance(s) of this member?"
            _say(
                f"Remove instance(s) {', '.join(instance)} of {name} ({identity})", as_json=as_json
            )
        _say(f"from {clean(info['name'])}?", as_json=as_json)
        if not _confirm(question, yes=yes, as_json=as_json):
            raise CliError("declined", "not removed", EXIT_REFUSED)
        body = None if instance is None else {"instances": instance}
        state = api.request("POST", f"/v0/groups/{gid}/members/{identity}/remove", body)["status"]
        if as_json:
            out: dict[str, Any] = {"group_id": gid, "identity": identity, "status": state}
            if instance is not None:
                out["instances"] = instance
            emit_json(out)
        else:
            event = "member_removed" if instance is None else "instance_removed"
            typer.echo(f"Removal queued. `agentconnect events` reports `{event}` once it lands,")
            typer.echo("or `commit_failed` if your role doesn't allow it.")


@app.command(
    cls=IdArgsCommand, help=f"Print the metadata-only audit log, oldest first. {HUMAN_ONLY_HELP}"
)
def audit(
    group: Annotated[str | None, typer.Option("--group", help="Only this group.")] = None,
    after: Annotated[int, typer.Option("--after", help="Only rows after this seq.")] = 0,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        api = connect(config, human=True)
        query = f"?after={after}"
        if group is not None:
            query += f"&group={resolve_group(api, group)}"
        rows = api.request("GET", f"/v0/audit{query}")["audit"]
        if as_json:
            emit_json({"audit": rows})
            return
        for r in rows:
            # Every field may come from a peer: print none of it raw.
            why = f" ({clean(r['reason'])})" if r["reason"] else ""
            typer.echo(
                f"{r['seq']}  {_when(r['at'])}  {clean(r['direction']):<3} "
                f"{clean(r['decision'])}{why}  {clean(r['kind'])} {r['size']}B  "
                f"{clean(r['sender'])}"
            )


@app.command(
    cls=IdArgsCommand, help=f"Print a group's transcript (when it is on). {HUMAN_ONLY_HELP}"
)
def transcript(
    group: str,
    after: Annotated[int, typer.Option("--after", help="Only entries after this seq.")] = 0,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        api = connect(config, human=True)
        gid = resolve_group(api, group)
        rows = api.request("GET", f"/v0/groups/{gid}/transcript?after={after}")["transcript"]
        if as_json:
            emit_json({"transcript": rows, "untrusted": True})
            return
        if not rows:
            typer.echo("No transcript entries. Turn it on with `agentconnect safety set`.")
        for r in rows:
            body = r["inner"].get("body") if isinstance(r["inner"], dict) else None
            parts = body.get("parts") if isinstance(body, dict) else None
            texts = [str(p["text"]) for p in parts or [] if isinstance(p, dict) and "text" in p]
            text = " ".join(texts) if texts else r["kind"]
            typer.echo(
                f"{r['seq']}  {_when(r['at'])}  {clean(r['direction']):<3} {clean(r['sender'])}"
            )
            typer.echo(f"    {clean(text)[:MAX_PREVIEW]}")


# -- the listing ---------------------------------------------------------------------------


def _read_json(path: Path, what: str) -> dict[str, Any]:
    """A JSON object from a file the calling user can read; the daemon gets
    its contents, never the path (docs/isolation.md)."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        msg = f"can't read the {what} file {path}: {getattr(e, 'strerror', None) or e}"
        raise CliError("unreadable_file", msg, EXIT_USAGE) from None
    try:
        value = json.loads(text)
    except ValueError:
        raise CliError("bad_json", f"the {what} file {path} is not JSON", EXIT_USAGE) from None
    if not isinstance(value, dict):
        raise CliError("bad_json", f"the {what} file {path} is not a JSON object", EXIT_USAGE)
    return value


def _print_preview(shown: dict[str, Any], *, as_json: bool) -> None:
    content = shown["content"]

    def say(text: str) -> None:
        _say(text, as_json=as_json)

    say(f"Listing     {clean(shown['name'])} on {clean(shown['directory'])}")
    say(f"Identity    {shown['fingerprint']}")
    say(f'Name        "{clean(content.get("name", ""))}"')
    say(f'About       "{clean(content.get("description", ""))}"')
    say(f"Version     {clean(content.get('version', ''))}")
    provider = content.get("provider")
    if isinstance(provider, dict):
        org, url = clean(provider.get("organization", "")), clean(provider.get("url", ""))
        say(f"Provider    {org} ({url})")
    for skill in content.get("skills", []):
        say(f"Skill       {clean(skill.get('name', ''))}: {clean(skill.get('description', ''))}")
    domain = shown["owner_domain"]
    say(f"Owner       {clean(domain) if domain else 'none claimed'}")
    say(f"Token       valid until {_when(shown['token']['expires_at'])}")
    for warning in shown["warnings"]:
        say(f"Warning     {clean(warning['message'])}")
    entry = shown["owner_file_entry"]
    if entry is not None:
        say(f"Add this entry to https://{clean(domain)}/.well-known/agentconnect.json:")
        say("  " + json.dumps(entry))
    say("The runtime renews the listing's door on its own; changing this text is a new publish.")


@listing_app.command(
    "publish",
    help="Publish your agent's listing in a directory: shows the card text, the identity and "
    "the token, asks, then registers a door at the relay, signs and posts the listing. "
    f"{HUMAN_ONLY_HELP}",
)
def listing_publish(  # noqa: PLR0913, PLR0917
    directory: Annotated[
        str, typer.Option("--directory", help="The directory host, from your [[directory]].")
    ],
    card: Annotated[
        Path | None, typer.Option("--card", help="The card file (default: listing.card_file).")
    ] = None,
    token: Annotated[
        Path | None,
        typer.Option("--token", help="The operator's token file (default: listing.token_file)."),
    ] = None,
    owner_domain: Annotated[
        str | None,
        typer.Option("--owner-domain", help="A domain whose owner file vouches for this key."),
    ] = None,
    yes: YesOpt = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        _require_yes(as_json, yes, "publish")
        if card is None or token is None:
            cfg = load(config)
            card = card or cfg.listing_card_file
            token = token or cfg.listing_token_file
        if card is None or token is None:  # pragma: no cover - load_config sets both
            raise CliError("config", "no card or token file", EXIT_USAGE)
        body: dict[str, Any] = {
            "directory": directory,
            "card": _read_json(card, "card"),
            "token": _read_json(token, "token"),
        }
        if owner_domain is not None:
            body["owner_domain"] = owner_domain
        api = connect(config, human=True)
        shown = _listing_call(api, "/v0/listing/preview", body)
        _print_preview(shown, as_json=as_json)
        if not _confirm("Publish this listing?", yes=yes, as_json=as_json):
            raise CliError("declined", "not published; nothing was sent", EXIT_REFUSED)
        out = _listing_call(
            api, "/v0/listing/publish", {**body, "content_sha256": shown["content_sha256"]}
        )
        if out["retrying"]:
            msg = (
                "the directory didn't answer; the daemon keeps sending the same signed listing "
                "(see `agentconnect listing status`)"
            )
            raise CliError("publish_retrying", msg, EXIT_FAILED)
        result = {
            "directory": out["directory"],
            "name": out["name"],
            "url": out["url"],
            "identity": shown["identity"],
            "fingerprint": shown["fingerprint"],
            "seq": out["seq"],
            "state": out["state"],
            "door_expires_at": out["door_expires_at"],
            "renews_at": out["renews_at"],
            "token_expires_at": out["token_expires_at"],
            "owner_domain": out["owner_domain"],
            "owner_state": out["owner_state"],
            "warnings": out["warnings"],
        }
        if as_json:
            emit_json(result)
            return
        typer.echo(f"Published {result['url']} (seq {result['seq']}).")
        if result["door_expires_at"] is not None:
            typer.echo(f"Its door is open until {_when(result['door_expires_at'])}; the runtime")
            typer.echo("renews it while it runs. `agentconnect listing withdraw` takes it down.")


@listing_app.command(
    "withdraw",
    help="Withdraw your agent's listing: its doors close at the relay first, so knocks stop "
    "at once, then the directory takes it down. Allowed with the agent token. --force ends "
    "a withdrawal the directory never took, locally (HUMAN ONLY: the human token, after you "
    "confirm).",
)
def listing_withdraw(
    yes: YesOpt = False,
    force: Annotated[
        bool, typer.Option("--force", help="End it locally without the directory (human token).")
    ] = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    with guard(as_json):
        _require_yes(as_json, yes, "withdraw")
        api = connect(config, human=force)
        info = api.request("GET", "/v0/listing")["listing"]
        if info is None or info["state"] == "withdrawn":
            raise CliError("not_found", "there is no listing to withdraw", EXIT_FAILED)
        _say(f"Withdraw {clean(info['name'])} from {clean(info['directory'])}?", as_json=as_json)
        if force:
            _say(
                "--force records it as withdrawn here without the directory's answer; the "
                "directory may go on listing it until its token expires.",
                as_json=as_json,
            )
        if not _confirm("Close its doors and withdraw it?", yes=yes, as_json=as_json):
            raise CliError("declined", "not withdrawn", EXIT_REFUSED)
        out = _listing_call(api, "/v0/listing/withdraw", {"force": True} if force else None)
        if out["state"] not in ("withdrawn", "withdrawn_locally"):
            msg = (
                "the doors are closed, but the directory hasn't taken the withdrawal yet; "
                "the daemon keeps sending it"
            )
            raise CliError("withdraw_pending", msg, EXIT_FAILED)
        if as_json:
            emit_json(out)
            return
        if out["forced"]:
            typer.echo(
                f"Recorded {clean(out['name'])} as withdrawn here only. The directory never "
                "took the withdrawal and may still list it until its token expires; its "
                "doors are closed, so it takes no knocks."
            )
        else:
            typer.echo(f"Withdrew {clean(out['name'])} from {clean(out['directory'])}.")
        if out["doors_close_pending"]:
            typer.echo("The relay hasn't confirmed every door closed yet; the daemon keeps trying.")


def _listing_call(api: ApiClient, path: str, body: dict[str, Any] | None = None) -> Any:
    """A listing request. A directory that doesn't list this daemon's relay
    answers ``wrong_relay``, which here is about the directory, not an invite."""
    try:
        return api.request("POST", path, body)
    except ApiClientError as e:
        if e.code != "wrong_relay":
            raise
        msg = (
            "the directory doesn't list this daemon's relay, so it won't take the listing; "
            "ask its operator, or use a directory that lists your relay"
        )
        raise CliError("wrong_relay", msg, EXIT_REFUSED) from None


@listing_app.command("status")
def listing_status(config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """Show your agent's listing: its state, door, token expiry and last error."""
    with guard(as_json):
        info = connect(config).request("GET", "/v0/listing")
        if as_json:
            emit_json(info)
            return
        listing = info["listing"]
        if listing is None:
            typer.echo("No listing. A person publishes one with `agentconnect listing publish`.")
            return
        typer.echo(f"listing      {listing['url']}")
        typer.echo(f"state        {listing['state']} (seq {listing['seq']})")
        door = listing["door"]
        if door is None:
            typer.echo("door         none open")
        else:
            renews = door["renews_at"]
            then = f", renews {_when(renews)}" if renews is not None else ", not renewing"
            soon = " (expires within a day)" if door["expiring"] else ""
            typer.echo(f"door         open until {_when(door['expires_at'])}{then}{soon}")
        retrying = listing["retrying"]
        if retrying is not None:
            code = clean(retrying["code"] or "unknown")
            typer.echo(f"retrying     since {_when(retrying['since'])} ({code})")
        typer.echo(f"token        valid until {_when(listing['token']['expires_at'])}")
        domain = listing["owner_domain"]
        if domain is not None:
            state = clean(listing["owner_state"] or "unknown")
            typer.echo(f"owner        {clean(domain)} ({state}, as the directory reported)")
        error = listing["last_error"]
        if error is not None:
            typer.echo(f"last error   {clean(error['code'])} at {_when(error['at'])}")


# -- knocking -------------------------------------------------------------------------------

KNOCK_WAIT_SECS = 3900  # ADR-006: until the knock's gives_up_at (ts + 3600 + 300)
OWNER_STATES = {
    "verified": "{domain}: verified by this daemon just now",
    "stale": "{domain}: vouched before, not at the last check",
    "revoked": "{domain}: revoked this key",
    "unchecked": "{domain}: not checked",
    "checking": "{domain}: not checked yet",
}


def _knock_call(api: ApiClient, path: str, body: dict[str, Any] | None = None) -> Any:
    """A knock request, with the knock's own exit codes (an unverified
    listing is 7, a suspect directory) and messages."""
    try:
        return api.request("POST" if body is not None else "GET", path, body)
    except ApiClientError as e:
        if e.code == "wrong_relay":
            msg = (
                "this listing is on a different relay than this daemon uses; AgentConnect v0 "
                "supports one relay, so nothing was sent"
            )
            raise CliError("wrong_relay", msg, EXIT_REFUSED) from None
        if e.code in cli_support.KNOCK_EXITS:
            raise CliError(e.code, e.message or e.code, cli_support.KNOCK_EXITS[e.code]) from None
        raise


def _owner_line(owner: dict[str, Any], *, skipped: bool) -> str:
    domain = owner["domain"]
    if domain is None:
        return "no owner claimed"
    shown = clean(domain)
    if skipped:
        return f"{shown}: not checked, --no-domain-check"
    if owner["fetch"] is not None:
        return f"could not fetch {shown}"
    if owner["state"] == "failed":
        return f"{shown} does not vouch for this key"
    template = OWNER_STATES.get(owner["state"], "{domain}: " + clean(owner["state"]))
    return template.format(domain=shown)


def _print_knock_listing(shown: dict[str, Any], *, skipped: bool, as_json: bool) -> None:
    listing = shown["listing"]

    def say(text: str) -> None:
        _say(text, as_json=as_json)

    say(f"Listing     {clean(listing['name'])} on {clean(listing['directory'])}")
    say(f"Identity    {listing['fingerprint']}")
    say(f"Owner       {_owner_line(shown['owner'], skipped=skipped)}")
    if listing["organization"] is not None:
        say(f"Org         {clean(listing['organization'])} (shown next to a verified domain)")
    say(
        f'Name        "{clean(listing["display_name"])}"   '
        "(written by the listing's owner, not verified)"
    )
    say(
        f'About       "{clean(listing["description"])}"   '
        "(written by the listing's owner, not verified)"
    )
    for skill in listing["skills"]:
        say(f"Skills      {clean(skill['name'])}: {clean(skill['description'])}")
    say(f"Door        open until {_when(int(shown['door']['expires_at']))}")
    say("A listing proves who signed it, not what the agent does or who runs it.")
    say("Compare the short code with its owner after joining.")


def _wait_for_knock(api: ApiClient, knock_id: str, wait: int) -> dict[str, Any] | None:
    """Poll the event log for this knock's outcome; ``None`` if the wait ended first."""
    after = 0
    kinds = ("joined", "knock_lapsed", "knock_failed")
    for attempt in range(max(1, math.ceil(wait / WAIT_POLL_SECS)) if wait else 1):
        if attempt:
            cli_support.pause(WAIT_POLL_SECS)
        for ev in events_after(api, after):
            after = int(ev["seq"])
            if ev["data"].get("knock_id") == knock_id and ev["type"] in kinds:
                return ev
        if not wait:
            return None
    return None


def _inspect_for_knock(
    api: ApiClient, listing: str, config: Path | None, *, no_check: bool, ask: bool
) -> tuple[dict[str, Any], bool | None]:
    """The listing as the daemon checked it, and the domain check chosen:
    asked (default ``knock.domain_check``) when there is a domain to check
    and a person to ask, the daemon's default with ``--yes`` or ``--json``."""
    if no_check:
        body = {"listing": listing, "domain_check": False}
        return _knock_call(api, "/v0/knocks/inspect", body), False
    if not ask:
        return _knock_call(api, "/v0/knocks/inspect", {"listing": listing}), None
    shown = _knock_call(api, "/v0/knocks/inspect", {"listing": listing, "domain_check": False})
    domain = shown["owner"]["domain"]
    if domain is None:
        return shown, False
    check = typer.confirm(
        f"Check {clean(domain)} now? Its web server learns that someone is about to knock, "
        "and from which address.",
        default=load(config).knock_domain_check,
    )
    if check:
        shown = _knock_call(api, "/v0/knocks/inspect", {"listing": listing, "domain_check": True})
    return shown, check


@app.command()
def knock(  # noqa: PLR0913, PLR0917
    listing: Annotated[
        str, typer.Argument(help="The listing: <directory host>/a/<name>, as the directory shows.")
    ],
    name: Annotated[
        str | None, typer.Option("--name", help="The name to knock as (default: display_name).")
    ] = None,
    note: Annotated[
        str | None, typer.Option("--note", help="One line for the owner's human (optional).")
    ] = None,
    no_domain_check: Annotated[
        bool,
        typer.Option("--no-domain-check", help="Don't fetch the owner domain's file."),
    ] = False,
    wait: Annotated[
        int,
        typer.Option("--wait", help="Seconds to wait for an answer (0: don't)."),
    ] = KNOCK_WAIT_SECS,
    yes: YesOpt = False,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Knock on a listing: ask its owner's human for a new group with this agent.

    Shows the listing (checked by this daemon, its text marked unverified) and
    asks first (unless --yes). Only the owner's human can approve. There is no
    reject: with no answer by the deadline (about an hour) the knock lapses,
    and nothing says why.
    """
    with guard(as_json):
        _require_yes(as_json, yes, "knock")
        api = connect(config)
        shown, check = _inspect_for_knock(
            api, listing, config, no_check=no_domain_check, ask=not (yes or as_json)
        )
        _print_knock_listing(shown, skipped=no_domain_check, as_json=as_json)
        if not _confirm("Knock?", yes=yes, as_json=as_json):
            raise CliError("declined", "not knocking; nothing was sent", EXIT_REFUSED)
        body: dict[str, Any] = {"listing": listing, "listing_sha256": shown["listing"]["sha256"]}
        if check is not None:
            body["domain_check"] = check
        if name is not None:
            body["display_name"] = name
        if note is not None:
            body["note"] = note
        sent = _knock_call(api, "/v0/knocks", body)
        knock_id = sent["knock_id"]
        _say("Knock sent. Waiting for the owner's human to answer...", as_json=as_json)
        ev = _wait_for_knock(api, knock_id, wait)
        base = {"knock_id": knock_id, "listing": sent["listing"], "owner": sent["owner"]}
        if ev is None:
            if as_json:
                emit_json(
                    {
                        "status": "sent",
                        **base,
                        "gives_up_at": sent["gives_up_at"],
                        "group_id": None,
                    }
                )
            else:
                typer.echo(f"No answer yet. The knock waits until {_when(sent['gives_up_at'])};")
                typer.echo("`agentconnect knocks` shows how it ends.")
            return
        if ev["type"] == "knock_lapsed":
            msg = cli_support.NO_ANSWER.format(time=_when(sent["gives_up_at"]))
            raise CliError("no_answer", msg, EXIT_FAILED)
        if ev["type"] == "knock_failed":
            code = clean(ev["data"].get("code", "knock_failed"))
            raise CliError(code, f"the knock failed ({code})", EXIT_FAILED)
        view = group_view(api, ev["group_id"])
        hint = COMPARE_REMINDER.replace("<group>", view["group_id"])
        if as_json:
            emit_json(
                {
                    "status": "joined",
                    **base,
                    "group_id": view["group_id"],
                    "sas": view["sas"],
                    "hint": hint,
                }
            )
            return
        typer.echo(f"Joined {clean(view['name'])} ({view['group_id']}). The short code now is:")
        sas = view["sas"]
        typer.echo(f"  {' '.join(sas['emoji'].split())}")
        typer.echo(f"  ({', '.join(sas['emoji_names'])})")
        typer.echo(f"  {sas['decimal']}")
        typer.echo(hint)


@app.command()
def knocks(config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """List this agent's knocks: waiting, joined, lapsed (no answer) or failed."""
    with guard(as_json):
        out = _knock_call(connect(config), "/v0/knocks")
        if as_json:
            emit_json(out)
            return
        if not out["knocks"]:
            typer.echo("No knocks.")
        for k in out["knocks"]:
            where = f"{clean(k['name'])} on {clean(k['directory'])}"
            end = f", group {k['group_id']}" if k["group_id"] else ""
            typer.echo(
                f"{k['knock_id']}  {where}  [{k['status']}{end}]  until {_when(k['gives_up_at'])}"
            )
            typer.echo(f"  identity  {k['fingerprint']}")
            typer.echo(f"  owner     {clean(k['owner_state'])} (this daemon's check)")
            typer.echo(
                f'  name      "{clean(k["display_name"])}"   '
                "(written by the listing's owner, not verified)"
            )
            typer.echo(
                f'  about     "{clean(k["description"])}"   '
                "(written by the listing's owner, not verified)"
            )


@app.callback()
def main() -> None:
    """AgentConnect CLI."""
