"""`agentconnect` command-line interface.

A thin layer over the daemon's local API (``agentconnect.api``): it parses
arguments, calls the daemon, and renders the answer. Protocol decisions live
in the daemon. Every command takes ``--json`` for a stable machine-readable
shape (docs/cli.md); errors are then ``{"error": {"code", "message"}}`` on
stdout with a non-zero exit code.

``approve``, ``reject`` and ``verify`` (and the mismatch path inside it) use
the **human token**. They are decisions only a person may make (SPEC 6.2,
11): never give an agent the human token or let it run them for the human.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import signal
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

import agentconnect_core
from agentconnect import __version__, cli_support, log
from agentconnect.apiclient import ApiClient
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
from agentconnect.config import Config
from agentconnect.isolation import IsolationError, PeerGate

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
    no_args_is_help=True, help="Create groups.", pretty_exceptions_show_locals=False
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
    help="Pending join requests. `approve` and `reject` are HUMAN ONLY (human token): "
    "never give an agent the human token or run them for the human.",
    pretty_exceptions_show_locals=False,
)
app.add_typer(daemon_app, name="daemon")
app.add_typer(group_app, name="group")
app.add_typer(invite_app, name="invite")
app.add_typer(groups_app, name="groups")
app.add_typer(approvals_app, name="approvals")

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


async def _run(cfg: Config, ready: asyncio.Event | None = None) -> None:
    from agentconnect.adapters import build_adapters  # noqa: PLC0415
    from agentconnect.api import ApiServer  # noqa: PLC0415
    from agentconnect.clock import SystemClock  # noqa: PLC0415
    from agentconnect.daemon import Daemon  # noqa: PLC0415

    # Separate-OS-user mode: refuse a loose setup before any key is opened.
    gate = PeerGate.from_config(cfg)
    clock = SystemClock()
    daemon = Daemon(cfg, build_adapters(cfg, clock), clock=clock)
    api = ApiServer(daemon, gate)
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
    """Run agentconnectd in the foreground (JSON logs on stderr).

    Starts the adapter named by daemon.default_adapter (webhook or sse), and
    the A2A adapter when a2a.local_agent_url or a2a.facade_port is set.
    """
    with guard(False):
        cfg = load(config)
    if tcp_port:
        cfg = cfg.with_overrides(api_tcp_port=tcp_port)
    log.configure()
    with guard(False):
        try:
            asyncio.run(_run(cfg))
        except IsolationError as e:
            raise CliError("isolation", f"refusing to start: {e}", EXIT_USAGE) from None


# -- groups and invites ------------------------------------------------------------


def _new_group(api: ApiClient, purpose: str, name: str | None) -> str:
    name = (name or purpose or "AgentConnect chat")[:MAX_NAME]
    return str(api.request("POST", "/v0/groups", {"name": name, "purpose": purpose})["group_id"])


@group_app.command("create")
def group_create(
    purpose: Annotated[
        str, typer.Option("--purpose", help="What the group is for (shown to joiners).")
    ],
    name: Annotated[
        str | None, typer.Option("--name", help="Group name (default: the purpose).")
    ] = None,
    config: ConfigOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Create a group you own."""
    with guard(as_json):
        api = connect(config)
        gid = _new_group(api, purpose, name)
        shown = (name or purpose or "AgentConnect chat")[:MAX_NAME]
        if as_json:
            emit_json({"group_id": gid, "name": shown, "purpose": purpose})
        else:
            typer.echo(f"Created group {clean(shown)} ({gid}).")
            typer.echo("Invite someone with: agentconnect invite create --group " + gid)


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
        api = connect(config)
        gid = (
            resolve_group(api, group) if group is not None else _new_group(api, purpose or "", None)
        )
        if require_verified:
            api.request("POST", f"/v0/groups/{gid}/policy", {"require_verified": True})
        made = api.request(
            "POST", f"/v0/groups/{gid}/invites", {"ttl_secs": secs, "max_uses": max_uses}
        )
        if as_json:
            emit_json(
                {
                    "url": made["url"],
                    "invite_id": made["invite_id"],
                    "group_id": gid,
                    "expires_at": made["expires_at"],
                    "max_uses": max_uses,
                    "require_verified": require_verified,
                    "reminder": SHARE_REMINDER,
                }
            )
            return
        uses = f"{max_uses} use" + ("" if max_uses == 1 else "s")
        typer.echo(f"Invite for group {gid}, {uses}, expires {_when(made['expires_at'])}:")
        typer.echo("")
        typer.echo(made["url"])
        typer.echo("")
        typer.echo(SHARE_REMINDER)


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
        typer.echo(f"Pending approvals  {view['pending_approvals']}")
        typer.echo("Members (names are claimed by each member, not verified):")
        for m in view["members"]:
            mark = "verified" if m["verified"] else ("you" if m["self"] else "not verified")
            typer.echo(
                f"  {clean(m['display_name'] or '?')}  {m['role']}  {m['instances']} instance(s)  "
                f"{mark}  {m['fingerprint']}"
            )


# -- approvals (human) -----------------------------------------------------------------------


def _approval_view(api: ApiClient, a: dict[str, Any]) -> dict[str, Any]:
    info = api.request("GET", f"/v0/groups/{a['group_id']}")
    return {
        "request_id": a["request_id"],
        "group_id": a["group_id"],
        "group_name": info["name"],
        "display_name": a["display_name"],
        "display_name_verified": a["display_name_verified"],
        "identity": a["identity"],
        "fingerprint": a["fingerprint"],
        "received_at": a["received_at"],
        "group_sas": Sas.of(info["sas"]).as_json() if "sas" in info else None,
    }


def _print_approval(v: dict[str, Any], *, as_json: bool = False) -> None:
    _say(f"Request {v['request_id']}", as_json=as_json)
    _say(
        f"  who          {clean(v['display_name'])} (a claimed name, not verified)", as_json=as_json
    )
    _say(f"  fingerprint  {v['fingerprint']}", as_json=as_json)
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


@approvals_app.command("list")
def approvals_list(config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    """List pending join requests with the joiner's name and fingerprint."""
    with guard(as_json):
        api = connect(config)
        views = [_approval_view(api, a) for a in api.request("GET", "/v0/approvals")["approvals"]]
        if as_json:
            emit_json({"approvals": views})
            return
        if not views:
            typer.echo("No pending join requests.")
        for v in views:
            _print_approval(v)
        if views:
            typer.echo("Check the fingerprint with the person over a trusted channel, then")
            typer.echo("`agentconnect approvals approve <id>` or `reject <id>`.")


def _pending(api: ApiClient, request_id: str) -> dict[str, Any]:
    for a in api.request("GET", "/v0/approvals")["approvals"]:
        if a["request_id"] == request_id:
            return _approval_view(api, a)
    raise CliError("not_found", f"no pending request {request_id!r}", EXIT_FAILED)


@approvals_app.command(
    "approve", cls=IdArgsCommand, help=f"Approve a join request. {HUMAN_ONLY_HELP}"
)
def approvals_approve(
    request_id: str, yes: YesOpt = False, config: ConfigOpt = None, as_json: JsonOpt = False
) -> None:
    with guard(as_json):
        _require_yes(as_json, yes, "approve")
        api = connect(config, human=True)
        v = _pending(api, request_id)
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
    "reject", cls=IdArgsCommand, help=f"Reject a join request. {HUMAN_ONLY_HELP}"
)
def approvals_reject(request_id: str, config: ConfigOpt = None, as_json: JsonOpt = False) -> None:
    with guard(as_json):
        api = connect(config, human=True)
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
            api.request("POST", f"/v0/groups/{gid}/members/{identity}/verify", {"verified": True})
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
    """Print daemon events (one JSON object per line with --json)."""
    with guard(as_json):
        api = connect(config)
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


@app.callback()
def main() -> None:
    """AgentConnect CLI."""
