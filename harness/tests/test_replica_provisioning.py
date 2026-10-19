"""Provisioning a replica on the real relay (docs/groups.md#replicas): the
identity key moves with `agentconnect identity export` and `identity import`
(never by copying the keystore), the replica gets an instance of its own, and
joins each group through a replica invite, which only its identity can use
and which its human creates whatever the group's invite policy says."""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from typer.testing import CliRunner

from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.cli import app
from agentconnect.cli_json import SCHEMAS
from agentconnect.config import load_config
from agentconnect.runtime.api import ApiServer
from agentconnect.runtime.engine import DaemonError
from agentconnect.shapes import conforms
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged, status

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
runner = CliRunner()


def _free() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def config_for(data_dir: Path, relay_url: str, tcp_port: int = 0) -> Path:
    """A config.toml for the CLI on ``data_dir`` (file keystore, as the harness)."""
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = data_dir.parent / f"{data_dir.name}.toml"
    path.write_text(
        f'[relay]\nurl = "{relay_url}"\n'
        f'[daemon]\ndata_dir = "{data_dir}"\nkeystore = "file"\n'
        f"[api]\ntcp_port = {tcp_port}\n",
        encoding="utf-8",
    )
    return path


def cli(config: Path, *args: str, input: str | None = None) -> tuple[int, Any]:
    """`agentconnect <args> --json --config <config>`: the exit code and the
    JSON it printed."""
    result = runner.invoke(app, [*args, "--json", "--config", str(config)], input=input)
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    lines = result.stdout.strip().splitlines()
    return result.exit_code, json.loads(lines[-1]) if lines else None


def data(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e.data for e in node.adapter.unique_events() if e.type == kind]


def instance_of(node: Node) -> str:
    return node.daemon.instance.instance_id_hex


@pytest_asyncio.fixture
async def serve() -> AsyncIterator[Callable[[Node], Awaitable[Path]]]:
    """Serve a node's local API on a loopback port; the config for its CLI."""
    servers: list[ApiServer] = []

    async def start(node: Node) -> Path:
        port = _free()
        node.daemon.config = node.config.with_overrides(api_tcp_port=port)
        server = ApiServer(node.daemon)
        await server.start()
        servers.append(server)
        return config_for(node.config.data_dir, node.config.relay_url, port)

    yield start
    for s in servers:
        await s.stop()


async def stopped(node: Node) -> None:
    await node.stop()
    await asyncio.wait_for(node.proxy.wait_no_sessions(), WAIT)


async def test_a_replica_provisioned_by_the_cli_joins_by_a_replica_invite_and_is_removed(  # noqa: PLR0915
    cluster: Cluster, group: GroupFixture, serve: Callable[[Node], Awaitable[Path]]
) -> None:
    """Scenario 11: under `invite: "owner"`, plain member X provisions a
    replica X2 (export, import), creates a replica invite with the human
    token, and X2 joins: every member reports `instance_joined`. X then
    removes X2 with `remove --instance`: `instance_removed`."""
    (a, x, c), gid = await group(3)
    with pytest.raises(DaemonError, match="does not let this identity invite"):
        await x.daemon.create_invite(gid)
    source = config_for(x.config.data_dir, x.config.relay_url)
    export = cluster.tmp / "x.export"

    # The runtime holds the data directory: nothing is exported.
    code, out = await asyncio.to_thread(cli, source, "identity", "export", "--out", str(export))
    assert (code, out["error"]["code"]) == (2, "runtime_running")
    assert not export.exists()

    await stopped(x)
    code, made = await asyncio.to_thread(cli, source, "identity", "export", "--out", str(export))
    assert code == 0, made
    assert conforms(made, SCHEMAS["identity export"])
    assert (made["identity"], made["file"]) == (x.me, str(export))
    assert export.stat().st_mode & 0o777 == 0o600
    assert made["code"] not in export.read_text(encoding="utf-8")
    # A copied data directory is not a replica: the import refuses it.
    copy = cluster.tmp / "x-copy"
    shutil.copytree(x.config.data_dir, copy)
    copied = config_for(copy, x.config.relay_url)
    code, out = await asyncio.to_thread(
        cli, copied, "identity", "import", str(export), "--code", made["code"]
    )
    assert (code, out["error"]["code"]) == (2, "not_empty")
    await x.start()

    target = cluster.tmp / "x2"
    fresh = config_for(target, x.config.relay_url)
    code, imported = await asyncio.to_thread(
        cli, fresh, "identity", "import", str(export), "--code", made["code"]
    )
    assert code == 0, imported
    assert conforms(imported, SCHEMAS["identity import"])
    assert imported["identity"] == x.me
    assert imported["instance_id"] != instance_of(x)
    x2 = await cluster.node("x2", data_dir=target)
    assert (x2.me, instance_of(x2)) == (x.me, imported["instance_id"])

    x_cli = await serve(x)
    agent = ApiClient(load_config(x_cli), human=False)
    with pytest.raises(ApiClientError) as refused:
        await asyncio.to_thread(
            agent.request, "POST", f"/v0/groups/{gid}/invites", {"replica": True}
        )
    assert (refused.value.status, refused.value.code) == (403, "human_only")
    with pytest.raises(ApiClientError) as refused:
        await asyncio.to_thread(agent.request, "POST", f"/v0/groups/{gid}/invites", {"replica": 1})
    assert (refused.value.status, refused.value.code) == (400, "bad_request")
    code, invite = await asyncio.to_thread(
        cli, x_cli, "invite", "create", "--group", gid, "--replica"
    )
    assert code == 0, invite
    assert conforms(invite, SCHEMAS["invite create"])
    assert invite["replica"] is True
    assert x.daemon.store.invite(invite["invite_id"])["replica"] is True  # ty: ignore[not-subscriptable]

    await x2.daemon.accept_invite(invite["url"])
    await converged([a, x, c, x2], gid)
    for n in (a, x, c):
        assert data(n, "instance_joined") == [
            {"identity": x.me, "instance_id": instance_of(x2), "by": x.me}
        ]
        assert [d["identity"] for d in data(n, "member_joined")].count(x.me) <= 1

    code, removed = await asyncio.to_thread(
        cli, x_cli, "remove", gid, x.me, "--instance", instance_of(x2), "--yes"
    )
    assert code == 0, removed
    await x2.wait(lambda: status(x2, gid) == "removed")
    await converged([a, x, c], gid)
    for n in (a, x, c):
        assert data(n, "instance_removed") == [
            {"identity": x.me, "instance_id": instance_of(x2), "by": x.me}
        ]
        assert data(n, "member_removed") == []


async def test_a_replica_invite_drops_every_other_identitys_request(
    cluster: Cluster, group: GroupFixture
) -> None:
    (a, x), gid = await group(2)
    made = await x.daemon.create_invite(gid, max_uses=2, replica=True)
    outsider = await cluster.node("outsider")
    await outsider.daemon.accept_invite(made["url"])
    await x.wait(lambda: any(r["reason"] == "join_not_replica" for r in x.daemon.store.audit(gid)))
    (row,) = [r for r in x.daemon.store.audit(gid) if r["reason"] == "join_not_replica"]
    assert (row["sender"], row["decision"]) == (outsider.me, "drop")
    assert x.daemon.approvals() == []
    assert not [e for e in x.daemon.store.events() if e["type"] == "pending_approval"]

    x2 = await cluster.node("x2", identity_of=x)
    await x2.daemon.accept_invite(made["url"])
    await converged([a, x, x2], gid)
    assert outsider.daemon.store.group(gid) is None
    assert data(a, "instance_joined") == [
        {"identity": x.me, "instance_id": instance_of(x2), "by": x.me}
    ]


async def test_a_replica_invite_stays_open_when_its_creator_may_no_longer_invite(
    cluster: Cluster, group: GroupFixture
) -> None:
    (a, b), gid = await group(2)
    assert a.daemon.change_policy(gid, {"invite": "members"}) == "committing"
    await converged([a, b], gid)
    plain = await b.daemon.create_invite(gid)
    replica = await b.daemon.create_invite(gid, replica=True)
    assert a.daemon.change_policy(gid, {"invite": "owner"}) == "committing"
    await converged([a, b], gid)
    await b.wait(lambda: b.daemon.store.invite(plain["invite_id"])["status"] == "revoked")  # ty: ignore[not-subscriptable]
    assert b.daemon.store.invite(replica["invite_id"])["status"] == "open"  # ty: ignore[not-subscriptable]

    b2 = await cluster.node("b2", identity_of=b)
    await b2.daemon.accept_invite(replica["url"])
    await converged([a, b, b2], gid)
    assert data(a, "instance_joined") == [
        {"identity": b.me, "instance_id": instance_of(b2), "by": b.me}
    ]
    # Removed from the group, its replica invites close too.
    another = await b.daemon.create_invite(gid, replica=True)
    a.daemon.remove_member(gid, b.me)
    await b.wait(lambda: status(b, gid) == "removed")
    await b.wait(lambda: b.daemon.store.invite(another["invite_id"])["status"] == "revoked")  # ty: ignore[not-subscriptable]
