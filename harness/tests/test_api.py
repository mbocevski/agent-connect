"""The local control API over its Unix socket, and the CLI that reads it."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import stat
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from typer.testing import CliRunner

from agentconnect.api import ApiServer
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.cli import _run, app
from agentconnect_harness.cluster import Cluster, Node


class Api:
    def __init__(self, node: Node, server: ApiServer) -> None:
        self.node, self.server = node, server
        self.transport = httpx.AsyncHTTPTransport(uds=str(server.address))

    async def call(
        self,
        method: str,
        path: str,
        body: Any = None,
        scope: str | None = "agent",
        raw: bytes | None = None,
    ) -> tuple[int, Any]:
        headers = {}
        if scope is not None:
            headers["authorization"] = f"Bearer {self.server.tokens.get(scope, scope)}"
        async with httpx.AsyncClient(transport=self.transport, base_url="http://ac") as c:
            resp = await c.request(method, path, json=body, content=raw, headers=headers)
        return resp.status_code, resp.json()


@pytest_asyncio.fixture
async def sockdir() -> AsyncIterator[Path]:
    # Unix socket paths are limited to ~100 bytes; pytest's tmp paths can be longer.
    d = Path(tempfile.mkdtemp(prefix="ac-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def serve(cluster: Cluster, name: str, sockdir: Path, auto_approve: bool) -> Api:
    node = await cluster.node(name, auto_approve=auto_approve)
    node.config = node.config.with_overrides(api_socket=sockdir / f"{name}.sock")
    node.daemon.config = node.config
    server = ApiServer(node.daemon)
    await server.start()
    return Api(node, server)


async def test_api_drives_the_one_to_one_lifecycle(  # noqa: PLR0915
    cluster: Cluster, sockdir: Path
) -> None:
    alice = await serve(cluster, "alice", sockdir, auto_approve=False)
    bob = await serve(cluster, "bob", sockdir, auto_approve=True)
    assert stat.S_IMODE(os.stat(str(alice.server.address)).st_mode) == 0o600
    for token_file in ("api-token", "human-token"):
        assert stat.S_IMODE(os.stat(alice.node.config.data_dir / token_file).st_mode) == 0o600

    status, created = await alice.call("POST", "/v0/groups", {"name": "Ops", "purpose": "Deploys"})
    assert status == 200
    gid = created["group_id"]
    await alice.node.idle()
    status, invite = await alice.call("POST", f"/v0/groups/{gid}/invites", {"ttl_secs": 3600})
    assert status == 200
    status, meta = await bob.call("POST", "/v0/invites/inspect", {"url": invite["url"]})
    assert meta["meta"]["purpose"] == "Deploys"
    status, accepted = await bob.call(
        "POST", "/v0/invites/accept", {"url": invite["url"], "display_name": "bob"}
    )
    assert accepted["status"] == "pending"
    await alice.node.wait(lambda: len(alice.node.daemon.approvals()) == 1)
    status, listed = await alice.call("GET", "/v0/approvals")
    (req,) = listed["approvals"]
    assert req["display_name_verified"] is False
    # Approval is human-only: the agent token is refused.
    status, err = await alice.call("POST", f"/v0/approvals/{req['request_id']}/approve")
    assert (status, err["code"]) == (403, "human_only")
    status, _ = await alice.call(
        "POST", f"/v0/approvals/{req['request_id']}/approve", scope="human"
    )
    assert status == 200
    await bob.node.wait(lambda: bob.node.daemon.store.group(gid) is not None)
    await cluster.settle(gid, 1)

    _, info_a = await alice.call("GET", f"/v0/groups/{gid}")
    _, info_b = await bob.call("GET", f"/v0/groups/{gid}")
    assert info_a["sas"] == info_b["sas"]
    assert {m["role"] for m in info_a["members"]} == {"owner", "member"}
    status, err = await alice.call("POST", f"/v0/groups/{gid}/members/{bob.node.me}/verify", {})
    assert status == 403
    status, done = await alice.call(
        "POST", f"/v0/groups/{gid}/members/{bob.node.me}/verify", {"verified": True}, scope="human"
    )
    assert done == {"verified": True}
    _, info_a = await alice.call("GET", f"/v0/groups/{gid}")
    assert info_a["trust_state"]["verified_members"] == 1

    status, sent = await alice.call("POST", f"/v0/groups/{gid}/messages", {"text": "hello"})
    assert status == 200
    assert sent["msg_id"]
    assert await bob.node.wait_texts(gid, 1) == ["hello"]
    # The agent token sends as the agent (SPEC 7.2, 10.3)...
    assert bob.node.adapter.deliveries[0].origin == "agent"
    # ...even if the query string claims otherwise...
    status, _ = await alice.call("POST", f"/v0/groups/{gid}/messages?_scope=human", {"text": "x"})
    # ...and can't send the human-only control.resume (SPEC 7.3).
    status, err = await alice.call(
        "POST", f"/v0/groups/{gid}/messages", {"kind": "control.resume", "body": {}}
    )
    assert (status, err["code"]) == (403, "human_only")
    status, _ = await alice.call(
        "POST",
        f"/v0/groups/{gid}/messages",
        {"kind": "control.resume", "body": {}},
        scope="human",
    )
    assert status == 200
    await bob.node.wait_texts(gid, 2)
    await bob.node.adapter.wait_for(
        lambda: any(d.kind == "control.resume" for d in bob.node.adapter.deliveries)
    )
    resume = next(d for d in bob.node.adapter.deliveries if d.kind == "control.resume")
    assert (resume.origin, resume.hop) == ("human", 0)
    assert [d.origin for d in bob.node.adapter.deliveries if d.kind == "a2a.message"] == [
        "agent",
        "agent",
    ]
    bob.node.adapter.deliveries.clear()
    status, sent = await bob.call(
        "POST", f"/v0/groups/{gid}/messages", {"body": {"data": 1}, "to": [alice.node.me]}
    )
    await alice.node.adapter.wait_for(lambda: len(alice.node.adapter.deliveries) == 1)

    _, groups = await bob.call("GET", "/v0/groups")
    assert [g["group_id"] for g in groups["groups"]] == [gid]
    _, events = await bob.call("GET", "/v0/events?after=0")
    assert "joined" in {e["type"] for e in events["events"]}
    _, status_info = await bob.call("GET", "/v0/status")
    assert status_info["relay"]["connected"]

    status, left = await bob.call("POST", f"/v0/groups/{gid}/leave")
    assert left == {"status": "leaving"}
    status, invite2 = await alice.call("POST", f"/v0/groups/{gid}/invites", {})
    status, revoked = await alice.call("DELETE", f"/v0/invites/{invite2['invite_id']}")
    assert revoked == {"revoked": invite2["invite_id"]}
    status, _rejected = await alice.call("POST", "/v0/approvals/nope/reject", scope="human")
    assert status == 404
    await alice.server.stop()
    await bob.server.stop()


@pytest.mark.parametrize(
    ("method", "path", "body", "token", "status", "code"),
    [
        ("GET", "/v0/status", None, None, 401, "auth_failed"),
        ("GET", "/v0/status", None, "wrong", 401, "auth_failed"),
        ("GET", "/v0/nothing", None, "agent", 404, "not_found"),
        ("PUT", "/v0/status", None, "agent", 405, "method_not_allowed"),
        ("POST", "/v0/groups", {"name": 3}, "agent", 400, "bad_request"),
        ("POST", "/v0/groups/x/invites", {"ttl_secs": "long"}, "agent", 400, "bad_request"),
        ("POST", "/v0/groups/x/invites", {"inviter_name": 1}, "agent", 400, "bad_request"),
        ("POST", "/v0/groups/x/invites", {}, "agent", 404, "not_found"),
        (
            "POST",
            "/v0/invites/accept",
            {"url": "x", "display_name": 1},
            "agent",
            400,
            "bad_request",
        ),
        ("POST", "/v0/invites/inspect", {"url": "nope"}, "agent", 400, "bad_request"),
        ("POST", "/v0/groups/x/messages", {"body": [1]}, "agent", 400, "bad_request"),
        ("POST", "/v0/groups/x/messages", {"text": "t", "to": "all"}, "agent", 400, "bad_request"),
        ("POST", "/v0/groups/x/messages", {"text": "t"}, "agent", 404, "not_found"),
        ("POST", "/v0/groups/x/members/y/verify", {"verified": "yes"}, "human", 400, "bad_request"),
        ("POST", "/v0/approvals/nope/approve", None, "human", 404, "not_found"),
    ],
)
async def test_api_errors(  # noqa: PLR0913, PLR0917
    cluster: Cluster,
    sockdir: Path,
    method: str,
    path: str,
    body: Any,
    token: str | None,
    status: int,
    code: str,
) -> None:
    api = await serve(cluster, "e", sockdir, auto_approve=False)
    got, err = await api.call(method, path, body, scope=token)
    assert (got, err["code"]) == (status, code)
    await api.server.stop()


async def test_api_rejects_malformed_http(cluster: Cluster, sockdir: Path) -> None:
    api = await serve(cluster, "m", sockdir, auto_approve=False)
    assert (await api.call("POST", "/v0/groups", raw=b"{not json"))[0] == 400
    assert (await api.call("POST", "/v0/groups", raw=b"[1]"))[0] == 400

    async def raw(data: bytes) -> bytes:
        reader, writer = await asyncio.open_unix_connection(str(api.server.address))
        writer.write(data)
        await writer.drain()
        out = await reader.read()
        writer.close()
        return out

    assert b" 400 " in await raw(b"GARBAGE\r\n\r\n")
    assert b" 413 " in await raw(b"POST /v0/groups HTTP/1.1\r\ncontent-length: 99999999\r\n\r\n")
    assert b" 400 " in await raw(b"GET /v0/status HTTP/1.1\r\n" + b"x: y\r\n" * 4000 + b"\r\n")
    await api.server.stop()


async def test_api_over_loopback_tcp_and_cli_status(cluster: Cluster) -> None:
    node = await cluster.node("t")
    node.daemon.config = node.config.with_overrides(api_tcp_port=_free())
    server = ApiServer(node.daemon)
    await server.start()
    assert str(server.address).startswith("http://127.0.0.1:")
    client = ApiClient(node.daemon.config)
    info = await asyncio.to_thread(client.request, "GET", "/v0/status")
    assert info["identity"] == node.me
    with pytest.raises(ApiClientError, match="not_found"):
        await asyncio.to_thread(client.request, "GET", "/v0/nope")
    runner = CliRunner()
    cfg_file = node.config.data_dir / "config.toml"
    cfg_file.write_text(
        f'[relay]\nurl = "{node.config.relay_url}"\n[daemon]\ndata_dir = "{node.config.data_dir}"\n'
        f"[api]\ntcp_port = {node.daemon.config.api_tcp_port}\n",
        encoding="utf-8",
    )
    result = await asyncio.to_thread(runner.invoke, app, ["status", "--config", str(cfg_file)])
    assert result.exit_code == 0, result.output
    assert "fingerprint" in result.stdout
    result = await asyncio.to_thread(
        runner.invoke, app, ["status", "--json", "--config", str(cfg_file)]
    )
    assert node.me in result.stdout
    await server.stop()
    result = await asyncio.to_thread(runner.invoke, app, ["status", "--config", str(cfg_file)])
    assert result.exit_code == 1
    assert "cannot reach" in result.output


def _free() -> int:
    import socket  # noqa: PLC0415

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_cli_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    bad = tmp_path / "bad.toml"
    bad.write_text('[relay]\nurl = "http://x"\n', encoding="utf-8")
    assert runner.invoke(app, ["status", "--config", str(bad)]).exit_code == 2
    empty = tmp_path / "ok.toml"
    empty.write_text(f'[daemon]\ndata_dir = "{tmp_path / "none"}"\n', encoding="utf-8")
    result = runner.invoke(app, ["status", "--config", str(empty)])
    assert result.exit_code == 1
    assert "daemon running" in result.output


async def test_daemon_run_serves_until_signalled(cluster: Cluster, sockdir: Path) -> None:
    cfg = (await cluster.node("seed")).config.with_overrides(
        data_dir=cluster.tmp / "run", api_socket=sockdir / "run.sock", keystore="file"
    )
    ready = asyncio.Event()
    task = asyncio.ensure_future(_run(cfg, ready))
    sock = sockdir / "run.sock"
    await asyncio.wait_for(ready.wait(), 10)
    info = await asyncio.to_thread(ApiClient(cfg).request, "GET", "/v0/status")
    assert info["keystore"] == "file"
    os.kill(os.getpid(), signal.SIGTERM)
    await asyncio.wait_for(task, 10)
    assert not sock.exists()
