"""The local control API over its Unix socket, and the CLI that reads it."""

from __future__ import annotations

import asyncio
import contextlib
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

from agentconnect import daemon as daemon_host
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.cli import app
from agentconnect.config import Config
from agentconnect.runtime.api import ApiServer
from agentconnect_harness.a2a_agents import AgentServer, HelloWorldExecutor
from agentconnect_harness.cluster import Cluster, Node, api_token
from agentconnect_harness.relay import reserved_port


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
            headers["authorization"] = f"Bearer {api_token(self.server, scope)}"
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
    status, listed = await alice.call("GET", "/v0/approvals", scope="human")
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
    path = f"/v0/groups/{gid}/members/{bob.node.me}/verify"
    status, err = await alice.call("POST", path, {"verified": True}, scope="human")
    assert (status, err["code"]) == (400, "bad_request")  # which code was compared?
    stale = {"verified": True, "epoch": info_a["epoch"] - 1}
    status, err = await alice.call("POST", path, stale, scope="human")
    assert (status, err["code"]) == (409, "stale_epoch")
    assert "compare again" in err["message"]
    shown = {"verified": True, "epoch": info_a["epoch"]}
    status, done = await alice.call("POST", path, shown, scope="human")
    assert done == {"verified": True}
    _, info_a = await alice.call("GET", f"/v0/groups/{gid}")
    assert info_a["trust_state"]["verified_members"] == 1

    status, sent = await alice.call("POST", f"/v0/groups/{gid}/messages", {"text": "hello"})
    assert status == 200
    assert sent["msg_id"]
    assert await bob.node.wait_texts(gid, 1) == ["hello"]
    # The agent token sends as the agent (SPEC 7.2, 10.3)...
    assert bob.node.adapter.deliveries[0].origin == "agent"
    assert bob.node.adapter.deliveries[0].hop == 1
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
    with reserved_port() as port:
        node.daemon.config = node.config.with_overrides(api_tcp_port=port)
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
    assert result.exit_code == 5
    assert "cannot reach" in result.output


async def test_cli_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    bad = tmp_path / "bad.toml"
    bad.write_text('[relay]\nurl = "http://x"\n', encoding="utf-8")
    assert runner.invoke(app, ["status", "--config", str(bad)]).exit_code == 2
    empty = tmp_path / "ok.toml"
    empty.write_text(f'[daemon]\ndata_dir = "{tmp_path / "none"}"\n', encoding="utf-8")
    result = runner.invoke(app, ["status", "--config", str(empty)])
    assert result.exit_code == 5
    assert "cannot reach the daemon" in result.output


async def _started(cfg: Config) -> asyncio.Task[None]:
    """`agentconnect daemon run` in this process, once it is up: its signal
    handlers are installed when `ready` is set. A daemon that fails to
    start, or isn't up in 10 s, fails the test here, so no SIGTERM goes out
    under the default handler, which would end the process (the xdist
    worker)."""
    ready = asyncio.Event()
    task = asyncio.create_task(daemon_host.serve(cfg, ready))
    up = asyncio.create_task(ready.wait())
    await asyncio.wait({task, up}, timeout=10, return_when=asyncio.FIRST_COMPLETED)
    up.cancel()
    if ready.is_set():
        return task
    if task.done():
        task.result()  # why it didn't start
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    pytest.fail("the daemon was not up in 10 s")


async def _signalled(task: asyncio.Task[None]) -> None:
    """Stop the daemon as a user would: SIGTERM to the process."""
    if not task.done():
        os.kill(os.getpid(), signal.SIGTERM)
    await asyncio.wait_for(task, 10)


async def test_daemon_run_serves_until_signalled(cluster: Cluster, sockdir: Path) -> None:
    cfg = (await cluster.node("seed")).config.with_overrides(
        data_dir=cluster.tmp / "run", api_socket=sockdir / "run.sock", keystore="file"
    )
    sock = sockdir / "run.sock"
    task = await _started(cfg)
    try:
        info = await asyncio.to_thread(ApiClient(cfg).request, "GET", "/v0/status")
        assert info["keystore"] == "file"
    finally:
        await _signalled(task)
    assert not sock.exists()


async def test_daemon_run_starts_the_a2a_adapter(cluster: Cluster, sockdir: Path) -> None:
    agent = AgentServer(HelloWorldExecutor(), "local")
    await agent.start()
    try:
        with reserved_port() as port:
            cfg = (await cluster.node("seed")).config.with_overrides(
                data_dir=cluster.tmp / "run-a2a",
                api_socket=sockdir / "a2a.sock",
                keystore="file",
                a2a_local_agent_url=agent.url,
                a2a_facade_port=port,
            )
            task = await _started(cfg)
        try:
            token_file = cfg.data_dir / "a2a-facade-token"
            assert token_file.stat().st_mode & 0o077 == 0
            token = token_file.read_text(encoding="ascii").strip()
            url = f"http://127.0.0.1:{port}/g/abc/.well-known/agent-card.json"
            async with httpx.AsyncClient() as http:
                card = await http.get(url, headers={"Authorization": f"Bearer {token}"})
            assert card.status_code == 200
        finally:
            await _signalled(task)
    finally:
        await agent.stop()


async def test_api_hardening(
    cluster: Cluster, sockdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = await serve(cluster, "h", sockdir, auto_approve=False)
    addr = str(api.server.address)
    monkeypatch.setattr("agentconnect.runtime.api.READ_TIMEOUT", 0.3)
    monkeypatch.setattr("agentconnect.runtime.api.MAX_CONNECTIONS", 1)
    # A client that never finishes its request is cut off (408)...
    reader, writer = await asyncio.open_unix_connection(addr)
    writer.write(b"GET /v0/status HTTP/1.1\r\n")
    await writer.drain()
    # ...and while it holds the only slot, others get 503.
    r2, w2 = await asyncio.open_unix_connection(addr)
    assert b" 503 " in await r2.read()
    w2.close()
    assert b" 408 " in await reader.read()
    writer.close()
    await api.server.stop()
    # The socket path must not be some other file.
    other = sockdir / "not-a-socket"
    other.write_text("keep me", encoding="utf-8")
    api.node.daemon.config = api.node.config.with_overrides(api_socket=other)
    with pytest.raises(FileExistsError, match="not a socket"):
        await ApiServer(api.node.daemon).start()
    assert other.read_text(encoding="utf-8") == "keep me"
    # Token files must stay private.
    token = api.node.config.data_dir / "api-token"
    token.chmod(0o644)
    with pytest.raises(PermissionError, match="0600"):
        ApiServer(api.node.daemon)


async def test_tcp_api_refuses_browser_requests(cluster: Cluster) -> None:
    node = await cluster.node("tcp")
    with reserved_port() as port:
        node.daemon.config = node.config.with_overrides(api_tcp_port=port)
        server = ApiServer(node.daemon)
        await server.start()
    auth = {"authorization": f"Bearer {api_token(server, 'agent')}"}
    async with httpx.AsyncClient(base_url=str(server.address)) as c:
        assert (await c.get("/v0/status", headers=auth)).status_code == 200
        bad_origin = {**auth, "origin": "https://evil.example"}
        assert (await c.get("/v0/status", headers=bad_origin)).status_code == 403
        rebound = {**auth, "host": "evil.example"}
        assert (await c.get("/v0/status", headers=rebound)).status_code == 403
    await server.stop()
