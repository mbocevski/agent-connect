"""The local control API over its Unix socket, and the CLI that reads it."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
import socket
import stat
import tempfile
from collections.abc import AsyncIterator, Callable
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
from agentconnect.runtime.api import MAX_PENDING, MAX_PENDING_HARD, ApiServer
from agentconnect_harness.a2a_agents import AgentServer, HelloWorldExecutor
from agentconnect_harness.cluster import WAIT, Cluster, Node, api_token
from agentconnect_harness.relay import on_free_port


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


async def until(predicate: Callable[[], bool]) -> None:
    """Poll (yielding to the loop): the server's connection handlers run
    on this loop and announce nothing."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


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
    assert "sas" not in info_a
    assert "sas" not in info_b
    assert {m["role"] for m in info_a["members"]} == {"owner", "member"}
    status, err = await alice.call("POST", f"/v0/groups/{gid}/members/{bob.node.me}/verify", {})
    assert status == 403
    path = f"/v0/groups/{gid}/members/{bob.node.me}/verify"
    status, err = await alice.call("POST", path, {"verified": True}, scope="human")
    assert (status, err["code"]) == (400, "bad_request")  # which run was compared?
    # The old answer for a group-wide code is refused, never mapped (SPEC 11.8).
    old = {"verified": True, "epoch": info_a["epoch"]}
    status, err = await alice.call("POST", path, old, scope="human")
    assert (status, err["code"]) == (400, "bad_request")
    # A SAS run: both humans start their side, the agent token can't.
    start_a = f"/v0/groups/{gid}/members/{bob.node.me}/sas"
    start_b = f"/v0/groups/{gid}/members/{alice.node.me}/sas"
    status, err = await alice.call("POST", start_a, {})
    assert (status, err["code"]) == (403, "human_only")
    status, run_a = await alice.call("POST", start_a, {}, scope="human")
    assert (status, run_a["state"]) == (200, "waiting")
    status, err = await alice.call("POST", start_a, {}, scope="human")
    assert (status, err["code"]) == (409, "conflict")  # one run per pair at a time
    status, run_b = await bob.call("POST", start_b, {}, scope="human")
    assert status == 200
    view = f"/v0/groups/{gid}/sas/runs/"

    async def done(caller: Any, run: str) -> dict[str, Any]:
        ended = ("done", "aborted")
        await caller.node.wait(lambda: caller.node.daemon.sas_run(gid, run)["state"] in ended)
        _, seen = await caller.call("GET", view + run, scope="human")
        return dict(seen)

    seen_a, seen_b = await done(alice, run_a["run"]), await done(bob, run_b["run"])
    assert seen_a["state"] == seen_b["state"] == "done"
    assert seen_a["sas"] == seen_b["sas"]
    assert seen_a["labels"] == {"self": seen_b["labels"]["peer"], "peer": seen_b["labels"]["self"]}
    status, err = await alice.call("GET", view + run_a["run"])
    assert (status, err["code"]) == (403, "human_only")
    status, err = await alice.call("POST", path, {"verified": True, "run": "nope"}, scope="human")
    assert (status, err["code"]) == (404, "not_found")
    shown = {"verified": True, "run": run_a["run"]}
    status, done_ = await alice.call("POST", path, shown, scope="human")
    assert done_ == {"verified": True}
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
        (
            "POST",
            "/v0/groups/x/messages",
            {"text": "t", "reply_to": "m"},
            "agent",
            400,
            "bad_request",
        ),
        (
            "POST",
            "/v0/groups/x/messages",
            {"text": "t", "addressee": [1]},
            "agent",
            400,
            "bad_request",
        ),
        (
            "POST",
            "/v0/groups/x/messages",
            {"text": "t", "instance": 5},
            "human",
            400,
            "bad_request",
        ),
        ("POST", "/v0/groups/x/invites", {"instance": 5}, "human", 400, "bad_request"),
        ("POST", "/v0/groups/x/messages", {"text": "t"}, "agent", 404, "not_found"),
        ("POST", "/v0/groups/x/members/y/verify", {"verified": "yes"}, "human", 400, "bad_request"),
        ("POST", "/v0/approvals/nope/approve", None, "human", 404, "not_found"),
        ("PUT", "/v0/groups/x/adapters", {"adapters": None}, "agent", 403, "human_only"),
        ("PUT", "/v0/groups/x/adapters", {"adapters": None}, "human", 404, "not_found"),
        ("PUT", "/v0/groups/x/adapters", {"adapters": "recording"}, "human", 400, "bad_request"),
        ("PUT", "/v0/groups/x/adapters", {}, "human", 400, "bad_request"),
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


async def test_the_human_pins_a_groups_adapters(cluster: Cluster, sockdir: Path) -> None:
    api = await serve(cluster, "p", sockdir, auto_approve=False)
    gid = api.node.daemon.create_group("Pins", "Adapters")
    await api.node.idle()
    path = f"/v0/groups/{gid}/adapters"
    status, out = await api.call("PUT", path, {"adapters": ["recording"]}, "human")
    assert (status, out) == (
        200,
        {"group_id": gid, "adapters": ["recording"], "delivers_to": ["recording"]},
    )
    status, info = await api.call("GET", f"/v0/groups/{gid}")
    assert (info["adapters"], info["delivers_to"]) == (["recording"], ["recording"])
    status, err = await api.call("PUT", path, {"adapters": ["webhook"]}, "human")
    assert (status, err["code"]) == (400, "bad_request")
    assert "webhook" in err["message"]
    status, err = await api.call("PUT", path, {"adapters": []}, "human")
    assert (status, err["code"]) == (400, "bad_request")
    status, out = await api.call("PUT", path, {"adapters": None}, "human")
    assert (status, out["adapters"], out["delivers_to"]) == (200, None, ["recording"])
    await api.server.stop()


async def test_api_checks_the_instance_hint(cluster: Cluster, sockdir: Path) -> None:
    """SPEC 9.4: an instance id, 16 lowercase hex, on a kind that triggers;
    either token. An id the group doesn't have is sent anyway."""
    api = await serve(cluster, "h", sockdir, auto_approve=False)
    gid = api.node.daemon.create_group("Hints", "Instance hints")
    await api.node.idle()
    path = f"/v0/groups/{gid}/messages"
    mine = api.node.daemon.instance.instance_id_hex
    for scope in ("agent", "human"):
        for bad in (5, "XYZ", "A" + mine[1:], mine[:15], mine + "\n"):
            status, err = await api.call("POST", path, {"text": "t", "instance": bad}, scope)
            assert (status, err["code"]) == (400, "bad_request"), bad
        body = {"messageId": "m", "parts": [{"text": "t"}], "metadata": {"instance": "XYZ"}}
        status, err = await api.call("POST", path, {"body": body}, scope)
        assert (status, err["code"]) == (400, "bad_request")
        pause = {"body": {"reason": "human"}, "kind": "control.pause", "instance": mine}
        status, err = await api.call("POST", path, pause, scope)
        assert (status, err["code"]) == (400, "bad_request")
        nobody = "0" * 16 if mine != "0" * 16 else "1" * 16
        status, sent = await api.call("POST", path, {"text": "t", "instance": nobody}, scope)
        assert (status, sent["status"]) == (200, "queued")
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


async def _tcp_api(node: Node, port: int) -> ApiServer:
    node.daemon.config = node.config.with_overrides(api_tcp_port=port)
    server = ApiServer(node.daemon)
    await server.start()
    return server


async def test_api_over_loopback_tcp_and_cli_status(cluster: Cluster) -> None:
    node = await cluster.node("t")
    server = await on_free_port(lambda port: _tcp_api(node, port))
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
        seed = (await cluster.node("seed")).config

        async def run(port: int) -> tuple[Config, asyncio.Task[None]]:
            cfg = seed.with_overrides(
                data_dir=cluster.tmp / "run-a2a",
                api_socket=sockdir / "a2a.sock",
                keystore="file",
                a2a_local_agent_url=agent.url,
                a2a_facade_port=port,
            )
            return cfg, await _started(cfg)

        cfg, task = await on_free_port(run)
        port = cfg.a2a_facade_port
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
    monkeypatch.setattr("agentconnect.runtime.api.HEADER_TIMEOUT", 0.3)
    monkeypatch.setattr("agentconnect.runtime.api.MAX_PENDING", 1)
    monkeypatch.setattr("agentconnect.runtime.api.EVICT_AFTER", 0)
    reader, writer = await asyncio.open_unix_connection(addr)
    writer.write(b"GET /v0/status HTTP/1.1\r\n")
    await writer.drain()
    await until(lambda: len(api.server._pending) == 1)
    # A connection that hasn't sent its request yet gives way to a new one
    # when no room is left (503)...
    r2, w2 = await asyncio.open_unix_connection(addr)
    w2.write(b"GET /v0/status HTTP/1.1\r\n")
    await w2.drain()
    assert b" 503 " in await reader.read()
    writer.close()
    # ...and one that doesn't send its headers in time is cut off (408).
    assert b" 408 " in await r2.read()
    w2.close()
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
    server = await on_free_port(lambda port: _tcp_api(node, port))
    auth = {"authorization": f"Bearer {api_token(server, 'agent')}"}
    async with httpx.AsyncClient(base_url=str(server.address)) as c:
        assert (await c.get("/v0/status", headers=auth)).status_code == 200
        bad_origin = {**auth, "origin": "https://evil.example"}
        assert (await c.get("/v0/status", headers=bad_origin)).status_code == 403
        rebound = {**auth, "host": "evil.example"}
        assert (await c.get("/v0/status", headers=rebound)).status_code == 403
    await server.stop()


# More half-sent connections than any limit: more than MAX_CONNECTIONS was.
HALF_OPEN = 80


@pytest.mark.parametrize("over", ["unix", "tcp"])
async def test_half_sent_connections_dont_keep_the_human_out(
    cluster: Cluster, sockdir: Path, over: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Connections that never finish their request (no token yet) can't
    take the capacity a request with a token needs: a human-token request
    and an agent-token request still get through, on the Unix socket and
    on loopback TCP. (Each has waited long enough to give way.)"""
    monkeypatch.setattr("agentconnect.runtime.api.EVICT_AFTER", 0)
    if over == "tcp":
        node = await cluster.node("half-tcp")
        server = await on_free_port(lambda port: _tcp_api(node, port))
        port = int(str(server.address).rsplit(":", 1)[1])
        transport = httpx.AsyncHTTPTransport()
        base, host = str(server.address), f"127.0.0.1:{port}"

        async def connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection("127.0.0.1", port)

    else:
        api = await serve(cluster, "half", sockdir, auto_approve=False)
        server = api.server
        transport, base, host = api.transport, "http://ac", "ac"

        async def connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_unix_connection(str(server.address))

    held = []
    try:
        for _ in range(HALF_OPEN):
            reader, writer = await connect()
            writer.write(f"GET /v0/status HTTP/1.1\r\nhost: {host}\r\n".encode())
            await writer.drain()
            held.append((reader, writer))
        await until(lambda: server._connections == min(HALF_OPEN, MAX_PENDING))
        async with httpx.AsyncClient(transport=transport, base_url=base) as c:
            for scope in ("human", "agent", "human"):
                auth = {"authorization": f"Bearer {api_token(server, scope)}"}
                resp = await c.get("/v0/status", headers=auth)
                assert resp.status_code == 200, (scope, resp.text)
        # The oldest unfinished ones were closed to make room, with a 503.
        reader, _ = held[0]
        assert b" 503 " in await reader.read()
    finally:
        for _, writer in held:
            writer.close()
        await server.stop()


def whole_request(host: str, token: str, path: str = "/v0/status") -> bytes:
    return f"GET {path} HTTP/1.1\r\nhost: {host}\r\nauthorization: Bearer {token}\r\n\r\n".encode()


async def status_of(sock: socket.socket) -> bytes:
    """The status code the server answered on ``sock``, once it closed."""
    loop = asyncio.get_running_loop()
    sock.setblocking(False)
    data = b""
    try:
        while chunk := await asyncio.wait_for(loop.sock_recv(sock, 65536), WAIT):
            data += chunk
    except ConnectionResetError:
        return b"reset"
    finally:
        sock.close()
    return data.split(b" ", 2)[1] if data else b"closed"


async def listener(cluster: Cluster, sockdir: Path, over: str) -> tuple[ApiServer, Any, str]:
    """An API server on the Unix socket or loopback TCP, a function making
    blocking connections to it, and the Host its requests name."""
    if over == "tcp":
        node = await cluster.node("tcp")
        server = await on_free_port(lambda port: _tcp_api(node, port))
        port = int(str(server.address).rsplit(":", 1)[1])
        return server, lambda: socket.create_connection(("127.0.0.1", port)), f"127.0.0.1:{port}"
    api = await serve(cluster, "unix", sockdir, auto_approve=False)

    def connect() -> socket.socket:
        s = socket.socket(socket.AF_UNIX)
        s.connect(str(api.server.address))
        return s

    return api.server, connect, "ac"


@pytest.mark.parametrize("n", [12, 24, 40, 60])
@pytest.mark.parametrize("over", ["unix", "tcp"])
async def test_requests_that_arrive_together_all_get_through(
    cluster: Cluster, sockdir: Path, over: str, n: int
) -> None:
    """Whole requests that arrive together, as an SDK's parallel calls do,
    are all answered: a connection whose headers arrived never gives way,
    and the server reads what has arrived before it closes anything."""
    server, connect, host = await listener(cluster, sockdir, over)
    token = api_token(server, "agent")
    socks = []
    try:
        for _ in range(n):  # blocking: all of them are in before the loop runs
            s = connect()
            s.sendall(whole_request(host, token))
            socks.append(s)
        statuses = await asyncio.gather(*(status_of(s) for s in socks))
        assert statuses == [b"200"] * n
    finally:
        for s in socks:
            s.close()
        await server.stop()


@pytest.mark.parametrize("burst", [MAX_PENDING - 1, MAX_PENDING, 40])
async def test_connects_behind_a_whole_request_dont_close_it(
    cluster: Cluster, sockdir: Path, burst: int
) -> None:
    """Loopback TCP, where any local user can connect: with the pool full
    of half-sent connections, the human's whole request is answered even
    when bare connects land right behind it."""
    server, connect, host = await listener(cluster, sockdir, "tcp")
    held: list[socket.socket] = []
    try:
        for _ in range(MAX_PENDING):
            s = connect()
            s.sendall(b"GET /v0/status HTTP/1.1\r\n")
            held.append(s)
        await until(lambda: len(server._pending) == MAX_PENDING)
        human = connect()
        human.sendall(whole_request(host, api_token(server, "human")))
        for _ in range(burst):  # the kernel completes them before the loop runs
            held.append(connect())
        assert await status_of(human) == b"200"
    finally:
        for s in held:
            s.close()
        await server.stop()


async def test_a_connection_that_sent_nothing_gives_way_first(
    cluster: Cluster, sockdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the limit, an unfinished connection that has sent nothing is
    closed before an older one that has sent part of its request, and only
    once it has waited EVICT_AFTER."""
    server, connect, host = await listener(cluster, sockdir, "unix")
    held: list[socket.socket] = []
    try:
        partial = connect()
        partial.sendall(f"GET /v0/status HTTP/1.1\r\nhost: {host}\r\n".encode())
        held.append(partial)
        await until(lambda: len(server._pending) == 1 and server._pending[0].started)
        for _ in range(MAX_PENDING - 1):
            held.append(connect())
        await until(lambda: len(server._pending) == MAX_PENDING)
        held.append(connect())  # none has waited long enough: let in over the limit
        await until(lambda: len(server._pending) == MAX_PENDING + 1)
        monkeypatch.setattr("agentconnect.runtime.api.EVICT_AFTER", 0)
        held.append(connect())
        assert await status_of(held[1]) == b"503"  # the oldest that sent nothing
        partial.sendall(f"authorization: Bearer {api_token(server, 'human')}\r\n\r\n".encode())
        assert await status_of(partial) == b"200"
    finally:
        for s in held:
            s.close()
        await server.stop()


@pytest.mark.parametrize("burst", [1, 2, 8])
async def test_past_the_hard_limit_a_stalled_connection_goes_not_a_fresh_one(
    cluster: Cluster, sockdir: Path, burst: int
) -> None:
    """Loopback TCP with the pool at its hard limit, every connection having
    sent a byte and stalled. The human's whole request arrives with bare
    connects right behind it: each new connection closes the oldest
    stalled one, never the fresh request whose first byte isn't read yet."""
    server, connect, host = await listener(cluster, sockdir, "tcp")
    held: list[socket.socket] = []
    try:
        for i in range(MAX_PENDING_HARD):
            s = connect()
            s.sendall(b"G")
            held.append(s)
            if i % 32 == 31:
                await until(lambda n=i + 1: len(server._pending) >= n)
        await until(
            lambda: (
                len(server._pending) == MAX_PENDING_HARD and all(p.started for p in server._pending)
            )
        )
        human = connect()
        human.sendall(whole_request(host, api_token(server, "human")))
        for _ in range(burst):  # the kernel completes them before the loop runs
            held.append(connect())
        assert await status_of(human) == b"200"
        for s in held[: burst + 1]:  # the oldest stalled ones gave way
            assert await status_of(s) == b"503"
    finally:
        for s in held:
            s.close()
        await server.stop()


async def test_a_refused_requests_body_is_read_before_the_answer(
    cluster: Cluster, sockdir: Path
) -> None:
    """A request refused at its headers (here: a wrong token) still has its
    body read, so the answer reaches the client instead of a reset."""
    server, connect, host = await listener(cluster, sockdir, "unix")
    body = b"{" + b" " * 300_000 + b"}"
    s = connect()
    try:
        s.sendall(
            f"POST /v0/groups HTTP/1.1\r\nhost: {host}\r\nauthorization: Bearer wrong\r\n"
            f"content-length: {len(body)}\r\n\r\n".encode()
        )
        loop = asyncio.get_running_loop()
        s.setblocking(False)
        await asyncio.wait_for(loop.sock_sendall(s, body), WAIT)
        assert await status_of(s) == b"401"
    finally:
        s.close()
        await server.stop()
