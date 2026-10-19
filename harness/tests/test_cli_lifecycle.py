"""The `agentconnect` invite lifecycle end to end: real relay, real daemons,
the CLI talking to each daemon's local API."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import pytest_asyncio
from typer.testing import CliRunner

from agentconnect import cli_support
from agentconnect.cli import app
from agentconnect.runtime.api import ApiServer
from agentconnect_harness.cluster import Cluster, Node, status
from agentconnect_harness.proxy import RelayProxy
from agentconnect_harness.relay import on_free_port

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
runner = CliRunner()


@dataclass
class Cli:
    """Runs `agentconnect ...` against one node's daemon."""

    node: Node
    config: str

    def run_sync(
        self,
        *args: str,
        input: str | None = None,
        stdout_only: bool = False,
    ) -> tuple[int, str]:
        # Ids are base64url and may start with "-"; the commands read them
        # as ids wherever they are (cli_support.IdArgsCommand), like a user
        # typing them would.
        argv = [*args, "--config", self.config]
        result = runner.invoke(app, argv, input=input)
        if result.exception and not isinstance(result.exception, SystemExit):
            raise result.exception
        return result.exit_code, result.stdout if stdout_only else result.output

    async def run(self, *args: str, input: str | None = None) -> tuple[int, str]:
        return await asyncio.to_thread(self.run_sync, *args, input=input)

    async def json(self, *args: str, input: str | None = None) -> tuple[int, Any]:
        code, out = await asyncio.to_thread(
            self.run_sync, *args, "--json", input=input, stdout_only=True
        )
        assert out.strip(), (args, code)
        return code, json.loads(out.strip().splitlines()[-1])


@pytest_asyncio.fixture
async def serve() -> AsyncIterator[Callable[[Node], Awaitable[Cli]]]:
    servers: list[ApiServer] = []

    async def start(node: Node) -> Cli:
        async def tcp_api(port: int) -> ApiServer:
            node.daemon.config = node.config.with_overrides(api_tcp_port=port)
            server = ApiServer(node.daemon)
            await server.start()
            return server

        server = await on_free_port(tcp_api)
        servers.append(server)
        cfg = node.config.data_dir / "config.toml"
        cfg.write_text(
            f'[relay]\nurl = "{node.config.relay_url}"\n'
            f'[daemon]\ndata_dir = "{node.config.data_dir}"\n'
            f"[api]\ntcp_port = {node.daemon.config.api_tcp_port}\n",
            encoding="utf-8",
        )
        return Cli(node, str(cfg))

    yield start
    for s in servers:
        await s.stop()


def host_of(url: str) -> str:
    return url.split("/")[2]


async def test_two_daemons_create_accept_approve_verify_send_leave(  # noqa: PLR0915
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]], monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = asyncio.get_running_loop()
    alice = await serve(await cluster.node("alice", auto_approve=False))
    bob = await serve(await cluster.node("bob", auto_approve=False))

    code, made = await alice.json("invite", "create", "--purpose", "Deploys", "--max-uses", "1")
    assert code == 0
    gid = made["group_id"]
    assert made["url"].startswith("http")
    assert "different channel" in made["reminder"]
    await alice.node.idle()

    steps: list[str] = []

    def inviter_side(_seconds: float) -> None:
        """While bob waits: alice's human approves, then bob's join completes."""
        if steps:
            return
        steps.append("approved")
        asyncio.run_coroutine_threadsafe(
            alice.node.wait(lambda: len(alice.node.daemon.approvals()) == 1), loop
        ).result(10)
        code, listed = alice.run_sync("approvals", "--json", stdout_only=True)
        assert code == 0
        (req,) = json.loads(listed)["approvals"]
        assert req["display_name"] == "bob"
        assert req["fingerprint"]
        assert "group_sas" not in req  # no group-wide code (SPEC 11)
        code, _ = alice.run_sync("approvals", "approve", req["request_id"], "--yes")
        assert code == 0
        asyncio.run_coroutine_threadsafe(
            bob.node.wait(
                lambda: any(e["type"] == "joined" for e in bob.node.daemon.store.events())
            ),
            loop,
        ).result(10)

    monkeypatch.setattr(cli_support, "pause", inviter_side)
    code, joined = await bob.json("accept", made["url"], "--yes")
    assert code == 0, joined
    assert joined["status"] == "joined"
    assert joined["group_id"] == gid
    assert joined["name"] == "Deploys"
    assert joined["hint"].startswith("ask your human to compare the short code ")
    assert "sas" not in joined
    await cluster.settle(gid, 1)
    monkeypatch.setattr(cli_support, "pause", time.sleep)

    # Verifying is a human, interactive step on both sides at once (SPEC 11):
    # a SAS run, the same code and mirrored labels, and each human's answer.
    code, shown = await alice.json("groups", "show", gid)
    assert code == 0
    assert "sas" not in shown
    assert shown["verified_summary"] == "0 of 1 verified"
    assert {m["role"] for m in shown["members"]} == {"owner", "member"}
    # (One CLI at a time in this process: bob's human takes the API's side.)
    verifying = asyncio.ensure_future(alice.run("verify", gid, input="y\ny\n"))
    await alice.node.wait(lambda: bool(alice.node.daemon.sas._active))
    run_b = bob.node.daemon.sas_start(gid, alice.node.me)["run"]
    code, out = await verifying
    assert code == 0, out
    assert "read the same two instance labels? [y/N]" in out
    assert "read exactly this code? [y/N]" in out
    seen_b = bob.node.daemon.sas_run(gid, run_b)
    assert seen_b["sas"]["decimal"] in out  # the same code on both screens
    assert f"yours {seen_b['labels']['peer']}, theirs {seen_b['labels']['self']}" in out
    bob.node.daemon.mark_verified(gid, alice.node.me, True, run_b)
    code, shown = await alice.json("groups", "show", gid)
    assert (shown["verified_summary"], shown["hint"]) == ("1 of 1 verified", None)

    code, _sent = await alice.json("send", gid, "hello bob")
    assert code == 0
    assert await bob.node.wait_texts(gid, 1) == ["hello bob"]
    code, _ = await bob.run("groups")
    assert code == 0

    code, left = await bob.json("leave", gid)
    assert (code, left["status"]) == (0, "leaving")
    await alice.node.wait(
        lambda: bob.node.me not in {m.identity for m in alice.node.daemon.store.members(gid)}
    )
    assert status(bob.node, gid) in {"left", "active"}


async def test_a_used_invite_raises_the_interception_warning(
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    (a, _b), gid = await cluster.group(2)
    alice = await serve(a)
    mallory = await serve(await cluster.node("mallory"))
    # `cluster.group` redeemed its own invite; make one more and use it up.
    code, made = await alice.json("invite", "create", f"--group={gid}")
    assert code == 0
    joiner = await serve(await cluster.node("carol"))
    code, _ = await joiner.json("accept", made["url"], "--yes", "--wait", "0")
    assert code == 0
    await joiner.node.wait(lambda: joiner.node.daemon.store.group(gid) is not None)
    await cluster.settle(gid, 2)
    code, out = await mallory.run("accept", made["url"], "--yes")
    assert code == 4
    assert "may have been intercepted" in out
    code, err = await mallory.json("accept", made["url"], "--yes")
    assert (code, err["error"]["code"]) == (4, "invite_not_open")


async def test_a_revoked_invite_raises_the_same_warning(
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    alice = await serve(await cluster.node("alice"))
    bob = await serve(await cluster.node("bob"))
    code, made = await alice.json("invite", "create", "--purpose", "Temp")
    assert code == 0
    assert (await alice.json("invite", "revoke", made["invite_id"]))[1] == {
        "revoked": made["invite_id"]
    }
    code, out = await bob.run("accept", made["url"], "--yes")
    assert code == 4
    assert "may have been intercepted" in out


async def test_an_invite_for_another_relay_is_refused_before_anything_is_sent(
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    alice = await serve(await cluster.node("alice"))
    bob = await serve(await cluster.node("bob"))
    _, made = await alice.json("invite", "create", "--purpose", "Elsewhere")
    other = made["url"].replace("http://" + host_of(made["url"]), "https://other.example", 1)
    code, out = await bob.run("accept", other, "--yes")
    assert code == 3
    assert "different relay" in out
    code, refused = await bob.json("accept", other, "--yes")
    assert (code, refused["error"]["code"]) == (3, "wrong_relay")
    assert bob.node.daemon.store.pending_joins() == []


async def test_reject_leaves_the_joiner_out(
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    alice = await serve(await cluster.node("alice", auto_approve=False))
    bob = await serve(await cluster.node("bob"))
    _, made = await alice.json("invite", "create", "--purpose", "Closed")
    await alice.node.idle()
    code, pending = await bob.json("accept", made["url"], "--yes", "--wait", "0")
    assert (code, pending["status"]) == (0, "pending")
    await alice.node.wait(lambda: len(alice.node.daemon.approvals()) == 1)
    _, listed = await alice.json("approvals", "list")
    (req,) = listed["approvals"]
    code, rejected = await alice.json("approvals", "reject", req["request_id"])
    assert (code, rejected["status"]) == (0, "rejected")
    assert (await alice.json("approvals"))[1] == {"approvals": [], "messages": []}
    assert (await bob.json("groups"))[1] == {"groups": []}


async def test_verify_cannot_start_without_the_human_token_file(
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    (a, _b), gid = await cluster.group(2)
    alice = await serve(a)
    (a.config.data_dir / "human-token").unlink()
    code, err = await alice.json("verify", gid, input="y\n")
    assert code == 5  # no human token on disk: the command can't even start
    assert err["error"]["code"] == "daemon_unreachable"


async def test_verify_no_leaves_and_reports_the_owner_handover(
    group: GroupFixture, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    (a, b, _c), gid = await group(3)
    alice = await serve(a)
    verifying = asyncio.ensure_future(alice.json("verify", gid, b.me, input="y\nn\n"))
    await a.wait(lambda: bool(a.daemon.sas._active))
    b.daemon.sas_start(gid, a.me)  # b's human starts the other side
    code, out = await verifying
    assert code == 6
    assert out["outcome"] == "mismatch"
    assert out["ownership_transfer"] == {
        "new_owner": b.me,
        "confirmed": True,
        "new_owner_name": "n1",
    }
    assert status(a, gid) == "left"


async def test_verify_no_after_a_fork_for_a_plain_member(
    group: GroupFixture,
    serve: Callable[[Node], Awaitable[Cli]],
    malicious_relay: Callable[[Node], RelayProxy],
) -> None:
    """A forked view shows as a run that never pairs (SPEC 12): here the
    relay refuses the forked member's messages, the run ends unpaired, and
    the human, told the daemons may not see the same group, treats it as
    different codes."""
    (a, _b, c), gid = await group(3)
    cli_c = await serve(c)
    malicious_relay(c).fork_own_commits()
    c.daemon.update(gid)
    await c.wait(lambda: c.epoch(gid) == a.epoch(gid) + 1)
    assert c.state(gid) != a.state(gid)
    a.daemon.sas_start(gid, c.me)
    code, out = await cli_c.json("verify", gid, a.me, input="y\n")
    assert (code, out["status"], out["ownership_transfer"]) == (6, "left", None)
    assert status(c, gid) == "left"
    code, listed = await cli_c.json("groups")
    assert listed["groups"][0]["status"] == "left"


async def test_policy_route_only_tightens_for_agents(
    group: GroupFixture, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    (a, _b), gid = await group(2)
    cli = await serve(a)
    port = a.daemon.config.api_tcp_port

    def post(token_file: str, value: bool) -> int:
        token = (a.config.data_dir / token_file).read_text(encoding="ascii").strip()
        resp = httpx.post(
            f"http://127.0.0.1:{port}/v0/groups/{gid}/policy",
            json={"require_verified": value},
            headers={"authorization": f"Bearer {token}"},
        )
        return resp.status_code

    assert await asyncio.to_thread(post, "api-token", True) == 200
    await a.idle()
    code, shown = await cli.json("groups", "show", gid)
    assert (code, shown["require_verified"]) == (0, True)
    assert await asyncio.to_thread(post, "api-token", False) == 403
    assert await asyncio.to_thread(post, "human-token", False) == 200
    await a.idle()
    assert (await cli.json("groups", "show", gid))[1]["require_verified"] is False


async def test_invite_create_require_verified_sets_the_policy(
    cluster: Cluster, serve: Callable[[Node], Awaitable[Cli]]
) -> None:
    alice = await serve(await cluster.node("alice"))
    code, made = await alice.json("invite", "create", "--purpose", "Strict", "--require-verified")
    assert (code, made["require_verified"]) == (0, True)
    await alice.node.idle()
    code, shown = await alice.json("groups", "show", made["group_id"])
    assert shown["require_verified"] is True
