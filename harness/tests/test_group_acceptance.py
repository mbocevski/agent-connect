"""Group mode acceptance on the real relay (docs/groups.md), on both hosts:
mention mode with a two-agent loop (harness scenario 7), a fork in a group
of five (scenario 13), and one group's whole life through the CLI, the
local API, the SDK and the A2A adapter."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.adapter import Delivery
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.relay import b64, unb64
from agentconnect.runtime.engine import new_msg_id
from agentconnect_harness.a2a_agents import AgentServer, HelloWorldExecutor, a2a_node
from agentconnect_harness.cli import run_cli
from agentconnect_harness.cluster import (
    WAIT,
    Cluster,
    Node,
    converged,
    group_state,
    status,
    unpaired,
    verify,
)
from agentconnect_harness.proxy import RelayProxy
from agentconnect_sdk import AgentConnect, Message

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Proxy = Callable[[Node], RelayProxy]


async def until(predicate: Callable[[], bool]) -> None:
    """Poll what no runtime announces (an adapter's or a proxy's record),
    yielding to the loop: a node's wait wakes only on the runtimes' change
    pulses."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def data(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e.data for e in node.adapter.unique_events() if e.type == kind]


def got(node: Node, msg_id: str) -> Delivery | None:
    return next((d for d in node.adapter.deliveries if d.msg_id == msg_id), None)


async def heard(nodes: list[Node], msg_id: str) -> list[tuple[bool, int]]:
    """Wait until every node has ``msg_id``: whether it triggered each one,
    and the hop each one read, in the order of ``nodes``."""
    out = []
    for n in nodes:
        await until(lambda n=n: got(n, msg_id) is not None)
        d = got(n, msg_id)
        assert d is not None
        out.append((d.addressed_to_me, d.hop))
    return out


def controls(node: Node, kind: str, sender: Node) -> list[Delivery]:
    return [d for d in node.adapter.deliveries if d.kind == kind and d.sender.identity == sender.me]


async def say(node: Node, gid: str, text: str, to: list[str], reply_to: str | None = None) -> str:
    """The node's agent sends ``text`` (``AgentApi.send``)."""
    answer = await node.runtime.agent.send(
        gid, text=text, to=to, reply_to=None if reply_to is None else [reply_to]
    )
    assert answer["status"] == "queued"
    return str(answer["msg_id"])


# -- scenario 7 --------------------------------------------------------------------------------


async def test_mention_mode_unaddressed_does_not_trigger_and_a_two_agent_loop_pauses(
    group: GroupFixture,
) -> None:
    """Three members in ``mention`` mode: an agent broadcast triggers nobody;
    a and b address each other with replies and c only ever gets context.
    Past ``max_agent_turns`` the receivers aren't triggered, each tells its
    human once (``loop_guard``) and sends one ``control.pause``, until a
    human's ``control.resume``."""
    nodes, gid = await group(3, invite="multi")
    a, b, c = nodes
    assert a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 3}) == "committing"
    await converged(nodes, gid)
    assert a.daemon.group_info(gid)["floor"]["mode"] == "mention"  # switched at three

    # An agent's broadcast triggers nobody in mention mode (SPEC 9.3).
    hello = await say(a, gid, "anyone?", ["*"])
    assert await heard([b, c], hello) == [(False, 1), (False, 1)]

    t1 = await say(a, gid, "t1", [b.me])
    assert await heard([b, c], t1) == [(True, 1), (False, 1)]
    t2 = await say(b, gid, "t2", [a.me], reply_to=t1)
    assert await heard([a, c], t2) == [(True, 2), (False, 2)]
    t3 = await say(a, gid, "t3", [b.me], reply_to=t2)
    assert await heard([b, c], t3) == [(True, 3), (False, 3)]
    # hop 4 > 3: a is addressed but not triggered. a and c, which both
    # received it, each pause the group once and tell their humans.
    t4 = await say(b, gid, "t4", [a.me], reply_to=t3)
    assert await heard([a, c], t4) == [(False, 4), (False, 4)]
    for n in (a, c):
        await until(lambda n=n: bool(data(n, "loop_guard")))
        assert data(n, "loop_guard") == [
            {"msg_id": t4, "sender": b.me, "hop": 4, "max_agent_turns": 3}
        ]
    for sender, others in ((a, (b, c)), (c, (a, b))):
        for n in others:
            await until(lambda n=n, s=sender: bool(controls(n, "control.pause", s)))
            (pause,) = controls(n, "control.pause", sender)
            assert pause.body == {"reason": "loop_guard"}
            assert pause.inner["reply_to"] == [t4]
            assert (pause.origin, pause.addressed_to_me) == ("agent", False)

    # a's agent answers anyway: b, addressed, isn't triggered either, and
    # every member has told its human exactly once.
    t5 = await say(a, gid, "t5", [b.me], reply_to=t4)
    assert await heard([b, c], t5) == [(False, 5), (False, 5)]
    await until(lambda: bool(data(b, "loop_guard")))
    # b's pause is sent once b has told its human; an empty outbox at b means
    # it left, not that it reached a and c through the relay.
    for n in (a, c):
        await until(lambda n=n: bool(controls(n, "control.pause", b)))
    for n in nodes:
        await n.idle()
    assert [len(data(n, "loop_guard")) for n in nodes] == [1, 1, 1]
    assert [len(controls(n, "control.pause", b)) for n in (a, c)] == [1, 1]
    assert not [d for d in c.adapter.deliveries if d.addressed_to_me]

    # A human resumes: the next agent turn is fresh and triggers again.
    a.daemon.send_message(gid, {}, kind="control.resume", origin="human")
    for n in (b, c):
        await until(lambda n=n: bool(controls(n, "control.resume", a)))
    again = await say(a, gid, "after resume", [b.me])
    assert await heard([b, c], again) == [(True, 1), (False, 1)]
    assert not [d for d in c.adapter.deliveries if d.addressed_to_me]


# -- scenario 13 -------------------------------------------------------------------------------


async def test_fork_in_a_five_member_group_shows_in_sas_runs(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    """The relay forks a group of five: b's commit reaches only a, and the
    others' commits never reach a and b. Each side agrees on its own view,
    and the two sides' views differ, also once both are at the same epoch
    number. A SAS run within a side gives both humans the same code; a run
    across the fork never pairs: the humans comparing codes catch it (SPEC
    11, 12)."""
    nodes, gid = await group(5)
    a, b, c, d, e = nodes
    minority, majority = [a, b], [c, d, e]
    await converged(nodes, gid)
    epoch = a.epoch(gid)
    shared = a.state(gid)

    for n in minority:
        malicious_relay(n).drop_deliveries(lambda env: env.get("kind") == "commit")
    fork = malicious_relay(b)
    fork.fork_own_commits()
    b.daemon.update(gid)
    await until(lambda: len(fork.forked) == 1)
    await malicious_relay(a).inject({"t": "deliver", "env": fork.forked[0]["env"]})
    await converged(minority, gid)
    await converged(majority, gid)
    assert [n.epoch(gid) for n in nodes] == [epoch + 1, epoch + 1, epoch, epoch, epoch]
    assert a.state(gid) == b.state(gid) != shared == c.state(gid) == d.state(gid) == e.state(gid)

    # The majority moves on through the real relay: the same epoch number on
    # both sides now, and still two codes.
    c.daemon.update(gid)
    await converged(majority, gid)
    assert {n.epoch(gid) for n in nodes} == {epoch + 1}
    assert group_state(a, gid) != group_state(c, gid)
    assert a.state(gid) == b.state(gid) != c.state(gid) == d.state(gid) == e.state(gid)
    # What each side's agents were told: the new epoch, and no code.
    for side in (minority, majority):
        for n in side:
            changed = data(n, "epoch_changed")[-1]
            assert changed["epoch"] == epoch + 1
            assert "sas" not in changed
    # Within a side the codes agree; across the fork the runs never pair.
    await verify(a, b, gid)
    await verify(c, d, gid)
    await unpaired(a, c, gid)
    for n in nodes:
        assert not data(n, "unauthorized_commit")


# -- the whole life of a group of five ----------------------------------------------------------

# The events a step must report, to the human and to the agent alike. Any of
# these that a step doesn't expect fails it (a commit_failed, say).
TRACKED = frozenset(
    {
        "pending_approval",
        "joined",
        "member_joined",
        "instance_joined",
        "member_leaving",
        "member_left",
        "member_removed",
        "instance_left",
        "instance_removed",
        "left",
        "removed",
        "leave_blocked",
        "policy_changed",
        "role_changed",
        "floor_changed",
        "commit_failed",
        "unauthorized_commit",
        "out_of_sync",
        "relay_misbehaviour",
        "invite_flooded",
        "loop_guard",
    }
)
Seen = tuple[str, str]


def seen(kind: str, data: dict[str, Any]) -> Seen:
    """An event as a step expects it: ``policy_changed`` by the fields it
    changed, ``joined`` and ``pending_approval`` without what is random."""
    if kind == "policy_changed":
        before, after = data["previous_policy"], data["policy"]
        changed = {k: v for k, v in after.items() if before.get(k) != v}
        data = {"changes": changed, "by": data["by"], "roles_known": data["roles_known"]}
    elif kind == "joined":
        data = {"invite_id": data["invite_id"]}
    elif kind == "pending_approval":
        keep = ("identity", "display_name", "identity_requests")
        data = {k: data[k] for k in keep}
    return kind, json.dumps(data, sort_keys=True)


@dataclass(eq=False)
class Member:
    """One member's node, with the CLI its human (and agent) runs and how
    far each of them has read the events."""

    node: Node
    config: Path
    human_after: int = 0
    agent_after: int = 0
    recorded: int = 0

    @property
    def me(self) -> str:
        return self.node.me

    @property
    def instance(self) -> str:
        return self.node.daemon.instance.instance_id_hex

    def _invoke(self, args: list[str], input: str | None) -> tuple[int, str]:
        result = run_cli([*args, "--config", str(self.config)], input=input)
        return result.exit_code, result.stdout

    async def cli(self, *args: str, input: str | None = None) -> Any:
        """``agentconnect <args> --json``: the JSON it printed last. It must
        succeed."""
        code, out = await asyncio.to_thread(self._invoke, [*args, "--json"], input)
        assert code == 0, (args, out)
        return json.loads(out.strip().splitlines()[-1])

    async def human(self, gid: str) -> list[Seen]:
        """The group's events the human hasn't read yet (``agentconnect
        events``, the human token)."""
        code, out = await asyncio.to_thread(
            self._invoke, ["events", "--json", "--after", str(self.human_after)], None
        )
        assert code == 0, out
        events = [json.loads(line) for line in out.strip().splitlines()]
        if events:
            self.human_after = int(events[-1]["seq"])
        return [
            seen(e["type"], e["data"])
            for e in events
            if e["group_id"] == gid and e["type"] in TRACKED
        ]

    async def api(
        self, method: str, path: str, body: dict[str, Any] | None = None, *, human: bool = False
    ) -> Any:
        """A local API request with the agent's token, or the human's."""
        client = ApiClient(self.node.config, human=human)
        return await asyncio.to_thread(client.request, method, path, body)

    async def agent(self, gid: str) -> list[Seen]:
        """The group's events the agent hasn't read yet (``GET /v0/events``,
        the agent token)."""
        page = (await self.api("GET", f"/v0/events?after={self.agent_after}&group={gid}"))["events"]
        if page:
            self.agent_after = int(page[-1]["seq"])
        return [seen(e["type"], e["data"]) for e in page if e["type"] in TRACKED]

    def adapter(self, gid: str) -> list[Seen] | None:
        """What the node's adapter was told since the last step, if the
        group delivers to it (an A2A node's group delivers to its agent)."""
        if self.node.adapter.name not in self.node.daemon.adapter_names(gid):
            return None
        events = self.node.adapter.unique_events()
        new, self.recorded = events[self.recorded :], len(events)
        return [seen(e.type, e.data) for e in new if e.group_id == gid and e.type in TRACKED]

    def pending(self, gid: str) -> int:
        """Tracked events recorded for the group past what the human read."""
        return len(
            [
                e
                for e in self.node.daemon.store.events(after=self.human_after, limit=10_000)
                if e["group_id"] == gid and e["type"] in TRACKED
            ]
        )

    @contextlib.asynccontextmanager
    async def sdk(self) -> AsyncGenerator[AgentConnect]:
        """The agent's SDK client: the embedded host's own, or one attached
        to the daemon's local API."""
        if self.node.sdk is not None:
            yield self.node.sdk
            return
        client = AgentConnect.attach(data_dir=self.node.config.data_dir, config_path=self.config)
        try:
            yield client
        finally:
            await client.aclose()


async def member(cluster: Cluster, node: Node) -> Member:
    """A config.toml for the node's CLI (its local API on the socket in its
    data directory); what its adapter was told so far counts as read."""
    path = cluster.tmp / f"{node.name}.toml"
    path.write_text(
        f'[relay]\nurl = "{node.config.relay_url}"\n'
        f'[daemon]\ndata_dir = "{node.config.data_dir}"\nkeystore = "file"\n',
        encoding="utf-8",
    )
    m = Member(node, path)
    m.recorded = len(node.adapter.unique_events())
    return m


Expect = list[tuple[str, dict[str, Any]]]


async def saw(gid: str, expected: dict[Member, Expect]) -> None:
    """Every member's human and agent (and its adapter, when the group
    delivers to it) saw exactly the expected events since the last step."""
    for m, events in expected.items():
        want = sorted(seen(kind, d) for kind, d in events)
        n = len(want)
        await m.node.wait(lambda m=m, n=n: m.pending(gid) >= n)
        await m.node.idle()
        assert sorted(await m.human(gid)) == want, m.node.name
        assert sorted(await m.agent(gid)) == want, m.node.name
        if (recorded := m.adapter(gid)) is not None:
            if len(recorded) < len(want):
                await until(lambda m=m: len(m.node.adapter.unique_events()) > m.recorded)
                recorded += m.adapter(gid) or []
            assert sorted(recorded) == want, m.node.name


def forged_request(stale: dict[str, Any], url: str, name: str) -> bytes:
    """A link holder wraps a KeyPackage it saw elsewhere (a JoinRequest its
    victim sent to the holder's own invite) in a JoinRequest for ``url``,
    under a name of its choice: it holds the link, so it can compute the MAC
    (docs/groups.md#multi-use-invites-and-approvals)."""
    link = ac.parse_invite_url(url)
    request = json.loads(unb64(stale["env"]["ct"]))
    kp = unb64(request["key_package"])
    mac = ac.join_request_mac(link.invite_id, link.secret_bytes(), kp, request["mailbox_id"], name)
    request |= {"invite_id": link.invite_id_b64, "display_name": name, "mac": b64(mac)}
    return json.dumps(request, sort_keys=True, separators=(",", ":")).encode()


def deliveries(node: Node, msg_id: str) -> list[Delivery]:
    return [d for d in node.adapter.deliveries if d.msg_id == msg_id]


def a2a_messages(node: Node, sender: Node) -> list[str]:
    return [
        d.msg_id
        for d in node.adapter.deliveries
        if d.kind == "a2a.message" and d.sender.identity == sender.me
    ]


def role(
    identity: str, before: str, after: str, by: str, moderator: tuple[bool, bool] = (False, False)
) -> tuple[str, dict[str, Any]]:
    return (
        "role_changed",
        {
            "identity": identity,
            "from": before,
            "to": after,
            "moderator_from": moderator[0],
            "moderator_to": moderator[1],
            "by": by,
        },
    )


def policy(by: str, **changes: Any) -> tuple[str, dict[str, Any]]:
    return (
        "policy_changed",
        {"previous_policy": {}, "policy": changes, "by": by, "roles_known": True},
    )


async def test_a_group_of_five_lives_through_every_change_and_converges(
    cluster: Cluster,
) -> None:
    """One group's whole life through the public surfaces: the humans use
    the CLI and the local API, the agents the SDK (attached to the daemon,
    or embedded) and the A2A adapter. Each step checks what every member's
    human and agent were told."""
    executor = HelloWorldExecutor()
    server = AgentServer(executor, "moderator")
    await server.start()
    try:
        await lifecycle(cluster, server, executor)
    finally:
        await server.stop()


async def lifecycle(  # noqa: PLR0915
    cluster: Cluster, server: AgentServer, executor: HelloWorldExecutor
) -> None:
    a = await member(cluster, await cluster.node("a", auto_approve=False, serve_api=True))
    # b's group messages go to a local A2A agent.
    b = await member(cluster, await a2a_node(cluster, "b", server, serve_api=True))
    c, d, e = [await member(cluster, await cluster.node(n, serve_api=True)) for n in "cde"]
    mallory = await cluster.node("mallory", auto_approve=False)

    # 1. a's human creates a group with a policy (the human token: it isn't
    # the default one).
    options = ("--purpose", "Ship the release", "--remove", "admins", "--max-members", "6")
    made = await a.cli("group", "create", *options)
    gid = made["group_id"]
    shown = await a.cli("groups", "show", gid)
    assert shown["policy_summary"] == {
        "invite": "owner",
        "remove": "admins",
        "max_members": 6,
        "max_agent_turns": 20,
    }
    assert shown["floor"] == {
        "mode": "free",
        "pinned": False,
        "moderator": None,
        "effective_moderator": a.me,
        "holder": None,
    }
    await saw(gid, {a: []})

    # 2. a's agent creates one invite for four joiners; joins need a human.
    invite = await a.cli("invite", "create", "--group", gid, "--max-uses", "4")
    assert (invite["max_uses"], invite["replica"]) == (4, False)
    url = invite["url"]
    await saw(gid, {a: []})

    # 3. Four agents redeem it. Mallory holds the link too, and a KeyPackage
    # of b's that b sent to her own invite: she sends it in b's name, from
    # her own mailbox, and a drops it (SPEC 6.2 step 3). The human approves
    # the four.
    bait_group = mallory.daemon.create_group("Bait", "A link b's agent was given")
    await mallory.idle()
    bait = await mallory.daemon.create_invite(bait_group)
    async with b.sdk() as sdk:
        assert (await sdk.accept(bait["url"], "bob"))["status"] == "pending"

    def stale_of_b() -> dict[str, Any] | None:
        return next(
            (
                f
                for f in mallory.proxy.delivered
                if f["env"].get("kind") == "join_request"
                and f["env"]["sender"] == b.node.daemon.mailbox
            ),
            None,
        )

    await until(lambda: stale_of_b() is not None)
    for i, (m, name) in enumerate(((b, "bob"), (c, "carol"), (d, "dave"), (e, "erin")), 1):
        async with m.sdk() as sdk:
            assert (await sdk.accept(url, name))["status"] == "pending"
        await a.node.wait(lambda i=i: len(a.node.daemon.approvals()) == i)
    stale = stale_of_b()
    assert stale is not None
    msg_id = new_msg_id()
    env = {
        "v": 0,
        "kind": "join_request",
        "msg_id": msg_id,
        "sender": mallory.daemon.mailbox,
        "ct": b64(forged_request(stale, url, "bob (laptop)")),
    }
    link = ac.parse_invite_url(url)
    mallory.daemon._enqueue(
        "frame",
        None,
        {"frame": {"t": "join", "invite_id": link.invite_id_b64, "env": env}, "msg_id": msg_id},
    )
    await a.node.wait(
        lambda: a.node.daemon.store.inbox_state(mallory.daemon.mailbox, msg_id) is not None
    )
    listed = (await a.cli("approvals", "list"))["approvals"]
    claims = {x["display_name"]: x for x in listed}
    assert sorted(claims) == ["bob", "carol", "dave", "erin"]
    assert claims["bob"]["identity"] == b.me
    assert [claims[n]["identity_requests"] for n in sorted(claims)] == [1, 1, 1, 1]
    for name in ("bob", "carol", "dave", "erin"):
        approved = await a.cli("approvals", "approve", claims[name]["request_id"], "--yes")
        assert (approved["status"], approved["group_id"]) == ("approving", gid)
    founders = [a, b, c, d, e]
    await converged([m.node for m in founders], gid)
    joins = [
        ("member_joined", {"identity": m.me, "instances": [m.instance], "by": a.me})
        for m in (b, c, d, e)
    ]
    switch = [
        policy(a.me, floor="mention"),
        (
            "floor_changed",
            {
                "mode": "mention",
                "moderator": None,
                "effective_moderator": a.me,
                "holder": None,
                "by": a.me,
                "reason": "policy",
            },
        ),
    ]
    requested = [
        ("pending_approval", {"identity": m.me, "display_name": n, "identity_requests": k})
        for m, n, k in (
            (b, "bob", 1),
            (c, "carol", 1),
            (d, "dave", 1),
            (e, "erin", 1),
        )
    ]
    welcomed = [("joined", {"invite_id": invite["invite_id"]})]
    await saw(
        gid,
        {
            a: requested + joins + switch,
            b: welcomed + joins[1:] + switch,
            c: welcomed + joins[2:],
            d: welcomed + joins[3:],
            e: welcomed,
        },
    )
    assert b.node.daemon.store.group(bait_group) is None  # mallory never let b in
    # b's group goes to its A2A agent; the others' to the recording adapter,
    # whose events `saw` checks too.
    assert [m.node.adapter.name in m.node.daemon.adapter_names(gid) for m in founders] == [
        True,
        False,
        True,
        True,
        True,
    ]

    # 4. The humans compare short codes, a pair at a time (SPEC 11): b's
    # human runs `agentconnect verify` with each other member while that
    # member's human starts the other side; a's verifies c alone, through the
    # API, where the old answer naming an epoch is refused.
    for other in (a, c, d, e):
        verifying = asyncio.ensure_future(b.cli("verify", gid, other.me, input="y\ny\n"))
        await b.node.wait(lambda: bool(b.node.daemon.sas._active))
        other.node.daemon.sas_start(gid, b.me)
        verified = await verifying
        assert (verified["outcome"], verified["verified"]) == ("verified", [other.me])
    shown = await a.cli("groups", "show", gid)
    run = await a.api("POST", f"/v0/groups/{gid}/members/{c.me}/sas", {}, human=True)
    c.node.daemon.sas_start(gid, a.me)
    await a.node.wait(lambda: a.node.daemon.sas_run(gid, run["run"])["state"] == "done")
    path = f"/v0/groups/{gid}/members/{c.me}/verify"
    with pytest.raises(ApiClientError) as refused:
        await a.api("POST", path, {"epoch": shown["epoch"]}, human=True)
    assert (refused.value.status, refused.value.code) == (400, "bad_request")
    assert await a.api("POST", path, {"run": run["run"]}, human=True) == {"verified": True}
    shown = await a.cli("groups", "show", gid)
    assert shown["verified_summary"] == "1 of 4 verified"
    assert {m["identity"] for m in shown["members"] if m["verified"]} == {c.me}
    assert (await b.cli("groups", "show", gid))["verified_summary"] == "4 of 4 verified"
    await saw(gid, {m: [] for m in founders})  # verifying is the human's alone: no event

    # 5. c's human provisions a replica on another host: export the identity
    # from the stopped runtime, import it into an empty data directory, and
    # add it with a replica invite pinned to the new instance.
    await c.node.stop()
    await asyncio.wait_for(c.node.proxy.wait_no_sessions(), WAIT)
    export = cluster.tmp / "c.export"
    made = await c.cli("identity", "export", "--out", str(export))
    assert made["identity"] == c.me
    await c.node.start()
    replica_dir = cluster.tmp / "c2"
    replica_config = cluster.tmp / "c2.toml"
    replica_config.write_text(
        f'[relay]\nurl = "{c.node.config.relay_url}"\n'
        f'[daemon]\ndata_dir = "{replica_dir}"\nkeystore = "file"\n',
        encoding="utf-8",
    )
    importer = Member(c.node, replica_config)  # the CLI only, on the new directory
    imported = await importer.cli("identity", "import", str(export), input=made["code"] + "\n")
    assert imported["identity"] == c.me
    c2 = await member(cluster, await cluster.node("c2", data_dir=replica_dir, serve_api=True))
    assert (c2.me, c2.instance) == (c.me, imported["instance_id"])
    replica = await c.cli(
        "invite", "create", "--group", gid, "--replica", "--instance", c2.instance
    )
    assert (replica["replica"], replica["instance"]) == (True, c2.instance)
    async with c2.sdk() as sdk:
        assert (await sdk.accept(replica["url"]))["status"] == "pending"
    everyone = [*founders, c2]
    await converged([m.node for m in everyone], gid)
    new_instance = ("instance_joined", {"identity": c.me, "instance_id": c2.instance, "by": c.me})
    # c's daemon approved the pinned request itself (auto_approve is on).
    asked_in = (
        "pending_approval",
        {"identity": c.me, "display_name": "c2", "identity_requests": 1},
    )
    await saw(
        gid,
        {m: [new_instance] for m in founders}
        | {c: [asked_in, new_instance], c2: [("joined", {"invite_id": replica["invite_id"]})]},
    )
    # a's human verified c before it had this instance: it shows as new.
    (shown_c,) = [
        m for m in (await a.cli("groups", "show", gid))["members"] if m["identity"] == c.me
    ]
    assert shown_c["verified"] is True
    assert {i["instance_id"]: i["new_since_verified"] for i in shown_c["instances"]} == {
        c.instance: False,
        c2.instance: True,
    }

    # 6. a's human makes b an admin.
    changed = await a.cli("group", "role", gid, b.me, "admin")
    assert (changed["role"], changed["status"]) == ("admin", "committing")
    await converged([m.node for m in everyone], gid)
    made_admin = [policy(a.me, admins=[b.me]), role(b.me, "member", "admin", a.me)]
    await saw(gid, {m: made_admin for m in everyone})

    # 7. a's human switches the floor to moderated with b as the moderator,
    # and b's agent gives the floor to c.
    changed = await a.cli("group", "policy", gid, "--floor", "moderated", "--moderator", b.me)
    assert changed["status"] == "committing"
    await converged([m.node for m in everyone], gid)

    def floor(holder: str | None, by: str, reason: str) -> tuple[str, dict[str, Any]]:
        return (
            "floor_changed",
            {
                "mode": "moderated",
                "moderator": b.me,
                "effective_moderator": b.me,
                "holder": holder,
                "by": by,
                "reason": reason,
            },
        )

    moderated = [
        policy(a.me, floor="moderated", floor_pinned=True, floor_moderator=b.me),
        role(b.me, "admin", "admin", a.me, moderator=(False, True)),
        floor(None, a.me, "policy"),
    ]
    await saw(gid, {m: moderated for m in everyone})
    granted = await b.cli("group", "floor", gid, c.me)
    assert (granted["holder"], granted["status"]) == (c.me, "granted")
    await converged([m.node for m in everyone], gid)
    await saw(gid, {m: [floor(c.me, b.me, "grant")] for m in everyone})

    # 8. Messages to one instance. a's agent writes to c's new replica: only
    # it is triggered, though c holds the floor and b moderates.
    sent = await a.cli("send", gid, "ship it", "--to", c.me, "--instance", c2.instance)
    hinted = sent["msg_id"]
    for m, triggered in ((c2, True), (c, False), (d, False), (e, False)):
        await until(lambda m=m: bool(deliveries(m.node, hinted)))
        (got_it,) = deliveries(m.node, hinted)
        assert got_it.addressed_to_me is triggered, m.node.name
        assert got_it.body["metadata"]["instance"] == c2.instance
    # The replica asks the moderator, whose A2A agent answers that instance
    # alone: the reply names it, and c's other instance gets it as context.
    async with c2.sdk() as sdk:
        asked = await sdk.group(gid).send("status?", to=[b.me])
    (request,) = await executor.wait_for(1)
    assert request.context_id == gid
    # In a moderated group `to` doesn't pick: the moderator and the holder's
    # instances are triggered, except the sender's own (c's other instance
    # gets its replica's question as context, SR-35), nobody else.
    for m, triggered in ((c, False), (a, False), (d, False), (e, False)):
        await until(lambda m=m: bool(deliveries(m.node, asked)))
        assert [x.addressed_to_me for x in deliveries(m.node, asked)] == [triggered], m.node.name
    for m, triggered in ((c2, True), (c, False), (a, False), (d, False), (e, False)):
        await until(
            lambda m=m: any(d.inner.get("reply_to") == [asked] for d in m.node.adapter.deliveries)
        )
        (answer,) = [d for d in m.node.adapter.deliveries if d.inner.get("reply_to") == [asked]]
        assert answer.sender.identity == b.me
        assert answer.addressed_to_me is triggered, m.node.name
        assert answer.inner["addressee"] == [c.me]
        assert answer.body["metadata"]["instance"] == c2.instance
    assert len(executor.received) == 1  # a's hinted message didn't trigger b
    await saw(gid, {m: [] for m in everyone})

    # 9. a's human changes the policy: admins may invite, and fewer agent turns.
    changed = await a.cli("group", "policy", gid, "--invite", "admins", "--max-agent-turns", "12")
    assert changed["status"] == "committing"
    await converged([m.node for m in everyone], gid)
    retuned = [policy(a.me, invite="admins", loop_guard={"max_agent_turns": 12})]
    await saw(gid, {m: retuned for m in everyone})

    # 10. a's human hands the group over to d and stays an admin.
    handed = await a.cli("group", "transfer", gid, d.me, "--yes")
    assert (handed["keep_admin"], handed["status"]) == (True, "committing")
    await converged([m.node for m in everyone], gid)
    transferred = [
        policy(a.me, owner=d.me, admins=[b.me, a.me]),
        role(a.me, "owner", "admin", a.me),
        role(d.me, "member", "owner", a.me),
    ]
    await saw(gid, {m: transferred for m in everyone})

    # 11. c's human removes the replica again; b, an admin, removes e; and a
    # leaves, now that it isn't the owner. The owner drops a's admin role.
    removed = await c.cli("remove", gid, c.me, "--instance", c2.instance, "--yes")
    assert (removed["status"], removed["instances"]) == ("removing", [c2.instance])
    await c2.node.wait(lambda: status(c2.node, gid) == "removed")
    await converged([m.node for m in founders], gid)
    gone_instance = ("instance_removed", {"identity": c.me, "instance_id": c2.instance, "by": c.me})
    await saw(gid, {m: [gone_instance] for m in founders} | {c2: [("removed", {"by": c.me})]})

    removed = await b.cli("remove", gid, e.me, "--yes")
    assert removed["status"] == "removing"
    await e.node.wait(lambda: status(e.node, gid) == "removed")
    staying = [a, b, c, d]
    await converged([m.node for m in staying], gid)
    gone_member = ("member_removed", {"identity": e.me, "by": b.me})
    await saw(gid, {m: [gone_member] for m in staying} | {e: [("removed", {"by": b.me})]})

    left = await a.cli("leave", gid)
    assert left["status"] == "leaving"
    await a.node.wait(lambda: status(a.node, gid) == "left")
    rest = [b, c, d]
    await converged([m.node for m in rest], gid)
    # The lowest leaf that isn't leaving commits it: b's (a's is the lowest).
    leaving = [
        ("member_leaving", {"identity": a.me, "instance_id": a.instance}),
        ("member_left", {"identity": a.me, "by": b.me}),
        policy(d.me, admins=[b.me]),
        role(a.me, "admin", "member", d.me),
    ]
    await saw(gid, {m: leaving for m in rest} | {a: [("left", {"confirmed": True, "by": b.me})]})

    # 12. c restarts while d's agent is sending: every message reaches it
    # once, in order, and each triggers it (it holds the floor).
    async def send(i: int) -> str:
        async with d.sdk() as sdk:
            return await sdk.group(gid).send(f"m{i}")

    stream = [await send(i) for i in range(2)]
    await until(lambda: a2a_messages(c.node, d.node) == stream)
    await c.node.stop()
    await asyncio.wait_for(c.node.proxy.wait_no_sessions(), WAIT)
    stream += [await send(i) for i in range(2, 4)]
    await d.node.idle()
    await c.node.start()
    stream += [await send(i) for i in range(4, 6)]
    await until(lambda: len(a2a_messages(c.node, d.node)) >= len(stream))
    await c.node.wait(lambda: c.node.daemon.status()["inbox_pending"] == 0)
    assert a2a_messages(c.node, d.node) == stream
    assert all(the.addressed_to_me for i in stream for the in deliveries(c.node, i))
    if c.node.sdk is not None:
        handled = [
            x.msg_id for x in c.node.handled if isinstance(x, Message) and x.msg_id in stream
        ]
        assert handled == stream
    # The moderator's agent was asked each one too, and answered d's
    # instance, which isn't triggered: d neither moderates nor holds the floor.
    await executor.wait_for(1 + len(stream))
    for msg_id in stream:
        await until(
            lambda i=msg_id: any(x.inner.get("reply_to") == [i] for x in d.node.adapter.deliveries)
        )
        (answer,) = [x for x in d.node.adapter.deliveries if x.inner.get("reply_to") == [msg_id]]
        assert answer.sender.identity == b.me
        assert (answer.inner["addressee"], answer.body["metadata"]["instance"]) == (
            [d.me],
            d.instance,
        )
        assert answer.addressed_to_me is False
    assert len(executor.received) == 1 + len(stream)
    await saw(gid, {m: [] for m in rest})

    # 13. Every member left agrees on everything.
    await converged([m.node for m in rest], gid)
    views = [await m.cli("groups", "show", gid) for m in rest]
    assert len({v["epoch"] for v in views}) == 1
    assert all("sas" not in v for v in views)
    for v in views:
        assert sorted((x["identity"], x["role"]) for x in v["members"]) == sorted(
            [(b.me, "admin"), (c.me, "member"), (d.me, "owner")]
        )
        assert v["floor"] == {
            "mode": "moderated",
            "pinned": True,
            "moderator": b.me,
            "effective_moderator": b.me,
            "holder": c.me,
        }
        assert v["policy_summary"] == {
            "invite": "admins",
            "remove": "admins",
            "max_members": 6,
            "max_agent_turns": 12,
        }
        assert v["pending_leaves"] == []
