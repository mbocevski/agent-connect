"""SAS runs (SPEC 11.3, 11.5, 11.7) between real daemons on the real relay.

A malicious member is a node whose ceremony messages the test writes itself
(:class:`Crafted`): sealed by its own core, so the receivers authenticate
them as that member's, exactly as an attacker's would be.
"""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.relay import b64, unb64
from agentconnect.runtime.engine import DaemonError, new_msg_id
from agentconnect.runtime.sas import (
    BUDGET,
    RUN_TIMEOUT_SECS,
    SAME_WINDOW_SECS,
    SAS_CANCEL,
    SAS_COMMIT,
    SAS_EVENTS,
    SAS_KINDS,
    SAS_REVEAL,
    UNPAIRED_NOTICE_SECS,
    UPDATE_DEFER_SECS,
    Run,
)
from agentconnect.store import SAS_RESET_NOTICE, SAS_RUN_MARKER, Store
from agentconnect_harness.cluster import Cluster, Node, compare, unpaired, verify
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]
ENDED = ("done", "aborted")


class Crafted:
    """A member that writes its own ceremony messages (an attacker's)."""

    def __init__(self, node: Node, rng: random.Random) -> None:
        self.node, self.rng = node, rng

    @property
    def me(self) -> str:
        return self.node.me

    @property
    def instance(self) -> int:
        return int(self.node.daemon.instance.instance_id_hex, 16)

    def nonce(self) -> bytes:
        return self.rng.randbytes(32)

    def send(self, gid: str, kind: str, body: dict[str, Any], to: list[str]) -> None:
        d = self.node.daemon
        inner = d.inner(kind, body, to, origin="human", hop=0)
        d._enqueue("app", gid, {"inner": inner, "msg_id": new_msg_id()})

    def commit(self, gid: str, peer: str, nonce: bytes, epoch: int | None = None) -> bytes:
        e = self.node.epoch(gid) if epoch is None else epoch
        c = bytes(ac.sas_commitment(unb64(gid), e, self.me, self.instance, peer, nonce))
        self.send(gid, SAS_COMMIT, {"commitment": b64(c), "epoch": e, "peer": peer}, [peer])
        return c

    def cancel(self, gid: str, peer: str, commitment: bytes) -> None:
        body = {"commitment": b64(commitment), "epoch": self.node.epoch(gid)}
        self.send(gid, SAS_CANCEL, body, [peer])

    def reveal(self, gid: str, peer: str, answers: bytes, nonce: bytes) -> None:
        body = {"answers": b64(answers), "epoch": self.node.epoch(gid), "nonce": b64(nonce)}
        self.send(gid, SAS_REVEAL, body, [peer])


async def moved_on(nodes: list[Node], gid: str, epoch: int) -> None:
    """Wait until every node is past ``epoch``."""
    await nodes[0].wait(lambda: all(n.epoch(gid) > epoch for n in nodes))


def run(node: Node, run_id: str) -> Run:
    return node.daemon.sas._runs[run_id]


def view(node: Node, gid: str, run_id: str) -> dict[str, Any]:
    return node.daemon.sas_run(gid, run_id)


async def ended(node: Node, gid: str, run_id: str) -> dict[str, Any]:
    await node.wait(lambda: view(node, gid, run_id)["state"] in ENDED)
    return view(node, gid, run_id)


def events(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e["data"] for e in node.daemon.store.events(limit=10_000) if e["type"] == kind]


async def started(node: Node, gid: str, peer: str) -> str:
    """Start a run and wait until its commitment is out (relay accepted)."""
    run_id = str(node.daemon.sas_start(gid, peer)["run"])
    await node.wait(lambda: run(node, run_id).commit_accepted)
    return run_id


# -- the messages themselves ---------------------------------------------------------------


async def test_a_reveal_that_doesnt_open_its_commitment_aborts(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node), gid = await group(2)
    m = Crafted(m_node, rng)
    run_id = await started(a, gid, m.me)
    nonce = m.nonce()
    m.commit(gid, a.me, nonce)
    await a.wait(lambda: run(a, run_id).revealed)
    assert view(a, gid, run_id)["state"] == "exchanging"
    m.reveal(gid, a.me, run(a, run_id).commitment or b"", m.nonce())  # another nonce
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"]) == ("bad_reveal", True)
    assert "sas" not in seen


async def test_a_reveal_before_its_commitment_aborts(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node), gid = await group(2)
    m = Crafted(m_node, rng)
    run_id = await started(a, gid, m.me)
    m.reveal(gid, a.me, run(a, run_id).commitment or b"", m.nonce())
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"]) == ("out_of_order", True)
    assert not run(a, run_id).revealed  # its nonce never went out


async def test_old_epochs_and_old_runs_never_pair_or_complete(
    group: GroupFixture, rng: random.Random, advance: Advance
) -> None:
    (a, m_node, b), gid = await group(3)
    m = Crafted(m_node, rng)
    # A commitment whose body names another epoch than the one it was sealed in.
    first = await started(a, gid, m.me)
    m.commit(gid, a.me, m.nonce(), epoch=a.epoch(gid) - 1)
    await m.node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    assert view(a, gid, first)["state"] == "waiting"
    # A reveal answering an earlier run's commitment in the same epoch: ignored.
    old_commitment = run(a, first).commitment or b""
    await advance(RUN_TIMEOUT_SECS + 1)  # the first run times out
    assert (await ended(a, gid, first))["reason"] == "timed_out"
    second = await started(a, gid, m.me)
    m.reveal(gid, a.me, old_commitment, m.nonce())
    await m.node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    assert view(a, gid, second)["state"] == "waiting"
    # A held commitment of epoch e is gone once the epoch ends (b's restart
    # in the new epoch sends a new one).
    b_run = await started(b, gid, a.me)
    await a.wait(lambda: bool(a.daemon.sas._held))
    epoch = a.epoch(gid)
    b.daemon.update(gid)
    await moved_on([a, b], gid, epoch)
    await b.wait(lambda: view(b, gid, b_run)["reason"] == "epoch_changed")
    await a.wait(lambda: all(h.epoch == epoch + 1 for h in a.daemon.sas._held.values()))


async def test_a_commit_before_the_reveal_restarts_after_it_warns(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node, b), gid = await group(3)
    m = Crafted(m_node, rng)
    # Before a's reveal: no warning, a new run with a fresh nonce.
    first = await started(a, gid, m.me)
    commitment = run(a, first).commitment
    b.daemon.update(gid)
    await a.wait(lambda: view(a, gid, first)["state"] == "aborted")
    seen = view(a, gid, first)
    assert (seen["reason"], seen["warning"], seen["committer"]) == ("epoch_changed", False, b.me)
    assert seen["next"] is not None
    second = str(seen["next"])
    await a.wait(lambda: run(a, second).commit_accepted)
    assert run(a, second).commitment != commitment
    assert run(a, second).epoch == a.epoch(gid)
    # After a's reveal: a warning naming the committer, and no restart.
    await m_node.wait(lambda: m_node.epoch(gid) == a.epoch(gid))
    m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: run(a, second).revealed)
    m_node.daemon.update(gid)  # m withholds its reveal and commits instead
    seen = await ended(a, gid, second)
    assert (seen["reason"], seen["warning"], seen["committer"]) == ("epoch_changed", True, m.me)
    assert seen["next"] is None
    await a.wait(lambda: any(e["run"] == second for e in events(a, "sas_aborted")))
    (told,) = [e for e in events(a, "sas_aborted") if e["run"] == second]
    assert (told["committer"], told["warning"]) == (m.me, True)


async def test_a_second_commitment_after_the_reveal_is_never_answered(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node), gid = await group(2)
    m = Crafted(m_node, rng)
    run_id = await started(a, gid, m.me)
    first = m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: run(a, run_id).revealed)
    second = m.commit(gid, a.me, m.nonce())
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"]) == ("peer_restarted", True)
    epoch = a.epoch(gid)
    assert a.daemon.store.sas_answered(gid, epoch, first)
    assert not a.daemon.store.sas_answered(gid, epoch, second)


async def test_commitments_for_other_members_are_ignored(group: GroupFixture) -> None:
    """B compares with A and with C at once: neither run aborts, nobody is
    prompted for a run that isn't theirs."""
    (a, b, c), gid = await group(3)
    with_a = b.daemon.sas_start(gid, a.me)["run"]
    with_c = b.daemon.sas_start(gid, c.me)["run"]
    await b.idle()
    await a.wait(lambda: len(a.daemon.sas._held) == 1)
    await c.wait(lambda: len(c.daemon.sas._held) == 1)
    for node in (a, c):
        await node.wait(lambda n=node: bool(events(n, "sas_requested")))
        (prompt,) = events(node, "sas_requested")
        assert prompt["peer"] == b.me
    a_run = a.daemon.sas_start(gid, b.me)["run"]
    c_run = c.daemon.sas_start(gid, a.me)["run"]  # c compares with a meanwhile
    c_b = c.daemon.sas_start(gid, b.me)["run"]
    for node, run_id in ((b, with_a), (b, with_c), (a, a_run), (c, c_b)):
        assert (await ended(node, gid, run_id))["state"] == "done"
    assert view(b, gid, with_a)["sas"] == view(a, gid, a_run)["sas"]
    assert view(b, gid, with_c)["sas"] == view(c, gid, c_b)["sas"]
    assert view(c, gid, c_run)["state"] == "waiting"  # a never started its side
    assert len(events(c, "sas_requested")) == 1
    assert not events(a, "sas_aborted")
    assert not events(b, "sas_aborted")


# -- answers -------------------------------------------------------------------------------


async def test_differ_is_always_acted_on(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    run_a, _ = await compare(a, b, gid)
    epoch = a.epoch(gid)
    c.daemon.update(gid)  # the epoch moves on after the code was shown
    await moved_on([a, c], gid, epoch)
    assert await a.daemon.sas_mismatch(gid, run_a["run"]) == "left"
    assert events(a, "sas_mismatch")[-1]["run"] == run_a["run"]


async def test_same_for_another_member_records_nothing(group: GroupFixture) -> None:
    """Regression: "same" naming another member than the run's peer is
    refused before anything is recorded."""
    (a, b, c), gid = await group(3)
    run_a, _ = await compare(a, b, gid)
    with pytest.raises(DaemonError) as other:
        a.daemon.mark_verified(gid, c.me, True, run_a["run"])
    assert other.value.code == "bad_request"
    assert not [m for m in a.daemon.store.members(gid) if m.verified]
    a.daemon.mark_verified(gid, b.me, True, run_a["run"])  # still answerable
    assert {m.identity for m in a.daemon.store.members(gid) if m.verified} == {b.me}


async def test_same_within_600_s_also_after_an_epoch_change(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b, c), gid = await group(3)
    run_a, _ = await compare(a, b, gid)
    epoch = a.epoch(gid)
    c.daemon.update(gid)
    await moved_on([a, b, c], gid, epoch)
    a.daemon.mark_verified(gid, b.me, True, run_a["run"])
    assert {m.identity: m.verified for m in a.daemon.store.members(gid)}[b.me]
    # Too late.
    run_a, _ = await compare(a, c, gid)
    assert run_a["state"] == "done"
    await advance(SAME_WINDOW_SECS + 1)
    with pytest.raises(DaemonError) as late:
        a.daemon.mark_verified(gid, c.me, True, run_a["run"])
    assert late.value.code == "stale_epoch"
    # A newer run with the peer ends the window of the earlier one.
    run_a, _ = await compare(a, c, gid)
    a.daemon.sas_start(gid, c.me)
    with pytest.raises(DaemonError) as superseded:
        a.daemon.mark_verified(gid, c.me, True, run_a["run"])
    assert superseded.value.code == "stale_epoch"


async def test_two_warnings_stop_and_the_count_survives_a_restart(
    group: GroupFixture, rng: random.Random, advance: Advance
) -> None:
    (a, m_node, b), gid = await group(3)
    m = Crafted(m_node, rng)
    for _ in range(2):
        run_id = await started(a, gid, m.me)
        m.reveal(gid, a.me, run(a, run_id).commitment or b"", m.nonce())  # out_of_order
        assert (await ended(a, gid, run_id))["warning"]
    seen = view(a, gid, run_id)
    assert (seen["warnings"], seen["stopped"]) == (2, True)
    assert "attacker in the middle" in seen["stop_text"]
    assert "ordinary commit by another member" in seen["stop_text"]
    await a.wait(lambda: bool(events(a, "sas_stopped")))
    with pytest.raises(DaemonError) as stopped:
        a.daemon.sas_start(gid, m.me)
    assert stopped.value.code == "sas_stopped"
    # (m still holds a's last commitment, which no cancel message withdraws:
    # let it expire, as a human would wait before trying again.)
    await advance(RUN_TIMEOUT_SECS + 1)
    await m_node.wait(lambda: not m_node.daemon.sas._held)
    await a.restart()
    assert a.daemon.store.sas_warnings(gid, m.me)[0] == 2
    with pytest.raises(DaemonError):
        a.daemon.sas_start(gid, m.me)
    # Acknowledged, a run goes ahead; a confirmed one resets the count.
    a.daemon.sas_start(gid, m.me, acknowledge=True)
    m_node.daemon.sas_start(gid, a.me)
    await a.wait(lambda: any(r.state == "done" for r in a.daemon.sas._runs.values()))
    done = next(r for r in a.daemon.sas._runs.values() if r.state == "done")
    a.daemon.mark_verified(gid, m.me, True, done.run_id)
    assert a.daemon.store.sas_warnings(gid, m.me) == (0, [])
    assert a.daemon.store.sas_warnings(gid, b.me) == (0, [])


async def test_an_unpaired_run_reports_a_possible_fork(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    run_id = await started(a, gid, b.me)
    assert not view(a, gid, run_id)["unpaired"]
    await advance(UNPAIRED_NOTICE_SECS + 1)
    await a.wait(lambda: view(a, gid, run_id)["unpaired"])
    assert "don't see the same group" in view(a, gid, run_id)["unpaired_text"]
    assert events(a, "sas_unpaired")
    a.daemon.sas_peer_started(gid, run_id)
    await advance(RUN_TIMEOUT_SECS)
    seen = await ended(a, gid, run_id)
    # Told the peer had started, a run that never paired is a warning.
    assert (seen["reason"], seen["warning"]) == ("timed_out", True)


async def test_a_held_commitment_expires(group: GroupFixture, advance: Advance) -> None:
    (a, b), gid = await group(2)
    await started(b, gid, a.me)
    await a.wait(lambda: bool(a.daemon.sas._held))
    await advance(RUN_TIMEOUT_SECS + 1)
    await a.wait(lambda: not a.daemon.sas._held)


async def test_one_run_per_pair_of_identities_and_labels(cluster: Cluster) -> None:
    (a, b), gid = await cluster.group(2)
    a2 = await cluster.node(identity_of=a)
    await cluster.invite(a, a2, gid)
    await started(a, gid, b.me)
    await a2.wait(lambda: bool(a2.daemon.sas._siblings))
    with pytest.raises(DaemonError) as sibling:
        a2.daemon.sas_start(gid, b.me)
    assert sibling.value.code == "conflict"
    with pytest.raises(DaemonError) as self_run:
        a2.daemon.sas_start(gid, a.me)
    assert self_run.value.code == "bad_request"
    b_run = b.daemon.sas_start(gid, a.me, instance=a.daemon.instance.instance_id_hex)["run"]
    seen_b = await ended(b, gid, b_run)
    assert seen_b["labels"] == {
        "self": b.daemon.instance.instance_id_hex[:8],
        "peer": a.daemon.instance.instance_id_hex[:8],
    }
    assert seen_b["peer_instance"] == a.daemon.instance.instance_id_hex


# -- interaction with the instance's own sends ------------------------------------------------


def make_update_due(node: Node, gid: str) -> None:
    node.daemon.store.update_group(gid, last_own_commit_at=0)
    row = node.daemon.store.group(gid)
    assert row is not None
    assert node.daemon.groups.update_due(row)


async def test_ceremony_sends_never_trigger_the_cadence_update(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    make_update_due(a, gid)
    epoch = a.epoch(gid)
    run_a, run_b = await compare(a, b, gid)
    assert run_a["state"] == run_b["state"] == "done"
    assert a.epoch(gid) == epoch


async def test_a_due_update_is_deferred_at_most_600_s(
    group: GroupFixture, advance: Advance, rng: random.Random
) -> None:
    (a, b, m_node), gid = await group(3)
    m = Crafted(m_node, rng)
    epoch = a.epoch(gid)
    make_update_due(a, gid)
    # A held commitment doesn't defer it.
    m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: bool(a.daemon.sas._held))
    a.daemon.send_message(gid, {"text": "one"})
    await a.wait(lambda: a.epoch(gid) == epoch + 1)
    make_update_due(a, gid)
    # A run under way does, for 600 s in total, also across runs.
    run_id = await started(a, gid, b.me)
    a.daemon.send_message(gid, {"text": "two"})
    await a.idle()
    assert a.epoch(gid) == epoch + 1
    await advance(UPDATE_DEFER_SECS - 100)
    a.daemon.sas.mismatch(gid, run_id)  # ends the run, keeps the deferral clock
    await started(a, gid, b.me)
    a.daemon.send_message(gid, {"text": "three"})
    await a.idle()
    assert a.epoch(gid) == epoch + 1
    await advance(101)
    a.daemon.send_message(gid, {"text": "four"})
    await a.wait(lambda: a.epoch(gid) == epoch + 2)


async def test_a_queued_ceremony_message_of_an_old_epoch_is_dropped(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    seen: list[dict[str, Any]] = []

    def record(frame: dict[str, Any]) -> list[dict[str, Any]]:
        if frame.get("t") == "send":
            seen.append(frame)
        return [frame]

    malicious_relay(a).client_filters.append(record)
    d = a.daemon
    inner = d.inner(SAS_COMMIT, {"commitment": b64(b"x" * 32), "epoch": 0, "peer": b.me}, [b.me])
    meta = {"run": "gone", "kind": SAS_COMMIT, "epoch": a.epoch(gid) - 1}
    d._enqueue("app", gid, {"inner": inner, "msg_id": new_msg_id(), "sas": meta})
    await a.idle()
    assert seen == []
    assert not [e for e in d.store.events(limit=10_000) if e["type"] == "send_failed"]


async def test_an_error_for_the_commitment_ends_the_run(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    malicious_relay(a).fail_next("send", "bad_request", kind="application")
    run_id = a.daemon.sas_start(gid, b.me)["run"]
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"]) == ("send_failed", False)
    assert "unpaired_text" in seen  # it never paired


async def test_the_ceremony_budget_counts_only_what_is_addressed_here(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, b, m_node), gid = await group(3)
    m = Crafted(m_node, rng)
    for _ in range(2 * BUDGET):
        m.commit(gid, b.me, m.nonce())  # for b: not a's budget
    last = None
    for _ in range(BUDGET + 1):
        last = m.commit(gid, a.me, m.nonce())
    await m.node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    (held,) = a.daemon.sas._held.values()
    assert held.commitment != last  # the 13th of the minute was dropped
    # One prompt per sending instance while it holds, not one per commitment.
    await a.wait(lambda: bool(events(a, "sas_requested")))
    assert len(events(a, "sas_requested")) == 1


async def test_the_answered_commitment_is_stored_before_the_reveal(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node), gid = await group(2)
    m = Crafted(m_node, rng)
    run_id = await started(a, gid, m.me)
    c1 = m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: run(a, run_id).revealed)
    assert a.daemon.store.sas_answered(gid, a.epoch(gid), c1)
    await a.restart()
    again = await started(a, gid, m.me)
    # The same commitment again after the restart: never answered twice.
    m.send(gid, SAS_COMMIT, {"commitment": b64(c1), "epoch": a.epoch(gid), "peer": a.me}, [a.me])
    await m.node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    assert view(a, gid, again)["state"] == "waiting"
    m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: view(a, gid, again)["state"] == "exchanging")


# -- human-only by type --------------------------------------------------------------------------


async def test_agents_never_see_a_run_or_a_code(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    await verify(a, b, gid)
    for node in (a, b):
        assert not [d for d in node.adapter.deliveries if d.kind in SAS_KINDS]
        agent = node.daemon.store.agent_events(limit=10_000)
        assert not [e for e in agent if e["type"] in SAS_EVENTS]

        def codes(value: Any) -> bool:
            if isinstance(value, dict):
                return "sas" in value or any(codes(v) for v in value.values())
            if isinstance(value, list):
                return any(codes(v) for v in value)
            return False

        assert not [e for e in agent if codes(e["data"])]
        assert not [e for e in node.adapter.events if codes(e.data)]
        assert "sas" not in node.daemon.group_info(gid)


async def test_a_forked_view_shows_as_runs_that_never_pair(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b, c), gid = await group(3)
    malicious_relay(c).fork_own_commits()
    c.daemon.update(gid)
    await c.wait(lambda: c.epoch(gid) == a.epoch(gid) + 1)
    await verify(a, b, gid)  # the honest side agrees
    await unpaired(a, c, gid)


# -- the one-time reset (SPEC 11.8) ------------------------------------------------------------


def test_verified_flags_are_reset_once(tmp_path: Any, rng: random.Random) -> None:
    key = rng.randbytes(32)
    path = tmp_path / "daemon.sqlite3"
    store = Store(path, key)
    assert store.kv_get(SAS_RUN_MARKER[0]) == SAS_RUN_MARKER[1]
    assert store.kv_get(SAS_RESET_NOTICE) is None  # nothing was verified
    # A store from before: the marker missing, a member verified.
    store.set_members("g", {"ac:v0:x": ("member", [])})
    store.set_verified("g", "ac:v0:x", True, 3)
    store.kv_set(SAS_RUN_MARKER[0], "")
    store.close()
    store = Store(path, key)
    assert not next(m for m in store.members("g")).verified
    assert store.kv_get(SAS_RESET_NOTICE) == "1"
    # Once: a flag set after the reset stays.
    store.set_verified("g", "ac:v0:x", True, 4)
    store.close()
    store = Store(path, key)
    assert next(m for m in store.members("g")).verified
    store.close()


def test_a_crash_in_the_reset_leaves_it_to_do(
    tmp_path: Any, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reset and its marker are one transaction: a crash between them
    leaves neither, and the next start resets."""
    key = rng.randbytes(32)
    path = tmp_path / "daemon.sqlite3"
    store = Store(path, key)
    store.set_members("g", {"ac:v0:x": ("member", [])})
    store.set_verified("g", "ac:v0:x", True, 3)
    store.kv_set(SAS_RUN_MARKER[0], "")
    store.close()
    real = Store.kv_set

    def crash(self: Store, k: str, value: str) -> None:
        if k == SAS_RUN_MARKER[0]:
            raise RuntimeError("crash")
        real(self, k, value)

    monkeypatch.setattr(Store, "kv_set", crash)
    with pytest.raises(RuntimeError):
        Store(path, key)
    monkeypatch.undo()
    store = Store(path, key)
    assert not next(m for m in store.members("g")).verified
    assert store.kv_get(SAS_RUN_MARKER[0]) == SAS_RUN_MARKER[1]
    store.close()


# -- review 67 regressions -----------------------------------------------------------------


def inject_commit(node: Node, gid: str, sender: tuple[str, str], commitment: bytes) -> None:
    """A commitment as the engine hands it over for an authenticated leaf of
    ``sender`` (identity, instance hex): what a member that certified an
    instance under any id it likes can send."""
    row = node.daemon.store.group(gid)
    assert row is not None
    epoch = node.epoch(gid)
    inner = {
        "v": 0,
        "sender": sender[0],
        "instance_id": sender[1],
        "to": [node.me],
        "hop": 0,
        "origin": "human",
        "kind": SAS_COMMIT,
        "body": {"commitment": b64(commitment), "epoch": epoch, "peer": node.me},
    }
    event = {"sender": {"identity": sender[0], "instance_id_hex": sender[1]}, "epoch": epoch}
    with node.daemon.store.tx():
        node.daemon.sas.on_message(row, event, inner)


async def test_another_member_cant_use_up_a_peers_budget(
    group: GroupFixture, rng: random.Random
) -> None:
    """Finding 2: Mallory certifies an instance under Bob's instance id and
    floods Alice. The budget is Mallory's own: Bob's run with Alice pairs."""
    (a, b, m), gid = await group(3)
    for _ in range(2 * BUDGET):
        inject_commit(a, gid, (m.me, b.daemon.instance.instance_id_hex), rng.randbytes(32))
    run_a, run_b = await compare(a, b, gid)
    assert run_a["state"] == run_b["state"] == "done"
    assert run_a["sas"] == run_b["sas"]
    assert a.daemon.store.sas_warnings(gid, b.me) == (0, [])
    # Only Mallory's own prompt came, once.
    await a.wait(lambda: bool(events(a, "sas_requested")))
    assert [e["peer"] for e in events(a, "sas_requested")] == [m.me]


async def test_a_leave_that_ends_a_run_names_the_leaver(
    group: GroupFixture, rng: random.Random
) -> None:
    """Finding 3: a pending leave stops every application message, the
    ceremony messages included, so its commit can't wait; when this
    instance commits it, the warning names the member that left, not this
    instance."""
    (a, m_node, c), gid = await group(3)
    m = Crafted(m_node, rng)
    run_id = await started(a, gid, m.me)
    m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: run(a, run_id).revealed)
    await c.daemon.leave(gid)
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"], seen["committer"]) == ("epoch_changed", True, c.me)
    assert a.daemon.store.sas_warnings(gid, m.me) == (1, [c.me])


async def test_a_restart_cancels_the_commitment_it_left(
    group: GroupFixture, advance: Advance
) -> None:
    """Finding 4: a restart cancels its unrevealed commitment, so the peer
    doesn't pair with it and ends with no warning."""
    (a, b), gid = await group(2)
    await started(b, gid, a.me)
    await a.wait(lambda: bool(a.daemon.sas._held))
    await b.restart()
    await a.wait(lambda: not a.daemon.sas._held)
    run_a = a.daemon.sas_start(gid, b.me)["run"]
    await a.idle()
    assert view(a, gid, run_a)["state"] == "waiting"
    await advance(RUN_TIMEOUT_SECS + 1)
    seen = await ended(a, gid, run_a)
    assert (seen["reason"], seen["warning"]) == ("timed_out", False)
    assert a.daemon.store.sas_warnings(gid, b.me) == (0, [])


async def test_a_timeout_and_the_human_cancel_before_the_reveal(
    group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    sent: list[str] = []

    def record(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "send" and env.get("kind") == "application":
            sent.append(str(env["msg_id"]))
        return [frame]

    malicious_relay(a).client_filters.append(record)
    # The human gives the run up: b no longer holds the commitment.
    run_a = await started(a, gid, b.me)
    await b.wait(lambda: bool(b.daemon.sas._held))
    seen = a.daemon.sas_cancel(gid, run_a)
    assert (seen["reason"], seen["warning"]) == ("cancelled", False)
    await b.wait(lambda: not b.daemon.sas._held)
    # A timeout before the reveal cancels too.
    run_a = await started(a, gid, b.me)
    before = len(sent)
    await advance(RUN_TIMEOUT_SECS + 1)
    await ended(a, gid, run_a)
    await a.idle()
    assert len(sent) == before + 1  # the cancel
    assert not a.daemon.store.sas_sent()


async def test_cancels_honoured_only_before_the_reveal_and_from_the_sender(
    cluster: Cluster, rng: random.Random, advance: Advance
) -> None:
    (a, m_node), gid = await cluster.group(2)
    m = Crafted(m_node, rng)
    m2_node = await cluster.node(identity_of=m_node)
    await cluster.invite(a, m2_node, gid)
    m2 = Crafted(m2_node, rng)
    # A held commitment: dropped by its sender's cancel, not by another
    # instance's of the same identity.
    c1 = m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: bool(a.daemon.sas._held))
    m2.cancel(gid, a.me, c1)
    await m2_node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    assert a.daemon.sas._held
    m.cancel(gid, a.me, c1)
    await a.wait(lambda: not a.daemon.sas._held)
    # After the reveal: ignored, and the run still ends as a warning.
    run_id = await started(a, gid, m.me)
    c2 = m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: run(a, run_id).revealed)
    m.cancel(gid, a.me, c2)
    await m_node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    assert view(a, gid, run_id)["state"] == "exchanging"
    await advance(RUN_TIMEOUT_SECS + 1)
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"]) == ("timed_out", True)


async def test_a_cancel_of_a_paired_run_before_its_reveal_counts_nothing(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node), gid = await group(2)
    m = Crafted(m_node, rng)
    proxy = a.proxy
    state: dict[str, Any] = {"msg_id": None}

    def client(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if (
            state["msg_id"] is None
            and frame.get("t") == "send"
            and env.get("kind") == "application"
        ):
            state["msg_id"] = env["msg_id"]
        return [frame]

    def server(frame: dict[str, Any]) -> list[dict[str, Any]]:
        # Hold `accepted` for a's commitment: a pairs but can't reveal yet.
        held = frame.get("t") == "accepted" and frame.get("msg_id") == state["msg_id"]
        return [] if held else [frame]

    proxy.client_filters.append(client)
    proxy.server_filters.append(server)
    run_id = a.daemon.sas_start(gid, m.me)["run"]
    await a.wait(lambda: state["msg_id"] is not None)
    c1 = m.commit(gid, a.me, m.nonce())
    await a.wait(lambda: run(a, run_id).paired is not None)
    assert not run(a, run_id).revealed
    m.cancel(gid, a.me, c1)
    seen = await ended(a, gid, run_id)
    assert (seen["reason"], seen["warning"]) == ("peer_cancelled", False)
    assert a.daemon.store.sas_warnings(gid, m.me) == (0, [])


async def test_labels_of_crossed_replicas_or_of_a_fork(cluster: Cluster) -> None:
    """Finding 1, the daemon's half: labels that don't mirror count a
    warning. Replicas paired crosswise (both labels name instances in the
    local view) restart; anything else leaves as codes that differ."""
    (a, b), gid = await cluster.group(2)
    a2 = await cluster.node(identity_of=a)
    await cluster.invite(a, a2, gid)
    b2 = await cluster.node(identity_of=b)
    await cluster.invite(a, b2, gid)
    run_a, run_b = await compare(a, b, gid)
    hexes = (b2.daemon.instance.instance_id_hex, a2.daemon.instance.instance_id_hex)
    out = await a.daemon.sas_labels(gid, run_a["run"], hexes[0][:8], hexes[1][:8])
    assert (out["outcome"], out["instance"]) == ("replicas", hexes[0])
    assert a.daemon.store.sas_warnings(gid, b.me)[0] == 1
    with pytest.raises(DaemonError):
        a.daemon.mark_verified(gid, b.me, True, run_a["run"])  # nothing recorded
    # Labels the local view can't explain: a fork, the mismatch.
    out = await b.daemon.sas_labels(gid, run_b["run"], "0" * 8, "f" * 8)
    assert (out["outcome"], out["status"]) == ("mismatch", "left")
    row = b.daemon.store.group(gid)
    assert row is not None
    assert row.status == "left"


async def test_a_finished_run_waiting_for_its_answer_defers_the_update(
    group: GroupFixture,
) -> None:
    """Info: from step 1 until the human answers (SPEC 11.3)."""
    (a, b), gid = await group(2)
    run_a, _ = await compare(a, b, gid)
    make_update_due(a, gid)
    epoch = a.epoch(gid)
    a.daemon.send_message(gid, {"text": "while the code waits"})
    await a.idle()
    assert a.epoch(gid) == epoch
    a.daemon.mark_verified(gid, b.me, True, run_a["run"])
    a.daemon.send_message(gid, {"text": "answered"})
    await a.wait(lambda: a.epoch(gid) == epoch + 1)


# -- the edges of the human API and of the message checks ----------------------------------


async def test_the_human_api_refuses_what_it_should(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    d = a.daemon
    for call, code in (
        (lambda: d.sas_start(gid, "ac:v0:nobody"), "not_found"),
        (lambda: d.sas_start(gid, b.me, instance="0" * 16), "not_found"),
        (lambda: d.sas_start(gid, b.me, instance="XYZ"), "bad_request"),
        (lambda: d.sas_start(gid, a.me), "bad_request"),
        (lambda: d.sas_run(gid, "nope"), "not_found"),
        (lambda: d.sas_peer_started(gid, "nope"), "not_found"),
        (lambda: d.sas_cancel(gid, "nope"), "not_found"),
    ):
        with pytest.raises(DaemonError) as refused:
            call()
        assert refused.value.code == code
    for labels, code in (((("nope", "x" * 8)), "bad_request"), (("0" * 8, "1" * 8), "not_found")):
        with pytest.raises(DaemonError) as refused:
            await d.sas_labels(gid, "nope", *labels)
        assert refused.value.code == code
    run_id = await started(a, gid, b.me)
    with pytest.raises(DaemonError) as early:
        await d.sas_labels(gid, run_id, "0" * 8, "1" * 8)
    assert early.value.code == "not_done"
    with pytest.raises(DaemonError) as early:
        d.mark_verified(gid, b.me, True, run_id)
    assert early.value.code == "not_done"
    with pytest.raises(DaemonError) as missing:
        d.mark_verified(gid, b.me, True, "nope")
    assert missing.value.code == "not_found"
    # Cancelling an ended run changes nothing.
    assert d.sas_cancel(gid, run_id)["reason"] == "cancelled"
    assert d.sas_cancel(gid, run_id)["reason"] == "cancelled"


async def test_malformed_ceremony_messages_are_ignored(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, m_node), gid = await group(2)
    m = Crafted(m_node, rng)
    run_id = await started(a, gid, m.me)
    epoch = a.epoch(gid)
    for body in (
        {"commitment": "é" * 43, "epoch": epoch, "peer": a.me},  # not ASCII
        {"commitment": "!!" * 21, "epoch": epoch, "peer": a.me},  # not base64url
        {"commitment": b64(rng.randbytes(31)), "epoch": epoch, "peer": a.me},  # 31 bytes
        {"commitment": b64(rng.randbytes(32)), "epoch": epoch, "peer": "ac:v0:x"},
        {"commitment": b64(rng.randbytes(32)), "epoch": epoch + 1, "peer": a.me},
        {"commitment": b64(rng.randbytes(32)), "epoch": True, "peer": a.me},
    ):
        m.send(gid, SAS_COMMIT, body, [a.me])
    m.send(gid, SAS_COMMIT, {"commitment": b64(rng.randbytes(32)), "epoch": epoch}, [a.me])
    m.send(gid, SAS_CANCEL, {"commitment": b64(rng.randbytes(32)), "epoch": epoch}, [m.me])
    m.send(gid, SAS_REVEAL, {"answers": "x", "epoch": epoch, "nonce": "y"}, [a.me])
    await m_node.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    assert view(a, gid, run_id)["state"] == "waiting"
    assert not a.daemon.sas._held
