"""SPEC §6.2 step 3: a JoinRequest is accepted only from the mailbox it
names. Anyone with an invite link can MAC any KeyPackage under it, so
without this check a link holder who saw someone else's unused KeyPackage
(say, in a request to their own invite) could get that identity added as a
member nobody controls: at once under ``policy.auto_approve``, or past a
human who sees a familiar fingerprint. On both hosts.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable

import pytest

import agentconnect_core as ac
from agentconnect.relay import b64, unb64
from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.proxy import RelayProxy

Proxy = Callable[[Node], RelayProxy]


@pytest.mark.parametrize("auto_approve", [True, False])
async def test_a_request_carrying_someone_elses_key_package_is_dropped(
    cluster: Cluster, malicious_relay: Proxy, rng: random.Random, auto_approve: bool
) -> None:
    # V asks to join M's group; M keeps the request and never approves it,
    # so V's KeyPackage stays unused everywhere.
    m = await cluster.node("m", auto_approve=False)
    m_relay = malicious_relay(m)
    m_invite = await m.daemon.create_invite(m.daemon.create_group("Bait", ""))
    v = await cluster.node("v")
    await v.daemon.accept_invite(m_invite["url"])
    await m.wait(lambda: len(m.daemon.join_approvals()) == 1)
    frame = next(
        f
        for f in m_relay.delivered
        if f["env"].get("kind") == "join_request" and f["env"]["sender"] == v.daemon.mailbox
    )
    victim = json.loads(unb64(frame["env"]["ct"]))

    # M also holds a link to C's group, and re-MACs V's request under it.
    c = await cluster.node("c", auto_approve=auto_approve)
    c_relay = malicious_relay(c)
    gid = c.daemon.create_group("Target", "")
    await c.idle()
    c_invite = await c.daemon.create_invite(gid)
    link = ac.parse_invite_url(c_invite["url"])
    forged = {
        **victim,
        "invite_id": link.invite_id_b64,
        "mac": b64(
            ac.join_request_mac(
                link.invite_id,
                link.secret_bytes(),
                unb64(victim["key_package"]),
                victim["mailbox_id"],
                victim["display_name"],
            )
        ),
    }
    attack = json.loads(json.dumps(frame))
    env = attack["env"]
    env["sender"] = m.daemon.mailbox  # the relay authenticated M, not V
    env["msg_id"] = b64(rng.randbytes(16))
    env["ct"] = b64(json.dumps(forged).encode())
    if "to" in env:
        env["to"] = c.daemon.mailbox
    await c_relay.inject(attack)
    await c.wait(lambda: c.daemon.store.inbox_state(env["sender"], env["msg_id"]) is not None)
    await c.idle()

    # Dropped as a failed MAC is: the inbox row is only the "done" marker
    # that deduplicates the envelope; nothing is stored, remembered, used,
    # audited or shown.
    assert c.daemon.store.inbox_state(env["sender"], env["msg_id"]) == "done"
    assert c.daemon.store.join_ledger_count(c_invite["invite_id"]) == 0
    stored = c.daemon.store.invite(c_invite["invite_id"])
    assert stored is not None
    assert stored["status"] == "open"
    assert not c.daemon._invite_closed(stored)
    assert not [r for r in c.daemon.store.audit(limit=100) if r["kind"] == "join_request"]
    assert c.daemon.join_approvals() == []
    assert not c.adapter.of_type("pending_approval")
    assert v.daemon.me not in json.dumps(c.daemon.group_info(gid))
    assert not c.daemon.store.outbox()
