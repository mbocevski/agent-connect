"""The A2A adapter on its own (no daemon): at-least-once deduplication,
retry and refusal, untrusted framing, context batching and Agent Cards."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import socket
import tempfile
import threading
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from a2a.client import A2AClientError
from a2a.types import (
    AgentCard,
    Message,
    Part,
    Role,
    StreamResponse,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)
from a2a.utils.errors import InvalidParamsError, UnsupportedOperationError
from a2a.utils.signing import create_agent_card_signer
from cryptography.hazmat.primitives.asymmetric import ec
from jwt import PyJWK
from jwt.utils import base64url_encode

from agentconnect.a2a_adapter import A2AAdapter, A2AOptions, cards, convert
from agentconnect.a2a_adapter import adapter as adapter_module
from agentconnect.a2a_adapter.adapter import message_id
from agentconnect.a2a_adapter.seen import Seen
from agentconnect.adapter import Delivery, DeliveryResult, Event, GroupView, Sender
from agentconnect.isolation import PeerCred
from agentconnect.runtime.engine import DaemonError
from agentconnect.schemas import normalize
from agentconnect.store import Store
from agentconnect_harness.a2a_agents import AgentServer, HelloWorldExecutor, ScriptedExecutor

GID = "Z3JvdXA"
PEER = "ac:v0:peer"


def view(floor: str = "free") -> GroupView:
    return GroupView(GID, "Group", "Testing", 1, floor)


def delivery(  # noqa: PLR0913
    msg_id: str,
    body: dict[str, Any],
    *,
    kind: str = "a2a.message",
    addressed: bool = True,
    sender: str = PEER,
    to: list[str] | None = None,
) -> Delivery:
    return Delivery(
        group_id=GID,
        msg_id=msg_id,
        kind=kind,
        body=body,
        sender=Sender(sender, "00" * 16, "peer", False),
        to=to or ["*"],
        addressed_to_me=addressed,
        scope="Testing",
        trust_state={"self": "unverified", "verified_members": 0, "members": 2},
        origin="agent",
        hop=1,
        inner={"kind": kind, "body": body, "reply_to": []},
    )


def text(t: str, **metadata: Any) -> dict[str, Any]:
    msg = Message(role=Role.ROLE_USER, message_id="peer-msg", parts=[Part(text=t)])
    if metadata:
        msg.metadata.update(metadata)
    return convert.to_json(msg)


class Sent:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.changed = asyncio.Event()

    async def __call__(self, group_id: str, body: dict[str, Any], **kw: Any) -> str:
        self.calls.append({"group_id": group_id, "body": body, **kw})
        self.changed.set()
        return f"out-{len(self.calls)}"

    async def wait_for(self, n: int) -> list[dict[str, Any]]:
        async def loop() -> None:
            while len(self.calls) < n:
                self.changed.clear()
                await self.changed.wait()

        await asyncio.wait_for(loop(), 5)
        return self.calls


@pytest_asyncio.fixture
async def hello() -> AsyncIterator[AgentServer]:
    agent = AgentServer(HelloWorldExecutor(), "hello")
    await agent.start()
    yield agent
    await agent.stop()


async def started(options: A2AOptions, store: Store | None = None) -> tuple[A2AAdapter, Sent]:
    adapter = A2AAdapter(options)
    if store is not None:
        adapter.bind_store(store)
    sent = Sent()
    await adapter.on_outbound(sent)
    return adapter, sent


def received(agent: AgentServer) -> list[Any]:
    executor = agent.executor
    assert isinstance(executor, HelloWorldExecutor | ScriptedExecutor)
    return executor.received


async def test_redelivery_never_reaches_the_agent_twice(hello: AgentServer, tmp_path: Path) -> None:
    options = A2AOptions(local_agent_url=hello.url, data_dir=tmp_path)
    store = Store(tmp_path / "daemon.db", secrets.token_bytes(32))
    adapter, sent = await started(options, store)
    d = delivery("m1", text("hi"))
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    await sent.wait_for(1)
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    await adapter.aclose()
    # Still deduplicated after a restart: the record is in the daemon's
    # encrypted database, and no plain file is written (SPEC 12).
    again, sent2 = await started(options, store)
    assert await again.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    await again.aclose()
    assert not (tmp_path / adapter_module.SEEN_FILE).exists()
    store.close()
    assert len(received(hello)) == 1
    assert sent2.calls == []
    # The agent's messageId comes from the sender and msg_id, for its own dedup.
    assert received(hello)[0].message.message_id == message_id(d)
    assert message_id(d).startswith("ac-")
    assert len(message_id(d)) == 25


async def test_a_msg_id_from_another_sender_is_not_a_redelivery(
    hello: AgentServer, tmp_path: Path
) -> None:
    """Deliveries are deduplicated by (sender, msg_id), as the inbox does: a
    member that reuses another member's msg_id can't hide the other's
    message from the agent, nor make the agent see two messages with one
    messageId."""
    adapter, sent = await started(A2AOptions(local_agent_url=hello.url, data_dir=tmp_path))
    first = delivery("m1", text("from the peer"))
    copy = delivery("m1", text("from mallory"), sender="ac:v0:mallory")
    for d in (first, copy, first, copy):
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    await sent.wait_for(2)
    await adapter.aclose()
    messages = [r.message for r in received(hello)]
    assert [p.text for m in messages for p in m.parts if p.text.startswith("from ")] == [
        "from the peer",
        "from mallory",
    ]
    assert len({m.message_id for m in messages}) == 2


async def test_events_are_deduplicated_by_event_id(hello: AgentServer, tmp_path: Path) -> None:
    adapter, _sent = await started(A2AOptions(local_agent_url=hello.url, data_dir=tmp_path))
    card = delivery("c1", convert.to_json(AgentCard(name="peer")), kind="a2a.agent_card")
    await adapter.deliver(view(), card.sender, card.to, card)
    assert PEER in adapter.peer_cards(GID)
    left = Event("member_left", GID, {"identity": PEER}, "ev-1")
    await adapter.on_event(view(), left)
    assert adapter.peer_cards(GID) == {}
    # The card comes back; a redelivered (same event_id) leave is ignored.
    card2 = delivery("c2", convert.to_json(AgentCard(name="peer")), kind="a2a.agent_card")
    await adapter.deliver(view(), card2.sender, card2.to, card2)
    await adapter.on_event(view(), left)
    assert PEER in adapter.peer_cards(GID)
    await adapter.on_event(view(), Event("member_left", GID, {"identity": PEER}, "ev-2"))
    assert adapter.peer_cards(GID) == {}
    await adapter.aclose()


async def test_an_unreachable_agent_is_retried(tmp_path: Path) -> None:
    agent = AgentServer(HelloWorldExecutor(), "late")
    await agent.start()
    url = agent.url
    await agent.stop()
    adapter, sent = await started(A2AOptions(local_agent_url=url, data_dir=tmp_path))
    d = delivery("m1", text("anyone?"))
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
    assert adapter.capabilities().agent_card is None
    await adapter.aclose()
    assert sent.calls == []


async def test_refusal_is_acked_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = ScriptedExecutor()
    right = secrets.token_urlsafe(16)
    agent = AgentServer(executor, "strict", token=right)
    await agent.start()
    try:
        # A wrong bearer token: the card can't be fetched, so it's a retry.
        adapter, _ = await started(
            A2AOptions(local_agent_url=agent.url, local_agent_token=right + "x", data_dir=tmp_path)
        )
        d = delivery("m1", text("hi"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
        await adapter.aclose()
        adapter, sent = await started(
            A2AOptions(local_agent_url=agent.url, local_agent_token=right, data_dir=tmp_path)
        )
        ok = delivery("m2", text("x"))
        assert await adapter.deliver(view(), ok.sender, ok.to, ok) is DeliveryResult.ACK
        await sent.wait_for(1)

        # A protocol error is the agent's answer: acked, so no retry loop
        # blocks later deliveries.
        async def refuse(*_a: Any, **_k: Any) -> AsyncIterator[Any]:
            raise InvalidParamsError(message="no")
            yield

        monkeypatch.setattr(adapter._client, "send_message", refuse)
        bad = delivery("m3", text("y"))
        assert await adapter.deliver(view(), bad.sender, bad.to, bad) is DeliveryResult.ACK
        assert len(executor.received) == 1
        await adapter.aclose()
    finally:
        await agent.stop()


async def test_peer_metadata_cannot_override_the_framing(
    hello: AgentServer, tmp_path: Path
) -> None:
    adapter, sent = await started(
        A2AOptions(local_agent_url=hello.url, data_dir=tmp_path, frame_text=False)
    )
    spoof = text("hi", untrusted=False, sender="ac:v0:someone-else", scope="admin")
    d = delivery("m1", spoof)
    await adapter.deliver(view(), d.sender, d.to, d)
    await sent.wait_for(1)
    seen = received(hello)[0].message
    meta = convert.to_json(seen)["metadata"]
    assert meta["untrusted"] is True
    assert meta["sender"]["identity"] == PEER
    assert meta["scope"] == "Testing"
    assert meta["peer_metadata"] == {
        "untrusted": False,
        "sender": "ac:v0:someone-else",
        "scope": "admin",
    }
    assert meta["peer_message_id"] == "peer-msg"
    assert [p.text for p in seen.parts] == ["hi"]  # frame_text off: parts as sent
    await adapter.aclose()


async def test_context_is_batched_and_bounded(hello: AgentServer, tmp_path: Path) -> None:
    adapter, sent = await started(
        A2AOptions(local_agent_url=hello.url, data_dir=tmp_path, context_messages=3)
    )
    for i in range(5):
        d = delivery(f"c{i}", text(f"context {i}"), addressed=False)
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    huge = delivery("big", text("x" * (70 * 1024)), addressed=False)
    await adapter.deliver(view(), huge.sender, huge.to, huge)
    # Other kinds are context-free; unknown control kinds are ignored.
    other = delivery("k", {}, kind="control.pause", addressed=False)
    await adapter.deliver(view(), other.sender, other.to, other)
    assert received(hello) == []
    d = delivery("t1", text("now you"))
    await adapter.deliver(view(), d.sender, d.to, d)
    await sent.wait_for(1)
    context = convert.to_json(received(hello)[0].message)["metadata"]["context_messages"]
    assert [m["msg_id"] for m in context] == ["c3", "c4", "big"]
    assert context[2]["omitted"] == "too_large"
    assert "parts" not in context[2]
    # Handed over once, then cleared.
    d2 = delivery("t2", text("again"))
    await adapter.deliver(view(), d2.sender, d2.to, d2)
    await sent.wait_for(2)
    assert "context_messages" not in convert.to_json(received(hello)[1].message)["metadata"]
    # SPEC 9.3: replies go to the group, addressed to the requester.
    assert sent.calls[0]["to"] == ["*"]
    assert sent.calls[0]["addressee"] == [PEER]
    assert sent.calls[0]["reply_to"] == ["t1"]
    # SPEC 7.2/9.4: and to the requesting instance only.
    assert sent.calls[0]["instance"] == d.sender.instance_id
    d3 = delivery("t3", text("just me"), to=[PEER])
    await adapter.deliver(view(), d3.sender, d3.to, d3)
    calls = await sent.wait_for(3)
    assert (calls[2]["to"], calls[2]["addressee"]) == (["*"], [PEER])
    await adapter.aclose()


def _es256_jwk(kid: str) -> tuple[Any, dict[str, str]]:
    # A fresh random key per test (no literal key bytes).
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()

    def b64(n: int) -> str:
        return base64url_encode(n.to_bytes(32, "big")).decode("ascii")

    return private, {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(numbers.x),
        "y": b64(numbers.y),
        "kid": kid,
    }


def _es256(kid: str) -> tuple[Any, PyJWK]:
    private, jwk = _es256_jwk(kid)
    return private, PyJWK(jwk)


def _signed(private: Any, kid: str, name: str = "signed") -> AgentCard:
    signer = create_agent_card_signer(
        private, {"kid": kid, "alg": "ES256", "jku": None, "typ": "JOSE"}
    )
    return signer(AgentCard(name=name, description="d", version="1"))


def test_card_signatures() -> None:
    private, public = _es256("k1")
    other, _ = _es256("k1")
    keys = {"k1": public}
    assert cards.signature_status(AgentCard(name="x"), keys) == "unsigned"
    card = _signed(private, "k1")
    assert cards.signature_status(card, keys) == "verified"
    assert cards.signature_status(card, {}) == "unverified"
    tampered = AgentCard()
    tampered.CopyFrom(card)
    tampered.name = "renamed"
    assert cards.signature_status(tampered, keys) == "invalid"
    assert cards.signature_status(_signed(other, "k1"), keys) == "invalid"
    assert cards.signature_status(_signed(private, "k2"), keys) == "unverified"


async def test_invalid_peer_cards_are_not_used(hello: AgentServer, tmp_path: Path) -> None:
    private, public = _es256("k1")
    forger, _ = _es256("k1")
    adapter, _ = await started(
        A2AOptions(local_agent_url=hello.url, data_dir=tmp_path, card_keys={"k1": public})
    )
    good = delivery("g", convert.to_json(_signed(private, "k1")), kind="a2a.agent_card")
    await adapter.deliver(view(), good.sender, good.to, good)
    assert adapter.card_status(GID, PEER) == "verified"
    bad = delivery(
        "b",
        convert.to_json(_signed(forger, "k1", "forged")),
        kind="a2a.agent_card",
        sender="ac:v0:forger",
    )
    await adapter.deliver(view(), bad.sender, bad.to, bad)
    assert "ac:v0:forger" not in adapter.peer_cards(GID)
    junk = delivery("j", {"name": ["not", "a", "string"]}, kind="a2a.agent_card")
    await adapter.deliver(view(), junk.sender, junk.to, junk)
    assert adapter.peer_cards(GID)[PEER].name == "signed"
    await adapter.aclose()


def test_parse_message_never_raises() -> None:
    assert [p.text for p in convert.parse_message({"text": "plain"}).parts] == ["plain"]
    data = convert.parse_message({"something": {"else": 1}})
    assert convert.to_json(data)["parts"] == [{"data": {"something": {"else": 1}}}]
    weird = convert.parse_message({"parts": "not a list", "text": "fallback"})
    assert [p.text for p in weird.parts] == ["fallback"]
    assert convert.parse_status({"taskId": {"not": "a string"}}) is None
    assert convert.parse_card({"name": {"nested": True}}) is None


def test_seen_prunes_old_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentconnect.a2a_adapter import seen as seen_module  # noqa: PLC0415

    monkeypatch.setattr(seen_module, "LIMIT", 5)
    monkeypatch.setattr(seen_module, "PRUNE_EVERY", 5)
    db = Store(tmp_path / "daemon.db", secrets.token_bytes(32))
    seen = Seen(db)
    for i in range(10):
        seen.add("m", str(i))
    assert not seen.has("m", "0")
    assert seen.has("m", "9")
    # The count carries on after a restart, so pruning keeps the newest.
    again = Seen(db)
    for i in range(10, 15):
        again.add("m", str(i))
    assert not again.has("m", "9")
    assert again.has("m", "14")
    db.close()
    # Without the daemon's database (unit use) it lives in memory only.
    memory = Seen(None)
    memory.add("m", "x")
    assert memory.has("m", "x")
    assert not list(tmp_path.glob("*seen*"))


def _legacy_seen(path: Path, n: int) -> None:
    import sqlite3  # noqa: PLC0415

    path.parent.mkdir(parents=True, exist_ok=True)
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE seen (h TEXT PRIMARY KEY, n INTEGER)")
    old.executemany(
        "INSERT INTO seen VALUES (?, ?)", ((Seen._h("m", str(i)), i + 1) for i in range(n))
    )
    old.commit()
    old.close()


def test_a_full_old_seen_file_imports_in_one_transaction_at_adapter_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full file (50,000 rows) moves in one transaction when the store is
    bound, not row by row inside the first delivery: that stalled the event
    loop for minutes. The directory name has a `#`, which a raw `file:` URI
    would cut short."""
    data = tmp_path / "data#dir"
    legacy = data / adapter_module.SEEN_FILE
    _legacy_seen(legacy, 50_000)
    db = Store(tmp_path / "daemon.db", secrets.token_bytes(32))
    depths: list[int] = []
    add = db.a2a_seen_add

    def counted(h: str, n: int) -> None:
        depths.append(db._depth)
        add(h, n)

    monkeypatch.setattr(db, "a2a_seen_add", counted)
    adapter = A2AAdapter(A2AOptions(data_dir=data))
    adapter.bind_store(db)
    assert not legacy.exists(), "imported when the store is bound"
    assert len(depths) == 50_000
    assert set(depths) == {1}, "every row inside one transaction"
    seen = adapter._seen
    assert seen.has("m", "0")
    assert seen.has("m", "49999")
    assert not (tmp_path / "data").exists(), "no file opened beside the data dir"
    db.close()


def test_an_unreadable_old_seen_file_is_deleted_all_the_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentconnect.a2a_adapter import seen as seen_module  # noqa: PLC0415

    legacy = tmp_path / adapter_module.SEEN_FILE
    legacy.write_bytes(b"not a database")
    db = Store(tmp_path / "daemon.db", secrets.token_bytes(32))
    seen = Seen(db, legacy)
    assert not seen.has("m", "anything")
    assert not legacy.exists()
    db.close()
    # In memory it keeps the newest LIMIT too.
    monkeypatch.setattr(seen_module, "LIMIT", 2)
    memory = Seen(None)
    for key in ("a", "b", "c"):
        memory.add("m", key)
    assert (memory.has("m", "a"), memory.has("m", "c")) == (False, True)


def test_an_old_plain_seen_file_moves_into_the_encrypted_database(tmp_path: Path) -> None:
    """Older daemons kept the seen set in a plain SQLite file: its hashes
    move into the encrypted database and the file is deleted."""
    import sqlite3  # noqa: PLC0415

    legacy = tmp_path / adapter_module.SEEN_FILE
    old = sqlite3.connect(legacy)
    old.execute("CREATE TABLE seen (h TEXT PRIMARY KEY, n INTEGER)")
    old.execute("INSERT INTO seen VALUES (?, 1)", (Seen._h("m", "before"),))
    old.commit()
    old.close()
    db = Store(tmp_path / "daemon.db", secrets.token_bytes(32))
    seen = Seen(db, legacy)
    assert seen.has("m", "before")
    assert not seen.has("m", "other")
    assert not legacy.exists()
    assert not list(tmp_path.glob(f"{adapter_module.SEEN_FILE}*"))
    db.close()


async def test_the_agent_going_away_after_its_card_is_a_retry(tmp_path: Path) -> None:
    agent = AgentServer(HelloWorldExecutor(), "brief")
    await agent.start()
    adapter, _ = await started(A2AOptions(local_agent_url=agent.url, data_dir=tmp_path))
    assert adapter.capabilities().agent_card is not None
    await agent.stop()
    d = delivery("m1", text("still there?"))
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
    await adapter.aclose()


async def test_streaming_refused_falls_back_and_stream_errors_end_quietly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = ScriptedExecutor()
    agent = AgentServer(executor, "picky")
    await agent.start()
    try:
        adapter, sent = await started(A2AOptions(local_agent_url=agent.url, data_dir=tmp_path))
        assert adapter._client is not None

        async def refuse(*_a: Any, **_k: Any) -> AsyncIterator[Any]:
            raise UnsupportedOperationError(message="no streaming")
            yield

        monkeypatch.setattr(adapter._client, "send_message", refuse)
        d = delivery("m1", text("stream this"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
        calls = await sent.wait_for(2)
        # SendMessage returns the task once it ends: its status, then its artifact.
        assert calls[0]["body"]["status"]["state"] == "TASK_STATE_COMPLETED"
        assert calls[1]["kind"] == "a2a.task_artifact"

        async def breaks(*_a: Any, **_k: Any) -> AsyncIterator[StreamResponse]:
            working = TaskStatusUpdateEvent(
                task_id="t", status=TaskStatus(state=TaskState.TASK_STATE_WORKING)
            )
            yield StreamResponse(status_update=working)
            raise A2AClientError("connection lost")

        monkeypatch.setattr(adapter._client, "send_message", breaks)
        d2 = delivery("m2", text("again"))
        assert await adapter.deliver(view(), d2.sender, d2.to, d2) is DeliveryResult.ACK
        await sent.wait_for(len(calls) + 1)
        await adapter.aclose()
    finally:
        await agent.stop()


async def test_replies_over_the_limits_are_dropped(hello: AgentServer, tmp_path: Path) -> None:
    adapter = A2AAdapter(A2AOptions(local_agent_url=hello.url, data_dir=tmp_path))
    tried: list[str] = []

    async def over_the_rate(group_id: str, body: dict[str, Any], **kw: Any) -> str:
        tried.append(kw["kind"])
        raise DaemonError("rate_limited", "over the rate")

    await adapter.on_outbound(over_the_rate)
    d = delivery("m1", text("hi"))
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    await asyncio.wait_for(asyncio.gather(*adapter._running), 5)
    assert tried == ["a2a.message"]
    await adapter.aclose()


async def test_task_memory_is_bounded_and_strangers_cannot_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adapter_module, "MAX_TASKS", 1)
    executor = ScriptedExecutor()
    agent = AgentServer(executor, "tasks")
    await agent.start()
    try:
        adapter, sent = await started(A2AOptions(local_agent_url=agent.url, data_dir=tmp_path))
        for i in range(2):
            d = delivery(f"m{i}", text(f"stream {i}"))
            await adapter.deliver(view(), d.sender, d.to, d)
        calls = await sent.wait_for(10)
        tasks = {c["body"].get("taskId") for c in calls}
        assert len(tasks) == 2
        assert len(adapter._tasks) == 1
        first = calls[0]["body"]["taskId"]
        # Forgotten (bounded memory), another member's, or malformed: ignored.
        for i, (body, who) in enumerate(
            [
                (convert.cancel_body(first), PEER),
                (convert.cancel_body(calls[-1]["body"]["taskId"]), "ac:v0:x"),
                ({"id": {"not": "a string"}}, PEER),
                ({}, PEER),
            ]
        ):
            c = delivery(f"c{i}", body, kind="a2a.task_cancel", sender=who)
            assert await adapter.deliver(view(), c.sender, c.to, c) is DeliveryResult.ACK
        assert executor.canceled == []
        await adapter.aclose()
    finally:
        await agent.stop()


async def test_lifecycle_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lone = A2AAdapter(A2AOptions())
    with pytest.raises(RuntimeError, match="not been started"):
        await lone.send_to_group(GID, {}, ["*"])
    # Without a data directory the facade token is random and not stored.
    await lone.on_outbound(Sent())
    assert lone.facade is None
    await lone.on_event(None, Event("out_of_sync", None, {}, ""))
    await lone.aclose()
    facade = A2AAdapter(A2AOptions(facade_port=0))
    await facade.on_outbound(Sent())
    assert facade.facade_token is not None
    await facade.aclose()

    agent = AgentServer(HelloWorldExecutor(), "signed")
    await agent.start()
    try:
        monkeypatch.setattr(cards, "signature_status", lambda *_: "invalid")
        adapter, _ = await started(A2AOptions(local_agent_url=agent.url, data_dir=tmp_path))
        assert adapter.capabilities().agent_card is None  # an invalid local card isn't sent
        card = delivery("c", convert.to_json(AgentCard(name="p")), kind="a2a.agent_card")
        await adapter.deliver(view(), card.sender, card.to, card)
        await adapter.on_event(view(), Event("removed", GID, {}, "ev-r"))
        assert adapter.group_info(GID) is None
        await adapter.aclose()
    finally:
        await agent.stop()


def test_jwks_loading(tmp_path: Path) -> None:
    _, public = _es256_jwk("good")
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    "not an object",
                    {"kty": "EC", "crv": "P-256"},
                    {"kty": "EC", "kid": "broken", "crv": "P-256", "x": "AA", "y": "AA"},
                    public,
                ]
            }
        )
    )
    assert list(cards.load_jwks(path)) == ["good"]
    path.write_text("[]")
    assert cards.load_jwks(path) == {}


def test_signatures_with_unpinned_or_garbled_headers() -> None:
    k1, public = _es256("k1")
    k2, _ = _es256("k2")
    forger, _ = _es256("k1")
    card = _signed(k2, "k2")
    card = create_agent_card_signer(
        forger, {"kid": "k1", "alg": "ES256", "jku": None, "typ": "JOSE"}
    )(card)
    # k2 has no pinned key, and k1's signature is a forgery.
    assert cards.signature_status(card, {"k1": public}) == "invalid"
    garbled = _signed(k1, "k1")
    garbled.signatures[0].protected = "%%%"
    assert cards.signature_status(garbled, {"k1": public}) == "unverified"


async def test_a_cancel_delivered_as_context_does_not_cancel(tmp_path: Path) -> None:
    executor = ScriptedExecutor()
    agent = AgentServer(executor, "tasks")
    await agent.start()
    try:
        adapter, sent = await started(A2AOptions(local_agent_url=agent.url, data_dir=tmp_path))
        d = delivery("m0", text("wait here"))
        await adapter.deliver(view(), d.sender, d.to, d)
        (*_, working) = await sent.wait_for(2)
        task = working["body"]["taskId"]
        # Past the loop guard, or for someone else: context, never a command.
        context = delivery("c0", convert.cancel_body(task), kind="a2a.task_cancel", addressed=False)
        assert await adapter.deliver(view(), context.sender, context.to, context) is (
            DeliveryResult.ACK
        )
        assert executor.canceled == []
        cancel = delivery("c1", convert.cancel_body(task), kind="a2a.task_cancel")
        await adapter.deliver(view(), cancel.sender, cancel.to, cancel)
        await executor.wait_canceled(1)
        await adapter.aclose()
    finally:
        await agent.stop()


# -- R2-2: cards are checked, never rewritten -----------------------------------------


def _rich_card() -> AgentCard:
    card = convert._parse(
        {
            "name": "Bob",
            "description": "Line one.\nLine two.",
            "version": "1",
            "skills": [
                {
                    "id": "s",
                    "name": "S",
                    "description": "d",
                    "securityRequirements": [{"schemes": {"oauth": {"list": ["r"]}}}],
                }
            ],
            "capabilities": {"streaming": True},
        },
        AgentCard(),
    )
    assert card is not None
    return card


def test_normalising_a_card_keeps_every_known_field_as_sent() -> None:
    body = convert.to_json(_rich_card())
    shaped = normalize("a2a.agent_card", body | {"future": "x"})
    assert shaped == body, "known fields as sent, the unknown one left out"
    loose = body | {"capabilities": {"streaming": True, "anything": "free text " * 300}}
    assert normalize("a2a.agent_card", loose) == body
    assert normalize("a2a.agent_card", body | {"description": "x" * 501}) is None, (
        "over a cap is refused, not cut"
    )


def test_a_signed_card_survives_normalising_and_verifies() -> None:
    private, public = _es256("k1")
    signer = create_agent_card_signer(
        private, {"kid": "k1", "alg": "ES256", "jku": None, "typ": "JOSE"}
    )
    signed = convert.to_json(signer(_rich_card()))
    shaped = normalize("a2a.agent_card", signed | {"future": 1})
    assert shaped is not None
    parsed = convert.parse_card(shaped)
    assert parsed is not None
    assert cards.signature_status(parsed, {"k1": public}) == "verified"


# -- where messages go: the configured endpoint only (SR-10, SR-30) -----------


class Listener:
    """A server on a thread that records every connection's bytes and
    answers nothing: a squatter, or a proxy that must never be used."""

    def __init__(self, path: Path | None = None) -> None:
        if path is None:
            self._sock = socket.create_server(("127.0.0.1", 0))
            self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}/"
        else:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.bind(str(path))
            self._sock.listen(8)
            self.url = ""
        self._sock.settimeout(0.05)
        self.received: list[bytes] = []
        self._open = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while self._open:
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(0.5)
                try:
                    self.received.append(conn.recv(65536))
                except TimeoutError:
                    self.received.append(b"")

    def close(self) -> list[bytes]:
        self._open = False
        self._thread.join(timeout=5)
        self._sock.close()
        return self.received


@pytest.fixture
def sockdir() -> Iterator[Path]:
    d = Path(tempfile.mkdtemp(prefix="ac-a2a-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def log_events(err: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in err.splitlines() if line.startswith("{")]


async def test_the_agent_on_a_socket_gets_its_messages(sockdir: Path, tmp_path: Path) -> None:
    agent = AgentServer(HelloWorldExecutor(), "uds", uds=sockdir / "a2a.sock")
    await agent.start()
    try:
        adapter, sent = await started(
            A2AOptions(
                local_agent_url=agent.url,
                local_agent_socket=sockdir / "a2a.sock",
                receiver_uids=frozenset({os.geteuid()}),
                data_dir=tmp_path,
            )
        )
        d = delivery("m1", text("over the socket"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
        await sent.wait_for(1)
        assert len(received(agent)) == 1
        await adapter.aclose()
    finally:
        await agent.stop()


async def test_an_agent_socket_of_another_user_is_a_retry(
    sockdir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    other = os.geteuid() + 1
    monkeypatch.setattr(
        "agentconnect.isolation.peer_credentials", lambda _s: PeerCred(uid=other, gid=other)
    )
    squatter = Listener(sockdir / "a2a.sock")
    adapter, sent = await started(
        A2AOptions(
            local_agent_url="http://localhost/",
            local_agent_socket=sockdir / "a2a.sock",
            local_agent_token=secrets.token_urlsafe(16),
            receiver_uids=frozenset({os.geteuid()}),
            data_dir=tmp_path,
        )
    )
    d = delivery("m1", text("not for a squatter"))
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
    await adapter.aclose()
    got = squatter.close()
    assert got  # it was dialled, and refused before a byte was written
    assert all(b == b"" for b in got)
    assert sent.calls == []
    refused = [
        e for e in log_events(capsys.readouterr().err) if e["event"] == "a2a_receiver_refused"
    ]
    assert refused
    assert str(other) in refused[0]["reason"]


async def test_a_card_naming_another_endpoint_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    elsewhere = Listener()
    agent = AgentServer(HelloWorldExecutor(), "liar", card_url=elsewhere.url)
    await agent.start()
    try:
        adapter, sent = await started(
            A2AOptions(
                local_agent_url=agent.url,
                local_agent_token=secrets.token_urlsafe(16),
                data_dir=tmp_path,
            )
        )
        d = delivery("m1", text("stay here"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
        assert adapter.capabilities().agent_card is None
        await adapter.aclose()
    finally:
        await agent.stop()
    assert elsewhere.close() == []
    assert received(agent) == []
    assert sent.calls == []
    (mismatch, *_) = [
        e for e in log_events(capsys.readouterr().err) if e["event"] == "a2a_card_endpoint_mismatch"
    ]
    assert mismatch["configured_endpoint"] == agent.url.rstrip("/")
    assert mismatch["card_endpoint"] == elsewhere.url.rstrip("/")


async def test_a_server_that_took_over_the_socket_gets_no_delivery(
    sockdir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The card came from the agent's user; the agent then went down and
    # another user's server took the path. Its connection is checked before
    # the message is written: the delivery waits, nothing reaches it.
    uds = sockdir / "a2a.sock"
    agent = AgentServer(HelloWorldExecutor(), "uds", uds=uds)
    await agent.start()
    adapter, sent = await started(
        A2AOptions(
            local_agent_url="http://localhost/",
            local_agent_socket=uds,
            receiver_uids=frozenset({os.geteuid()}),
            data_dir=tmp_path,
        )
    )
    assert adapter.capabilities().agent_card is not None
    await agent.stop()
    other = os.geteuid() + 1
    monkeypatch.setattr(
        "agentconnect.isolation.peer_credentials", lambda _s: PeerCred(uid=other, gid=other)
    )
    uds.unlink(missing_ok=True)  # the stale socket, replaced
    squatter = AgentServer(HelloWorldExecutor(), "squatter", uds=uds)
    await squatter.start()
    try:
        d = delivery("m1", text("for the agent only"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
        await adapter.aclose()
    finally:
        await squatter.stop()
    assert received(squatter) == []
    assert sent.calls == []
    refused = [
        e for e in log_events(capsys.readouterr().err) if e["event"] == "a2a_receiver_refused"
    ]
    assert refused
    assert str(other) in refused[0]["reason"]


@pytest.mark.parametrize("card_url", ["http://localhost:9999/", "http://agent.example.org/"])
async def test_on_a_socket_the_cards_own_url_doesnt_matter(
    sockdir: Path, tmp_path: Path, card_url: str
) -> None:
    # An agent's card names the URL it was written with; on a socket every
    # request goes to the socket anyway, so the card isn't pinned.
    agent = AgentServer(HelloWorldExecutor(), "uds", uds=sockdir / "a2a.sock", card_url=card_url)
    await agent.start()
    try:
        adapter, sent = await started(
            A2AOptions(
                local_agent_url="http://localhost/",
                local_agent_socket=sockdir / "a2a.sock",
                receiver_uids=frozenset({os.geteuid()}),
                data_dir=tmp_path,
            )
        )
        d = delivery("m1", text("through the socket"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
        await sent.wait_for(1)
        await adapter.aclose()
    finally:
        await agent.stop()
    assert len(received(agent)) == 1


@pytest.mark.parametrize("over", ["tcp", "socket"])
@pytest.mark.parametrize("card_url", ["http://127.0.0.1:99999/", "http://127.0.0.1:abc/"])
async def test_a_card_with_a_broken_url_is_refused_and_the_adapter_keeps_running(
    sockdir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], over: str, card_url: str
) -> None:
    # Whoever answers local_agent_url chooses the card: a malformed URL in it
    # must not stop the runtime.
    uds = sockdir / "a2a.sock" if over == "socket" else None
    agent = AgentServer(HelloWorldExecutor(), "broken", uds=uds, card_url=card_url)
    await agent.start()
    try:
        adapter, sent = await started(
            A2AOptions(
                local_agent_url=agent.url,
                local_agent_socket=uds,
                receiver_uids=frozenset({os.geteuid()}),
                data_dir=tmp_path,
            )
        )
        d = delivery("m1", text("anyone?"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
        assert adapter.capabilities().agent_card is None
        await adapter.aclose()
    finally:
        await agent.stop()
    assert received(agent) == []
    assert sent.calls == []
    events = [e["event"] for e in log_events(capsys.readouterr().err)]
    assert "a2a_card_endpoint_mismatch" in events


@pytest.mark.parametrize("bindings", [(), ("HTTP+JSON",), ("GRPC",)], ids=["none", "rest", "grpc"])
async def test_a_card_without_json_rpc_is_refused_and_the_adapter_keeps_running(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bindings: tuple[str, ...]
) -> None:
    # The adapter speaks JSON-RPC only: a card offering nothing it can use
    # is refused like any other unusable card, and the runtime still starts.
    agent = AgentServer(HelloWorldExecutor(), "elsewhere", bindings=bindings)
    await agent.start()
    try:
        adapter, sent = await started(A2AOptions(local_agent_url=agent.url, data_dir=tmp_path))
        d = delivery("m1", text("anyone?"))
        assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.RETRY
        assert adapter.capabilities().agent_card is None
        await adapter.aclose()
    finally:
        await agent.stop()
    assert received(agent) == []
    assert sent.calls == []
    (unusable, *_) = [
        e for e in log_events(capsys.readouterr().err) if e["event"] == "a2a_card_unusable"
    ]
    assert unusable["reason"] == "no JSON-RPC interface"
    assert unusable["configured_endpoint"] == adapter_module._origin(agent.url)
    assert "elsewhere" not in json.dumps(unusable)


async def test_environment_proxies_are_ignored(
    hello: AgentServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy = Listener()
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, proxy.url)
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    adapter, sent = await started(A2AOptions(local_agent_url=hello.url, data_dir=tmp_path))
    d = delivery("m1", text("direct, please"))
    assert await adapter.deliver(view(), d.sender, d.to, d) is DeliveryResult.ACK
    await sent.wait_for(1)
    await adapter.aclose()
    assert proxy.close() == []
