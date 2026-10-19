"""The webhook adapter against a fake receiver (httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentconnect.a2a_adapter import A2AAdapter
from agentconnect.adapter import Delivery, DeliveryResult, Event, GroupView, Sender
from agentconnect.adapters import build_adapters
from agentconnect.clock import FakeClock, unix_seconds
from agentconnect.config import Config
from agentconnect.payloads import message_payload
from agentconnect.sse import SseAdapter
from agentconnect.webhook import SIGNATURE_HEADER, TIMESTAMP_HEADER, WebhookAdapter, sign

GROUP = GroupView("g1", "Ops", "Deploys", 3, "free")
SENDER = Sender("ac:v0:peer", "i1", "peer-bot", False)


def delivery(msg_id: str = "m1", kind: str = "a2a.message", **extra: Any) -> Delivery:
    inner = {"kind": kind, "body": {"text": "hi"}, **extra}
    return Delivery(
        "g1",
        msg_id,
        kind,
        {"text": "hi"},
        SENDER,
        ["*"],
        True,
        "Deploys",
        {"self": "unverified", "verified_members": 0, "members": 2},
        "agent",
        1,
        inner,
    )


class Receiver:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.fail: Exception | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail is not None:
            raise self.fail
        return httpx.Response(self.status)

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]


@pytest.fixture
def receiver() -> Receiver:
    return Receiver()


@pytest.fixture
def secret() -> str:
    return secrets.token_urlsafe(16)


@pytest.fixture
def adapter(receiver: Receiver, secret: str, fake_clock: FakeClock) -> WebhookAdapter:
    return WebhookAdapter(
        "http://127.0.0.1:9/hook", secret, fake_clock, transport=httpx.MockTransport(receiver)
    )


async def deliver(adapter: WebhookAdapter, d: Delivery) -> DeliveryResult:
    return await adapter.deliver(GROUP, d.sender, d.to, d)


async def test_a_2xx_response_acks_and_the_body_has_the_framing(
    adapter: WebhookAdapter, receiver: Receiver
) -> None:
    receiver.status = 204
    assert await deliver(adapter, delivery()) is DeliveryResult.ACK
    (body,) = receiver.bodies()
    assert body["event"] == "message"
    assert body["msg_id"] == "m1"
    assert body["group"] == {
        "id": "g1",
        "name": "Ops",
        "purpose": "Deploys",
        "epoch": 3,
        "floor": "free",
        "floor_holder": None,
    }
    assert body["sender"] == {
        "identity": "ac:v0:peer",
        "instance_id": "i1",
        "display_name": "peer-bot",
        "verified": False,
    }
    assert body["to"] == ["*"]
    assert body["addressed_to_me"] is True
    assert body["scope"] == "Deploys"
    assert body["untrusted"] is True
    assert body["trust_state"]["members"] == 2
    assert body["a2a"] == {"text": "hi"}
    assert body["hop"] == 1
    assert "reply_to" not in body


async def test_every_message_kind_has_an_event_name(
    adapter: WebhookAdapter, receiver: Receiver
) -> None:
    for kind in (
        "a2a.message",
        "a2a.task_status",
        "a2a.task_artifact",
        "a2a.agent_card",
        "control.pause",
    ):
        await deliver(adapter, delivery(msg_id=kind, kind=kind, reply_to=["m0"]))
    assert [b["event"] for b in receiver.bodies()] == [
        "message",
        "task_status",
        "task_artifact",
        "agent_card",
        "control.pause",
    ]
    assert all(b["reply_to"] == ["m0"] for b in receiver.bodies())


async def test_requests_are_signed_over_timestamp_and_body(
    adapter: WebhookAdapter, receiver: Receiver, secret: str, fake_clock: FakeClock
) -> None:
    await deliver(adapter, delivery())
    (request,) = receiver.requests
    stamp = request.headers[TIMESTAMP_HEADER]
    assert stamp == str(unix_seconds(fake_clock))
    assert request.headers[SIGNATURE_HEADER] == sign(secret, stamp, request.content)
    assert request.headers[SIGNATURE_HEADER] != sign(secrets.token_hex(8), stamp, request.content)
    fake_clock.advance(10)
    await deliver(adapter, delivery())
    # Every attempt is signed afresh.
    assert receiver.requests[1].headers[SIGNATURE_HEADER] != request.headers[SIGNATURE_HEADER]


@pytest.mark.parametrize("status", [301, 400, 404, 500, 503])
async def test_other_statuses_retry(
    adapter: WebhookAdapter, receiver: Receiver, status: int
) -> None:
    receiver.status = status
    assert await deliver(adapter, delivery()) is DeliveryResult.RETRY


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")])
async def test_unreachable_receivers_retry(
    adapter: WebhookAdapter, receiver: Receiver, error: Exception
) -> None:
    receiver.fail = error
    assert await deliver(adapter, delivery()) is DeliveryResult.RETRY


async def test_an_event_is_posted_at_once_with_its_id(
    adapter: WebhookAdapter, receiver: Receiver
) -> None:
    await adapter.on_event(GROUP, Event("member_joined", "g1", {"identity": "x"}, "e1"))
    await adapter.on_event(None, Event("relay_misbehaviour", None, {}, "e2"))
    first, second = receiver.bodies()
    assert first["event"] == "member_joined"
    assert first["event_id"] == "e1"
    assert first["group"]["id"] == "g1"
    assert first["untrusted"] is True
    assert first["data"] == {"identity": "x"}
    assert second["group"] is None


async def test_a_failed_event_raises_and_is_retried_in_order(
    adapter: WebhookAdapter, receiver: Receiver, fake_clock: FakeClock
) -> None:
    await adapter.on_outbound(_unused)
    receiver.fail = httpx.ConnectError("down")
    with pytest.raises(ConnectionError):
        await adapter.on_event(GROUP, Event("a", "g1", {}, "e1"))
    with pytest.raises(ConnectionError):  # behind e1: queued, not posted
        await adapter.on_event(GROUP, Event("b", "g1", {}, "e2"))
    with pytest.raises(ConnectionError):  # the daemon's own resend: not queued twice
        await adapter.on_event(GROUP, Event("a", "g1", {}, "e1"))
    receiver.fail = None
    receiver.requests.clear()
    for _ in range(20):
        if receiver.requests:
            break
        fake_clock.advance(300)
        await asyncio.sleep(0)
    await adapter_idle(adapter)
    assert [b["event_id"] for b in receiver.bodies()] == ["e1", "e2"]
    await adapter.close()


async def adapter_idle(adapter: WebhookAdapter) -> None:
    for _ in range(50):
        if not adapter._events:
            return
        await asyncio.sleep(0)


async def _unused(*_a: object, **_k: object) -> str:
    return ""


async def test_the_event_queue_is_bounded(
    adapter: WebhookAdapter, receiver: Receiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentconnect.webhook.EVENT_QUEUE_LIMIT", 2)
    receiver.fail = httpx.ConnectError("down")
    for i in range(4):
        with pytest.raises(ConnectionError):
            await adapter.on_event(GROUP, Event("x", "g1", {}, f"e{i}"))
    assert [p["event_id"] for p in adapter._events] == ["e2", "e3"]
    await adapter.close()


async def test_close_is_idempotent_and_the_client_comes_back(
    adapter: WebhookAdapter, receiver: Receiver
) -> None:
    await adapter.close()
    await adapter.close()
    assert await deliver(adapter, delivery()) is DeliveryResult.ACK
    await adapter.close()


def test_repr_hides_the_secret(adapter: WebhookAdapter, secret: str) -> None:
    assert secret not in repr(adapter)
    assert "127.0.0.1" in repr(adapter)
    assert adapter.capabilities().originates is False


def test_build_adapters_follows_the_config(tmp_path: Path, fake_clock: FakeClock) -> None:
    base = Config(relay_url="ws://127.0.0.1:1", relay_host="127.0.0.1:1", data_dir=tmp_path)
    assert build_adapters(base, fake_clock) == []
    (sse,) = build_adapters(base.with_overrides(default_adapter="sse"), fake_clock)
    assert isinstance(sse, SseAdapter)
    cfg = base.with_overrides(default_adapter="webhook", webhook_url="http://127.0.0.1:9/")
    (hook,) = build_adapters(cfg, fake_clock)
    assert isinstance(hook, WebhookAdapter)
    secret_file = tmp_path / "webhook-secret"
    assert secret_file.stat().st_mode & 0o777 == 0o600
    # The same secret on the next start.
    (again,) = build_adapters(cfg, fake_clock)
    assert isinstance(again, WebhookAdapter)
    assert again._secret == hook._secret == secret_file.read_text().strip()


def test_build_adapters_runs_a2a_next_to_webhook_or_sse(
    tmp_path: Path, fake_clock: FakeClock
) -> None:
    base = Config(relay_url="ws://127.0.0.1:1", relay_host="127.0.0.1:1", data_dir=tmp_path)
    a2a = base.with_overrides(a2a_local_agent_url="http://127.0.0.1:9/")
    # Groups bound to `none` deliver to the first adapter: the A2A one.
    (only,) = build_adapters(a2a, fake_clock)
    assert isinstance(only, A2AAdapter)
    hook, bridge = build_adapters(
        a2a.with_overrides(default_adapter="webhook", webhook_url="http://127.0.0.1:9/"),
        fake_clock,
    )
    assert (type(hook), type(bridge)) == (WebhookAdapter, A2AAdapter)
    (named,) = build_adapters(a2a.with_overrides(default_adapter="a2a"), fake_clock)
    assert isinstance(named, A2AAdapter)
    sse_cfg = base.with_overrides(default_adapter="sse", a2a_facade_port=1)
    stream, facade = build_adapters(sse_cfg, fake_clock)
    assert (type(stream), type(facade)) == (SseAdapter, A2AAdapter)


def test_payloads_carry_addressee_and_name_task_cancel() -> None:
    d = delivery(kind="a2a.task_cancel", addressee=["ac:v0:me"], reply_to=["m0"])
    out = message_payload(GROUP, d)
    assert out["event"] == "task_cancel"
    assert out["addressee"] == ["ac:v0:me"]
    assert "addressee" not in message_payload(GROUP, delivery())
