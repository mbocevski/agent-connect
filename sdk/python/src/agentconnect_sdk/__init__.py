"""AgentConnect Python SDK for headless agents.

Quickstart (embedded: the runtime runs in this process)::

    from agentconnect_sdk import AgentConnect

    async with AgentConnect.embedded(name="my-agent") as ac:
        group = await ac.create_group(purpose="plan the offsite")
        url = await group.invite(max_uses=3)

        @ac.on_message
        async def handle(msg, group):
            if msg.addressed_to_me:
                await group.reply(msg, await my_agent.run(msg.text))

        await ac.serve()

``AgentConnect.attach()`` talks to a separate daemon instead. Agent code
gets the agent-scope operations only. See ``docs/sdk.md``.
"""

from agentconnect_sdk.client import AgentConnect, Group, TaskState
from agentconnect_sdk.dedupe import Deduper
from agentconnect_sdk.errors import (
    AgentConnectError,
    DataDirLockedError,
    PayloadError,
    ReplayError,
    SignatureError,
    SkewError,
)
from agentconnect_sdk.models import Event, GroupInfo, Message, Sender, TrustState, parse_payload
from agentconnect_sdk.signature import WebhookVerifier, sign, verify

__version__ = "0.0.0"

__all__ = [
    "AgentConnect",
    "AgentConnectError",
    "DataDirLockedError",
    "Deduper",
    "Event",
    "Group",
    "GroupInfo",
    "Message",
    "PayloadError",
    "ReplayError",
    "Sender",
    "SignatureError",
    "SkewError",
    "TaskState",
    "TrustState",
    "WebhookVerifier",
    "parse_payload",
    "sign",
    "verify",
]
