"""The agent-scope operations of a runtime (ADR-005, Decision 1).

:class:`AgentApi` is everything an agent may do: groups, invites (create,
inspect, accept, revoke), send, leave, events, its own held sends, reading
the safety policy and raising ``require_verified``. The local API's routes
call it for the agent token, and the embedded SDK calls it in-process, so
the two paths can't drift apart. Every answer has the shape of the matching
route's JSON (``docs/api.md``).

There is no human-scope operation here: approving or rejecting joins and
held messages, marking members verified, reporting a SAS mismatch, removing
members, changing the safety policy and relaxing ``require_verified`` exist
only as local API routes that need the human token (SPEC 6.2, 10.4, 11).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agentconnect.policy import HUMAN_ONLY_KINDS
from agentconnect.runtime.engine import HUMAN_EVENTS, Engine, new_msg_id
from agentconnect.runtime.errors import ApiError


def a2a_text(group_id: str, text: str, human: bool) -> dict[str, Any]:
    """The ``text`` shorthand as an A2A v1.0 ``Message`` (SPEC 7.2)."""
    return {
        "messageId": new_msg_id(),
        "contextId": group_id,
        "role": "ROLE_USER" if human else "ROLE_AGENT",
        "parts": [{"text": text}],
    }


class AgentApi:
    """The agent-scope operation set over one engine."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    async def status(self) -> dict[str, Any]:
        """The runtime's status. SPEC 10.2: the agent can't learn (and tell
        a peer) what is held of the peers' messages; ``held_messages``
        counts its own held sends only."""
        info = self._engine.status()
        info["held_messages"] = len(self._engine.held_messages(direction="out"))
        return info

    async def list_groups(self) -> dict[str, Any]:
        return {"groups": self._engine.list_groups()}

    async def create_group(self, name: str, purpose: str = "") -> dict[str, Any]:
        return {"group_id": self._engine.create_group(name, purpose)}

    async def group_info(self, group_id: str) -> dict[str, Any]:
        return self._engine.group_info(group_id)

    async def create_invite(
        self,
        group_id: str,
        *,
        ttl_secs: int = 86_400,
        max_uses: int = 1,
        inviter_name: str | None = None,
    ) -> dict[str, Any]:
        return await self._engine.create_invite(group_id, ttl_secs, max_uses, inviter_name)

    async def revoke_invite(self, invite_id: str) -> dict[str, Any]:
        await self._engine.revoke_invite(invite_id)
        return {"revoked": invite_id}

    async def inspect_invite(self, url: str) -> dict[str, Any]:
        return await self._engine.inspect_invite(url)

    async def accept_invite(self, url: str, display_name: str | None = None) -> dict[str, Any]:
        return await self._engine.accept_invite(url, display_name)

    async def set_policy(self, group_id: str, *, require_verified: bool) -> dict[str, Any]:
        """Only ``require_verified``, and only on: turning it on tightens
        the gate; turning it off needs the human (SPEC 10.4)."""
        if not require_verified:
            raise ApiError(403, "human_only", "relaxing verification needs the human token")
        self._engine.set_policy(group_id, require_verified=True)
        return {"require_verified": True}

    async def send(  # noqa: PLR0913
        self,
        group_id: str,
        body: dict[str, Any] | None = None,
        *,
        text: str | None = None,
        to: Sequence[str] = ("*",),
        kind: str = "a2a.message",
        reply_to: Sequence[str] | None = None,
        addressee: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Send as the agent (SPEC 7.2/10.3: only the human's own requests
        are human-originated). The controls SPEC 7.3 reserves to humans
        (``control.resume``) are refused."""
        if kind in HUMAN_ONLY_KINDS:
            raise ApiError(403, "human_only", f"{kind} needs the human token")
        if body is None:
            if text is None:
                raise ApiError(400, "bad_request", "give text or body")
            body = a2a_text(group_id, text, human=False)
        msg_id, status = self._engine.queue_message(
            group_id,
            body,
            to=list(to),
            kind=kind,
            origin="agent",
            reply_to=None if reply_to is None else list(reply_to),
            addressee=None if addressee is None else list(addressee),
        )
        return {"msg_id": msg_id, "status": status}

    async def leave(self, group_id: str) -> dict[str, Any]:
        return {"status": await self._engine.leave(group_id)}

    async def approvals(self) -> dict[str, Any]:
        """No join requests and no held peer messages (their sender, msg_id
        and task would tell the agent what the policy did); only the
        agent's own held sends."""
        await self._engine.expire_held()
        return {"approvals": [], "messages": self._engine.held_messages(direction="out")}

    async def safety(self, group_id: str) -> dict[str, Any]:
        """The group's safety settings (read only)."""
        return self._engine.safety_settings(group_id)

    async def events(self, after: int = 0, group_id: str | None = None) -> dict[str, Any]:
        """Events in order, without the safety policy's own (SPEC 10.2): an
        agent that heard of a hold could tell the sender."""
        rows = self._engine.store.events(after, group_id=group_id, exclude=tuple(HUMAN_EVENTS))
        return {"events": rows}
