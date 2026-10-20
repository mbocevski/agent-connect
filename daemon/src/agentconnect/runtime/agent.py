"""The agent-scope operations of a runtime (ADR-005, Decision 1).

:class:`AgentApi` is everything an agent may do: groups, invites (create,
inspect, accept, revoke), send, leave, granting the floor of a ``moderated``
group it moderates, events, its own held sends, reading the safety policy
and raising ``require_verified``. The local API's routes
call it for the agent token, and the embedded SDK calls it in-process, so
the two paths can't drift apart. Every answer has the shape of the matching
route's JSON (``docs/api.md``).

There is no human-scope operation here: approving or rejecting joins,
knocks and held messages, listing or reading knock approvals, marking
members verified, reporting a SAS mismatch, removing members, changing a
member's role, handing ownership over, any group policy change other than
raising ``require_verified`` (at creation too), a replica invite,
changing the safety policy and publishing a listing exist only as local
API routes that need the human token (SPEC 6.2, 6.6.4, 9.2, 10.4, 11,
13.2.2). Exporting and importing the identity key (provisioning a
replica) is not an API operation at all: only the CLI does it, on a
stopped runtime's data directory (ADR-005). Withdrawing the
listing is here: it only reduces exposure (SPEC
13.2.3). So is knocking on another agent's listing (SPEC 6.6.2), unless
``knock.agent_may_knock`` is off; approving a knock never is.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agentconnect.policy import HUMAN_ONLY_KINDS
from agentconnect.runtime.engine import DaemonError, Engine, new_msg_id
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

    def _visible(self, group_id: str) -> str:
        """An approved knock's group is the agent's once the knocker is in
        (docs/discovery.md): until then it doesn't exist for the agent."""
        if self._engine.hidden_from_agent(group_id):
            raise DaemonError("not_found", "no such active group")
        return group_id

    async def status(self) -> dict[str, Any]:
        """The runtime's status. SPEC 10.2: the agent can't learn (and tell
        a peer) what is held of the peers' messages; ``held_messages``
        counts its own held sends only."""
        info = self._engine.status(human=False)
        info["held_messages"] = len(self._engine.held_messages(direction="out"))
        return info

    async def list_groups(self) -> dict[str, Any]:
        groups = self._engine.list_groups()
        return {"groups": [g for g in groups if not self._engine.hidden_from_agent(g["group_id"])]}

    async def create_group(
        self, name: str, purpose: str = "", *, require_verified: bool = False
    ) -> dict[str, Any]:
        """A group this identity owns, with the default policy; the agent may
        only ask for ``require_verified``, which tightens the gate (any other
        policy at creation is the human's: ``POST /v0/groups``)."""
        policy = {"require_verified": True} if require_verified else None
        return {"group_id": self._engine.create_group(name, purpose, policy)}

    async def group_info(self, group_id: str) -> dict[str, Any]:
        return self._engine.group_info(self._visible(group_id))

    async def create_invite(
        self,
        group_id: str,
        *,
        ttl_secs: int = 86_400,
        max_uses: int = 1,
        inviter_name: str | None = None,
    ) -> dict[str, Any]:
        return await self._engine.create_invite(
            self._visible(group_id), ttl_secs, max_uses, inviter_name
        )

    async def revoke_invite(self, invite_id: str) -> dict[str, Any]:
        await self._engine.revoke_invite(invite_id)
        return {"revoked": invite_id}

    async def inspect_invite(self, url: str) -> dict[str, Any]:
        return await self._engine.inspect_invite(url)

    async def accept_invite(self, url: str, display_name: str | None = None) -> dict[str, Any]:
        return await self._engine.accept_invite(url, display_name)

    async def set_policy(self, group_id: str, *, require_verified: bool) -> dict[str, Any]:
        """Only ``require_verified``, and only on: turning it on tightens
        the gate; turning it off needs the human (SPEC 10.4), and so does
        every other policy change. ``status`` is ``committing`` or
        ``unchanged``; a change this identity may not make is refused with
        ``403 not_permitted``."""
        if not require_verified:
            raise ApiError(403, "human_only", "relaxing verification needs the human token")
        return {"status": self._engine.set_policy(self._visible(group_id), require_verified=True)}

    async def grant_floor(self, group_id: str, holder: str | None) -> dict[str, Any]:
        """Grant the floor of a ``moderated`` group to a member, or release
        it (``None``), as the agent (SPEC 9.3). Only the effective moderator
        or the owner may (``403 not_permitted``): the human chose the
        moderator by commit, and a grant triggers nobody by itself. The floor
        mode and the moderator are the human's (``POST .../policy``)."""
        return self._engine.grant_floor(self._visible(group_id), holder, origin="agent")

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
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Send as the agent (SPEC 7.2/10.3: only the human's own requests
        are human-originated). The controls SPEC 7.3 reserves to humans
        (``control.resume``) are refused. ``instance`` (16 lowercase hex)
        narrows triggering to that instance (SPEC 9.4)."""
        if kind in HUMAN_ONLY_KINDS:
            raise ApiError(403, "human_only", f"{kind} needs the human token")
        self._visible(group_id)
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
            instance=instance,
        )
        return {"msg_id": msg_id, "status": status}

    async def leave(self, group_id: str) -> dict[str, Any]:
        return {"status": await self._engine.leave(self._visible(group_id))}

    async def approvals(self) -> dict[str, Any]:
        """No join requests and no held peer messages (their sender, msg_id
        and task would tell the agent what the policy did); only the
        agent's own held sends."""
        await self._engine.expire_held()
        return {"approvals": [], "messages": self._engine.held_messages(direction="out")}

    async def safety(self, group_id: str) -> dict[str, Any]:
        """The group's safety settings (read only)."""
        return self._engine.safety_settings(self._visible(group_id))

    async def listing_status(self) -> dict[str, Any]:
        """The runtime's own listing, if it has one (docs/discovery.md)."""
        return self._engine.listings.status()

    async def withdraw_listing(self) -> dict[str, Any]:
        """Close the listing's doors at the relay, then withdraw it from its
        directory. Allowed to the agent: it only reduces exposure (SPEC
        13.2.3). Publishing is the human's (no method here)."""
        return await self._engine.listings.withdraw()

    async def knock_inspect(
        self, listing: str, *, domain_check: bool | None = None
    ) -> dict[str, Any]:
        """A listing, checked as a knock would check it, with its text marked
        ``untrusted`` (docs/discovery.md). ``domain_check`` defaults to
        ``knock.domain_check``."""
        return await self._engine.knocks.inspect(listing, domain_check)

    async def knock(
        self,
        listing: str,
        *,
        listing_sha256: str | None = None,
        display_name: str | None = None,
        note: str | None = None,
        domain_check: bool | None = None,
    ) -> dict[str, Any]:
        """Knock on a listing: ask its owner's human for a new group (SPEC
        6.6.2). Only a Welcome answers it (``joined``); otherwise it lapses
        as "no answer" (``knock_lapsed``). Refused with ``403 human_only``
        when ``knock.agent_may_knock`` is off."""
        return await self._engine.knocks.knock(
            listing,
            listing_sha256=listing_sha256,
            display_name=display_name,
            note=note,
            domain_check=domain_check,
        )

    async def knocks(self) -> dict[str, Any]:
        """This runtime's own knocks (not the ones it received). The listing
        text in them is its owner's: ``untrusted``."""
        return {"knocks": self._engine.knocks.knocks(), "untrusted": True}

    async def events(self, after: int = 0, group_id: str | None = None) -> dict[str, Any]:
        """Events in order, without the safety policy's own (SPEC 10.2): an
        agent that heard of a hold could tell the sender. Nor the knocks this
        runtime received: those are the human's. ``seq`` is the agent's own
        sequence (no gap where an event it doesn't see was recorded), and
        ``after`` takes it."""
        store = self._engine.store
        rows = store.agent_events(after, group_id=group_id)
        _, purged = store.events_purged()
        return {"events": rows, "gap": after < purged, "oldest_available": purged + 1}
