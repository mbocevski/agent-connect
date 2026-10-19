"""Floor control in ``moderated`` groups (SPEC 7.3, 9.3; docs/groups.md).

In a ``moderated`` group the instances of the **floor holder** and of the
**effective moderator** are triggered (:func:`agentconnect.runtime.engine.
addressed_to_me`). The effective moderator is ``floor_moderator`` while it is
a member, otherwise the owner. The holder is local state, one per group in
the ``floor`` table, and starts as nobody.

**Grants.** The effective moderator or the owner grants the floor with a
``control.floor{holder}`` (:meth:`FloorService.grant`, either token: the
human picked the moderator by commit, and a grant triggers nobody by
itself). A received grant is a peer's message, so it changes the holder only
if this daemon's own view allows it: the floor is ``moderated``, the sender
is the effective moderator or the owner, the holder is nobody or a current
member, and its ``seq`` is above that of the last grant accepted from the
same sender instance (a grant the relay held back can't undo a newer one).
Any other grant is dropped silently, after the inbound rates counted it.

**Resets.** After every commit the holder becomes nobody when it has no
instance left (``reason: "reset"``) or when the commit changed ``floor`` or
``floor_moderator`` (``reason: "policy"``). Each change is reported as
``floor_changed``, compared with what the ``floor`` row last reported, so a
commit replayed after a crash reports nothing twice.

**New members** start with nobody. The effective moderator's lowest
instance sends its current grant again after a commit that adds an
instance.

The holder can differ between members when the relay drops a grant; that
changes only who is triggered (SPEC 12).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from agentconnect import log
from agentconnect.relay import unb64
from agentconnect.runtime.engine import DaemonError, Engine

LOG = log.get("agentconnect.floor")

FLOOR_KIND = "control.floor"


def effective_moderator(policy: dict[str, Any], identities: Iterable[str]) -> str | None:
    """``floor_moderator`` while it is a member, otherwise the owner (SPEC 9.3)."""
    moderator = policy.get("floor_moderator")
    if isinstance(moderator, str) and moderator in set(identities):
        return moderator
    owner = policy.get("owner")
    return owner if isinstance(owner, str) else None


def may_grant(policy: dict[str, Any], identities: Iterable[str], identity: str) -> bool:
    """Whether ``identity`` may grant the floor: the floor is ``moderated``
    and it is the effective moderator or the owner (SPEC 7.3)."""
    if policy.get("floor") != "moderated":
        return False
    return identity in (effective_moderator(policy, identities), policy.get("owner"))


def floor_event(
    policy: dict[str, Any], effective: str | None, holder: str | None, by: str, reason: str
) -> dict[str, Any]:
    """The data of a ``floor_changed`` event."""
    return {
        "mode": policy.get("floor"),
        "moderator": policy.get("floor_moderator"),
        "effective_moderator": effective,
        "holder": holder,
        "by": by,
        "reason": reason,
    }


def _seq(inner: dict[str, Any]) -> int | None:
    seq = inner.get("seq")
    return seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else None


def _holder(inner: dict[str, Any]) -> str | None:
    body = inner.get("body")
    holder = body.get("holder") if isinstance(body, dict) else None
    return holder if isinstance(holder, str) else None


class FloorService:
    """The floor holder of each group of one :class:`Engine`."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # -- state ----------------------------------------------------------------

    def _identities(self, group_id: str) -> set[str]:
        return {str(m["identity"]) for m in self._engine.client.members(unb64(group_id))}

    def _policy(self, group_id: str) -> dict[str, Any]:
        return dict(json.loads(self._engine.client.policy(unb64(group_id))))

    def holder(self, group_id: str) -> str | None:
        row = self._engine.store.floor(group_id)
        holder = None if row is None else row["holder"]
        return holder if isinstance(holder, str) else None

    def view(self, group_id: str, policy: dict[str, Any], active: bool) -> dict[str, Any]:
        """The group view's ``floor``: the policy's mode, pin and moderator,
        the effective moderator and the holder (both ``None`` for a group
        that isn't active)."""
        return {
            "mode": policy.get("floor"),
            "pinned": bool(policy.get("floor_pinned")),
            "moderator": policy.get("floor_moderator"),
            "effective_moderator": (
                effective_moderator(policy, self._identities(group_id)) if active else None
            ),
            "holder": self.holder(group_id) if active else None,
        }

    def triggers(self, group_id: str, policy: dict[str, Any]) -> tuple[str | None, str | None]:
        """``(effective moderator, holder)``: whom ``moderated`` triggers."""
        if policy.get("floor") != "moderated":
            return None, None
        return effective_moderator(policy, self._identities(group_id)), self.holder(group_id)

    def _reported(self, group_id: str, policy: dict[str, Any]) -> dict[str, Any]:
        """The floor row, or for a group without one (it predates floor
        control) the state of ``policy`` with nobody holding the floor."""
        row = self._engine.store.floor(group_id)
        if row is not None:
            return row
        return {
            "holder": None,
            "mode": policy.get("floor"),
            "moderator": policy.get("floor_moderator"),
            "effective": effective_moderator(policy, self._identities(group_id)),
        }

    def ensure(self, group_id: str) -> None:
        """Give a group that has no floor row one, with nobody holding the
        floor: a group this runtime created or joined starts so."""
        if self._engine.store.floor(group_id) is None:
            state = self._reported(group_id, self._policy(group_id))
            self._engine.store.set_floor(group_id, **state)

    def _take(
        self,
        group_id: str,
        holder: str | None,
        *,
        by: str,
        instance_id: str,
        seq: int,
    ) -> dict[str, Any] | None:
        """Record a grant: the data of its ``floor_changed``, or ``None``
        when the holder stays."""
        e = self._engine
        policy = self._policy(group_id)
        before = self._reported(group_id, policy)
        effective = effective_moderator(policy, self._identities(group_id))
        e.store.set_floor(
            group_id,
            holder=holder,
            granted_by=by,
            granted_seq=seq,
            sender_instance=instance_id,
            at=e.now(),
            mode=policy.get("floor"),
            moderator=policy.get("floor_moderator"),
            effective=effective,
        )
        if before["holder"] == holder:
            return None
        return floor_event(policy, effective, holder, by, "grant")

    # -- received grants --------------------------------------------------------

    def acceptable(
        self, group_id: str, identity: str, instance_id: str, inner: dict[str, Any]
    ) -> bool:
        """Whether a received ``control.floor`` may change the holder (see
        the module docs). Its body fits the schema (``agentconnect.schemas``)."""
        seq = _seq(inner)
        if seq is None:
            return False
        identities = self._identities(group_id)
        if not may_grant(self._policy(group_id), identities, identity):
            return False
        holder = _holder(inner)
        if holder is not None and holder not in identities:
            return False
        last = self._engine.store.floor_seq(group_id, identity, instance_id)
        return last is None or seq > last

    async def accept(
        self, group_id: str, identity: str, instance_id: str, inner: dict[str, Any]
    ) -> None:
        """Take an :meth:`acceptable` grant (inside its message's transaction)."""
        seq = int(inner["seq"])
        self._engine.store.set_floor_seq(group_id, identity, instance_id, seq)
        data = self._take(group_id, _holder(inner), by=identity, instance_id=instance_id, seq=seq)
        if data is not None:
            LOG.info("floor_granted", group=log.hid(group_id))
            await self._engine.emit(group_id, "floor_changed", **data)

    # -- own grants -------------------------------------------------------------

    def grant(self, group_id: str, holder: str | None, *, origin: str) -> dict[str, Any]:
        """Grant the floor to ``holder``, or release it (``None``): send
        ``control.floor`` to the group and take the holder locally. Only the
        effective moderator or the owner of a ``moderated`` group may.
        ``origin`` is ``human`` for the human token, else ``agent``."""
        e = self._engine
        group_id = e._group_or_raise(group_id).group_id
        policy = self._policy(group_id)
        identities = self._identities(group_id)
        if policy.get("floor") != "moderated":
            raise DaemonError("not_moderated", "the group's floor isn't moderated")
        if not may_grant(policy, identities, e.me):
            msg = "only the effective moderator or the owner grants the floor (SPEC 9.3)"
            raise DaemonError("not_permitted", msg)
        if holder is not None and holder not in identities:
            raise DaemonError("not_found", "no such member")
        with e.store.tx():
            msg_id = e.send_message(
                group_id, {"holder": holder}, kind=FLOOR_KIND, origin=origin, internal=True
            )
            # The seq the grant went out with (the last one drawn).
            seq = int(e.store.kv_get("inner_seq") or "0")
            data = self._take(
                group_id, holder, by=e.me, instance_id=e.instance.instance_id_hex, seq=seq
            )
            event = None
            if data is not None:
                event = e._record(group_id, "floor_changed", f"floor_grant/{msg_id}", data)
        e._notify_soon([] if event is None else [event])
        LOG.info("floor_grant_sent", group=log.hid(group_id))
        return {"status": "granted", "holder": holder, "msg_id": msg_id}

    # -- commits ----------------------------------------------------------------

    async def after_commit(self, group_id: str, summary: dict[str, Any], joined: list[str]) -> None:
        """After a merged commit (inside its transaction): the holder becomes
        nobody when it has no instance left or the commit changed the floor
        or the moderator; a change is reported; and instances the commit
        added get the current grant."""
        e = self._engine
        policy = self._policy(group_id)
        members = e.client.members(unb64(group_id))
        identities = {str(m["identity"]) for m in members}
        previous = summary.get("previous_policy")
        before = self._reported(group_id, json.loads(previous) if previous else policy)
        effective = effective_moderator(policy, identities)
        holder, reason = before["holder"], "reset"
        if (before["mode"], before["moderator"]) != (
            policy.get("floor"),
            policy.get("floor_moderator"),
        ):
            holder, reason = None, "policy"
        elif holder not in identities:
            holder = None
        now = (policy.get("floor"), policy.get("floor_moderator"), effective, holder)
        if (before["mode"], before["moderator"], before["effective"], before["holder"]) != now:
            e.store.set_floor(
                group_id,
                holder=holder,
                mode=policy.get("floor"),
                moderator=policy.get("floor_moderator"),
                effective=effective,
            )
            by = str(summary["committer"]["identity"])
            await e.emit(
                group_id, "floor_changed", **floor_event(policy, effective, holder, by, reason)
            )
        if not joined or holder is None or policy.get("floor") != "moderated":
            return
        # The effective moderator's lowest instance tells the newcomers.
        leaves = sorted(int(m["leaf_index"]) for m in members if m["identity"] == effective)
        own = next((int(m["leaf_index"]) for m in members if m["mailbox_id"] == e.mailbox), None)
        if leaves and own == leaves[0]:
            e.send_message(
                group_id, {"holder": holder}, to=sorted(set(joined)), kind=FLOOR_KIND, internal=True
            )
