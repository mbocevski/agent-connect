"""Floor control in ``moderated`` groups (SPEC 7.3, 9.3; docs/groups.md).

In a ``moderated`` group the instances of the **floor holder** and of the
**effective moderator** are triggered (:func:`agentconnect.runtime.engine.
addressed_to_me`). The effective moderator is ``floor_moderator`` while it is
a member, otherwise the owner.

**A register every member computes the same.** The holder is the result of
folding the valid writes in key order ``(epoch, counter, sender identity,
sender instance)``. Members that have seen the same writes have the same
holder, whatever order the writes reached them in:

* **Grants.** ``control.floor{holder, counter}``; ``counter`` orders the
  grants of one epoch and starts again at each epoch (at most
  :data:`~agentconnect.schemas.MAX_FLOOR_COUNTER`). The grant's epoch is the
  MLS epoch it was sent in, and it is judged against the **floor facts of
  that epoch** (the mode, the owner, the effective moderator, the member
  identities), never against the receiver's current view. Each member keeps
  the facts of the epochs whose messages it can still decrypt (the current
  one and :data:`PAST_EPOCHS` before it); a grant from an epoch with no
  facts is ignored, the same way everywhere. A valid grant is a write
  whatever this member's own delivery policy decides for the message
  (:meth:`FloorService.accept`). The sender takes its own grant as it seals
  it (:meth:`FloorService.seal`), in the transaction that stores the
  envelope, and keeps that epoch until the relay has taken it.
* **Resets.** A commit that changes ``floor`` or ``floor_moderator`` writes
  nobody at ``(new epoch, 0)``; a commit after which an identity has no
  instance writes "drop it" at ``(new epoch, 0)``, which clears the holder if
  it names that identity at that point of the order. A grant from before the
  commit loses to them however late it arrives.
* **Copies.** After a commit that adds instances, one instance (the copier)
  sends the newcomers the current value with the key of the write that set
  it (``copy``), and sends it again whenever a write from before their
  epoch, which they can't decrypt, changes it, nobody included. Existing
  members merge it by key: it wins only where it really is newer.

Any other grant is dropped silently. Writes older than the decryptable
epochs are folded into a base value, and of one epoch's grants only the
greatest is kept. Each change is reported as ``floor_changed``.

Members still disagree when the relay drops a grant (SPEC 12); that changes
only who is triggered.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from agentconnect import log
from agentconnect.relay import unb64
from agentconnect.runtime.engine import DaemonError, Engine
from agentconnect.schemas import MAX_FLOOR_COUNTER, normalize

LOG = log.get("agentconnect.floor")

FLOOR_KIND = "control.floor"
# Past epochs whose application messages members can still decrypt (the
# core's MAX_PAST_EPOCHS, the relay's one-epoch grace window, SPEC 8.3).
PAST_EPOCHS = 1

Key = tuple[int, int, str, str]  # (epoch, counter, sender identity, sender instance)
Write = tuple[int, int, str, str, str, str | None]  # key, kind, holder


def effective_moderator(policy: dict[str, Any], identities: Iterable[str]) -> str | None:
    """``floor_moderator`` while it is a member, otherwise the owner (SPEC 9.3)."""
    moderator = policy.get("floor_moderator")
    if isinstance(moderator, str) and moderator in set(identities):
        return moderator
    owner = policy.get("owner")
    return owner if isinstance(owner, str) else None


def facts_of(policy: dict[str, Any], identities: Iterable[str]) -> dict[str, Any]:
    """The floor facts of an epoch: what a grant sent in it is judged on."""
    members = sorted(set(identities))
    return {
        "mode": policy.get("floor"),
        "moderator": policy.get("floor_moderator"),
        "owner": policy.get("owner"),
        "effective": effective_moderator(policy, members),
        "identities": members,
    }


def may_grant(facts: dict[str, Any], identity: str) -> bool:
    """Whether ``identity`` may grant under ``facts``: the floor is
    ``moderated`` and it is the effective moderator or the owner (SPEC 7.3)."""
    return bool(
        facts.get("mode") == "moderated" and identity in (facts["effective"], facts["owner"])
    )


def floor_write(
    facts: dict[str, Any] | None, epoch: int, sender: str, instance: str, body: dict[str, Any]
) -> tuple[Key, str | None] | None:
    """The register write a ``control.floor`` sent in ``epoch`` makes, judged
    on that epoch's ``facts``: ``(key, holder)``, or ``None`` if it is not
    valid. ``body`` is in its schema's shape."""
    if facts is None or not may_grant(facts, sender):
        return None
    holder = _opt_str(body.get("holder"))
    if holder is not None and holder not in facts["identities"]:
        return None
    counter = int(body["counter"])
    copy = body.get("copy")
    if copy is None:
        return (epoch, counter, sender, instance), holder
    if int(copy["epoch"]) > epoch:
        return None
    return (int(copy["epoch"]), counter, str(copy["sender"]), str(copy["instance"])), holder


def fold(
    holder: str | None, source: Key | None, writes: Iterable[Write]
) -> tuple[str | None, Key | None]:
    """The register after ``writes`` (in key order) over a base value: the
    holder and the key of the write that last set it."""
    for epoch, counter, sender, instance, kind, value in writes:
        if kind in {"grant", "reset"} or (kind == "drop" and holder == value):
            holder = value if kind == "grant" else None
            source = (epoch, counter, sender, instance)
    return holder, source


def floor_event(facts: dict[str, Any], holder: str | None, by: str, reason: str) -> dict[str, Any]:
    """The data of a ``floor_changed`` event."""
    return {
        "mode": facts["mode"],
        "moderator": facts["moderator"],
        "effective_moderator": facts["effective"],
        "holder": holder,
        "by": by,
        "reason": reason,
    }


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _key(raw: Any) -> Key | None:
    return None if raw is None else (int(raw[0]), int(raw[1]), str(raw[2]), str(raw[3]))


class FloorService:
    """The floor register of each group of one :class:`Engine`."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # -- state ----------------------------------------------------------------

    def _now_facts(self, group_id: str) -> dict[str, Any]:
        client = self._engine.client
        gid = unb64(group_id)
        policy = dict(json.loads(client.policy(gid)))
        return facts_of(policy, (str(m["identity"]) for m in client.members(gid)))

    def _epoch(self, group_id: str) -> int:
        return int(self._engine.client.epoch(unb64(group_id)))

    def _load(self, group_id: str) -> tuple[str | None, dict[str, Any]]:
        """The holder and the register state; a group without a row (just
        created or joined, or from before floor control) starts with nobody,
        and the facts of its current epoch."""
        row = self._engine.store.floor(group_id)
        if row is not None:
            holder, state = row
            for field in ("counters", "pending", "joins"):
                state.setdefault(field, {})
            return holder, state
        facts = self._now_facts(group_id)
        state = {
            "counters": {},
            "pending": {},
            "joins": {},
            "base": None,
            "bound": None,
            "source": None,
            "facts": {str(self._epoch(group_id)): facts},
            "reported": {
                "mode": facts["mode"],
                "moderator": facts["moderator"],
                "effective": facts["effective"],
                "holder": None,
            },
        }
        return None, state

    def _facts(self, group_id: str, state: dict[str, Any], epoch: int) -> dict[str, Any] | None:
        """The facts of ``epoch``, if kept. The current epoch's are taken
        from the group when missing (a group from before floor control)."""
        facts = state["facts"].get(str(epoch))
        if facts is None and epoch == self._epoch(group_id):
            facts = state["facts"][str(epoch)] = self._now_facts(group_id)
        return facts

    def ensure(self, group_id: str) -> None:
        """Give a group that has no floor row one, with nobody holding the
        floor: a group this runtime created or joined starts so."""
        if self._engine.store.floor(group_id) is None:
            holder, state = self._load(group_id)
            self._engine.store.set_floor(group_id, holder, state)

    def holder(self, group_id: str) -> str | None:
        row = self._engine.store.floor(group_id)
        return None if row is None else row[0]

    def view(self, group_id: str, policy: dict[str, Any], active: bool) -> dict[str, Any]:
        """The group view's ``floor``: the policy's mode, pin and moderator,
        the effective moderator and the holder (both ``None`` for a group
        that isn't active)."""
        return {
            "mode": policy.get("floor"),
            "pinned": bool(policy.get("floor_pinned")),
            "moderator": policy.get("floor_moderator"),
            "effective_moderator": self._now_facts(group_id)["effective"] if active else None,
            "holder": self.holder(group_id) if active else None,
        }

    def triggers(self, group_id: str, policy: dict[str, Any]) -> tuple[str | None, str | None]:
        """``(effective moderator, holder)``: whom ``moderated`` triggers."""
        if policy.get("floor") != "moderated":
            return None, None
        return _opt_str(self._now_facts(group_id)["effective"]), self.holder(group_id)

    def _fold(self, group_id: str, state: dict[str, Any]) -> str | None:
        base = state["base"] or {"holder": None, "source": None}
        holder, source = fold(
            base["holder"], _key(base["source"]), self._engine.store.floor_writes(group_id)
        )
        state["source"] = None if source is None else list(source)
        return holder

    def _merge(
        self, group_id: str, state: dict[str, Any], key: Key, kind: str, value: str | None
    ) -> str | None:
        """Keep a write and return the register's holder after it. A write
        older than what was folded away is not kept. Of the grants of one
        epoch only the greatest is kept: it alone decides the fold, so every
        member keeps the same set whatever order the grants came in."""
        store = self._engine.store
        bound = _key(state["bound"])
        if bound is not None and key <= bound:
            return self._fold(group_id, state)
        store.add_floor_write(group_id, key, kind, value)
        counters = state["counters"]
        counters[str(key[0])] = max(int(counters.get(str(key[0]), 0)), key[1])
        if kind == "grant":
            self._prune(group_id, state, key[0])
        return self._fold(group_id, state)

    def _prune(self, group_id: str, state: dict[str, Any], epoch: int) -> None:
        """Keep, of an epoch's grants, the greatest, the greatest that isn't
        this instance's own pending one (which may still be taken back) and
        the pending ones: the rest can never decide the fold again."""
        store = self._engine.store
        pending = {tuple(k) for k in state["pending"].values()}
        grants = [w[:4] for w in store.floor_writes(group_id) if w[0] == epoch and w[4] == "grant"]
        keep = set(pending)
        if grants:
            keep.add(max(grants))
            final = [g for g in grants if g not in pending]
            if final:
                keep.add(max(final))
        for g in grants:
            if g not in keep:
                store.delete_floor_write(group_id, g)

    def _report(
        self, state: dict[str, Any], facts: dict[str, Any], holder: str | None, by: str, reason: str
    ) -> dict[str, Any] | None:
        """``floor_changed`` data when the holder, mode, moderator or effective
        moderator differs from what was last reported."""
        now = {**{k: facts[k] for k in ("mode", "moderator", "effective")}, "holder": holder}
        if state["reported"] == now:
            return None
        state["reported"] = now
        return floor_event(facts, holder, by, reason)

    # -- grants -----------------------------------------------------------------

    def judge(
        self, group_id: str, epoch: int, sender: str, instance: str, inner: dict[str, Any]
    ) -> tuple[Key, str | None] | None:
        """The write a ``control.floor`` sent in ``epoch`` makes, or ``None``
        when it isn't valid (see the module docs)."""
        _, state = self._load(group_id)
        return self._judge(group_id, state, epoch, sender, instance, inner)

    def _judge(  # noqa: PLR0913, PLR0917
        self,
        group_id: str,
        state: dict[str, Any],
        epoch: int,
        sender: str,
        instance: str,
        inner: dict[str, Any],
    ) -> tuple[Key, str | None] | None:
        body = inner.get("body")
        shaped = normalize(FLOOR_KIND, body) if isinstance(body, dict) else None
        if shaped is None:
            return None
        return floor_write(self._facts(group_id, state, epoch), epoch, sender, instance, shaped)

    def _changed(
        self,
        group_id: str,
        state: dict[str, Any],
        before: str | None,
        holder: str | None,
        key: Key,
    ) -> dict[str, Any] | None:
        """After a write at ``key`` moved the holder from ``before``: tell
        the instances that joined in a later epoch, which can't decrypt the
        write, if this instance is the one that copies to them (SPEC 9.3),
        and return the ``floor_changed`` data."""
        if holder != before:
            for epoch, join in sorted(state["joins"].items()):
                if key[0] < int(epoch) and join["copier"]:
                    self._send_copy(group_id, holder, state, join["identities"])
        by = key[2] or self._engine.me
        return self._report(state, self._now_facts(group_id), holder, by, "grant")

    async def accept(
        self, group_id: str, epoch: int, sender: str, instance: str, inner: dict[str, Any]
    ) -> None:
        """Take a received grant (inside its message's transaction), whatever
        the local delivery policy decided for the message: a rate or a size
        limit is the receiver's own, and the register must not depend on it."""
        before, state = self._load(group_id)
        write = self._judge(group_id, state, epoch, sender, instance, inner)
        if write is None:
            return
        key, value = write
        holder = self._merge(group_id, state, key, "grant", value)
        data = self._changed(group_id, state, before, holder, key)
        self._engine.store.set_floor(group_id, holder, state)
        if data is not None:
            LOG.info("floor_changed", group=log.hid(group_id), reason="grant")
            await self._engine.emit(group_id, "floor_changed", **data)

    def seal(self, group_id: str, payload: dict[str, Any], epoch: int) -> Any:
        """This instance seals its own ``control.floor`` in ``epoch`` (inside
        the transaction that stores the sealed envelope): a grant gets the
        epoch's next counter, and the write is taken now, by the receivers'
        rule, so a crash after the relay took it loses nothing. It stays
        pending, with its epoch's facts kept, until the relay confirms it
        (:meth:`confirmed`); a reseal in a later epoch replaces it, and a send
        that fails takes it back (:meth:`unsent`). Returns the event to tell."""
        e = self._engine
        body = payload["inner"]["body"]
        if "copy" in body:
            return None  # a copy of what this instance holds: nothing to take
        before, state = self._load(group_id)
        msg_id = str(payload["msg_id"])
        self._take_back(group_id, state, msg_id)
        body["counter"] = min(int(state["counters"].get(str(epoch), 0)) + 1, MAX_FLOOR_COUNTER)
        me, instance = e.me, e.instance.instance_id_hex
        write = self._judge(group_id, state, epoch, me, instance, payload["inner"])
        key: Key = (epoch, 0, me, instance)
        if write is not None:
            key, value = write
            state["pending"][msg_id] = list(key)
            holder = self._merge(group_id, state, key, "grant", value)
        else:
            holder = self._fold(group_id, state)  # a reseal may have taken one back
        data = self._changed(group_id, state, before, holder, key)
        e.store.set_floor(group_id, holder, state)
        if data is None:
            return None
        return e._record(group_id, "floor_changed", f"floor_sent/{msg_id}/{epoch}", data)

    def _take_back(self, group_id: str, state: dict[str, Any], msg_id: str) -> None:
        key = _key(state["pending"].pop(msg_id, None))
        if key is not None:
            self._engine.store.delete_floor_write(group_id, key)

    def confirmed(self, group_id: str, msg_id: str) -> None:
        """The relay took this instance's ``control.floor``: it is final."""
        row = self._engine.store.floor(group_id)
        if row is not None and msg_id in row[1].get("pending", {}):
            holder, state = row
            key = state["pending"].pop(msg_id)
            self._prune(group_id, state, int(key[0]))
            self._engine.store.set_floor(group_id, holder, state)

    def unsent(self, group_id: str, msg_id: str) -> Any:
        """A sealed ``control.floor`` of this instance will never go out: take
        its write back. Returns the event to tell."""
        e = self._engine
        if e.store.group(group_id) is None:
            return None
        before, state = self._load(group_id)
        key = _key(state["pending"].get(msg_id))
        if key is None:
            return None
        self._take_back(group_id, state, msg_id)
        holder = self._fold(group_id, state)
        data = self._changed(group_id, state, before, holder, key)
        e.store.set_floor(group_id, holder, state)
        if data is None:
            return None
        return e._record(group_id, "floor_changed", f"floor_unsent/{msg_id}", data)

    def grant(self, group_id: str, holder: str | None, *, origin: str) -> dict[str, Any]:
        """Grant the floor to ``holder``, or release it (``None``): send
        ``control.floor`` to the group. Only the effective moderator or the
        owner of a ``moderated`` group may; the grant is taken when it is
        sealed (:meth:`seal`). ``origin`` is ``human`` for the human token,
        else ``agent``, whose grants count against its send rate like its
        messages."""
        e = self._engine
        group_id = e._group_or_raise(group_id).group_id
        facts = self._now_facts(group_id)
        if facts["mode"] != "moderated":
            raise DaemonError("not_moderated", "the group's floor isn't moderated")
        if not may_grant(facts, e.me):
            msg = "only the effective moderator or the owner grants the floor (SPEC 9.3)"
            raise DaemonError("not_permitted", msg)
        if holder is not None and holder not in facts["identities"]:
            raise DaemonError("not_found", "no such member")
        # The counter is the sealing epoch's, set when it is sealed.
        msg_id, _ = e.queue_message(
            group_id,
            {"holder": holder, "counter": 0},
            kind=FLOOR_KIND,
            origin=origin,
            floor_grant=True,
        )
        LOG.info("floor_grant_queued", group=log.hid(group_id))
        return {"status": "granted", "holder": holder, "msg_id": msg_id}

    # -- commits ----------------------------------------------------------------

    async def after_commit(self, group_id: str, summary: dict[str, Any], joined: list[str]) -> None:
        """After a merged commit (inside its transaction): keep the new
        epoch's facts, write the resets the commit makes, fold away writes no
        grant can come after any more, report a change, and send newcomers a
        copy of the current value."""
        e = self._engine
        epoch = int(summary["epoch"])
        holder, state = self._load(group_id)
        facts = self._now_facts(group_id)
        if epoch == self._epoch(group_id):
            state["facts"][str(epoch)] = facts
        before = state["facts"].get(str(epoch - 1))
        reason = "moderator"
        if self._floor_changed(summary, before, facts):
            holder = self._merge(group_id, state, (epoch, 0, "", ""), "reset", None)
            reason = "policy"
        gone = {str(m["identity"]) for m in summary.get("removed") or []}
        for identity in sorted(gone - set(facts["identities"])):
            holder = self._merge(group_id, state, (epoch, 0, "", identity), "drop", identity)
        if reason != "policy" and holder != state["reported"].get("holder"):
            reason = "reset"
        if joined:
            copier = self._copier(group_id, summary, facts)
            state["joins"][str(epoch)] = {"identities": sorted(set(joined)), "copier": copier}
        self._fold_old(group_id, state, epoch - PAST_EPOCHS)
        data = self._report(state, facts, holder, str(summary["committer"]["identity"]), reason)
        e.store.set_floor(group_id, holder, state)
        if data is not None:
            await e.emit(group_id, "floor_changed", **data)
        if joined and state["joins"][str(epoch)]["copier"] and holder is not None:
            self._send_copy(group_id, holder, state, joined)

    @staticmethod
    def _floor_changed(
        summary: dict[str, Any], before: dict[str, Any] | None, facts: dict[str, Any]
    ) -> bool:
        """Whether the commit changed ``floor`` or ``floor_moderator``."""
        if not summary.get("policy_changed"):
            return False
        previous = summary.get("previous_policy")
        if previous:
            old = json.loads(previous)
            return (old.get("floor"), old.get("floor_moderator")) != (
                facts["mode"],
                facts["moderator"],
            )
        # A summary journalled before the core reported policies.
        return before is not None and (before["mode"], before["moderator"]) != (
            facts["mode"],
            facts["moderator"],
        )

    def _fold_old(self, group_id: str, state: dict[str, Any], oldest: int) -> None:
        """Fold the writes of epochs before ``oldest`` into the base value:
        no grant from those epochs can be decrypted any more. An epoch with
        an own grant still pending keeps its writes and facts."""
        store = self._engine.store
        pending = [int(k[0]) for k in state["pending"].values()]
        oldest = min([oldest, *pending])
        old = [w for w in store.floor_writes(group_id) if w[0] < oldest]
        if old:
            base = state["base"] or {"holder": None, "source": None}
            holder, source = fold(base["holder"], _key(base["source"]), old)
            state["base"] = {"holder": holder, "source": None if source is None else list(source)}
            state["bound"] = list(old[-1][:4])
            store.drop_floor_writes(group_id, oldest)
        for field in ("facts", "counters", "joins"):
            state[field] = {k: v for k, v in state[field].items() if int(k) >= oldest}

    def _copier(self, group_id: str, summary: dict[str, Any], facts: dict[str, Any]) -> bool:
        """Whether this instance copies the floor to the instances a commit
        added: the lowest instance, among those that were in the group before
        the commit, of the effective moderator, or else of the owner (a
        moderator that just joined has no value yet)."""
        e = self._engine
        if facts["mode"] != "moderated":
            return False
        added = {str(m.get("mailbox_id")) for m in summary.get("added") or []}
        members = [m for m in e.client.members(unb64(group_id)) if m["mailbox_id"] not in added]
        senders = [m for m in members if m["identity"] == facts["effective"]] or [
            m for m in members if m["identity"] == facts["owner"]
        ]
        lowest = min(senders, key=lambda m: int(m["leaf_index"]), default=None)
        return lowest is not None and str(lowest["mailbox_id"]) == e.mailbox

    def _send_copy(
        self, group_id: str, holder: str | None, state: dict[str, Any], to: list[str]
    ) -> None:
        """Send ``to`` the current value with the key of the write that set
        it: the daemon's own control, hop 0, replying to nothing."""
        source = _key(state["source"])
        if source is None:
            return
        epoch, counter, sender, instance = source
        body = {
            "holder": holder,
            "counter": counter,
            "copy": {"epoch": epoch, "sender": sender, "instance": instance},
        }
        self._engine.queue_message(
            group_id, body, to=sorted(set(to)), kind=FLOOR_KIND, daemon_control=True
        )
