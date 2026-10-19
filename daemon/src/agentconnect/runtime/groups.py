"""Group membership in the runtime: who is in a group, how they leave or
are removed, and what each member is told (SPEC 9.2, 9.4, 11; docs/groups.md).

**Leaves.** A leaving instance sends ``control.leave``, a notice only, then
a Remove proposal for its own leaf; membership changes only with the
commit that carries it. Which leaves are pending comes from the core
(``Client.pending_leaves``), never from memory, so a restart loses nothing:
the member with the lowest leaf that isn't itself leaving commits them, and
if they are still pending :data:`LEAVE_COMMIT_GRACE_SECS` after the first
proposal of the epoch arrived, the next one does, and so on. The check runs
when a proposal arrives, on every (re)connect and on a timer.

A leave can end without a commit, and the leaver can tell: when every
instance of the owner proposes a leave at once, the one with the lowest leaf
stays (SPEC 9.2), and a transfer of ownership committed without the new
owner's pending leave ends it with the epoch. Either way the instance is now
the owner's last one, which may not leave before it hands over ownership.
It keeps its leave and reports ``leave_blocked`` once; the leave goes on
once ownership has moved. A leave that no commit completes within
``groups.leave_timeout_secs`` ends locally (``left`` with ``confirmed:
false``), but only once the runtime has caught up with the relay, and never
for an instance of the owner, whose view can't tell whether it became the
owner's last one: it keeps its state and reports ``leave_blocked`` with
``timed_out``. A group that is out of sync commits and times out no leaves.

**Events** come from the commit's summary, not from a diff of cached state,
so a replay of the same journal entry (ADR-004) reports the same:
``member_joined``, ``instance_joined``, ``member_left`` (every instance it
had left on its own), ``member_removed``, ``instance_left``,
``instance_removed``, ``policy_changed`` and ``role_changed``, each with the
committer as ``by``.

**Updates.** Each instance renews its leaf key at most 24 hours or a number
of messages after its last commit. The number is drawn per instance and
epoch in [900, 1000] (SPEC 3.1 asks for 1000 at most), so the members of a
busy group don't all commit at once.

Peer commits are untrusted: the core checks each against the group policy
before it is merged, on every member. Nothing here decides who may do what.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

import agentconnect_core as ac
from agentconnect import log
from agentconnect.backoff import Backoff
from agentconnect.relay import RelayError, b64, unb64
from agentconnect.runtime.engine import (
    TRANSFER_TIMEOUT_SECS,
    UPDATE_AFTER_MESSAGES,
    UPDATE_AFTER_SECS,
    DaemonError,
    Engine,
    ac_identity_key,
    canonical,
    new_msg_id,
)
from agentconnect.store import GroupRow, OutboxRow
from agentconnect.tasks import cancel_and_wait

LOG = log.get("agentconnect.groups")

# How long a pending leave waits for the member before the next one commits it.
LEAVE_COMMIT_GRACE_SECS = 60
# The update threshold is drawn in [UPDATE_AFTER_MESSAGES - spread, UPDATE_AFTER_MESSAGES].
UPDATE_JITTER_MESSAGES = 100
UPDATE_THRESHOLD_INFO = "agentconnect/update-threshold"
INSTANCE_ID = re.compile(r"^[0-9a-f]{16}$")
MAX_INSTANCES = 50  # SPEC 8.3: the group size
OWNER_MUST_TRANSFER = "owner_must_transfer"
OWNER_INSTANCE = "owner_instance"
LEAVE_BLOCKED_WARNING = (
    "This instance is the group owner's last one, so it can't leave yet (SPEC 9.2). "
    "Hand ownership over to another member first; the leave goes on after that."
)
OWNER_LEAVE_WARNING = (
    "No member committed this instance's leave, and an instance of the group's owner "
    "never times out on its own: it may not have seen that it is the owner's last one. "
    "Hand ownership over, or remove this instance from another instance of the owner."
)


def update_threshold(group_id: str, epoch: int, instance_id: str) -> int:
    """Messages after which this instance renews its leaf key in this epoch:
    drawn per instance and epoch in [900, 1000], so the members of a busy
    group don't reach it together. Derived, so it survives a restart."""
    digest = hashlib.sha256(canonical([UPDATE_THRESHOLD_INFO, group_id, epoch, instance_id]))
    spread = int.from_bytes(digest.digest()[:8], "big") % (UPDATE_JITTER_MESSAGES + 1)
    return UPDATE_AFTER_MESSAGES - UPDATE_JITTER_MESSAGES + spread


def role_of(policy: dict[str, Any], identity: str) -> str:
    if identity == policy.get("owner"):
        return "owner"
    admins = policy.get("admins")
    return "admin" if isinstance(admins, list) and identity in admins else "member"


def _by_identity(members: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for m in members:
        out.setdefault(str(m["identity"]), []).append(str(m["instance_id_hex"]))
    return {identity: sorted(ids) for identity, ids in out.items()}


def membership_events(
    summary: dict[str, Any], current: list[dict[str, Any]]
) -> list[tuple[str, dict[str, Any]]]:
    """The membership events of a merged commit, from its summary and the
    members after it (``Client.members``), in a stable order.

    An identity all of whose instances the commit added joined
    (``member_joined``); a new instance of an identity already in the group
    is ``instance_joined``. An identity with no instance left is
    ``member_left`` when every removed instance proposed its own leave
    (``summary["left"]``), else ``member_removed``; one that keeps an
    instance gets ``instance_left`` or ``instance_removed`` per instance."""
    by = str(summary["committer"]["identity"])
    after = _by_identity(current)
    left = {str(m["instance_id_hex"]) for m in summary.get("left") or []}
    out: list[tuple[str, dict[str, Any]]] = []
    for identity, ids in sorted(_by_identity(summary.get("added") or []).items()):
        if set(after.get(identity, [])) <= set(ids):
            out.append(("member_joined", {"identity": identity, "instances": ids, "by": by}))
            continue
        out.extend(
            ("instance_joined", {"identity": identity, "instance_id": i, "by": by}) for i in ids
        )
    for identity, ids in sorted(_by_identity(summary.get("removed") or []).items()):
        if identity not in after:
            kind = "member_left" if all(i in left for i in ids) else "member_removed"
            out.append((kind, {"identity": identity, "by": by}))
            continue
        for i in ids:
            kind = "instance_left" if i in left else "instance_removed"
            out.append((kind, {"identity": identity, "instance_id": i, "by": by}))
    return out


def policy_events(
    summary: dict[str, Any], current: dict[str, Any]
) -> list[tuple[str, dict[str, Any]]]:
    """``policy_changed`` and one ``role_changed`` per identity whose role
    (owner, admin, member) the commit changed, from the policies in the
    summary. ``current`` is the policy the core holds now.

    A summary journalled before the core reported the policies says
    ``policy_changed`` with neither: the policy it set and whether any role
    changed are unknown. Its ``policy_changed`` carries the current policy,
    ``previous_policy: None`` and ``roles_known: False``, and no
    ``role_changed`` is made up for it."""
    by = str(summary["committer"]["identity"])
    previous_raw, policy_raw = summary.get("previous_policy"), summary.get("policy")
    if previous_raw is None or policy_raw is None:
        data = {"policy": current, "previous_policy": None, "roles_known": False, "by": by}
        return [("policy_changed", data)]
    previous, policy = json.loads(previous_raw), json.loads(policy_raw)
    out: list[tuple[str, dict[str, Any]]] = [
        (
            "policy_changed",
            {"policy": policy, "previous_policy": previous, "roles_known": True, "by": by},
        )
    ]
    named = {previous.get("owner"), policy.get("owner")}
    for p in (previous, policy):
        admins = p.get("admins")
        named.update(admins if isinstance(admins, list) else [])
    for identity in sorted(str(i) for i in named if isinstance(i, str)):
        before, now = role_of(previous, identity), role_of(policy, identity)
        if before != now:
            out.append(
                ("role_changed", {"identity": identity, "from": before, "to": now, "by": by})
            )
    return out


class GroupService:
    """Membership for one :class:`Engine`: member state, commits' events,
    leaves, removals and the owner's hand-over after a SAS mismatch."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._wake = asyncio.Event()

    # -- plumbing -------------------------------------------------------------

    @property
    def _client(self) -> ac.Client:
        return self._engine.client

    def _now(self) -> int:
        return self._engine.now()

    def _kv(self, key: str) -> str:
        return self._engine.store.kv_get(key) or ""

    def wake(self) -> None:
        self._wake.set()

    # -- member state ---------------------------------------------------------

    def refresh(self, group_id: str) -> None:
        """Re-read members, roles, policy and epoch from the core."""
        e = self._engine
        gid = unb64(group_id)
        policy = json.loads(self._client.policy(gid))
        grouped: dict[str, list[dict[str, Any]]] = {}
        for m in self._client.members(gid):
            grouped.setdefault(m["identity"], []).append(
                {
                    "instance_id": m["instance_id_hex"],
                    "mailbox_id": m["mailbox_id"],
                    "leaf_index": m["leaf_index"],
                }
            )
        members = {
            identity: (role_of(policy, identity), instances)
            for identity, instances in grouped.items()
        }
        e.store.set_members(group_id, members)
        e.store.update_group(group_id, policy=policy, epoch=self._client.epoch(gid))

    def trust_state(self, group_id: str) -> dict[str, Any]:
        members = self._engine.store.members(group_id)
        others = [m for m in members if m.identity != self._engine.me]
        verified = sum(1 for m in others if m.verified)
        return {
            "self": "verified" if others and verified == len(others) else "unverified",
            "verified_members": verified,
            "members": len(members),
        }

    def update_due(self, group: GroupRow) -> bool:
        """SPEC 3.1: renew this instance's leaf a day, or a drawn number of
        messages (:func:`update_threshold`), after its last commit."""
        threshold = update_threshold(
            group.group_id, group.epoch, self._engine.instance.instance_id_hex
        )
        return (
            self._now() - group.last_own_commit_at >= UPDATE_AFTER_SECS
            or group.msgs_since_commit >= threshold
        )

    def _own_leaf(self, members: list[dict[str, Any]]) -> int | None:
        mailbox = self._engine.mailbox
        return next((int(m["leaf_index"]) for m in members if m["mailbox_id"] == mailbox), None)

    def owner_must_transfer(self, gid: bytes) -> bool:
        """Whether this instance is the owner's last one, counting the
        instances whose leave is pending as gone: it may not propose a leave
        until it hands ownership over (SPEC 9.2)."""
        if json.loads(self._client.policy(gid)).get("owner") != self._engine.me:
            return False
        pending = {int(m["leaf_index"]) for m in self._client.pending_leaves(gid)}
        members = self._client.members(gid)
        own = self._own_leaf(members)
        return not any(
            m["identity"] == self._engine.me
            and int(m["leaf_index"]) != own
            and int(m["leaf_index"]) not in pending
            for m in members
        )

    # -- commits --------------------------------------------------------------

    async def after_commit(
        self, group_id: str, summary: dict[str, Any], env: dict[str, Any] | None, own: bool
    ) -> None:
        """Bookkeeping after any merged commit, own or another member's.

        The cached members, roles, policy and epoch are re-read from the core
        first. The events come from the commit's summary (see the module
        docs), so a replay of the same journal entry emits the same ones."""
        e = self._engine
        gid = unb64(group_id)
        self.refresh(group_id)
        if env is not None:
            # Shapes were checked before processing (_envelope_problem).
            hinted = env.get("routing") or {}
            expected = summary["routing"]
            if sorted(hinted.get("add", [])) != sorted(expected["add"]) or sorted(
                hinted.get("remove", [])
            ) != sorted(expected["remove"]):
                await e.emit(
                    group_id,
                    "relay_misbehaviour",
                    reason="routing_mismatch",
                    epoch=summary["epoch"],
                )
            if env.get("epoch") is not None and env["epoch"] + 1 != summary["epoch"]:
                await e.emit(
                    group_id, "relay_misbehaviour", reason="epoch_mismatch", epoch=summary["epoch"]
                )
        if own:
            e.store.update_group(group_id, last_own_commit_at=self._now(), msgs_since_commit=0)
        for kind, data in membership_events(summary, self._client.members(gid)):
            await e.emit(group_id, kind, **data)
            if kind == "member_joined":
                await e._send_card(group_id, [data["identity"]])
        if summary.get("policy_changed"):
            current = json.loads(self._client.policy(gid))
            for kind, data in policy_events(summary, current):
                await e.emit(group_id, kind, **data)
        trust = self.trust_state(group_id)
        await e.emit(
            group_id,
            "epoch_changed",
            epoch=summary["epoch"],
            sas=e._sas(gid),
            verified=f"{trust['verified_members']} of {trust['members'] - 1} verified",
        )
        if self.leaving(group_id):
            await self._propose_again(group_id)
        e._defer(self.wake)

    async def _propose_again(self, group_id: str) -> None:
        """After a commit while leaving: the epoch ended this instance's
        proposal, so it proposes again, unless it is now the owner's last
        instance."""
        e = self._engine
        if self.owner_must_transfer(unb64(group_id)):
            await self._blocked(group_id)
            return
        if self._kv(f"leave_blocked/{group_id}"):
            # Unblocked: the timeout counts from this proposal.
            e.store.kv_set(f"leave_blocked/{group_id}", "")
            e.store.kv_set(f"leaving_since/{group_id}", str(self._now()))
        if not self._proposal_queued(group_id):
            # One queued row proposes in whatever epoch it runs in.
            e._enqueue("proposal", group_id, {})

    async def on_removed(
        self, group_id: str, summary: dict[str, Any], *, legacy: bool = False
    ) -> None:
        """A commit removed this instance: a leave if the commit carried its
        own leave proposal, otherwise a removal, as every other member reads
        the same summary. Only a summary replayed from a journal entry an
        older daemon wrote (``legacy``) may predate the core's ``left``, which
        then reads back empty: there, a leaving instance reports a leave."""
        mailbox = self._engine.mailbox
        by = str(summary["committer"]["identity"])
        own_leave = any(m["mailbox_id"] == mailbox for m in summary.get("left") or [])
        if own_leave or (legacy and self.leaving(group_id)):
            await self.gone(group_id, "left", confirmed=True, by=by)
        else:
            await self.gone(group_id, "removed", by=by)

    async def gone(
        self, group_id: str, kind: str, *, cause: str | None = None, **data: Any
    ) -> None:
        """This instance is no longer in the group (removed or left).

        The daemon's record goes first and the core's state after it (a
        crash in between is cleaned up by ``Engine._recover``): the other way
        round, a crash would leave an "active" group with no MLS state."""
        e = self._engine
        gid = unb64(group_id)
        e.store.update_group(group_id, status=kind)
        await e._drop_group_holds(group_id)
        e.store.delete_group_data(group_id)
        self._end_leave(group_id)
        await e.emit(group_id, kind, cause=cause, **data)

        def forget() -> None:
            e.safety.forget_group(group_id)
            with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                self._client.delete_group(gid)

        e._defer(forget)

    # -- leaves ---------------------------------------------------------------

    def leaving(self, group_id: str) -> bool:
        return self._kv(f"leaving/{group_id}") == "1"

    def leave_state(self, group_id: str) -> dict[str, Any] | None:
        """``{since, blocked}`` while this instance is leaving the group."""
        if not self.leaving(group_id):
            return None
        return {
            "since": int(self._kv(f"leaving_since/{group_id}") or "0"),
            "blocked": self._kv(f"leave_blocked/{group_id}") != "",
        }

    def _end_leave(self, group_id: str) -> None:
        store = self._engine.store
        store.kv_set(f"leaving/{group_id}", "0")
        for key in ("leaving_since", "leave_blocked", "leave_seen"):
            store.kv_set(f"{key}/{group_id}", "")

    def recover(self, group: GroupRow) -> None:
        """After a restart: a leave recorded before its start time was kept
        starts its timeout now."""
        if self.leaving(group.group_id) and not self._kv(f"leaving_since/{group.group_id}"):
            self._engine.store.kv_set(f"leaving_since/{group.group_id}", str(self._now()))

    async def leave(self, group_id: str) -> str:
        """Leave the group (SPEC 9.2): a sole member deletes its state; the
        owner's last instance must hand ownership over first; anyone else
        sends ``control.leave`` and its leave proposal, and leaves once a
        member commits it."""
        e = self._engine
        e._group_or_raise(group_id)
        gid = unb64(group_id)
        if len(self._client.members(gid)) == 1:
            # Sole member: delete, recorded with its event in one transaction.
            await self._gone_atomically("leave", group_id, "left", confirmed=True)
            return "left"
        if self.owner_must_transfer(gid):
            raise DaemonError("forbidden", "transfer ownership before leaving (SPEC 9.2)")
        if self.leaving(group_id):
            return "leaving"
        with e.store.tx():
            e.store.kv_set(f"leaving/{group_id}", "1")
            e.store.kv_set(f"leaving_since/{group_id}", str(self._now()))
            e.store.kv_set(f"leave_blocked/{group_id}", "")
            # SPEC 7.3: a notice right before the proposal; it changes nothing.
            e.send_message(group_id, {}, kind="control.leave", internal=True)
            e._enqueue("proposal", group_id, {})
        self.wake()
        return "leaving"

    async def _gone_atomically(
        self, path: str, group_id: str, kind: str, *, cause: str | None = None, **data: Any
    ) -> None:
        """:meth:`gone` in one daemon transaction (failpoints ``<path>.in_tx``
        and ``<path>.after_tx``): a crash leaves either the group and its leave
        as they were, or the group gone and its event recorded, which the
        adapter is told of after a restart."""

        async def body() -> str:
            await self.gone(group_id, kind, cause=cause, **data)
            return kind

        await self._engine._apply(path, body)

    async def _blocked(
        self, group_id: str, *, timed_out: bool = False, reason: str = OWNER_MUST_TRANSFER
    ) -> None:
        """Tell the human (once, and once more at the timeout) that this
        leave waits for an ownership transfer."""
        key = f"leave_blocked/{group_id}"
        state, want = self._kv(key), "timeout" if timed_out else "blocked"
        if state in (want, "timeout"):
            return
        self._engine.store.kv_set(key, want)
        LOG.info("leave_blocked", group=log.hid(group_id), timed_out=timed_out)
        since = self._kv(f"leaving_since/{group_id}")
        await self._engine.emit(
            group_id,
            "leave_blocked",
            cause=f"leave_blocked/{since}/{want}",
            reason=reason,
            timed_out=timed_out,
            warning=LEAVE_BLOCKED_WARNING if reason == OWNER_MUST_TRANSFER else OWNER_LEAVE_WARNING,
        )

    async def run_proposal(self, row: OutboxRow, group: GroupRow) -> str:
        """Send this instance's leave proposal (an outbox row)."""
        e = self._engine
        gid = unb64(group.group_id)
        payload = dict(row.payload)
        if "env" in payload and int(payload["env"]["epoch"]) != int(self._client.epoch(gid)):
            payload.pop("env")  # built in an epoch that ended: propose in this one
        if "env" not in payload:
            if not self.leaving(group.group_id):
                return "failed"  # the leave ended meanwhile
            if self.owner_must_transfer(gid):
                await self._blocked(group.group_id)
                return "failed"
            members = self._client.members(gid)
            own = self._own_leaf(members)
            if any(int(m["leaf_index"]) == own for m in self._client.pending_leaves(gid)):
                return "done"  # proposed in this epoch already: once is enough
            try:
                proposal = self._client.propose_leave(gid)
            except ac.AgentConnectError as e_:
                LOG.info("leave_not_possible", reason=str(e_)[:60])
                if self.owner_must_transfer(gid):
                    await self._blocked(group.group_id)
                return "failed"
            payload["env"] = {
                "v": 0,
                "kind": "proposal",
                "group_id": group.group_id,
                "epoch": self._client.epoch(gid),
                "msg_id": new_msg_id(),
                "sender": e.mailbox,
                "ct": b64(proposal),
            }
            e.store.update_outbox(row.seq, payload=payload)
        try:
            await e._request({"t": "send", "env": payload["env"]}, str(payload["env"]["msg_id"]))
        except RelayError as err:
            # A stale proposal: the next commit we process triggers a resend.
            LOG.info("proposal_failed", code=err.code)
            return "failed"
        return "done"

    async def on_leave_proposed(self, group_id: str, member: dict[str, Any]) -> None:
        """Another member proposed its own removal (inside the journal
        entry's transaction)."""
        e = self._engine
        await e.emit(
            group_id,
            "member_leaving",
            identity=str(member["identity"]),
            instance_id=str(member["instance_id_hex"]),
        )
        self.check_leaves(group_id)
        if self.leaving(group_id) and self.owner_must_transfer(unb64(group_id)):
            # Every owner instance proposed at once and this one, the lowest,
            # stays (SPEC 9.2): its own leave is not pending any more.
            await self._blocked(group_id)
        e._defer(self.wake)

    def _proposal_queued(self, group_id: str) -> bool:
        """Whether a leave proposal for the current epoch waits in the outbox:
        one not built yet (it proposes in whatever epoch it runs in), or built
        in this epoch and being sent. One built in an earlier epoch is for an
        epoch that ended, so it doesn't count."""
        epoch = int(self._client.epoch(unb64(group_id)))
        return any(
            r.kind == "proposal"
            and r.group_id == group_id
            and ("env" not in r.payload or int(r.payload["env"]["epoch"]) == epoch)
            for r in self._engine.store.outbox()
        )

    def _proposals_queued(self, group_id: str) -> bool:
        return any(
            r.kind == "commit"
            and r.group_id == group_id
            and (r.payload.get("intent") or {}).get("type") == "proposals"
            for r in self._engine.store.outbox()
        )

    def check_leaves(self, group_id: str) -> float | None:
        """Commit the group's pending leaves if this instance is the one to:
        the lowest leaf not itself leaving at once, the next one after
        :data:`LEAVE_COMMIT_GRACE_SECS`, and so on, counted from when the
        epoch's first leave proposal reached this instance. Returns when to
        check again, or ``None``."""
        e = self._engine
        group = e.store.group(group_id)
        if group is None or group.out_of_sync:
            return None  # its commits can't land: a retry would only fail again
        gid = unb64(group_id)
        key = f"leave_seen/{group_id}"
        pending = self._client.pending_leaves(gid)
        if not pending:
            if self._kv(key):
                e.store.kv_set(key, "")
            return None
        now, epoch = self._now(), int(self._client.epoch(gid))
        seen = json.loads(self._kv(key) or "null")
        if not isinstance(seen, dict) or seen.get("epoch") != epoch:
            seen = {"epoch": epoch, "at": now}
            e.store.kv_set(key, json.dumps(seen))
        leaving = {int(m["leaf_index"]) for m in pending}
        members = self._client.members(gid)
        candidates = sorted(int(m["leaf_index"]) for m in members if m["leaf_index"] not in leaving)
        own = self._own_leaf(members)
        if own is None or own not in candidates:
            return None
        if self.leaving(group_id) and not self.owner_must_transfer(gid):
            # Its own leave is queued or pending: the core refuses its commits.
            # (The owner's kept instance, whose leave was dropped, commits.)
            return None
        due = int(seen["at"]) + candidates.index(own) * LEAVE_COMMIT_GRACE_SECS
        tried = seen.get("tried")
        if isinstance(tried, int):
            due = max(due, tried + LEAVE_COMMIT_GRACE_SECS)
        if now < due:
            return float(due)
        if not self._proposals_queued(group_id):
            e._enqueue("commit", group_id, {"intent": {"type": "proposals"}})
            seen["tried"] = now
            e.store.kv_set(key, json.dumps(seen))
        # Check again later: the commit may lose a race or fail.
        return float(now + LEAVE_COMMIT_GRACE_SECS)

    async def _leave_timeout(self, group: GroupRow) -> float | None:
        """D10: a leave no commit completes ends locally after
        ``groups.leave_timeout_secs``.

        Never for an instance of the owner (in the latest state it knows):
        a sibling's leave, or the commit that made it the owner's only
        instance, may not have reached it, so it keeps its state and reports
        ``leave_blocked`` with ``timed_out``. Anyone else times out only once
        its view is current (``Engine.caught_up``: connected, the reconnect
        drain handled, the journal replayed), and only if it is then still a
        member and still not the owner: a transfer to an instance that slept
        through its deadline reaches it first."""
        e = self._engine
        group_id = group.group_id
        if not self.leaving(group_id):
            return None
        since = int(self._kv(f"leaving_since/{group_id}") or str(self._now()))
        due = since + e.config.groups_leave_timeout_secs
        if self._now() < due:
            return float(due)
        gid = unb64(group_id)
        current = e.caught_up()
        if json.loads(self._client.policy(gid)).get("owner") == e.me:
            reason = OWNER_MUST_TRANSFER if self.owner_must_transfer(gid) else OWNER_INSTANCE
            await self._blocked(group_id, timed_out=True, reason=reason)
            return None
        if not current or self._own_leaf(self._client.members(gid)) is None:
            return None  # catching up wakes the timer
        LOG.info("leave_timed_out", group=log.hid(group_id))
        await self._gone_atomically(
            "leave_timeout", group_id, "left", cause=f"left/{group_id}/{since}", confirmed=False
        )
        return None

    async def step(self) -> float | None:
        """One pass of the timer over the active groups; when the next is due."""
        times: list[float] = []
        for group in self._engine.store.groups():
            if group.status != "active" or group.out_of_sync:
                continue  # an out-of-sync view decides nothing
            try:
                due = [self.check_leaves(group.group_id), await self._leave_timeout(group)]
            except (ac.AgentConnectError, ac.CoreError) as err:
                LOG.info("group_timer_skipped", reason=type(err).__name__)
                continue
            times.extend(d for d in due if d is not None)
        return min(times) if times else None

    async def run(self) -> None:
        """The membership timer: pending leaves this instance commits after
        the grace period, and leave timeouts. A pass that fails is logged by
        type and retried after a backoff."""
        e = self._engine
        backoff = Backoff(base=1.0, cap=300.0, rng=e.options.backoff_rng)
        while True:
            self._wake.clear()
            try:
                due = await self.step()
                backoff.reset()
            except Exception as err:
                LOG.warning("group_timer_failed", error=type(err).__name__)
                due = self._now() + backoff.next()
            woken = asyncio.ensure_future(self._wake.wait())
            waits: set[asyncio.Future[Any]] = {woken}
            if due is not None:
                waits.add(asyncio.ensure_future(e.clock.sleep_until(due, deadline=True)))
            try:
                await asyncio.sleep(0)
                e._pulse()
                await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for w in waits:
                    w.cancel()

    # -- removal --------------------------------------------------------------

    def remove_member(self, group_id: str, identity: str) -> None:
        """Commit the removal of every instance of ``identity`` (SPEC 9.2;
        the core checks this instance's role)."""
        group = self._engine._group_or_raise(group_id)
        self._engine._enqueue(
            "commit", group.group_id, {"intent": {"type": "remove", "identity": identity}}
        )

    def remove_instances(self, group_id: str, identity: str, instance_ids: list[str]) -> None:
        """Commit the removal of some of ``identity``'s instances, such as a
        dead replica (SPEC 9.2). One's own identity's other instances need
        no permission; anyone else's need ``remove``, which the core checks.
        This instance can't remove itself: it leaves."""
        e = self._engine
        group = e._group_or_raise(group_id)
        if not 0 < len(instance_ids) <= MAX_INSTANCES or not all(
            isinstance(i, str) and INSTANCE_ID.match(i) for i in instance_ids
        ):
            msg = f"instances must list 1 to {MAX_INSTANCES} instance ids (16 hex characters)"
            raise DaemonError("bad_request", msg)
        member = next((m for m in e.store.members(group_id) if m.identity == identity), None)
        if member is None:
            raise DaemonError("not_found", "no such member")
        known = {str(i["instance_id"]) for i in member.instances}
        if not set(instance_ids) <= known:
            raise DaemonError("not_found", "no such instance of this member")
        if e.instance.instance_id_hex in instance_ids:
            raise DaemonError("bad_request", "this instance can't remove itself: leave instead")
        e._enqueue(
            "commit",
            group.group_id,
            {
                "intent": {
                    "type": "remove_instances",
                    "identity": identity,
                    "instances": sorted(set(instance_ids)),
                }
            },
        )

    # -- SAS mismatch (SPEC 11) -------------------------------------------------

    async def sas_mismatch(self, group_id: str, epoch: int | None = None) -> str:
        """**Human-only.** The human compared the SAS of the current epoch and
        the codes differ (SPEC 11): the group view may be forked. Leave at
        once and raise ``sas_mismatch``.

        * The owner's last instance first makes a best-effort ownership
          transfer (SPEC 9.2): a policy commit naming the lowest-index admin,
          or else the lowest-index other member, sent and awaited for at most
          ``TRANSFER_TIMEOUT_SECS``. If the relay confirms it, this
          instance is now a plain member and proposes its own removal.
        * Anyone else sends a leave proposal when one is allowed.
        * A sole member just deletes.

        The local group state is deleted in every case, since nothing more
        from this view can be trusted. ``epoch`` guards against answering
        for a code from an earlier epoch."""
        e = self._engine
        group = e._group_or_raise(group_id)
        gid = unb64(group_id)
        current = e._core_epoch(gid)
        if epoch is not None and epoch != current:
            msg = f"the SAS shown was for epoch {epoch}; the group is at epoch {current}"
            raise DaemonError("stale_epoch", msg)
        sas = e._sas(gid)
        transfer: dict[str, Any] | None = None
        if self._is_last_owner_instance(group):
            transfer = await self.transfer_ownership(group)
        if transfer is None or transfer["confirmed"]:
            self._propose_own_leave(group)
        await self.gone(group_id, "left", confirmed=False)
        e.store.update_group(group_id, out_of_sync=True, out_of_sync_reason="sas_mismatch")
        data: dict[str, Any] = {"epoch": current, "sas": sas}
        if transfer is not None:
            data["transfer"] = transfer
        await e.emit(group_id, "sas_mismatch", **data)
        return "left"

    def _is_last_owner_instance(self, group: GroupRow) -> bool:
        me = self._engine.me
        if group.policy.get("owner") != me:
            return False
        mine = [m for m in self._client.members(unb64(group.group_id)) if m["identity"] == me]
        return len(mine) == 1

    def _next_owner(self, group: GroupRow) -> str | None:
        """The lowest-index admin, else the lowest-index other member."""
        me = self._engine.me
        members = sorted(
            (m for m in self._client.members(unb64(group.group_id)) if m["identity"] != me),
            key=lambda m: m["leaf_index"],
        )
        admins = set(group.policy.get("admins", []))
        for m in members:
            if m["identity"] in admins:
                return str(m["identity"])
        return str(members[0]["identity"]) if members else None

    async def transfer_ownership(self, group: GroupRow) -> dict[str, Any] | None:
        """Commit ``owner = next owner`` and wait (bounded) for the relay.
        ``None`` for a sole member; otherwise who and whether it landed."""
        e = self._engine
        new_owner = self._next_owner(group)
        if new_owner is None:
            return None
        gid = unb64(group.group_id)
        policy = {**json.loads(self._client.policy(gid)), "owner": new_owner}
        policy["admins"] = [a for a in policy.get("admins", []) if a != new_owner]
        result: dict[str, Any] = {"new_owner": new_owner, "confirmed": False}
        try:
            out = self._client.set_policy(gid, canonical(policy))
        except (ac.AgentConnectError, ac.CoreError) as err:
            LOG.info("ownership_transfer_not_built", reason=str(err)[:60])
            return result
        env = {
            "v": 0,
            "kind": "commit",
            "group_id": group.group_id,
            "epoch": out["epoch"],
            "msg_id": out["msg_id"],
            "sender": e.mailbox,
            "routing": out["routing"],
            "ct": b64(out["commit"]),
        }
        send = asyncio.ensure_future(e._request({"t": "send", "env": env}, out["msg_id"]))
        timer = asyncio.ensure_future(e._sleep(TRANSFER_TIMEOUT_SECS))
        try:
            await asyncio.wait({send, timer}, return_when=asyncio.FIRST_COMPLETED)
        except BaseException:
            await cancel_and_wait(send, timer, ignore=(Exception,))
            raise
        timer.cancel()
        if send.done() and not send.cancelled() and send.exception() is None:
            # Accepted; the fan-out echo may already have merged it.
            with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                self._client.confirm_pending_commit(gid, str(out["msg_id"]))
        try:
            confirmed = json.loads(self._client.policy(gid)).get("owner") == new_owner
        except (ac.AgentConnectError, ac.CoreError, ValueError):
            confirmed = False
        # Stops the send if it is still waiting; a cancellation of this task
        # meanwhile propagates (a restart discards the unsent commit, §8.3).
        await cancel_and_wait(send, timer, ignore=(Exception,))
        if not confirmed:
            with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                self._client.discard_pending_commit(gid)
        result["confirmed"] = confirmed
        LOG.info("ownership_transfer", confirmed=confirmed)
        return result

    def _propose_own_leave(self, group: GroupRow) -> None:
        """Queue a self-Remove proposal when SPEC 9.2 allows one."""
        e = self._engine
        gid = unb64(group.group_id)
        try:
            proposal = self._client.propose_leave(gid)
        except (ac.AgentConnectError, ac.CoreError) as err:
            LOG.info("sas_mismatch_no_proposal", reason=str(err)[:60])
            return
        msg_id = new_msg_id()
        env = {
            "v": 0,
            "kind": "proposal",
            "group_id": group.group_id,
            "epoch": e._core_epoch(gid),
            "msg_id": msg_id,
            "sender": e.mailbox,
            "ct": b64(proposal),
        }
        e._enqueue("frame", None, {"frame": {"t": "send", "env": env}, "msg_id": msg_id})

    # -- the view -------------------------------------------------------------

    def group_info(self, group_id: str) -> dict[str, Any]:
        e = self._engine
        group = e.store.group(group_id)
        if group is None:
            raise DaemonError("not_found", "no such group")
        info: dict[str, Any] = {
            "group_id": group.group_id,
            "name": group.name,
            "purpose": group.purpose,
            "status": group.status,
            "epoch": group.epoch,
            "policy": group.policy,
            "out_of_sync": group.out_of_sync,
            "out_of_sync_reason": group.out_of_sync_reason,
            "adapter": group.adapter,
            "trust_state": self.trust_state(group_id),
            "leaving": self.leave_state(group_id),
            "members": [
                {
                    "identity": m.identity,
                    "fingerprint": ac.fingerprint(ac_identity_key(m.identity)),
                    "display_name": m.display_name,
                    "display_name_verified": False,
                    "role": m.role,
                    "verified": m.verified,
                    "instances": [
                        {**i, "self": i.get("mailbox_id") == e.mailbox} for i in m.instances
                    ],
                    "self": m.identity == e.me,
                }
                for m in e.store.members(group_id)
            ],
            # SPEC 10.1: peer-supplied, so framed as untrusted.
            "agent_cards": {
                identity: {"untrusted": True, "card": card}
                for identity, card in e.store.cards(group_id).items()
            },
        }
        if group.status == "active":
            info["sas"] = e._sas(unb64(group_id))
        e._knock_origin(group_id, info)
        return info
