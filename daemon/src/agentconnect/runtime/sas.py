"""SAS runs (SPEC 11): the commit-then-reveal exchange behind the short code.

A run is between this instance and one instance of another member. Its human
starts it (``start``, human API only); the daemon sends its commitment,
pairs the run with the first commitment addressed to it from an instance of
the peer, reveals its nonce once the run is paired and the relay accepted
its own commitment, checks the peer's reveal and derives the code. Every
ceremony message stays in the daemon: :meth:`SasService.on_message` takes
them before the safety policy and nothing reaches an adapter.

What a run keeps:

* in memory: the run itself (it doesn't survive a restart, SPEC 11.3),
  the commitments held before a run, the ceremony budget and the cadence
  deferral;
* in the encrypted store: the commitments answered in the current epoch,
  written before the reveal goes out (``sas_answered``), and the warning
  count per peer (``sas_warnings``).

Events are human-only by type (``SAS_EVENTS``, part of ``HUMAN_EVENTS``):
no agent token, adapter or SDK agent sees a code, a run or a prompt.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import agentconnect_core as ac
from agentconnect import log
from agentconnect.backoff import Backoff
from agentconnect.relay import b64, unb64

if TYPE_CHECKING:
    from agentconnect.runtime.engine import Engine
    from agentconnect.store import GroupRow

LOG = log.get("agentconnect.sas")

SAS_COMMIT = "control.sas_commit"
SAS_REVEAL = "control.sas_reveal"
SAS_KINDS = frozenset({SAS_COMMIT, SAS_REVEAL})

RUN_TIMEOUT_SECS = 600  # SPEC 11.3, as Matrix SAS verification
HELD_TTL_SECS = 600
UNPAIRED_NOTICE_SECS = 60
SAME_WINDOW_SECS = 600  # SPEC 11.5: "same" within 600 s of step 5
SIBLING_WINDOW_SECS = 600  # step 1: one run per pair of identities
MAX_RESTARTS = 3
WARNING_STOP = 2
BUDGET = 12  # ceremony messages a minute from one sending instance
BUDGET_WINDOW_SECS = 60
UPDATE_DEFER_SECS = 600  # SPEC 3.1: all deferrals of one due Update
MAX_EPOCH = (1 << 53) - 1
NONCE_LEN = 32

# Human-only by type (SPEC 11.5): a prompt, a run's progress and its code.
SAS_EVENTS = frozenset(
    {
        "sas_requested",
        "sas_paired",
        "sas_code",
        "sas_aborted",
        "sas_unpaired",
        "sas_stopped",
        "verifications_reset",
    }
)

# Aborts after this instance's reveal are warnings whatever the reason; these
# are warnings at any time (SPEC 11.3, "Warnings and the abort count").
ALWAYS_WARNING = frozenset({"bad_reveal", "out_of_order"})

STOP_TEXT = (
    "Comparisons with {name} ended twice without a code. This is what an attacker in the "
    "middle produces, but also what a relay that drops messages, or an ordinary commit by "
    "another member, produces.{committers} If {name}'s human says they saw a code, or you "
    "can't finish a comparison, treat it as different codes."
)
UNPAIRED_TEXT = (
    "If {name} says they have started, your daemons don't see the same group. "
    "Treat this as different codes."
)
WARNING_TEXT = (
    "The comparison ended the way an attacker in the middle ends a run it can't win. "
    "It can also be a relay that drops messages, or another member's commit."
)


class SasError(Exception):
    """A run the human asked for can't go ahead; ``code`` is the API code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical_b64(value: object, size: int) -> bytes | None:
    """The bytes of canonical base64url of ``size`` bytes, else ``None``."""
    if not isinstance(value, str) or not value.isascii():
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(raw) != size or b64(raw) != value:
        return None
    return raw


def canonical_identity(value: object) -> bool:
    """``ac:v0:`` and the canonical base64url of a 32-byte key (SPEC 2, 11.2)."""
    return (
        isinstance(value, str)
        and value.startswith("ac:v0:")
        and _canonical_b64(value[6:], 32) is not None
    )


def label(instance_hex: str) -> str:
    """An instance label (SPEC 11.4): the first 8 hex characters."""
    return instance_hex[:8]


@dataclass
class Run:
    """One SAS run of this instance with ``peer`` (SPEC 11.3)."""

    run_id: str
    group_id: str
    peer: str
    started_at: int
    command: str
    restart: int = 0
    want_instance: str | None = None
    epoch: int | None = None
    nonce: Any = None  # ac.SasNonce, in Rust; None once the run ended
    commitment: bytes | None = None
    commit_accepted: bool = False
    paired: tuple[str, bytes] | None = None  # (instance hex, commitment)
    revealed: bool = False
    peer_nonce: bytes | None = None
    code: dict[str, Any] | None = None
    shown_at: int | None = None
    state: str = "starting"  # starting, waiting, exchanging, done, aborted
    reason: str | None = None
    warning: bool = False
    committer: str | None = None
    peer_started: bool = False
    unpaired_told: bool = False
    same_closed: bool = False
    answered: bool = False
    next_run: str | None = None
    acknowledged: bool = False

    @property
    def under_way(self) -> bool:
        return self.state in ("starting", "waiting", "exchanging")


@dataclass
class _Held:
    commitment: bytes
    epoch: int
    at: int


@dataclass
class _Budget:
    times: deque[int] = field(default_factory=deque)


class SasService:
    """SAS runs of one engine (SPEC 11.3)."""

    def __init__(self, engine: Engine) -> None:
        self._e = engine
        self._runs: dict[str, Run] = {}
        # (group, peer identity) -> the run under way.
        self._active: dict[tuple[str, str], str] = {}
        # (group, sender identity, sender instance) -> a held commitment.
        self._held: dict[tuple[str, str, str], _Held] = {}
        # (group, peer identity) -> when another instance of this identity
        # last committed to that peer, and in which epoch (step 1).
        self._siblings: dict[tuple[str, str], tuple[int, int]] = {}
        self._budgets: dict[tuple[str, str], _Budget] = {}
        self._update_due_since: dict[str, int] = {}
        self._wake = asyncio.Event()

    # -- helpers ----------------------------------------------------------------

    def _now(self) -> int:
        return self._e.now()

    def _name(self, group_id: str, identity: str) -> str:
        return self._e._display_name(group_id, identity) or identity

    def wake(self) -> None:
        self._wake.set()

    def _under_way(self, group_id: str) -> list[Run]:
        return [r for r in self._runs.values() if r.group_id == group_id and r.under_way]

    # -- the human's side (human API only) -----------------------------------------

    def start(
        self,
        group_id: str,
        peer: str,
        *,
        instance: str | None = None,
        acknowledge: bool = False,
        after: Run | None = None,
    ) -> dict[str, Any]:
        """**Human-only.** Start a run with ``peer`` (SPEC 11.3 step 1).
        ``after`` is the run this one restarts (same command)."""
        e = self._e
        restart = 0 if after is None else after.restart + 1
        group = e._group_or_raise(group_id)
        if peer == e.me:
            raise SasError("bad_request", "a run with one's own identity is refused")
        member = next((m for m in e.store.members(group_id) if m.identity == peer), None)
        if member is None:
            raise SasError("not_found", "no such member")
        if instance is not None and instance not in {
            str(i["instance_id"]) for i in member.instances
        }:
            raise SasError("not_found", "no such instance of this member")
        if (group_id, peer) in self._active:
            raise SasError("conflict", "a comparison with this member is under way")
        epoch = e._core_epoch(unb64(group_id))
        if epoch > MAX_EPOCH:
            raise SasError("bad_request", "the group's epoch is beyond a run's range")
        sibling = self._siblings.get((group_id, peer))
        if (
            sibling is not None
            and sibling[0] == epoch
            and self._now() - sibling[1] < (SIBLING_WINDOW_SECS)
        ):
            raise SasError(
                "conflict",
                "another instance of your identity is comparing codes with this member",
            )
        count, committers = e.store.sas_warnings(group_id, peer)
        if count >= WARNING_STOP and not acknowledge and restart == 0:
            raise SasError("sas_stopped", self._stop_text(group_id, peer, committers))
        now = self._now()
        run = Run(
            run_id=b64(secrets.token_bytes(16)),
            group_id=group_id,
            peer=peer,
            started_at=now,
            command=after.command if after is not None else b64(secrets.token_bytes(16)),
            restart=restart,
            want_instance=instance,
            acknowledged=acknowledge,
        )
        # SPEC 11.5: a new run ends the "same" window of earlier ones.
        self._close_same(group_id, peer)
        self._runs[run.run_id] = run
        self._active[(group_id, peer)] = run.run_id
        self._begin(run, group)
        self.wake()
        return self.view(group_id, run.run_id)

    def _begin(self, run: Run, group: GroupRow | None = None) -> None:
        """Step 1 once no own commit is pending: the nonce and the commitment."""
        e = self._e
        gid = unb64(run.group_id)
        if group is None:
            group = e.store.group(run.group_id)
        if group is None or group.status != "active":
            self._abort(run, "group_gone")
            return
        try:
            if e.client.has_pending_commit(gid):
                return  # waits: begun after the commit is confirmed or discarded
            run.epoch = e._core_epoch(gid)
            run.nonce = e.client.sas_nonce()
            run.commitment = bytes(e.client.sas_commitment(gid, run.peer, run.nonce))
        except (ac.AgentConnectError, ac.CoreError) as err:
            LOG.info("sas_begin_failed", error=type(err).__name__)
            self._abort(run, "failed")
            return
        run.state = "waiting"
        body = {"commitment": b64(run.commitment), "epoch": run.epoch, "peer": run.peer}
        with e.store.tx():
            self._send(run, SAS_COMMIT, body, [run.peer])
        # A commitment held from before the run (the peer's human started first).
        held = sorted(
            (
                (h.at, inst, h)
                for (g, s, inst), h in self._held.items()
                if g == run.group_id and s == run.peer and h.epoch == run.epoch
            ),
            key=lambda x: x[0],
        )
        for _at, inst, h in held:
            if self._pairable(run, inst, h.commitment):
                del self._held[(run.group_id, run.peer, inst)]
                self._pair(run, inst, h.commitment)
                break

    def _send(self, run: Run, kind: str, body: dict[str, Any], to: list[str]) -> None:
        """Queue one ceremony message (inside a transaction). It bypasses the
        safety policy: own sends don't count against what this instance
        accepts, and ceremony messages carry no content."""
        e = self._e
        msg_id = b64(secrets.token_bytes(16))
        inner = e.inner(kind, body, to, origin="human", hop=0)
        meta = {"run": run.run_id, "kind": kind, "epoch": run.epoch}
        e._enqueue("app", run.group_id, {"inner": inner, "msg_id": msg_id, "sas": meta})

    def view(self, group_id: str, run_id: str) -> dict[str, Any]:
        """**Human-only.** A run as the human sees it (SPEC 11.5)."""
        run = self._runs.get(run_id)
        if run is None or run.group_id != group_id:
            raise SasError("not_found", "no such comparison (runs end with a restart)")
        now = self._now()
        state = run.state
        count, committers = self._e.store.sas_warnings(group_id, run.peer)
        out: dict[str, Any] = {
            "run": run.run_id,
            "group_id": group_id,
            "peer": run.peer,
            "peer_name": self._e._display_name(group_id, run.peer),
            "epoch": run.epoch,
            "state": state,
            "unpaired": run.under_way and run.paired is None and run.unpaired_told,
            "peer_started": run.peer_started,
            "reason": run.reason,
            "warning": run.warning,
            "committer": run.committer,
            "next": run.next_run,
            "warnings": count,
            "stopped": count >= WARNING_STOP,
            "answerable": self._answerable(run, now),
            "expires_at": run.started_at + RUN_TIMEOUT_SECS,
        }
        if run.paired is not None:
            out["peer_instance"] = run.paired[0]
        if run.code is not None:
            out["sas"] = run.code
            out["labels"] = {
                "self": label(self._e.instance.instance_id_hex),
                "peer": label(run.paired[0] if run.paired else ""),
            }
        if out["stopped"]:
            out["stop_text"] = self._stop_text(group_id, run.peer, committers)
        never_paired = run.state == "aborted" and run.paired is None and run.reason != "mismatch"
        if out["unpaired"] or never_paired:
            # SPEC 11.5: a run that never pairs is how a fork can show.
            out["unpaired_text"] = UNPAIRED_TEXT.format(name=self._name(group_id, run.peer))
        if run.warning:
            out["warning_text"] = WARNING_TEXT
        return out

    def _answerable(self, run: Run, now: int) -> bool:
        return (
            run.state == "done"
            and run.shown_at is not None
            and now - run.shown_at <= SAME_WINDOW_SECS
            and not run.same_closed
            and not run.answered
        )

    def confirm(self, group_id: str, run_id: str) -> str:
        """**Human-only.** The human read the same code (SPEC 11.5): the peer
        identity is verified at this instance, also after an epoch change
        within the window. Returns the peer identity."""
        e = self._e
        e._group_or_raise(group_id)
        run = self._runs.get(run_id)
        if run is None or run.group_id != group_id:
            raise SasError("not_found", "no such comparison")
        if run.state != "done":
            raise SasError("not_done", "this comparison has no code yet, or it ended without one")
        if not self._answerable(run, self._now()):
            raise SasError(
                "stale_epoch",
                "this code can't be confirmed any more (too old, or a newer comparison "
                "with this member started): compare again",
            )
        with e.store.tx():
            if not e.store.set_verified(group_id, run.peer, True, run.epoch):
                raise SasError("not_found", "no such member")
            e.store.set_sas_warnings(group_id, run.peer, 0, [])
        run.answered = True
        return run.peer

    def peer_started(self, group_id: str, run_id: str) -> dict[str, Any]:
        """**Human-only.** The human says the peer started its side: if the
        run then times out unpaired, that is a warning (SPEC 11.3)."""
        run = self._runs.get(run_id)
        if run is None or run.group_id != group_id:
            raise SasError("not_found", "no such comparison")
        run.peer_started = True
        return self.view(group_id, run_id)

    def mismatch(self, group_id: str, run_id: str | None) -> None:
        """The human answered "differ" (or took the mismatch action): the run
        ends; the group leaves through :meth:`GroupService.sas_mismatch`."""
        run = self._runs.get(run_id or "")
        if run is not None and run.group_id == group_id:
            run.answered = True
            if run.under_way:
                self._end(run, "mismatch")

    def _stop_text(self, group_id: str, peer: str, committers: list[str]) -> str:
        names = sorted({self._name(group_id, c) for c in committers})
        said = f" The runs were ended by commits from: {', '.join(names)}." if names else ""
        return STOP_TEXT.format(name=self._name(group_id, peer), committers=said)

    def _close_same(self, group_id: str, peer: str) -> None:
        for r in self._runs.values():
            if r.group_id == group_id and r.peer == peer:
                r.same_closed = True

    # -- pairing and the reveal --------------------------------------------------------

    def _pairable(self, run: Run, instance: str, commitment: bytes) -> bool:
        return (
            run.state == "waiting"
            and run.paired is None
            and (run.want_instance is None or run.want_instance == instance)
            and not self._e.store.sas_answered(run.group_id, int(run.epoch or 0), commitment)
        )

    def _pair(self, run: Run, instance: str, commitment: bytes) -> None:
        run.paired = (instance, commitment)
        run.state = "exchanging"
        self._event(run, "sas_paired", peer_instance=instance)
        self._maybe_reveal(run)

    def _maybe_reveal(self, run: Run) -> None:
        """Step 3: the reveal, once paired and once the relay accepted this
        instance's commitment. The answered commitment is stored in the same
        transaction that queues the reveal, so before the reveal goes out."""
        if run.revealed or run.paired is None or not run.commit_accepted or not run.under_way:
            return
        e = self._e
        instance, commitment = run.paired
        body = {"answers": b64(commitment), "epoch": run.epoch, "nonce": b64(run.nonce.reveal())}
        with e.store.tx():
            e.store.add_sas_answered(run.group_id, int(run.epoch or 0), commitment)
            self._send(run, SAS_REVEAL, body, [run.peer])
        run.revealed = True
        self._maybe_done(run)
        LOG.info("sas_revealed", group=log.hid(run.group_id), instance=log.hid(instance))

    def _maybe_done(self, run: Run) -> None:
        """Step 5: the code, under this epoch's authenticator only."""
        if not (run.revealed and run.peer_nonce is not None and run.paired is not None):
            return
        e = self._e
        try:
            sas = e.client.sas_code(
                unb64(run.group_id),
                int(run.epoch or 0),
                run.nonce,
                run.peer,
                int(run.paired[0], 16),
                run.peer_nonce,
            )
        except (ac.AgentConnectError, ac.CoreError) as err:
            # Another epoch by now, or the peer instance left: no code.
            LOG.info("sas_code_refused", error=type(err).__name__)
            self._abort(run, "epoch_changed")
            return
        run.code = {"decimal": sas.decimal, "emoji_indices": sas.emoji_indices}
        run.shown_at = self._now()
        run.state = "done"
        run.nonce = None
        self._active.pop((run.group_id, run.peer), None)
        self._event(run, "sas_code")

    # -- received ceremony messages ------------------------------------------------------

    def on_message(self, group: GroupRow, event: dict[str, Any], inner: dict[str, Any]) -> None:
        """A received ceremony message (inside the engine's transaction for
        it). Never delivered: whatever it is, it ends here."""
        e = self._e
        sender = event["sender"]
        identity, instance = str(sender["identity"]), str(sender["instance_id_hex"])
        epoch = int(event["epoch"])
        body = inner.get("body")
        if (
            inner.get("sender") != identity
            or inner.get("instance_id") != instance
            or inner.get("origin") != "human"
            or inner.get("hop") != 0
            or "reply_to" in inner
            or "addressee" in inner
            or not isinstance(body, dict)
            or type(body.get("epoch")) is not int
            or body["epoch"] != epoch
            or epoch > MAX_EPOCH
        ):
            return
        if epoch != e._core_epoch(unb64(group.group_id)):
            return  # from an earlier epoch (the grace window): never pairs
        if inner["kind"] == SAS_COMMIT:
            self._on_commit(group.group_id, (identity, instance), epoch, inner, body)
        else:
            self._on_reveal(group.group_id, identity, instance, inner, body)

    def _within_budget(self, group_id: str, instance: str) -> bool:
        """12 a minute from one sending instance, counting only messages
        addressed to this instance's identity (SPEC 11.3, "Limits")."""
        now = self._now()
        budget = self._budgets.setdefault((group_id, instance), _Budget())
        while budget.times and now - budget.times[0] >= BUDGET_WINDOW_SECS:
            budget.times.popleft()
        if len(budget.times) >= BUDGET:
            return False
        budget.times.append(now)
        return True

    def _on_commit(
        self,
        group_id: str,
        sender: tuple[str, str],
        epoch: int,
        inner: dict[str, Any],
        body: dict[str, Any],
    ) -> None:
        e = self._e
        identity, instance = sender
        commitment = _canonical_b64(body.get("commitment"), NONCE_LEN)
        peer = body.get("peer")
        if commitment is None or not canonical_identity(peer) or inner.get("to") != [peer]:
            return
        if identity == e.me:
            # Another instance of this identity compares with `peer` (step 1).
            self._siblings[(group_id, str(peer))] = (epoch, self._now())
        elif peer != e.me:
            pass  # addressed to another member: ignored entirely
        elif not self._within_budget(group_id, instance):
            LOG.info("sas_budget_exceeded", group=log.hid(group_id))
        else:
            self._addressed_commit(group_id, sender, epoch, commitment)

    def _addressed_commit(
        self, group_id: str, sender: tuple[str, str], epoch: int, commitment: bytes
    ) -> None:
        identity, instance = sender
        run = self._runs.get(self._active.get((group_id, identity), ""))
        if run is None or run.state == "starting":
            self._hold(group_id, sender, commitment, epoch)
        elif run.paired is None:
            if run.epoch == epoch and self._pairable(run, instance, commitment):
                self._pair(run, instance, commitment)
        elif run.paired[0] == instance and run.paired[1] != commitment:
            # The paired instance committed again: never answered here.
            self._abort(run, "peer_restarted")
            self._hold(group_id, sender, commitment, epoch)
        # Otherwise another instance's, or the same one again: ignored.

    def _hold(self, group_id: str, sender: tuple[str, str], commitment: bytes, epoch: int) -> None:
        identity, instance = sender
        if self._e.store.sas_answered(group_id, epoch, commitment):
            return
        key = (group_id, identity, instance)
        known = self._held.get(key)
        self._held[key] = _Held(commitment, epoch, self._now())
        if known is None or known.commitment != commitment:
            self._e._defer(
                lambda: self._emit(
                    group_id,
                    "sas_requested",
                    peer=identity,
                    peer_name=self._e._display_name(group_id, identity),
                    peer_instance=instance,
                )
            )
        self.wake()

    def _on_reveal(
        self,
        group_id: str,
        identity: str,
        instance: str,
        inner: dict[str, Any],
        body: dict[str, Any],
    ) -> None:
        e = self._e
        answers = _canonical_b64(body.get("answers"), NONCE_LEN)
        nonce = _canonical_b64(body.get("nonce"), NONCE_LEN)
        if answers is None or nonce is None or inner.get("to") != [e.me] or identity == e.me:
            return
        run = self._runs.get(self._active.get((group_id, identity), ""))
        if run is None or run.commitment is None or answers != run.commitment:
            return  # addressed to another run, or none
        if not self._within_budget(group_id, instance):
            LOG.info("sas_budget_exceeded", group=log.hid(group_id))
            return
        if run.paired is None:
            self._abort(run, "out_of_order")
            return
        if run.paired[0] != instance or run.peer_nonce is not None:
            return
        expected = ac.sas_commitment(
            unb64(group_id), int(run.epoch or 0), identity, int(instance, 16), e.me, nonce
        )
        if bytes(expected) != run.paired[1]:
            self._abort(run, "bad_reveal")
            return
        run.peer_nonce = nonce
        self._maybe_done(run)

    # -- the outbox's answers ----------------------------------------------------------

    def on_sent(self, meta: dict[str, Any]) -> None:
        """The relay accepted a ceremony message (``accepted``)."""
        run = self._runs.get(str(meta.get("run")))
        if run is None or meta.get("kind") != SAS_COMMIT:
            return
        run.commit_accepted = True
        self._maybe_reveal(run)

    def on_send_failed(self, meta: dict[str, Any], code: str) -> None:
        """An ``error`` frame (or a stale epoch) for a ceremony message."""
        run = self._runs.get(str(meta.get("run")))
        if run is None or not run.under_way or code == "sas_stale":
            return
        self._abort(run, "send_failed")

    def stale(self, meta: dict[str, Any], epoch: int) -> bool:
        """Whether a queued ceremony message belongs to an earlier epoch: it
        is dropped, never sealed in a new one (SPEC 11.3)."""
        return bool(meta.get("epoch") != epoch)

    # -- epoch changes, aborts and timeouts --------------------------------------------------

    def on_epoch_changed(self, group_id: str, committer: str | None) -> None:
        """A commit merged (another member's or this instance's own): the
        runs of the earlier epoch end, held commitments with them."""
        e = self._e
        epoch = e._core_epoch(unb64(group_id))
        for key in [k for k, h in self._held.items() if k[0] == group_id and h.epoch != epoch]:
            del self._held[key]
        e.store.forget_sas_answered(group_id, epoch)
        for run in self._under_way(group_id):
            if run.state == "starting":
                continue  # begins in the new epoch
            if run.epoch is not None and run.epoch != epoch:
                restart = not run.revealed
                self._abort(run, "epoch_changed", committer=committer)
                if restart:
                    self._restart(run)
        self.wake()

    def _restart(self, run: Run) -> None:
        """SPEC 11.3: a new run in the new epoch, only for an abort before
        this instance's reveal, at most 3 times per command, and only while
        the command waits (within the first run's timeout)."""
        if run.restart >= MAX_RESTARTS or self._now() - run.started_at >= RUN_TIMEOUT_SECS:
            return
        count, _ = self._e.store.sas_warnings(run.group_id, run.peer)
        if count >= WARNING_STOP and not run.acknowledged:
            return
        try:
            view = self.start(
                run.group_id,
                run.peer,
                instance=run.want_instance,
                acknowledge=run.acknowledged,
                after=run,
            )
        except (SasError, Exception) as err:
            LOG.info("sas_restart_failed", error=type(err).__name__)
            return
        run.next_run = str(view["run"])
        new = self._runs[run.next_run]
        new.started_at = run.started_at  # the command's timeout carries over

    def _abort(self, run: Run, reason: str, *, committer: str | None = None) -> None:
        warning = reason in ALWAYS_WARNING or (
            run.revealed and reason not in ("mismatch", "restarted", "group_gone")
        )
        if reason == "timed_out" and run.paired is None and run.peer_started:
            warning = True
        run.committer = committer if reason == "epoch_changed" else None
        run.warning = warning
        self._end(run, reason)
        if warning:
            self._close_same(run.group_id, run.peer)
            count, committers = self._e.store.sas_warnings(run.group_id, run.peer)
            if committer is not None:
                committers = [*committers, committer]
            self._e.store.set_sas_warnings(run.group_id, run.peer, count + 1, committers)
            if count + 1 >= WARNING_STOP:
                self._event(
                    run, "sas_stopped", text=self._stop_text(run.group_id, run.peer, committers)
                )
        self._event(run, "sas_aborted", reason=reason, warning=warning, committer=run.committer)

    def _end(self, run: Run, reason: str) -> None:
        run.state = "aborted"
        run.reason = reason
        run.nonce = None
        if self._active.get((run.group_id, run.peer)) == run.run_id:
            del self._active[(run.group_id, run.peer)]

    def _event(self, run: Run, kind: str, **data: Any) -> None:
        data = {
            "run": run.run_id,
            "peer": run.peer,
            "peer_name": self._e._display_name(run.group_id, run.peer),
            **data,
        }
        self._e._defer(lambda: self._emit(run.group_id, kind, **data))

    def _emit(self, group_id: str, kind: str, **data: Any) -> None:
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._e.emit(group_id, kind, **data))
        self._e._background.add(task)
        task.add_done_callback(self._e._background.discard)

    def step(self) -> int | None:
        """Timeouts, the unpaired notice, held expiry and runs waiting for an
        own commit; returns the next time something is due."""
        now = self._now()
        due: list[int] = []
        for run in list(self._runs.values()):
            if run.under_way:
                due.extend(self._step_run(run, now))
        for key, h in list(self._held.items()):
            if now - h.at >= HELD_TTL_SECS:
                del self._held[key]
            else:
                due.append(h.at + HELD_TTL_SECS)
        # Ended runs are kept for their answers, then forgotten.
        for run_id, run in list(self._runs.items()):
            if not run.under_way and now - run.started_at >= 2 * RUN_TIMEOUT_SECS + (
                SAME_WINDOW_SECS
            ):
                del self._runs[run_id]
        return min(due) if due else None

    def _step_run(self, run: Run, now: int) -> list[int]:
        """One run's timers; returns when it next needs a look."""
        if run.state == "starting":
            self._begin(run)
        deadline = run.started_at + RUN_TIMEOUT_SECS
        if now >= deadline:
            self._abort(run, "timed_out")
            return []
        due = [deadline]
        if run.state == "starting":
            due.append(now + 1)
        if run.paired is None:
            notice = run.started_at + UNPAIRED_NOTICE_SECS
            if now < notice:
                due.append(notice)
            elif not run.unpaired_told:
                run.unpaired_told = True
                text = UNPAIRED_TEXT.format(name=self._name(run.group_id, run.peer))
                self._event(run, "sas_unpaired", text=text)
        return due

    async def run(self) -> None:
        """The SAS timer (one of the engine's workers)."""
        e = self._e
        backoff = Backoff(base=1.0, cap=60.0, rng=e.options.backoff_rng)
        while True:
            self._wake.clear()
            try:
                due = self.step()
                backoff.reset()
            except Exception as err:
                LOG.warning("sas_timer_failed", error=type(err).__name__)
                due = self._now() + int(backoff.next())
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

    # -- the cadence Update (SPEC 3.1, 11.3) ------------------------------------------------

    def defer_update(self, group_id: str) -> bool:
        """Called when the cadence Update is due before a send: whether to
        defer it. Only while this instance takes part in a run, and for at
        most 600 s in total for one due Update. A held commitment doesn't
        defer it."""
        now = self._now()
        since = self._update_due_since.setdefault(group_id, now)
        if not self._under_way(group_id):
            return False
        return now - since < UPDATE_DEFER_SECS

    def update_not_due(self, group_id: str) -> None:
        self._update_due_since.pop(group_id, None)

    # -- recovery ------------------------------------------------------------------------

    def recover(self) -> None:
        """On start: runs don't survive a restart, so their queued messages
        are dropped (a commitment nobody would follow with a reveal)."""
        self._e.store.drop_queued_sas()
