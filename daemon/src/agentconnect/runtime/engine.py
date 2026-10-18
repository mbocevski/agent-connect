"""``agentconnectd``: identity, MLS state, relay link, queues and adapters.

Three workers run on one event loop:

* **inbound**: takes relay frames in order, runs them through the core and
  records the outcome in the inbox (dedup by ``(sender, msg_id)``);
* **outbox**: sends queued work in order (group creation, joins,
  application messages, commits, proposals, Welcomes). Because there is
  one outbox, local commits are serialised;
* **delivery**: hands pending inbox rows to the adapter and acks the relay
  frame only once the adapter accepted it.

Commit handling follows SPEC §8.3 and the core's semantics exactly: a
commit is sent under its ``msg_id`` and merged on ``accepted`` (or when the
core recognises its exact bytes in the fan-out); on ``epoch_conflict`` it is
discarded, the winning commit is processed, and the intent is rebuilt.

Crash consistency (ADR-004): the core and the daemon keep separate
databases, so every processed message, own-commit confirmation and Welcome
goes through the core's **journal**. The core stores the result in the same
transaction as the MLS state change, under the key ``sender/msg_id``. The
daemon then records everything that follows from it (inbox row, members,
policy, epoch, events, queued sends) in **one** transaction of its own,
consumes the journal entry, and only then acks the relay. A crash or an
exception anywhere in between leaves either a pending journal entry, which
the daemon finishes on start (and the redelivered frame replays), or the
inbox row, which marks the entry as applied. Adapters are told about events
after that transaction commits.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import random
import secrets
from collections.abc import Awaitable, Callable, Generator, Iterable
from dataclasses import dataclass, replace
from typing import Any

import agentconnect_core as ac
from agentconnect import log
from agentconnect.a2a_adapter import cards, convert
from agentconnect.adapter import (
    Adapter,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    Sender,
    SendReceipt,
)
from agentconnect.backoff import Backoff
from agentconnect.clock import Clock, SystemClock, unix_seconds
from agentconnect.config import Config
from agentconnect.failpoints import FailpointError, Failpoints, SimulatedCrash
from agentconnect.identity import (
    Seeded,
    load_db_key,
    load_identity,
    load_instance,
    open_core_client,
)
from agentconnect.keystore import DataDirLock, Keystore, open_keystore
from agentconnect.limits import DRAIN_RATE_MULTIPLE, KNOWN_KINDS, DrainBudget
from agentconnect.policy import (
    HUMAN_ONLY_KINDS,
    Decision,
    Inbound,
    Outbound,
    PolicyError,
    SafetyPolicy,
    Verdict,
    drop,
    task_of,
    verification_holds,
)
from agentconnect.relay import (
    DRAIN_KEY,
    NotConnectedError,
    RelayError,
    RelayLink,
    RelayRest,
    b64,
    unb64,
)
from agentconnect.runtime.registry import AdapterRegistry
from agentconnect.schemas import normalize
from agentconnect.store import GroupRow, OutboxRow, Store
from agentconnect.tasks import cancel_and_wait

LOG = log.get("agentconnect.engine")

UPDATE_AFTER_SECS = 24 * 3600  # SPEC §3.1 update cadence
UPDATE_AFTER_MESSAGES = 1000
APPROVAL_TIMEOUT_SECS = 3600  # SPEC §6.2 step 4
JOIN_CLOSED_GRACE_SECS = 60
MAX_PARKED_GROUPS = 8
MAX_PARKED_PER_GROUP = 256
MAX_REPLY_TO = 16  # SPEC 7.2
MAX_ADDRESSEE = 50  # SPEC 7.2: at most the group size
HOP_MEMORY_SECS = 7 * 24 * 3600
TRANSFER_TIMEOUT_SECS = 10.0  # owner hand-over before a SAS-mismatch exit
REBUILD_WAIT_SECS = 60.0
MAX_COMMIT_ATTEMPTS = 8
DELIVERY_BATCH = 100  # pending rows a group's delivery worker reads at a time
# Safety-policy events that reveal what the policy did with a peer's message:
# recorded for the human (GET /v0/events with the human token, the CLI), never
# passed to the agent's adapter.
HELD_PRIVATE = ("payload", "inbox_seq", "status")  # never in held listings
# The owner's knock events (docs/discovery.md): who knocked and what the
# human decided. Strangers' knocks come before any relationship, as held
# messages do, so the agent hears of the group only once the knocker is in.
KNOCK_OWNER_EVENTS = frozenset(
    {
        "knock_received",
        "knock_approved",
        "knock_rejected",
        "knock_expired",
        "knock_approval_failed",
    }
)
HUMAN_EVENTS = (
    frozenset({"message_held", "held_expired", "repeated_violations"}) | KNOCK_OWNER_EVENTS
)
INVITE_WARNING = (
    "This invite was already used or revoked. If you didn't expect this, "
    "the link may have been intercepted. Tell the sender."
)


class DaemonError(Exception):
    """A local operation failed; ``code`` is a short machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def canonical(obj: Any) -> bytes:
    """JCS for the JSON values the protocol uses (no floats)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def gid_b64(gid: bytes) -> str:
    return b64(gid)


def new_msg_id() -> str:
    return b64(secrets.token_bytes(16))


class TransientError(Exception):
    """Processing failed for a reason that may pass (storage, a core panic):
    the frame is neither recorded nor acked, and is retried."""

    def __init__(self, group_id: str | None, reason: str) -> None:
        super().__init__(reason)
        self.group_id, self.reason = group_id, reason


# Core errors that say nothing about the message itself (SQLCipher I/O or a
# lock, the RNG, an internal error); a CoreError (a panic) is transient too.
TRANSIENT_PREFIXES = (
    "storage error",
    "wrong database key",
    "randomness source failed",
    "internal error",
)
MAX_TRANSIENT_RETRIES = 8
# Relay errors that say "not now" rather than "no" (SPEC 8.4).
RETRYABLE_RELAY_ERRORS = frozenset({"rate_limited", "internal"})
BENIGN = "benign"  # a failed outbox row nobody needs to hear about
OUTBOUND_PROBLEMS = {
    "unknown_kind": ("bad_request", "unknown message kind"),
    "too_large": ("too_large", "message too large (SPEC 10.2: 256 KiB, or the group's limit)"),
    "part_kind": (
        "forbidden",
        "only text and data parts are allowed (SPEC 10.2), and file parts where the group's "
        "policy allows them",
    ),
    "file_too_large": ("too_large", "file part larger than the group's max_file_bytes"),
    "rate_limited": ("rate_limited", "over the SPEC 10.2 message rate"),
    "hold_overflow": ("rate_limited", "too many messages already wait for the human's approval"),
    "hold_queue_full": ("rate_limited", "the group's approval queue is full"),
    "task_pending": ("forbidden", "the task's first update waits for the human's approval"),
    "task_rejected": ("forbidden", "the human rejected this task"),
    "not_for_agents": (
        "forbidden",
        "control messages and Agent Cards come from the daemon or the human, not the agent",
    ),
}


def _core_error(e: Exception) -> str:
    text = str(e)
    if isinstance(e, ac.CoreError) or text.startswith(TRANSIENT_PREFIXES):
        return "transient"
    if "re-sync required" in text:
        return "own_commit_lost"
    if text == "message already processed":
        return "duplicate"
    if text.startswith("unauthorized commit"):
        return "unauthorized_commit"
    return "rejected"


KNOCK_REQUEST_PREFIX = "kn-"  # knock request ids (agentconnect.runtime.knocks)
ENVELOPE_KINDS = frozenset(
    {"commit", "proposal", "application", "welcome_wrapped", "join_request", "knock"}
)
MAX_ID_LEN = 64
DOOR_ID_CHARS = 22  # 16 bytes, base64url without padding
GROUP_FIELDS = ("group_id", "epoch", "to", "routing")  # never on a knock (SPEC 7.1)
# The last signed relay request's ts (RelayRest), kept across restarts.
REST_TS_KEY = "relay/rest_ts"
# An internal frame: finish every pending journal entry (ADR-004).
REPLAY_JOURNAL = "_replay_journal"
TransientFailure = (TransientError, FailpointError)


def journal_key(sender: str, msg_id: str) -> str:
    """The core journal key of a relay message (ADR-004)."""
    return f"{sender}/{msg_id}"


def journal_context(
    env: dict[str, Any],
    *,
    from_relay: bool,
    invite_id: str | None = None,
    knock_id: str | None = None,
) -> bytes:
    """What the daemon needs to finish a journal entry after a restart: the
    envelope without its ciphertext (and the join's invite or knock)."""
    ctx: dict[str, Any] = {
        "env": {k: v for k, v in env.items() if k != "ct"},
        "from_relay": from_relay,
    }
    if invite_id is not None:
        ctx["invite_id"] = invite_id
    if knock_id is not None:
        ctx["knock_id"] = knock_id
    return canonical(ctx)


def _door_id(value: Any) -> bool:
    """SPEC 7.1: canonical base64url of 16 bytes."""
    if not isinstance(value, str) or len(value) != DOOR_ID_CHARS:
        return False
    try:
        return b64(unb64(value)) == value
    except ValueError:
        return False


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _short_str(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_ID_LEN


def _str_list(value: Any) -> bool:
    return isinstance(value, list) and all(_short_str(x) for x in value)


def _envelope_problem(env: dict[str, Any]) -> str | None:  # noqa: PLR0911, PLR0912
    """Why a delivered envelope is malformed (SPEC 7.1), or None.

    Checked before anything reaches the core: the relay controls every
    field here, and a wrong type must not surface after a commit merged."""
    if not _is_int(env.get("v")) or env.get("v") != 0:
        return "version"
    kind = env.get("kind")
    if kind not in ENVELOPE_KINDS:
        return "kind"
    if not _short_str(env.get("msg_id")) or not _short_str(env.get("sender")):
        return "ids"
    if not isinstance(env.get("ct"), str):
        return "ct"
    if kind == "knock":
        # SPEC 7.1: {v, kind, door_id, msg_id, sender, ct} and nothing of a group's.
        if not _door_id(env.get("door_id")):
            return "door_id"
        return "knock_fields" if any(k in env for k in GROUP_FIELDS) else None
    if "door_id" in env:
        return "door_id"  # no other kind may carry one
    if kind != "join_request" and not _short_str(env.get("group_id")):
        return "group_id"
    if kind in ("commit", "proposal", "application"):
        epoch = env.get("epoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            return "epoch"
    if "to" in env and not _str_list(env["to"]):
        return "to"
    if kind == "commit" and "routing" in env:
        routing = env["routing"]
        if not isinstance(routing, dict) or not all(
            _str_list(routing.get(k, [])) for k in ("add", "remove")
        ):
            return "routing"
    return None


def _header_mismatch(env: dict[str, Any], group_id: bytes, head: dict[str, Any]) -> str | None:
    """How a group envelope disagrees with its MLS header (SPEC 7.1), or
    None. ``head`` is ``agentconnect_core.peek_header`` of its ``ct``."""
    if head["group_id"] != group_id:
        return "group_mismatch"
    if head["epoch"] != env["epoch"]:
        return "epoch_mismatch"
    return None


def _same_relay(a: str, b: str) -> bool:
    """SPEC 4.4/8.1.1: compare relay hosts in canonical form."""
    try:
        return ac.canonical_relay_host(a) == ac.canonical_relay_host(b)
    except ac.AgentConnectError:
        return False


def _max_turns(policy: dict[str, Any]) -> int:
    guard = policy.get("loop_guard")
    turns = guard.get("max_agent_turns") if isinstance(guard, dict) else None
    return turns if isinstance(turns, int) and not isinstance(turns, bool) else 20


def addressed_to_me(
    floor: str, inner: dict[str, Any], me: str, my_instance: str, moderator: str | None
) -> bool:
    """SPEC §9.3/§9.4: is this instance *triggered* by ``inner``?"""
    to = inner.get("to") or ["*"]
    addressee = inner.get("addressee")
    if addressee is not None and floor in ("free", "mention"):
        # SPEC 9.3: `addressee` names exactly who is triggered; a malformed
        # one triggers nobody.
        hit = _str_list(addressee) and me in addressee
    elif floor == "free":
        hit = True
    elif floor == "mention":
        hit = me in to or (to == ["*"] and inner.get("origin") == "human")
    else:  # moderated: floor control is a later task; only the moderator
        hit = moderator == me
    if not hit:
        return False
    body = inner.get("body")
    metadata = body.get("metadata") if isinstance(body, dict) else None
    target = metadata.get("instance") if isinstance(metadata, dict) else None
    return target in (None, my_instance)


@dataclass(frozen=True)
class Options:
    """Test seams; production uses the defaults."""

    testing: Seeded | None = None
    backoff_rng: random.Random | None = None
    keyring_backend: Any = None
    # Who holds the data-directory lock, as told to a second runtime.
    lock_owner: str = "daemon"
    # Discovery (docs/discovery.md): an httpx transport for every directory
    # request and one for the relay's REST calls, an owner-file fetcher
    # (agentconnect.ownerfile.Fetcher), and a door lifetime below the
    # config's minimum.
    directory_transport: Any = None
    relay_transport: Any = None
    owner_fetcher: Any = None
    door_lifetime_secs: int | None = None


class Engine:
    """The protocol engine of one runtime: one identity, one instance, one
    relay connection. Hosts use it through :class:`agentconnect.runtime.Runtime`."""

    def __init__(
        self,
        config: Config,
        adapters: Iterable[Adapter] | AdapterRegistry = (),
        *,
        clock: Clock | None = None,
        keystore: Keystore | None = None,
        options: Options | None = None,
    ) -> None:
        self.config = config
        self.clock: Clock = clock or SystemClock()
        self.adapters = (
            adapters if isinstance(adapters, AdapterRegistry) else AdapterRegistry(adapters)
        )
        self.options = options or Options()
        self.failpoints = Failpoints()  # inert unless a test arms one
        # Set while one journal entry's effects are being recorded (_apply).
        self._batch: list[Event] | None = None
        self._after: list[Callable[[], None]] | None = None
        # (scope, n): where the ids of events emitted now come from.
        self._cause: tuple[str, int] | None = None
        self._registering: set[str] = set()
        # Before touching keys or databases: one daemon per data directory.
        self._lock = DataDirLock(config.data_dir, self.options.lock_owner)
        try:
            self._open(keystore)
        except BaseException:
            self._lock.release()
            raise

    def _open(self, keystore: Keystore | None) -> None:
        config = self.config
        config.require_relay()
        self.keystore = keystore or open_keystore(
            config.keystore, config.data_dir, self.options.keyring_backend
        )
        self.identity = load_identity(self.keystore, self.options.testing)
        self.instance = load_instance(self.keystore, self.identity, self.options.testing)
        mls_db, daemon_db = config.data_dir / "mls.sqlite3", config.data_dir / "daemon.sqlite3"
        db_key = load_db_key(self.keystore, (mls_db, daemon_db))
        self.client: ac.Client = open_core_client(
            mls_db, self.instance, db_key, self.options.testing
        )
        # Encrypted under a key the core derives from db_key (ADR-003).
        self.store = Store(daemon_db, db_key)
        self.store.number_agent_events(HUMAN_EVENTS)
        self.link = RelayLink(
            config.relay_ws,
            config.relay_host,
            self.instance,
            self.clock,
            self._on_frame,
            backoff=Backoff(rng=self.options.backoff_rng),
            on_connected=self._on_connected,
            on_state=self._pulse,
        )
        self.rest = RelayRest(
            config.relay_http,
            config.relay_host,
            self.instance,
            self.clock,
            transport=self.options.relay_transport,
            last_ts=int(self.store.kv_get(REST_TS_KEY) or "0"),
            on_ts=lambda ts: self.store.kv_set(REST_TS_KEY, str(ts)),
        )
        self._frames: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._outbox_wake = asyncio.Event()
        self._delivery_wake = asyncio.Event()
        self._changed = asyncio.Event()
        self._parked: dict[str, list[dict[str, Any]]] = {}
        self._leaving: set[str] = set()
        self._proposed_leaves: dict[str, set[str]] = {}
        self._tasks: list[asyncio.Task[None]] = []
        # Every message in and out goes through it (agentconnect.policy).
        self.safety = SafetyPolicy(
            config.safety_defaults(),
            self.store,
            self.clock,
            audit_retention_days=config.policy_audit_retention_days,
            transcript_max_bytes=config.policy_transcript_max_bytes,
            audit_group_rows=config.policy_audit_max_rows_per_group,
            audit_sender_rows=config.policy_audit_max_rows_per_sender,
        )
        self._background: set[asyncio.Task[None]] = set()
        # Pinned card-signing keys (SPEC 10.5), checked on every received card.
        self._card_keys = cards.load_jwks(config.a2a_card_keys_file)
        self._held_wake = asyncio.Event()
        self._fail_codes: dict[int, str] = {}
        self._drain_frame = False
        self._drain = DrainBudget()
        self.running = False
        self._closed = False
        from agentconnect.runtime.knocks import KnockService  # noqa: PLC0415 - import cycle
        from agentconnect.runtime.listing import ListingManager  # noqa: PLC0415 - import cycle

        # The listing, its doors and the discovery worker (docs/discovery.md).
        self.listings = ListingManager(self)
        # Knocks, both sides: the owner's ledger and approvals, the knocker's knocks.
        self.knocks = KnockService(self)

    # -- lifecycle ------------------------------------------------------------

    @property
    def me(self) -> str:
        return self.identity.id

    @property
    def mailbox(self) -> str:
        return self.instance.mailbox_id

    def now(self) -> int:
        return unix_seconds(self.clock)

    async def start(self) -> None:
        self.adapters.close()
        self._recover()
        # First thing the inbound worker does: finish what a crash left in
        # the core's journal.
        self._frames.put_nowait({"t": REPLAY_JOURNAL})
        loop = asyncio.get_running_loop()
        workers: dict[str, Callable[[], Awaitable[None]]] = {
            "inbound": self._inbound,
            "outbox": self._outbox,
            "delivery": self._delivery,
            "held_timer": self._held_timer,
            "discovery": self.listings.run,
            "knock_timer": self.knocks.run,
            "relay_link": self.link.run,
        }
        for name, worker in workers.items():
            self._tasks.append(loop.create_task(self._supervised(name, worker)))
        for adapter in self.adapters.values():
            bind = getattr(adapter, "bind_store", None)
            if bind is not None:
                bind(self.store)  # optional hook: adapters that keep a durable feed
            await adapter.on_outbound(self.adapter_send)
        self.running = True
        LOG.info("daemon_started", identity=log.hid(self.me), keystore=self.keystore.kind)

    async def _supervised(self, name: str, worker: Callable[[], Awaitable[None]]) -> None:
        """Run a worker forever: if it ever returns or raises (a bug), log the
        type only and restart it after a pause, instead of leaving the daemon
        "running" with a dead queue."""
        backoff = Backoff(base=1.0, cap=60.0, rng=self.options.backoff_rng)
        while True:
            try:
                await worker()
                reason = "returned"
            except Exception as e:
                reason = type(e).__name__
            except asyncio.CancelledError:
                # Our own cancellation (stop) ends the worker; a stray one
                # (user code that awaited something else's cancelled task)
                # is a failure like any other.
                current = asyncio.current_task()
                if current is None or current.cancelling():
                    raise
                reason = "CancelledError"
            if not self.running:
                return
            LOG.error("worker_died", worker=name, reason=reason)
            await self._sleep(backoff.next())

    async def stop(self) -> None:
        """Stop the workers and close the databases (also used to simulate a
        crash in tests: nothing is flushed that isn't already durable).

        Every step runs even if the caller is cancelled meanwhile; that
        cancellation propagates once the lock is released."""
        if self._closed:
            return
        self.running = False
        try:
            await self.link.stop()
        finally:
            try:
                await cancel_and_wait(*self._tasks, ignore=(Exception, SimulatedCrash))
            finally:
                self._tasks.clear()
                try:
                    for adapter in self.adapters.values():
                        # Optional hook: adapters with workers or connections release them.
                        close = getattr(adapter, "close", None)
                        if close is not None:
                            with contextlib.suppress(Exception):
                                await close()
                finally:
                    self.close()

    def close(self) -> None:
        """Close the databases and release the data directory, without
        stopping anything (for an engine that never started, or after
        :meth:`stop`)."""
        if self._closed:
            return
        self._closed = True
        self.running = False
        try:
            self.store.close()
            # Drop the core client so its SQLite connections close.
            del self.client
        finally:
            self._lock.release()
            LOG.info("daemon_stopped")

    def _recover(self) -> None:
        """After a restart: a commit built but never persisted for sending
        was never sent, so it is safe to discard (SPEC §8.3)."""
        built = {
            row.group_id
            for row in self.store.outbox()
            if row.kind == "commit" and "env" in row.payload
        }
        for group in self.store.groups():
            gid = unb64(group.group_id)
            if group.status != "active":
                # Left or removed: the core state goes after the daemon's
                # record of it, so a crash in between leaves it behind.
                with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                    self.client.delete_group(gid)
                continue
            with contextlib.suppress(ac.AgentConnectError):
                if self.client.has_pending_commit(gid) and group.group_id not in built:
                    self.client.discard_pending_commit(gid)
                    LOG.info("discarded_unsent_commit", group=log.hid(group.group_id))
            if self._leaving_state(group):
                self._leaving.add(group.group_id)
        # A join recorded as done whose secret a crash left in the keystore.
        self._forget_join_secrets()

    def _leaving_state(self, group: GroupRow) -> bool:
        return self.store.kv_get(f"leaving/{group.group_id}") == "1"

    def _pulse(self) -> None:
        self._changed.set()

    async def _sleep(self, seconds: float) -> None:
        """Sleep on the daemon clock, announcing it (tests advance time once
        the daemon is waiting)."""
        nap = asyncio.ensure_future(self.clock.sleep(seconds))
        await asyncio.sleep(0)
        self._pulse()
        await nap

    async def wait_until(self, predicate: Callable[[], bool], within: float = 5.0) -> None:
        """Wait (with a real-time guard) until ``predicate`` holds."""

        async def loop() -> None:
            while True:
                # Clear before checking: a pulse after the check isn't lost.
                self._changed.clear()
                if predicate():
                    return
                await self._changed.wait()

        await asyncio.wait_for(loop(), within)

    def _drain_exempt(self, group_id: str, identity: str) -> bool:
        """Whether the frame being handled is part of the reconnect drain and
        still within the drain's budget: :data:`MAX_DRAIN_EXEMPT` for this
        connection, and twice the per-sender rate for each identity."""
        if not self._drain_frame:
            return False
        limit = self.safety.settings(group_id).limits(identity).sender_per_minute
        return self._drain.take(f"{group_id}/{identity}", DRAIN_RATE_MULTIPLE * limit)

    async def _on_connected(self) -> None:
        self._drain.reset()
        # Anything a failure in this run left unfinished in the journal.
        self._frames.put_nowait({"t": REPLAY_JOURNAL})
        self._outbox_wake.set()
        self._delivery_wake.set()
        self._pulse()
        try:
            await self.expire()
            await self.check_joins()
            await self._abandon_unregistered_invites()
        except Exception as e:  # never let the reconnect hook die
            LOG.warning("check_joins_failed", error=type(e).__name__)

    async def _abandon_unregistered_invites(self) -> None:
        """An invite still ``registering`` from an earlier run never reached
        its caller (the daemon stopped mid-registration), so nobody holds its
        link: revoke it at the relay (best effort) and drop its secret."""
        for invite in self.store.invites("registering"):
            invite_id = str(invite["invite_id"])
            if invite_id in self._registering:
                continue  # a registration in progress in this run
            with contextlib.suppress(RelayError, OSError):
                await self.rest.revoke_invite(invite_id)
            self.store.set_invite_status(invite_id, "revoked")
            self.keystore.delete(f"invite/{invite_id}")

    async def _on_frame(self, frame: dict[str, Any]) -> None:
        await self._frames.put(frame)

    # -- events -------------------------------------------------------------

    def _view(self, group_id: str) -> GroupView | None:
        g = self.store.group(group_id)
        if g is None:
            return None
        return GroupView(g.group_id, g.name, g.purpose, g.epoch, str(g.policy.get("floor", "free")))

    def _adapter_for(self, group_id: str | None) -> Adapter | None:
        name = self.config.default_adapter
        if group_id is not None:
            g = self.store.group(group_id)
            if g is not None:
                name = g.adapter
        return self.adapters.bound(name)

    async def emit(
        self, group_id: str | None, kind: str, *, cause: str | None = None, **data: Any
    ) -> None:
        """Record an event for the local API, then tell the group's adapter.

        Events are at-least-once with a stable ``event_id`` (ADR-004): the id
        is derived from the event's cause (``cause``, else the message being
        handled and the event's place among those it caused, else an id in
        ``data``), so an event regenerated after a crash has the same id. An
        event is recorded before the adapter hears of it and marked
        notified once the adapter accepted it; unnotified events are sent
        again on start and on every reconnect. Inside :meth:`_apply` the
        event is recorded in its transaction and the adapter is told once
        that commits."""
        event = self._record(group_id, kind, cause, data)
        if event is None:
            return
        if self._batch is not None:
            self._batch.append(event)
            return
        await self._notify(event)

    def _record(
        self, group_id: str | None, kind: str, cause: str | None, data: dict[str, Any]
    ) -> Event | None:
        """Record an event (in the current transaction, if any); the event to
        notify, or None if the adapter already has it."""
        event_id = self._event_id(group_id, kind, cause, data)
        agent = kind not in HUMAN_EVENTS and not self.hidden_from_agent(group_id)
        new = self.store.add_event(group_id, kind, data, self.now(), event_id, agent=agent)
        LOG.info("event", type=kind, group=log.hid(group_id), event_id=log.hid(event_id))
        if not new and self.store.event_notified(event_id):
            return None  # regenerated after a crash, and the adapter already has it
        return Event(kind, group_id, data, event_id)

    def _notify_soon(self, events: list[Event]) -> None:
        """Tell the adapter about recorded events from synchronous code. They
        are durable already: if this never runs, :meth:`_renotify` sends them."""
        if not events:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop (never in the daemon): the next renotify sends them

        async def notify() -> None:
            for event in events:
                await self._notify(event)

        task = loop.create_task(notify())
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    def _event_id(
        self, group_id: str | None, kind: str, cause: str | None, data: dict[str, Any]
    ) -> str:
        if cause is None and self._cause is not None:
            scope, n = self._cause
            self._cause = (scope, n + 1)
            cause = f"{scope}#{n}"
        if cause is None:
            for field in ("msg_id", "request_id", "invite_id", "knock_id", "epoch"):
                if data.get(field) is not None:
                    cause = f"{field}={data[field]}"
                    break
        if cause is None:
            return new_msg_id()  # no cause to derive from: a one-off event
        digest = hashlib.sha256(canonical([group_id, kind, cause])).digest()
        return b64(digest[:16])

    @contextlib.contextmanager
    def _causing(self, scope: str) -> Generator[None]:
        """Events emitted inside take their ids from ``scope`` (the journal
        key of the message being handled) and their order."""
        saved, self._cause = self._cause, (scope, 0)
        try:
            yield
        finally:
            self._cause = saved

    def _defer(self, action: Callable[[], None]) -> None:
        """Run ``action`` once the current :meth:`_apply` transaction has
        committed (now, outside one): for effects outside the daemon
        database (the core's state, the keystore)."""
        if self._after is not None:
            self._after.append(action)
        else:
            action()

    async def _apply(self, path: str, body: Callable[[], Awaitable[str]]) -> str:
        """Record the effects of one journal entry in one daemon transaction.

        ``body`` must not suspend (it only touches the store and the core and
        emits events, which are batched), so no other task's writes can
        interleave with the transaction. Deferred actions run and the
        adapter hears about the events after it commits."""
        batch: list[Event] = []
        after: list[Callable[[], None]] = []
        self._batch, self._after = batch, after
        try:
            with self.store.tx():
                result = await body()
                self.failpoints.hit(f"{path}.in_tx")
        finally:
            self._batch = self._after = None
        self.failpoints.hit(f"{path}.after_tx")
        for action in after:
            action()
        for event in batch:
            await self._notify(event)
        return result

    async def _notify(self, event: Event) -> None:
        """Tell the adapter about a recorded event; mark it notified once
        the adapter accepted it. A failure leaves it for :meth:`_renotify`."""
        adapter = self._adapter_for(event.group_id)
        try:
            self.failpoints.hit("event.after_record")
            # The policy's own events are for the human only: an agent that
            # heard of a hold could tell the sender (SPEC 10.2). So are the
            # knocks and an approved knock's group until the knocker is in.
            if (
                adapter is not None
                and event.type not in HUMAN_EVENTS
                and self.store.agent_visible(event.event_id)
            ):
                view = None if event.group_id is None else self._view(event.group_id)
                await adapter.on_event(view, event)
            self.failpoints.hit("event.after_notify")
            self.store.mark_notified(event.event_id)
        except Exception:
            LOG.warning("adapter_event_failed", type=event.type)
        self._pulse()

    async def _renotify(self) -> None:
        """Send again every recorded event the adapter has not accepted
        (a crash between recording and notifying, or a failing adapter)."""
        for row in self.store.unnotified_events():
            await self._notify(
                Event(row["type"], row["group_id"], row["data"], str(row["event_id"]))
            )

    async def mark_out_of_sync(self, group_id: str, reason: str, **data: Any) -> None:
        self.store.update_group(group_id, out_of_sync=True, out_of_sync_reason=reason)
        await self.emit(group_id, "out_of_sync", reason=reason, **data)

    # -- group state ----------------------------------------------------------

    def _sas(self, gid: bytes) -> dict[str, Any]:
        sas = self.client.sas(gid)
        return {"decimal": sas.decimal, "emoji_indices": sas.emoji_indices}

    def _refresh(self, group_id: str) -> tuple[set[str], set[str]]:
        """Re-read members, roles, policy and epoch from the core."""
        gid = unb64(group_id)
        policy = json.loads(self.client.policy(gid))
        admins = set(policy.get("admins", []))
        grouped: dict[str, list[dict[str, Any]]] = {}
        for m in self.client.members(gid):
            grouped.setdefault(m["identity"], []).append(
                {
                    "instance_id": m["instance_id_hex"],
                    "mailbox_id": m["mailbox_id"],
                    "leaf_index": m["leaf_index"],
                }
            )
        members = {
            identity: (
                "owner"
                if identity == policy["owner"]
                else "admin"
                if identity in admins
                else "member",
                instances,
            )
            for identity, instances in grouped.items()
        }
        joined, gone = self.store.set_members(group_id, members)
        self.store.update_group(group_id, policy=policy, epoch=self.client.epoch(gid))
        return joined, gone

    def _core_epoch(self, gid: bytes) -> int:
        try:
            return int(self.client.epoch(gid))
        except (ac.AgentConnectError, ac.CoreError):
            return 0

    def _trust_state(self, group_id: str) -> dict[str, Any]:
        members = self.store.members(group_id)
        others = [m for m in members if m.identity != self.me]
        verified = sum(1 for m in others if m.verified)
        return {
            "self": "verified" if others and verified == len(others) else "unverified",
            "verified_members": verified,
            "members": len(members),
        }

    def _display_name(self, group_id: str, identity: str) -> str | None:
        for m in self.store.members(group_id):
            if m.identity == identity:
                return m.display_name
        return None

    def _membership_change(
        self, group_id: str, summary: dict[str, Any]
    ) -> tuple[set[str], set[str]]:
        """Identities a commit added (all their instances are new) and
        removed (no instance left)."""
        current: dict[str, set[str]] = {}
        for m in self.client.members(unb64(group_id)):
            current.setdefault(m["identity"], set()).add(m["mailbox_id"])
        added = {m["mailbox_id"] for m in summary.get("added", [])}
        joined = {i for i, boxes in current.items() if boxes <= added}
        gone = {str(m["identity"]) for m in summary.get("removed", [])} - current.keys()
        return joined, gone

    async def _after_commit(
        self, group_id: str, summary: dict[str, Any], env: dict[str, Any] | None, own: bool
    ) -> None:
        """Bookkeeping after any merged commit, own or another member's.

        The cached members, roles, policy and epoch are re-read from the core
        first. Who joined and left comes from the commit's summary, not from
        the cache's diff, so a replay of the same journal entry (ADR-004)
        emits the same events."""
        self._refresh(group_id)
        joined, gone = self._membership_change(group_id, summary)
        if env is not None:
            # Shapes were checked before processing (_envelope_problem).
            hinted = env.get("routing") or {}
            expected = summary["routing"]
            if sorted(hinted.get("add", [])) != sorted(expected["add"]) or sorted(
                hinted.get("remove", [])
            ) != sorted(expected["remove"]):
                await self.emit(
                    group_id,
                    "relay_misbehaviour",
                    reason="routing_mismatch",
                    epoch=summary["epoch"],
                )
            if env.get("epoch") is not None and env["epoch"] + 1 != summary["epoch"]:
                await self.emit(
                    group_id, "relay_misbehaviour", reason="epoch_mismatch", epoch=summary["epoch"]
                )
        if own:
            self.store.update_group(group_id, last_own_commit_at=self.now(), msgs_since_commit=0)
        left = set(self._proposed_leaves.get(group_id, set()))

        def forget_leaves() -> None:
            self._proposed_leaves.pop(group_id, None)

        self._defer(forget_leaves)
        for identity in sorted(joined):
            await self.emit(group_id, "member_joined", identity=identity)
            await self._send_card(group_id, [identity])
        for identity in sorted(gone):
            kind = "member_left" if identity in left else "member_removed"
            await self.emit(group_id, kind, identity=identity)
        if summary.get("policy_changed"):
            await self.emit(
                group_id, "policy_changed", policy=json.loads(self.client.policy(unb64(group_id)))
            )
        trust = self._trust_state(group_id)
        await self.emit(
            group_id,
            "epoch_changed",
            epoch=summary["epoch"],
            sas=self._sas(unb64(group_id)),
            verified=f"{trust['verified_members']} of {trust['members'] - 1} verified",
        )
        if group_id in self._leaving:
            self._enqueue("proposal", group_id, {})

    async def _gone(self, group_id: str, kind: str) -> None:
        """This instance is no longer in the group (removed or left).

        The daemon's record goes first and the core's state after it (a
        crash in between is cleaned up by :meth:`_recover`): the other way
        round, a crash would leave an "active" group with no MLS state."""
        gid = unb64(group_id)
        self.store.update_group(group_id, status=kind)
        await self._drop_group_holds(group_id)
        self.store.delete_group_data(group_id)
        self.store.kv_set(f"leaving/{group_id}", "0")
        await self.emit(group_id, kind)

        def forget() -> None:
            self._leaving.discard(group_id)
            self.safety.forget_group(group_id)
            with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                self.client.delete_group(gid)

        self._defer(forget)

    # -- inbound --------------------------------------------------------------

    async def _inbound(self) -> None:
        backoff = Backoff(base=1.0, cap=300.0, rng=self.options.backoff_rng)
        while True:
            frame = await self._frames.get()
            # SPEC 8.2/10.2: messages queued while we were away are exempt
            # from the per-minute rates (bounded per connection).
            self._drain_frame = bool(frame.pop(DRAIN_KEY, False))
            for attempt in range(1, MAX_TRANSIENT_RETRIES + 1):
                try:
                    await self._handle_frame(frame)
                except TransientFailure as e:
                    # Nothing was acked: retry the same frame, in order. If
                    # the core already processed it, the retry gets the
                    # journalled result back (ADR-004), and the inbox's
                    # (sender, msg_id) dedup means its effects are recorded
                    # once: a retry can't process or deliver a message twice.
                    group_id, reason = (
                        (e.group_id, e.reason)
                        if isinstance(e, TransientError)
                        else (None, "failpoint")
                    )
                    LOG.warning("inbound_transient", reason=reason, attempt=attempt)
                    if attempt < MAX_TRANSIENT_RETRIES:
                        await self._sleep(backoff.next())
                        continue
                    # Give up for now; unacked, the relay redelivers it after
                    # the next reconnect.
                    await self.emit(group_id, "processing_failed", reason=reason)
                except Exception:
                    LOG.exception("inbound_failed", t=frame.get("t"))
                backoff.reset()
                break
            self._pulse()

    async def _ack(self, msg_id: str) -> None:
        with contextlib.suppress(NotConnectedError):
            await self.link.send({"t": "ack", "msg_id": msg_id})

    def _park(self, group_id: str, env: dict[str, Any]) -> None:
        """Hold a frame for a group we may be about to join (unacked, so the
        relay keeps it). Bounded, and deduplicated by (sender, msg_id): a
        relay can't grow it without limit."""
        if group_id not in self._parked and len(self._parked) >= MAX_PARKED_GROUPS:
            return
        held = self._parked.setdefault(group_id, [])
        key = (env.get("sender"), env.get("msg_id"))
        if len(held) < MAX_PARKED_PER_GROUP and all(
            (e.get("sender"), e.get("msg_id")) != key for e in held
        ):
            held.append(env)

    async def expire(self) -> None:
        """SPEC 6.1/4.3: secrets don't outlive their invites. An open invite
        past ``expires_at`` is marked expired and its secret deleted; a
        pending join past its invite's expiry (plus a grace period for an
        in-flight Welcome) fails and its secret goes. With no join pending,
        parked frames are dropped. Held messages past their approval window
        are dropped, and the audit log and transcripts keep their retention.
        Runs before each inbound frame and on (re)connect."""
        now = self.now()
        for invite in self.store.invites("open"):
            if now >= int(invite["expires_at"]):
                self.store.set_invite_status(invite["invite_id"], "expired")
                self.keystore.delete(f"invite/{invite['invite_id']}")
        for pending in self.store.pending_joins():
            expires = pending["meta"].get("expires_at")
            if isinstance(expires, int) and now >= expires + JOIN_CLOSED_GRACE_SECS:
                invite_id = pending["invite_id"]
                self.store.finish_join(invite_id, "expired")
                self.keystore.delete(f"join/{invite_id}")
                await self.emit(None, "join_failed", invite_id=invite_id, reason="expired")
        if self._parked and not self._may_join():
            self._parked.clear()
        # Hops are needed only while a reply can still arrive (relay TTL);
        # so are the journal's tombstones of consumed entries.
        self.store.forget_hops(now - HOP_MEMORY_SECS)
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
            self.client.journal_purge(now - HOP_MEMORY_SECS)
        await self.expire_held()
        self.safety.purge()

    def hidden_from_agent(self, group_id: str | None) -> bool:
        """Whether the agent can't see this group: an approved knock's group
        until its Add and Welcome went out (or for good, if they never did)."""
        if group_id is None:
            return False
        group = self.store.group(group_id)
        return group is not None and group.hidden

    def reveal_to_agent(self, group_id: str) -> list[Event]:
        """Inside a transaction: the group is the agent's from now on. Its
        events so far that the agent may see are numbered in the agent's
        sequence; returns them, for the adapter to be told once it commits.
        Its held inbound deliveries go out from the inbox, in order."""
        self.store.update_group(group_id, hidden=False)
        released = self.store.release_agent_events(group_id, HUMAN_EVENTS)
        self._defer(self._delivery_wake.set)
        return [Event(e["type"], e["group_id"], e["data"], str(e["event_id"])) for e in released]

    def _may_join(self) -> bool:
        """Whether a Welcome may still come: a join or a knock is pending."""
        return bool(self.store.pending_joins()) or self.knocks.waiting()

    async def _handle_frame(self, frame: dict[str, Any]) -> None:
        await self.expire()
        t = frame.get("t")
        if t == REPLAY_JOURNAL:
            await self._replay_journal()
            await self._renotify()
        elif t == "deliver" and isinstance(frame.get("env"), dict):
            await self._handle_env(frame["env"])
        elif t == "queue_overflow":
            group_id = str(frame.get("group_id", ""))
            if self.store.group(group_id) is not None:
                await self.mark_out_of_sync(
                    group_id, "queue_overflow", msg_id=frame.get("msg_id"), epoch=frame.get("epoch")
                )
            await self._ack(str(frame.get("msg_id", "")))
        else:
            LOG.info("relay_frame_ignored", t=t, code=frame.get("code"))

    async def _malformed(self, env: dict[str, Any], problem: str) -> None:
        """SPEC 7.1: relay-visible fields are unauthenticated. A malformed
        envelope is dropped before the core sees it."""
        LOG.info("envelope_malformed", problem=problem)
        group_id = env.get("group_id")
        if isinstance(group_id, str) and self.store.group(group_id) is not None:
            await self.emit(group_id, "relay_misbehaviour", reason="malformed_envelope")
            if env.get("kind") == "commit":
                # A commit we can't process leaves us behind the group.
                await self.mark_out_of_sync(group_id, "commit_dropped")
        if isinstance(env.get("msg_id"), str):
            await self._ack(str(env["msg_id"]))

    async def _handle_env(self, env: dict[str, Any]) -> None:
        with self._causing(journal_key(str(env.get("sender")), str(env.get("msg_id"))) + "/env"):
            await self._handle_env_inner(env)

    async def _handle_env_inner(self, env: dict[str, Any]) -> None:
        sender, msg_id, kind = str(env.get("sender")), str(env.get("msg_id")), env.get("kind")
        problem = _envelope_problem(env)
        if problem is not None:
            await self._malformed(env, problem)
            return
        state = self.store.inbox_state(sender, msg_id)
        if state is not None:
            # A replay or a redelivery after reconnect. Pending rows belong to
            # the delivery worker, which acks them once the adapter has them.
            # A failure after its effects were recorded may have left the
            # rest undone: the journal entry, the secret, the wake-up.
            self._settle_recorded(env)
            if state != "pending":
                await self._ack(msg_id)
            LOG.debug("duplicate_ignored", msg=log.hid(msg_id))
            return
        group_id = env.get("group_id")
        now = self.now()
        if kind == "knock":
            # Recorded, acked and audited there; silent toward the knocker.
            await self.knocks.on_knock(env)
            return
        if kind == "join_request":
            await self._on_join_request(env)
            self.store.record_inbox(sender, msg_id, None, "done", now)
        elif kind == "welcome_wrapped":
            await self._on_welcome_env(env)
            return
        elif kind in ("application", "commit", "proposal") and isinstance(group_id, str):
            group = self.store.group(group_id)
            if group is None or group.status != "active":
                if group is None and self._may_join():
                    # Sent after our Add but before the Welcome reached us.
                    self._park(group_id, env)
                    return
                self.store.record_inbox(sender, msg_id, group_id, "dropped", now)
            else:
                await self._on_group_message(group, env)
                return
        else:
            self.store.record_inbox(sender, msg_id, group_id, "dropped", now)
        await self._ack(msg_id)

    def _settle_recorded(self, env: dict[str, Any]) -> None:
        """Finish what follows an entry's recorded effects (ADR-004); all
        of it is idempotent."""
        key = journal_key(str(env.get("sender")), str(env.get("msg_id")))
        group_id = env.get("group_id")
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError, ValueError):
            if env.get("kind") == "welcome_wrapped":
                self.client.journal_consume(key)
                self._forget_join_secrets()
            elif isinstance(group_id, str):
                self.client.journal_consume(key, unb64(group_id))
                group = self.store.group(group_id)
                if group is not None and group.status != "active":
                    self.client.delete_group(unb64(group_id))
        self._delivery_wake.set()

    def _forget_join_secrets(self) -> None:
        """Delete the secrets of joins that ended (SPEC §6.3)."""
        for invite_id in self.store.joined_invites():
            self.keystore.delete(f"join/{invite_id}")

    async def _on_welcome_env(self, env: dict[str, Any]) -> None:
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        joined = await self._on_welcome(env)
        if joined is None:
            self.store.record_inbox(sender, msg_id, env.get("group_id"), "done", self.now())
            await self._ack(msg_id)
            return
        for parked in self._parked.pop(joined, []):
            await self._handle_env(parked)

    async def _rejected(self, group_id: str, env: dict[str, Any], e: Exception) -> None:
        """The core refused a group message (or failed transiently)."""
        reason = _core_error(e)
        if reason == "transient":
            raise TransientError(group_id, type(e).__name__) from None
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        if reason == "duplicate":
            # Its journal entry was consumed, so its effects are recorded.
            self.store.record_inbox(sender, msg_id, group_id, "done", self.now())
            await self._ack(msg_id)
            return
        self.store.record_inbox(sender, msg_id, group_id, "failed", self.now())
        await self._ack(msg_id)
        LOG.info(
            "message_rejected",
            group=log.hid(group_id),
            kind=env.get("kind"),
            reason=reason,
            # Core errors never carry key material or plaintext.
            detail=str(e)[:100],
        )
        if reason == "own_commit_lost":
            await self.mark_out_of_sync(group_id, "own_commit_lost")
            return
        if reason == "unauthorized_commit":
            await self.emit(group_id, "unauthorized_commit", detail=str(e))
        if env["kind"] == "commit" and int(env["epoch"]) >= self._core_epoch(unb64(group_id)):
            # A commit for the current (or a later) epoch that we can't
            # merge: the group moves on without us. (Replays of older
            # commits are harmless and don't count.)
            await self.mark_out_of_sync(group_id, "commit_rejected", error=reason)

    async def _on_group_message(self, group: GroupRow, env: dict[str, Any]) -> None:
        group_id, sender, msg_id = group.group_id, str(env["sender"]), str(env["msg_id"])
        gid = unb64(group_id)
        try:
            ct = unb64(str(env["ct"]))
        except ValueError:
            await self._malformed(env, "ct")
            return
        try:
            # SPEC 7.1: compare the envelope with the unprotected MLS header
            # first. Peeking uses no key, so a dropped message consumes none.
            head = ac.peek_header(ct)
        except (ac.AgentConnectError, ac.CoreError) as e:
            await self._rejected(group_id, env, e)
            return
        mismatch = _header_mismatch(env, gid, head)
        if mismatch is not None and head["content_type"] != "commit":
            # An application message or a proposal is dropped unprocessed. A
            # commit is still processed (dropping an authenticated commit
            # would fork us); its epoch mismatch is flagged in _after_commit.
            self.store.record_inbox(sender, msg_id, group_id, "dropped", self.now())
            await self._ack(msg_id)
            await self.emit(group_id, "relay_misbehaviour", reason=mismatch)
            return
        if mismatch == "group_mismatch":
            # A commit of another group: flagged here, rejected by the core.
            await self.emit(group_id, "relay_misbehaviour", reason=mismatch)
        if env["kind"] == "proposal" and int(env["epoch"]) != self._core_epoch(gid):
            # SPEC 7.1: a proposal is only valid in the current epoch, so an
            # envelope epoch that differs is dropped (commits are merged and
            # flagged instead, see _after_commit).
            self.store.record_inbox(sender, msg_id, group_id, "dropped", self.now())
            await self._ack(msg_id)
            await self.emit(group_id, "relay_misbehaviour", reason="epoch_mismatch")
            return
        self.failpoints.hit("receive.before_core")
        try:
            # Journalled (ADR-004): after a crash or a failure below, the
            # same frame gives the same event back instead of failing on its
            # consumed key.
            event = self.client.process(
                gid,
                ct,
                key=journal_key(sender, msg_id),
                context=journal_context(env, from_relay=True),
            )
        except (ac.AgentConnectError, ac.CoreError) as e:
            await self._rejected(group_id, env, e)
            return
        self.failpoints.hit("receive.after_core")
        await self._finish(env, event, from_relay=True, path="receive")

    async def _finish(
        self, env: dict[str, Any], event: dict[str, Any], *, from_relay: bool, path: str
    ) -> None:
        """Record what a journalled group event means, once, then consume
        its journal entry and ack the relay frame (ADR-004).

        The inbox row ``(sender, msg_id)`` is written in the same daemon
        transaction as every other effect, so it marks the entry as applied:
        a replay after a crash that followed that transaction only consumes
        the entry."""
        group_id, sender, msg_id = str(env["group_id"]), str(env["sender"]), str(env["msg_id"])
        state = self.store.inbox_state(sender, msg_id)
        scope = journal_key(sender, msg_id) + "/apply"
        if state is not None:
            self._settle_recorded(env)
        else:
            group = self.store.group(group_id)
            if group is None or group.status != "active":

                async def dropped() -> str:
                    self.store.record_inbox(sender, msg_id, group_id, "dropped", self.now())
                    return "dropped"

                with self._causing(scope):
                    state = await self._apply(path, dropped)
            else:
                try:
                    with self._causing(scope):
                        state = await self._apply(
                            path, lambda: self._effects(group, env, event, from_relay=from_relay)
                        )
                except Exception:
                    # The effects rolled back and the entry stays pending (it
                    # is finished on the next replay), but the cached view
                    # must follow the core now: local decisions use it.
                    with contextlib.suppress(Exception):
                        self._refresh(group_id)
                    raise
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
            self.client.journal_consume(journal_key(sender, msg_id), unb64(group_id))
        self.failpoints.hit(f"{path}.after_consume")
        if state == "pending":
            self._delivery_wake.set()
        elif from_relay:
            await self._ack(msg_id)
        self._pulse()

    async def _effects(
        self, group: GroupRow, env: dict[str, Any], event: dict[str, Any], *, from_relay: bool
    ) -> str:
        """The daemon-side effects of one group event (inside :meth:`_apply`);
        returns the inbox state recorded for it."""
        group_id, sender, msg_id = group.group_id, str(env["sender"]), str(env["msg_id"])
        now = self.now()
        etype = event["type"]
        if etype == "application":
            if event["epoch"] != env.get("epoch"):
                # SPEC §7.1: envelope and MLS epochs must agree.
                self.store.record_inbox(sender, msg_id, group_id, "dropped", now)
                await self.emit(group_id, "relay_misbehaviour", reason="epoch_mismatch")
                return "dropped"
            self.store.bump_messages(group_id)
            replayed = bool(event.get("replayed"))
            delivery, decision, kind, hop = self._make_delivery(
                group, msg_id, event, replayed=replayed
            )
            identity, size = str(event["sender"]["identity"]), len(event["plaintext"])
            self.safety.audit(
                group_id,
                "in",
                sender=identity,
                msg_id=msg_id,
                kind=kind,
                size=size,
                decision=decision.verdict,
                reason=decision.reason,
            )
            # SPEC 10.3 on the hop alone, before and whatever the policy
            # decided: a pause only for what passed would tell a peer which of
            # its probes passed (SPEC 10.2).
            if hop is not None and hop > _max_turns(group.policy):
                await self._loop_guard(group, msg_id, identity, hop)
            if delivery is None:
                self.store.record_inbox(sender, msg_id, group_id, "dropped", now)
                alert = (
                    None if replayed else self.safety.violation(group_id, identity, decision.reason)
                )
                if alert is not None:
                    await self.emit(group_id, "repeated_violations", **alert)
                return "dropped"
            held = decision.verdict is Verdict.HOLD_FOR_APPROVAL
            self.store.record_inbox(
                sender,
                msg_id,
                group_id,
                "held" if held else "pending",
                now,
                delivery=delivery.to_json(),
                hop=delivery.hop,
            )
            if held:
                await self._hold_inbound(group, sender, delivery, size)
            else:
                self.safety.transcribe(group_id, "in", identity, msg_id, delivery.inner)
                self._defer(self._delivery_wake.set)
            if delivery.kind == "control.close":
                # SPEC 7.3: the owner asks everyone to leave. Leaving is the
                # human's decision; the daemon never leaves on its own.
                reason = delivery.body.get("reason")
                await self.emit(
                    group_id,
                    "close_requested",
                    sender=delivery.sender.identity,
                    reason=reason[:200] if isinstance(reason, str) else "",
                )
            return "held" if held else "pending"
        if etype in ("commit", "own_commit_confirmed"):
            await self._after_commit(
                group_id,
                event,
                env if from_relay else None,
                own=etype == "own_commit_confirmed",
            )
        elif etype == "removed":
            await self._gone(group_id, "left" if group_id in self._leaving else "removed")
        elif etype == "leave_proposed":
            await self._on_leave_proposed(group_id, event["member"])
        self.store.record_inbox(sender, msg_id, group_id, "done", now)
        return "done"

    async def _replay_journal(self) -> None:
        """Finish every journal entry the core holds but the daemon hasn't
        consumed: a crash (or a failure) came after the core committed and
        before the daemon recorded the result (ADR-004)."""
        for entry in self.client.journal_pending():
            try:
                ctx = json.loads(entry["context"])
                env = ctx["env"]
                if not isinstance(env, dict) or _envelope_problem({**env, "ct": ""}) is not None:
                    raise ValueError("context")
            except (ValueError, KeyError, TypeError):
                # Not something this daemon wrote: drop it.
                self.client.journal_consume(
                    str(entry["key"]), None if entry["welcome"] else entry["group_id"]
                )
                continue
            LOG.info("journal_replay", kind=env.get("kind"), msg=log.hid(str(env.get("msg_id"))))
            if entry["welcome"] and isinstance(ctx.get("knock_id"), str):
                await self.knocks.finish_welcome(env, ctx["knock_id"], entry["group_id"])
            elif entry["welcome"]:
                await self._finish_welcome(env, str(ctx.get("invite_id")), entry["group_id"])
            else:
                event = {**entry["event"], "replayed": True}
                path = "receive" if ctx.get("from_relay", True) else "confirm"
                await self._finish(env, event, from_relay=bool(ctx.get("from_relay")), path=path)

    def _received_hop(self, group_id: str, inner: dict[str, Any]) -> int:
        """The SPEC 10.3 hop of a received message: what it claims, and at
        least one more than any message it replies to that we know (SPEC
        7.2), whatever the sender claims."""
        raw_hop = inner.get("hop")
        hop = raw_hop if isinstance(raw_hop, int) and not isinstance(raw_hop, bool) else 0
        hop = max(hop, 0)
        refs = inner.get("reply_to")
        if isinstance(refs, list):
            known = self.store.inbox_hops(
                group_id, [r for r in refs[:MAX_REPLY_TO] if isinstance(r, str)]
            )
            if known:
                hop = max(hop, max(known) + 1)
        return hop

    def _card_problem(self, inner: dict[str, Any]) -> str:
        """Why a received Agent Card can't be used, or ``""``. A card the A2A
        types can't parse is ``malformed`` (its signature couldn't be checked,
        so it is never let through unchecked); one whose signature fails
        against a pinned key (``a2a.card_keys_file``, SPEC 10.5) is
        ``bad_signature``. Checked on the card as received."""
        if inner.get("kind") != "a2a.agent_card":
            return ""
        body = inner.get("body")
        parsed = convert.parse_card(body) if isinstance(body, dict) else None
        if parsed is None:
            return "malformed"
        if self._card_keys and cards.signature_status(parsed, self._card_keys) == "invalid":
            return "bad_signature"
        return ""

    def _card_changed(self, group_id: str, identity: str, inner: dict[str, Any]) -> bool:
        """Whether an Agent Card says something new: with inbound approval, a
        changed card is held like any content (its text reaches the agent)."""
        if inner.get("kind") != "a2a.agent_card" or not isinstance(inner.get("body"), dict):
            return False
        shaped = normalize("a2a.agent_card", inner["body"])
        return shaped is not None and self.store.cards(group_id).get(identity) != shaped

    def _triggered(self, group_id: str, hop: int, msg_id: str) -> None:
        """The default "message replied to" for this instance's next agent
        message in the group (see _reply_hop)."""
        self.store.kv_set(f"trigger_hop/{group_id}", str(hop))
        self.store.kv_set(f"trigger_msg/{group_id}", msg_id)

    def _make_delivery(
        self, group: GroupRow, msg_id: str, event: dict[str, Any], *, replayed: bool = False
    ) -> tuple[Delivery | None, Decision, str, int | None]:
        """Apply the safety policy to a received application message. Returns
        the delivery to record (``None`` if dropped), the decision and the
        message kind."""
        try:
            inner = json.loads(event["plaintext"])
        except ValueError:
            return None, drop("malformed"), "", None
        if not isinstance(inner, dict) or not isinstance(inner.get("kind"), str):
            return None, drop("malformed"), "", None
        # The kind is peer text: record only the ones the protocol defines.
        kind = str(inner["kind"]) if inner["kind"] in KNOWN_KINDS else "unknown"
        sender = event["sender"]
        identity = sender["identity"]
        policy = group.policy
        hop = self._received_hop(group.group_id, inner)
        # The hop the loop guard acts on (None: a human's message, SPEC 10.3).
        guard_hop = None if inner.get("origin") == "human" else hop
        addressed = addressed_to_me(
            str(policy.get("floor", "free")),
            inner,
            self.me,
            self.instance.instance_id_hex,
            policy.get("floor_moderator"),
        )
        # One decision: SPEC 7.2 (unknown kinds are ignored), 7.3, 9.3, 10.2
        # (size, parts, rates; a replayed journal entry was counted when the
        # core first processed it), 10.3 and require_approval.
        decision = self.safety.inbound(
            Inbound(
                group.group_id,
                identity,
                str(sender["instance_id_hex"]),
                inner,
                len(event["plaintext"]),
                policy.get("owner"),
                hop,
                _max_turns(policy),
                addressed,
                replayed=replayed,
                drain_exempt=lambda: self._drain_exempt(group.group_id, identity),
                card_changed=self._card_changed(group.group_id, identity, inner),
                card_problem=self._card_problem(inner),
            )
        )
        if decision.verdict is Verdict.DROP:
            LOG.info("message_dropped", group=log.hid(group.group_id), reason=decision.reason)
            return None, decision, kind, guard_hop
        self.store.record_hop(group.group_id, msg_id, hop, self.now())
        if inner["kind"] in HUMAN_ONLY_KINDS:
            self._reset_loop_guard(group.group_id)
        if decision.verdict is Verdict.DELIVER:
            self._triggered(group.group_id, hop, msg_id)
        # A held message triggers once approved if it would trigger now.
        triggers = decision.verdict is Verdict.DELIVER or (
            decision.verdict is Verdict.HOLD_FOR_APPROVAL
            and addressed
            and hop <= _max_turns(policy)
        )
        body = inner.get("body") if isinstance(inner.get("body"), dict) else {}
        # Controls, cards and cancels reach adapters in their schema's shape
        # only: unknown fields stripped, card text capped (agentconnect.schemas).
        shaped = normalize(inner["kind"], body)
        if shaped is not None and shaped is not body:
            body = shaped
            inner = dict(inner)
            inner["body"] = shaped
        verified = any(
            m.identity == identity and m.verified for m in self.store.members(group.group_id)
        )
        raw_to = inner.get("to")
        to: list[Any] = raw_to if isinstance(raw_to, list) else ["*"]
        delivery = Delivery(
            group_id=group.group_id,
            msg_id=msg_id,
            kind=inner["kind"],
            body=body,
            sender=Sender(
                identity,
                sender["instance_id_hex"],
                self._display_name(group.group_id, identity),
                verified,
            ),
            to=[str(x) for x in to],
            addressed_to_me=triggers,
            scope=group.purpose,
            trust_state=self._trust_state(group.group_id),
            origin="human" if inner.get("origin") == "human" else "agent",
            hop=hop,
            inner=inner,
            frame_text=self.safety.settings(group.group_id).frame_text,
        )
        return delivery, decision, kind, guard_hop

    # -- loop guard (SPEC 10.3) ---------------------------------------------

    def _reply_hop(self, group_id: str, reply_to: list[str] | None) -> tuple[int, list[str]]:
        """``hop`` for an agent message: one more than the largest ``hop`` of
        the messages it replies to.

        "Replies to" is the received messages named in ``reply_to`` (their
        ``msg_id``s) when the agent says; otherwise the last message that
        triggered this instance in the group (0 before any, so a fresh agent
        message has hop 1). A ``control.resume`` resets that to 0.

        Also returns the ``msg_id``s replied to, for the inner ``reply_to``.
        """
        refs: list[str] = [str(r) for r in (reply_to or [])][:MAX_REPLY_TO]
        hops = self.store.inbox_hops(group_id, refs)
        if hops:
            return int(max(hops)) + 1, refs
        last = self.store.kv_get(f"trigger_msg/{group_id}") or ""
        hop = int(self.store.kv_get(f"trigger_hop/{group_id}") or "0") + 1
        if not refs and last != "":
            refs = [last]
        return hop, refs

    def _reset_loop_guard(self, group_id: str) -> None:
        """A human ``control.resume`` (sent or received) resets the counter."""
        self.store.kv_set(f"trigger_hop/{group_id}", "0")
        self.store.kv_set(f"trigger_msg/{group_id}", "")
        self.store.kv_set(f"loop_paused/{group_id}", "0")

    async def _loop_guard(self, group: GroupRow, msg_id: str, sender: str, hop: int) -> None:
        """SPEC 10.3: the agent was not triggered; pause the group once and
        tell the human (until a ``control.resume``)."""
        key = f"loop_paused/{group.group_id}"
        if self.store.kv_get(key) == "1":
            return
        self.store.kv_set(key, "1")
        await self.emit(
            group.group_id,
            "loop_guard",
            msg_id=msg_id,
            sender=sender,
            hop=hop,
            max_agent_turns=_max_turns(group.policy),
        )
        try:
            self.send_message(
                group.group_id,
                {"reason": "loop_guard"},
                kind="control.pause",
                reply_to=[msg_id],
                internal=True,
            )
        except DaemonError as e:
            LOG.info("loop_guard_pause_not_sent", code=e.code)

    async def _on_leave_proposed(self, group_id: str, member: dict[str, Any]) -> None:
        self._proposed_leaves.setdefault(group_id, set()).add(member["identity"])
        # One designated member commits pending leaves (the lowest leaf that
        # isn't leaving), so members don't race each other into conflicts.
        leaving = self._proposed_leaves[group_id]
        candidates = sorted(
            (m for m in self.client.members(unb64(group_id)) if m["identity"] not in leaving),
            key=lambda m: m["leaf_index"],
        )
        if candidates and candidates[0]["mailbox_id"] == self.mailbox:
            self._enqueue("commit", group_id, {"intent": {"type": "proposals"}})

    # -- joins ----------------------------------------------------------------

    def _invite_object(self, invite: dict[str, Any]) -> ac.Invite | None:
        secret = self.keystore.get(f"invite/{invite['invite_id']}")
        if secret is None:
            return None
        return ac.Invite.from_parts(
            self.config.relay_host, unb64(invite["invite_id"]), secret, invite["expires_at"]
        )

    async def _on_join_request(self, env: dict[str, Any]) -> None:
        if str(env["msg_id"]).startswith(KNOCK_REQUEST_PREFIX):
            # A join's request id is its msg_id, which the joiner (or the
            # relay) picks: it must never look like a knock's.
            LOG.info("join_request_malformed")
            return
        raw = unb64(str(env.get("ct", "")))
        try:
            invite_id = str(json.loads(raw)["invite_id"])
        except (ValueError, KeyError, TypeError):
            LOG.info("join_request_malformed")
            return
        invite = self.store.invite(invite_id)
        obj = None if invite is None or invite["status"] != "open" else self._invite_object(invite)
        if invite is None or obj is None:
            LOG.info("join_request_unknown_invite", invite=log.hid(invite_id))
            return
        if self._invite_closed(invite):
            # SPEC 6.2 step 1: no uses left (or expired). The joiner sees the
            # SPEC 4.3 "already used" warning when its join lapses.
            LOG.info("join_request_invite_used", invite=log.hid(invite_id))
            return
        try:
            verified = self.client.verify_join_request(raw, obj)
        except (ac.AgentConnectError, ac.CoreError) as e:
            LOG.info("join_request_rejected", invite=log.hid(invite_id), reason=str(e)[:60])
            return
        kp_ref = b64(verified.key_package_ref)
        if self.store.open_approval_for(kp_ref) is not None:
            # The same JoinRequest again under a fresh msg_id (a relay
            # replay): one approval per KeyPackage.
            LOG.info("join_request_replayed", invite=log.hid(invite_id))
            return
        request_id = str(env["msg_id"])
        self.store.add_approval(
            {
                "request_id": request_id,
                "invite_id": invite_id,
                "group_id": invite["group_id"],
                "request": b64(raw),
                "identity": verified.identity,
                "display_name": verified.display_name,
                "mailbox_id": verified.mailbox_id,
                "received_at": self.now(),
                "kp_ref": kp_ref,
            }
        )
        await self.emit(
            invite["group_id"],
            "pending_approval",
            request_id=request_id,
            identity=verified.identity,
            display_name=verified.display_name,
            display_name_verified=False,
        )
        if self.config.auto_approve:
            # Joins only: nothing approves a knock but the human (SPEC 6.6.4).
            self._approve_join(request_id)

    async def check_joins(self) -> None:
        """SPEC 4.3: a pending join whose invite was used up or revoked
        lapses with the "already used" warning, so a joiner beaten to a
        single-use link (perhaps by whoever intercepted it) hears about it.

        The relay marks an invite used only after the inviter sent the
        Welcome, so a join is failed only once the invite has been seen
        closed for :data:`JOIN_CLOSED_GRACE_SECS` (its Welcome may still be
        on the way). Runs on every (re)connect.
        """
        for pending in self.store.pending_joins():
            invite_id = pending["invite_id"]
            try:
                status = (await self.rest.invite_meta(invite_id)).get("status")
            except RelayError as e:
                status = "revoked" if e.code == "invite_not_open" else None
            key = f"join_closed/{invite_id}"
            if status not in ("exhausted", "revoked", "expired"):
                continue
            seen = self.store.kv_get(key)
            if seen is None:
                self.store.kv_set(key, str(self.now()))
                continue
            if self.now() - int(seen) < JOIN_CLOSED_GRACE_SECS:
                continue
            if self.store.join_status(invite_id) != ("pending", None):
                continue  # the Welcome arrived meanwhile
            self.store.finish_join(invite_id, "failed")
            self.keystore.delete(f"join/{invite_id}")
            await self.emit(
                None,
                "join_failed",
                invite_id=invite_id,
                reason="invite_used",
                warning=INVITE_WARNING,
            )

    async def _on_welcome(self, env: dict[str, Any]) -> str | None:
        """Join from a wrapped Welcome; returns the group id (recorded and
        acked), or ``None`` if it matched no pending join (the caller records
        and acks it)."""
        wrapped = unb64(str(env.get("ct", "")))
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        for pending in self.store.pending_joins():
            invite_id = pending["invite_id"]
            url = self.keystore.get(f"join/{invite_id}")
            if url is None:
                continue
            link = ac.parse_invite_url(url.decode())
            try:
                ac.unwrap_welcome(link.invite_id, link.secret_bytes(), wrapped)
            except ac.AgentConnectError:
                continue
            self.failpoints.hit("welcome.before_core")
            try:
                # Journalled (ADR-004): the same Welcome after a crash gives
                # the joined group back instead of failing on the spent
                # KeyPackage.
                gid = self.client.join(
                    link,
                    canonical(pending["meta"]),
                    wrapped,
                    key=journal_key(sender, msg_id),
                    context=journal_context(env, from_relay=True, invite_id=invite_id),
                )
            except (ac.AgentConnectError, ac.CoreError) as e:
                reason = _core_error(e)
                if reason == "transient":
                    raise TransientError(None, type(e).__name__) from None
                if reason == "duplicate":
                    return None
                # The KeyPackage is used up; a retry needs a new JoinRequest.
                self.store.finish_join(invite_id, "failed")
                self.keystore.delete(f"join/{invite_id}")
                await self.emit(None, "join_failed", invite_id=invite_id, reason=str(e)[:80])
                return None
            self.failpoints.hit("welcome.after_core")
            return await self._finish_welcome(env, invite_id, gid)
        # No pending join opened it: one of this runtime's knocks may (SPEC 6.6.5).
        joined = await self.knocks.on_welcome(env, wrapped)
        if joined is None:
            LOG.info("welcome_unmatched")
        return joined

    async def _finish_welcome(self, env: dict[str, Any], invite_id: str, gid: bytes) -> str:
        """Record a journalled join once, consume the entry, ack (ADR-004)."""
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        group_id = gid_b64(gid)

        async def body() -> str:
            if self.store.group(group_id) is None:
                meta = json.loads(self.client.meta(gid))
                self.store.add_group(
                    GroupRow(
                        group_id=group_id,
                        name=meta["name"],
                        purpose=meta["purpose"],
                        policy={},
                        adapter=self.config.default_adapter,
                        status="active",
                        out_of_sync=False,
                        out_of_sync_reason=None,
                        epoch=self.client.epoch(gid),
                        created_at=self.now(),
                        last_own_commit_at=self.now(),
                        msgs_since_commit=0,
                    )
                )
            self._refresh(group_id)
            name = self.store.join_name(invite_id) or self.config.display_name
            self.store.set_display_name(group_id, self.me, name)
            self.store.finish_join(invite_id, "joined", group_id)
            self.store.record_inbox(sender, msg_id, group_id, "done", self.now())
            # SPEC §6.3: the invite secret goes once the join succeeded.
            self._defer(lambda: self.keystore.delete(f"join/{invite_id}"))
            await self.emit(group_id, "joined", invite_id=invite_id, sas=self._sas(gid))
            await self._send_card(group_id, ["*"])
            return "done"

        if self.store.inbox_state(sender, msg_id) is None:
            with self._causing(journal_key(sender, msg_id) + "/apply"):
                await self._apply("welcome", body)
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
            self.client.journal_consume(journal_key(sender, msg_id))
        self.failpoints.hit("welcome.after_consume")
        await self._ack(msg_id)
        self._pulse()
        return group_id

    # -- safety policy: approvals, audit, settings (agentconnect.policy) -----------

    def _hold_id(self, group_id: str, direction: str, msg_id: str) -> str:
        """Stable, so a replayed journal entry holds the same item."""
        return b64(hashlib.sha256(canonical([group_id, direction, msg_id])).digest()[:16])

    def _held_event(self, item: dict[str, Any]) -> dict[str, Any]:
        """Metadata only: the human reads the content with the human token."""
        keys = ("hold_id", "direction", "sender", "msg_id", "size", "expires_at")
        return {k: item[k] for k in keys} | {"message_kind": item["kind"]}

    def _new_hold(
        self, group_id: str, direction: str, inner: dict[str, Any], **row: Any
    ) -> dict[str, Any]:
        now = self.now()
        item = {
            "hold_id": self._hold_id(group_id, direction, row["msg_id"]),
            "group_id": group_id,
            "direction": direction,
            "kind": str(inner.get("kind")),
            "task_id": task_of(inner),
            "created_at": now,
            "expires_at": now + self.safety.settings(group_id).approval_ttl_secs,
            **row,
        }
        self.store.add_held(item)
        self._held_wake.set()
        return item

    async def _hold_inbound(
        self, group: GroupRow, mailbox: str, delivery: Delivery, size: int
    ) -> None:
        """Inside :meth:`_apply`: the inbox row (state ``held``) keeps the
        message; this records the approval item and tells the human."""
        item = self._new_hold(
            group.group_id,
            "in",
            delivery.inner,
            sender=delivery.sender.identity,
            instance=delivery.sender.instance_id,
            msg_id=delivery.msg_id,
            size=size,
            inbox_seq=self.store.inbox_seq(mailbox, delivery.msg_id),
        )
        await self.emit(
            group.group_id,
            "message_held",
            cause=f"hold={item['hold_id']}",
            **self._held_event(item),
        )

    def _hold_outbound(self, group: GroupRow, payload: dict[str, Any], size: int) -> list[Event]:
        """Inside :meth:`queue_message`'s transaction: keep a send for the
        human's approval and record ``message_held`` with it, so a crash
        can't lose the event. Returns the events to notify."""
        item = self._new_hold(
            group.group_id,
            "out",
            payload["inner"],
            sender=self.me,
            instance=self.instance.instance_id_hex,
            msg_id=payload["msg_id"],
            size=size,
            payload=payload,
        )
        event = self._record(
            group.group_id, "message_held", f"hold={item['hold_id']}", self._held_event(item)
        )
        return [] if event is None else [event]

    def held_messages(self, direction: str | None = None) -> list[dict[str, Any]]:
        """Messages waiting for the human's approval, metadata only; with
        ``direction`` (``in`` or ``out``) only those."""
        now = self.now()
        return [
            {k: v for k, v in item.items() if k not in HELD_PRIVATE}
            for item in self.store.held_items()
            if now < int(item["expires_at"]) and direction in (None, item["direction"])
        ]

    def _pending_hold(self, hold_id: str) -> dict[str, Any]:
        item = self.store.held(hold_id)
        if item is None or item["status"] != "pending":
            raise DaemonError("not_found", "no such held message")
        if self.now() >= int(item["expires_at"]):
            raise DaemonError("expired", "the approval window has passed")
        return item

    def _held_inner(self, item: dict[str, Any]) -> dict[str, Any]:
        if item["direction"] == "out":
            payload = item["payload"] or {}
            return dict(payload.get("inner") or {})
        row = self.store.inbox_row(int(item["inbox_seq"] or 0))
        if row is None or row.delivery is None:
            return {}
        return dict(row.delivery["inner"])

    def held_message(self, hold_id: str) -> dict[str, Any]:
        """One held message with everything the agent (or the group) would
        get: the whole body, ``to``, ``addressee`` and ``reply_to`` (human
        scope only: the content is what the human decides on). Peer content
        stays untrusted."""
        item = self._pending_hold(hold_id)
        inner = self._held_inner(item)
        body = inner.get("body") if isinstance(inner.get("body"), dict) else {}
        out = {k: v for k, v in item.items() if k not in HELD_PRIVATE}
        return out | {
            "untrusted": item["direction"] == "in",
            "to": inner.get("to"),
            "addressee": inner.get("addressee"),
            "reply_to": inner.get("reply_to"),
            "body": body,
        }

    def approve_message(self, hold_id: str) -> dict[str, Any]:
        """Human-gated: release a held message, to the adapter (inbound) or
        to the relay (outbound). Approving a task's first update approves the
        task's later updates too."""
        item = self._pending_hold(hold_id)
        group_id = str(item["group_id"])
        group = self.store.group(group_id)
        if group is None or group.status != "active":
            raise DaemonError("not_found", "the group is no longer active")
        events: list[Event] = []
        with self.store.tx():
            if not self.store.set_held_status(hold_id, "approved"):
                raise DaemonError("not_found", "no such held message")
            if item["direction"] == "in":
                row = self.store.inbox_row(int(item["inbox_seq"] or 0))
                if row is not None and row.state == "held" and row.delivery is not None:
                    delivery = Delivery.from_json(row.delivery)
                    self.store.set_inbox_state(row.seq, "pending")
                    if delivery.addressed_to_me:
                        self._triggered(group_id, delivery.hop, delivery.msg_id)
                    self.safety.transcribe(
                        group_id, "in", item["sender"], item["msg_id"], delivery.inner
                    )
            else:
                payload = item["payload"] or {}
                self._enqueue("app", group_id, payload)
                self.safety.transcribe(group_id, "out", self.me, item["msg_id"], payload["inner"])
                # The agent's own message goes out: tell its adapter (the
                # A2A facade waits for it), in the same transaction.
                sent = self._record(
                    group_id,
                    "send_approved",
                    f"hold={hold_id}/approved",
                    {"msg_id": item["msg_id"], "hold_id": hold_id},
                )
                events = [] if sent is None else [sent]
            if item["task_id"] is not None and item["direction"] == "in":
                self.safety.decide_task(group_id, item["sender"], item["task_id"], approved=True)
            self._audit_hold(item, "approved")
        self._notify_soon(events)
        self._delivery_wake.set()
        self._held_wake.set()
        self._pulse()
        return {"hold_id": hold_id, "group_id": group_id, "status": "approved"}

    def _audit_hold(self, item: dict[str, Any], decision: str) -> None:
        self.safety.audit(
            str(item["group_id"]),
            str(item["direction"]),
            sender=str(item["sender"]),
            msg_id=str(item["msg_id"]),
            kind=str(item["kind"]),
            size=int(item["size"]),
            decision=decision,
        )

    def _drop_hold(self, item: dict[str, Any], status: str, code: str) -> list[Event]:
        """Drop a held item once (a concurrent caller that decided it first
        wins): its plaintext goes, the audit log records it, its task is
        rejected, and the events are recorded in the same transaction (the
        human's ``held_expired`` on expiry, the agent's ``send_failed`` for
        its own send). Nothing reaches the peer (SPEC 10.2). Returns the
        events to notify."""
        hold_id, group_id = str(item["hold_id"]), str(item["group_id"])
        events: list[Event | None] = []
        with self.store.tx():
            if not self.store.set_held_status(hold_id, status):
                return []
            if item["direction"] == "in" and item["inbox_seq"] is not None:
                row = self.store.inbox_row(int(item["inbox_seq"]))
                if row is not None and row.state == "held":
                    self.store.set_inbox_state(row.seq, "dropped")
            if item["task_id"] is not None and item["direction"] == "in":
                self.safety.decide_task(group_id, item["sender"], item["task_id"], approved=False)
            self._audit_hold(item, status)
            if status == "expired":
                events.append(
                    self._record(
                        group_id, "held_expired", f"hold={hold_id}/expired", self._held_event(item)
                    )
                )
            if item["direction"] == "out":
                data = {"msg_id": item["msg_id"], "hold_id": hold_id, "code": code}
                events.append(
                    self._record(group_id, "send_failed", f"hold={hold_id}/{status}", data)
                )
        self._held_wake.set()
        return [e for e in events if e is not None]

    async def reject_message(self, hold_id: str) -> dict[str, Any]:
        """Human-gated: drop a held message. Nothing tells the peer; an
        outbound one fails like any send (``send_failed``)."""
        item = self._pending_hold(hold_id)
        for event in self._drop_hold(item, "rejected", "rejected"):
            await self._notify(event)
        return {"hold_id": hold_id, "group_id": item["group_id"], "status": "rejected"}

    async def expire_held(self) -> None:
        """Held messages past ``approval_ttl_secs`` are dropped silently (the
        peer is not told) and the human gets ``held_expired``. Runs on a timer
        (:meth:`_held_timer`), so plaintext doesn't outlive the window."""
        now = self.now()
        for item in self.store.held_items():
            if now < int(item["expires_at"]):
                continue
            for event in self._drop_hold(item, "expired", "expired"):
                await self._notify(event)

    async def _drop_group_holds(self, group_id: str) -> None:
        """The group ended: its held messages are dropped, and the agent's own
        held sends fail with ``group_gone`` (inside :meth:`_apply` the
        events join its batch)."""
        for item in self.store.held_items():
            if item["group_id"] != group_id:
                continue
            for event in self._drop_hold(item, "dropped", "group_gone"):
                if self._batch is not None:
                    self._batch.append(event)
                else:
                    await self._notify(event)

    async def _held_timer(self) -> None:
        """Expire held messages when their window ends, traffic or not (the
        plaintext of a held message must not outlive it). A failure is logged
        by type only and retried after a backoff; the timer keeps running."""
        backoff = Backoff(base=1.0, cap=300.0, rng=self.options.backoff_rng)
        while True:
            try:
                await self._held_timer_step()
                backoff.reset()
            except Exception as e:
                LOG.warning("held_timer_failed", error=type(e).__name__)
                await self._sleep(backoff.next())

    async def _held_timer_step(self) -> None:
        """Wait for the next expiry (or a new hold), then expire what is due."""
        self._held_wake.clear()
        pending = self.store.held_items()
        if not pending:
            await self._held_wake.wait()
            return
        delay = min(int(item["expires_at"]) for item in pending) - self.now()
        if delay > 0:
            sleep = asyncio.ensure_future(self.clock.sleep(delay))
            woken = asyncio.ensure_future(self._held_wake.wait())
            try:
                await asyncio.wait({sleep, woken}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for waiter in (sleep, woken):
                    waiter.cancel()
            return
        self.failpoints.hit("held_timer.expire")
        await self.expire_held()

    def safety_settings(self, group_id: str) -> dict[str, Any]:
        group = self._group_or_raise(group_id)
        return {
            "group_id": group.group_id,
            "settings": self.safety.settings(group.group_id).as_json(),
            "overrides": self.safety.overrides(group.group_id),
        }

    def update_safety(
        self, group_id: str, changes: dict[str, Any], sender: str | None = None
    ) -> dict[str, Any]:
        """Human-gated: change a group's policy (``None`` clears an override)."""
        group = self._group_or_raise(group_id)
        try:
            self.safety.update(group.group_id, changes, sender)
        except PolicyError as e:
            raise DaemonError("bad_request", str(e)) from None
        return self.safety_settings(group.group_id)

    def transcript(self, group_id: str, after: int = 0) -> list[dict[str, Any]]:
        group = self._group_or_raise(group_id)
        return self.store.transcript(group.group_id, after)

    # -- delivery -------------------------------------------------------------

    def _gated(self, group_id: str | None) -> bool:
        """SPEC §10.4: hold deliveries until the human verified the epoch. And
        while the group is hidden from the agent (an approved knock's, until
        the knocker is in), they wait in the inbox too."""
        if group_id is None:
            return False
        if self.hidden_from_agent(group_id):
            return True
        g = self.store.group(group_id)
        if g is None:
            return False
        required = bool(g.policy.get("require_verified"))
        if g.status == "active":
            # The core's policy is the source of truth; if it can't be read,
            # hold (fail closed).
            try:
                required = bool(json.loads(self.client.policy(unb64(group_id)))["require_verified"])
            except (ac.AgentConnectError, ac.CoreError, ValueError, KeyError):
                required = True
        return verification_holds(required, self._trust_state(group_id))

    def _keep_card(self, delivery: Delivery) -> None:
        """A peer's Agent Card (and the name in it) is peer-controlled text:
        keep it only once its delivery has passed the SPEC 10.4 gate and the
        safety policy, like any other message."""
        identity = delivery.sender.identity
        if delivery.kind != "a2a.agent_card" or identity == self.me:
            return
        self.store.put_card(delivery.group_id, identity, delivery.body)
        name = delivery.body.get("name")
        if isinstance(name, str) and name:
            self.store.set_display_name(delivery.group_id, identity, name[:80])

    async def _delivery(self) -> None:
        """Hand pending inbox rows to the adapters: one worker per group with
        deliverable rows, so a slow or failing adapter call holds up its own
        group only, and strict order within each group. A worker's crash or
        failure ends this worker too (the supervisor restarts it)."""
        workers: dict[str, asyncio.Task[None]] = {}
        woken = True
        try:
            while True:
                # Reap first: a worker that just found its group empty must not
                # keep a row that arrived since from getting a new worker.
                for group_id, worker in list(workers.items()):
                    if worker.done():
                        del workers[group_id]
                        if worker.cancelled():
                            # Not by us (we'd be cancelled too): restart it.
                            LOG.error("delivery_worker_died", reason="CancelledError")
                            woken = True
                        else:
                            worker.result()  # a failure ends this worker too
                if woken:
                    # Clear before reading, so a row recorded after the
                    # read wakes us again.
                    self._delivery_wake.clear()
                    for group_id in self.store.pending_groups():
                        if group_id not in workers and not self._gated(group_id):
                            workers[group_id] = asyncio.ensure_future(self._deliver_group(group_id))
                wake = asyncio.ensure_future(self._delivery_wake.wait())
                try:
                    done, _ = await asyncio.wait(
                        {wake, *workers.values()}, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    wake.cancel()
                woken = wake in done
        finally:
            await cancel_and_wait(*workers.values(), ignore=(Exception, SimulatedCrash))

    async def _deliver_group(self, group_id: str) -> None:
        """One group's pending deliveries, in order, until none is left that
        can be delivered now; a ``RETRY`` waits out the group's backoff."""
        backoff = Backoff(base=1.0, cap=300.0, rng=self.options.backoff_rng)
        while True:
            if self._gated(group_id):
                return
            rows = self.store.pending_deliveries(group_id, limit=DELIVERY_BATCH)
            delivered, retry = 0, False
            for row in rows:
                if row.delivery is None:
                    continue
                stored = Delivery.from_json(row.delivery)
                # Trust can change between reception and delivery (a human
                # verified a member meanwhile): frame with the current state.
                members = {m.identity: m for m in self.store.members(stored.group_id)}
                known = members.get(stored.sender.identity)
                sender = replace(
                    stored.sender,
                    verified=known is not None and known.verified,
                    display_name=stored.sender.display_name
                    if known is None
                    else known.display_name,
                )
                delivery = replace(
                    stored, sender=sender, trust_state=self._trust_state(stored.group_id)
                )
                view = self._view(delivery.group_id)
                adapter = self._adapter_for(delivery.group_id)
                if view is None or adapter is None:
                    continue
                self._keep_card(delivery)
                try:
                    result = await adapter.deliver(view, delivery.sender, delivery.to, delivery)
                except Exception:
                    LOG.warning("adapter_deliver_failed")
                    result = DeliveryResult.RETRY
                if result is DeliveryResult.ACK:
                    self.failpoints.hit("delivery.after_adapter")
                    self.store.set_inbox_state(row.seq, "done")
                    backoff.reset()
                    await self._ack(row.msg_id)
                    delivered += 1
                    self._pulse()
                else:
                    retry = True
                    break
            if retry:
                await self._sleep(backoff.next())
            elif delivered == 0:
                return  # nothing left, or only rows that can't go out yet

    # -- outbox ---------------------------------------------------------------

    def _enqueue(self, kind: str, group_id: str | None, payload: dict[str, Any]) -> int:
        seq = self.store.enqueue(kind, group_id, payload, self.now())
        self._outbox_wake.set()
        return seq

    async def _outbox(self) -> None:
        backoff = Backoff(base=1.0, cap=60.0, rng=self.options.backoff_rng)
        while True:
            row = self.store.next_outbox()
            if row is None:
                self._outbox_wake.clear()
                await self._outbox_wake.wait()
                continue
            await self.link.wait_connected()
            try:
                state = await self._run_row(row)
            except NotConnectedError:
                continue
            except TransientFailure:
                # The row stays queued and runs again from what it recorded;
                # a confirmed commit is finished from the core's journal.
                LOG.warning("outbox_transient", kind=row.kind)
                await self._sleep(backoff.next())
                continue
            except Exception:
                LOG.exception("outbox_failed", kind=row.kind)
                state = "failed"
            backoff.reset()
            msg_id = row.payload.get("msg_id")
            self.store.update_outbox(row.seq, state=state)
            code = self._fail_codes.pop(row.seq, "failed")
            if state == "failed" and row.group_id is not None:
                # Tell the caller: it holds a msg_id (or an intent) that will
                # never be delivered.
                if row.kind == "app":
                    await self.emit(row.group_id, "send_failed", msg_id=msg_id, code=code)
                elif row.kind == "commit" and code != BENIGN and not self._knock_row(row):
                    # (An approved knock's Add failing is the human's
                    # knock_approval_failed, not the agent's to hear.)
                    intent = row.payload.get("intent") or {}
                    await self.emit(
                        row.group_id,
                        "commit_failed",
                        cause=f"outbox/{row.seq}",
                        intent=intent.get("type"),
                        code=code,
                    )
            self._pulse()

    @staticmethod
    def _knock_row(row: OutboxRow) -> bool:
        intent = row.payload.get("intent")
        return isinstance(intent, dict) and bool(intent.get("type") == "knock_add")

    async def _run_row(self, row: OutboxRow) -> str:
        if row.kind == "frame":
            return await self._run_frame(row)
        group = self.store.group(row.group_id or "")
        if group is None or group.status != "active":
            return "failed"
        if row.kind == "app":
            return await self._run_app(row, group)
        if row.kind == "commit":
            return await self._run_commit(row, group)
        if row.kind == "proposal":
            return await self._run_proposal(row, group)
        return "failed"

    async def _request(
        self,
        frame: dict[str, Any],
        msg_id: str,
        on_sent: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        return await self.link.request(frame, msg_id, on_sent=on_sent)

    async def _run_frame(self, row: OutboxRow) -> str:
        frame, msg_id = row.payload["frame"], row.payload["msg_id"]
        if frame.get("t") == "knock":
            return await self.knocks.send_frame(row.payload)
        try:
            await self._request(frame, msg_id)
        except RelayError as e:
            LOG.info("relay_request_failed", t=frame.get("t"), code=e.code)
            if frame.get("t") == "join":
                invite_id = str(frame.get("invite_id"))
                self.store.finish_join(invite_id, "failed")
                self.keystore.delete(f"join/{invite_id}")
                await self.emit(None, "join_failed", invite_id=invite_id, reason=e.code)
            return "failed"
        if frame.get("t") == "invite.consume":
            invite = self.store.invite(str(frame["invite_id"]))
            if invite is not None:
                used = len(
                    [
                        a
                        for a in self.store.approvals("approved")
                        if a["invite_id"] == invite["invite_id"]
                    ]
                )
                if used >= invite["max_uses"]:
                    self.store.set_invite_status(invite["invite_id"], "exhausted")
                    self.keystore.delete(f"invite/{invite['invite_id']}")
        return "done"

    def _update_due(self, group: GroupRow) -> bool:
        return (
            self.now() - group.last_own_commit_at >= UPDATE_AFTER_SECS
            or group.msgs_since_commit >= UPDATE_AFTER_MESSAGES
        )

    async def _run_app(self, row: OutboxRow, group: GroupRow) -> str:
        if group.out_of_sync:
            self._fail_codes[row.seq] = "out_of_sync"
            return "failed"
        gid = unb64(group.group_id)
        payload = dict(row.payload)
        for _ in range(MAX_COMMIT_ATTEMPTS):
            if "env" not in payload:
                if self._update_due(group):
                    # SPEC §3.1: renew keys just before the next send.
                    group = await self._cadence_update(row, payload, group)
                inner = canonical(payload["inner"])
                payload["env"] = {
                    "v": 0,
                    "kind": "application",
                    "group_id": group.group_id,
                    "epoch": self.client.epoch(gid),
                    "msg_id": payload["msg_id"],
                    "sender": self.mailbox,
                    "ct": b64(self.client.seal(gid, inner)),
                }
                self.store.update_outbox(row.seq, payload=payload)
            try:
                await self._request({"t": "send", "env": payload["env"]}, payload["msg_id"])
            except RelayError as e:
                if e.code == "epoch_conflict":
                    payload.pop("env")  # too old an epoch: seal again
                    continue
                if e.code in RETRYABLE_RELAY_ERRORS:
                    await self._sleep(1.0)
                    continue
                LOG.info("send_failed", code=e.code)
                self._fail_codes[row.seq] = e.code
                return "failed"
            self.store.bump_messages(group.group_id)
            return "done"
        self._fail_codes[row.seq] = "attempts_exhausted"
        return "failed"

    async def _run_proposal(self, row: OutboxRow, group: GroupRow) -> str:
        gid = unb64(group.group_id)
        payload = dict(row.payload)
        if "env" not in payload:
            try:
                proposal = self.client.propose_leave(gid)
            except ac.AgentConnectError as e:
                LOG.info("leave_not_possible", reason=str(e)[:60])
                return "failed"
            payload["env"] = {
                "v": 0,
                "kind": "proposal",
                "group_id": group.group_id,
                "epoch": self.client.epoch(gid),
                "msg_id": new_msg_id(),
                "sender": self.mailbox,
                "ct": b64(proposal),
            }
            self.store.update_outbox(row.seq, payload=payload)
        try:
            await self._request({"t": "send", "env": payload["env"]}, str(payload["env"]["msg_id"]))
        except RelayError as e:
            # A stale proposal: the next commit we process triggers a resend.
            LOG.info("proposal_failed", code=e.code)
            return "failed"
        return "done"

    def _build(self, gid: bytes, intent: dict[str, Any]) -> dict[str, Any]:
        t = intent["type"]
        if t == "update":
            return self.client.update(gid)
        if t == "proposals":
            return self.client.commit_pending_proposals(gid)
        if t == "remove":
            return self.client.remove(gid, intent["identity"])
        if t == "policy":
            return self.client.set_policy(gid, canonical(intent["policy"]))
        if t == "knock_add":
            return self.knocks.build_add(gid, intent)
        if t == "add":
            approval = self.store.approval(intent["request_id"])
            invite = None if approval is None else self.store.invite(approval["invite_id"])
            obj = None if invite is None else self._invite_object(invite)
            if approval is None or obj is None:
                msg = "approval or invite no longer available"
                raise DaemonError("gone", msg)
            verified = self.client.verify_join_request(unb64(approval["request"]), obj)
            return self.client.add_member(gid, verified, obj)
        msg = f"unknown commit intent {t}"
        raise DaemonError("bad_intent", msg)

    async def _cadence_update(
        self, row: OutboxRow, payload: dict[str, Any], group: GroupRow
    ) -> GroupRow:
        """Run the cadence Update before an application send. The commit has
        its own outbox row (remembered in the app row) so a reconnect or a
        restart resumes the same commit instead of building a second one."""
        seq = payload.get("update_row")
        if seq is None:
            seq = self.store.enqueue(
                "commit", group.group_id, {"intent": {"type": "update"}}, self.now()
            )
            payload["update_row"] = seq
            self.store.update_outbox(row.seq, payload=payload)
        update = self.store.outbox_row(int(seq))
        if update is not None and update.state == "queued":
            state = await self._run_commit(update, group)
            self.store.update_outbox(update.seq, state=state)
        payload.pop("update_row", None)
        self.store.update_outbox(row.seq, payload=payload)
        return self.store.group(group.group_id) or group

    async def _run_commit(self, row: OutboxRow, group: GroupRow) -> str:
        gid = unb64(group.group_id)
        payload = dict(row.payload)
        intent = payload["intent"]
        backoff = Backoff(base=1.0, cap=60.0, rng=self.options.backoff_rng)
        for _ in range(MAX_COMMIT_ATTEMPTS):
            current = self.store.group(group.group_id)
            if current is None or current.status != "active" or current.out_of_sync:
                self._fail_codes[row.seq] = "out_of_sync"
                return "failed"
            if "env" not in payload and not self._build_commit(row, group, payload):
                return "failed"
            env = payload["env"]
            if not payload.get("confirmed") and self._own_commit_landed(env):
                # A crash came after the relay accepted it (ADR-004): finish
                # it from the journal instead of sending it again.
                await self._confirm_own(gid, group.group_id, env)
                payload["confirmed"] = True
                self.store.update_outbox(row.seq, payload=payload)
            if not payload.get("confirmed"):
                try:
                    await self._request({"t": "send", "env": env}, str(env["msg_id"]))
                except RelayError as e:
                    if e.code in RETRYABLE_RELAY_ERRORS:
                        # SPEC 8.3: resend the same bytes under the same
                        # msg_id; the relay didn't take it (a rejected send
                        # doesn't consume its msg_id).
                        LOG.info("commit_retry", code=e.code)
                        await self._sleep(backoff.next())
                        continue
                    with contextlib.suppress(ac.AgentConnectError):
                        self.client.discard_pending_commit(gid)
                    built_epoch = int(env["epoch"])
                    payload.pop("env")
                    payload.pop("welcome", None)
                    self.store.update_outbox(row.seq, payload=payload)
                    if e.code != "epoch_conflict":
                        LOG.info("commit_rejected", code=e.code)
                        self._fail_codes[row.seq] = e.code
                        self._fail_intent(intent, e.code)
                        return "failed"
                    LOG.info("epoch_conflict", group=log.hid(group.group_id))
                    await self._await_epoch(group.group_id, built_epoch)
                    continue
                await self._confirm_own(gid, group.group_id, env)
                payload["confirmed"] = True
                self.store.update_outbox(row.seq, payload=payload)
            if not payload.get("consume_queued"):
                await self._commit_followups(row, group, intent, payload)
            return "done"
        if "env" in payload and not payload.get("confirmed"):
            # Still unconfirmed after every attempt: give it up.
            with contextlib.suppress(ac.AgentConnectError):
                self.client.discard_pending_commit(gid)
        self._fail_codes[row.seq] = "attempts_exhausted"
        self._fail_intent(intent, "attempts_exhausted")
        return "failed"

    def _own_commit_landed(self, env: dict[str, Any]) -> bool:
        """Whether this own commit was already confirmed (finished, or
        journalled by the core and not yet finished)."""
        msg_id = str(env["msg_id"])
        if self.store.inbox_state(self.mailbox, msg_id) is not None:
            return True
        key = journal_key(self.mailbox, msg_id)
        return any(e["key"] == key for e in self.client.journal_pending())

    async def _confirm_own(self, gid: bytes, group_id: str, env: dict[str, Any]) -> None:
        """Merge an own commit the relay accepted, journalled under the key
        its fan-out copy is processed under, so whichever comes first
        confirms it and the other finds it done (ADR-004)."""
        msg_id = str(env["msg_id"])
        if self.store.inbox_state(self.mailbox, msg_id) is not None:
            self._settle_recorded(env)
            return
        self.failpoints.hit("confirm.before_core")
        try:
            summary = self.client.confirm_pending_commit(
                gid,
                msg_id,
                key=journal_key(self.mailbox, msg_id),
                context=journal_context(env, from_relay=False),
            )
        except (ac.AgentConnectError, ac.CoreError) as e:
            if _core_error(e) == "transient":
                raise TransientError(group_id, type(e).__name__) from None
            # Merged from the fan-out copy and finished there already.
            LOG.info("own_commit_already_merged", reason=str(e)[:60])
            return
        self.failpoints.hit("confirm.after_core")
        await self._finish(
            env, {**summary, "type": "own_commit_confirmed"}, from_relay=False, path="confirm"
        )

    def _build_commit(self, row: OutboxRow, group: GroupRow, payload: dict[str, Any]) -> bool:
        """Build the row's commit and persist it (envelope, Welcome) before
        it is sent, so a restart resends the same bytes."""
        intent = payload["intent"]
        try:
            out = self._build(unb64(group.group_id), intent)
        except (ac.AgentConnectError, DaemonError) as e:
            benign = "no pending proposals" in str(e)
            if not benign:
                LOG.info("commit_not_built", intent=intent["type"], reason=str(e)[:80])
            self._fail_codes[row.seq] = BENIGN if benign else "not_built"
            self._fail_intent(intent, "not_built")
            return False
        payload["env"] = {
            "v": 0,
            "kind": "commit",
            "group_id": group.group_id,
            "epoch": out["epoch"],
            "msg_id": out["msg_id"],
            "sender": self.mailbox,
            "routing": out["routing"],
            "ct": b64(out["commit"]),
        }
        if out.get("welcome") is not None:
            payload["welcome"] = b64(out["welcome"])
        self.store.update_outbox(row.seq, payload=payload)
        return True

    async def _await_epoch(self, group_id: str, built_epoch: int) -> None:
        """Wait until the winning commit has been processed (or give up after
        a while and let the caller rebuild anyway)."""

        def moved() -> bool:
            g = self.store.group(group_id)
            return g is None or g.status != "active" or g.out_of_sync or g.epoch > built_epoch

        if moved():
            return
        waiter = asyncio.ensure_future(self.wait_until(moved, within=REBUILD_WAIT_SECS * 10))
        timer = asyncio.ensure_future(self._sleep(REBUILD_WAIT_SECS))
        try:
            await asyncio.wait({waiter, timer}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # Our own cancellation, here or in the wait, still propagates.
            await cancel_and_wait(waiter, timer, ignore=(TimeoutError,))

    def _fail_intent(self, intent: dict[str, Any], code: str = "failed") -> None:
        if intent["type"] == "add":
            self.store.set_approval_status(intent["request_id"], "failed")
        elif intent["type"] == "knock_add":
            self.knocks.add_failed(str(intent["request_id"]), code)

    async def _commit_followups(
        self, row: OutboxRow, group: GroupRow, intent: dict[str, Any], payload: dict[str, Any]
    ) -> None:
        """After an Add is confirmed: send the Welcome, then consume the
        invite. Each step is recorded in the row, so a retry after a dropped
        connection neither sends a second Welcome nor consumes a second use.
        An approved knock's Add has a Welcome and no use to consume."""
        if intent["type"] == "knock_add":
            await self.knocks.after_add(row.seq, group, intent, payload)
            return
        if intent["type"] != "add":
            return
        approval = self.store.approval(intent["request_id"])
        if approval is None:
            return
        if "welcome" in payload and not payload.get("welcome_sent"):
            if "welcome_msg_id" not in payload:
                payload["welcome_msg_id"] = new_msg_id()
                self.store.update_outbox(row.seq, payload=payload)
            welcome = {
                "v": 0,
                "kind": "welcome_wrapped",
                "group_id": group.group_id,
                "msg_id": payload["welcome_msg_id"],
                "sender": self.mailbox,
                "to": [approval["mailbox_id"]],
                "ct": payload["welcome"],
            }
            await self._request({"t": "send", "env": welcome}, str(welcome["msg_id"]))
            payload["welcome_sent"] = True
            self.store.update_outbox(row.seq, payload=payload)
        self.store.set_approval_status(intent["request_id"], "approved")
        self.store.set_display_name(group.group_id, approval["identity"], approval["display_name"])
        consume_id = new_msg_id()
        with self.store.tx():
            self.store.enqueue(
                "frame",
                None,
                {
                    "frame": {
                        "t": "invite.consume",
                        "invite_id": approval["invite_id"],
                        "msg_id": consume_id,
                    },
                    "msg_id": consume_id,
                },
                self.now(),
            )
            payload["consume_queued"] = True
            self.store.update_outbox(row.seq, payload=payload)
        self._outbox_wake.set()

    async def _send_card(self, group_id: str, to: list[str]) -> None:
        adapter = self._adapter_for(group_id)
        card = adapter.capabilities().agent_card if adapter is not None else None
        if card is not None and convert.parse_card(card) is None:
            LOG.warning("own_card_refused", code="malformed")
            return
        if card is not None:
            try:
                self.send_message(group_id, card, to=to, kind="a2a.agent_card", internal=True)
            except DaemonError as e:
                # Over a card cap (agentconnect.schemas): fix the agent's card.
                LOG.warning("own_card_refused", code=e.code)

    # -- operations (local API and adapters) --------------------------------

    def _group_or_raise(self, group_id: str) -> GroupRow:
        group = self.store.group(group_id)
        if group is None or group.status != "active":
            raise DaemonError("not_found", "no such active group")
        return group

    def create_group(self, name: str, purpose: str) -> str:
        try:
            gid = self.client.create_group(name, purpose)
        except ac.AgentConnectError as e:
            raise DaemonError("bad_request", str(e)) from None
        group_id = gid_b64(gid)
        now = self.now()
        self.store.add_group(
            GroupRow(
                group_id,
                name,
                purpose,
                {},
                self.config.default_adapter,
                "active",
                False,
                None,
                0,
                now,
                now,
                0,
            )
        )
        self._refresh(group_id)
        self.store.set_display_name(group_id, self.me, self.config.display_name)
        msg_id = new_msg_id()
        self._enqueue(
            "frame",
            None,
            {
                "frame": {"t": "group.create", "group_id": group_id, "epoch": 0, "msg_id": msg_id},
                "msg_id": msg_id,
            },
        )
        LOG.info("group_created", group=log.hid(group_id))
        return group_id

    async def create_invite(
        self,
        group_id: str,
        ttl_secs: int = 86_400,
        max_uses: int = 1,
        inviter_name: str | None = None,
    ) -> dict[str, Any]:
        group = self._group_or_raise(group_id)
        policy = group.policy
        allowed = {
            "owner": {policy.get("owner")},
            "admins": {policy.get("owner"), *policy.get("admins", [])},
        }.get(str(policy.get("invite")))
        if allowed is not None and self.me not in allowed:
            raise DaemonError("forbidden", "the group policy does not let this identity invite")
        invite = self.client.create_invite(self.config.relay_host, ttl_secs)
        members = len(self.client.members(unb64(group_id)))
        meta = {
            "invite_id": invite.invite_id_b64,
            "group_name": group.name,
            "inviter_name": inviter_name or self.config.display_name,
            "purpose": group.purpose,
            "expires_at": invite.expires_at,
            "max_uses": max_uses,
            "member_count": members,
            "protocol": 0,
        }
        invite_id = invite.invite_id_b64
        # Recorded before the relay hears of it (ADR-004): after a crash
        # mid-registration the row says so, and the next connect revokes
        # the invite and drops its secret instead of orphaning them.
        self.store.add_invite(
            invite_id, group_id, invite.expires_at, max_uses, self.now(), status="registering"
        )
        # The secret stays local; only public metadata goes to the relay.
        self.keystore.put(f"invite/{invite_id}", invite.secret_bytes())
        self._registering.add(invite_id)
        try:
            await self.rest.create_invite(meta)
            self.failpoints.hit("invite.after_register")
            self.store.set_invite_status(invite_id, "open")
        except Exception as e:
            # Never leave a secret for an invite we don't track. (A crash or
            # a cancellation leaves the row "registering" for the sweep.)
            self.store.delete_invite(invite_id)
            self.keystore.delete(f"invite/{invite_id}")
            if isinstance(e, RelayError):
                raise DaemonError("relay", f"invite registration failed: {e.code}") from None
            raise
        finally:
            self._registering.discard(invite_id)
        return {
            "url": invite.url,
            "invite_id": invite.invite_id_b64,
            "expires_at": invite.expires_at,
        }

    async def revoke_invite(self, invite_id: str) -> None:
        if self.store.invite(invite_id) is None:
            raise DaemonError("not_found", "no such invite")
        await self.rest.revoke_invite(invite_id)
        self.store.set_invite_status(invite_id, "revoked")
        self.keystore.delete(f"invite/{invite_id}")

    def _link(self, url: str) -> ac.InviteLink:
        try:
            link = ac.parse_invite_url(url)
        except ac.AgentConnectError as e:
            raise DaemonError("bad_request", str(e)) from None
        if not _same_relay(link.relay_host, self.config.relay_host):
            raise DaemonError("wrong_relay", "the invite is for a different relay")
        return link

    async def inspect_invite(self, url: str) -> dict[str, Any]:
        """Parse the URL locally and fetch the public metadata (§6.1)."""
        link = self._link(url)
        try:
            meta = await self.rest.invite_meta(link.invite_id_b64)
        except RelayError as e:
            raise DaemonError(
                "invite_not_open", INVITE_WARNING if e.code == "invite_not_open" else str(e)
            ) from None
        warning = INVITE_WARNING if meta.get("status") in ("exhausted", "revoked") else None
        return {"meta": meta, "warning": warning, "untrusted": True}

    async def accept_invite(self, url: str, display_name: str | None = None) -> dict[str, Any]:
        """Send the JoinRequest; the Welcome is processed when it arrives."""
        link = self._link(url)
        info = await self.inspect_invite(url)
        meta = info["meta"]
        if meta.get("status") != "open":
            raise DaemonError("invite_not_open", info["warning"] or "invite is not open")
        name = display_name or self.config.display_name
        try:
            request = self.client.create_join_request(link, name)
        except ac.AgentConnectError as e:
            raise DaemonError("bad_request", str(e)) from None
        invite_id = link.invite_id_b64
        self.keystore.put(f"join/{invite_id}", url.encode())
        self.store.add_join(invite_id, meta, name, self.now())
        msg_id = new_msg_id()
        env = {
            "v": 0,
            "kind": "join_request",
            "msg_id": msg_id,
            "sender": self.mailbox,
            "ct": b64(request),
        }
        self._enqueue(
            "frame",
            None,
            {"frame": {"t": "join", "invite_id": invite_id, "env": env}, "msg_id": msg_id},
        )
        return {"invite_id": invite_id, "status": "pending", "meta": meta}

    def approvals(self) -> list[dict[str, Any]]:
        """**Human-only.** Join requests (``kind: join``), then knocks
        (``kind: knock``), waiting for the human's decision."""
        return self.join_approvals() + self.knocks.approvals()

    def join_approvals(self) -> list[dict[str, Any]]:
        out = []
        for a in self.store.approvals():
            if self.now() - a["received_at"] > APPROVAL_TIMEOUT_SECS:
                self.store.set_approval_status(a["request_id"], "expired")
                continue
            out.append(
                {
                    k: a[k]
                    for k in ("request_id", "group_id", "identity", "display_name", "received_at")
                }
                | {
                    "kind": "join",
                    "display_name_verified": False,
                    "fingerprint": ac.fingerprint(ac_identity_key(a["identity"])),
                }
            )
        return out

    def _invite_closed(self, invite: dict[str, Any]) -> bool:
        """No uses left (counting approvals already under way) or expired."""
        return bool(
            str(invite["status"]) != "open"
            or self.now() >= int(invite["expires_at"])
            or self.store.uses_taken(str(invite["invite_id"])) >= int(invite["max_uses"])
        )

    def approve(self, request_id: str, purpose: str | None = None) -> dict[str, Any]:
        """**Human-only** (the local API's human-token route): approve a join
        request, or a knock (``purpose`` is for knocks only: the new
        group's scope)."""
        if self.store.knock_request(request_id) is not None:
            return self.knocks.approve(request_id, purpose)
        if purpose is not None:
            raise DaemonError("bad_request", "purpose is for knocks only")
        self._approve_join(request_id)
        return {"status": "approving"}

    def reject(self, request_id: str) -> dict[str, Any]:
        """**Human-only.** Reject a join request or a knock. Neither peer is told."""
        if self.store.knock_request(request_id) is not None:
            return self.knocks.reject(request_id)
        approval = self.store.approval(request_id)
        if approval is None or approval["status"] != "pending":
            raise DaemonError("not_found", "no such pending request")
        self.store.set_approval_status(request_id, "rejected")
        return {"status": "rejected"}

    def _approve_join(self, request_id: str) -> None:
        """Human-gated (or ``policy.auto_approve``): commit the Add for a
        verified JoinRequest.

        Each approval reserves one of the invite's uses before its Add is
        queued (SPEC 6.2 step 1), so a single-use link admits one joiner even
        when two redemptions arrive together. A failed Add releases it.
        """
        # Synchronous on the event loop: the check and the reservation can't
        # interleave with another approval.
        approval = self.store.approval(request_id)
        if approval is None or approval["status"] != "pending":
            raise DaemonError("not_found", "no such pending request")
        if self.now() - approval["received_at"] > APPROVAL_TIMEOUT_SECS:
            self.store.set_approval_status(request_id, "expired")
            raise DaemonError("expired", "the approval window (1 hour) has passed")
        invite = self.store.invite(approval["invite_id"])
        if invite is None or self._invite_closed(invite):
            self.store.set_approval_status(request_id, "rejected")
            raise DaemonError("invite_not_open", "the invite has no uses left or expired")
        self.store.set_approval_status(request_id, "approving")
        self._enqueue(
            "commit", approval["group_id"], {"intent": {"type": "add", "request_id": request_id}}
        )

    def inner(  # noqa: PLR0913
        self,
        kind: str,
        body: dict[str, Any],
        to: list[str],
        *,
        origin: str = "agent",
        hop: int = 0,
        reply_to: list[str] | None = None,
        addressee: list[str] | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "v": 0,
            "seq": self.store.next_seq(),
            "sender": self.me,
            "instance_id": self.instance.instance_id_hex,
            "to": to,
            "hop": hop,
            "origin": origin,
            "kind": kind,
            "body": body,
        }
        if reply_to is not None and len(reply_to) > 0:
            out["reply_to"] = reply_to
        if addressee is not None:
            out["addressee"] = addressee
        return out

    def send_message(  # noqa: PLR0913
        self,
        group_id: str,
        body: dict[str, Any],
        *,
        to: list[str] | None = None,
        kind: str = "a2a.message",
        origin: str = "agent",
        reply_to: list[str] | None = None,
        internal: bool = False,
        addressee: list[str] | None = None,
    ) -> str:
        """Queue an application message (:meth:`queue_message`); returns its
        ``msg_id``, also when the policy holds it for approval."""
        return self.queue_message(
            group_id,
            body,
            to=to,
            kind=kind,
            origin=origin,
            reply_to=reply_to,
            internal=internal,
            addressee=addressee,
        )[0]

    def queue_message(  # noqa: PLR0913
        self,
        group_id: str,
        body: dict[str, Any],
        *,
        to: list[str] | None = None,
        kind: str = "a2a.message",
        origin: str = "agent",
        reply_to: list[str] | None = None,
        internal: bool = False,
        addressee: list[str] | None = None,
    ) -> tuple[str, str]:
        """Queue an application message; returns ``(msg_id, status)`` where
        ``status`` is ``queued``, or ``held`` when the group's
        ``require_approval`` holds it for the human. ``hop`` is computed here
        (SPEC 10.3): 0 for the human's own messages, otherwise see
        :meth:`_reply_hop`.

        The safety policy applies (:meth:`SafetyPolicy.outbound`): SPEC 10.2
        by default allows at most 256 KiB, ``text``/``data`` parts only, and
        30 messages a minute from this sender (120 in the group); task
        updates have their own budget (300 a minute per task). The daemon's
        own messages (``internal``: Agent Cards, loop-guard pauses) don't
        count against the rate and are never held.

        ``addressee`` (SPEC 9.3): with ``to: ["*"]`` every member sees the
        message, and only the members listed are triggered."""
        group = self._group_or_raise(group_id)
        if addressee is not None and not (
            _str_list(addressee) and 0 < len(addressee) <= MAX_ADDRESSEE
        ):
            raise DaemonError("bad_request", f"addressee must list 1 to {MAX_ADDRESSEE} members")
        if kind not in KNOWN_KINDS:
            raise DaemonError("bad_request", "unknown message kind")
        if origin not in ("agent", "human"):
            raise DaemonError("bad_request", "origin must be agent or human")
        if kind in HUMAN_ONLY_KINDS and origin != "human":
            raise DaemonError("forbidden", f"{kind} must come from the human")
        if origin == "human":
            hop, refs = 0, list(reply_to or [])[:MAX_REPLY_TO]
        else:
            hop, refs = self._reply_hop(group.group_id, reply_to)
        # A control or cancel goes out in its schema's shape only. A card goes
        # out exactly as built (a signature covers it): it must already fit.
        shaped = normalize(kind, body)
        if shaped is not None and kind != "a2a.agent_card":
            body = shaped
        inner = self.inner(
            kind, body, to or ["*"], origin=origin, hop=hop, reply_to=refs, addressee=addressee
        )
        size = len(canonical(inner))
        decision = self.safety.outbound(
            Outbound(
                group.group_id,
                self.me,
                self.instance.instance_id_hex,
                inner,
                size,
                internal=internal,
            )
        )
        if decision.verdict is Verdict.DROP:
            self.safety.audit(
                group.group_id,
                "out",
                sender=self.me,
                msg_id="",
                kind=kind,
                size=size,
                decision=decision.verdict,
                reason=decision.reason,
            )
            code, text = OUTBOUND_PROBLEMS.get(decision.reason, ("bad_request", "malformed"))
            raise DaemonError(code, text)
        msg_id = new_msg_id()
        payload = {"inner": inner, "msg_id": msg_id}
        with self.store.tx():
            self.store.record_hop(group.group_id, msg_id, hop, self.now())
            self.safety.audit(
                group.group_id,
                "out",
                sender=self.me,
                msg_id=msg_id,
                kind=kind,
                size=size,
                decision=decision.verdict,
                reason=decision.reason,
            )
            held = decision.verdict is Verdict.HOLD_FOR_APPROVAL
            events: list[Event] = []
            if held:
                events = self._hold_outbound(group, payload, size)
            else:
                self._enqueue("app", group.group_id, payload)
                self.safety.transcribe(group.group_id, "out", self.me, msg_id, inner)
        if held:
            self._notify_soon(events)
            return msg_id, "held"
        if kind in HUMAN_ONLY_KINDS:
            self._reset_loop_guard(group.group_id)
        return msg_id, "queued"

    async def adapter_send(  # noqa: PLR0913
        self,
        group_id: str,
        body: dict[str, Any],
        to: list[str] | None = None,
        kind: str = "a2a.message",
        reply_to: list[str] | None = None,
        *,
        addressee: list[str] | None = None,
    ) -> SendReceipt:
        """What adapters get through ``on_outbound``: agent-originated only.
        A group the agent can't see yet (``hidden_from_agent``) is not found.
        ``reply_to`` names the ``msg_id``s of the deliveries this answers;
        ``addressee`` names who is triggered (SPEC 9.3). The answer is the
        ``msg_id``, a :class:`SendReceipt` whose ``held`` says the group's
        ``require_approval`` holds the message for the human."""
        if self.hidden_from_agent(group_id):
            raise DaemonError("not_found", "no such active group")
        msg_id, status = self.queue_message(
            group_id,
            body,
            to=to,
            kind=kind,
            origin="agent",
            reply_to=reply_to,
            addressee=addressee,
        )
        if status != "held":
            return SendReceipt(msg_id)
        hold_id = self._hold_id(group_id, "out", msg_id)
        return SendReceipt(
            msg_id, held=True, hold_id=hold_id, withdraw=lambda: self.withdraw_send(hold_id)
        )

    async def withdraw_send(self, hold_id: str) -> None:
        """The adapter takes back a held send (its request was cancelled): the
        hold is rejected and audited, and the send fails with ``cancelled``.
        Nothing happens to one the human already decided."""
        item = self.store.held(hold_id)
        if item is None or item["status"] != "pending" or item["direction"] != "out":
            return
        for event in self._drop_hold(item, "cancelled", "cancelled"):
            await self._notify(event)

    def update(self, group_id: str) -> None:
        group = self._group_or_raise(group_id)
        self._enqueue("commit", group.group_id, {"intent": {"type": "update"}})

    def remove_member(self, group_id: str, identity: str) -> None:
        group = self._group_or_raise(group_id)
        self._enqueue(
            "commit", group.group_id, {"intent": {"type": "remove", "identity": identity}}
        )

    def set_policy(self, group_id: str, **changes: Any) -> None:
        """Commit a policy change (the core checks this instance's role)."""
        group = self._group_or_raise(group_id)
        policy = {**group.policy, **changes}
        self._enqueue("commit", group.group_id, {"intent": {"type": "policy", "policy": policy}})

    async def leave(self, group_id: str) -> str:
        group = self._group_or_raise(group_id)
        members = self.store.members(group_id)
        if len(members) == 1 and len(members[0].instances) == 1:
            await self._gone(group_id, "left")  # sole member: just delete (§9.2)
            return "left"
        mine = next((m for m in members if m.identity == self.me), None)
        if group.policy.get("owner") == self.me and mine is not None and len(mine.instances) == 1:
            raise DaemonError("forbidden", "transfer ownership before leaving (SPEC 9.2)")
        self._leaving.add(group_id)
        self.store.kv_set(f"leaving/{group_id}", "1")
        self._enqueue("proposal", group_id, {})
        return "leaving"

    def mark_verified(self, group_id: str, identity: str, verified: bool = True) -> None:
        """**Human-only.** Records that the human compared the SAS with this
        member over an independent channel. Never reachable by agents: an
        agent that could mark verification would defeat the SAS check, which
        exists precisely to catch a relay or link thief in the middle."""
        self._group_or_raise(group_id)
        if identity == self.me or not self.store.set_verified(group_id, identity, verified):
            raise DaemonError("not_found", "no such member")
        self._delivery_wake.set()
        self._pulse()

    async def sas_mismatch(self, group_id: str, epoch: int | None = None) -> str:
        """**Human-only.** The human compared the SAS of the current epoch and
        the codes differ (SPEC 11): the group view may be forked. Leave at
        once and raise ``sas_mismatch``.

        * The owner's last instance first makes a best-effort ownership
          transfer (SPEC 9.2): a policy commit naming the lowest-index admin,
          or else the lowest-index other member, sent and awaited for at most
          :data:`TRANSFER_TIMEOUT_SECS`. If the relay confirms it, this
          instance is now a plain member and proposes its own removal.
        * Anyone else sends a leave proposal when one is allowed.
        * A sole member just deletes.

        The local group state is deleted in every case, since nothing more
        from this view can be trusted. ``epoch`` guards against answering
        for a code from an earlier epoch."""
        group = self._group_or_raise(group_id)
        gid = unb64(group_id)
        current = self._core_epoch(gid)
        if epoch is not None and epoch != current:
            msg = f"the SAS shown was for epoch {epoch}; the group is at epoch {current}"
            raise DaemonError("stale_epoch", msg)
        sas = self._sas(gid)
        transfer: dict[str, Any] | None = None
        if self._is_last_owner_instance(group):
            transfer = await self._transfer_ownership(group)
        if transfer is None or transfer["confirmed"]:
            self._propose_own_leave(group)
        await self._gone(group_id, "left")
        self.store.update_group(group_id, out_of_sync=True, out_of_sync_reason="sas_mismatch")
        data: dict[str, Any] = {"epoch": current, "sas": sas}
        if transfer is not None:
            data["transfer"] = transfer
        await self.emit(group_id, "sas_mismatch", **data)
        return "left"

    def _is_last_owner_instance(self, group: GroupRow) -> bool:
        if group.policy.get("owner") != self.me:
            return False
        mine = [m for m in self.client.members(unb64(group.group_id)) if m["identity"] == self.me]
        return len(mine) == 1

    def _next_owner(self, group: GroupRow) -> str | None:
        """The lowest-index admin, else the lowest-index other member."""
        members = sorted(
            (m for m in self.client.members(unb64(group.group_id)) if m["identity"] != self.me),
            key=lambda m: m["leaf_index"],
        )
        admins = set(group.policy.get("admins", []))
        for m in members:
            if m["identity"] in admins:
                return str(m["identity"])
        return str(members[0]["identity"]) if members else None

    async def _transfer_ownership(self, group: GroupRow) -> dict[str, Any] | None:
        """Commit ``owner = next owner`` and wait (bounded) for the relay.
        ``None`` for a sole member; otherwise who and whether it landed."""
        new_owner = self._next_owner(group)
        if new_owner is None:
            return None
        gid = unb64(group.group_id)
        policy = {**json.loads(self.client.policy(gid)), "owner": new_owner}
        policy["admins"] = [a for a in policy.get("admins", []) if a != new_owner]
        result: dict[str, Any] = {"new_owner": new_owner, "confirmed": False}
        try:
            out = self.client.set_policy(gid, canonical(policy))
        except (ac.AgentConnectError, ac.CoreError) as e:
            LOG.info("ownership_transfer_not_built", reason=str(e)[:60])
            return result
        env = {
            "v": 0,
            "kind": "commit",
            "group_id": group.group_id,
            "epoch": out["epoch"],
            "msg_id": out["msg_id"],
            "sender": self.mailbox,
            "routing": out["routing"],
            "ct": b64(out["commit"]),
        }
        send = asyncio.ensure_future(self._request({"t": "send", "env": env}, out["msg_id"]))
        timer = asyncio.ensure_future(self._sleep(TRANSFER_TIMEOUT_SECS))
        try:
            await asyncio.wait({send, timer}, return_when=asyncio.FIRST_COMPLETED)
        except BaseException:
            await cancel_and_wait(send, timer, ignore=(Exception,))
            raise
        timer.cancel()
        if send.done() and not send.cancelled() and send.exception() is None:
            # Accepted; the fan-out echo may already have merged it.
            with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                self.client.confirm_pending_commit(gid, str(out["msg_id"]))
        try:
            confirmed = json.loads(self.client.policy(gid)).get("owner") == new_owner
        except (ac.AgentConnectError, ac.CoreError, ValueError):
            confirmed = False
        # Stops the send if it is still waiting; a cancellation of this task
        # meanwhile propagates (a restart discards the unsent commit, §8.3).
        await cancel_and_wait(send, timer, ignore=(Exception,))
        if not confirmed:
            with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
                self.client.discard_pending_commit(gid)
        result["confirmed"] = confirmed
        LOG.info("ownership_transfer", confirmed=confirmed)
        return result

    def _propose_own_leave(self, group: GroupRow) -> None:
        """Queue a self-Remove proposal when SPEC 9.2 allows one."""
        gid = unb64(group.group_id)
        try:
            proposal = self.client.propose_leave(gid)
        except (ac.AgentConnectError, ac.CoreError) as e:
            LOG.info("sas_mismatch_no_proposal", reason=str(e)[:60])
            return
        msg_id = new_msg_id()
        env = {
            "v": 0,
            "kind": "proposal",
            "group_id": group.group_id,
            "epoch": self._core_epoch(gid),
            "msg_id": msg_id,
            "sender": self.mailbox,
            "ct": b64(proposal),
        }
        self._enqueue("frame", None, {"frame": {"t": "send", "env": env}, "msg_id": msg_id})

    def group_info(self, group_id: str) -> dict[str, Any]:
        group = self.store.group(group_id)
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
            "trust_state": self._trust_state(group_id),
            "members": [
                {
                    "identity": m.identity,
                    "fingerprint": ac.fingerprint(ac_identity_key(m.identity)),
                    "display_name": m.display_name,
                    "display_name_verified": False,
                    "role": m.role,
                    "verified": m.verified,
                    "instances": m.instances,
                    "self": m.identity == self.me,
                }
                for m in self.store.members(group_id)
            ],
            # SPEC 10.1: peer-supplied, so framed as untrusted.
            "agent_cards": {
                identity: {"untrusted": True, "card": card}
                for identity, card in self.store.cards(group_id).items()
            },
        }
        if group.status == "active":
            info["sas"] = self._sas(unb64(group_id))
        self._knock_origin(group_id, info)
        return info

    def _knock_origin(self, group_id: str, info: dict[str, Any]) -> None:
        """A group that started from a knock says so: ``origin`` on both
        sides, and on the knocker's side ``listed_as`` on the member the
        listing named (its listing, not a verification: SPEC 6.6.5, 11)."""
        peer = self.store.listed_peer(group_id)
        group = self.store.group(group_id)
        if peer is not None:
            info["origin"] = {"kind": "knock", "directory": peer["directory"], "name": peer["name"]}
            for m in info["members"]:
                if m["identity"] == peer["identity"]:
                    m["listed_as"] = {
                        "directory": peer["directory"],
                        "name": peer["name"],
                        "owner_domain": peer["owner_domain"],
                        "owner_state": peer["owner_state"],
                    }
        elif group is not None and group.origin is not None:
            info["origin"] = dict(group.origin)

    def list_groups(self) -> list[dict[str, Any]]:
        return [
            {
                "group_id": g.group_id,
                "name": g.name,
                "status": g.status,
                "epoch": g.epoch,
                "members": len(self.store.members(g.group_id)),
                "out_of_sync": g.out_of_sync,
            }
            for g in self.store.groups()
        ]

    def status(self, *, human: bool = True) -> dict[str, Any]:
        """The runtime's status. ``pending_approvals`` counts knocks only for
        the human (the agent doesn't learn of incoming knocks)."""
        groups = self.store.groups()
        pending = self.approvals() if human else self.join_approvals()
        return {
            "identity": self.me,
            "fingerprint": self.identity.fingerprint,
            "instance_id": self.instance.instance_id_hex,
            "mailbox_id": self.mailbox,
            "relay": {"url": self.config.relay_url, "connected": self.link.connected},
            "keystore": self.keystore.kind,
            "groups": len([g for g in groups if g.status == "active"]),
            "out_of_sync": [g.group_id for g in groups if g.out_of_sync],
            "outbox_queued": len(self.store.outbox()),
            "inbox_pending": len(self.store.pending_deliveries()),
            "pending_approvals": len(pending),
            "held_messages": len(self.held_messages()),
        }


def ac_identity_key(identity: str) -> bytes:
    """IK.pub from an ``ac:v0:`` identifier."""
    return unb64(identity.removeprefix("ac:v0:"))
