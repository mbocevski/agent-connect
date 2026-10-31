"""``agentconnectd``: identity, MLS state, relay link, queues and adapters.

Three workers run on one event loop:

* **inbound**: takes relay frames in order, runs them through the core and
  records the outcome in the inbox (dedup by ``(sender, msg_id)``);
* **outbox**: sends queued work in order (group creation, joins,
  application messages, commits, proposals, Welcomes). Rows of one group
  go out in the order they were queued, so local commits are serialised.
  A row the relay refuses for now (``internal``, ``over_budget``, a
  Welcome's ``quota_exceeded``) waits out a backoff and holds up only its
  own group (``Engine._next_row``); ``rate_limited`` (the mailbox's send
  rate) and ``storage_full`` (the relay's storage) are shared by every
  group, so they pause the whole outbox. Two waits still
  hold up every group: a commit that lost an epoch conflict waits in its
  row for the winning commit (``Engine._await_epoch``, up to
  ``REBUILD_WAIT_SECS``), and a request the relay doesn't answer waits
  ``relay.REQUEST_TIMEOUT`` before the link is treated as down;
* **delivery**: hands pending inbox rows to each adapter of their group, with
  a marker per adapter (the relay frame was acked once the row was recorded).

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
import re
import secrets
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Generator, Iterable
from dataclasses import dataclass, replace
from typing import Any

import httpx
import keyring.errors

import agentconnect_core as ac
from agentconnect import log
from agentconnect.a2a_adapter import cards, convert
from agentconnect.adapter import (
    Adapter,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    OutboundSend,
    Sender,
    SendReceipt,
)
from agentconnect.backoff import Backoff
from agentconnect.clock import Clock, SystemClock, unix_seconds
from agentconnect.config import JOIN_FAILURE_WINDOW_SECS, Config
from agentconnect.failpoints import FailpointError, Failpoints, SimulatedCrash
from agentconnect.identity import (
    Seeded,
    load_db_key,
    load_identity,
    load_instance,
    open_core_client,
)
from agentconnect.keystore import (
    DataDirLock,
    Keystore,
    KeystoreError,
    KeystoreNameError,
    open_keystore,
)
from agentconnect.limits import (
    DRAIN_RATE_MULTIPLE,
    KNOWN_KINDS,
    MAX_PAYLOAD_DEPTH,
    MAX_TASK_ID,
    TASK_UPDATE_KINDS,
    U32_MAX,
    DrainBudget,
    inner_problem,
    loads,
    parse_inner,
    valid_hop,
)
from agentconnect.policy import (
    HUMAN_ONLY_KINDS,
    TERMINAL_STATES,
    Decision,
    Inbound,
    Outbound,
    PolicyError,
    SafetyPolicy,
    Verdict,
    acts_on,
    drop,
    task_of,
    task_state,
    verification_holds,
)
from agentconnect.relay import (
    CAUGHT_UP,
    DRAIN_KEY,
    NotConnectedError,
    RelayError,
    RelayLink,
    RelayRest,
    b64,
    unb64,
)
from agentconnect.runtime import ledger as replay
from agentconnect.runtime.registry import AdapterRegistry
from agentconnect.runtime.sas import (
    PROPOSAL_PENDING,
    SAS_EVENTS,
    SAS_KINDS,
    SasError,
    SasService,
)
from agentconnect.schemas import normalize
from agentconnect.store import GROUP_ADAPTERS_KEY, SAS_RESET_NOTICE, GroupRow, OutboxRow, Store
from agentconnect.tasks import cancel_and_wait

LOG = log.get("agentconnect.engine")

UPDATE_AFTER_SECS = 24 * 3600  # SPEC §3.1 update cadence
UPDATE_AFTER_MESSAGES = 1000
APPROVAL_TIMEOUT_SECS = 3600  # SPEC §6.2 step 4
# Join requests claiming one identity that wait per invite (docs/groups.md).
MAX_PENDING_PER_IDENTITY = 4
JOIN_IDENTITY_FULL = "join_identity_full"
JOIN_FAILURES = "join_failures"
# An instance id as SPEC 3.3 writes it: the 64-bit id, 16 lowercase hex.
INSTANCE_ID = re.compile(r"^[0-9a-f]{16}$")
INSTANCE_ID_RULE = "must be an instance id: 16 lowercase hex characters"
# The kinds an instance hint (SPEC 9.4) can narrow: the ones that trigger.
# Controls and cards never trigger, and their bodies keep only their schema.
HINTED_KINDS = frozenset({"a2a.message", "a2a.task_status", "a2a.task_artifact", "a2a.task_cancel"})


def instance_hex(instance_id: int) -> str:
    """A 64-bit instance id as 16 lowercase hex characters (SPEC 3.3)."""
    return f"{instance_id:016x}"


JOIN_CLOSED_GRACE_SECS = 60
# The last Welcome to a joiner goes out this long before it stops waiting
# (its invite's expiry plus JOIN_CLOSED_GRACE_SECS), so it still arrives.
WELCOME_MARGIN_SECS = 30
# The relay's send window per mailbox (relay.rs: sends_per_sec over 1 s).
RATE_WINDOW_SECS = 1.0
MAX_PARKED_GROUPS = 8
MAX_PARKED_PER_GROUP = 256
MAX_REPLY_TO = 16  # SPEC 7.2
MAX_ADDRESSEE = 50  # SPEC 7.2: at most the group size
HOP_MEMORY_SECS = 7 * 24 * 3600
# Give-ups of one message (a frame or a journal entry) whose failure is
# retried, counted across reconnects and restarts: past this it fails alone.
MAX_ENTRY_ATTEMPTS = 8
# Events kept at most, newest first (and daemon.event_retention_days).
MAX_EVENT_ROWS = 100_000
RETENTION_EVERY_SECS = 60  # how often the event and attempt tables are trimmed
DAY_SECS = 86_400
# (group, sender) pairs whose message_failed events are coalesced, at most.
MAX_FAILED_TRACKED = 10_000
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
# Where a group's deliveries stand (docs/config.md, "Several adapters"):
# the human's, like the policy's own events.
DELIVERY_EVENTS = frozenset(
    {"adapter_unavailable", "adapter_available", "delivery_stalled", "delivery_resumed"}
)
HUMAN_EVENTS = (
    frozenset(
        {
            "message_held",
            "held_expired",
            "repeated_violations",
            "message_failed",
            "invite_flooded",
            "join_ledger_full",
            # SPEC 7.3: leaving is the human's decision. The agent gets the
            # close itself, through the delivery gates (require_verified
            # included), never its reason ahead of them (SR-34).
            "close_requested",
        }
    )
    | KNOCK_OWNER_EVENTS
    # SPEC 11.5: a code, a run's progress and a held commitment are the
    # human's, by event type.
    | SAS_EVENTS
    | DELIVERY_EVENTS
)
VERIFICATIONS_RESET = (
    "This version derives the short code from a comparison run between two daemons "
    "(SPEC 11). Earlier verifications used a code an attacker in the middle could choose, "
    "so every member is unverified again: run `agentconnect verify <group> <member>` with "
    "each of them."
)
# A group's pending messages past which the relay is no longer acked early, so its
# mailbox fills as it did before (SPEC 8.3: 64 MiB, 7 days).
PENDING_MAX_BYTES = 64 << 20
PENDING_MAX_AGE_SECS = 7 * 86_400
HELD_KEY = "delivery/unavailable"  # groups whose listed adapters don't run
STALLED_KEY = "delivery/stalled"  # groups past their pending limits
# A flood of join requests on one of the human's invites (SPEC 6.2
# "Replays"): the human's to act on, by revoking the invite.
INVITE_FLOOD_WARNING = (
    "This invite gets more join requests than it can hold, and new ones are "
    "dropped. If you didn't expect that many, the link may have leaked: revoke "
    "it with `agentconnect invite revoke <invite_id>`."
)
JOIN_FAILURES_WARNING = (
    "{limit} join requests for this invite failed within {minutes} minutes: a wrong "
    "invite MAC, or a request sent from a mailbox other than the one it names. They "
    "were dropped; requests that pass the checks still reach you. Someone may be "
    "probing the invite, or forging requests with a leaked link: if you didn't expect "
    "that, revoke it with `agentconnect invite revoke <invite_id>`."
)
# The message of a JoinRequest from another sender (SPEC 6.2 step 3).
SENDER_MISMATCH = "credential mismatch: sender is not the request's mailbox_id"
IDENTITY_FLOOD_WARNING = (
    "More than {limit} requests claim identity {identity} on this invite, and new ones are "
    "dropped. Some may be replayed: anyone who saw one of its KeyPackages (in a join "
    "request or a knock it sent them) can send one in its name, so its own request may be "
    "one of those dropped. Verify before approving: ask the person which request is "
    "theirs, and compare the short code once they join."
)
JOIN_LEDGER_FULL_WARNING = (
    "The join ledger is full, so new join requests for every invite are "
    "dropped. Revoke the invites you no longer need: that frees their entries."
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


class RateLimitedError(TransientError):
    """The relay answered a send ``rate_limited``. Its send budget is per
    mailbox, shared by every group, so the whole outbox pauses for one
    shared backoff (``Engine._outbox``) and the row isn't charged a try."""


MAX_TRANSIENT_RETRIES = 8
# Relay answers that pause the whole outbox (SPEC 8.4): the mailbox's send
# rate, and the relay's storage at its high-water mark. Neither counts as a
# try: the same frame goes again after the shared backoff, however long.
PAUSE_RELAY_ERRORS = frozenset({"rate_limited", "storage_full"})
# The sender's budget of undelivered messages (in all, or the group's
# share): only the row's own lane waits, uncounted, until recipients have
# fetched enough (SPEC 8.3, "Limits").
WAIT_RELAY_ERRORS = frozenset({"over_budget"})
# Relay errors that say "not now" rather than "no" (SPEC 8.4).
RETRYABLE_RELAY_ERRORS = PAUSE_RELAY_ERRORS | WAIT_RELAY_ERRORS | {"internal"}
# Answers to a Welcome that say "not now": it is sent again, as a knock's is.
RETRY_WELCOME = RETRYABLE_RELAY_ERRORS | {"quota_exceeded"}
WELCOME_NOT_SENT = "welcome_not_sent"
BENIGN = "benign"  # a failed outbox row nobody needs to hear about
# Commit intents that change the policy, each built against the policy in
# force when it is built (agentconnect.runtime.groups.planned_policy).
POLICY_INTENTS = frozenset({"policy", "owner", "role", "drop_roles"})
UNCHANGED = "unchanged"  # a policy change the policy already has
GROUP_FULL = "group_full"  # an approval whose Add would pass max_members
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
    """What a core failure means for the message, by the error's kind: a
    panic (``CoreError``) and storage, key, randomness or internal failures
    say nothing about the message itself (``transient``)."""
    kind = getattr(e, "kind", "other")
    if isinstance(e, ac.CoreError) or kind == "transient":
        return "transient"
    if kind in ("own_commit_lost", "duplicate"):
        return str(kind)
    if kind == "unauthorized":
        return "unauthorized_commit"
    return "rejected"


# What a peer answers with task updates (SPEC 9.3): a message, which may
# start or continue a task, and a cancel, which the canceled status answers.
REQUEST_KINDS = frozenset({"a2a.message", "a2a.task_cancel"})


def _request_task(kind: str, body: dict[str, Any]) -> str | None:
    """The task an own request names: a follow-up's ``taskId``, a cancel's
    ``id``; ``None`` for a new request."""
    task = body.get("id" if kind == "a2a.task_cancel" else "taskId")
    return task if isinstance(task, str) and 0 < len(task) <= MAX_TASK_ID else None


def _named(inner: dict[str, Any]) -> list[str]:
    """The identities a message names: its ``addressee``, else its ``to``
    unless that is ``["*"]``."""
    addressee, to = inner.get("addressee"), inner.get("to")
    if isinstance(addressee, list):
        return [str(a) for a in addressee]
    if isinstance(to, list) and "*" not in to:
        return [str(t) for t in to]
    return []


def _refs(inner: dict[str, Any]) -> list[str]:
    """The ``reply_to`` entries the runtime reads (SPEC 7.2: at most 16)."""
    refs = inner.get("reply_to")
    return [r for r in refs[:MAX_REPLY_TO] if isinstance(r, str)] if isinstance(refs, list) else []


def _retry_reason(e: BaseException) -> tuple[str | None, str]:
    """The group and reason a retried failure is reported with."""
    if isinstance(e, TransientError):
        return e.group_id, e.reason
    if isinstance(e, FailpointError):
        return None, "failpoint"
    return None, type(e).__name__


class RetriesExhausted(Exception):  # noqa: N818 - the reason a human reads
    """A message whose handling never finished in
    :data:`MAX_ENTRY_ATTEMPTS` tries (each crashed the process, or gave up):
    it fails alone without another."""


def _waits_unbounded(e: BaseException) -> bool:
    """Whether a failure is the local secret store being locked or
    unavailable (an OS keyring nobody unlocked yet). It says nothing about
    the message and waiting loses nothing, so the message is retried for as
    long as it takes and never fails alone for it. A secret name the store
    refuses is the message's (it came from the message)."""
    if isinstance(e, KeystoreNameError):
        return False
    return isinstance(e, KeystoreError | keyring.errors.KeyringError)


def _deletion_deferred(e: BaseException) -> bool:
    """Whether a failed secret deletion is the keystore's state (locked,
    unavailable, a failing disk) and is tried again later, rather than a
    bug (a name the keystore refuses, a bad argument), which is raised."""
    if isinstance(e, KeystoreNameError):
        return False
    return isinstance(e, KeystoreError | keyring.errors.KeyringError | OSError)


def _transient(e: BaseException) -> bool:
    """Whether a failure handling a frame may pass if the same frame is
    tried again: it comes from local state or a connection, not from the
    message. That is an injected or flagged transient failure, a lost
    connection or the network, the OS (files, memory), a locked or
    unavailable keystore (:func:`_waits_unbounded`), a relay answer that
    says "not now", or a core or storage failure of the transient kind.
    Any other failure would repeat on every try, so the message fails alone
    (``Engine._fail_message``)."""
    transient = (
        TransientError,
        FailpointError,
        OSError,
        TimeoutError,
        MemoryError,
        httpx.TransportError,
    )
    if isinstance(e, transient) or _waits_unbounded(e):
        return True
    if isinstance(e, RelayError):
        return e.code in RETRYABLE_RELAY_ERRORS
    if isinstance(e, ac.AgentConnectError | ac.CoreError):
        return _core_error(e) == "transient"
    return False


KNOCK_REQUEST_PREFIX = "kn-"  # knock request ids, 19 characters (agentconnect.runtime.knocks)
ENVELOPE_KINDS = frozenset(
    {"commit", "proposal", "application", "welcome_wrapped", "join_request", "knock"}
)
MAX_ID_LEN = 64
ID16_CHARS = 22  # 16 bytes, base64url without padding: a door_id, a join's msg_id
GROUP_FIELDS = ("group_id", "epoch", "to", "routing")  # never on a knock (SPEC 7.1)
# The last signed relay request's ts (RelayRest), kept across restarts.
REST_TS_KEY = "relay/rest_ts"
# An internal frame: finish every pending journal entry (ADR-004).
REPLAY_JOURNAL = "_replay_journal"
SUMMARY_REPORTS_LEAVES = "left_reported"
# Since when a Welcome waits for a locked keystore (Engine._welcome_waiting).
WELCOME_WAITING = "welcome_waiting"
# Secrets a locked keystore kept from being deleted (Engine._forget_secret).
KEPT_SECRETS = "secrets/kept"
TransientFailure = (TransientError, FailpointError)


@dataclass
class Postponed:
    """An outbox row that failed for now: it runs again at ``at`` (Unix
    seconds on the daemon clock), and its group's later rows wait for it."""

    at: float
    backoff: Backoff


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
        # Written with a core whose summaries report leaves (`left`); an
        # entry without it may hold an older summary, whose `left` is empty.
        SUMMARY_REPORTS_LEAVES: True,
    }
    if invite_id is not None:
        ctx["invite_id"] = invite_id
    if knock_id is not None:
        ctx["knock_id"] = knock_id
    return canonical(ctx)


def _id16(value: Any) -> bool:
    """SPEC 7.1: canonical base64url of 16 bytes."""
    if not isinstance(value, str) or len(value) != ID16_CHARS:
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
        if not _id16(env.get("door_id")):
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


def _join_request_invite(raw: bytes) -> str | None:
    """The ``invite_id`` a JoinRequest names, read without trusting it: JSON
    nested past the bound, or an id that isn't ASCII, is ``None``."""
    try:
        invite_id = loads(raw, MAX_PAYLOAD_DEPTH)["invite_id"]
    except (ValueError, KeyError, TypeError):
        return None
    return invite_id if isinstance(invite_id, str) and invite_id.isascii() else None


def _encodable(value: Any) -> bool:
    """Whether ``value`` can be written out as UTF-8 JSON, as every adapter
    writes a delivery (a lone surrogate can't)."""
    try:
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        return False
    return True


def _same_relay(a: str, b: str) -> bool:
    """SPEC 4.4/8.1.1: compare relay hosts in canonical form."""
    try:
        return ac.canonical_relay_host(a) == ac.canonical_relay_host(b)
    except ac.AgentConnectError:
        return False


def _ceremony_inner(event: dict[str, Any]) -> dict[str, Any] | None:
    """The inner message of a received SAS ceremony message (SPEC 11.2),
    within the SPEC 7.2 bounds: one outside them is malformed, dropped like
    any other message and never acted on."""
    plaintext = event.get("plaintext")
    inner = parse_inner(plaintext) if isinstance(plaintext, bytes | str) else None
    if inner is None or inner.get("kind") not in SAS_KINDS or inner_problem(inner) is not None:
        return None
    return inner


def _floor_inner(event: dict[str, Any]) -> dict[str, Any] | None:
    """A received application event's inner message if it is a
    ``control.floor`` within the SPEC 7.2 bounds (one outside them is
    malformed and moves nothing)."""
    inner = parse_inner(event["plaintext"])
    if inner is None or inner.get("kind") != "control.floor" or inner_problem(inner) is not None:
        return None
    return inner


def _max_turns(policy: dict[str, Any]) -> int:
    guard = policy.get("loop_guard")
    turns = guard.get("max_agent_turns") if isinstance(guard, dict) else None
    return turns if isinstance(turns, int) and not isinstance(turns, bool) else 20


def addressed_to_me(  # noqa: PLR0913, PLR0917
    floor: str,
    inner: dict[str, Any],
    me: str,
    my_instance: str,
    moderator: str | None,
    holder: str | None = None,
) -> bool:
    """SPEC §9.3/§9.4: is this instance *triggered* by ``inner``?

    ``moderator`` is the effective moderator and ``holder`` the floor
    holder (``agentconnect.runtime.floor``); only ``moderated`` reads them.

    ``body.metadata.instance`` is the sender's word: it is read only after
    the floor has picked this member, so it can narrow who is triggered and
    never widen it. A value that isn't this instance's id, malformed ones
    included, leaves this instance untriggered."""
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
    else:  # moderated: the effective moderator and the floor holder
        hit = me in (moderator, holder)
    if not hit:
        return False
    body = inner.get("body")
    metadata = body.get("metadata") if isinstance(body, dict) else None
    target = metadata.get("instance") if isinstance(metadata, dict) else None
    return target in (None, my_instance)


def with_instance(kind: str, body: dict[str, Any], instance: str | None) -> dict[str, Any]:
    """``body`` with the instance hint ``instance`` (SPEC 9.4) as
    ``metadata.instance``, which replaces any the body had; ``metadata`` is
    created when absent. Without ``instance``, a hint the body already
    carries must be well formed too. The body is not changed in place.

    The hint names one instance of the identities the message triggers. It
    is checked for shape only: the instance may have left, or not have
    joined yet in this runtime's view, and the receivers decide."""
    metadata = body.get("metadata")
    if instance is None:
        hint = metadata.get("instance") if isinstance(metadata, dict) else None
        if kind in HINTED_KINDS and hint is not None and not _instance_id(hint):
            raise DaemonError("bad_request", f"body.metadata.instance {INSTANCE_ID_RULE}")
        return body
    if not _instance_id(instance):
        raise DaemonError("bad_request", f"instance {INSTANCE_ID_RULE}")
    if kind not in HINTED_KINDS:
        msg = f"an instance hint goes on {', '.join(sorted(HINTED_KINDS))} only"
        raise DaemonError("bad_request", msg)
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise DaemonError("bad_request", "body.metadata must be an object")
    return {**body, "metadata": {**metadata, "instance": instance}}


def _instance_id(value: object) -> bool:
    return isinstance(value, str) and INSTANCE_ID.fullmatch(value) is not None


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

    def _open(self, keystore: Keystore | None) -> None:  # noqa: PLR0915 - one attribute each
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
        # Outbox rows waiting out a backoff, by seq (_postpone).
        self._postponed: dict[int, Postponed] = {}
        # The relay's "not now" answers to each row's own send, by seq
        # (_refused_for_now): what MAX_COMMIT_ATTEMPTS counts.
        self._refusals: dict[int, int] = {}
        # rate_limited pauses the whole outbox until then (Unix seconds).
        self._throttle = Backoff(base=1.0, cap=60.0, rng=self.options.backoff_rng)
        self._throttled_until = 0.0
        self._delivery_wake = asyncio.Event()
        self._changed = asyncio.Event()
        self._parked: dict[str, list[dict[str, Any]]] = {}
        # Parked frames released by a join, handled after its Welcome, each
        # as a frame of its own.
        self._followups: deque[dict[str, Any]] = deque()
        # The journal entry a replay stopped at, when it is retried.
        self._replaying: dict[str, Any] | None = None
        # The messages whose handling this frame counted already (_count).
        self._counted: set[str] = set()
        # message_failed per (group, sender): when the last one went out and
        # the failures since (_failed_report).
        self._failed: OrderedDict[tuple[str, str], tuple[int, int]] = OrderedDict()
        self._trimmed_at = -RETENTION_EVERY_SECS
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
        # Pinned card-signing keys (SPEC 10.5), checked on every received card.
        self._card_keys = cards.load_jwks(config.a2a_card_keys_file)
        self._held_wake = asyncio.Event()
        self._fail_codes: dict[int, str] = {}
        self._unregistered: set[str] = set()  # listed adapters warned about
        self._background: set[asyncio.Task[None]] = set()
        self._event_wake = asyncio.Event()
        # Where each (group, adapter) delivery worker got to (a seq), and the
        # adapter list each group's rows were last settled for.
        self._cursors: dict[tuple[str, str], int] = {}
        # Bumped when an older row of the group becomes pending (an approved
        # hold): a worker mid-delivery then doesn't move its cursor past it.
        self._cursor_gen: dict[str, int] = {}
        self._settled: dict[tuple[str, str | None], tuple[str, ...]] = {}
        self._drain_frame = False
        self._drain = DrainBudget()
        # The relay connection (RelayLink.connections) whose reconnect drain
        # the inbound worker has handled: until then the view may be stale.
        self._caught_up = 0
        # The connection during which the inbound worker last gave a frame up:
        # the view misses it until the relay redelivers it, so only a later
        # connection's drain can be caught up.
        self._gave_up = 0
        self.running = False
        self._closed = False
        from agentconnect.runtime.floor import FloorService  # noqa: PLC0415 - import cycle
        from agentconnect.runtime.groups import GroupService  # noqa: PLC0415 - import cycle
        from agentconnect.runtime.knocks import KnockService  # noqa: PLC0415 - import cycle
        from agentconnect.runtime.listing import ListingManager  # noqa: PLC0415 - import cycle

        # Membership: member state, commits' events, leaves and removals (docs/groups.md).
        self.groups = GroupService(self)
        # Floor control in moderated groups: the holder and its grants (SPEC 9.3).
        self.floor = FloorService(self)
        # The listing, its doors and the discovery worker (docs/discovery.md).
        self.listings = ListingManager(self)
        # Knocks, both sides: the owner's ledger and approvals, the knocker's knocks.
        self.knocks = KnockService(self)
        # SAS runs: the commit-then-reveal exchange behind the short code (SPEC 11).
        self.sas = SasService(self)
        # The inviter's JoinRequest replay ledger (SPEC 6.2, "Replays").
        self._join_capacity = ac.DEFAULT_LEDGER_CAPACITY
        self._join_ledger = self._load_join_ledger()
        # When each invite's recent failed requests arrived (SPEC 6.2 steps 2
        # and 3), and when the human was last told of them; in memory, so a
        # restart starts the window again.
        self._join_failures: dict[str, deque[int]] = {}
        self._join_failures_told: dict[str, tuple[int, int]] = {}

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
        self._migrate_group_adapters()
        self.store.settle_unseen_events()
        held = [g.group_id for g in self.store.groups() if g.status == "active"]
        self._notify_soon([e for group_id in held for e in self._check_held(group_id)])
        # First thing the inbound worker does: finish what a crash left in
        # the core's journal.
        self._frames.put_nowait({"t": REPLAY_JOURNAL})
        loop = asyncio.get_running_loop()
        workers: dict[str, Callable[[], Awaitable[None]]] = {
            "inbound": self._inbound,
            "outbox": self._outbox,
            "delivery": self._delivery,
            "events": self._events,
            "held_timer": self._held_timer,
            "discovery": self.listings.run,
            "knock_timer": self.knocks.run,
            "group_timer": self.groups.run,
            "sas_timer": self.sas.run,
            "relay_link": self.link.run,
        }
        for name, worker in workers.items():
            self._tasks.append(loop.create_task(self._supervised(name, worker)))
        for adapter in self.adapters.values():
            bind = getattr(adapter, "bind_store", None)
            if bind is not None:
                bind(self.store)  # optional hook: adapters that keep a durable feed
            bind_clock = getattr(adapter, "bind_clock", None)
            if bind_clock is not None:
                bind_clock(self.clock)  # optional hook: adapters that stamp what they keep
            await adapter.on_outbound(self._outbound_for(adapter.name))
        self.running = True
        if bool(self.store.kv_get(SAS_RESET_NOTICE)):
            # SPEC 11.8: tell the human, once, why its members are unverified.
            await self.emit(None, "verifications_reset", reason=VERIFICATIONS_RESET)
            self.store.kv_set(SAS_RESET_NOTICE, "")
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
            self.groups.recover(group)
        # Own floor grants a crash left pending although their send is over;
        # their events are recorded, and the renotify after the replay tells them.
        self.floor.reconcile()
        # A join recorded as done whose secret a crash left in the keystore.
        self._forget_join_secrets()
        # SAS runs don't survive a restart: their queued messages never go out.
        self.sas.recover()

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

    def caught_up(self) -> bool:
        """Whether this runtime's view is as current as the relay can make
        it: connected, the reconnect drain handled with no frame given up
        (during it or since), the journal replayed."""
        return (
            self.link.connected
            and self._caught_up == self.link.connections
            and not self.client.journal_pending()
        )

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
        # Pending leaves this instance should commit, after a restart too.
        self.groups.wake()
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
            self._forget_secret(f"invite/{invite_id}")

    async def _on_frame(self, frame: dict[str, Any]) -> None:
        await self._frames.put(frame)

    # -- events -------------------------------------------------------------

    def _view(self, group_id: str) -> GroupView | None:
        g = self.store.group(group_id)
        if g is None:
            return None
        return GroupView(
            g.group_id,
            g.name,
            g.purpose,
            g.epoch,
            str(g.policy.get("floor", "free")),
            self.floor.holder(g.group_id),
        )

    def listed_adapters(self, group_id: str | None) -> list[str]:
        """The group's adapter list as written: its pinned one, else the
        config's (``daemon.adapters``)."""
        if group_id is not None:
            g = self.store.group(group_id)
            if g is not None and g.adapters is not None:
                return list(g.adapters)
        return list(self.config.adapter_names)

    def adapter_names(self, group_id: str | None) -> list[str]:
        """The adapters the group delivers to, by name, in order: those of
        its list this runtime runs. A listed adapter it doesn't run is
        skipped with a warning. With none of them running the group is held
        (nothing; :meth:`unavailable`), never sent elsewhere. Only a list
        that names nothing (``default_adapter = "none"``) means the first
        adapter registered."""
        names = self.listed_adapters(group_id)
        found = [n for n in names if n in self.adapters]
        for name in set(names) - set(found) - self._unregistered:
            self._unregistered.add(name)
            LOG.warning("adapter_not_registered", adapter=name)
        if found or names:
            return found
        first = self.adapters.first()
        return [] if first is None else [first.name]

    def unavailable(self, group_id: str | None) -> list[str] | None:
        """The group's listed adapters when none of them runs (its messages
        and events wait for them), else ``None``."""
        names = self.listed_adapters(group_id)
        if names and not any(n in self.adapters for n in names):
            return names
        return None

    def targets(self, group_id: str | None) -> list[Adapter]:
        """The adapters the group delivers its messages and events to."""
        return [self.adapters[n] for n in self.adapter_names(group_id)]

    def _triggered_adapter(self, group_id: str, delivery: Delivery) -> str | None:
        """Which of the group's adapters a message that triggers is for:
        the one that sent the message it replies to, else the first that
        answers (Capabilities.answers). The others get it as context, so
        two answering adapters don't both reply."""
        names = self.adapter_names(group_id)
        refs = _refs(delivery.inner)
        task = task_of(delivery.inner)
        if task is not None:
            # A task update is for the adapter whose request granted it
            # (SPEC 9.3), not whichever sent another message it names.
            granted = self.store.granting_request(group_id, refs, delivery.sender.identity, task)
            refs = [] if granted is None else [granted]
        for msg_id in refs:
            via = self.store.sent_via(group_id, msg_id)
            if via in names:
                return via
        answering = [n for n in names if self.adapters[n].capabilities().answers]
        return answering[0] if answering else None

    def _outbound_for(self, name: str) -> OutboundSend:
        """The send an adapter gets: :meth:`adapter_send`, remembering that
        this adapter sent the message (so a reply to it triggers this one)."""

        async def send(  # noqa: PLR0913
            group_id: str,
            body: dict[str, Any],
            to: list[str] | None = None,
            kind: str = "a2a.message",
            reply_to: list[str] | None = None,
            *,
            addressee: list[str] | None = None,
            instance: str | None = None,
        ) -> SendReceipt:
            receipt = await self.adapter_send(
                group_id,
                body,
                to,
                kind,
                reply_to,
                addressee=addressee,
                instance=instance,
            )
            self.store.record_sent_via(group_id, str(receipt), name, self.now())
            return receipt

        return send

    def _migrate_group_adapters(self) -> None:
        """Once, on a database from before per-group adapter lists: a group
        stayed on the adapter it was bound to at creation while that adapter
        ran (ADR-005). It follows the config now only when that is what the
        config gives it; otherwise it is pinned to that adapter."""
        if self.store.kv_get(GROUP_ADAPTERS_KEY) != "pending":
            return
        follow = self.adapter_names(None)
        with self.store.tx():
            for g in self.store.groups():
                old = g.adapter
                if g.adapters is not None or old in ("", "none") or follow == [old]:
                    continue
                self.store.set_group_adapters(g.group_id, [old])
                LOG.warning("group_adapter_pinned", group=log.hid(g.group_id), adapter=old)
            self.store.kv_set(GROUP_ADAPTERS_KEY, "done")

    def _flagged(self, key: str) -> dict[str, Any]:
        raw = self.store.kv_get(key)
        return {} if raw is None else dict(json.loads(raw))

    def _check_held(self, group_id: str) -> list[Event]:
        """Tell the human, once each way, when none of the group's listed
        adapters runs (``adapter_unavailable``) and when one does again
        (``adapter_available``)."""
        held = self._flagged(HELD_KEY)
        names = self.unavailable(group_id)
        was = held.get(group_id)
        if (names is None) == (was is None):
            return []
        if names is None:
            held.pop(group_id)
            kind, data = "adapter_available", {"adapters": self.adapter_names(group_id)}
        else:
            held[group_id] = names
            kind, data = "adapter_unavailable", {"adapters": names}
            LOG.warning("group_delivery_held", group=log.hid(group_id))
        with self.store.tx():
            self.store.kv_set(HELD_KEY, json.dumps(held))
            event = self._record(group_id, kind, f"{kind}/{self.now()}/{len(held)}", data)
        return [] if event is None else [event]

    def _pending_over(self, group_id: str) -> bool:
        size, oldest = self.store.pending_load(group_id)
        return size > PENDING_MAX_BYTES or (
            oldest is not None and self.now() - oldest > PENDING_MAX_AGE_SECS
        )

    def _check_stalled(self, group_id: str) -> tuple[list[Event], list[str]]:
        """Past its pending limits a group's messages are no longer acked
        early (``delivery_stalled``, naming the adapters behind); below
        them again, what waited is acked (``delivery_resumed``). Returns the
        events and the msg_ids to ack now."""
        stalled = self._flagged(STALLED_KEY)
        over = self._pending_over(group_id)
        if over == (group_id in stalled):
            return [], []
        size, oldest = self.store.pending_load(group_id)
        if over:
            # Behind: the adapters that haven't taken the oldest pending row.
            oldest_row = self.store.pending_deliveries(group_id, limit=1)
            behind = [
                n
                for n in self.adapter_names(group_id)
                if oldest_row and not self.store.delivered_to(oldest_row[0].seq, n)
            ]
            stalled[group_id] = behind
            kind = "delivery_stalled"
            data: dict[str, Any] = {"adapters": behind, "bytes": size, "since": oldest}
            acks: list[str] = []
            LOG.warning("group_delivery_stalled", group=log.hid(group_id))
        else:
            data = {"adapters": stalled.pop(group_id)}
            kind = "delivery_resumed"
            acks = self.store.take_unacked(group_id, pending_too=True)
        with self.store.tx():
            self.store.kv_set(STALLED_KEY, json.dumps(stalled))
            event = self._record(group_id, kind, f"{kind}/{self.now()}/{len(stalled)}", data)
        return ([] if event is None else [event]), acks

    async def _release(self, group_id: str) -> None:
        """A row of the group is done, or an adapter of it waited out a
        backoff: ack what the relay kept for rows that are done, and see
        where the group stands against its pending limits."""
        events, acks = self._check_stalled(group_id)
        acks += self.store.take_unacked(group_id)
        for msg_id in acks:
            await self._ack(msg_id)
        self._notify_soon(events)

    def set_adapters(self, group_id: str, names: list[str] | None) -> dict[str, Any]:
        """**Human-only.** Pin the adapters a group delivers to (``None``:
        follow the config). Each must be an adapter of this runtime, once."""
        group = self._group_or_raise(group_id)
        if names is not None:
            if not names or not all(isinstance(n, str) for n in names):
                raise DaemonError("bad_request", "adapters must list adapter names, or be null")
            for name in names:
                if name not in self.adapters:
                    have = ", ".join(self.adapters) or "none"
                    msg = f"{name} is not an adapter of this runtime (it has: {have})"
                    raise DaemonError("bad_request", msg)
                if names.count(name) > 1:
                    raise DaemonError("bad_request", f"{name} is listed more than once")
        self.store.set_group_adapters(group.group_id, None if names is None else list(names))
        LOG.info("group_adapters_set", group=log.hid(group.group_id), pinned=names is not None)
        self._notify_soon(self._check_held(group.group_id))
        self._delivery_wake.set()
        self._event_wake.set()
        return {
            "group_id": group.group_id,
            "adapters": names,
            "delivers_to": self.adapter_names(group.group_id),
        }

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
        if agent:
            # The events worker runs once this code yields, after the
            # transaction (which never spans an await) has committed; also
            # when what follows the commit fails before notifying.
            self._event_wake.set()
        return Event(kind, group_id, data, event_id)

    def _notify_soon(self, events: list[Event]) -> None:
        """Tell the adapters about recorded events from synchronous code.
        They are durable already: the events worker hands them over."""
        for event in events:
            self._queue_event(event)

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
        """Hand a recorded event to its group's adapters (the events worker
        tells each one, in order, from a worker of its own)."""
        self._queue_event(event)

    def _queue_event(self, event: Event) -> None:
        # The policy's own events are for the human only: an agent that
        # heard of a hold could tell the sender (SPEC 10.2). So are the
        # knocks and an approved knock's group until the knocker is in.
        if event.type in HUMAN_EVENTS or not self.store.agent_visible(event.event_id):
            self.store.mark_notified(event.event_id)
            self._pulse()
            return
        self._event_wake.set()

    async def _renotify(self) -> None:
        """Hand over again every recorded event an adapter has not accepted
        (a crash between recording and notifying, or a failing adapter)."""
        self._event_wake.set()

    async def _events(self) -> None:
        """Tell the adapters about recorded events: one worker per group and
        adapter with events it hasn't accepted, so an adapter that is slow or
        never returns holds up only its own events in that group, never the
        inbound worker or another adapter. Order is kept per adapter."""
        workers: dict[tuple[str | None, str], asyncio.Task[None]] = {}
        woken = True
        try:
            while True:
                for key, worker in list(workers.items()):
                    if worker.done():
                        del workers[key]
                        if worker.cancelled():
                            LOG.error("event_worker_died", reason="CancelledError")
                            woken = True
                        else:
                            worker.result()
                if woken:
                    self._event_wake.clear()
                    self._start_event_workers(workers)
                wake = asyncio.ensure_future(self._event_wake.wait())
                try:
                    done, _ = await asyncio.wait(
                        {wake, *workers.values()}, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    wake.cancel()
                woken = wake in done
        finally:
            await cancel_and_wait(*workers.values(), ignore=(Exception, SimulatedCrash))

    def _start_event_workers(
        self, workers: dict[tuple[str | None, str], asyncio.Task[None]]
    ) -> None:
        for group_id in self.store.unnotified_groups():
            names = self.adapter_names(group_id)
            if not names and self.unavailable(group_id) is not None:
                continue  # held: they wait for the group's adapters
            if self._settled.get(("events", group_id)) != tuple(names):
                self._settled["events", group_id] = tuple(names)
                if self.store.settle_events(group_id, names):
                    self._pulse()
            for name in names:
                if (group_id, name) not in workers:
                    workers[group_id, name] = asyncio.ensure_future(
                        self._notify_group(group_id, self.adapters[name])
                    )

    async def _notify_group(self, group_id: str | None, adapter: Adapter) -> None:
        """One group's events for one adapter, in order, until it has them
        all; a failure waits out this group and adapter's backoff."""
        backoff = Backoff(base=1.0, cap=300.0, rng=self.options.backoff_rng)
        while True:
            rows = self.store.unnotified_for(group_id, adapter.name)
            if not rows:
                return
            failed = False
            for row in rows:
                names = self.adapter_names(group_id)
                if adapter.name not in names:
                    return
                event = Event(row["type"], row["group_id"], row["data"], str(row["event_id"]))
                if event.type in HUMAN_EVENTS:
                    # Recorded notified already; never an adapter's (SPEC 10.2).
                    self.store.mark_notified(event.event_id)
                    continue
                view = None if group_id is None else self._view(group_id)
                try:
                    self.failpoints.hit("event.after_record")
                    await adapter.on_event(view, event)
                    self.failpoints.hit("event.after_notify")
                except Exception:
                    LOG.warning("adapter_event_failed", type=event.type, adapter=adapter.name)
                    failed = True
                    break
                with self.store.tx():
                    self.store.mark_event(event.event_id, adapter.name)
                    if all(self.store.event_marked(event.event_id, n) for n in names):
                        self.store.mark_notified(event.event_id)
                backoff.reset()
                self._pulse()
            if failed:
                await self._sleep(backoff.next())

    async def mark_out_of_sync(self, group_id: str, reason: str, **data: Any) -> None:
        self.store.update_group(group_id, out_of_sync=True, out_of_sync_reason=reason)
        await self.emit(group_id, "out_of_sync", reason=reason, **data)

    async def on_group_refused(self, group_id: str, code: str) -> None:
        """The relay refused a send to a group this instance is in.

        - ``unknown_group``: the relay doesn't hold the group. It deleted it
          after the idle period, or never registered it (SPEC 8.3, "Idle
          groups"). It can't be resumed there, so the group goes out of sync
          and the human hears of it. Nothing rejoins or re-creates it: the
          humans start a new group.
        - ``not_member``: the relay's group doesn't have this instance,
          though the MLS group does. Someone registered the id again after
          the relay deleted the group, or the relay misbehaves (or a commit
          removing this instance is still on its way). The human hears of
          it, once per epoch; the group stays as it is."""
        group = self.store.group(group_id)
        if group is None or group.status != "active" or group.out_of_sync:
            return
        if code == "unknown_group":
            LOG.warning("group_unknown_at_relay", group=log.hid(group_id))
            await self.mark_out_of_sync(group_id, "unknown_group")
        elif code == "not_member":
            LOG.warning("not_member_at_relay", group=log.hid(group_id))
            await self.emit(
                group_id,
                "relay_misbehaviour",
                cause=f"not_member/{group_id}/{group.epoch}",
                reason="not_member",
            )

    async def on_group_create_refused(self, group_id: str, code: str) -> None:
        """The relay refused to register a group this instance created
        (``quota_exceeded`` at its limits, or any other definitive refusal).
        The group exists only here:
        it goes out of sync with reason ``not_created`` and the refusal's
        code, which tells the human, and takes no invites. It is not
        reported as a group the relay deleted. (``rate_limited`` and
        ``internal`` are tried again first; a repeat the relay already took
        is answered ``accepted``.)"""
        group = self.store.group(group_id)
        if group is None or group.out_of_sync:
            return
        LOG.warning("group_not_created", group=log.hid(group_id), code=code)
        await self.mark_out_of_sync(group_id, "not_created", code=code)

    # -- group state ----------------------------------------------------------

    def _refresh(self, group_id: str) -> None:
        """Re-read members, roles, policy and epoch from the core."""
        self.groups.refresh(group_id)
        self.floor.ensure(group_id)

    def _core_epoch(self, gid: bytes) -> int:
        try:
            return int(self.client.epoch(gid))
        except (ac.AgentConnectError, ac.CoreError):
            return 0

    def _trust_state(self, group_id: str) -> dict[str, Any]:
        return self.groups.trust_state(group_id)

    def _display_name(self, group_id: str, identity: str) -> str | None:
        for m in self.store.members(group_id):
            if m.identity == identity:
                return m.display_name
        return None

    # -- inbound --------------------------------------------------------------

    async def _inbound(self) -> None:
        backoff = Backoff(base=1.0, cap=300.0, rng=self.options.backoff_rng)
        while True:
            frame = await self._frames.get()
            # SPEC 8.2/10.2: messages queued while we were away are exempt
            # from the per-minute rates (bounded per connection).
            self._drain_frame = bool(frame.pop(DRAIN_KEY, False))
            # Before the frame and outside its failure handling: a failure
            # here is no message's, so it fails none.
            await self._housekeeping()
            await self._process_frame(frame, backoff)
            while self._followups:
                await self._process_frame(
                    {"t": "deliver", "env": self._followups.popleft()}, backoff
                )
            self._pulse()

    async def _process_frame(self, frame: dict[str, Any], backoff: Backoff) -> None:
        """Handle one frame. A failure the frame itself would cause on every
        try fails its message alone (SPEC 7.2). One that may pass is retried
        in place, then given up for now (the relay redelivers it after a
        reconnect, and a journal entry is replayed).

        Each handling of a message is counted before it starts, in a write
        of its own, and the count goes once it is handled: a message that
        crashes the process is counted too. Past :data:`MAX_ENTRY_ATTEMPTS`
        handlings, counted across restarts, it fails alone. A locked or
        unavailable keystore (:func:`_waits_unbounded`) is never counted: it
        says nothing about the message, and waiting loses nothing."""
        self._counted = set()
        key = self._frame_key(frame)
        if key is not None and self._count(key) > MAX_ENTRY_ATTEMPTS:
            await self._fail_frame(frame, RetriesExhausted())
            self._uncount(key)
            backoff.reset()
            return
        attempt = 0
        while True:
            attempt += 1
            self._replaying = None
            try:
                await self._dispatch_frame(frame)
            except Exception as e:
                if not self._retried(frame, e):
                    # It would fail the same way every time: it fails alone,
                    # and the frames after it go on (SPEC 7.2).
                    await self._fail_frame(frame, e)
                    self._uncount(key)
                    break
                # Nothing was acked: retry the same frame, in order. If the
                # core already processed it, the retry gets the journalled
                # result back (ADR-004), and the inbox's (sender, msg_id)
                # dedup means its effects are recorded once: a retry can't
                # process or deliver a message twice.
                group_id, reason = _retry_reason(e)
                LOG.warning("inbound_transient", reason=reason, attempt=attempt)
                if _waits_unbounded(e):
                    # Never counted, from the first try: a daemon restarted
                    # before this handling gives up must not run the count up.
                    stopped = self._stopped_at()
                    self._uncount(key if stopped is None else str(stopped["key"]))
                if attempt < MAX_TRANSIENT_RETRIES and _transient(e):
                    await self._sleep(backoff.next())
                    continue
                entry = self._stopped_at()
                failing = key if entry is None else str(entry["key"])
                if _waits_unbounded(e):
                    self._uncount(failing)  # retried for as long as it takes
                elif self._count(failing) >= MAX_ENTRY_ATTEMPTS:
                    # Tried on every reconnect and restart, and it never
                    # passed: whatever the cause, it fails alone now.
                    if entry is None:
                        await self._fail_frame(frame, e)
                        self._uncount(key)
                        break
                    if await self._fail_entry(entry, e):
                        self._uncount(failing)
                        attempt = 0
                        continue  # the rest of the replay goes on
                # Give up for now; unacked, the relay redelivers it after
                # the next reconnect, which this asks for. Until a later
                # drain completes, the view misses it: not caught up.
                self._caught_up, self._gave_up = 0, self.link.connections
                await self.emit(group_id, "processing_failed", reason=reason)
                await self.link.kick()
            else:
                self._uncount(key)
            break
        backoff.reset()

    def _retried(self, frame: dict[str, Any], error: Exception) -> bool:
        """Whether a failure handling ``frame`` is retried rather than failed
        alone: it may pass (:func:`_transient`), or it is the bookkeeping of
        a Welcome the core has joined, whose journal entry is kept for the
        replay to finish (a joined group is never left without its record)."""
        if _transient(error):
            return True
        if frame.get("t") == REPLAY_JOURNAL:
            return self._replaying is not None and bool(self._replaying.get("welcome"))
        env = frame.get("env")
        if not isinstance(env, dict) or env.get("kind") != "welcome_wrapped":
            return False
        return self._journal_entry(env) is not None

    def _count(self, key: str | None) -> int:
        """The handlings of the message ``key`` so far, this one included:
        the first call while a frame is handled counts it, in a committed
        write of its own (:meth:`Store.attempt`), and later ones read the
        count. A count that can't be stored is 0: tried again."""
        if key is None:
            return 0
        try:
            if key in self._counted:
                return self.store.attempt_count(key)
            self._counted.add(key)
            return self.store.attempt(key, self.now())
        except Exception as e:
            LOG.warning("attempt_not_counted", error=type(e).__name__)
            return 0

    def _uncount(self, key: str | None) -> None:
        """The message ``key`` is handled (or failed alone): its count goes."""
        if key is None:
            return
        try:
            self.store.attempt_clear(key)
        except Exception as e:
            LOG.warning("attempt_not_cleared", error=type(e).__name__)

    def _stopped_at(self) -> dict[str, Any] | None:
        """The journal entry the last replay stopped at, if it did."""
        return self._replaying

    def _frame_key(self, frame: dict[str, Any]) -> str | None:
        """The message a delivered frame carries, to count its handlings by;
        ``None`` for any other frame and for a message recorded already (a
        redelivery, which is only acked)."""
        env = frame.get("env")
        if (
            frame.get("t") != "deliver"
            or not isinstance(env, dict)
            or not isinstance(env.get("sender"), str)
            or not isinstance(env.get("msg_id"), str)
        ):
            return None
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        with contextlib.suppress(Exception):
            if self.store.inbox_state(sender, msg_id) is not None:
                return None
        return journal_key(sender, msg_id)

    def _journal_entry(self, env: dict[str, Any]) -> dict[str, Any] | None:
        """The core's pending journal entry for the message ``env`` carries."""
        key = journal_key(str(env.get("sender")), str(env.get("msg_id")))
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
            return next((e for e in self.client.journal_pending() if e["key"] == key), None)
        return None

    async def _housekeeping(self) -> None:
        """:meth:`expire`, before each frame. It fails no frame: a failure is
        logged, by its type, and the next frame tries again."""
        try:
            await self.expire()
        except Exception as e:
            LOG.warning("housekeeping_failed", error=type(e).__name__)

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
        are dropped, and the audit log, transcripts and events keep their
        retention. Runs before each inbound frame (outside its failure
        handling, :meth:`_housekeeping`) and on (re)connect."""
        now = self.now()
        self._forget_kept_secrets()
        ended = []
        for invite in self.store.invites("open"):
            if now >= int(invite["expires_at"]):
                self.store.set_invite_status(invite["invite_id"], "expired")
                self._forget_secret(f"invite/{invite['invite_id']}")
                ended.append(str(invite["invite_id"]))
        self._forget_invite_requests(*ended)
        waiting = self._welcome_waiting()
        pending_joins = self.store.pending_joins()
        for pending in [] if waiting else pending_joins:
            expires = pending["meta"].get("expires_at")
            if isinstance(expires, int) and now >= expires + JOIN_CLOSED_GRACE_SECS:
                invite_id = pending["invite_id"]
                self.store.finish_join(invite_id, "expired")
                self._forget_secret(f"join/{invite_id}")
                await self.emit(None, "join_failed", invite_id=invite_id, reason="expired")
        if (self.store.kv_get(WELCOME_WAITING) or "") != "" and (not waiting or not pending_joins):
            # Stale (the Welcome can't come again), or no join left to wait.
            self.store.kv_set(WELCOME_WAITING, "")
        if self._parked and not self._may_join():
            self._parked.clear()
        # Hops are needed only while a reply can still arrive (relay TTL);
        # so are the journal's tombstones of consumed entries.
        self.store.forget_hops(now - HOP_MEMORY_SECS)
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
            self.client.journal_purge(now - HOP_MEMORY_SECS)
        # After the invites above: an entry outlives its invite's expiry.
        replay.purge(self.store, "join", self._join_ledger, now)
        await self.expire_held()
        self.safety.purge()
        if now - self._trimmed_at >= RETENTION_EVERY_SECS:
            self._trimmed_at = now
            # Events have a retention (daemon.event_retention_days) and a
            # cap; a message's give-ups are forgotten once the relay could no
            # longer redeliver it.
            cutoff = now - self.config.event_retention_days * DAY_SECS
            self.store.events_purge(before=cutoff, keep=MAX_EVENT_ROWS)
            self.store.attempts_purge(before=now - HOP_MEMORY_SECS)

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
        """Housekeeping, the frame, then the parked frames it released (the
        inbound worker runs each apart, so that a failure in one is never
        another's)."""
        await self._housekeeping()
        await self._dispatch_frame(frame)
        while self._followups:
            await self._dispatch_frame({"t": "deliver", "env": self._followups.popleft()})

    async def _dispatch_frame(self, frame: dict[str, Any]) -> None:
        t = frame.get("t")
        if t == REPLAY_JOURNAL:
            await self._replay_journal()
            await self._renotify()
        elif t == "deliver" and isinstance(frame.get("env"), dict):
            await self._handle_env(frame["env"])
        elif t == CAUGHT_UP:
            connection = int(frame.get("connection") or 0)
            if connection > self._gave_up:  # a drain with no frame given up
                self._caught_up = connection
            self.groups.wake()
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
            # A replay or a redelivery after reconnect: recorded already, so
            # acked (ADR-004), pending rows too; the delivery workers hand
            # those to each adapter. A failure after its effects were
            # recorded may have left the rest undone: the journal entry, the
            # secret, the wake-up.
            self._settle_recorded(env)
            await self._ack_recorded(sender, msg_id, env.get("group_id"), state)
            LOG.debug("duplicate_ignored", msg=log.hid(msg_id))
            return
        group_id = env.get("group_id")
        now = self.now()
        if kind == "knock":
            # Recorded, acked and audited there; silent toward the knocker.
            await self.knocks.on_knock(env)
            return
        if kind == "join_request":
            await self._on_join_request(env)  # records the inbox row
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
            self._forget_secret(f"join/{invite_id}")

    def _forget_secret(self, name: str) -> None:
        """Delete a secret whose invite or join ended (SPEC §6.3). If the
        keystore can't delete it now (locked, unavailable, a failing disk),
        it is kept for later: a later housekeeping pass deletes it
        (:meth:`_forget_kept_secrets`). A name the keystore refuses is a
        bug, and raised."""
        try:
            self.keystore.delete(name)
        except Exception as e:
            if not _deletion_deferred(e):
                raise
            kept = set(json.loads(self.store.kv_get(KEPT_SECRETS) or "[]")) | {name}
            self.store.kv_set(KEPT_SECRETS, json.dumps(sorted(kept)))
            LOG.warning("secret_kept", error=type(e).__name__)

    def _forget_kept_secrets(self) -> None:
        """Delete the secrets kept for later, as far as the keystore lets
        us. One that fails, whatever the error, stays kept and holds up
        nothing: the rest of the housekeeping pass goes on. The log has the
        error's type, never the secret's name."""
        kept = json.loads(self.store.kv_get(KEPT_SECRETS) or "[]")
        if not kept:
            return
        left = []
        for name in kept:
            try:
                self.keystore.delete(name)
            except Exception as e:
                LOG.warning("kept_secret_not_deleted", error=type(e).__name__)
                left.append(name)
        self.store.kv_set(KEPT_SECRETS, json.dumps(left))

    def _welcome_waiting(self) -> bool:
        """Whether a Welcome waits for a locked keystore, and may still come
        (within the relay's lifetime for it): no pending join lapses then."""
        since = self.store.kv_get(WELCOME_WAITING) or ""
        return since != "" and self.now() - int(since) < HOP_MEMORY_SECS

    def _welcome_done(self) -> None:
        """The waiting Welcome stopped waiting (joined, dropped or failed alone)."""
        if (self.store.kv_get(WELCOME_WAITING) or "") != "":
            self.store.kv_set(WELCOME_WAITING, "")

    async def _on_welcome_env(self, env: dict[str, Any]) -> None:
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        joined = await self._on_welcome(env)
        self._welcome_done()
        if joined is None:
            self.store.record_inbox(sender, msg_id, env.get("group_id"), "done", self.now())
            await self._ack(msg_id)
            return
        # Each is a message of its own: handled after this frame, so that a
        # failure in one is neither the Welcome's nor another's.
        self._followups.extend(self._parked.pop(joined, []))

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
            # The error's kind, not its text: a parser's message may quote
            # what it parsed, and this was a peer's.
            error=str(getattr(e, "kind", type(e).__name__)),
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

    async def _fail_frame(self, frame: dict[str, Any], error: Exception) -> None:
        """A frame whose handling failed for a reason that would repeat
        (:meth:`_retried` says no), or that was retried
        :data:`MAX_ENTRY_ATTEMPTS` times: its message fails alone
        (:meth:`_fail_message`), its journal entry is consumed and the relay
        is acked, so the frames after it go on and it is never retried. If
        even that fails, the frame stays unacked, as before."""
        env = frame.get("env") if frame.get("t") == "deliver" else None
        if (
            not isinstance(env, dict)
            or not isinstance(env.get("sender"), str)
            or not isinstance(env.get("msg_id"), str)
        ):
            LOG.error("inbound_failed", t=frame.get("t"), error=type(error).__name__)
            return
        try:
            entry = self._journal_entry(env)
            joined = self._joined(entry)
            event = None if entry is None or joined is not None else entry["event"]
            state = await self._fail_message(env, error, event, joined=joined)
            self._settle_recorded(env)
            await self._ack_recorded(
                str(env["sender"]), str(env["msg_id"]), env.get("group_id"), state
            )
        except Exception as e:
            LOG.error("inbound_failed", t=frame.get("t"), error=type(e).__name__)

    def _joined(self, entry: dict[str, Any] | None) -> tuple[str, str | None] | None:
        """For a Welcome's journal entry (the core joined the group): the
        group and the invite it was joined through (``None`` for a knock's)."""
        if entry is None or not entry.get("welcome"):
            return None
        invite_id = None
        with contextlib.suppress(ValueError, TypeError):
            ctx = loads(entry["context"], MAX_PAYLOAD_DEPTH)
            if isinstance(ctx, dict) and isinstance(ctx.get("invite_id"), str):
                invite_id = str(ctx["invite_id"])
        return gid_b64(bytes(entry["group_id"])), invite_id

    async def _fail_message(
        self,
        env: dict[str, Any],
        error: Exception,
        event: dict[str, Any] | None = None,
        *,
        joined: tuple[str, str | None] | None = None,
    ) -> str:
        """Record a message that failed in this daemon's own handling, for a
        reason that would repeat on every try (SPEC 7.2, "fails alone"): the
        inbox marks it failed, so a redelivery is only acked; the audit log
        gets a ``drop`` row with reason ``processing_failed``, and it counts
        against the sender as a violation; the human gets ``message_failed``,
        at most once per sender, group and violation window, with the
        failures since the last one (:meth:`_failed_report`).

        A commit that fails alone leaves the group out of sync, and this
        instance's invites to it close: merged by the core (``event`` is the
        core's), the bookkeeping that follows a commit (invites, roles,
        events, SAS runs) was skipped; not merged, this member is behind the
        group. A Welcome the core joined (``joined``: the group and the
        invite) but the daemon could never record leaves the group recorded,
        out of sync. The loop guard still decides on the message's hop (SPEC
        10.3). Returns the inbox state. The caller consumes the journal entry
        and acks the relay.

        ``event`` is the core's result for the message, when it has one: the
        sender's identity and the inner kind come from it, else the sender
        is its mailbox and the kind the envelope's."""
        sender, msg_id = str(env["sender"]), str(env["msg_id"])
        state = self.store.inbox_state(sender, msg_id)
        if state is not None:
            return state
        group_id = env.get("group_id") if isinstance(env.get("group_id"), str) else None
        if joined is not None:
            group_id = joined[0]
        group = None if group_id is None else self.store.group(group_id)
        etype = event.get("type") if isinstance(event, dict) else None
        identity, kind, size = f"mailbox:{sender}", str(env.get("kind")), len(str(env.get("ct")))
        inner = None
        if etype == "application" and isinstance(event, dict):
            identity = str(event["sender"]["identity"])
            size = len(event["plaintext"])
            inner = parse_inner(event["plaintext"])
            raw_kind = None if inner is None else inner.get("kind")
            kind = raw_kind if raw_kind in KNOWN_KINDS else "unknown"
        # The type only: an exception's text may quote what it handled.
        reason = type(error).__name__
        LOG.warning("message_failed", group=log.hid(group_id), kind=kind, error=reason)
        cause = journal_key(sender, msg_id) + "/failed"
        active = group is not None and group.status == "active"
        behind = (
            active
            and env.get("kind") == "commit"
            and etype is None
            and isinstance(env.get("epoch"), int)
            and int(env["epoch"]) >= self._core_epoch(unb64(str(group_id)))
        )
        merged = etype in ("commit", "own_commit_confirmed", "removed")
        report_key = (group_id or "", identity)
        count = self._failed_report(report_key)

        async def failed() -> str:
            self.store.record_inbox(sender, msg_id, group_id, "failed", self.now())
            self.safety.audit(
                group_id or "",
                "in",
                sender=identity,
                msg_id=msg_id,
                kind=kind,
                size=size,
                decision=Verdict.DROP,
                reason="processing_failed",
            )
            if env.get("kind") == "welcome_wrapped":
                self._welcome_done()  # it waits no more
            if joined is not None:
                await self._joined_out_of_sync(*joined)
            elif group is not None and active:
                if (merged or behind) and not group.out_of_sync:
                    # Merged, the bookkeeping that follows a commit was
                    # skipped; not merged, this member is behind the group.
                    # Either way its view can't be trusted, nor can its
                    # commits land, so its invites close.
                    await self.mark_out_of_sync(group.group_id, "commit_unapplied")
                    self.groups.close_invites(group.group_id)
                if merged and etype != "removed":
                    # SPEC 11.3: the earlier epoch's SAS runs end with it,
                    # whatever else of the bookkeeping failed.
                    committer = (event or {}).get("committer") or {}
                    with contextlib.suppress(Exception), self.store.tx():
                        self.sas.on_epoch_changed(group.group_id, committer.get("identity"))
                if inner is not None and inner.get("origin") != "human":
                    await self._guard_failed(group, msg_id, identity, inner)
            # Like a malformed message: held against the sender (SPEC 10.2),
            # unless that is this instance (its own commit, confirmed).
            alert = (
                None
                if sender == self.mailbox
                else self.safety.violation(group_id or "", identity, "processing_failed")
            )
            if alert is not None:
                await self.emit(group_id, "repeated_violations", **alert)
            if count is not None:
                await self.emit(
                    group_id,
                    "message_failed",
                    cause=cause,
                    sender=identity,
                    msg_id=msg_id,
                    message_kind=kind,
                    reason=reason,
                    count=count,
                )
            self._defer(lambda: self._failed_counted(report_key, reported=count is not None))
            return "failed"

        with self._causing(cause):
            return await self._apply("poison", failed)

    def _failed_report(self, key: tuple[str, str]) -> int | None:
        """The ``count`` of a ``message_failed`` event for one more failure
        from this (group, sender): the failures since the last event, this
        one included. ``None`` while the last event is within the group's
        violation window: the failure is counted toward the next one."""
        now = self.now()
        window = self.safety.settings(key[0]).violation_window_secs
        last, since = self._failed.get(key, (None, 0))
        if last is not None and now - last < window:
            return None
        return since + 1

    def _failed_counted(self, key: tuple[str, str], *, reported: bool) -> None:
        """After :meth:`_fail_message` committed: one failure more, or one
        reported now. At most :data:`MAX_FAILED_TRACKED` pairs are kept."""
        last, since = self._failed.get(key, (None, 0))
        self._failed[key] = (self.now(), 0) if reported or last is None else (last, since + 1)
        self._failed.move_to_end(key)
        while len(self._failed) > MAX_FAILED_TRACKED:
            self._failed.popitem(last=False)

    async def _joined_out_of_sync(self, group_id: str, invite_id: str | None) -> None:
        """Inside a transaction: the core joined a group through a Welcome
        whose bookkeeping never succeeded. The group is recorded, out of
        sync, so the human sees it and can leave it; its join is over."""
        gid = unb64(group_id)
        now = self.now()
        if self.store.group(group_id) is None:
            name, purpose = "", ""
            with contextlib.suppress(Exception):
                meta = json.loads(self.client.meta(gid))
                name, purpose = str(meta["name"]), str(meta["purpose"])
            self.store.add_group(
                GroupRow(
                    group_id=group_id,
                    name=name,
                    purpose=purpose,
                    policy={},
                    adapter=self.config.default_adapter,
                    status="active",
                    out_of_sync=True,
                    out_of_sync_reason="welcome_failed",
                    epoch=self._core_epoch(gid),
                    created_at=now,
                    last_own_commit_at=now,
                    msgs_since_commit=0,
                )
            )
            # Members, roles and policy as far as they can be read.
            with contextlib.suppress(Exception), self.store.tx():
                self._refresh(group_id)
            await self.emit(group_id, "out_of_sync", reason="welcome_failed")
        else:
            await self.mark_out_of_sync(group_id, "welcome_failed")
        if invite_id is not None:
            self.store.finish_join(invite_id, "joined", group_id)
            self._defer(lambda: self._forget_secret(f"join/{invite_id}"))

    async def _guard_failed(
        self, group: GroupRow, msg_id: str, identity: str, inner: dict[str, Any]
    ) -> None:
        """SPEC 10.3 for a message that failed: the pause is decided on its
        hop alone, as for any other. A failure here is logged, so it can't
        keep the message from failing alone."""
        try:
            if inner_problem(inner) is not None:
                return
            hop = self._received_hop(group.group_id, inner)
            if hop > _max_turns(group.policy):
                await self._loop_guard(group, msg_id, identity, hop)
        except Exception as e:
            LOG.warning("loop_guard_failed", group=log.hid(group.group_id), error=type(e).__name__)

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
                except Exception as e:
                    # The effects rolled back, but the cached view must
                    # follow the core now: local decisions use it.
                    with contextlib.suppress(Exception):
                        self._refresh(group_id)
                    if _transient(e):
                        raise  # the entry stays pending: retried, or replayed
                    # It would fail the same way on every retry and replay.
                    state = await self._fail_message(env, e, event)
        with contextlib.suppress(ac.AgentConnectError, ac.CoreError):
            self.client.journal_consume(journal_key(sender, msg_id), unb64(group_id))
        self.failpoints.hit(f"{path}.after_consume")
        if state == "pending":
            self._delivery_wake.set()
        if from_relay:
            await self._ack_recorded(sender, msg_id, group_id, state)
        self._pulse()

    async def _ack_recorded(
        self, sender: str, msg_id: str, group_id: Any, state: str | None
    ) -> None:
        """A message is recorded in the inbox: the relay's copy can go, and
        each adapter's delivery is tracked here (ADR-004). Not while the
        group's pending messages are past their limits: then a pending message's copy
        stays at the relay, whose mailbox fills as before (SPEC 8.3), and is
        acked once delivered or once the pending messages drain."""
        if state == "pending" and isinstance(group_id, str) and self._pending_over(group_id):
            self.store.mark_unacked(sender, msg_id)
            self._delivery_wake.set()
            return
        await self._ack(msg_id)

    async def _effects(  # noqa: PLR0912
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
            ceremony = _ceremony_inner(event)
            if ceremony is not None:
                # SPEC 11.5: handled here and never delivered, not even as
                # context; outside the safety policy's rates (SPEC 11.3).
                if not event.get("replayed"):
                    self.sas.on_message(group, event, ceremony)
                self.store.record_inbox(sender, msg_id, group_id, "done", now)
                return "done"
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
            floor = _floor_inner(event)
            if floor is not None:
                # SPEC 9.3: a valid grant moves the floor register on every
                # member, whatever this member's own delivery policy (rates,
                # sizes, the drain) decided for the message.
                await self.floor.accept(
                    group_id,
                    int(event["epoch"]),
                    identity,
                    str(event["sender"]["instance_id_hex"]),
                    floor,
                )
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
                # human's decision; the daemon never leaves on its own, and
                # until the human answers the agent may not either (SR-34).
                self.store.kv_set(f"close_pending/{group_id}", msg_id)
                reason = delivery.body.get("reason")
                await self.emit(
                    group_id,
                    "close_requested",
                    sender=delivery.sender.identity,
                    reason=reason[:200] if isinstance(reason, str) else "",
                )
            return "held" if held else "pending"
        if etype in ("commit", "own_commit_confirmed"):
            await self.groups.after_commit(
                group_id,
                event,
                env if from_relay else None,
                own=etype == "own_commit_confirmed",
            )
        elif etype == "removed":
            legacy = self._journalled_by_an_older_daemon(journal_key(sender, msg_id))
            await self.groups.on_removed(group_id, event, legacy=legacy)
        elif etype == "leave_proposed":
            await self.groups.on_leave_proposed(group_id, event["member"])
        self.store.record_inbox(sender, msg_id, group_id, "done", now)
        return "done"

    async def _replay_journal(self) -> None:
        """Finish every journal entry the core holds but the daemon hasn't
        consumed: a crash (or a failure) came after the core committed and
        before the daemon recorded the result (ADR-004)."""
        for entry in self.client.journal_pending():
            key = str(entry["key"])
            if self._count(key) > MAX_ENTRY_ATTEMPTS:
                # Its handlings never finished (each crashed, or gave up):
                # it fails alone, unreplayed.
                if await self._fail_entry(entry, RetriesExhausted()):
                    self._uncount(key)
                continue
            try:
                await self._replay_entry(entry)
            except Exception as err:
                if _transient(err) or entry.get("welcome"):
                    # The inbound worker retries the replay after a backoff,
                    # and counts the give-ups against this entry
                    # (MAX_ENTRY_ATTEMPTS). A Welcome's entry stays for the
                    # replay to finish whatever failed: the core has joined.
                    self._replaying = entry
                    raise
                # One entry that fails for good must not stop the others, nor
                # the renotify after them, nor come back on every replay: it
                # fails alone.
                if await self._fail_entry(entry, err):
                    self._uncount(key)
            else:
                self._uncount(key)

    async def _fail_entry(self, entry: dict[str, Any], error: Exception) -> bool:
        """A journal entry whose replay failed for a reason that would
        repeat, or that was given up :data:`MAX_ENTRY_ATTEMPTS` times: its
        message fails alone (:meth:`_fail_message`) and the entry is
        consumed. If even that fails, it stays pending, as before: returns
        whether it went."""
        try:
            ctx = loads(entry["context"], MAX_PAYLOAD_DEPTH)
            env = ctx.get("env") if isinstance(ctx, dict) else None
            joined = self._joined(entry)
            if (
                isinstance(env, dict)
                and isinstance(env.get("sender"), str)
                and isinstance(env.get("msg_id"), str)
            ):
                event = None if entry["welcome"] else entry["event"]
                await self._fail_message(env, error, event, joined=joined)
            self.client.journal_consume(
                str(entry["key"]), None if entry["welcome"] else entry["group_id"]
            )
            if joined is not None:
                self._forget_join_secrets()
        except Exception as err:
            LOG.warning(
                "journal_replay_failed",
                error=type(err).__name__,
                entry=log.hid(str(entry.get("key"))),
            )
            return False
        return True

    async def _replay_entry(self, entry: dict[str, Any]) -> None:
        """Finish one pending journal entry (:meth:`_replay_journal`)."""
        try:
            ctx = loads(entry["context"], MAX_PAYLOAD_DEPTH)
            env = ctx["env"]
            if not isinstance(env, dict) or _envelope_problem({**env, "ct": ""}) is not None:
                raise ValueError("context")
        except (ValueError, KeyError, TypeError):
            # Not something this daemon wrote: drop it.
            self.client.journal_consume(
                str(entry["key"]), None if entry["welcome"] else entry["group_id"]
            )
            return
        LOG.info("journal_replay", kind=env.get("kind"), msg=log.hid(str(env.get("msg_id"))))
        if entry["welcome"] and isinstance(ctx.get("knock_id"), str):
            await self.knocks.finish_welcome(env, ctx["knock_id"], entry["group_id"])
        elif entry["welcome"]:
            await self._finish_welcome(env, str(ctx.get("invite_id")), entry["group_id"])
        else:
            event = {**entry["event"], "replayed": True}
            path = "receive" if ctx.get("from_relay", True) else "confirm"
            await self._finish(env, event, from_relay=bool(ctx.get("from_relay")), path=path)

    def _journalled_by_an_older_daemon(self, key: str) -> bool:
        """Whether the journal entry being finished was written by a daemon
        from before ``SUMMARY_REPORTS_LEAVES``: its summary may predate the
        core's ``left``, which then reads back empty. The entry is still pending
        while its effects are recorded, whether it is replayed after a restart
        or the core hands it back for the frame processed again. Only asked
        for a removal of this instance, so the lookup costs nothing elsewhere."""
        for entry in self.client.journal_pending():
            if entry["key"] == key:
                try:
                    ctx = loads(entry["context"], MAX_PAYLOAD_DEPTH)
                except (ValueError, TypeError):
                    return False
                return isinstance(ctx, dict) and not ctx.get(SUMMARY_REPORTS_LEAVES)
        return False

    def _dropped_hop(self, group_id: str, inner: dict[str, Any]) -> int | None:
        """The SPEC 10.3 hop of a dropped message, for the loop guard alone,
        which decides on the hop whatever the policy decided: ``None`` for a
        human's message or a malformed hop. Read like any other, but if the
        messages it replies to can't be read, the hop it claims."""
        claimed = inner.get("hop", 0)
        if inner.get("origin") == "human" or not valid_hop(claimed):
            return None
        try:
            return self._received_hop(group_id, inner)
        except Exception as e:
            LOG.warning("hop_unread", group=log.hid(group_id), error=type(e).__name__)
            return int(claimed)

    def _received_hop(self, group_id: str, inner: dict[str, Any]) -> int:
        """The SPEC 10.3 hop of a received message: what it claims, and at
        least one more than any message it replies to that we know (SPEC
        7.2), whatever the sender claims; never past a u32. ``hop`` is
        checked first (:func:`inner_problem`)."""
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
        return min(hop, U32_MAX)

    def _granting(
        self, group_id: str, identity: str, instance: str, inner: dict[str, Any]
    ) -> str | None:
        """SPEC 9.3: the request of this instance that a received task update
        answers (named in ``reply_to``, asked this member and grants it this
        task, :meth:`Store.grant_task`), or ``None``."""
        task = task_of(inner)
        if task is None:
            return None
        return self.store.grant_task(
            group_id,
            _refs(inner),
            responder=identity,
            instance=instance,
            task_id=task,
            now=self.now(),
        )

    def _request_asks(
        self, group: GroupRow, kind: str, inner: dict[str, Any]
    ) -> tuple[list[str], str | None]:
        """Whom a request this instance sends asks (SPEC 9.3): the members it
        triggers under the floor rules, and its instance hint. One that names
        a task asks only the member running it, when this instance knows it,
        else only the members it names."""
        raw = inner.get("body")
        body: dict[str, Any] = raw if isinstance(raw, dict) else {}
        metadata = body.get("metadata")
        hint = metadata.get("instance") if isinstance(metadata, dict) else None
        hint = hint if isinstance(hint, str) else None
        moderator, holder = self.floor.triggers(group.group_id, group.policy)
        floor = str(group.policy.get("floor", "free"))
        asked = [
            m.identity
            for m in self.store.members(group.group_id)
            if m.identity != self.me
            and addressed_to_me(floor, inner, m.identity, hint or "", moderator, holder)
        ]
        task = _request_task(kind, body)
        if task is None:
            return asked, hint
        owner = self.store.task_owner(group.group_id, task)
        if owner is None:
            named = _named(inner)
            return [m for m in asked if m in named], hint
        if owner[0] not in asked or hint not in (None, owner[1]):
            return [], hint
        return [owner[0]], owner[1]

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

    def _triggered(self, group_id: str, hop: int, msg_id: str, sender: str) -> None:
        """The default "message replied to" for this instance's next agent
        message in the group (see _reply_hop), and for a task update to
        ``sender`` (see queue_message)."""
        self.store.kv_set(f"trigger_hop/{group_id}", str(hop))
        self.store.kv_set(f"trigger_msg/{group_id}", msg_id)
        self.store.kv_set(f"trigger_from/{group_id}/{sender}", msg_id)

    def _task_facts(
        self, group: GroupRow, identity: str, instance: str, inner: dict[str, Any]
    ) -> tuple[int, bool, str | None, str | None, bool]:
        """What the rates and the trigger of a received message depend on:
        its hop (SPEC 10.3), whether it addresses this instance (SPEC 9.3),
        the request of this instance a task update answers, the state it
        enters and whether that triggers the requester (SPEC 9.3)."""
        policy = group.policy
        hop = self._received_hop(group.group_id, inner)
        moderator, holder = self.floor.triggers(group.group_id, policy)
        addressed = addressed_to_me(
            str(policy.get("floor", "free")),
            inner,
            self.me,
            self.instance.instance_id_hex,
            moderator,
            holder,
        )
        if inner["kind"] not in TASK_UPDATE_KINDS:
            return hop, addressed, None, None, False
        # SPEC 9.3: a task update triggers only the instance that asked for
        # the task, and only then has the task budget (SPEC 10.2).
        granting = self._granting(group.group_id, identity, instance, inner)
        # SPEC 9.3: a granted task triggers only on entering a state the
        # requester acts on, once per state, and not after it ended; its
        # other updates are progress, delivered as context.
        state = task_state(inner) if granting is not None else None
        trigger = (
            granting is not None
            and acts_on(state)
            and self.store.task_triggers(group.group_id, granting, identity, str(state))
        )
        return hop, addressed and trigger, granting, state, trigger

    def _make_delivery(
        self, group: GroupRow, msg_id: str, event: dict[str, Any], *, replayed: bool = False
    ) -> tuple[Delivery | None, Decision, str, int | None]:
        """Apply the safety policy to a received application message. Returns
        the delivery to record (``None`` if dropped), the decision and the
        message kind."""
        # SPEC 7.2: nesting, hop, to and addressee are bounded before anything
        # else reads the message, so no step after can fail on its shape.
        inner = parse_inner(event["plaintext"])
        if inner is None or not isinstance(inner.get("kind"), str):
            return None, drop("malformed"), "", None
        # The kind is peer text: record only the ones the protocol defines.
        kind = str(inner["kind"]) if inner["kind"] in KNOWN_KINDS else "unknown"
        if inner_problem(inner) is not None:
            return None, drop("malformed"), kind, self._dropped_hop(group.group_id, inner)
        sender = event["sender"]
        identity = sender["identity"]
        instance = str(sender["instance_id_hex"])
        policy = group.policy
        # The facts the rates depend on (SPEC 9.3, 10.2): the hop, whether
        # this instance is addressed, the task request a task update
        # answers. Reading them may fail; the message is then counted at the
        # ordinary rates all the same (as no request's, triggering nobody),
        # and only then does its failure become its own (SPEC 7.2).
        hop = int(inner.get("hop", 0))  # a u32: inner_problem passed
        addressed, granting, state, trigger = False, None, None, False
        failure: Exception | None = None
        try:
            hop, addressed, granting, state, trigger = self._task_facts(
                group, identity, instance, inner
            )
        except Exception as e:
            failure = e
        requested = granting is not None
        # The hop the loop guard acts on (None: a human's message, SPEC 10.3).
        guard_hop = None if inner.get("origin") == "human" else hop
        # SPEC 10.2 next: size, shape and the sender's rates, before anything
        # else that reads the message, so every message counts against them.
        refused = self.safety.admit(
            Inbound(
                group.group_id,
                identity,
                instance,
                inner,
                len(event["plaintext"]),
                policy.get("owner"),
                hop,
                _max_turns(policy),
                addressed,
                replayed=replayed,
                drain_exempt=lambda: self._drain_exempt(group.group_id, identity),
                requested=requested,
                progress=requested and not trigger,
                trigger=trigger,
            )
        )
        if refused is not None:
            LOG.info("message_dropped", group=log.hid(group.group_id), reason=refused.reason)
            return None, refused, kind, guard_hop
        if failure is not None:
            raise failure
        # One decision: SPEC 7.2 (unknown kinds are ignored), 7.3, 9.3, 10.2
        # (size, parts, rates; a replayed journal entry was counted when the
        # core first processed it), 10.3 and require_approval.
        decision = self.safety.inbound(
            Inbound(
                group.group_id,
                identity,
                instance,
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
                requested=requested,
                progress=requested and not trigger,
                trigger=trigger,
                admitted=True,
            )
        )
        if (
            decision.verdict is not Verdict.DROP
            and inner["kind"] == "control.floor"
            and self.floor.judge(
                group.group_id,
                int(event["epoch"]),
                identity,
                str(sender["instance_id_hex"]),
                inner,
            )
            is None
        ):
            # SPEC 9.3: a grant the facts of its epoch don't allow is
            # ignored, silently, after the rates counted it.
            decision = drop("floor_ignored")
        if decision.verdict is Verdict.DROP:
            LOG.info("message_dropped", group=log.hid(group.group_id), reason=decision.reason)
            return None, decision, kind, guard_hop
        self.store.record_hop(group.group_id, msg_id, hop, self.now())
        if inner["kind"] in REQUEST_KINDS and addressed and identity != self.me:
            # SPEC 9.3: the requester's grant, as this instance's answer
            # sees it (_own_trigger).
            raw = inner.get("body")
            self.store.record_asked(
                group.group_id,
                msg_id,
                task_id=_request_task(inner["kind"], raw if isinstance(raw, dict) else {}),
                now=self.now(),
            )
        if inner["kind"] in HUMAN_ONLY_KINDS:
            self._reset_loop_guard(group.group_id)
        if decision.verdict is Verdict.DELIVER:
            self._triggered(group.group_id, hop, msg_id, identity)
        # A held message triggers once approved if it would trigger now.
        triggers = decision.verdict is Verdict.DELIVER or (
            decision.verdict is Verdict.HOLD_FOR_APPROVAL
            and addressed
            and hop <= _max_turns(policy)
        )
        if granting is not None and trigger and triggers:
            # SPEC 9.3: the state is used only when it triggers (now, or once
            # approved); one delivered as context can trigger if entered again.
            self.store.task_entered(
                group.group_id,
                granting,
                identity,
                str(state),
                terminal=state in TERMINAL_STATES,
            )
        raw_body = inner.get("body")
        body: dict[str, Any] = raw_body if isinstance(raw_body, dict) else {}
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
        the messages it replies to, at most 2^32 - 1 (SPEC 7.2: a u32).

        "Replies to" is the received messages named in ``reply_to`` (their
        ``msg_id``s) when the agent says, and always the last message that
        triggered this instance in the group (0 before any, so a fresh agent
        message has hop 1): naming an older message, a human's at hop 0 say,
        can't lower it, or two agents could talk forever under
        ``max_agent_turns`` (SR-33). A ``control.resume`` resets the trigger
        to 0.

        Also returns the ``msg_id``s replied to, for the inner ``reply_to``.
        """
        refs: list[str] = [str(r) for r in (reply_to or [])][:MAX_REPLY_TO]
        hops = self.store.inbox_hops(group_id, refs)
        last = self.store.kv_get(f"trigger_msg/{group_id}") or ""
        hop = int(self.store.kv_get(f"trigger_hop/{group_id}") or "0") + 1
        if hops:
            hop = max(hop, int(max(hops)) + 1)
        elif not refs and last != "":
            refs = [last]
        return min(hop, U32_MAX), refs

    def _record_task_links(
        self, group: GroupRow, msg_id: str, kind: str, inner: dict[str, Any], refs: list[str]
    ) -> None:
        """Inside :meth:`queue_message`'s transaction. A request: what a
        peer may answer with task updates that trigger this instance, and who
        (SPEC 9.3). A task update: the request this instance's task answers,
        for its updates sent without ``reply_to``."""
        if kind in REQUEST_KINDS:
            asked, hint = self._request_asks(group, kind, inner)
            self.store.record_request(
                group.group_id,
                msg_id,
                task_id=_request_task(kind, inner["body"]),
                asked=asked,
                instance=hint,
                now=self.now(),
            )
        task = task_of(inner)
        if task is not None and refs:
            self.store.record_answered(group.group_id, task, refs[0], self.now())
            state = self._own_trigger(group.group_id, inner)
            self.store.answered_asked(
                group.group_id, refs[0], task, state, terminal=state in TERMINAL_STATES
            )

    def _own_trigger(self, group_id: str, inner: dict[str, Any]) -> str | None:
        """The state, if this instance's task update triggers its requester
        as the requester's grant takes it (SPEC 9.3): its first ``reply_to``
        is a request this instance received that asked it, the task is that
        request's, and the state is one the requester acts on, entered for
        the first time and before the task ended. At most three per received
        request, so the send is never refused for the task's budget and the
        requester always learns the outcome; anything else has the rates."""
        state, task, refs = task_state(inner), task_of(inner), _refs(inner)
        if not acts_on(state) or task is None or not refs:
            return None
        if not self.store.answer_triggers(group_id, refs[0], task, str(state)):
            return None
        return state

    def _task_request(
        self, group_id: str, kind: str, body: dict[str, Any], addressee: list[str] | None
    ) -> list[str] | None:
        """``reply_to`` for an agent's task update sent without one: the
        request whose task it is (the first update of the task named it),
        else the last message from the ``addressee`` that triggered this
        instance; ``None`` leaves it to :meth:`_reply_hop` (and any other
        kind)."""
        if kind not in TASK_UPDATE_KINDS:
            return None
        task = body.get("taskId")
        if isinstance(task, str) and task:
            known = self.store.answered_request(group_id, task)
            if known is not None:
                return [known]
        if addressee is not None and len(addressee) > 0:
            last = self.store.kv_get(f"trigger_from/{group_id}/{addressee[0]}")
            if last is not None and last != "":
                return [last]
        return None

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

    # -- joins ----------------------------------------------------------------

    def _invite_object(self, invite: dict[str, Any]) -> ac.Invite | None:
        secret = self.keystore.get(f"invite/{invite['invite_id']}")
        if secret is None:
            return None
        return ac.Invite.from_parts(
            self.config.relay_host, unb64(invite["invite_id"]), secret, invite["expires_at"]
        )

    async def _on_join_request(self, env: dict[str, Any]) -> None:
        """An invite's JoinRequest (SPEC 6.2). Steps 1-3 are checked, then
        the request is remembered in the join replay ledger before anything
        else happens to it, so a request that was decided, lapsed or dropped
        can't come back while its invite is open ("Replays"). A replay is
        dropped silently: no approval, no event, nothing to the joiner, one
        audit row with the reason code. The ledger row, the approval, its
        event and the inbox row are one transaction."""
        sender, msg_id = str(env["sender"]), str(env["msg_id"])

        def ignore(event: str, **fields: Any) -> None:
            LOG.info(event, **fields)
            self.store.record_inbox(sender, msg_id, None, "done", self.now())

        if not _id16(msg_id):
            # A join's request id is its msg_id, which the joiner (or the
            # relay) picks. SPEC 7.1 makes it 16 bytes (22 characters), and a
            # knock's request id has 19, so the two can't collide.
            ignore("join_request_malformed")
            return
        raw = unb64(str(env.get("ct", "")))
        invite_id = _join_request_invite(raw)
        if invite_id is None:
            ignore("join_request_malformed")
            return
        invite = self.store.invite(invite_id)
        obj = None if invite is None or invite["status"] != "open" else self._invite_object(invite)
        if invite is None or obj is None:
            ignore("join_request_unknown_invite", invite=log.hid(invite_id))
            return
        if self._invite_closed(invite):
            # SPEC 6.2 step 1: no uses left (or expired). The joiner sees the
            # SPEC 4.3 "already used" warning when its join lapses.
            ignore("join_request_invite_used", invite=log.hid(invite_id))
            return
        verified = await self._verify_join(raw, obj, sender, invite, ignore)
        if verified is None:
            return
        group_id, request_id = str(invite["group_id"]), msg_id
        kp_ref = b64(verified.key_package_ref)

        def drop_it(reason: str) -> str:
            self.safety.audit(
                group_id,
                "in",
                sender=verified.identity,
                msg_id=msg_id,
                kind="join_request",
                size=len(raw),
                decision=Verdict.DROP,
                reason=reason,
            )
            self.store.record_inbox(sender, msg_id, None, "dropped", self.now())
            LOG.info("join_request_dropped", invite=log.hid(invite_id), reason=reason)
            return "dropped"

        async def flooded(reason: str) -> str:
            # Too many requests claiming one identity: say which.
            await self._tell_join_flood(
                group_id,
                invite_id,
                reason,
                verified.identity if reason == JOIN_IDENTITY_FULL else None,
            )
            return drop_it(reason)

        async def body() -> str:
            key = replay.entry_key("join", request_id)
            if (early := self._early_drop(invite, key, verified)) is not None:
                return drop_it(early) if early == "join_not_replica" else await flooded(early)
            refused = replay.remember(
                self.store,
                "join",
                self._join_ledger,
                lambda ledger: verified.remember_in(ledger, key),
                entry_id=request_id,
                kp_ref=verified.key_package_ref,
                forget_after=verified.forget_after,
                invite_id=invite_id,
            )
            if refused == "join_ledger_full":
                await self._tell_join_flood(None, None, refused)
                return drop_it(refused)
            if refused is not None:
                return drop_it(refused)
            if (
                taken := self._join_taken(request_id, kp_ref, invite_id, verified.identity)
            ) is not None:
                return await flooded(taken) if taken == JOIN_IDENTITY_FULL else drop_it(taken)
            waiting = self.store.pending_approvals_for(
                invite_id, self.now() - APPROVAL_TIMEOUT_SECS
            )
            if waiting >= self.config.policy_max_pending_joins_per_invite:
                return await flooded("join_invite_full")
            # Before any approval: it checks the request's sender by this row.
            self.store.record_inbox(sender, msg_id, None, "done", self.now())
            self.store.add_approval(
                {
                    "request_id": request_id,
                    "invite_id": invite_id,
                    "group_id": group_id,
                    "request": b64(raw),
                    "identity": verified.identity,
                    "display_name": verified.display_name,
                    "mailbox_id": verified.mailbox_id,
                    "received_at": self.now(),
                    "kp_ref": kp_ref,
                    "instance_id": instance_hex(verified.instance_id),
                }
            )
            await self.emit(
                group_id,
                "pending_approval",
                request_id=request_id,
                identity=verified.identity,
                instance_id=instance_hex(verified.instance_id),
                mailbox_id=verified.mailbox_id,
                display_name=verified.display_name,
                display_name_verified=False,
                identity_requests=self._identity_requests(invite_id, verified.identity),
            )
            if self.config.auto_approve and not (invite["replica"] and invite["instance"] is None):
                # Joins only: nothing approves a knock but the human (SPEC
                # 6.6.4), nor a request on an unpinned replica invite, where
                # every request claims this identity and only the instance
                # tells them apart. In this transaction, so a failure once it
                # commits can't leave the approval pending until it lapses.
                self._auto_approve(request_id, group_id)
            return "held"

        try:
            await self._apply("join_request", body)
        except BaseException:
            # The in-memory ledger has no remove: rebuild it from the store.
            self._join_ledger = self._load_join_ledger()
            raise

    def _early_drop(
        self, invite: dict[str, Any], key: bytes, verified: ac.VerifiedJoinRequest
    ) -> str | None:
        """Why a join request is dropped before the ledger, or ``None``. A
        replica invite refuses another identity, or another instance than the
        one it is pinned to (SPEC 9.4), before the request takes any of the
        invite's share of the ledger; then the invite's quota."""
        pinned = invite["instance"]
        if invite["replica"] and (
            verified.identity != self.me
            or (pinned is not None and instance_hex(verified.instance_id) != pinned)
        ):
            return "join_not_replica"
        if self._over_join_quota(invite, key, verified.key_package_ref):
            return "join_invite_quota"
        return None

    def _join_taken(
        self, request_id: str, kp_ref: str, invite_id: str, identity: str
    ) -> str | None:
        """Why a new join request can't get an approval of its own, or
        ``None``. Past the ledger's window the request id or the KeyPackage
        may still be taken: one approval per id and per KeyPackage (an exact
        copy is dropped). Distinct requests that claim one identity all reach
        the human, marked as such, up to :data:`MAX_PENDING_PER_IDENTITY` per
        invite: a relay that lies about the sender can deliver a request
        built from one of an identity's KeyPackages in its name, so the
        human chooses, and its own can't be crowded out by one other
        request."""
        if (
            self.store.approval(request_id) is not None
            or self.store.open_approval_for(kp_ref) is not None
        ):
            return "join_replay"
        if self._identity_requests(invite_id, identity) >= MAX_PENDING_PER_IDENTITY:
            return JOIN_IDENTITY_FULL
        return None

    def _identity_requests(self, invite_id: str, identity: str) -> int:
        """Join requests of this invite that claim ``identity`` and wait."""
        since = self.now() - APPROVAL_TIMEOUT_SECS
        return self.store.pending_approvals_of(invite_id, identity, since)

    def _auto_approve(self, request_id: str, group_id: str) -> None:
        """``policy.auto_approve``: approve at once, unless the group is full,
        when the request waits for the human, who can make room first."""
        room = self.groups.room(group_id)
        if room is not None and room < 1:
            LOG.info("join_request_group_full")
            return
        self._approve_join(request_id)

    def _over_join_quota(self, invite: dict[str, Any], key: bytes, kp_ref: bytes) -> bool:
        """Whether a request that isn't a replay would take the invite past
        its share of the join ledger (a replay is dropped as one)."""
        quota = replay.join_quota(
            int(invite["max_uses"]), self.config.policy_join_ledger_per_invite
        )
        return self.store.join_ledger_count(str(invite["invite_id"])) >= quota and not (
            self._join_ledger.seen(key, kp_ref)
        )

    async def _verify_join(
        self,
        raw: bytes,
        obj: ac.Invite,
        sender: str,
        invite: dict[str, Any],
        ignore: Callable[..., None],
    ) -> ac.VerifiedJoinRequest | None:
        """SPEC 6.2 steps 2 and 3 for an open invite's request, or ``None``
        when it is dropped (``ignore`` records why)."""
        invite_id = str(invite["invite_id"])
        try:
            # Step 3: only from the mailbox it names. Anyone with the link can
            # MAC any KeyPackage, so a request from another sender is dropped
            # here, before the replay ledger and the approval, like a failed
            # MAC.
            return self.client.verify_join_request(raw, obj, sender)
        except (ac.AgentConnectError, ac.CoreError) as e:
            # The error's kind, not its text, which may quote the request.
            reason = str(getattr(e, "kind", type(e).__name__))
            ignore("join_request_rejected", invite=log.hid(invite_id), reason=reason)
            if reason == "authentication" or str(e) == SENDER_MISMATCH:
                # Step 2: counted, to tell the human. Nothing is dropped
                # unchecked for it: anyone who knows the invite id could
                # then lock its joiners out, and the relay already caps the
                # requests an invite gets.
                await self._count_join_failure(str(invite["group_id"]), invite_id)
            return None

    async def _count_join_failure(self, group_id: str, invite_id: str) -> None:
        """A failed request for ``invite_id``. At the limit within the window
        the human is told; while the failures go on, the next notice waits
        twice as long as the last (from the window up to a day), and a quiet
        window starts over, so an attack that comes back is told again."""
        now, limit = self.now(), self.config.policy_max_failed_joins_per_invite
        # Only the newest `limit` times matter: a full deque whose oldest is
        # inside the window is the limit reached.
        times = self._join_failures.setdefault(invite_id, deque(maxlen=limit))
        while times and times[0] <= now - JOIN_FAILURE_WINDOW_SECS:
            times.popleft()
        if not times:
            self._join_failures_told.pop(invite_id, None)
        times.append(now)
        if len(times) < limit:
            return
        told = self._join_failures_told.get(invite_id)
        if told is not None and now - told[0] < told[1]:
            return
        interval = JOIN_FAILURE_WINDOW_SECS if told is None else min(2 * told[1], 86_400)
        self._join_failures_told[invite_id] = (now, interval)
        await self._tell_join_flood(group_id, invite_id, JOIN_FAILURES)

    async def _tell_join_flood(
        self,
        group_id: str | None,
        invite_id: str | None,
        reason: str,
        identity: str | None = None,
    ) -> None:
        """Tell the human (never the agent) that join requests are dropped
        by a limit: an invite's (``invite_flooded``, once per invite and
        reason, and for too many requests claiming one identity once per
        identity, naming it), or the whole ledger's (``join_ledger_full``,
        daemon-wide and once a day: the invite whose request found it full is
        a bystander, so it isn't named)."""
        if invite_id is None:
            await self.emit(
                None,
                "join_ledger_full",
                cause=f"join_ledger_full/{self.now() // 86_400}",
                warning=JOIN_LEDGER_FULL_WARNING,
            )
            return
        if identity is not None:
            warning = IDENTITY_FLOOD_WARNING.format(
                limit=MAX_PENDING_PER_IDENTITY, identity=identity
            )
            await self.emit(
                group_id,
                "invite_flooded",
                cause=f"invite_flooded/{invite_id}/{reason}/{identity}",
                invite_id=invite_id,
                reason=reason,
                identity=identity,
                warning=warning,
            )
            return
        warning, cause = INVITE_FLOOD_WARNING, f"invite_flooded/{invite_id}/{reason}"
        if reason == JOIN_FAILURES:
            warning = JOIN_FAILURES_WARNING.format(
                limit=self.config.policy_max_failed_joins_per_invite,
                minutes=JOIN_FAILURE_WINDOW_SECS // 60,
            )
            cause += f"/{self.now()}"  # once per window, not once ever
        await self.emit(
            group_id,
            "invite_flooded",
            cause=cause,
            invite_id=invite_id,
            reason=reason,
            warning=warning,
        )

    def _load_join_ledger(self) -> ac.ReplayLedger:
        return replay.load(self.store, "join", self._join_capacity)

    def _forget_invite_requests(self, *invite_ids: str) -> None:
        """Revoked, expired or used up (stored ``exhausted``): all final, so
        step 1 refuses any copy of these invites' requests and the join
        ledger forgets them (SPEC 6.2). The in-memory ledger is rebuilt once
        for all of them, from at most its capacity of rows."""
        forgotten = 0
        for invite_id in invite_ids:
            forgotten += self.store.join_ledger_forget(invite_id)
        if forgotten:
            self._join_ledger = self._load_join_ledger()

    def _join_reserve(self, max_uses: int) -> int:
        """What one open invite can hold in the join ledger at most: its
        share for requests that weren't added, plus one entry per use for
        those being added or added (outside the share)."""
        return replay.join_quota(max_uses, self.config.policy_join_ledger_per_invite) + max_uses

    async def check_joins(self) -> None:
        """SPEC 4.3: a pending join whose invite was used up or revoked
        lapses with the "already used" warning, so a joiner beaten to a
        single-use link (perhaps by whoever intercepted it) hears about it.

        The relay marks an invite used only after the inviter sent the
        Welcome, so a join is failed only once the invite has been seen
        closed for :data:`JOIN_CLOSED_GRACE_SECS` (its Welcome may still be
        on the way). Runs on every (re)connect. Not while a Welcome waits for
        a locked keystore (``WELCOME_WAITING``): it may be this join's.
        """
        if self._welcome_waiting():
            return  # a Welcome came that the locked keyring kept us from opening
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
            self._forget_secret(f"join/{invite_id}")
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
            try:
                url = self.keystore.get(f"join/{invite_id}")
            except KeystoreError:
                # The keyring is locked: this Welcome waits (it is retried),
                # and no pending join lapses as "invite used" meanwhile.
                self.store.kv_set(WELCOME_WAITING, str(self.now()))
                raise
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
                self._forget_secret(f"join/{invite_id}")
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
            self._defer(lambda: self._forget_secret(f"join/{invite_id}"))
            await self.emit(group_id, "joined", invite_id=invite_id)
            await self.send_capabilities(group_id)
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
                self._release_inbound(item)
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
                # The task's updates held behind this one (its request for
                # input, its end) follow the human's decision (SPEC 9.3).
                for queued in self._task_holds(item):
                    if self.store.set_held_status(str(queued["hold_id"]), "approved"):
                        self._release_inbound(queued)
                        self._audit_hold(queued, "approved")
            self._audit_hold(item, "approved")
        self._notify_soon(events)
        self._delivery_wake.set()
        self._held_wake.set()
        self._pulse()
        return {"hold_id": hold_id, "group_id": group_id, "status": "approved"}

    def _release_inbound(self, item: dict[str, Any]) -> None:
        """Inside a transaction: an approved inbound message goes to the
        adapters, triggering the agent if it would have when it arrived."""
        group_id = str(item["group_id"])
        row = self.store.inbox_row(int(item["inbox_seq"] or 0))
        if row is None or row.state != "held" or row.delivery is None:
            return
        delivery = Delivery.from_json(row.delivery)
        self.store.set_inbox_state(row.seq, "pending")
        for key in [k for k in self._cursors if k[0] == group_id]:
            del self._cursors[key]
        self._cursor_gen[group_id] = self._cursor_gen.get(group_id, 0) + 1
        if delivery.addressed_to_me:
            self._triggered(group_id, delivery.hop, delivery.msg_id, delivery.sender.identity)
        self.safety.transcribe(group_id, "in", item["sender"], item["msg_id"], delivery.inner)

    def _task_holds(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        """The other held inbound updates of ``item``'s task (its sender's,
        in its group), in the order they arrived."""
        return [
            other
            for other in self.store.held_items()
            if other["hold_id"] != item["hold_id"]
            and other["direction"] == "in"
            and other["group_id"] == item["group_id"]
            and other["sender"] == item["sender"]
            and other["task_id"] == item["task_id"]
        ]

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
                # A task the human rejected (or let expire) ends there: the
                # updates held behind its first go with it (SPEC 9.3).
                for queued in self._task_holds(item):
                    events.extend(self._drop_hold(queued, status, code))
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
        """Hand pending inbox rows to the adapters: one worker per group and
        adapter with deliverable rows, so a slow or failing adapter holds up
        its own deliveries in its own group only, and strict order within
        each. A worker's crash or failure ends this worker too (the
        supervisor restarts it)."""
        workers: dict[tuple[str, str], asyncio.Task[None]] = {}
        woken = True
        try:
            while True:
                # Reap first: a worker that just found its group empty must not
                # keep a row that arrived since from getting a new worker.
                for key, worker in list(workers.items()):
                    if worker.done():
                        del workers[key]
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
                    await self._start_deliveries(workers)
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

    async def _start_deliveries(self, workers: dict[tuple[str, str], asyncio.Task[None]]) -> None:
        """A worker for every group and adapter with rows it can take that
        has none yet; and where a group's deliveries stand (held, stalled)."""
        events: list[Event] = []
        acks: list[str] = []
        pending = self.store.pending_groups()
        for group_id in {*pending, *self._flagged(STALLED_KEY)}:
            got, ack = self._check_stalled(group_id)
            events += got
            acks += ack
        for group_id in pending:
            events += self._check_held(group_id)
            names = self.adapter_names(group_id)
            if not names:
                continue  # held for its adapters, or none registered
            # Taken by every adapter it still goes to (its list changed):
            # done. Only when the list changed, not on every wake.
            if self._settled.get(("inbox", group_id)) != tuple(names):
                self._settled["inbox", group_id] = tuple(names)
                if self.store.settle_deliveries(group_id, names):
                    acks += self.store.take_unacked(group_id)
                    self._pulse()
            if self._gated(group_id):
                continue
            for name in names:
                if (group_id, name) not in workers:
                    workers[group_id, name] = asyncio.ensure_future(
                        self._deliver_group(group_id, self.adapters[name])
                    )
        for msg_id in acks:
            await self._ack(msg_id)
        self._notify_soon(events)

    def _framed(self, stored: Delivery, adapter: str) -> Delivery:
        """A recorded delivery as one adapter gets it now. Trust can change
        between reception and delivery (a human verified a member
        meanwhile): it is framed with the current state. One adapter is
        triggered; the others get it as context."""
        members = {m.identity: m for m in self.store.members(stored.group_id)}
        known = members.get(stored.sender.identity)
        sender = replace(
            stored.sender,
            verified=known is not None and known.verified,
            display_name=stored.sender.display_name if known is None else known.display_name,
        )
        delivery = replace(stored, sender=sender, trust_state=self._trust_state(stored.group_id))
        if delivery.addressed_to_me:
            mine = self._triggered_adapter(stored.group_id, delivery) == adapter
            delivery = replace(delivery, addressed_to_me=mine)
        return delivery

    async def _hand_over(
        self, adapter: Adapter, view: GroupView, delivery: Delivery
    ) -> DeliveryResult:
        """Give ``adapter`` one delivery. A message no adapter could write
        out (a string with a lone surrogate, recorded before the receive path
        refused them) fails alone for this adapter: acked, and the human
        hears (:meth:`_undeliverable`). Any other failure is retried."""
        if _encodable(delivery.to_json()):
            try:
                return await adapter.deliver(view, delivery.sender, delivery.to, delivery)
            except UnicodeError:
                pass
            except Exception as e:
                LOG.warning("adapter_deliver_failed", error=type(e).__name__)
                return DeliveryResult.RETRY
        await self._undeliverable(delivery, adapter.name)
        return DeliveryResult.ACK

    async def _undeliverable(self, delivery: Delivery, adapter: str) -> None:
        """A delivery that can't be written out fails alone for ``adapter``:
        the caller acks it, and the human hears (``message_failed``, at most
        once per sender, group and window, :meth:`_failed_report`)."""
        LOG.warning("delivery_unencodable", group=log.hid(delivery.group_id), adapter=adapter)
        key = (delivery.group_id, delivery.sender.identity)
        count = self._failed_report(key)
        if count is not None:
            await self.emit(
                delivery.group_id,
                "message_failed",
                cause=f"{delivery.msg_id}/{adapter}/unencodable",
                sender=delivery.sender.identity,
                msg_id=delivery.msg_id,
                message_kind=delivery.kind,
                reason="unencodable",
                count=count,
            )
        self._failed_counted(key, reported=count is not None)

    async def _deliver_group(self, group_id: str, adapter: Adapter) -> None:
        """One group's pending deliveries to one adapter, in order, until
        none is left that it can take now; a ``RETRY`` waits out this
        group and adapter's backoff."""
        backoff = Backoff(base=1.0, cap=300.0, rng=self.options.backoff_rng)
        key = (group_id, adapter.name)
        while True:
            gen = self._cursor_gen.get(group_id, 0)
            rows = self.store.pending_deliveries(
                group_id,
                limit=DELIVERY_BATCH,
                adapter=adapter.name,
                after=self._cursors.get(key, 0),
            )
            delivered, retry = 0, False
            for row in rows:
                # Each row, not each batch: the human may have taken this
                # adapter out of the group meanwhile, or the row was settled.
                names = self.adapter_names(group_id)
                if self._gated(group_id) or adapter.name not in names:
                    return
                if row.delivery is None or self.store.inbox_row_state(row.seq) != "pending":
                    continue
                delivery = self._framed(Delivery.from_json(row.delivery), adapter.name)
                view = self._view(delivery.group_id)
                if view is None:
                    continue
                self._keep_card(delivery)
                result = await self._hand_over(adapter, view, delivery)
                if result is DeliveryResult.ACK:
                    self.failpoints.hit("delivery.after_adapter")
                    # Recorded per adapter; done once every adapter has it.
                    if self.store.mark_delivered(row.seq, adapter.name, names):
                        await self._release(group_id)
                    if self._cursor_gen.get(group_id, 0) != gen:
                        # An older row became pending meanwhile: read again
                        # from the start, so it comes next.
                        delivered += 1
                        break
                    self._cursors[key] = row.seq
                    backoff.reset()
                    delivered += 1
                    self._pulse()
                else:
                    retry = True
                    break
            if retry:
                await self._sleep(backoff.next())
                await self._release(group_id)  # old pending messages stall it by age alone
            elif delivered == 0:
                return  # nothing left, or only rows that can't go out yet

    # -- outbox ---------------------------------------------------------------

    def _enqueue(self, kind: str, group_id: str | None, payload: dict[str, Any]) -> int:
        seq = self.store.enqueue(kind, group_id, payload, self.now())
        self._outbox_wake.set()
        return seq

    def _next_row(self) -> OutboxRow | None:
        """The first queued row that may run now. A group's rows (its lane,
        ``Store.outbox_lanes``) go out in the order they were queued, so while
        a lane's first row waits out its backoff the rest of that lane waits
        behind it, and every other lane goes on. While the relay's send
        budget is used up (``RateLimitedError``) nothing runs, and then the
        oldest row goes first."""
        now = self.clock.unix_millis() / 1000
        if now < self._throttled_until:
            return None
        if not self._postponed:
            return self.store.next_outbox()
        lanes = self.store.outbox_lanes()
        queued = {seq for seq, _ in lanes}
        for seq in [s for s in self._postponed if s not in queued]:
            del self._postponed[seq]  # finished some other way
        seen: set[str | None] = set()
        for seq, lane in lanes:
            if lane in seen:
                continue
            seen.add(lane)
            wait = self._postponed.get(seq)
            if wait is None or wait.at <= now:
                return self.store.outbox_row(seq)
        return None

    def _postpone(self, seq: int) -> None:
        """Run this row again after its own backoff (it stays queued)."""
        wait = self._postponed.get(seq)
        if wait is None:
            backoff = Backoff(base=1.0, cap=60.0, rng=self.options.backoff_rng)
            wait = self._postponed[seq] = Postponed(0.0, backoff)
        wait.at = self.clock.unix_millis() / 1000 + wait.backoff.next()

    def _refused_for_now(self, seq: int, group_id: str, code: str) -> None:
        """The relay answered row ``seq``'s own send with a "not now" code
        (``RETRYABLE_RELAY_ERRORS``). ``rate_limited`` raises
        ``RateLimitedError`` and isn't counted. Any other such answer counts toward the row's
        ``MAX_COMMIT_ATTEMPTS`` tries and raises ``TransientError``, so the
        row is postponed; it returns only when that answer used up the last
        try, and the caller fails the row. Nothing else counts: not storage
        or core errors, not epoch conflicts (``_run_commit`` rebuilds up to
        ``MAX_COMMIT_ATTEMPTS`` times per run), and not a cadence Update's
        answers, which count toward the Update's own row. The counts start
        again when the daemon does."""
        if code in PAUSE_RELAY_ERRORS:
            raise RateLimitedError(group_id, code) from None
        if code in WAIT_RELAY_ERRORS:
            raise TransientError(group_id, code) from None
        tries = self._refusals.get(seq, 0) + 1
        if tries >= MAX_COMMIT_ATTEMPTS:
            self._refusals.pop(seq, None)
            return
        self._refusals[seq] = tries
        raise TransientError(group_id, code) from None

    def _pause_outbox(self) -> None:
        """Pause the whole outbox: the next try waits out the shared
        backoff, which a send that goes through resets. Never less than the
        relay's rate window, so the first try after a pause finds room
        instead of doubling the next pause."""
        pause = max(RATE_WINDOW_SECS, self._throttle.next())
        self._throttled_until = self.clock.unix_millis() / 1000 + pause

    async def _outbox_idle(self) -> None:
        """Wait for a new row, for the end of a pause (``RateLimitedError``),
        or for the first postponed row's time."""
        if self.clock.unix_millis() / 1000 < self._throttled_until:
            due = self._throttled_until
        elif self._postponed:
            due = min(w.at for w in self._postponed.values())
        else:
            await self._outbox_wake.wait()
            return
        timer = asyncio.ensure_future(self.clock.sleep_until(due))
        waker = asyncio.ensure_future(self._outbox_wake.wait())
        await asyncio.sleep(0)
        self._pulse()  # announce the pause (tests advance time then)
        try:
            await asyncio.wait({timer, waker}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            await cancel_and_wait(timer, waker)

    async def _outbox(self) -> None:
        while True:
            row = self._next_row()
            if row is None:
                self._outbox_wake.clear()
                await self._outbox_idle()
                continue
            await self.link.wait_connected()
            try:
                state = await self._run_row(row)
            except NotConnectedError:
                continue
            except RateLimitedError:
                # The mailbox's send budget is used up: every lane waits,
                # and then the oldest row goes first.
                LOG.warning("outbox_throttled", kind=row.kind)
                self._pause_outbox()
                continue
            except TransientFailure:
                # The row stays queued and runs again from what it recorded,
                # after a backoff; a confirmed commit is finished from the
                # core's journal. Only its own lane waits for it.
                LOG.warning("outbox_transient", kind=row.kind)
                self._postpone(row.seq)
                continue
            except Exception:
                LOG.exception("outbox_failed", kind=row.kind)
                state = "failed"
            self._postponed.pop(row.seq, None)
            self._refusals.pop(row.seq, None)
            if state == "done":
                self._throttle.reset()
            msg_id = row.payload.get("msg_id")
            event = None
            with self.store.tx():
                self.store.update_outbox(row.seq, state=state)
                if state == "failed" and row.kind == "app" and row.payload.get("floor"):
                    # Its write was taken when it was sealed: take it back,
                    # in the same transaction (FloorService.reconcile).
                    event = self.floor.unsent(str(row.group_id), str(msg_id))
            if event is not None:
                await self._notify(event)
            code = self._fail_codes.pop(row.seq, "failed")
            if state == "failed":
                await self._row_failed(row, code)
            self._pulse()

    async def _row_failed(self, row: OutboxRow, code: str) -> None:
        """Tell whoever waits for a row that failed for good."""
        if row.kind == "app" and row.payload.get("sas"):
            # A ceremony message: the run's, never the agent's to hear.
            self.sas.on_send_failed(row.payload["sas"], code)
            return
        if row.group_id is None:
            return
        # Tell the caller: it holds a msg_id (or an intent) that will never
        # be delivered.
        if row.kind == "app":
            await self.emit(
                row.group_id, "send_failed", msg_id=row.payload.get("msg_id"), code=code
            )
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
            return await self.groups.run_proposal(row, group)
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
            if e.code in PAUSE_RELAY_ERRORS:
                # The mailbox's send rate (group.create, join), or the
                # relay's storage: not now, for the whole outbox.
                raise RateLimitedError(None, e.code) from None
            if e.code in WAIT_RELAY_ERRORS:
                # The mailbox's budget (a join): this row waits.
                raise TransientError(None, e.code) from None
            if frame.get("t") == "group.create":
                group_id = str(frame.get("group_id"))
                if e.code in RETRYABLE_RELAY_ERRORS:
                    # Not now (`internal`): the same frame again after a
                    # backoff, until the row's tries run out. A repeat the
                    # relay already took is answered `accepted` (SPEC 8.3).
                    self._refused_for_now(row.seq, group_id, e.code)
                await self.on_group_create_refused(group_id, e.code)
            env = frame.get("env")
            if isinstance(env, dict) and isinstance(env.get("group_id"), str):
                # A group-bound send queued as a frame (a leave proposal).
                await self.on_group_refused(env["group_id"], e.code)
            if frame.get("t") == "join":
                invite_id = str(frame.get("invite_id"))
                self.store.finish_join(invite_id, "failed")
                self._forget_secret(f"join/{invite_id}")
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
                    self._forget_secret(f"invite/{invite['invite_id']}")
                    self._forget_invite_requests(str(invite["invite_id"]))
        return "done"

    def _sas_unsealable(self, sas: dict[str, Any] | None, gid: bytes, epoch: int) -> str | None:
        """Why a queued ceremony message isn't sealed now, if it isn't."""
        if sas is None:
            return None
        if self.sas.stale(sas, epoch):
            return "sas_stale"  # dropped across an epoch change, never sealed in a new one
        if self.client.has_pending_proposals(gid):
            # MLS seals nothing while a proposal waits for its commit: the
            # run waits for it (SPEC 11.3).
            return PROPOSAL_PENDING
        return None

    async def _run_app(self, row: OutboxRow, group: GroupRow) -> str:
        if group.out_of_sync:
            self._fail_codes[row.seq] = "out_of_sync"
            return "failed"
        gid = unb64(group.group_id)
        payload = dict(row.payload)
        for _ in range(MAX_COMMIT_ATTEMPTS):
            if "env" not in payload:
                sas = payload.get("sas")
                if (
                    sas is None
                    and self.groups.update_due(group)
                    and not self.sas.defer(group.group_id)
                ):
                    # SPEC §3.1: renew keys just before the next send. Not for
                    # a ceremony message, and deferred (at most 600 s) while
                    # a SAS run is under way (SPEC 11.3).
                    group = await self._cadence_update(row, payload, group)
                epoch = self.client.epoch(gid)
                unsealable = self._sas_unsealable(sas, gid, epoch)
                if unsealable is not None:
                    self._fail_codes[row.seq] = unsealable
                    return "failed"
                event = None
                with self.store.tx():
                    if payload.get("floor"):
                        # Taken as it is sealed, in this epoch (FloorService.seal).
                        event = self.floor.seal(group.group_id, payload, epoch)
                    inner = canonical(payload["inner"])
                    payload["env"] = {
                        "v": 0,
                        "kind": "application",
                        "group_id": group.group_id,
                        "epoch": epoch,
                        "msg_id": payload["msg_id"],
                        "sender": self.mailbox,
                        "ct": b64(self.client.seal(gid, inner)),
                    }
                    self.store.update_outbox(row.seq, payload=payload)
                self.sas.on_sealed(sas)
                if event is not None:
                    await self._notify(event)
            try:
                await self._request({"t": "send", "env": payload["env"]}, payload["msg_id"])
            except RelayError as e:
                if e.code == "epoch_conflict":
                    payload.pop("env")  # too old an epoch: seal again
                    continue
                if e.code in RETRYABLE_RELAY_ERRORS:
                    # Not now: the same envelope again after a backoff.
                    self._refused_for_now(row.seq, group.group_id, e.code)
                    self._fail_codes[row.seq] = "attempts_exhausted"
                    return "failed"
                LOG.info("send_failed", code=e.code)
                self._fail_codes[row.seq] = e.code
                await self.on_group_refused(group.group_id, e.code)
                return "failed"
            self.store.bump_messages(group.group_id)
            if payload.get("floor"):
                self.floor.confirmed(group.group_id, str(payload["msg_id"]))
            if payload.get("sas"):
                self.sas.on_sent(payload["sas"])
            return "done"
        self._fail_codes[row.seq] = "attempts_exhausted"
        return "failed"

    def _build(self, gid: bytes, intent: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911
        t = intent["type"]
        if t == "update":
            return self.client.update(gid)
        if t == "proposals":
            return self.client.commit_pending_proposals(gid)
        if t == "remove":
            return self.client.remove(gid, intent["identity"])
        if t == "remove_instances":
            return self.client.remove_instances(gid, list(intent["instances"]))
        if t in POLICY_INTENTS:
            # Applied to the policy in force now, so a rebuild after an
            # epoch conflict keeps a concurrent change (docs/groups.md).
            return self.groups.build_policy_commit(gid, intent)
        if t == "knock_add":
            return self.knocks.build_add(gid, intent)
        if t == "add":
            approval = self.store.approval(intent["request_id"])
            invite = None if approval is None else self.store.invite(approval["invite_id"])
            obj = None if invite is None else self._invite_object(invite)
            if approval is None or obj is None:
                msg = "approval or invite no longer available"
                raise DaemonError("gone", msg)
            self._check_approval_sender(approval)
            verified = self.client.verify_join_request(
                unb64(approval["request"]), obj, approval["mailbox_id"]
            )
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
            self._refusals.pop(update.seq, None)
        payload.pop("update_row", None)
        self.store.update_outbox(row.seq, payload=payload)
        return self.store.group(group.group_id) or group

    async def _run_commit(self, row: OutboxRow, group: GroupRow) -> str:
        """Build, send and confirm the row's commit. A cadence Update runs
        inside its message's row, and its refusals count toward its own row."""
        gid = unb64(group.group_id)
        payload = dict(row.payload)
        intent = payload["intent"]
        for _ in range(MAX_COMMIT_ATTEMPTS):
            current = self.store.group(group.group_id)
            if current is None or current.status != "active" or current.out_of_sync:
                self._fail_codes[row.seq] = "out_of_sync"
                # An approval waiting on this Add fails now, not never.
                reason = None if current is None else current.out_of_sync_reason
                self._fail_intent(intent, reason or "out_of_sync")
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
                        # doesn't consume its msg_id). After a backoff.
                        LOG.info("commit_retry", code=e.code)
                        self._refused_for_now(row.seq, group.group_id, e.code)
                        break
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
                        await self.on_group_refused(group.group_id, e.code)
                        return "failed"
                    LOG.info("epoch_conflict", group=log.hid(group.group_id))
                    # In the row: every lane waits, usually only until the
                    # winning commit (already on its way) is processed.
                    await self._await_epoch(group.group_id, built_epoch)
                    continue
                await self._confirm_own(gid, group.group_id, env)
                payload["confirmed"] = True
                self.store.update_outbox(row.seq, payload=payload)
            if not payload.get("consume_queued") and not await self._commit_followups(
                row, group, intent, payload
            ):
                return "failed"
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
            # Nothing left to do: the leaves were committed, or the policy
            # already says what the change asked for.
            benign = getattr(e, "kind", None) == "nothing_to_commit" or (
                isinstance(e, DaemonError) and e.code == UNCHANGED
            )
            refused = getattr(e, "kind", None) in ("unauthorized", "not_permitted") or (
                isinstance(e, DaemonError) and e.code == "not_permitted"
            )
            if not benign:
                LOG.info("commit_not_built", intent=intent["type"], reason=str(e)[:80])
            code = BENIGN if benign else "not_permitted" if refused else "not_built"
            self._fail_codes[row.seq] = code
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
    ) -> bool:
        """After an Add is confirmed: send the Welcome, then consume the
        invite. Each step is recorded in the row, so a retry after a dropped
        connection neither sends a second Welcome nor consumes a second use.
        An approved knock's Add has a Welcome and no use to consume. False:
        the Welcome can't go out, and the joiner is removed again."""
        if intent["type"] == "knock_add":
            await self.knocks.after_add(row.seq, group, intent, payload)
            return True
        if intent["type"] != "add":
            return True
        approval = self.store.approval(intent["request_id"])
        if approval is None:
            return True
        if "welcome" in payload and not payload.get("welcome_sent"):
            if self.now() >= self._welcome_deadline(approval):
                # Checked before every try: a Welcome sent this late could
                # reach a joiner that has stopped waiting.
                LOG.info("welcome_not_sent", code="too_late")
                self._welcome_failed(row, group, intent, approval)
                return False
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
            try:
                await self._request({"t": "send", "env": welcome}, str(welcome["msg_id"]))
            except RelayError as e:
                if e.code in RETRY_WELCOME:
                    # Not now: the same Welcome again after a backoff (the
                    # whole outbox's, for the mailbox's rate_limited), until
                    # the deadline above.
                    LOG.info("welcome_retry", code=e.code)
                    if e.code in PAUSE_RELAY_ERRORS:
                        raise RateLimitedError(group.group_id, e.code) from None
                    raise TransientError(group.group_id, e.code) from None
                LOG.info("welcome_not_sent", code=e.code)
                self._welcome_failed(row, group, intent, approval)
                return False
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
        return True

    def _welcome_deadline(self, approval: dict[str, Any]) -> int:
        """The last moment to send the joiner its Welcome: the joiner stops
        waiting at its invite's expiry plus the grace for a Welcome in flight
        (:meth:`expire`), and the last one goes ``WELCOME_MARGIN_SECS``
        before that."""
        invite = self.store.invite(str(approval["invite_id"]))
        if invite is None:
            return 0
        return int(invite["expires_at"]) + JOIN_CLOSED_GRACE_SECS - WELCOME_MARGIN_SECS

    def _welcome_failed(
        self, row: OutboxRow, group: GroupRow, intent: dict[str, Any], approval: dict[str, Any]
    ) -> None:
        """The Add is in, but its Welcome can't reach the joiner: the
        approval fails (releasing its use of the invite) and the instance the
        Add put in the group is removed again."""
        self._fail_codes[row.seq] = WELCOME_NOT_SENT
        with self.store.tx():
            self._fail_intent(intent, WELCOME_NOT_SENT)
            instance = approval.get("instance_id")
            if instance:
                self._enqueue(
                    "commit",
                    group.group_id,
                    {
                        "intent": {
                            "type": "remove_instances",
                            "identity": str(approval["identity"]),
                            "instances": [str(instance)],
                        }
                    },
                )

    async def send_capabilities(self, group_id: str) -> None:
        """SPEC 7.3: right after joining, tell the group what this
        instance's adapters accept. Whatever the adapters (a webhook or SSE
        agent has no Agent Card), it is also this instance's first send in
        the group, and only from then on does the relay count the group's
        traffic to it as member traffic (SPEC 8.3, "Limits"). `adapters`
        stays empty: the operator's adapter names are its own business."""
        accepts: list[str] = []
        for name in self.adapter_names(group_id):
            for kind in self.adapters[name].capabilities().accepts:
                if kind not in accepts:
                    accepts.append(kind)
        try:
            self.send_message(
                group_id,
                {"adapters": [], "accepts": accepts},
                kind="control.capabilities",
                internal=True,
            )
        except DaemonError as e:
            LOG.warning("capabilities_not_sent", code=e.code)

    async def _send_card(self, group_id: str, to: list[str]) -> None:
        # The first of the group's adapters that has an Agent Card speaks for it.
        cards_ = (a.capabilities().agent_card for a in self.targets(group_id))
        card = next((c for c in cards_ if c is not None), None)
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

    def create_group(self, name: str, purpose: str, policy: dict[str, Any] | None = None) -> str:
        """Create a group this identity owns. ``policy`` holds the fields of
        a policy change (:func:`~agentconnect.runtime.groups.policy_changes`)
        over the SPEC 9.1 defaults, set in the group's first epoch: no extra
        commit, so nothing changes before anyone joins. **Human-only** beyond
        ``require_verified`` (``AgentApi.create_group``)."""
        try:
            if policy is not None and len(policy) > 0:
                gid = self.client.create_group(name, purpose, self.groups.initial_policy(policy))
            else:
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

    async def create_invite(  # noqa: PLR0913
        self,
        group_id: str,
        ttl_secs: int = 86_400,
        max_uses: int = 1,
        inviter_name: str | None = None,
        *,
        replica: bool = False,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Create and register an invite. ``replica`` (**human-only**, the
        API checks the token) makes it an invite for another instance of
        this identity: it may be created whatever ``invite`` says, and a
        join request from any other identity is dropped (SPEC 9.2, 9.4).
        ``instance`` pins it to the one instance id that `identity import`
        printed: a request from any other instance is dropped too, and only
        a pinned replica invite is ever approved automatically."""
        if instance is not None:
            if not replica:
                raise DaemonError(
                    "bad_request", "an instance pin needs a replica invite (--replica)"
                )
            if not INSTANCE_ID.fullmatch(instance):
                raise DaemonError("bad_request", "instance must be 16 lowercase hex characters")
            if instance == self.instance.instance_id_hex:
                msg = "that is this instance: pin the replica's, which `identity import` printed"
                raise DaemonError("bad_request", msg)
        group = self._group_or_raise(group_id)
        if group.out_of_sync:
            # Its commits can't land, so no one could join through it.
            raise DaemonError(
                "out_of_sync",
                f"the group is out of sync ({group.out_of_sync_reason}): start a new group",
            )
        policy = group.policy
        allowed = {
            "owner": {policy.get("owner")},
            "admins": {policy.get("owner"), *policy.get("admins", [])},
        }.get(str(policy.get("invite")))
        if not replica and allowed is not None and self.me not in allowed:
            raise DaemonError("forbidden", "the group policy does not let this identity invite")
        reserved = sum(
            self._join_reserve(int(i["max_uses"]))
            for status in ("open", "registering")
            for i in self.store.invites(status)
        )
        if reserved + self._join_reserve(max_uses) > self._join_capacity:
            # SPEC 6.2 "Replays": the open invites' shares can't fill the join
            # ledger, which every invite shares.
            raise DaemonError(
                "too_many_invites",
                "too many open invites: revoke the ones you no longer need",
            )
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
            invite_id,
            group_id,
            invite.expires_at,
            max_uses,
            self.now(),
            status="registering",
            replica=replica,
            instance=instance,
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
            self._forget_secret(f"invite/{invite_id}")
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
        self._forget_secret(f"invite/{invite_id}")
        self._forget_invite_requests(invite_id)

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
                    for k in (
                        "request_id",
                        "group_id",
                        "identity",
                        "display_name",
                        "received_at",
                        "mailbox_id",
                        # None for a request stored before it was recorded.
                        "instance_id",
                    )
                }
                | {
                    "kind": "join",
                    "display_name_verified": False,
                    "fingerprint": ac.fingerprint(ac_identity_key(a["identity"])),
                    # Requests that claim this identity on this invite, this
                    # one included: more than one means someone else may
                    # hold one of its KeyPackages (docs/groups.md).
                    "identity_requests": self._identity_requests(
                        str(a["invite_id"]), str(a["identity"])
                    ),
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
        self._check_approval_sender(approval)
        if self.now() - approval["received_at"] > APPROVAL_TIMEOUT_SECS:
            self.store.set_approval_status(request_id, "expired")
            raise DaemonError("expired", "the approval window (1 hour) has passed")
        invite = self.store.invite(approval["invite_id"])
        if invite is None or self._invite_closed(invite):
            self.store.set_approval_status(request_id, "rejected")
            raise DaemonError("invite_not_open", "the invite has no uses left or expired")
        room = self.groups.room(str(approval["group_id"]))
        if room is not None and room < 1:
            # The core would refuse the Add (SPEC 9.2). The request stays
            # pending: removing a member makes room before it lapses.
            msg = "the group is full (its policy's max_members): remove someone first"
            raise DaemonError(GROUP_FULL, msg)
        self.store.set_approval_status(request_id, "approving")
        self._enqueue(
            "commit", approval["group_id"], {"intent": {"type": "add", "request_id": request_id}}
        )

    def _check_approval_sender(self, approval: dict[str, Any]) -> None:
        """A join approval's request came from the mailbox it names (SPEC 6.2
        step 3): its inbox row is keyed by the envelope's sender and the
        request id (the envelope's msg_id). A daemon before this check stored
        approvals without it, so one built by a link holder from someone
        else's KeyPackage has its row under the holder's mailbox: it expires
        instead of being added."""
        sender, request_id = str(approval["mailbox_id"]), str(approval["request_id"])
        if self.store.inbox_state(sender, request_id) is not None:
            return
        self.store.set_approval_status(request_id, "expired")
        msg = "the request didn't come from the mailbox it names"
        raise DaemonError("expired", msg)

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

    def queue_message(  # noqa: PLR0912, PLR0913
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
        floor_grant: bool = False,
        daemon_control: bool = False,
        instance: str | None = None,
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
        message, and only the members listed are triggered.

        ``floor_grant``: a ``control.floor`` that ``FloorService.grant``
        checked; the agent's count against its send rate. ``daemon_control``:
        a control the daemon sends on its own, not on anyone's behalf (the
        floor copy for newcomers): internal, hop 0, replying to nothing.

        ``instance`` (SPEC 9.4): of the identities the message triggers,
        only this instance is (:func:`with_instance`). Every instance still
        receives and decrypts it."""
        group = self._group_or_raise(group_id)
        internal = internal or daemon_control
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
        if kind == "control.floor" and not (internal or floor_grant):
            # The grant checks the role first (FloorService.grant).
            raise DaemonError("bad_request", "grant the floor with POST /v0/groups/{gid}/floor")
        body = with_instance(kind, body, instance)
        if daemon_control:
            hop, refs = 0, []
        elif origin == "human":
            hop, refs = 0, list(reply_to or [])[:MAX_REPLY_TO]
        else:
            hop, refs = self._reply_hop(
                group.group_id,
                reply_to or self._task_request(group.group_id, kind, body, addressee),
            )
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
                grant=floor_grant,
                trigger=self._own_trigger(group.group_id, inner) is not None,
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
        payload: dict[str, Any] = {"inner": inner, "msg_id": msg_id}
        if kind == "control.floor":
            payload["floor"] = True  # this instance's own: taken when sealed
        with self.store.tx():
            self.store.record_hop(group.group_id, msg_id, hop, self.now())
            self._record_task_links(group, msg_id, kind, inner, refs)
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
        instance: str | None = None,
    ) -> SendReceipt:
        """What adapters get through ``on_outbound``: agent-originated only.
        A group the agent can't see yet (``hidden_from_agent``) is not found.
        ``reply_to`` names the ``msg_id``s of the deliveries this answers;
        ``addressee`` names who is triggered (SPEC 9.3) and ``instance``
        which of their instances (SPEC 9.4). The answer is the
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
            instance=instance,
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
        self.groups.remove_member(group_id, identity)

    def remove_instances(self, group_id: str, identity: str, instance_ids: list[str]) -> None:
        self.groups.remove_instances(group_id, identity, instance_ids)

    def set_policy(self, group_id: str, **changes: Any) -> str:
        """Commit a change of policy fields, as they sit in the policy:
        :meth:`GroupService.change_policy`."""
        return self.groups.change_policy(group_id, {"type": "policy", "changes": changes})

    def change_policy(self, group_id: str, fields: dict[str, Any]) -> str:
        """**Human-only** beyond raising ``require_verified``: the fields of
        ``POST /v0/groups/{gid}/policy`` (``groups.policy_changes``)."""
        return self.set_policy(group_id, **self.groups.policy_changes_of(fields))

    def grant_floor(
        self, group_id: str, holder: str | None, *, origin: str = "agent"
    ) -> dict[str, Any]:
        """Grant the floor of a ``moderated`` group to a member, or release
        it (``None``): :meth:`FloorService.grant`. Either token: only the
        effective moderator or the owner may, and a grant triggers nobody."""
        return self.floor.grant(group_id, holder, origin=origin)

    def set_role(self, group_id: str, identity: str, role: str) -> str:
        """**Human-only.** Make a member an admin or a plain member."""
        return self.groups.set_role(group_id, identity, role)

    def transfer_ownership(self, group_id: str, identity: str, keep_admin: bool = True) -> str:
        """**Human-only.** Hand ownership over to another member."""
        return self.groups.transfer_to(group_id, identity, keep_admin=keep_admin)

    async def leave(self, group_id: str) -> str:
        status = await self.groups.leave(group_id)
        self.store.kv_set(f"close_pending/{group_id}", "")
        return status

    def close_pending(self, group_id: str) -> bool:
        """Whether the owner's close (SPEC 7.3) waits for the human's answer
        in this group: until then the agent may not leave it."""
        return bool(self.store.kv_get(f"close_pending/{group_id}"))

    def stay(self, group_id: str) -> None:
        """**Human-only.** The human's answer to the owner's close: it stays
        in the group, and the agent may leave on its own judgement again."""
        group = self.store.group(group_id)
        if group is None or group.status != "active":
            raise DaemonError("not_found", "no such active group")
        self.store.kv_set(f"close_pending/{group_id}", "")

    def mark_verified(
        self, group_id: str, identity: str, verified: bool = True, run: str | None = None
    ) -> None:
        """**Human-only.** Records that the human compared the code of SAS
        run ``run`` with this member over an independent channel, and read
        the same code (SPEC 11.5). Never reachable by agents: an agent that
        could mark verification would defeat the SAS check, which exists
        precisely to catch a relay or link thief in the middle.

        ``verified=False`` clears the flag and needs no run."""
        self._group_or_raise(group_id)
        if identity == self.me:
            raise DaemonError("not_found", "no such member")
        if verified:
            if run is None:
                raise DaemonError("bad_request", "marking verified needs the run compared")
            try:
                self.sas.confirm(group_id, run, identity)
            except SasError as e:
                raise DaemonError(e.code, str(e)) from e
        elif not self.store.set_verified(group_id, identity, False):
            raise DaemonError("not_found", "no such member")
        self._delivery_wake.set()
        self._pulse()

    def sas_start(
        self,
        group_id: str,
        identity: str,
        instance: str | None = None,
        acknowledge: bool = False,
    ) -> dict[str, Any]:
        """**Human-only.** Start a SAS run with ``identity`` (SPEC 11.3)."""
        if instance is not None and not _instance_id(instance):
            raise DaemonError("bad_request", f"instance {INSTANCE_ID_RULE}")
        try:
            return self.sas.start(group_id, identity, instance=instance, acknowledge=acknowledge)
        except SasError as e:
            raise DaemonError(e.code, str(e)) from e

    def sas_run(self, group_id: str, run: str) -> dict[str, Any]:
        """**Human-only.** A SAS run as its human sees it (SPEC 11.5)."""
        try:
            return self.sas.view(group_id, run)
        except SasError as e:
            raise DaemonError(e.code, str(e)) from e

    def sas_cancel(self, group_id: str, run: str) -> dict[str, Any]:
        """**Human-only.** The human gives a run up (SPEC 11.3)."""
        try:
            return self.sas.cancel(group_id, run)
        except SasError as e:
            raise DaemonError(e.code, str(e)) from e

    async def sas_labels(
        self, group_id: str, run: str, self_label: str, peer_label: str
    ) -> dict[str, Any]:
        """**Human-only.** The other human reads labels that don't mirror
        ours (SPEC 11.5): a warning, and codes that differ unless replicas
        paired crosswise explain the labels."""
        if not all(re.fullmatch(r"[0-9a-f]{8}", x) for x in (self_label, peer_label)):
            raise DaemonError("bad_request", "labels are 8 lowercase hex characters")
        try:
            out = self.sas.labels(group_id, run, (self_label, peer_label))
        except SasError as e:
            raise DaemonError(e.code, str(e)) from e
        if out["outcome"] == "mismatch":
            out["status"] = await self.sas_mismatch(group_id, run)
        return out

    def sas_peer_started(self, group_id: str, run: str) -> dict[str, Any]:
        """**Human-only.** The human says the peer started its side."""
        try:
            return self.sas.peer_started(group_id, run)
        except SasError as e:
            raise DaemonError(e.code, str(e)) from e

    async def sas_mismatch(self, group_id: str, run: str | None = None) -> str:
        """**Human-only.** The codes differ, or the human takes the mismatch
        action (SPEC 11.5): always accepted. See
        :meth:`GroupService.sas_mismatch`."""
        self.sas.mismatch(group_id, run)
        return await self.groups.sas_mismatch(group_id, run)

    async def _transfer_ownership(self, group: GroupRow) -> dict[str, Any] | None:
        return await self.groups.transfer_ownership(group)

    def group_info(self, group_id: str) -> dict[str, Any]:
        return self.groups.group_info(group_id)

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
        the human (the agent doesn't learn of incoming knocks). For the agent
        nothing counts a group hidden from it (an approved knock's group
        before the knocker is in): not the groups, ``out_of_sync``, the
        queues or the pending joins."""
        groups = self.store.groups()
        pending = self.approvals() if human else self.join_approvals()
        outbox, inbox = self.store.outbox(), self.store.pending_deliveries()
        if not human:
            hidden = {g.group_id for g in groups if g.hidden}
            groups = [g for g in groups if g.group_id not in hidden]
            pending = [a for a in pending if a.get("group_id") not in hidden]
            outbox = [r for r in outbox if r.group_id not in hidden]
            inbox = [r for r in inbox if r.group_id not in hidden]
        return {
            "identity": self.me,
            "fingerprint": self.identity.fingerprint,
            "instance_id": self.instance.instance_id_hex,
            "mailbox_id": self.mailbox,
            "relay": {"url": self.config.relay_url, "connected": self.link.connected},
            "keystore": self.keystore.kind,
            "groups": len([g for g in groups if g.status == "active"]),
            "out_of_sync": [g.group_id for g in groups if g.out_of_sync],
            "outbox_queued": len(outbox),
            "inbox_pending": len(inbox),
            "pending_approvals": len(pending),
            "held_messages": len(self.held_messages()),
        }


def ac_identity_key(identity: str) -> bytes:
    """IK.pub from an ``ac:v0:`` identifier."""
    return unb64(identity.removeprefix("ac:v0:"))
