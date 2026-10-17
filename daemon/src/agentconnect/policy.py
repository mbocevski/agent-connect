"""The safety policy: one decision for every message, made before any adapter
sees it (SPEC §10).

Encryption keeps the relay out. It does nothing about a member that is
malicious or confused, so every decrypted message goes through
:meth:`SafetyPolicy.inbound` and every message the agent sends through
:meth:`SafetyPolicy.outbound`. Each returns a :class:`Decision`:

* ``deliver``: hand it to the adapter, triggering the agent;
* ``deliver_as_context``: hand it over with ``addressed_to_me: false``
  (not for this member, or past the loop guard, SPEC §9.3 and §10.3);
* ``hold_for_approval``: keep it until the human approves it with the human
  token (``require_approval``), or drop it when the hold expires;
* ``drop``: never deliver (or send) it, with a reason.

The daemon calls these in exactly one place each (``Daemon._make_delivery``
when a message is received, ``Daemon.queue_message`` when one is sent) and
records the decision with the message. Adapters only ever see what was
recorded as delivered, and adapters can only send through
``Daemon.adapter_send``, so neither direction can bypass the policy.

Settings come from ``[policy]`` in ``config.toml`` (:data:`KNOBS`), with
per-group overrides and, for the limits, per-sender overrides, which the
human sets through the local API (``POST /v0/groups/{gid}/safety``) or
``agentconnect safety set``. The §10.4 verification gate (``require_verified``)
is part of the group's MLS policy instead, and holds deliveries until the
human has verified every member (:func:`verification_holds`).

Every decision is written to the audit log: who, when, kind, size, decision
and reason, never the body. With ``transcript`` on, the group's delivered
and sent messages are also kept in full. Both live in the encrypted daemon
database with bounded retention.
"""

from __future__ import annotations

import enum
import math
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields, replace
from typing import TYPE_CHECKING, Any

from agentconnect.clock import Clock, unix_seconds
from agentconnect.limits import (
    DEFAULT_MAX_FILE_BYTES,
    GROUP_PER_MINUTE,
    IDENTITY_RATE_MULTIPLE,
    MAX_MESSAGE_BYTES,
    SENDER_PER_MINUTE,
    TASK_PER_MINUTE,
    Limits,
    RateLimiter,
    content_problem,
)
from agentconnect.schemas import NON_CONTENT_KINDS

if TYPE_CHECKING:
    from agentconnect.store import Store

# SPEC 7.3: controls only a human-originated message may carry.
HUMAN_ONLY_KINDS = frozenset({"control.resume"})
# What require_approval holds: content from (or for) an agent. Controls and
# Agent Cards carry no content (agentconnect.schemas) and pass, so membership,
# the loop guard and capabilities keep working.
HOLDABLE_KINDS = frozenset(
    {"a2a.message", "a2a.task_status", "a2a.task_artifact", "a2a.task_cancel"}
)
# Drop reasons that count against the sender (an unknown kind doesn't: SPEC
# 7.2 makes ignoring it the forward-compatible behaviour).
VIOLATIONS = frozenset(
    {
        "too_large",
        "malformed",
        "part_kind",
        "file_too_large",
        "rate_limited",
        "not_human",
        "not_owner",
    }
)
APPROVAL_MODES = ("off", "inbound", "outbound", "both")
DAY_SECS = 86_400
PURGE_EVERY_SECS = 60
MAX_AUDIT_ROWS = 100_000
DEFAULT_VIOLATION_THRESHOLD = 10
DEFAULT_VIOLATION_WINDOW_SECS = 600
DEFAULT_AUDIT_RETENTION_DAYS = 30


class Verdict(enum.StrEnum):
    DELIVER = "deliver"
    DELIVER_AS_CONTEXT = "deliver_as_context"
    HOLD_FOR_APPROVAL = "hold_for_approval"
    DROP = "drop"


@dataclass(frozen=True)
class Decision:
    """What happens to one message, and why (``reason`` is empty for a plain
    ``deliver``)."""

    verdict: Verdict
    reason: str = ""

    @property
    def delivered(self) -> bool:
        """Whether the adapter gets it now (triggering or as context)."""
        return self.verdict in (Verdict.DELIVER, Verdict.DELIVER_AS_CONTEXT)


DELIVER = Decision(Verdict.DELIVER)


def as_context(reason: str) -> Decision:
    return Decision(Verdict.DELIVER_AS_CONTEXT, reason)


def hold(reason: str) -> Decision:
    return Decision(Verdict.HOLD_FOR_APPROVAL, reason)


def drop(reason: str) -> Decision:
    return Decision(Verdict.DROP, reason)


class PolicyError(ValueError):
    """An invalid setting."""


@dataclass(frozen=True)
class Knob:
    """One setting: its ``[policy]`` key, type, default and bounds."""

    name: str
    kind: type
    default: Any
    doc: str
    lo: int = 0
    hi: int = 0
    choices: tuple[str, ...] = ()
    per_sender: bool = False  # may be overridden for one sender

    def check(self, value: Any) -> Any:
        """``value`` if it is valid for this knob, else :class:`PolicyError`."""
        if not isinstance(value, self.kind) or (self.kind is int and isinstance(value, bool)):
            msg = f"{self.name} must be {self.kind.__name__}"
            raise PolicyError(msg)
        if self.kind is int and not self.lo <= value <= self.hi:
            msg = f"{self.name} must be {self.lo}..{self.hi}"
            raise PolicyError(msg)
        if self.choices and value not in self.choices:
            msg = f"{self.name} must be one of {', '.join(self.choices)}"
            raise PolicyError(msg)
        return value


KNOBS: tuple[Knob, ...] = (
    Knob(
        "max_message_bytes",
        int,
        MAX_MESSAGE_BYTES,
        "Largest inner message accepted, in bytes (1024 to 262144, the SPEC 10.2 default; "
        "never more).",
        1024,
        MAX_MESSAGE_BYTES,
        per_sender=True,
    ),
    Knob(
        "sender_per_minute",
        int,
        SENDER_PER_MINUTE,
        "Messages a minute accepted from one sender instance (1 to 30, the SPEC 10.2 "
        "default; never more).",
        1,
        SENDER_PER_MINUTE,
        per_sender=True,
    ),
    Knob(
        "group_per_minute",
        int,
        GROUP_PER_MINUTE,
        "Messages a minute accepted from the whole group (1 to 120, the SPEC 10.2 "
        "default; never more).",
        1,
        GROUP_PER_MINUTE,
    ),
    Knob(
        "identity_rate_multiple",
        int,
        IDENTITY_RATE_MULTIPLE,
        "All instances of one identity together may send this many times "
        "`sender_per_minute` (1 to 3, the SPEC 10.2 default), so replicas can't multiply "
        "an identity's budget.",
        1,
        IDENTITY_RATE_MULTIPLE,
    ),
    Knob(
        "task_per_minute",
        int,
        TASK_PER_MINUTE,
        "Updates a minute accepted for one task of one sender instance (1 to 300, the "
        "SPEC 10.2 default; never more).",
        1,
        TASK_PER_MINUTE,
        per_sender=True,
    ),
    Knob(
        "allow_files",
        bool,
        False,
        "Accept A2A `file` parts. Off by default: only `text` and `data` parts pass.",
        per_sender=True,
    ),
    Knob(
        "max_file_bytes",
        int,
        DEFAULT_MAX_FILE_BYTES,
        "Largest `file` part accepted when `allow_files` is on, in bytes of its JSON "
        "(1 to 262144).",
        1,
        MAX_MESSAGE_BYTES,
        per_sender=True,
    ),
    Knob(
        "frame_text",
        bool,
        True,
        "Ask text-oriented consumers to show the SPEC 10.1 notice in front of the text "
        "(`frame_text` in webhook and SSE payloads; the SDK's `msg.text`).",
    ),
    Knob(
        "require_approval",
        str,
        "off",
        "Hold agent messages until the human approves them: `off`, `inbound`, `outbound` "
        "or `both`.",
        choices=APPROVAL_MODES,
    ),
    Knob(
        "approval_ttl_secs",
        int,
        3600,
        "How long a held message waits for approval before it is dropped (60 to 604800).",
        60,
        604_800,
    ),
    Knob(
        "violation_threshold",
        int,
        DEFAULT_VIOLATION_THRESHOLD,
        "Policy violations by one sender within `violation_window_secs` that raise a "
        "`repeated_violations` event (1 to 1000).",
        1,
        1000,
    ),
    Knob(
        "violation_window_secs",
        int,
        DEFAULT_VIOLATION_WINDOW_SECS,
        "The window violations are counted over (60 to 86400).",
        60,
        86_400,
    ),
    Knob(
        "transcript",
        bool,
        False,
        "Keep a full transcript of the messages delivered and sent, in the encrypted "
        "daemon database.",
    ),
    Knob(
        "transcript_retention_days",
        int,
        7,
        "Days a transcript entry is kept (1 to 365).",
        1,
        365,
    ),
)
KNOB = {k.name: k for k in KNOBS}
LIMIT_FIELDS = tuple(f.name for f in fields(Limits))


@dataclass(frozen=True)
class Settings:
    """The effective settings of one group. ``senders`` holds per-sender
    overrides of the limits (identity to ``{knob: value}``)."""

    max_message_bytes: int = MAX_MESSAGE_BYTES
    sender_per_minute: int = SENDER_PER_MINUTE
    group_per_minute: int = GROUP_PER_MINUTE
    identity_rate_multiple: int = IDENTITY_RATE_MULTIPLE
    task_per_minute: int = TASK_PER_MINUTE
    allow_files: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    frame_text: bool = True
    require_approval: str = "off"
    approval_ttl_secs: int = 3600
    violation_threshold: int = DEFAULT_VIOLATION_THRESHOLD
    violation_window_secs: int = DEFAULT_VIOLATION_WINDOW_SECS
    transcript: bool = False
    transcript_retention_days: int = 7
    senders: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @staticmethod
    def of(values: Mapping[str, Any]) -> Settings:
        """Settings from ``{knob: value}`` (unknown names are an error)."""
        return Settings(**check_changes(values, sender=False, clear=False))

    def limits(self, sender: str | None = None) -> Limits:
        """The §10.2 limits for ``sender`` (its overrides applied)."""
        values: dict[str, Any] = {name: getattr(self, name) for name in LIMIT_FIELDS}
        if sender is not None:
            values.update(self.senders.get(sender, {}))
        return Limits(**values)

    @property
    def approve_inbound(self) -> bool:
        return self.require_approval in ("inbound", "both")

    @property
    def approve_outbound(self) -> bool:
        return self.require_approval in ("outbound", "both")

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {k.name: getattr(self, k.name) for k in KNOBS}
        out["senders"] = {s: dict(v) for s, v in self.senders.items()}
        return out

    def merged(self, overrides: Mapping[str, Any]) -> Settings:
        """These settings with a group's stored overrides applied."""
        values = {k: v for k, v in overrides.items() if k in KNOB}
        senders = overrides.get("senders")
        return replace(
            self,
            **values,
            senders={str(s): dict(v) for s, v in senders.items()}
            if isinstance(senders, dict)
            else {},
        )


def check_changes(raw: Mapping[str, Any], *, sender: bool, clear: bool = True) -> dict[str, Any]:
    """Validate ``{knob: value}``; ``None`` (with ``clear``) removes an
    override. With ``sender``, only the per-sender knobs are allowed."""
    out: dict[str, Any] = {}
    for name, value in raw.items():
        knob = KNOB.get(name)
        if knob is None:
            msg = f"unknown setting {name!r}"
            raise PolicyError(msg)
        if sender and not knob.per_sender:
            msg = f"{name} can't be set for one sender"
            raise PolicyError(msg)
        out[name] = None if value is None and clear else knob.check(value)
    return out


def apply_changes(
    overrides: Mapping[str, Any], changes: Mapping[str, Any], sender: str | None
) -> dict[str, Any]:
    """A group's stored overrides after ``changes`` (validated by
    :func:`check_changes`) for the group or for ``sender``."""
    out = {k: v for k, v in overrides.items() if k != "senders"}
    senders = {str(s): dict(v) for s, v in dict(overrides.get("senders") or {}).items()}
    target = out if sender is None else senders.setdefault(sender, {})
    for name, value in changes.items():
        if value is None:
            target.pop(name, None)
        else:
            target[name] = value
    senders = {s: v for s, v in senders.items() if v}
    if senders:
        out["senders"] = senders
    return out


def verification_holds(require_verified: bool, trust_state: Mapping[str, Any]) -> bool:
    """SPEC 10.4: with ``require_verified``, deliveries wait until
    ``trust_state.self`` is ``verified``."""
    return require_verified and str(trust_state.get("self")) != "verified"


@dataclass(frozen=True)
class Inbound:
    """One received inner message, as the policy sees it."""

    group_id: str
    sender: str  # the authenticated identity
    instance: str  # its instance (SPEC 3.3): rates count per instance
    inner: dict[str, Any]
    size: int  # bytes of the inner message's JSON
    owner: str | None  # the group's owner (SPEC 7.3: only it may close)
    hop: int
    max_turns: int
    addressed: bool  # the floor rules trigger this instance (SPEC 9.3)
    replayed: bool = False  # a journal replay: counted when first received
    drain_exempt: Callable[[], bool] = lambda: False  # SPEC 8.2/10.2

    @property
    def kind(self) -> str:
        return str(self.inner.get("kind"))

    @property
    def origin(self) -> str:
        return "human" if self.inner.get("origin") == "human" else "agent"


@dataclass(frozen=True)
class Outbound:
    """One inner message this instance is about to queue."""

    group_id: str
    sender: str
    instance: str
    inner: dict[str, Any]
    size: int
    internal: bool  # the daemon's own (Agent Cards, loop-guard pauses)

    @property
    def kind(self) -> str:
        return str(self.inner.get("kind"))


class SafetyPolicy:
    """The policy for every group of one daemon."""

    def __init__(
        self,
        defaults: Settings,
        store: Store,
        clock: Clock,
        audit_retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS,
    ) -> None:
        self.defaults = defaults
        self.store = store
        self.clock = clock
        self.audit_retention_days = audit_retention_days
        self.limiter = RateLimiter(clock)
        self._violations: dict[tuple[str, str], deque[int]] = {}
        self._alerted: dict[tuple[str, str], float] = {}
        self._purged_at = -math.inf

    def _now(self) -> int:
        return unix_seconds(self.clock)

    # -- settings -----------------------------------------------------------

    def settings(self, group_id: str) -> Settings:
        return self.defaults.merged(self.store.safety_overrides(group_id))

    def overrides(self, group_id: str) -> dict[str, Any]:
        return self.store.safety_overrides(group_id)

    def update(
        self, group_id: str, changes: Mapping[str, Any], sender: str | None = None
    ) -> Settings:
        """Change a group's overrides (``None`` clears one); for ``sender``
        only the limits. Raises :class:`PolicyError`."""
        checked = check_changes(changes, sender=sender is not None)
        merged = apply_changes(self.overrides(group_id), checked, sender)
        settings = self.defaults.merged(merged)  # every combination stays valid
        self.store.set_safety_overrides(group_id, merged)
        return settings

    # -- decisions ----------------------------------------------------------

    def inbound(self, m: Inbound) -> Decision:  # noqa: PLR0911
        """The decision for a received message. Counts it against the rates
        (except replays and the reconnect drain)."""
        settings = self.settings(m.group_id)
        limits = settings.limits(m.sender)
        problem = content_problem(m.inner, m.size, limits)
        if problem is not None:
            return drop(problem)
        if (
            not m.replayed
            and not m.drain_exempt()
            and not self.limiter.allow_inner(
                m.group_id, m.instance, m.kind, m.inner.get("body"), limits, identity=m.sender
            )
        ):
            return drop("rate_limited")
        if m.kind in HUMAN_ONLY_KINDS and m.origin != "human":
            return drop("not_human")  # SPEC 7.3: an agent can't resume
        if m.kind == "control.close" and m.sender != m.owner:
            return drop("not_owner")  # SPEC 7.3: only the owner may close
        if m.kind in NON_CONTENT_KINDS:
            # Controls and cards carry no content (agentconnect.schemas) and
            # never trigger the agent, so there is nothing to hold.
            return as_context("not_content")
        if settings.approve_inbound and m.kind in HOLDABLE_KINDS:
            return hold("require_approval")
        if m.hop > m.max_turns:
            return as_context("loop_guard")  # SPEC 10.3: don't trigger the agent
        if not m.addressed:
            return as_context("not_addressed")  # SPEC 9.3
        return DELIVER

    def outbound(self, m: Outbound) -> Decision:
        """The decision for a message the agent (or the human) sends. Counts
        it against this sender's rate unless it is the daemon's own."""
        settings = self.settings(m.group_id)
        limits = settings.limits(m.sender)
        problem = content_problem(m.inner, m.size, limits)
        if problem is not None:
            return drop(problem)
        human = m.inner.get("origin") == "human"
        if m.kind in NON_CONTENT_KINDS and not m.internal and not human:
            # Cards and controls come from the daemon or the human, never
            # from the agent: it can't use them to carry content.
            return drop("not_for_agents")
        if not m.internal and not self.limiter.allow_inner(
            m.group_id, m.instance, m.kind, m.inner.get("body"), limits, identity=m.sender
        ):
            return drop("rate_limited")
        if not m.internal and not human and settings.approve_outbound and m.kind in HOLDABLE_KINDS:
            return hold("require_approval")
        return DELIVER

    # -- violations -----------------------------------------------------------

    def violation(self, group_id: str, sender: str, reason: str) -> dict[str, Any] | None:
        """Count a drop against ``sender``. Returns the data of a
        ``repeated_violations`` event when the count reaches the threshold
        (at most once per window and sender), else ``None``."""
        if reason not in VIOLATIONS:
            return None
        settings = self.settings(group_id)
        now = self._now()
        window = settings.violation_window_secs
        key = (group_id, sender)
        times = self._violations.setdefault(key, deque())
        while times and times[0] <= now - window:
            times.popleft()
        times.append(now)
        if len(times) < settings.violation_threshold:
            return None
        if now - self._alerted.get(key, -math.inf) < window:
            return None
        self._alerted[key] = now
        return {
            "sender": sender,
            "count": len(times),
            "threshold": settings.violation_threshold,
            "window_secs": window,
            "last_reason": reason,
        }

    def violations(self, group_id: str, sender: str) -> int:
        """Violations by ``sender`` in the current window."""
        times = self._violations.get((group_id, sender), deque())
        window = self.settings(group_id).violation_window_secs
        return sum(1 for t in times if t > self._now() - window)

    # -- audit log and transcript ------------------------------------------------

    def audit(  # noqa: PLR0913
        self,
        group_id: str,
        direction: str,
        *,
        sender: str,
        msg_id: str,
        kind: str,
        size: int,
        decision: str,
        reason: str = "",
    ) -> None:
        """One metadata-only audit row: never the body."""
        self.store.audit_add(
            group_id,
            at=self._now(),
            direction=direction,
            sender=sender,
            msg_id=msg_id,
            kind=kind,
            size=size,
            decision=decision,
            reason=reason,
        )

    def transcribe(
        self, group_id: str, direction: str, sender: str, msg_id: str, inner: dict[str, Any]
    ) -> None:
        """Keep the full message, if the group has ``transcript`` on."""
        if self.settings(group_id).transcript:
            self.store.transcript_add(
                group_id,
                at=self._now(),
                direction=direction,
                sender=sender,
                msg_id=msg_id,
                kind=str(inner.get("kind")),
                inner=inner,
            )

    def purge(self) -> None:
        """Bounded retention: audit rows older than ``audit_retention_days``
        (and beyond the newest :data:`MAX_AUDIT_ROWS`), transcript entries
        older than their group's ``transcript_retention_days``. Runs at most
        once a minute of daemon time."""
        now = self._now()
        if now - self._purged_at < PURGE_EVERY_SECS:
            return
        self._purged_at = now
        self.store.audit_purge(now - self.audit_retention_days * DAY_SECS, MAX_AUDIT_ROWS)
        for group_id in self.store.transcript_groups():
            days = self.settings(group_id).transcript_retention_days
            self.store.transcript_purge(group_id, now - days * DAY_SECS)
