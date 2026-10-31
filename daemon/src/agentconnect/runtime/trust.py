"""Standing rules: a person's decision, made once, that this daemon may approve
matching connections on its own (ADR-007).

A rule is a row in the encrypted daemon database, read and changed only through
the human token's routes. Creating, widening or enabling one is refused outside
the separate-OS-user mode, whoever asks: on a same-user install the agent can
read the human token, so a rule would turn one injection into a standing
connection. Narrowing works everywhere.

A change goes through a preview, whose hash covers what the rule is now and what
it would become, so the human commits what they saw. Every change raises
``rule_changed`` and writes an audit row.

:data:`KINDS` stays empty until an anchor is built: a rule of a kind nothing
evaluates would do nothing, silently.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from agentconnect.runtime.errors import ApiError

if TYPE_CHECKING:
    from agentconnect.runtime.engine import Engine

#: Rules together may approve this many new connections a day, below the relay's
#: 100 groups per mailbox (SPEC 8.3), so the human's own approvals still get groups.
DAILY_CONNECTIONS_CEILING = 80
MAX_PURPOSE_CHARS = 500
NAME = re.compile(r"[a-z0-9-]{1,32}")
PROFILES = frozenset({"standard", "restricted"})
CAP_LIMITS = ("new_per_hour", "new_per_day", "open_at_once")
RULE_FIELDS = frozenset({"kind", "caps", "profile", "purpose", "fields"})
NOT_ONE_LINE = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"})
HOW = "`agentconnect trust rule`, with the human token"


@dataclass(frozen=True)
class Caps:
    """What a rule may approve (ADR-007 Decision 7). ``lifetime_secs`` ``None``:
    a connection has no lifetime."""

    new_per_hour: int
    new_per_day: int
    open_at_once: int
    lifetime_secs: int | None


#: The most any rule may set: no setting goes past these.
CEILINGS = Caps(
    new_per_hour=DAILY_CONNECTIONS_CEILING,
    new_per_day=DAILY_CONNECTIONS_CEILING,
    open_at_once=256,
    lifetime_secs=None,
)


@dataclass(frozen=True)
class KindSpec:
    """One kind of rule: an anchor registers this when it is built.

    ``validate`` returns the kind's clean fields, or raises ``ValueError``.
    ``narrows(old, new)`` says whether ``new`` lets in nothing ``old`` didn't."""

    name: str
    default_caps: Caps
    validate: Callable[[dict[str, Any]], dict[str, Any]]
    narrows: Callable[[dict[str, Any], dict[str, Any]], bool]
    ceilings: Caps = CEILINGS


KINDS: dict[str, KindSpec] = {}


def _bad(message: str) -> ApiError:
    return ApiError(400, "bad_request", message)


def _lifetime_grew(old: int | None, new: int | None) -> bool:
    if old is None:
        return False
    return new is None or new > old


def widens(before: Mapping[str, Any], after: Mapping[str, Any], spec: KindSpec) -> bool:
    """Whether ``after`` could let in anything ``before`` couldn't."""
    old, new = before["caps"], after["caps"]
    return bool(
        any(new[k] > old[k] for k in CAP_LIMITS)
        or _lifetime_grew(old["lifetime_secs"], new["lifetime_secs"])
        or (before["profile"] == "restricted" and after["profile"] != "restricted")
        or not spec.narrows(before["fields"], after["fields"])
    )


def rule_hash(rule: Mapping[str, Any] | None) -> str | None:
    """A rule's content, without its times, for the audit trail."""
    if rule is None:
        return None
    return hashlib.sha256(_canonical(_content(rule))).hexdigest()


def _content(rule: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in rule.items() if k not in {"created_at", "changed_at"}}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _one_line(text: str) -> bool:
    return not any(unicodedata.category(c) in NOT_ONE_LINE for c in text)


def _caps(raw: Any, spec: KindSpec) -> dict[str, Any]:
    fields = {*CAP_LIMITS, "lifetime_secs"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise _bad(f"caps must have exactly {', '.join(sorted(fields))}")
    for key, value in raw.items():
        if value is None and key == "lifetime_secs":
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise _bad(f"{key} must be a positive integer")
    limits = asdict(spec.ceilings)
    over = [k for k in CAP_LIMITS if raw[k] > limits[k]]
    if limits["lifetime_secs"] is not None and _lifetime_grew(
        limits["lifetime_secs"], raw["lifetime_secs"]
    ):
        over.append("lifetime_secs")
    if over:
        raise ApiError(409, "over_ceiling", f"past the ceiling for this kind: {', '.join(over)}")
    return dict(raw)


def _purpose(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or len(raw) > MAX_PURPOSE_CHARS or not _one_line(raw):
        raise _bad(f"purpose must be one line of at most {MAX_PURPOSE_CHARS} characters")
    return raw


def _profile(raw: Any) -> str:
    if raw not in PROFILES:
        raise _bad(f"profile must be one of {', '.join(sorted(PROFILES))}")
    if raw == "restricted":
        # Its content has nowhere isolated to go yet (ADR-007 Decision 6).
        raise ApiError(409, "no_restricted_endpoint", "no restricted endpoint is configured")
    return str(raw)


def _fields(raw: Any, spec: KindSpec) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _bad("fields must be an object")
    try:
        return spec.validate(raw)
    except ValueError as e:
        raise _bad(str(e)) from None


def _spec(kind: Any) -> KindSpec:
    spec = KINDS.get(kind) if isinstance(kind, str) else None
    if spec is None:
        raise ApiError(400, "unknown_kind", "no rule of this kind can be created yet")
    return spec


@dataclass(frozen=True)
class _Plan:
    action: str
    name: str
    before: dict[str, Any] | None
    after: dict[str, Any]
    widening: bool

    @property
    def hash(self) -> str:
        shown = {
            "action": self.action,
            "name": self.name,
            "before": None if self.before is None else _content(self.before),
            "after": _content(self.after),
        }
        return hashlib.sha256(_canonical(shown)).hexdigest()


class RuleService:
    """The human's routes, and whether rules count at all in this runtime."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @property
    def active(self) -> bool:
        """Rules count only in the separate-OS-user mode. Elsewhere the ones in
        the database stay there, and nothing evaluates them."""
        return bool(self._engine.config.isolation)

    def require_active(self) -> None:
        """The gate for everything that creates or widens a rule, or lets a
        rule approve more: refused outside the mode, with any token."""
        if not self.active:
            raise ApiError(
                409,
                "needs_isolation",
                "standing rules need the separate-OS-user mode (docs/isolation.md): here the "
                "agent can read the human token, so connections stay a person's, one at a time",
            )

    async def announce_inert(self) -> None:
        """Tell the human, once per start, of rules that count for nothing here."""
        engine = self._engine
        if self.active or engine.rules_inert_told:
            return
        rules = engine.store.trust_rules()
        if rules:
            engine.rules_inert_told = True
            await engine.emit(None, "rules_inert", rules=len(rules))

    def list(self) -> dict[str, Any]:
        return {"rules": self._engine.store.trust_rules()}

    def get(self, name: str) -> dict[str, Any]:
        return self._existing(name)

    def _existing(self, name: str) -> dict[str, Any]:
        rule = self._engine.store.trust_rule(name)
        if rule is None:
            raise ApiError(404, "not_found", "no such rule")
        return rule

    def _plan(self, body: Mapping[str, Any]) -> _Plan:
        action, name = body.get("action"), body.get("name")
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise _bad("name must be 1 to 32 of a-z, 0-9 and -")
        unknown = set(body) - RULE_FIELDS - {"action", "name", "hash"}
        if unknown:
            raise _bad(f"unknown field(s): {', '.join(sorted(unknown))}")
        if action == "create":
            plan = self._plan_create(name, body)
        elif action == "change":
            plan = self._plan_change(name, body)
        elif action == "enable":
            plan = self._plan_enable(name, body)
        else:
            raise _bad("action must be create, change or enable")
        if plan.widening:
            self.require_active()
            self._check_daily_total(plan.after)
        return plan

    def _plan_create(self, name: str, body: Mapping[str, Any]) -> _Plan:
        spec = _spec(body.get("kind"))
        if self._engine.store.trust_rule(name) is not None:
            raise ApiError(409, "rule_exists", "a rule with this name exists")
        after = {
            "name": name,
            "kind": spec.name,
            "enabled": True,
            "caps": _caps(body.get("caps", asdict(spec.default_caps)), spec),
            "profile": _profile(body.get("profile", "standard")),
            "purpose": _purpose(body.get("purpose")),
            "fields": _fields(body.get("fields", {}), spec),
        }
        return _Plan("create", name, None, after, widening=True)

    def _plan_change(self, name: str, body: Mapping[str, Any]) -> _Plan:
        before = self._existing(name)
        if "kind" in body:
            raise _bad("a rule's kind can't change")
        spec = _spec(before["kind"])
        after = dict(before)
        if "caps" in body:
            after["caps"] = _caps(body["caps"], spec)
        if "profile" in body:
            after["profile"] = _profile(body["profile"])
        if "purpose" in body:
            after["purpose"] = _purpose(body["purpose"])
        if "fields" in body:
            after["fields"] = _fields(body["fields"], spec)
        # A disabled rule lets in nothing whatever it says, but enabling it
        # later must not be the only check on what it says now.
        return _Plan("change", name, before, after, widening=widens(before, after, spec))

    def _plan_enable(self, name: str, body: Mapping[str, Any]) -> _Plan:
        before = self._existing(name)
        if set(body) - {"action", "name", "hash"}:
            raise _bad("enable takes only the rule's name")
        _spec(before["kind"])
        return _Plan("enable", name, before, {**before, "enabled": True}, widening=True)

    def _check_daily_total(self, after: Mapping[str, Any]) -> None:
        others = sum(
            r["caps"]["new_per_day"]
            for r in self._engine.store.trust_rules()
            if r["enabled"] and r["name"] != after["name"]
        )
        if after["enabled"] and others + after["caps"]["new_per_day"] > DAILY_CONNECTIONS_CEILING:
            raise ApiError(
                409,
                "over_ceiling",
                f"rules together may approve at most {DAILY_CONNECTIONS_CEILING} new "
                f"connections a day; the others take {others}",
            )

    def preview(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """What a change would do, and the hash that commits it. Changes nothing."""
        plan = self._plan(body)
        return {
            "action": plan.action,
            "name": plan.name,
            "before": plan.before,
            "after": plan.after,
            "widens": plan.widening,
            "hash": plan.hash,
        }

    async def commit(self, body: Mapping[str, Any]) -> dict[str, Any]:
        plan = self._plan(body)
        shown = body.get("hash")
        if not isinstance(shown, str):
            raise _bad("hash is required: preview the change first")
        if shown != plan.hash:
            raise ApiError(409, "stale_preview", "the rule or the change differs: preview again")
        await self._record(plan.action, plan.name, plan.before, plan.after)
        return self._existing(plan.name)

    async def disable(self, name: str) -> dict[str, Any]:
        """Takes no preview: stopping a rule mustn't wait for anything."""
        before = self._existing(name)
        await self._record("disable", name, before, {**before, "enabled": False})
        return self._existing(name)

    async def remove(self, name: str) -> dict[str, Any]:
        before = self._existing(name)
        await self._record("remove", name, before, None)
        return {"name": name, "status": "removed"}

    async def _record(
        self,
        action: str,
        name: str,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
    ) -> None:
        engine = self._engine

        async def body() -> str:
            now = engine.now()
            if after is None:
                engine.store.delete_trust_rule(name)
            else:
                created = now if before is None else before["created_at"]
                engine.store.put_trust_rule({**after, "created_at": created, "changed_at": now})
            await engine.emit(
                None,
                "rule_changed",
                rule=name,
                action=action,
                before_hash=rule_hash(before),
                after_hash=rule_hash(after),
            )
            engine.safety.audit(
                "",
                "local",
                sender="human",
                msg_id="",
                kind="trust_rule",
                size=0,
                decision="rule_changed",
                reason=action,
            )
            return action

        await engine._apply("rule_change", body)
