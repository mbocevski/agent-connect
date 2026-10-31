"""Standing rules are a person's (ADR-007 Decision 1): only the human token reads
or changes one, nothing else can widen one, and outside the separate-OS-user mode
nothing can create or widen one at all, because the agent can read the human
token there, and a rule would turn one injection into a standing connection.

No kind of rule is registered in production yet, so these tests register a fake
one. Nothing here approves anything: evaluation comes later.
"""

from __future__ import annotations

import inspect
import json
import random
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

import agentconnect_sdk
from agentconnect.clock import FakeClock
from agentconnect.config import Config, ConfigError, load_config
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.mcp.tools import TOOLS
from agentconnect.runtime import AgentApi, ApiError, Options, Runtime
from agentconnect.runtime.api import ROUTE_SPECS, ApiServer
from agentconnect.runtime.engine import HUMAN_EVENTS
from agentconnect.runtime.trust import (
    DAILY_CONNECTIONS_CEILING,
    KINDS,
    Caps,
    KindSpec,
    widens,
)
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE
from agentconnect_sdk import embedded

NOW = 1_800_000_000
CAPS = {"new_per_hour": 2, "new_per_day": 5, "open_at_once": 3, "lifetime_secs": 3600}
RULES = "/v0/trust/rules"


def _entries(fields: dict[str, Any]) -> dict[str, Any]:
    entries = fields.get("entries")
    if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
        raise ValueError("entries must be a list of strings")
    return {"entries": entries}


def _fewer(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return set(new["entries"]) <= set(old["entries"])


FAKE = KindSpec(
    name="fake",
    default_caps=Caps(new_per_hour=1, new_per_day=2, open_at_once=3, lifetime_secs=60),
    validate=_entries,
    narrows=_fewer,
)


@pytest.fixture
def fake_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(KINDS, FAKE.name, FAKE)


@dataclass
class Daemon:
    rt: Runtime
    server: ApiServer
    tokens: dict[str, str]

    async def call(
        self, scope: str, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        raw = json.dumps(body).encode() if body is not None else b""
        headers = {"authorization": f"Bearer {self.tokens[scope]}"}
        _status, out = await self.server.handle(method, path, headers, raw)
        return out

    async def refused(
        self, scope: str, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, str]:
        with pytest.raises(ApiError) as e:
            await self.call(scope, method, path, body)
        return e.value.status, e.value.code

    def rule(self, name: str) -> dict[str, Any]:
        rule = self.rt._engine.store.trust_rule(name)
        assert rule is not None
        return rule

    def isolated(self, on: bool = True) -> None:
        engine = self.rt._engine
        engine.config = engine.config.with_overrides(isolation=on)

    async def apply(self, body: dict[str, Any]) -> Any:
        preview = await self.call("human", "POST", f"{RULES}/preview", body)
        return await self.call("human", "POST", RULES, {**body, "hash": preview["hash"]})

    async def create(self, name: str = "r1", **over: Any) -> Any:
        return await self.apply(
            {"action": "create", "name": name, "kind": "fake", "fields": {"entries": ["a"]}, **over}
        )

    def events(self) -> list[dict[str, Any]]:
        return list(self.rt._engine.store.events(limit=1000))

    def audit(self) -> list[dict[str, Any]]:
        return [r for r in self.rt._engine.store.audit(limit=1000) if r["kind"] == "trust_rule"]


def _runtime(tmp_path: Path, rng: random.Random) -> Runtime:
    clock = FakeClock(datetime.fromtimestamp(NOW, UTC))
    config = Config(
        relay_url="ws://127.0.0.1:1",
        relay_host="127.0.0.1:1",
        data_dir=tmp_path / "data",
        keystore="file",
    )
    return Runtime(
        config,
        clock=clock,
        keystore=FileKeystore(tmp_path / "data" / "keys"),
        options=Options(testing=Seeded(rng.getrandbits(63))),
        serve_api=False,
    )


def _daemon(rt: Runtime) -> Daemon:
    server = ApiServer(rt._engine)  # it writes the tokens
    data = rt._engine.config.data_dir
    tokens = {
        scope: (data / name).read_text(encoding="ascii").strip()
        for scope, name in (("agent", API_TOKEN_FILE), ("human", HUMAN_TOKEN_FILE))
    }
    return Daemon(rt, server, tokens)


@pytest.fixture
async def daemon(tmp_path: Path, rng: random.Random, fake_kind: None) -> AsyncIterator[Daemon]:
    rt = _runtime(tmp_path, rng)
    yield _daemon(rt)
    await rt.stop(flush=0)


TRUST_ROUTES = [s for s in ROUTE_SPECS if "/trust/" in s.path]


def test_every_trust_route_needs_the_human_token() -> None:
    assert {f"{s.method} {s.path}" for s in TRUST_ROUTES} == {
        f"GET {RULES}",
        f"GET {RULES}/{{name}}",
        f"POST {RULES}/preview",
        f"POST {RULES}",
        f"POST {RULES}/{{name}}/disable",
        f"DELETE {RULES}/{{name}}",
    }
    assert all(s.human for s in TRUST_ROUTES), [s.path for s in TRUST_ROUTES if not s.human]


async def test_the_agent_token_cant_read_or_change_a_rule(daemon: Daemon) -> None:
    """Reads too: a rule says whose identity or which domain gets through."""
    daemon.isolated()
    await daemon.create()
    before = daemon.rt._engine.store.trust_rule("r1")
    for spec in TRUST_ROUTES:
        path = spec.path.replace("{name}", "r1")
        body = {"action": "create", "name": "r2", "kind": "fake", "hash": "x", "fields": {}}
        assert await daemon.refused("agent", spec.method, path, body) == (403, "human_only")
    assert daemon.rt._engine.store.trust_rule("r1") == before
    assert daemon.rt._engine.store.trust_rule("r2") is None


def test_the_agent_api_the_sdk_and_the_tools_have_no_way_to_a_rule() -> None:
    # Whole parts of a name: ``untrusted`` is about something else.
    words = re.compile(r"(^|_)(rules?|trust|pin|unpin|widen)(_|$)")
    names = [n for n, _ in inspect.getmembers(AgentApi) if not n.startswith("__")]
    assert not [n for n in names if words.search(n)]
    assert not [t.name for t in TOOLS if words.search(t.name)]
    public = [getattr(agentconnect_sdk, n) for n in agentconnect_sdk.__all__]
    sdk = (agentconnect_sdk.AgentConnect, agentconnect_sdk.Group, embedded, embedded.EmbeddedHost)
    for obj in (*public, *sdk):
        members = [n for n, _ in inspect.getmembers(obj) if not n.startswith("_")]
        assert not [n for n in members if words.search(n)], obj


@pytest.mark.parametrize("table", ["trust", "rules"])
def test_the_config_has_no_table_for_rules(tmp_path: Path, table: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(f'[{table}]\nname = "x"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="human token"):
        load_config(path, {"HOME": str(tmp_path)})


def test_no_kind_is_registered_in_production() -> None:
    """Until an anchor lands, a rule could only do nothing, silently."""
    assert KINDS == {}


async def test_an_unregistered_kind_is_refused(tmp_path: Path, rng: random.Random) -> None:
    rt = _runtime(tmp_path, rng)
    daemon = _daemon(rt)
    daemon.isolated()
    body = {"action": "create", "name": "r1", "kind": "pinned", "fields": {}}
    assert await daemon.refused("human", "POST", f"{RULES}/preview", body) == (400, "unknown_kind")
    await rt.stop(flush=0)


async def test_outside_the_mode_nothing_creates_or_widens(daemon: Daemon) -> None:
    """With the human token: on a same-user install the agent can read it."""
    body = {"action": "create", "name": "r1", "kind": "fake", "fields": {"entries": ["a"]}}
    assert await daemon.refused("human", "POST", f"{RULES}/preview", body) == (
        409,
        "needs_isolation",
    )
    assert await daemon.refused("human", "POST", RULES, {**body, "hash": "x"}) == (
        409,
        "needs_isolation",
    )
    assert daemon.rt._engine.store.trust_rule("r1") is None
    # The same database, opened where the mode was on.
    daemon.isolated()
    await daemon.create(caps=CAPS)
    await daemon.call("human", "POST", f"{RULES}/r1/disable", {})
    daemon.isolated(False)
    for action, change in (
        ("enable", {}),
        ("change", {"caps": {**CAPS, "new_per_day": 6}}),
        ("change", {"fields": {"entries": ["a", "b"]}}),
    ):
        body = {"action": action, "name": "r1", **change}
        assert await daemon.refused("human", "POST", f"{RULES}/preview", body) == (
            409,
            "needs_isolation",
        ), body
        assert await daemon.refused("human", "POST", RULES, {**body, "hash": "x"}) == (
            409,
            "needs_isolation",
        ), body


async def test_outside_the_mode_narrowing_still_works(daemon: Daemon) -> None:
    daemon.isolated()
    await daemon.create(caps=CAPS)
    await daemon.create("r2")
    daemon.isolated(False)
    await daemon.apply({"action": "change", "name": "r1", "caps": {**CAPS, "new_per_day": 1}})
    assert daemon.rule("r1")["caps"]["new_per_day"] == 1
    await daemon.apply({"action": "change", "name": "r2", "fields": {"entries": []}})
    await daemon.call("human", "POST", f"{RULES}/r1/disable", {})
    assert daemon.rule("r1")["enabled"] is False
    await daemon.call("human", "DELETE", f"{RULES}/r1")
    assert daemon.rt._engine.store.trust_rule("r1") is None


async def test_a_change_commits_only_what_the_preview_showed(daemon: Daemon) -> None:
    daemon.isolated()
    body = {"action": "create", "name": "r1", "kind": "fake", "fields": {"entries": ["a"]}}
    preview = await daemon.call("human", "POST", f"{RULES}/preview", body)
    assert preview["widens"] is True
    assert preview["after"]["fields"] == {"entries": ["a"]}
    assert daemon.rt._engine.store.trust_rule("r1") is None, "a preview changes nothing"
    wider = {**body, "fields": {"entries": ["a", "b"]}, "hash": preview["hash"]}
    assert await daemon.refused("human", "POST", RULES, wider) == (409, "stale_preview")
    assert await daemon.refused("human", "POST", RULES, body) == (400, "bad_request")
    await daemon.call("human", "POST", RULES, {**body, "hash": preview["hash"]})
    # The rule moved since this preview: the hash covers what it was.
    change = {"action": "change", "name": "r1", "caps": CAPS}
    shown = await daemon.call("human", "POST", f"{RULES}/preview", change)
    await daemon.apply({"action": "change", "name": "r1", "purpose": "other"})
    assert await daemon.refused("human", "POST", RULES, {**change, "hash": shown["hash"]}) == (
        409,
        "stale_preview",
    )


@pytest.mark.parametrize(
    "over",
    [
        {"name": "Has Caps"},
        {"name": ""},
        {"name": "x" * 33},
        {"fields": {"entries": "not a list"}},
        {"purpose": "two\nlines"},
        {"purpose": "x" * 501},
        {"caps": {**CAPS, "new_per_day": 0}},
        {"caps": {**CAPS, "new_per_day": "many"}},
        {"caps": {**CAPS, "unknown": 1}},
        {"caps": {"new_per_day": 1}},
        {"unknown": 1},
    ],
)
async def test_a_bad_rule_is_refused(daemon: Daemon, over: dict[str, Any]) -> None:
    daemon.isolated()
    body = {"action": "create", "name": "r1", "kind": "fake", "fields": {"entries": []}, **over}
    assert await daemon.refused("human", "POST", f"{RULES}/preview", body) == (400, "bad_request")


async def test_the_restricted_profile_waits_for_its_endpoint(daemon: Daemon) -> None:
    daemon.isolated()
    body = {
        "action": "create",
        "name": "r1",
        "kind": "fake",
        "fields": {"entries": []},
        "profile": "restricted",
    }
    assert await daemon.refused("human", "POST", f"{RULES}/preview", body) == (
        409,
        "no_restricted_endpoint",
    )


async def test_no_setting_goes_past_a_ceiling(daemon: Daemon) -> None:
    daemon.isolated()
    over = {**CAPS, "new_per_day": DAILY_CONNECTIONS_CEILING + 1}
    body = {"action": "create", "name": "r1", "kind": "fake", "fields": {"entries": []}}
    assert await daemon.refused("human", "POST", f"{RULES}/preview", {**body, "caps": over}) == (
        409,
        "over_ceiling",
    )


async def test_the_rules_together_stay_under_the_daily_ceiling(daemon: Daemon) -> None:
    """The relay's group budget has to leave room for the human's approvals."""
    daemon.isolated()
    near = {**CAPS, "new_per_day": DAILY_CONNECTIONS_CEILING - 1}
    await daemon.create("r1", caps=near)
    body = {
        "action": "create",
        "name": "r2",
        "kind": "fake",
        "fields": {"entries": []},
        "caps": {**CAPS, "new_per_day": 2},
    }
    assert await daemon.refused("human", "POST", f"{RULES}/preview", body) == (
        409,
        "over_ceiling",
    )
    # A disabled rule doesn't count, until it comes back.
    await daemon.call("human", "POST", f"{RULES}/r1/disable", {})
    await daemon.apply(body)
    enable = {"action": "enable", "name": "r1"}
    assert await daemon.refused("human", "POST", f"{RULES}/preview", enable) == (
        409,
        "over_ceiling",
    )


async def test_every_change_raises_a_human_event_and_an_audit_row(daemon: Daemon) -> None:
    daemon.isolated()
    await daemon.create()
    await daemon.apply({"action": "change", "name": "r1", "purpose": "other"})
    await daemon.call("human", "POST", f"{RULES}/r1/disable", {})
    await daemon.call("human", "DELETE", f"{RULES}/r1")
    events = [e["data"] for e in daemon.events() if e["type"] == "rule_changed"]
    assert [e["action"] for e in events] == ["create", "change", "disable", "remove"]
    assert all(e["rule"] == "r1" for e in events)
    assert events[0]["before_hash"] is None
    assert events[0]["after_hash"]
    assert events[1]["before_hash"] == events[0]["after_hash"]
    assert events[3]["after_hash"] is None
    rows = daemon.audit()
    assert [r["reason"] for r in rows] == ["create", "change", "disable", "remove"]
    assert {r["decision"] for r in rows} == {"rule_changed"}
    assert "rule_changed" in HUMAN_EVENTS
    assert "rules_inert" in HUMAN_EVENTS
    _, seen = await daemon.server.handle(
        "GET", "/v0/events", {"authorization": f"Bearer {daemon.tokens['agent']}"}, b""
    )
    assert not [e for e in seen["events"] if e["type"].startswith("rule")]


async def test_a_failed_change_records_nothing(daemon: Daemon) -> None:
    daemon.isolated()
    assert await daemon.refused("human", "POST", f"{RULES}/nope/disable", {}) == (404, "not_found")
    assert await daemon.refused("human", "DELETE", f"{RULES}/nope") == (404, "not_found")
    assert not [e for e in daemon.events() if e["type"] == "rule_changed"]
    assert daemon.audit() == []


async def test_a_rule_can_be_listed_and_read_by_the_human(daemon: Daemon) -> None:
    daemon.isolated()
    await daemon.create(caps=CAPS, purpose="Deploys")
    listed = await daemon.call("human", "GET", RULES)
    assert [r["name"] for r in listed["rules"]] == ["r1"]
    rule = await daemon.call("human", "GET", f"{RULES}/r1")
    assert rule["kind"] == "fake"
    assert rule["enabled"] is True
    assert rule["caps"] == CAPS
    assert rule["profile"] == "standard"
    assert rule["purpose"] == "Deploys"
    assert rule["fields"] == {"entries": ["a"]}
    assert (rule["created_at"], rule["changed_at"]) == (NOW, NOW)
    assert await daemon.refused("human", "GET", f"{RULES}/nope") == (404, "not_found")


async def test_defaults_come_from_the_kind(daemon: Daemon) -> None:
    daemon.isolated()
    await daemon.create()
    assert (await daemon.call("human", "GET", f"{RULES}/r1"))["caps"] == {
        "new_per_hour": 1,
        "new_per_day": 2,
        "open_at_once": 3,
        "lifetime_secs": 60,
    }


async def test_rules_survive_a_restart(tmp_path: Path, rng: random.Random, fake_kind: None) -> None:
    rt = _runtime(tmp_path, rng)
    daemon = _daemon(rt)
    daemon.isolated()
    await daemon.create()
    await rt.stop(flush=0)
    rt = _runtime(tmp_path, rng)
    assert rt._engine.store.trust_rule("r1") is not None
    await rt.stop(flush=0)


async def test_rules_outside_the_mode_are_inert_and_said_so_once_per_start(
    daemon: Daemon,
) -> None:
    engine = daemon.rt._engine
    daemon.isolated()
    await daemon.create()
    daemon.isolated(False)
    assert engine.rules.active is False
    await engine.rules.announce_inert()
    await engine.rules.announce_inert()
    inert = [e for e in daemon.events() if e["type"] == "rules_inert"]
    assert [e["data"]["rules"] for e in inert] == [1]


async def test_no_rules_or_the_mode_on_says_nothing(daemon: Daemon) -> None:
    engine = daemon.rt._engine
    await engine.rules.announce_inert()
    assert not [e for e in daemon.events() if e["type"] == "rules_inert"]
    daemon.isolated()
    await daemon.create()
    assert engine.rules.active is True
    await engine.rules.announce_inert()
    assert not [e for e in daemon.events() if e["type"] == "rules_inert"]


@given(
    old=st.fixed_dictionaries(
        {
            "new_per_hour": st.integers(1, 80),
            "new_per_day": st.integers(1, 80),
            "open_at_once": st.integers(1, 64),
            "lifetime_secs": st.none() | st.integers(1, 10**7),
        }
    ),
    new=st.fixed_dictionaries(
        {
            "new_per_hour": st.integers(1, 80),
            "new_per_day": st.integers(1, 80),
            "open_at_once": st.integers(1, 64),
            "lifetime_secs": st.none() | st.integers(1, 10**7),
        }
    ),
    old_entries=st.sets(st.sampled_from("abcd")),
    new_entries=st.sets(st.sampled_from("abcd")),
)
def test_only_a_change_that_lets_nothing_more_in_is_narrowing(
    old: dict[str, Any], new: dict[str, Any], old_entries: set[str], new_entries: set[str]
) -> None:
    before = {
        "kind": "fake",
        "caps": old,
        "profile": "standard",
        "fields": {"entries": sorted(old_entries)},
    }
    after = {**before, "caps": new, "fields": {"entries": sorted(new_entries)}}
    raised = (
        any(new[k] > old[k] for k in ("new_per_hour", "new_per_day", "open_at_once"))
        or (new["lifetime_secs"] is None and old["lifetime_secs"] is not None)
        or (
            new["lifetime_secs"] is not None
            and old["lifetime_secs"] is not None
            and new["lifetime_secs"] > old["lifetime_secs"]
        )
    )
    assert widens(before, after, FAKE) == (raised or not new_entries <= old_entries)


def test_leaving_the_restricted_profile_widens() -> None:
    caps = {"new_per_hour": 1, "new_per_day": 1, "open_at_once": 1, "lifetime_secs": 1}
    before = {"kind": "fake", "caps": caps, "profile": "restricted", "fields": {"entries": []}}
    assert widens(before, {**before, "profile": "standard"}, FAKE) is True
    after = {**before, "profile": "restricted"}
    assert widens(before, after, FAKE) is False
    assert widens({**before, "profile": "standard"}, after, FAKE) is False
