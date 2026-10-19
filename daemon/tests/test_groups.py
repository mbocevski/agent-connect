"""Membership events, policy events and the update threshold
(agentconnect.runtime.groups, docs/groups.md), and the ``[groups]`` config."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest

from agentconnect.config import (
    MAX_LEAVE_TIMEOUT_SECS,
    MIN_LEAVE_TIMEOUT_SECS,
    ConfigError,
    load_config,
)
from agentconnect.runtime.engine import (
    SUMMARY_REPORTS_LEAVES,
    UPDATE_AFTER_MESSAGES,
    DaemonError,
    canonical,
    journal_context,
)
from agentconnect.runtime.groups import (
    UPDATE_JITTER_MESSAGES,
    may_invite,
    membership_events,
    planned_policy,
    policy_changes,
    policy_events,
    role_of,
    update_threshold,
)


class Ids:
    """Identities and instance ids drawn from the test's seed."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def identity(self) -> str:
        return f"ac:v0:{self.rng.getrandbits(128):032x}"

    def instance(self) -> str:
        return f"{self.rng.getrandbits(64):016x}"


def member(identity: str, instance: str, leaf: int = 0) -> dict[str, Any]:
    return {"identity": identity, "instance_id_hex": instance, "leaf_index": leaf}


def summary(committer: str, **parts: Any) -> dict[str, Any]:
    return {
        "committer": member(committer, "00" * 8),
        "added": parts.get("added", []),
        "removed": parts.get("removed", []),
        "left": parts.get("left", []),
        "policy_changed": parts.get("policy_changed", False),
        "previous_policy": parts.get("previous_policy"),
        "policy": parts.get("policy"),
    }


def policy(owner: str, admins: list[str] | None = None) -> dict[str, Any]:
    return {"v": 0, "owner": owner, "admins": admins or [], "invite": "owner"}


def by_identity(events: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, dict[str, Any]]]:
    """Events in the order membership_events gives them: by identity."""
    return sorted(events, key=lambda e: e[1]["identity"])


@pytest.fixture
def ids(rng: random.Random) -> Ids:
    return Ids(rng)


def test_joins_say_whether_an_identity_or_an_instance_is_new(ids: Ids) -> None:
    a, b, c = ids.identity(), ids.identity(), ids.identity()
    a1, b1, b2, c1, c2 = (ids.instance() for _ in range(5))
    after = [member(a, a1), member(b, b1), member(b, b2), member(c, c1), member(c, c2)]
    s = summary(a, added=[member(b, b2), member(c, c2), member(c, c1)])
    assert membership_events(s, after) == by_identity(
        [
            ("instance_joined", {"identity": b, "instance_id": b2, "by": a}),
            ("member_joined", {"identity": c, "instances": sorted([c1, c2]), "by": a}),
        ]
    )


def test_a_leave_and_a_removal_are_told_apart_by_the_summary(ids: Ids) -> None:
    a, b, c, d = (ids.identity() for _ in range(4))
    a1, b1, c1, d1, d2 = (ids.instance() for _ in range(5))
    after = [member(a, a1)]
    s = summary(
        a,
        removed=[member(b, b1), member(c, c1), member(d, d1), member(d, d2)],
        left=[member(b, b1), member(d, d1)],
    )
    assert membership_events(s, after) == by_identity(
        [
            ("member_left", {"identity": b, "by": a}),
            ("member_removed", {"identity": c, "by": a}),
            # One instance left, the other was removed: a removal.
            ("member_removed", {"identity": d, "by": a}),
        ]
    )


def test_instances_that_go_while_their_identity_stays(ids: Ids) -> None:
    a, b = ids.identity(), ids.identity()
    a1, b1, b2, b3 = (ids.instance() for _ in range(4))
    s = summary(b, removed=[member(b, b2), member(b, b3)], left=[member(b, b3)])
    events = membership_events(s, [member(a, a1), member(b, b1)])
    assert sorted(events, key=lambda e: e[1]["instance_id"]) == sorted(
        [
            ("instance_removed", {"identity": b, "instance_id": b2, "by": b}),
            ("instance_left", {"identity": b, "instance_id": b3, "by": b}),
        ],
        key=lambda e: e[1]["instance_id"],
    )
    assert membership_events(summary(a), [member(a, a1)]) == []


def test_role_changes_come_from_the_summarys_policies(ids: Ids) -> None:
    a, b, c = ids.identity(), ids.identity(), ids.identity()
    before, after = policy(a, [c]), policy(b, [a])
    s = summary(
        a,
        policy_changed=True,
        previous_policy=canonical(before),
        policy=canonical(after),
    )
    events = policy_events(s, current=policy(c))
    assert events[0] == (
        "policy_changed",
        {"policy": after, "previous_policy": before, "roles_known": True, "by": a},
    )
    roles = {e[1]["identity"]: (e[1]["from"], e[1]["to"]) for e in events[1:]}
    assert roles == {a: ("owner", "admin"), b: ("member", "owner"), c: ("admin", "member")}
    assert all(kind == "role_changed" and data["by"] == a for kind, data in events[1:])

    same = summary(
        a,
        policy_changed=True,
        previous_policy=canonical(before),
        policy=canonical({**before, "invite": "admins"}),
    )
    assert [kind for kind, _ in policy_events(same, current=before)] == ["policy_changed"]


def test_a_summary_journalled_before_the_core_reported_policies_says_roles_are_unknown(
    ids: Ids,
) -> None:
    """A journal entry written before the core put ``previous_policy`` and
    ``policy`` in summaries reads back with both ``None``: that is not "no
    role changed", so no ``role_changed`` is made up and the event says so."""
    a, b = ids.identity(), ids.identity()
    legacy = summary(a, policy_changed=True)
    assert (legacy["previous_policy"], legacy["policy"]) == (None, None)
    current = policy(b, [a])
    assert policy_events(legacy, current) == [
        (
            "policy_changed",
            {"policy": current, "previous_policy": None, "roles_known": False, "by": a},
        )
    ]
    # Only one of the two is no better.
    half = summary(a, policy_changed=True, policy=canonical(current))
    assert policy_events(half, current)[0][1]["roles_known"] is False


def test_role_of() -> None:
    p = {"owner": "o", "admins": ["x"]}
    assert [role_of(p, i) for i in ("o", "x", "y")] == ["owner", "admin", "member"]
    assert role_of({"owner": "o", "admins": "x"}, "x") == "member"
    assert json.loads(canonical(p)) == p


def test_the_update_threshold_is_spread_per_instance_and_epoch(ids: Ids) -> None:
    group = f"{ids.rng.getrandbits(128):032x}"
    instances = [ids.instance() for _ in range(40)]
    lowest = UPDATE_AFTER_MESSAGES - UPDATE_JITTER_MESSAGES
    drawn = [update_threshold(group, 7, i) for i in instances]
    assert all(lowest <= t <= UPDATE_AFTER_MESSAGES for t in drawn)
    assert len(set(drawn)) > 1  # instances don't all reach it together
    assert drawn == [update_threshold(group, 7, i) for i in instances]  # survives a restart
    assert [update_threshold(group, e, instances[0]) for e in range(40)].count(drawn[0]) < 40


def _load(tmp_path: Path, text: str) -> Any:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, {"HOME": str(tmp_path)})


def test_the_leave_timeout_can_only_be_shortened(tmp_path: Path) -> None:
    assert _load(tmp_path, "").groups_leave_timeout_secs == MAX_LEAVE_TIMEOUT_SECS
    cfg = _load(tmp_path, f"[groups]\nleave_timeout_secs = {MIN_LEAVE_TIMEOUT_SECS}\n")
    assert cfg.groups_leave_timeout_secs == MIN_LEAVE_TIMEOUT_SECS
    for bad in (MIN_LEAVE_TIMEOUT_SECS - 1, MAX_LEAVE_TIMEOUT_SECS + 1):
        with pytest.raises(ConfigError, match="leave_timeout_secs"):
            _load(tmp_path, f"[groups]\nleave_timeout_secs = {bad}\n")
    with pytest.raises(ConfigError, match="unknown key"):
        _load(tmp_path, "[groups]\nauto_leave = true\n")
    with pytest.raises(ConfigError, match="must be int"):
        _load(tmp_path, '[groups]\nleave_timeout_secs = "soon"\n')


def test_journal_entries_say_their_summaries_report_leaves() -> None:
    """An entry this daemon journals says its summary has a real `left`; one
    an older daemon wrote doesn't, and may hold a summary from before it."""
    env = {"kind": "commit", "group_id": "g", "msg_id": "m", "sender": "s", "ct": "x"}
    ctx = json.loads(journal_context(env, from_relay=True))
    assert ctx[SUMMARY_REPORTS_LEAVES] is True
    assert "ct" not in ctx["env"]


# -- roles and the policy (G2, G3, G11) ---------------------------------------------------


def full_policy(owner: str, **fields: Any) -> dict[str, Any]:
    return {
        "v": 0,
        "owner": owner,
        "admins": [],
        "invite": "owner",
        "remove": "owner",
        "max_members": 50,
        "require_verified": False,
        "floor": "free",
        "floor_pinned": False,
        "floor_moderator": None,
        "loop_guard": {"max_agent_turns": 20},
        **fields,
    }


def test_a_request_becomes_the_policy_fields_it_changes() -> None:
    assert policy_changes({"max_agent_turns": 4, "invite": "members"}) == {
        "invite": "members",
        "loop_guard": {"max_agent_turns": 4},
    }
    # Setting the floor pins it, unless the request says otherwise.
    assert policy_changes({"floor": "mention"}) == {"floor": "mention", "floor_pinned": True}
    assert policy_changes({"floor": "free", "floor_pinned": False}) == {
        "floor": "free",
        "floor_pinned": False,
    }
    assert policy_changes({"floor_moderator": None}) == {"floor_moderator": None}
    for bad, why in (({}, "nothing to change"), ({"owner": "x"}, "unknown policy field")):
        with pytest.raises(DaemonError, match=why) as e:
            policy_changes(bad)
        assert e.value.code == "bad_request"


def test_a_policy_change_is_applied_to_the_policy_in_force(ids: Ids) -> None:
    """G2: the intent holds what changes, so a rebuild against a newer
    policy keeps what another member changed meanwhile."""
    a, b = ids.identity(), ids.identity()
    queued = {"type": "policy", "changes": {"invite": "members"}}
    newer = full_policy(a, floor="moderated", floor_pinned=True)
    assert planned_policy(newer, queued, {a, b}) == {**newer, "invite": "members"}
    # A row queued before changes were deltas holds a whole policy: only its
    # require_verified applies, never the rest it cached (review 52 F5).
    legacy = {"type": "policy", "policy": full_policy(b, admins=[a], require_verified=True)}
    assert planned_policy(newer, legacy, {a}) == {**newer, "require_verified": True}
    assert planned_policy(newer, {"type": "policy", "policy": {"owner": b}}, {a}) == newer
    assert planned_policy(newer, {"type": "policy"}, {a}) == newer


def test_a_transfer_and_role_changes(ids: Ids) -> None:
    a, b, c = ids.identity(), ids.identity(), ids.identity()
    current = full_policy(a, admins=[b, c])
    to_b = {"type": "owner", "identity": b, "keep_admin": True}
    assert planned_policy(current, to_b, {a, b, c}) == {**current, "owner": b, "admins": [c, a]}
    keep_not = {**to_b, "keep_admin": False}
    assert planned_policy(current, keep_not, {a, b, c}) == {**current, "owner": b, "admins": [c]}
    assert planned_policy(current, {**to_b, "identity": a}, {a}) == current
    # The old owner already an admin (a policy the core accepts) stays once.
    odd = full_policy(a, admins=[a, b])
    assert planned_policy(odd, to_b, {a, b})["admins"] == [a]

    make = {"type": "role", "identity": c, "role": "admin"}
    assert planned_policy(full_policy(a), make, {a, c})["admins"] == [c]
    # Gone by the time the commit is built (review 52 F4b): no role for it.
    with pytest.raises(DaemonError) as e:
        planned_policy(full_policy(a), make, {a})
    assert e.value.code == "not_permitted"
    assert planned_policy(current, make, {a, b, c}) == current  # already one
    drop = {**make, "role": "member"}
    assert planned_policy(current, drop, {a, b, c})["admins"] == [b]
    with pytest.raises(DaemonError, match="transfer"):
        planned_policy(current, {**make, "identity": a}, {a})


def test_departed_roles_only_narrow(ids: Ids) -> None:
    """G11: only identities with no instance left lose their roles, and the
    change never adds one."""
    a, b, c, m = (ids.identity() for _ in range(4))
    current = full_policy(a, admins=[b, c], floor_moderator=m)
    gone = {"type": "drop_roles", "identities": [b, m]}
    assert planned_policy(current, gone, {a, c}) == {
        **current,
        "admins": [c],
        "floor_moderator": None,
    }
    # One that came back meanwhile keeps its role.
    assert planned_policy(current, gone, {a, b, c, m}) == current
    with pytest.raises(DaemonError, match="unknown policy intent"):
        planned_policy(current, {"type": "nope"}, {a})


def test_who_may_invite(ids: Ids) -> None:
    a, b, c = ids.identity(), ids.identity(), ids.identity()
    owner_only = full_policy(a, admins=[b])
    assert may_invite(owner_only, a)
    assert not may_invite(owner_only, b)
    admins = {**owner_only, "invite": "admins"}
    assert may_invite(admins, b)
    assert not may_invite(admins, c)
    assert may_invite({**owner_only, "invite": "members"}, c)
    assert not may_invite({**admins, "admins": None}, b)


def test_departed_roles_cleanup_can_be_turned_off(tmp_path: Path) -> None:
    assert _load(tmp_path, "").groups_cleanup_departed_roles is True
    cfg = _load(tmp_path, "[groups]\ncleanup_departed_roles = false\n")
    assert cfg.groups_cleanup_departed_roles is False
    with pytest.raises(ConfigError, match="must be bool"):
        _load(tmp_path, '[groups]\ncleanup_departed_roles = "no"\n')


def test_a_leaf_repeating_an_instance_id_is_a_new_instance(ids: Ids) -> None:
    """Review 52 F1: instances are told apart by id and mailbox, so a leaf
    that repeats an instance id with another key is reported as joining."""
    a, b = ids.identity(), ids.identity()
    one = {**member(b, "1" * 16, 1), "mailbox_id": "m1"}
    twin = {**member(b, "1" * 16, 2), "mailbox_id": "m2"}
    events = membership_events(summary(a, added=[twin]), [one, twin])
    assert events == [("instance_joined", {"identity": b, "instance_id": "1" * 16, "by": a})]
    gone = membership_events(summary(a, removed=[twin], left=[one]), [one])
    assert gone == [("instance_removed", {"identity": b, "instance_id": "1" * 16, "by": a})]
