"""The instance hint (SPEC 9.4, docs/groups.md#addressing-one-instance): the
sender's daemon checks its shape and writes it as ``body.metadata.instance``;
a receiver reads it only to narrow who is triggered, never to widen it. The
harness sends it between real daemons (``harness/tests/test_instance_hint.py``)."""

from __future__ import annotations

import random
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentconnect.runtime.engine import (
    HINTED_KINDS,
    DaemonError,
    addressed_to_me,
    with_instance,
)
from agentconnect.schemas import normalize

ME, OTHER = "ac:v0:me", "ac:v0:other"
MINE, THEIRS = "00000000000000aa", "00000000000000bb"


def instance(rng: random.Random) -> str:
    return f"{rng.getrandbits(64):016x}"


def message(text: str = "hi", **metadata: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"messageId": "m1", "role": "ROLE_AGENT", "parts": [{"text": text}]}
    if metadata:
        body["metadata"] = metadata
    return body


def test_the_hint_becomes_body_metadata_instance(rng: random.Random) -> None:
    hint = instance(rng)
    body = message()
    hinted = with_instance("a2a.message", body, hint)
    assert hinted["metadata"] == {"instance": hint}
    assert "metadata" not in body  # the caller's body is left as it was
    # Other metadata is kept, and a hint already there is replaced.
    kept = with_instance("a2a.message", message(lang="en", instance=instance(rng)), hint)
    assert kept["metadata"] == {"lang": "en", "instance": hint}


@pytest.mark.parametrize("kind", sorted(HINTED_KINDS))
def test_every_kind_that_triggers_takes_a_hint(kind: str, rng: random.Random) -> None:
    hint = instance(rng)
    assert with_instance(kind, {"id": "t1"}, hint)["metadata"]["instance"] == hint


def test_a_cancel_keeps_its_hint_in_its_schema(rng: random.Random) -> None:
    hint = instance(rng)
    shaped = normalize("a2a.task_cancel", with_instance("a2a.task_cancel", {"id": "t1"}, hint))
    assert shaped == {"id": "t1", "metadata": {"instance": hint}}


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "XYZ",
        "00000000000000AA",  # SPEC 3.3: lowercase
        "00000000000000a",  # 15 characters
        "00000000000000aaa",  # 17 characters
        "00000000000000aa\n",
        " 00000000000000aa",
        "ac:v0:someone",
    ],
)
def test_a_malformed_hint_is_refused(bad: str) -> None:
    with pytest.raises(DaemonError) as e:
        with_instance("a2a.message", message(), bad)
    assert e.value.code == "bad_request"
    # Also when the body carries it itself.
    with pytest.raises(DaemonError) as e:
        with_instance("a2a.message", message(instance=bad), None)
    assert e.value.code == "bad_request"


@pytest.mark.parametrize("bad", [7, ["00000000000000aa"], {"id": "00000000000000aa"}, True])
def test_a_body_hint_that_is_not_a_string_is_refused(bad: object) -> None:
    with pytest.raises(DaemonError) as e:
        with_instance("a2a.task_status", {"taskId": "t", "metadata": {"instance": bad}}, None)
    assert e.value.code == "bad_request"


def test_a_well_formed_body_hint_or_none_passes_unchanged(rng: random.Random) -> None:
    body = message(instance=instance(rng))
    assert with_instance("a2a.message", body, None) is body
    unset = message(instance=None)
    assert with_instance("a2a.message", unset, None) is unset
    odd = {"messageId": "m", "parts": [{"text": "x"}], "metadata": "not an object"}
    assert with_instance("a2a.message", odd, None) is odd  # the limits judge the rest


@pytest.mark.parametrize("kind", ["control.pause", "control.leave", "a2a.agent_card"])
def test_kinds_that_trigger_nobody_take_no_hint(kind: str, rng: random.Random) -> None:
    with pytest.raises(DaemonError) as e:
        with_instance(kind, {}, instance(rng))
    assert e.value.code == "bad_request"
    # A control's body keeps only its schema, so nothing there is checked.
    body = {"reason": "human", "metadata": {"instance": "XYZ"}}
    assert with_instance(kind, body, None) is body


def test_metadata_that_is_not_an_object_is_refused(rng: random.Random) -> None:
    with pytest.raises(DaemonError) as e:
        with_instance("a2a.message", {"parts": [], "metadata": ["x"]}, instance(rng))
    assert e.value.code == "bad_request"


def hinted(inner: dict[str, Any], hint: object) -> dict[str, Any]:
    body = dict(inner.get("body") or {})
    body["metadata"] = {"instance": hint}
    return {**inner, "body": body}


def test_a_hint_picks_one_instance_of_whoever_the_floor_triggers() -> None:
    to_me = {"to": [ME], "origin": "agent", "body": {"text": "x"}}
    assert addressed_to_me("mention", hinted(to_me, MINE), ME, MINE, None)
    assert not addressed_to_me("mention", hinted(to_me, THEIRS), ME, MINE, None)
    # Naming an instance of a member the floor doesn't trigger triggers nobody.
    to_other = {"to": [OTHER], "origin": "agent", "body": {"text": "x"}}
    assert not addressed_to_me("mention", hinted(to_other, MINE), ME, MINE, None)
    # A malformed hint names no instance: nobody is triggered.
    for bad in ("XYZ", 7, ["00000000000000aa"], {"x": 1}, MINE.upper()):
        assert not addressed_to_me("free", hinted(to_me, bad), ME, MINE, None)
    # An explicit null is no hint.
    assert addressed_to_me("mention", hinted(to_me, None), ME, MINE, None)
    # Moderated: within the moderator and the holder only.
    anyone = {"to": ["*"], "origin": "human", "body": {"text": "x"}}
    assert addressed_to_me("moderated", hinted(anyone, MINE), ME, MINE, OTHER, ME)
    assert not addressed_to_me("moderated", hinted(anyone, MINE), ME, MINE, OTHER, OTHER)
    assert not addressed_to_me("moderated", hinted(anyone, THEIRS), ME, MINE, ME, ME)


IDENTITIES = st.sampled_from([ME, OTHER, "ac:v0:third"])
HINTS = st.one_of(
    st.none(),
    st.sampled_from([MINE, THEIRS, MINE.upper(), ""]),
    st.text(max_size=20),
    st.integers(),
    st.lists(st.sampled_from([MINE, THEIRS]), max_size=2),
)


@given(
    floor=st.sampled_from(["free", "mention", "moderated", "other"]),
    to=st.one_of(st.just(["*"]), st.lists(IDENTITIES, min_size=1, max_size=3)),
    addressee=st.one_of(st.none(), st.lists(IDENTITIES, max_size=3), st.just("not a list")),
    origin=st.sampled_from(["agent", "human"]),
    moderator=st.one_of(st.none(), IDENTITIES),
    holder=st.one_of(st.none(), IDENTITIES),
    hint=HINTS,
)
def test_a_hint_never_widens_triggering(  # noqa: PLR0913, PLR0917
    floor: str,
    to: list[str],
    addressee: object,
    origin: str,
    moderator: str | None,
    holder: str | None,
    hint: object,
) -> None:
    inner: dict[str, Any] = {"to": to, "origin": origin, "body": {"text": "x"}}
    if addressee is not None:
        inner["addressee"] = addressee
    plain = addressed_to_me(floor, inner, ME, MINE, moderator, holder)
    narrowed = addressed_to_me(floor, hinted(inner, hint), ME, MINE, moderator, holder)
    # A peer's hint can only take triggering away (SPEC 9.4)...
    assert not narrowed or plain
    # ...and naming this instance, or nothing, takes nothing away.
    if hint is None or hint == MINE:
        assert narrowed == plain
    else:
        assert not narrowed
