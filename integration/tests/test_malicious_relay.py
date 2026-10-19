"""The malicious relay double against the docker deployment.

The fast tier runs these attacks on in-process daemons
(``harness/tests/test_scenarios.py``, ``test_group_acceptance.py``); here
the same checks run on the docker hosts, each behind its own relay tap,
whose harness proxy replays, injects and forks frames on request
(``agentconnect_harness.tap``). One group of three for the module; the
fork goes last, since it leaves the group split."""

from __future__ import annotations

import base64
import random
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.timeout(600)


@pytest.fixture(scope="module")
def trio(
    image: str, driver: ModuleType, compose_project: Callable[[str], str]
) -> Iterator[tuple[Any, str, dict[str, str]]]:
    with driver.deployment(compose_project("malicious"), ("group",), quiet=True) as dep:
        gid, ids = driver.form_group(dep)
        yield dep, gid, ids


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def state(dep: Any, gid: str, service: str) -> tuple[int, int]:
    view = dep.group(service, gid)
    return int(view["epoch"]), len(view["members"])


def statement(driver: ModuleType, dep: Any, gid: str, to: str, text: str) -> None:
    """The human tells B something (not a question: nobody answers it)."""
    driver.human_send(dep, "daemon-a", gid, text, [to])


def test_replayed_frames_are_rejected(
    trio: tuple[Any, str, dict[str, str]], driver: ModuleType, rng: random.Random
) -> None:
    dep, gid, ids = trio
    first, later = f"r1-{rng.getrandbits(32):08x}", f"r2-{rng.getrandbits(32):08x}"
    statement(driver, dep, gid, ids["b"], f"Status: the v0.1 branch is frozen ({first}).")
    dep.wait_log("agent-b", first)
    replayed = dep.tap("host-b", "replay", kind="application")  # the same msg_id
    renamed = dep.tap("host-b", "replay", kind="application", rename=True)  # same ciphertext
    assert replayed["env"]["ct"] == renamed["env"]["ct"]
    assert replayed["env"]["msg_id"] != renamed["env"]["msg_id"]
    # Delivery is in order per group: once the next message is through,
    # both replays were handled before it.
    statement(driver, dep, gid, ids["b"], f"Status: the notes are reviewed ({later}).")
    dep.wait_log("agent-b", later)
    assert len(dep.lines("agent-b", first)) == 1
    assert {r["msg_id"] for r in dep.audit("daemon-b")} >= {replayed["env"]["msg_id"]}
    assert renamed["env"]["msg_id"] not in {
        r["msg_id"] for r in dep.audit("daemon-b") if r["decision"].startswith("deliver")
    }
    assert len({state(dep, gid, s) for s in ("daemon-a", "daemon-b", "agent-c")}) == 1


def test_an_injected_commit_is_rejected(
    trio: tuple[Any, str, dict[str, str]], driver: ModuleType, rng: random.Random
) -> None:
    """The relay presents a commit nobody sent at this epoch: an old one
    relabelled as current, and one with a changed byte. No member moves."""
    dep, gid, ids = trio
    before = {s: state(dep, gid, s) for s in ("daemon-a", "daemon-b", "agent-c")}
    epoch = before["daemon-b"][0]
    old = dep.tap("host-b", "last", kind="commit")["env"]
    assert old["epoch"] < epoch
    ct = bytearray(base64.urlsafe_b64decode(old["ct"] + "=" * (-len(old["ct"]) % 4)))
    ct[len(ct) // 2] ^= 0x01
    forged = [
        {**old, "epoch": epoch, "msg_id": b64(rng.randbytes(16))},
        {**old, "epoch": epoch, "msg_id": b64(rng.randbytes(16)), "ct": b64(bytes(ct))},
    ]
    for env in forged:
        dep.tap("host-b", "inject", frame={"t": "deliver", "env": env})
    marker = f"r3-{rng.getrandbits(32):08x}"
    statement(driver, dep, gid, ids["b"], f"Status: still one group ({marker}).")
    dep.wait_log("agent-b", marker)
    after = {s: state(dep, gid, s) for s in before}
    assert after == before
    # B tells its human that it refused a commit (it can't tell a forged one
    # from a real one it can't process); A and C saw nothing.
    flagged = [e["data"] for e in dep.events("daemon-b") if e["type"] == "out_of_sync"]
    assert flagged
    assert {d["reason"] for d in flagged} == {"commit_rejected"}
    for s in ("daemon-a", "agent-c"):
        assert not [e for e in dep.events(s) if e["type"] == "out_of_sync"]


def test_a_forked_group_view_shows_in_sas_runs(
    trio: tuple[Any, str, dict[str, str]], driver: ModuleType
) -> None:
    """A's commit reaches B only: A and B move to an epoch C never sees. A
    SAS run between A and B gives both the same code; one between A and C
    never pairs (SPEC 12)."""
    dep, gid, _ids = trio
    epoch, members = state(dep, gid, "agent-c")
    dep.tap("host-a", "fork")
    dep.cli("daemon-a", "group", "policy", gid, "--max-agent-turns", "9", echo=False)
    driver.wait_for("A's own commit", lambda: state(dep, gid, "daemon-a")[0] == epoch + 1 or None)
    (withheld,) = dep.tap("host-a", "forked")
    dep.tap("host-b", "inject", frame={"t": "deliver", "env": withheld["env"]})
    driver.wait_for("B on A's epoch", lambda: state(dep, gid, "daemon-b")[0] == epoch + 1 or None)
    a, b, c = (state(dep, gid, s) for s in ("daemon-a", "daemon-b", "agent-c"))
    assert a == b == (epoch + 1, members)
    assert c == (epoch, members)
    run_a, run_b = driver.sas_runs(dep, "daemon-a", "daemon-b", gid)
    assert run_a["state"] == run_b["state"] == "done"
    assert run_a["sas"] == run_b["sas"]
    run_a, run_c = driver.sas_runs(dep, "daemon-a", "agent-c", gid, within=15)
    for seen in (run_a, run_c):
        assert "peer_instance" not in seen, seen  # never paired
        assert "sas" not in seen
