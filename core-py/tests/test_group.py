"""Round trips through the bindings: identity, invite, join, messages, SAS runs."""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path
from typing import Any

import pytest

import agentconnect_core as ac

NAME = "Trip planning"
PURPOSE = "Plan the offsite"


def make_client(rng: random.Random, path: Path | None = None) -> ac.Client:
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(64))
    return ac.Client._for_testing(
        None if path is None else str(path),
        instance.to_secret_bytes(),
        rng.getrandbits(64),
        None if path is None else rng.randbytes(ac.DB_KEY_LEN),
    )


def inner(client: ac.Client, text: str) -> bytes:
    return json.dumps(
        {
            "v": 0,
            "sender": client.identity,
            "instance_id": client.instance_id_hex,
            "kind": "a2a.message",
            "body": {"text": text},
        }
    ).encode()


def invite_meta(invite: ac.Invite) -> bytes:
    return json.dumps(
        {
            "invite_id": invite.invite_id_b64,
            "group_name": NAME,
            "inviter_name": "a",
            "purpose": PURPOSE,
            "expires_at": invite.expires_at,
            "max_uses": 1,
            "uses_left": 1,
            "status": "open",
            "protocol": 0,
        }
    ).encode()


def join(inviter: ac.Client, gid: bytes, joiner: ac.Client) -> dict[str, Any]:
    invite = inviter.create_invite("relay.example", 3600)
    link = ac.parse_invite_url(invite.url)
    request = joiner.create_join_request(link, "joiner")
    verified = inviter.verify_join_request(request, invite)
    assert verified.mailbox_id == joiner.mailbox_id
    out = inviter.add_member(gid, verified, invite)
    with pytest.raises(ac.AgentConnectError, match="already pending"):
        inviter.add_member(gid, verified, invite)
    # A failed add leaves the verified request usable: rebuild after a discard.
    inviter.discard_pending_commit(gid)
    out = inviter.add_member(gid, verified, invite)
    inviter.confirm_pending_commit(gid, out["msg_id"])
    with pytest.raises(ac.AgentConnectError, match="key package already used"):
        inviter.add_member(gid, verified, invite)
    with pytest.raises(ac.AgentConnectError, match="key package already used"):
        inviter.verify_join_request(request, invite)
    welcome = out["welcome"]
    assert isinstance(welcome, bytes)
    assert joiner.join(link, invite_meta(invite), welcome) == gid
    return out


def run_codes(a: ac.Client, b: ac.Client, gid: bytes) -> tuple[ac.Sas, ac.Sas]:
    """Both sides' codes of a SAS run between `a` and `b` (SPEC 11.4), each
    in its own current epoch."""
    na, nb = a.sas_nonce(), b.sas_nonce()
    code_a = a.sas_code(gid, a.epoch(gid), na, b.identity, int(b.instance_id_hex, 16), nb.reveal())
    code_b = b.sas_code(gid, b.epoch(gid), nb, a.identity, int(a.instance_id_hex, 16), na.reveal())
    return code_a, code_b


def same_view(a: ac.Client, b: ac.Client, gid: bytes) -> bool:
    code_a, code_b = run_codes(a, b, gid)
    return code_a == code_b


def test_one_to_one_round_trip(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    assert a.epoch(gid) == b.epoch(gid) == 1
    code_a, code_b = run_codes(a, b, gid)
    assert code_a == code_b
    assert len(code_a.emoji_indices) == 7
    assert repr(a.sas_nonce()) == "SasNonce(..)"
    nonce = a.sas_nonce()
    with pytest.raises(ac.AgentConnectError, match="different epoch"):
        a.sas_code(gid, 0, nonce, b.identity, int(b.instance_id_hex, 16), nonce.reveal())
    with pytest.raises(ac.AgentConnectError, match="oneself"):
        a.sas_code(gid, 1, nonce, a.identity, int(a.instance_id_hex, 16), nonce.reveal())
    with pytest.raises(ac.AgentConnectError, match="unknown member"):
        a.sas_code(gid, 1, nonce, b.identity, 7, nonce.reveal())
    with pytest.raises(ac.AgentConnectError, match="32 bytes"):
        a.sas_code(gid, 1, nonce, b.identity, int(b.instance_id_hex, 16), b"short")
    own = a.sas_commitment(gid, b.identity, nonce)
    assert own == ac.sas_commitment(
        gid, 1, a.identity, int(a.instance_id_hex, 16), b.identity, nonce.reveal()
    )
    assert json.loads(b.meta(gid))["purpose"] == PURPOSE
    assert json.loads(a.policy(gid))["owner"] == a.identity

    ct = a.seal(gid, inner(a, "hi"))
    msg = b.open(gid, ct)
    assert msg["type"] == "application"
    assert msg["sender"]["identity"] == a.identity
    assert json.loads(msg["plaintext"])["body"]["text"] == "hi"
    event = a.process(gid, b.seal(gid, inner(b, "hello")))
    assert event["sender"]["identity"] == b.identity

    with pytest.raises(ac.AgentConnectError):
        b.open(gid, ct)  # replay


def test_group_commits_converge(rng: random.Random) -> None:
    a, b, c = (make_client(rng) for _ in range(3))
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    out = join(a, gid, c)
    event = b.process(gid, out["commit"])
    assert event["type"] == "commit"
    assert event["routing"] == out["routing"]
    assert json.loads(b.policy(gid))["floor"] == "mention"
    assert same_view(a, b, gid)
    assert same_view(a, c, gid)

    upd = b.update(gid)
    assert b.has_pending_commit(gid)
    with pytest.raises(ac.AgentConnectError, match="does not match the pending commit"):
        b.confirm_pending_commit(gid, out["msg_id"])
    assert b.process(gid, upd["commit"])["type"] == "own_commit_confirmed"
    for client in (a, c):
        client.process(gid, upd["commit"])
    assert same_view(a, b, gid)
    assert same_view(b, c, gid)

    leave = c.propose_leave(gid)
    assert a.process(gid, leave)["type"] == "leave_proposed"
    b.process(gid, leave)
    out = a.commit_pending_proposals(gid)
    a.confirm_pending_commit(gid, out["msg_id"])
    b.process(gid, out["commit"])
    assert c.process(gid, out["commit"])["type"] == "removed"
    assert len(a.members(gid)) == 2
    c.delete_group(gid)

    policy = json.loads(a.policy(gid))
    policy["require_verified"] = True
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    out = a.set_policy(gid, canonical)
    a.discard_pending_commit(gid)
    with pytest.raises(ac.AgentConnectError, match="not permitted"):
        b.remove(gid, a.identity)
    assert out["epoch"] == a.epoch(gid)


def test_wrong_secret_and_bad_inputs(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    a.create_group(NAME, PURPOSE)
    invite = a.create_invite("relay.example", 60)
    wrong = rng.randbytes(32)
    link = ac.parse_invite_url(invite.url.split("&s=")[0] + "&s=" + _b64(wrong))
    request = b.create_join_request(link, "b")
    with pytest.raises(ac.AgentConnectError, match="MAC"):
        a.verify_join_request(request, invite)
    with pytest.raises(ac.AgentConnectError, match="unsupported protocol version"):
        ac.parse_invite_url(invite.url.replace("v=0", "v=1"))
    with pytest.raises(ac.AgentConnectError, match="unknown group"):
        a.epoch(b"\x00" * 16)
    with pytest.raises(ac.AgentConnectError, match="16 bytes"):
        ac.unwrap_welcome(b"x", bytes(32), b"")
    with pytest.raises(ac.AgentConnectError, match="32 bytes"):
        ac.unwrap_welcome(bytes(16), b"y", b"")
    a._set_time_for_testing(invite.expires_at)
    good = b.create_join_request(ac.parse_invite_url(invite.url), "b")
    with pytest.raises(ac.AgentConnectError, match="expired"):
        a.verify_join_request(good, invite)
    a._set_time_for_testing(None)


def test_a_join_request_seen_before_is_a_replay(rng: random.Random) -> None:
    """SPEC 6.2 "Replays": the inviter remembers a verified request by its
    request id and KeyPackageRef until its invite expires (plus the grace),
    and a full ledger refuses (``busy``) without evicting."""
    a, b = make_client(rng), make_client(rng)
    invite = a.create_invite("relay.example", 86_400)
    link = ac.parse_invite_url(invite.url)
    request = b.create_join_request(link, "b")
    first = a.verify_join_request(request, invite)
    assert first.forget_after == invite.expires_at + ac.LEDGER_GRACE_SECS
    ledger = ac.ReplayLedger(capacity=2)
    first.remember_in(ledger, b"msg-1")  # then the human rejects it
    again = a.verify_join_request(request, invite)
    for request_id in (b"msg-1", b"msg-2"):
        with pytest.raises(ac.AgentConnectError) as e:
            again.remember_in(ledger, request_id)
        assert e.value.kind == "replay"
    other = a.verify_join_request(b.create_join_request(link, "b"), invite)
    other.remember_in(ledger, b"msg-3")
    third = a.verify_join_request(b.create_join_request(link, "b"), invite)
    with pytest.raises(ac.AgentConnectError) as e:
        third.remember_in(ledger, b"msg-4")
    assert e.value.kind == "busy"
    assert sorted(i for i, _, _ in ledger.entries()) == [b"msg-1", b"msg-3"]
    ledger.purge(first.forget_after + 1)
    assert len(ledger) == 0
    assert ac.ReplayLedger().capacity == ac.DEFAULT_LEDGER_CAPACITY


def test_persistence_and_invite_parts(rng: random.Random, tmp_path: Path) -> None:
    db = tmp_path / "b.sqlite"
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(64), now=1_800_000_000)
    assert json.loads(instance.cert_json)["created_at"] == 1_800_000_000
    saved = instance.to_secret_bytes()
    db_key = rng.randbytes(ac.DB_KEY_LEN)
    a = make_client(rng)
    b = ac.Client(str(db), saved, db_key)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    del b
    b = ac.Client(str(db), ac.Instance.from_secret_bytes(saved).to_secret_bytes(), db_key)
    assert same_view(a, b, gid)
    assert b.open(gid, a.seal(gid, inner(a, "persisted")))["epoch"] == 1

    invite = a.create_invite("relay.example")
    restored = ac.Invite.from_parts(
        invite.relay_host, invite.invite_id, invite.secret_bytes(), invite.expires_at
    )
    assert restored.url == invite.url
    link = ac.parse_invite_url(invite.url)
    assert link.secret_bytes() == invite.secret_bytes()
    assert link.invite_id == invite.invite_id
    assert link.relay_host == "relay.example"
    assert link.url == invite.url
    again = ac.Identity.from_secret_bytes(identity.secret_bytes())
    assert again.id == identity.id
    assert again.fingerprint == ac.fingerprint(identity.public_key)
    assert ac.identity_id(identity.public_key) == identity.id
    assert instance.identity == identity.id
    assert instance.mailbox_id == ac.mailbox_id(instance.public_key)
    assert f"{instance.instance_id:016x}" == instance.instance_id_hex
    assert repr(identity).startswith("Identity(")


def test_peek_header_reads_the_header_and_consumes_nothing(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    epoch = b.epoch(gid)
    ct = a.seal(gid, inner(a, "peeked"))
    head = ac.peek_header(ct)
    assert head == {"group_id": gid, "epoch": epoch, "content_type": "application"}
    # An envelope claiming another epoch is caught before processing; the
    # key is untouched, so the original still opens (once).
    assert head["epoch"] != epoch + 1
    assert ac.peek_header(ct) == head
    assert b.open(gid, ct)["plaintext"] == inner(a, "peeked")
    with pytest.raises(ac.AgentConnectError):
        b.open(gid, ct)
    assert ac.peek_header(b.propose_leave(gid))["content_type"] == "proposal"
    commit = a.update(gid)["commit"]
    assert ac.peek_header(commit) == {"group_id": gid, "epoch": epoch, "content_type": "commit"}


@pytest.mark.parametrize("bad", [b"", b"junk", b"\x00\x01"])
def test_peek_header_rejects_what_process_rejects(rng: random.Random, bad: bytes) -> None:
    with pytest.raises(ac.AgentConnectError, match="malformed"):
        ac.peek_header(bad)
    a = make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    with pytest.raises(ac.AgentConnectError, match="malformed"):
        a.process(gid, bad)


def test_group_policy_vectors(rng: random.Random) -> None:
    """The policies of testdata/group-policy.json (SPEC 9.1) through set_policy.

    Its authorization cases (SPEC 9.2) are checked by core/src/vectors.rs;
    the policy changes alone are also checked here, through
    check_policy_change (test_group_policy_authorization_vectors).
    """
    testdata = Path(__file__).resolve().parents[2] / "testdata"
    vectors = json.loads((testdata / "group-policy.json").read_text(encoding="utf-8"))
    a = make_client(rng)
    gid = a.create_group(NAME, PURPOSE)

    def own(policy: str) -> bytes:
        # The vector's owner becomes this client, the group's only member.
        return policy.replace(json.loads(policy)["owner"], a.identity).encode()

    assert a.policy(gid) == own(vectors["default"])
    for case in vectors["valid"]:
        if "pending" in case:
            # A SPEC rule the core doesn't implement yet: drop the mark when
            # it does, and this policy is accepted.
            with pytest.raises(ac.AgentConnectError, match="malformed group policy"):
                a.set_policy(gid, own(case["policy"]))
            continue
        a.set_policy(gid, own(case["policy"]))
        a.discard_pending_commit(gid)
    for case in vectors["invalid"]:
        with pytest.raises(ac.AgentConnectError) as err:
            a.set_policy(gid, case["policy"].encode())
        assert str(err.value) == case["error"], case["name"]


def _join_without_switch(owner: ac.Client, gid: bytes, joiner: ac.Client) -> bytes:
    """``join``, but the Add never switches the floor: the vector's policy
    stays the one in force."""
    invite = owner.create_invite("relay.example", 3600)
    link = ac.parse_invite_url(invite.url)
    verified = owner.verify_join_request(joiner.create_join_request(link, "j"), invite)
    out = owner.add_member(gid, verified, invite, switch_floor=False)
    owner.confirm_pending_commit(gid, out["msg_id"])
    assert joiner.join(link, invite_meta(invite), out["welcome"]) == gid
    commit = out["commit"]
    assert isinstance(commit, bytes)
    return commit


#: Authorization cases of group-policy.json Python doesn't check, by name,
#: each with the reason. Every other case is checked.
SKIPPED_AUTHORIZATION_CASES: dict[str, str] = {}


def _dry_runnable(facts: dict[str, Any], three: set[str]) -> bool:
    """A GroupContextExtensions alone, in a group of owner, admin and
    member: what the committer's check_policy_change can answer."""
    return (
        not facts["adds"]
        and not facts["removes"]
        and facts["new_policy"] is not None
        and set(facts["identities_before"]) == three
        and set(facts["identities_after"]) == three
        and (facts["leaves_before"], facts["leaves_after"]) == (3, 3)
    )


def test_group_policy_authorization_vectors(rng: random.Random) -> None:
    """Every authorization case of testdata/group-policy.json (SPEC 9.2).

    Each case's facts go through the core's authorisation as stored in the
    file. The policy-change cases also run, in a real group of owner, admin
    and member, through the committer's check_policy_change, with the
    vector's identities replaced by these clients'. A case marked
    `pending` must not pass, as in core/src/vectors.rs.
    """
    testdata = Path(__file__).resolve().parents[2] / "testdata"
    vectors = json.loads((testdata / "group-policy.json").read_text(encoding="utf-8"))
    ids = vectors["identities"]
    clients = {label: make_client(rng) for label in ("owner", "admin", "member", "joiner")}

    def ours(policy: str) -> bytes:
        for label, identity in ids.items():
            policy = policy.replace(identity, clients[label].identity)
        return policy.encode()

    def answer(call: Any) -> str:
        try:
            call()
        except ac.AgentConnectError as e:
            return str(e)
        return "ok"

    policies = {p["name"]: p["policy"] for p in vectors["valid"]}
    three = {ids["owner"], ids["admin"], ids["member"]}
    cases = vectors["authorization"]
    names = [c["name"] for c in cases]
    assert len(set(names)) == len(names)
    assert set(SKIPPED_AUTHORIZATION_CASES) <= set(names)
    groups: dict[str, bytes] = {}
    checked = dry_runs = 0
    for case in cases:
        name, f, old = case["name"], case["facts"], case["policy"]
        if name in SKIPPED_AUTHORIZATION_CASES:
            continue
        new = None if f["new_policy"] is None else policies[f["new_policy"]].encode()
        got = answer(
            lambda f=f, old=old, new=new: ac._native._authorize_for_testing(
                policies[old].encode(), json.dumps(f).encode(), new
            )
        )
        if "pending" in case:
            assert got != case["result"], f"{name} passes now; drop `pending`"
        else:
            assert got == case["result"], name
        checked += 1
        if "pending" in case or not _dry_runnable(f, three):
            continue
        if old not in groups:
            owner = clients["owner"]
            gid = owner.create_group(NAME, PURPOSE, policy=ours(policies[old]))
            _join_without_switch(owner, gid, clients["admin"])
            commit = _join_without_switch(owner, gid, clients["member"])
            clients["admin"].process(gid, commit)
            assert owner.policy(gid) == ours(policies[old]), old
            groups[old] = gid
        label = next(k for k, v in ids.items() if v == f["committer"])
        new_ours = ours(policies[f["new_policy"]])
        dry = answer(
            lambda c=clients[label], g=groups[old], n=new_ours: c.check_policy_change(g, n)
        )
        assert dry == case["result"], name
        dry_runs += 1
    assert checked + len(SKIPPED_AUTHORIZATION_CASES) == len(cases)
    assert dry_runs == sum(
        1 for c in cases if "pending" not in c and _dry_runnable(c["facts"], three)
    )
    assert dry_runs > 0


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def replicas(rng: random.Random, n: int) -> list[ac.Client]:
    """``n`` instances of one identity."""
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    return [
        ac.Client._for_testing(
            None,
            identity._create_instance_for_testing(seed=rng.getrandbits(64)).to_secret_bytes(),
            rng.getrandbits(64),
        )
        for _ in range(n)
    ]


def grow(owner: ac.Client, gid: bytes, members: list[ac.Client], joiner: ac.Client) -> None:
    """``joiner`` joins through the owner; every member processes the commit."""
    out = join(owner, gid, joiner)
    for m in members:
        if m is not owner:
            assert m.process(gid, out["commit"])["type"] == "commit"
    members.append(joiner)


def test_a_group_starts_with_its_policy_and_a_replica_keeps_it_free(rng: random.Random) -> None:
    a = make_client(rng)
    defaults = json.loads(a.policy(a.create_group(NAME, PURPOSE)))
    assert defaults["floor_pinned"] is False
    b1, b2 = replicas(rng, 2)
    gid = a.create_group(NAME, PURPOSE)
    members = [a]
    grow(a, gid, members, b1)
    grow(a, gid, members, b2)
    # Three instances, two identities: still free.
    assert json.loads(a.policy(gid))["floor"] == "free"

    pinned = {**defaults, "floor_pinned": True}
    with pytest.raises(ac.AgentConnectError, match="creator must be the owner"):
        b1.create_group(NAME, PURPOSE, policy=canonical(pinned))
    with pytest.raises(ac.AgentConnectError, match="max_members"):
        a.create_group(NAME, PURPOSE, policy=canonical({**pinned, "max_members": 0}))
    gid = a.create_group(NAME, PURPOSE, policy=canonical(pinned))
    assert json.loads(a.policy(gid)) == pinned
    members = [a]
    for joiner in (make_client(rng), make_client(rng)):
        grow(a, gid, members, joiner)
    assert json.loads(members[2].policy(gid)) == pinned


def test_check_policy_change_is_a_dry_run(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    policy = json.loads(a.policy(gid))
    verified = canonical({**policy, "require_verified": True})
    assert a.check_policy_change(gid, verified) is None
    assert not a.has_pending_commit(gid)
    with pytest.raises(ac.AgentConnectError, match="may not change this policy"):
        b.check_policy_change(gid, verified)
    with pytest.raises(ac.AgentConnectError, match="new owner is not a member"):
        a.check_policy_change(gid, canonical({**policy, "owner": make_client(rng).identity}))
    with pytest.raises(ac.AgentConnectError, match="malformed"):
        a.check_policy_change(gid, b"{}")
    epoch = a.epoch(gid)
    out = a.set_policy(gid, verified)
    summary = a.confirm_pending_commit(gid, out["msg_id"])
    assert a.epoch(gid) == epoch + 1
    assert summary["policy_changed"] is True
    assert summary["previous_policy"] == canonical(policy)
    assert summary["policy"] == verified
    event = b.process(gid, out["commit"])
    assert (event["previous_policy"], event["policy"]) == (canonical(policy), verified)
    up = b.update(gid)
    s = b.confirm_pending_commit(gid, up["msg_id"])
    assert (s["policy_changed"], s["previous_policy"], s["policy"]) == (False, None, None)


def test_a_refused_policy_change_says_why_in_its_kind(rng: random.Random) -> None:
    """Callers tell "not permitted" from a bad policy or a commit under way by
    the error's kind, never by its message."""
    a, b, c = (make_client(rng) for _ in range(3))
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    out = join(a, gid, c)
    b.process(gid, out["commit"])
    policy = json.loads(a.policy(gid))
    verified = canonical({**policy, "require_verified": True})
    kinds: dict[str, str] = {}

    def kind_of(client: ac.Client, new: bytes) -> str:
        with pytest.raises(ac.AgentConnectError) as e:
            client.check_policy_change(gid, new)
        return e.value.kind

    kinds["member"] = kind_of(b, verified)
    kinds["bad policy"] = kind_of(a, canonical({**policy, "max_members": 0}))
    kinds["not canonical"] = kind_of(a, b"{}")
    leave = c.propose_leave(gid)
    kinds["own leave pending"] = kind_of(c, verified)
    a.process(gid, leave)
    a.update(gid)
    kinds["commit pending"] = kind_of(a, verified)
    a.discard_pending_commit(gid)
    with pytest.raises(ac.AgentConnectError) as e:
        b.commit_pending_proposals(gid)
    kinds["nothing to commit"] = e.value.kind
    # A storage failure (a core failpoint) says nothing about the message.
    ct = b.seal(gid, inner(b, "hello"))
    a._arm_failpoint_for_testing("process.before_mls", "error")
    with pytest.raises(ac.AgentConnectError) as e:
        a.process(gid, ct, key="b/1", context=b"x")
    kinds["storage"] = e.value.kind
    a._clear_failpoints_for_testing()
    assert kinds == {
        "member": "unauthorized",
        "bad policy": "malformed",
        "not canonical": "malformed",
        "own leave pending": "not_permitted",
        "commit pending": "commit_pending",
        "nothing to commit": "nothing_to_commit",
        "storage": "transient",
    }
    # A policy that fails validation is refused before a pending commit is.
    assert kind_of(a, canonical({**policy, "max_members": 0})) == "malformed"


def test_the_default_policy_is_the_cores(rng: random.Random) -> None:
    a = make_client(rng)
    defaults = ac.default_group_policy(a.identity)
    assert defaults == a.policy(a.create_group(NAME, PURPOSE))
    gid = a.create_group(NAME, PURPOSE, policy=defaults)
    assert a.policy(gid) == defaults
    with pytest.raises(ac.AgentConnectError) as e:
        ac.default_group_policy("not an identity")
    assert e.value.kind == "malformed"


def test_pending_leaves_left_and_removing_one_instance(rng: random.Random) -> None:
    a = make_client(rng)
    b1, b2 = replicas(rng, 2)
    c = make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    members = [a]
    for joiner in (b1, b2, c):
        grow(a, gid, members, joiner)
    assert a.pending_leaves(gid) == []
    proposal = c.propose_leave(gid)
    for m in (a, b1, b2):
        assert m.process(gid, proposal)["type"] == "leave_proposed"
    for m in members:
        assert [x["identity"] for x in m.pending_leaves(gid)] == [c.identity]
    out = b1.commit_pending_proposals(gid)
    s = b1.confirm_pending_commit(gid, out["msg_id"])
    assert [x["identity"] for x in s["left"]] == [c.identity]
    assert s["left"] == s["removed"]
    for m in (a, b2):
        assert m.process(gid, out["commit"])["left"] == s["left"]
    assert c.process(gid, out["commit"])["type"] == "removed"

    # B1 removes its own replica B2 by instance id; B1 stays.
    with pytest.raises(ac.AgentConnectError, match="unknown member"):
        b1.remove_instances(gid, ["00" * 8])
    with pytest.raises(ac.AgentConnectError, match="may not remove members"):
        b2.remove_instances(gid, [a.instance_id_hex])
    out = b1.remove_instances(gid, [b2.instance_id_hex])
    s = b1.confirm_pending_commit(gid, out["msg_id"])
    assert [x["instance_id_hex"] for x in s["removed"]] == [b2.instance_id_hex]
    assert s["left"] == []
    assert a.process(gid, out["commit"])["type"] == "commit"
    assert b2.process(gid, out["commit"])["type"] == "removed"
    assert [m["identity"] for m in a.members(gid)] == [a.identity, b1.identity]


def test_an_unchecked_commit_is_rejected_by_honest_members(rng: random.Random) -> None:
    a, b, c = (make_client(rng) for _ in range(3))
    gid = a.create_group(NAME, PURPOSE)
    members = [a]
    grow(a, gid, members, b)
    grow(a, gid, members, c)
    epoch, state = a.epoch(gid), a._state_fingerprint_for_testing(gid)
    leaf_c = next(m["leaf_index"] for m in a.members(gid) if m["identity"] == c.identity)
    bad = b._commit_unchecked_for_testing(gid, remove_leaves=[leaf_c])
    assert bad["epoch"] == epoch
    assert b.epoch(gid) == epoch + 1
    for honest in (a, c):
        with pytest.raises(ac.AgentConnectError, match="may not remove members"):
            honest.process(gid, bad["commit"])
        assert (honest.epoch(gid), honest._state_fingerprint_for_testing(gid)) == (epoch, state)
    # The committer alone moved on: a SAS run with it shows the fork.
    assert not same_view(a, b, gid)
    assert b.process(gid, bad["commit"])["type"] == "own_echo"

    policy = json.loads(a.policy(gid))
    grab = a._commit_unchecked_for_testing(
        gid, policy=canonical({**policy, "owner": b.identity}), meta=a.meta(gid)
    )
    # The owner may hand over ownership; C (still at A's epoch) accepts.
    assert c.process(gid, grab["commit"])["type"] == "commit"
    assert json.loads(c.policy(gid))["owner"] == b.identity
