"""Shared vectors in testdata/, checked through the bindings.

The Rust side (core/src/vectors.rs) generates and checks the same files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
from pathlib import Path
from typing import Any

import pytest

import agentconnect_core as ac

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"


def load(name: str) -> dict[str, Any]:
    return json.loads((TESTDATA / name).read_text(encoding="utf-8"))


def h(s: str) -> bytes:
    return bytes.fromhex(s)


def lp(field: bytes) -> bytes:
    return len(field).to_bytes(4, "big") + field


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    """RFC 5869 HKDF-SHA256 with a 32-byte output (one expand block)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def test_invite_kdf_vectors() -> None:
    for case in load("invite-kdf.json")["cases"]:
        invite_id, secret = h(case["invite_id"]), h(case["invite_secret"])
        # The bindings never hand out join_key or welcome_key; check the
        # derivation (SPEC 3.5) independently here.
        join_key = hkdf_sha256(secret, invite_id, b"agentconnect/v0/join")
        assert join_key.hex() == case["join_key"]
        welcome_key = hkdf_sha256(secret, invite_id, b"agentconnect/v0/welcome")
        assert welcome_key.hex() == case["welcome_key"]
        req = case["join_request"]
        mac = ac.join_request_mac(
            invite_id, secret, h(req["key_package"]), req["mailbox_id"], req["display_name"]
        )
        assert mac.hex() == req["mac"]
        # The MAC input, rebuilt independently (SPEC 6.1 length-prefixed fields).
        mac_input = b"agentconnect/v0/join-request" + b"".join(
            lp(field)
            for field in (
                invite_id,
                h(req["key_package"]),
                req["mailbox_id"].encode("ascii"),
                req["display_name"].encode("utf-8"),
            )
        )
        assert mac_input.hex() == req["mac_input"]
        assert hmac.new(join_key, mac_input, hashlib.sha256).hexdigest() == req["mac"]
        wrapped = case["wrapped_welcome"]
        assert h(wrapped["wrapped"])[:12].hex() == wrapped["nonce"]
        opened = ac.unwrap_welcome(invite_id, secret, h(wrapped["wrapped"]))
        assert opened.hex() == wrapped["welcome"]
        tampered = bytearray(h(wrapped["wrapped"]))
        tampered[-1] ^= 1
        with pytest.raises(ac.AgentConnectError, match="authentication"):
            ac.unwrap_welcome(invite_id, secret, bytes(tampered))


def sas_participant(p: dict[str, str]) -> tuple[str, int, bytes]:
    return p["identity"], int(p["instance_id"], 16), h(p["nonce"])


def test_sas_commit_reveal_vectors() -> None:
    """SPEC 11.2 and 11.4, recomputed here from the formulas and through the
    bindings."""
    table = json.loads((TESTDATA / "sas-emoji.json").read_text(encoding="utf-8"))
    cases = load("sas-commit-reveal.json")["cases"]
    assert cases
    for case in cases:
        gid, epoch, ea = h(case["group_id"]), case["epoch"], h(case["epoch_authenticator"])
        a, b = sas_participant(case["a"]), sas_participant(case["b"])
        for (me, peer), key in (((a, b), "commitment_a"), ((b, a), "commitment_b")):
            data = (
                b"agentconnect/v0/sas-commit"
                + lp(gid)
                + epoch.to_bytes(8, "big")
                + lp(me[0].encode())
                + lp(me[1].to_bytes(8, "big"))
                + lp(peer[0].encode())
                + lp(me[2])
            )
            assert len(data) == 208
            assert data.hex() == case[key]["input"]
            assert hashlib.sha256(data).hexdigest() == case[key]["commitment"]
            assert (
                ac.sas_commitment(gid, epoch, me[0], me[1], peer[0], me[2]).hex()
                == (case[key]["commitment"])
            )
        lo, hi = sorted((a, b), key=lambda x: x[0].encode())
        info = b"agentconnect/v0/sas-code" + epoch.to_bytes(8, "big")
        for x in (lo, hi):
            info += lp(x[0].encode()) + lp(x[1].to_bytes(8, "big")) + lp(x[2])
        assert len(info) == 234
        assert info.hex() == case["info"]
        assert hkdf_sha256(ea, gid, info)[:6].hex() == case["sas_bytes"]
        sas = ac.derive_sas(ea, gid, epoch, *a, *b)
        assert sas == ac.derive_sas(ea, gid, epoch, *b, *a)
        assert sas.bytes.hex() == case["sas_bytes"]
        assert sas.emoji_indices == case["emoji_indices"]
        assert [table[i]["emoji"] for i in sas.emoji_indices] == case["emoji"]
        assert sas.decimal == case["decimal"]
        # Any one input changed changes the code.
        flipped = bytes([a[2][0] ^ 1]) + a[2][1:]
        for other in (
            ac.derive_sas(bytes([ea[0] ^ 1]) + ea[1:], gid, epoch, *a, *b),
            ac.derive_sas(ea, bytes([gid[0] ^ 1]) + gid[1:], epoch, *a, *b),
            ac.derive_sas(ea, gid, epoch ^ 1, *a, *b),
            ac.derive_sas(ea, gid, epoch, a[0], a[1] ^ 1, a[2], *b),
            ac.derive_sas(ea, gid, epoch, a[0], a[1], flipped, *b),
            ac.derive_sas(ea, gid, epoch, a[0], a[1], b[2], b[0], b[1], a[2]),
        ):
            assert other != sas
        with pytest.raises(ac.AgentConnectError, match="oneself"):
            ac.derive_sas(ea, gid, epoch, *a, a[0], b[1], b[2])


def test_padding_vectors() -> None:
    v = load("padding-vectors.json")
    assert v["buckets"] == ac.PADDING_BUCKETS
    for case in v["cases"]:
        assert ac.padding_bucket(case["plaintext_len"]) == case["bucket"]


def test_instance_cert_vectors() -> None:
    for case in load("instance-cert.json")["cases"]:
        identity = ac.Identity.from_secret_bytes(h(case["ik_secret"]))
        assert identity.public_key.hex() == case["ik_pub"]
        assert identity.id == case["identity"]
        assert identity.fingerprint == case["fingerprint"]
        assert ac.mailbox_id(h(case["sig_key"])) == case["mailbox_id"]
        cert = ac.verify_instance_cert(case["cert_json"].encode())
        assert cert["identity"] == case["identity"]
        assert cert["instance_id"] == case["instance_id"]
        assert cert["sig_key"].hex() == case["sig_key"]
        assert cert["created_at"] == case["created_at"]
        assert cert["signing_input"] == case["signing_input"].encode()
        bad = case["cert_json"].replace(case["identity"], ac.Identity.generate().id)
        with pytest.raises(ac.AgentConnectError, match="instance certificate"):
            ac.verify_instance_cert(bad.encode())


def test_identity_export_vectors() -> None:
    v = load("identity-export.json")
    for case in v["cases"]:
        file = case["file"].encode()
        # The code is the key, and the file carries the nonce in clear.
        assert base64.urlsafe_b64decode(case["code"] + "=").hex() == case["key"]
        wrapped = json.loads(file)["wrapped"]
        assert base64.urlsafe_b64decode(wrapped + "==")[:12].hex() == case["nonce"]
        assert case["code"] not in case["file"]
        assert ac.identity_export_identity(file) == case["identity"]
        opened = ac.unwrap_identity_export(file, case["code"])
        assert opened.secret_bytes().hex() == case["ik_secret"]
        assert opened.id == case["identity"]
    for case in v["negatives"]:
        with pytest.raises(ac.AgentConnectError) as e:
            ac.unwrap_identity_export(case["file"].encode(), case["code"])
        assert str(e.value) == case["error"], case["name"]
        assert getattr(e.value, "kind", None) == case["kind"], case["name"]


def test_an_identity_export_round_trips_under_a_fresh_code() -> None:
    identity = ac.Identity.generate()
    file, code = ac.wrap_identity_export(identity)
    again, other = ac.wrap_identity_export(identity)
    assert (again, other) != (file, code)
    assert ac.unwrap_identity_export(file, code).secret_bytes() == identity.secret_bytes()
    assert code not in file.decode()
    assert len(file) <= ac.MAX_IDENTITY_EXPORT_LEN
    with pytest.raises(ac.AgentConnectError) as e:
        ac.unwrap_identity_export(file, other)
    assert getattr(e.value, "kind", None) == "authentication"


def test_invite_url_vectors() -> None:
    v = load("invite-urls.json")
    for case in v["valid"]:
        link = ac.parse_invite_url(case["url"])
        assert link.relay_host == case["relay_host"]
        assert link.invite_id_b64 == case["invite_id"]
        assert ac.parse_invite_url(link.url).secret_bytes() == link.secret_bytes()
    for case in v["invalid"]:
        expected = {
            "unsupported_version": "unsupported protocol version",
            "invalid_url": "invalid invite URL",
        }[case["error"]]
        with pytest.raises(ac.AgentConnectError, match=expected):
            ac.parse_invite_url(case["url"])


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_relay_auth_vectors() -> None:
    v = load("relay-auth.json")
    instance = ac.Instance.from_secret_bytes(v["instance"].encode())
    assert _b64(instance.public_key) == v["sig_key"]
    assert instance.mailbox_id == v["mailbox_id"]
    for c in v["challenges"]:
        nonce = _unb64(c["nonce"])
        # The signed bytes, rebuilt independently (SPEC 8.2).
        message = b"agentconnect/v0/relay-auth" + nonce + c["relay_host"].encode()
        assert message.hex() == c["message"]
        assert _b64(instance.sign_relay_challenge(nonce, c["relay_host"])) == c["sig"]
        assert _b64(instance.sign_relay_challenge(nonce, "relay.other")) != c["sig"]
    for r in v["requests"]:
        body = r["body"].encode()
        head = f"{r['method']}\n{r['path']}\n{r['ts']}\n".encode()
        message = (
            b"agentconnect/v0/relay-rest"
            + head
            + hashlib.sha256(body).digest()
            + r["relay_host"].encode()
        )
        assert message.hex() == r["message"]
        sig = instance.sign_relay_request(r["method"], r["path"], r["ts"], body, r["relay_host"])
        assert _b64(sig) == r["sig"]
        assert r["authorization"] == f"AgentConnect-Ed25519 {v['sig_key']}.{r['ts']}.{r['sig']}"
    # Only domain-separated signing is exposed, never a generic signer.
    assert not hasattr(instance, "sign")


def test_relay_challenge_nonce_must_be_32_bytes() -> None:
    # SPEC 8.2: the nonce is 32 bytes. Any other length is refused, because
    # nonce `X || "x."` at `relay.test` would sign the same bytes as nonce
    # `X` at `x.relay.test`.
    v = load("relay-auth.json")
    instance = ac.Instance.from_secret_bytes(v["instance"].encode())
    nonce = _unb64(v["challenges"][0]["nonce"])
    for bad in (b"", nonce[:31], nonce + b"x", nonce + b"x."):
        with pytest.raises(ac.AgentConnectError, match="nonce"):
            instance.sign_relay_challenge(bad, "relay.test")


def test_relay_host_canonical_form() -> None:
    v = load("relay-auth.json")
    for case in v["hosts"]:
        if case["canonical"] is None:
            with pytest.raises(ac.AgentConnectError, match="relay host"):
                ac.canonical_relay_host(case["input"])
        else:
            assert ac.canonical_relay_host(case["input"]) == case["canonical"]
    # The signers apply it: mixed case signs what the relay verifies.
    instance = ac.Instance.from_secret_bytes(v["instance"].encode())
    c = v["challenges"][0]
    nonce = _unb64(c["nonce"])
    assert _b64(instance.sign_relay_challenge(nonce, c["relay_host"].upper())) == c["sig"]
    r = v["requests"][0]
    sig = instance.sign_relay_request(
        r["method"], r["path"], r["ts"], r["body"].encode(), r["relay_host"].upper()
    )
    assert _b64(sig) == r["sig"]


def _mlkem768_x25519_seed(ikm: bytes) -> bytes:
    # SPEC 3.1: SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32) with
    # suite_id = "KEM" || I2OSP(0x647a, 2).
    label = b"DeriveKeyPair"
    suite_id = b"KEM" + (0x647A).to_bytes(2, "big")
    labeled = ikm + b"HPKE-v1" + suite_id + len(label).to_bytes(2, "big") + label
    return hashlib.shake_256(labeled + (32).to_bytes(2, "big")).digest(32)


def test_hpke_pq_derive_key_pair_known_answer(rng: random.Random) -> None:
    # draft-ietf-hpke-pq vectors, vendored byte-for-byte (MANIFEST.json).
    vectors = [
        v
        for v in json.loads((TESTDATA / "hpke-pq-test-vectors.json").read_text())
        if v["kem_id"] == 0x647A
    ]
    assert len(vectors) == 2
    for v in vectors:
        ikm = h(v["ikmR"])
        # The X-Wing private key is the 32-byte seed itself.
        assert _mlkem768_x25519_seed(ikm) == h(v["skRm"])
        door = ac.Door._derive_for_testing(rng.randbytes(16), ikm, 2**40)
        assert door.public_key == h(v["pkRm"])
