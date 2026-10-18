"""Discovery vectors in testdata/ (SPEC 6.6, 13), checked through the bindings.

The Rust side (core/src/vectors.rs) generates and checks the same files:
listings.json, listing-tokens.json, withdrawals.json, owner-files.json and
knocks.json. Where the bindings expose no primitive (HKDF, the JWS
signature, the knock signature), the check is redone independently here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import agentconnect_core as ac

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"


def load(name: str) -> dict[str, Any]:
    return json.loads((TESTDATA / name).read_text(encoding="utf-8"))


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def ed25519_ok(public: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
    except Exception:
        return False
    return True


def test_listings() -> None:
    v = load("listings.json")
    keys = [b64d(k) for k in v["directory_keys"]]
    good = v["valid"]
    listing = ac.verify_listing(good["listing"].encode())
    assert listing.bytes == good["listing"].encode()
    assert listing.identity == good["identity"]
    assert listing.fingerprint == good["fingerprint"]
    assert listing.url == good["url"]
    assert listing.sha256.hex() == good["sha256"]
    assert listing.sha256 == hashlib.sha256(listing.bytes).digest()
    assert listing.seq == good["seq"]
    assert listing.name == good["name"]
    assert b64e(listing.token_id) == good["token_id"]
    door = listing.door
    assert door is not None
    assert b64e(door["id"]) == good["door_id"]
    assert door["expires_at"] == good["door_expires_at"]
    assert listing.unsigned_card == good["unsigned_card"].encode()
    listing.check_token(v["directory"], keys, good["now"])
    listing.check_publish(good["now"])
    assert listing.door_open(good["now"])
    # The JWS, independently: protected || "." || b64url(payload) under kid.
    card = json.loads(good["listing"])
    sig = card["signatures"][0]
    assert sig["protected"] == good["protected"]
    header = json.loads(b64d(sig["protected"]))
    assert header == {"alg": "EdDSA", "kid": good["identity"], "typ": "JOSE"}
    signing_input = f"{sig['protected']}.{b64e(good['unsigned_card'].encode())}".encode()
    ik = b64d(good["identity"].removeprefix("ac:v0:"))
    assert ed25519_ok(ik, signing_input, b64d(sig["signature"]))
    # The canonical unsigned form is a fixed point.
    assert ac.canonical_card(good["unsigned_card"].encode()) == good["unsigned_card"].encode()
    for case in v["invalid"]:
        with pytest.raises(ac.AgentConnectError) as e:
            ac.verify_listing(case["listing"].encode())
        assert str(e.value) == case["error"], case["name"]
    for case in v["checks"]:
        listing = ac.verify_listing(case["listing"].encode())
        key_set = [b64d(v["other_directory_key"])] if "unpinned" in case["name"] else keys
        revoked = [b64d(case["revoked"])] if case["revoked"] else []
        if case["check"] == "publish":
            with pytest.raises(ac.AgentConnectError) as e:
                listing.check_publish(case["now"])
        else:
            with pytest.raises(ac.AgentConnectError) as e:
                listing.check_token(v["directory"], key_set, case["now"], revoked)
        assert str(e.value) == case["error"], case["name"]


def test_listing_tokens() -> None:
    v = load("listing-tokens.json")
    key = b64d(v["directory_key"])
    good = v["valid"]
    fields = ac.verify_listing_token(good["token"].encode(), v["directory"], [key], good["now"])
    assert fields["identity"] == good["identity"]
    assert b64e(fields["key_id"]) == v["key_id"]
    assert b64e(hashlib.sha256(key).digest()[:16]) == v["key_id"]
    token = json.loads(good["token"])
    assert good["signing_input"].startswith("agentconnect/v0/listing-token{")
    assert ed25519_ok(key, good["signing_input"].encode(), b64d(token["sig"]))
    for case in v["verify_invalid"]:
        with pytest.raises(ac.AgentConnectError) as e:
            ac.verify_listing_token(
                case["token"].encode(), v["directory"], [b64d(case["directory_key"])], case["now"]
            )
        assert str(e.value) == case["error"], case["name"]
    for case in v["binding_invalid"]:
        with pytest.raises(ac.AgentConnectError) as e:
            ac.check_token_binding(
                good["token"].encode(),
                case["directory"],
                case["listing_name"],
                case["identity"],
                case["owner_domain"],
            )
        assert str(e.value) == case["error"], case["name"]
    rev = v["revocation"]
    fields = ac.verify_token_revocation(rev["revocation"].encode(), v["directory"], [key])
    assert fields["token_id"] == b64d(token["token_id"])
    with pytest.raises(ac.AgentConnectError) as e:
        ac.verify_token_revocation(rev["tampered"].encode(), v["directory"], [key])
    assert str(e.value) == rev["tampered_error"]


def test_withdrawals() -> None:
    v = load("withdrawals.json")
    listing = ac.verify_listing(v["listing"].encode())
    good = v["valid"]
    data = good["withdrawal"].encode()
    fields = ac.verify_withdrawal(data)
    assert fields["identity"] == listing.identity
    ik = b64d(listing.identity.removeprefix("ac:v0:"))
    assert ed25519_ok(
        ik, good["signing_input"].encode(), b64d(json.loads(good["withdrawal"])["sig"])
    )
    for now in good["fresh_at"]:
        ac.check_withdrawal_fresh(data, v["directory"], now)
    for now in good["stale_at"]:
        with pytest.raises(ac.AgentConnectError) as e:
            ac.check_withdrawal_fresh(data, v["directory"], now)
        assert str(e.value) == good["stale_error"]
    assert ac.withdrawal_applies(data, listing) is good["applies"]
    assert ac.withdrawal_applies(v["old_seq"]["withdrawal"].encode(), listing) is False
    for case in v["invalid"]:
        with pytest.raises(ac.AgentConnectError) as e:
            ac.verify_withdrawal(case["withdrawal"].encode())
        assert str(e.value) == case["error"], case["name"]


def test_owner_files() -> None:
    v = load("owner-files.json")
    for case in v["files"]:
        data = case["file"].encode()
        if case["error"] is None:
            ac.parse_owner_file(data)
        else:
            with pytest.raises(ac.AgentConnectError) as e:
                ac.parse_owner_file(data)
            assert str(e.value) == case["error"], case["name"]
        for r in case["results"]:
            got = ac.owner_vouch(data, r["identity"], r["directory"], r["name"])
            assert got == r["vouch"], (case["name"], r)
    for s in v["states"]:
        got = ac.owner_state(
            s["owner_domain"], s["now"], s["latest_result"], s["latest_at"], s["last_vouched_at"]
        )
        assert got == s["state"], s


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def test_knocks() -> None:
    v = load("knocks.json")
    d = v["door"]
    door = ac.Door._derive_for_testing(b64d(d["id"]), bytes.fromhex(d["ikm"]), d["expires_at"])
    assert b64e(door.public_key) == d["public_key"]
    assert len(door.public_key) == 1216
    good = v["valid"]
    opened = door.open_knock(b64d(d["id"]), b64d(good["sealed"]), good["now"])
    knock = json.loads(good["knock"])
    assert b64e(opened.knock_id) == knock["knock_id"]
    assert opened.display_name == knock["display_name"]
    assert opened.note == knock.get("note")
    assert opened.mailbox_id == knock["mailbox_id"]
    assert opened.ts == knock["ts"]
    assert opened.signing_input == good["signing_input"].encode()
    # The signature input is the label and the knock without "sig".
    without_sig = {k: val for k, val in knock.items() if k != "sig"}
    assert good["signing_input"].startswith("agentconnect/v0/knock{")
    assert json.loads(good["signing_input"].removeprefix("agentconnect/v0/knock")) == without_sig
    assert ed25519_ok(b64d(good["sig_key"]), opened.signing_input, opened.sig)
    assert ac.mailbox_id(b64d(good["sig_key"])) == opened.mailbox_id
    for case, expected in zip(
        v["invalid"],
        [
            "not this door",
            "door_id mismatch",
            "ts out of range",
            "ts out of range",
            "sealed knock too short",
        ],
        strict=True,
    ):
        with pytest.raises(ac.AgentConnectError) as e:
            door.open_knock(b64d(case["envelope_door_id"]), b64d(case["sealed"]), case["now"])
        assert str(e.value) == f"invalid knock: {expected}", case["name"]
    bad = v["bad_signature"]
    forged = door.open_knock(b64d(d["id"]), b64d(bad["sealed"]), bad["now"])
    assert not ed25519_ok(b64d(bad["sig_key"]), forged.signing_input, forged.sig)
    w = v["welcome"]
    knock_id, secret = bytes.fromhex(w["knock_id"]), bytes.fromhex(w["welcome_secret"])
    assert knock_id == opened.knock_id
    key = hkdf_sha256(secret, knock_id, b"agentconnect/v0/knock-welcome")
    assert key.hex() == w["welcome_key"]
    wrapped = bytes.fromhex(w["wrapped"])
    assert wrapped[:12].hex() == w["nonce"]
    assert ac.unwrap_knock_welcome(knock_id, secret, wrapped).hex() == w["welcome"]
    tampered = bytearray(wrapped)
    tampered[-1] ^= 1
    with pytest.raises(ac.AgentConnectError, match="authentication"):
        ac.unwrap_knock_welcome(knock_id, secret, bytes(tampered))
    other = bytearray(secret)
    other[0] ^= 1
    with pytest.raises(ac.AgentConnectError, match="authentication"):
        ac.unwrap_knock_welcome(knock_id, bytes(other), wrapped)
