"""Shared vectors in testdata/, checked through the bindings.

The Rust side (core/src/vectors.rs) generates and checks the same files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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


def test_sas_vectors() -> None:
    table = json.loads((TESTDATA / "sas-emoji.json").read_text(encoding="utf-8"))
    for case in load("sas-vectors.json")["cases"]:
        sas = ac.derive_sas(h(case["epoch_authenticator"]), h(case["group_id"]), case["epoch"])
        assert sas.bytes.hex() == case["sas_bytes"]
        assert sas.emoji_indices == case["emoji_indices"]
        assert [table[i]["emoji"] for i in sas.emoji_indices] == case["emoji"]
        assert sas.decimal == case["decimal"]


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
