"""Listings and a2a-sdk's own Agent Card signing agree (SPEC 13.1, ADR-006).

- a2a-sdk's verifier accepts a listing the core signed, given a key
  provider that reads `kid` and refuses `jku`; it rejects tampering.
- A card a2a-sdk signs (with `alg: EdDSA`, `kid`, `typ: JOSE`) and then
  serialises as JCS is a listing the core accepts, byte for byte.
- The shared vector testdata/listings.json verifies under a2a-sdk too.
"""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path
from typing import Any

import pytest
from a2a.types import AgentCard
from a2a.utils._jcs import canonicalize
from a2a.utils.signing import (
    InvalidSignaturesError,
    create_agent_card_signer,
    create_signature_verifier,
)
from google.protobuf.json_format import MessageToDict, Parse
from jwt.api_jwk import PyJWK
from jwt.exceptions import InvalidKeyError

import agentconnect_core as ac

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"
DIRECTORY = "agents.example"
T0 = 1_792_497_600


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def okp(public: bytes, secret: bytes | None = None) -> PyJWK:
    """An Ed25519 JWK (RFC 8037), public or with its private part."""
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64e(public)}
    if secret is not None:
        jwk["d"] = b64e(secret)
    return PyJWK(jwk, algorithm="EdDSA")


def key_provider(kid: str | None, jku: str | None) -> PyJWK:
    """The key the listing names in `kid`; never a key location.

    Refusals are `PyJWTError`s, which a2a-sdk counts as an invalid signature.
    """
    if jku is not None:
        raise InvalidKeyError("jku is refused")
    if kid is None or not kid.startswith("ac:v0:"):
        raise InvalidKeyError("kid must be an AgentConnect identity")
    return okp(b64d(kid.removeprefix("ac:v0:")))


verify = create_signature_verifier(key_provider, ["EdDSA"])


def unsigned_card(ik: ac.Identity, token: bytes) -> dict[str, Any]:
    door = ac.Door.generate(T0 + 86_400)
    return {
        "name": "Release planner",
        "description": "Plans release trains and drafts schedules — one line.",
        "version": "1.4.0",
        "provider": {"organization": "Example Ltd", "url": "https://example.com"},
        "capabilities": {
            "extensions": [
                {
                    "uri": ac.E2E_EXTENSION_URI,
                    "description": "Reachable end-to-end encrypted through AgentConnect.",
                    "required": True,
                    "params": {
                        "v": 0,
                        "identity": ik.id,
                        "name": "release-planner",
                        "directory": DIRECTORY,
                        "relay": "relay.example",
                        "seq": 7,
                        "issued_at": T0,
                        "door": {
                            "id": b64e(door.id),
                            "key": b64e(door.public_key),
                            "expires_at": door.expires_at,
                        },
                        "owner_domain": "example.com",
                        "token": json.loads(token),
                    },
                }
            ]
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "release-planning",
                "name": "Release planning",
                "description": "Turns a change list into a dated release plan.",
                "tags": ["release planning", "scheduling"],
            }
        ],
        "supportedInterfaces": [
            {
                "protocolBinding": "AGENTCONNECT",
                "protocolVersion": "0",
                "url": f"https://{DIRECTORY}/a/release-planner.json",
            }
        ],
    }


def as_proto(data: bytes) -> AgentCard:
    card = AgentCard()
    Parse(data.decode("utf-8"), card)
    return card


@pytest.fixture
def setup(rng: random.Random) -> tuple[bytes, ac.Identity, bytes]:
    seed = rng.getrandbits(64)
    ik = ac.Identity._generate_for_testing(seed)
    dk = ac.DirectoryKey._generate_for_testing(rng.getrandbits(64))
    token = dk.issue_token(
        DIRECTORY, "release-planner", ik.id, T0, T0 + 86_400, owner_domain="example.com"
    )
    return ik.secret_bytes(), ik, token


def test_a2a_verifies_a_core_signed_listing(setup: tuple[bytes, ac.Identity, bytes]) -> None:
    _, ik, token = setup
    listing = ac.sign_listing(json.dumps(unsigned_card(ik, token)).encode(), ik)
    verify(as_proto(listing.bytes))
    # Tampered text fails a2a-sdk's check as it fails ours.
    tampered = listing.bytes.replace(b"Plans release", b"Plans RELEASE")
    with pytest.raises(InvalidSignaturesError):
        verify(as_proto(tampered))
    with pytest.raises(ac.AgentConnectError, match="signature"):
        ac.verify_listing(tampered)


def test_core_verifies_an_a2a_signed_card(setup: tuple[bytes, ac.Identity, bytes]) -> None:
    secret, ik, token = setup
    card = as_proto(json.dumps(unsigned_card(ik, token)).encode())
    # Exactly alg, kid and typ: a `"jku": null` entry would be signed too.
    header: Any = {"alg": "EdDSA", "kid": ik.id, "typ": "JOSE"}
    signer = create_agent_card_signer(okp(ik.public_key, secret), header)
    signed = signer(card)
    verify(signed)
    published = canonicalize(MessageToDict(signed)).encode("utf-8")
    listing = ac.verify_listing(published)
    assert listing.identity == ik.id
    # Ed25519 is deterministic, so both sides produce the same bytes.
    ours = ac.sign_listing(json.dumps(unsigned_card_from(listing)).encode(), ik)
    assert ours.bytes == published


def unsigned_card_from(listing: ac.Listing) -> dict[str, Any]:
    return json.loads(listing.unsigned_card)


def test_a2a_signer_with_a_key_location_is_refused(
    setup: tuple[bytes, ac.Identity, bytes],
) -> None:
    secret, ik, token = setup
    card = as_proto(json.dumps(unsigned_card(ik, token)).encode())
    header: Any = {"alg": "EdDSA", "kid": ik.id, "typ": "JOSE", "jku": "https://evil.example/jwks"}
    signer = create_agent_card_signer(okp(ik.public_key, secret), header)
    published = canonicalize(MessageToDict(signer(card))).encode("utf-8")
    with pytest.raises(ac.AgentConnectError, match="key location"):
        ac.verify_listing(published)
    with pytest.raises(InvalidSignaturesError):
        verify(as_proto(published))


def test_shared_vector_verifies_under_a2a() -> None:
    v = json.loads((TESTDATA / "listings.json").read_text(encoding="utf-8"))
    verify(as_proto(v["valid"]["listing"].encode()))
    # MessageToDict and a2a-sdk's canonicaliser give back the published bytes.
    card = MessageToDict(as_proto(v["valid"]["listing"].encode()))
    assert canonicalize(card).encode("utf-8") == v["valid"]["listing"].encode()
