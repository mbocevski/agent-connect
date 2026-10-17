"""Agent Cards: signature checks and the cards the facade serves.

Signatures (A2A v1.0 ``AgentCard.signatures``, JWS over the RFC 8785 form of
the card) are checked against keys the user pinned in a JWKS file
(``a2a.card_keys_file``). A key is never fetched from a URL a card names
(``jku``): for a peer's card that URL is peer-controlled.

* ``verified``: a signature checks out with a pinned key.
* ``unsigned``: the card has no signature.
* ``unverified``: signed, but with no pinned key for it.
* ``invalid``: signed with a pinned key, and no signature checks out. An
  invalid card is not used.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    HTTPAuthSecurityScheme,
    SecurityRequirement,
    SecurityScheme,
    StringList,
)
from a2a.utils.signing import SignatureVerificationError, create_signature_verifier
from jwt import PyJWK
from jwt.exceptions import PyJWKError, PyJWTError
from jwt.utils import base64url_decode

# Asymmetric only: a symmetric (HS*) key in a JWKS would let anyone holding
# it forge cards, and accepting HS* invites algorithm confusion.
ALGORITHMS = ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "EdDSA"]
BEARER = "agentconnectBearer"


def load_jwks(path: Path | None) -> dict[str, PyJWK]:
    """The pinned card-signing keys, by ``kid``."""
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    keys: dict[str, PyJWK] = {}
    for jwk in data.get("keys", []) if isinstance(data, dict) else []:
        if not isinstance(jwk, dict) or not isinstance(jwk.get("kid"), str):
            continue
        if jwk.get("kty") == "oct":
            continue  # symmetric keys are refused, see ALGORITHMS
        try:
            keys[jwk["kid"]] = PyJWK(jwk)
        except PyJWTError:
            continue
    return keys


def _kids(card: AgentCard) -> list[str | None]:
    kids: list[str | None] = []
    for sig in card.signatures:
        try:
            header = json.loads(base64url_decode(sig.protected.encode("ascii")))
        except (ValueError, UnicodeError):
            kids.append(None)
            continue
        kid = header.get("kid") if isinstance(header, dict) else None
        kids.append(kid if isinstance(kid, str) else None)
    return kids


def signature_status(card: AgentCard, keys: Mapping[str, PyJWK]) -> str:
    """``verified``, ``unsigned``, ``unverified`` or ``invalid`` (above)."""
    if len(card.signatures) == 0:
        return "unsigned"
    if not any(kid in keys for kid in _kids(card) if kid is not None):
        return "unverified"

    def key_for(kid: str | None, _jku: str | None) -> PyJWK:
        if kid is None or kid not in keys:
            msg = "no pinned key"
            raise PyJWKError(msg)
        return keys[kid]

    try:
        create_signature_verifier(key_for, ALGORITHMS)(card)
    except SignatureVerificationError:
        return "invalid"
    return "verified"


def _bearer(card: AgentCard) -> None:
    card.security_schemes[BEARER].CopyFrom(
        SecurityScheme(
            http_auth_security_scheme=HTTPAuthSecurityScheme(
                scheme="Bearer", description="The facade token (a2a-facade-token)."
            )
        )
    )
    card.security_requirements.append(SecurityRequirement(schemes={BEARER: StringList(list=[])}))


def facade_card(
    url: str,
    name: str,
    description: str,
    skills: list[AgentSkill],
    source: AgentCard | None = None,
) -> AgentCard:
    """A card for the local facade at ``url``: ``source`` (a peer's card)
    mirrored with the facade's interface and auth, or a composite one."""
    card = AgentCard()
    if source is not None:
        card.CopyFrom(source)
        # The peer's interfaces, auth and signatures don't apply here.
        card.ClearField("supported_interfaces")
        card.ClearField("security_schemes")
        card.ClearField("security_requirements")
        card.ClearField("signatures")
    else:
        card.name = name
        card.description = description
        card.version = "0"
        card.default_input_modes.extend(["text/plain", "application/json"])
        card.default_output_modes.extend(["text/plain", "application/json"])
        card.skills.extend(skills)
    card.supported_interfaces.append(
        AgentInterface(url=url, protocol_binding="JSONRPC", protocol_version="1.0")
    )
    card.capabilities.CopyFrom(AgentCapabilities(streaming=True, push_notifications=True))
    _bearer(card)
    return card


def composite_skills(cards: Mapping[str, AgentCard], names: Mapping[str, str]) -> list[AgentSkill]:
    """Every member's skills, ids prefixed by the member so they stay unique
    and say whom to address (``metadata.to``)."""
    out: list[AgentSkill] = []
    for identity in sorted(cards):
        for skill in cards[identity].skills:
            s = AgentSkill()
            s.CopyFrom(skill)
            s.id = f"{identity}/{skill.id}"
            label = names.get(identity) or identity
            s.name = f"{label}: {skill.name}"
            s.tags.append(f"member:{identity}")
            out.append(s)
    return out
