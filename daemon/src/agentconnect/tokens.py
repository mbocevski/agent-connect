"""The local API's bearer tokens and other 0600 secret files.

``api-token`` (agent scope) and ``human-token`` (human scope) live in the
data directory, created on first start. The runtime reads each once and
keeps only its SHA-256 (:class:`TokenDigest`), so the token's value is not
held in the runtime's memory (ADR-005, Decision 4). The CLI reads the file
per command; the SDK and agent integrations read ``api-token`` only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import override

from agentconnect.keystore import write_private

API_TOKEN_FILE = "api-token"  # noqa: S105 - a file name
HUMAN_TOKEN_FILE = "human-token"  # noqa: S105 - a file name


def load_token(path: Path) -> str:
    """Read the token at ``path``, creating it (0600) if missing. An existing
    token file must be ours and private (no group or other bits)."""
    if path.exists():
        st = path.stat()
        if st.st_mode & 0o077 or st.st_uid != os.geteuid():
            msg = f"{path.name} must be owned by this user with mode 0600"
            raise PermissionError(msg)
        return path.read_text(encoding="ascii").strip()
    token = secrets.token_urlsafe(32)
    write_private(path, token.encode("ascii"))
    return token


class TokenDigest:
    """The SHA-256 of a token, for a constant-time bearer check. The token's
    value is never stored, and the digest is kept out of ``repr``."""

    __slots__ = ("_digest",)

    # SHA-256, not a password hash, on purpose: the tokens are 256 bits from
    # secrets.token_urlsafe(32), not passwords people choose, so there is
    # nothing to brute-force and no stretching (bcrypt, scrypt) to add. The
    # hash only keeps the value out of memory; compare_digest keeps the
    # comparison constant-time.
    def __init__(self, token: str) -> None:
        self._digest = hashlib.sha256(token.encode()).digest()

    @classmethod
    def of_file(cls, path: Path) -> TokenDigest:
        """Load (or create) the token file at ``path`` and keep its digest."""
        return cls(load_token(path))

    def matches(self, bearer_token: str) -> bool:
        return hmac.compare_digest(hashlib.sha256(bearer_token.encode()).digest(), self._digest)

    @override
    def __repr__(self) -> str:
        return "TokenDigest(<redacted>)"
