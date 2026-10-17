"""Python bindings for the AgentConnect protocol core (see SPEC.md).

Errors from the core raise ``AgentConnectError``. An internal failure (a
panic) raises ``CoreError``; the operation did not complete, and a
``Client`` reloads its group state from storage on next use.

Names of the form ``_..._for_testing`` are test-only (seeded randomness, a
settable clock) and must not be used in production.
"""

from agentconnect_core._native import (
    CIPHERSUITE_V0,
    DB_KEY_LEN,
    PADDING_BUCKETS,
    PROTOCOL_VERSION,
    AgentConnectError,
    Client,
    CoreError,
    Database,
    Identity,
    Instance,
    Invite,
    InviteLink,
    Sas,
    VerifiedJoinRequest,
    canonical_relay_host,
    derive_sas,
    fingerprint,
    identity_id,
    join_request_mac,
    mailbox_id,
    padding_bucket,
    parse_invite_url,
    rekey_store,
    supports_protocol,
    unwrap_welcome,
    verify_instance_cert,
)

__all__ = [
    "CIPHERSUITE_V0",
    "DB_KEY_LEN",
    "PADDING_BUCKETS",
    "PROTOCOL_VERSION",
    "AgentConnectError",
    "Client",
    "CoreError",
    "Database",
    "Identity",
    "Instance",
    "Invite",
    "InviteLink",
    "Sas",
    "VerifiedJoinRequest",
    "canonical_relay_host",
    "derive_sas",
    "fingerprint",
    "identity_id",
    "join_request_mac",
    "mailbox_id",
    "padding_bucket",
    "parse_invite_url",
    "rekey_store",
    "supports_protocol",
    "unwrap_welcome",
    "verify_instance_cert",
]
