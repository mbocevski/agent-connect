"""The ``--json`` output shapes of the CLI: the contract in one place.

``daemon/tests/test_cli_commands.py`` checks real output against these
shapes, and ``scripts/gen_reference.py`` renders them into ``docs/cli.md``.
Change a shape here (and the command) and the docs follow with
``just docs-gen``. Notation: :mod:`agentconnect.shapes`.
"""

from __future__ import annotations

from typing import Any

from agentconnect.shapes import Opt

SAS: dict[str, Any] = {"decimal": "str", "emoji": "str", "emoji_names": ["str"]}

GROUP_VIEW: dict[str, Any] = {
    "group_id": "str",
    "name": "str",
    "purpose": "str",
    "status": "str",
    "epoch": "int",
    "out_of_sync": "bool",
    "out_of_sync_reason": Opt("str"),
    "require_verified": "bool",
    "trust_state": {"self": "str", "verified_members": "int", "members": "int"},
    "verified_summary": "str",
    "sas": Opt(SAS),
    "members": [
        {
            "identity": "str",
            "fingerprint": "str",
            "display_name": Opt("str"),
            "display_name_verified": "bool",
            "role": "str",
            "verified": "bool",
            "self": "bool",
            "instances": "int",
        }
    ],
    "pending_approvals": "int",
    "hint": Opt("str"),
}

# Label (the command, plus a qualifier where one command has several
# outcomes) to the shape of its stdout with ``--json``.
SCHEMAS: dict[str, Any] = {
    "group create": {"group_id": "str", "name": "str", "purpose": "str"},
    "invite create": {
        "url": "str",
        "invite_id": "str",
        "group_id": "str",
        "expires_at": "int",
        "max_uses": "int",
        "require_verified": "bool",
        "reminder": "str",
    },
    "invite revoke": {"revoked": "str"},
    "accept (approved)": {
        "status": "str",
        "invite_id": "str",
        "inviter_name": "str",
        **GROUP_VIEW,
    },
    "accept (still pending)": {
        "status": "str",
        "invite_id": "str",
        "name": "str",
        "purpose": "str",
        "inviter_name": "str",
        "group_id": "null",
    },
    "groups list": {
        "groups": [
            {
                "group_id": "str",
                "name": "str",
                "status": "str",
                "epoch": "int",
                "members": "int",
                "out_of_sync": "bool",
            }
        ]
    },
    "groups show": GROUP_VIEW,
    "approvals list": {
        "approvals": [
            {
                "request_id": "str",
                "group_id": "str",
                "group_name": "str",
                "display_name": "str",
                "display_name_verified": "bool",
                "identity": "str",
                "fingerprint": "str",
                "received_at": "int",
                "group_sas": Opt(SAS),
            }
        ]
    },
    "approvals approve": {"request_id": "str", "status": "str", "group_id": "str"},
    "approvals reject": {"request_id": "str", "status": "str"},
    "verify (verified)": {"outcome": "str", "group_id": "str", "verified": ["str"]},
    "verify (mismatch)": {
        "outcome": "str",
        "group_id": "str",
        "status": "str",
        "ownership_transfer": Opt(
            {"new_owner": "str", "new_owner_name": Opt("str"), "confirmed": "bool"}
        ),
    },
    "leave": {"group_id": "str", "status": "str"},
    "send": {"msg_id": "str", "group_id": "str", "hint": Opt("str")},
    "events (one object per line)": {
        "seq": "int",
        "group_id": Opt("str"),
        "type": "str",
        "data": "object",
        "at": "int",
    },
}

# What the less obvious values mean, rendered under the shape.
NOTES: dict[str, str] = {
    "accept (approved)": (
        "`status` is `joined`. The rest is the `groups show` object, so the short code is there."
    ),
    "accept (still pending)": "`status` is `pending`: the wait ended before the inviter approved.",
    "groups show": (
        "`sas` is `null` once the group is no longer active. `hint` is set "
        "while the group is unverified: relay it to the human, don't act on it."
    ),
    "approvals list": ("`group_sas` is the group's code now; it changes once the joiner is added."),
    "approvals approve": "`status` is `approving`.",
    "approvals reject": "`status` is `rejected`.",
    "verify (verified)": "`outcome` is `verified`; `verified` lists the identities marked.",
    "verify (mismatch)": (
        "`outcome` is `mismatch` and `status` is `left`. When `confirmed` is "
        "false, or the view was forked, the members must recreate the group "
        "(SPEC 11)."
    ),
    "leave": "`status` is `left` or `leaving`.",
}
