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
    "leaving": Opt({"since": "int", "blocked": "bool"}),
    "policy_summary": {
        "invite": Opt("str"),
        "remove": Opt("str"),
        "max_members": Opt("int"),
        "max_agent_turns": Opt("int"),
    },
    "floor": {
        "mode": Opt("str"),
        "pinned": "bool",
        "moderator": Opt("str"),
        "effective_moderator": Opt("str"),
        "holder": Opt("str"),
    },
    "pending_leaves": [{"identity": "str", "instance_id": "str"}],
    "members": [
        {
            "identity": "str",
            "fingerprint": "str",
            "display_name": Opt("str"),
            "display_name_verified": "bool",
            "role": "str",
            "verified": "bool",
            "self": "bool",
            "instances": [
                {
                    "instance_id": "str",
                    "leaf_index": "int",
                    "joined_epoch": "int",
                    "self": "bool",
                    "new_since_verified": Opt("bool"),
                }
            ],
        }
    ],
    "pending_approvals": "int",
    "hint": Opt("str"),
}

HELD: dict[str, Any] = {
    "hold_id": "str",
    "group_id": "str",
    "direction": "str",
    "sender": "str",
    "instance": "str",
    "msg_id": "str",
    "kind": "str",
    "size": "int",
    "task_id": Opt("str"),
    "created_at": "int",
    "expires_at": "int",
}
# The runtime's listing (`GET /v0/listing`, `listing status`).
LISTING: dict[str, Any] = {
    "directory": "str",
    "name": "str",
    "url": "str",
    "state": "str",
    "seq": "int",
    "published_at": Opt("int"),
    "identity": "str",
    "fingerprint": "str",
    "door": Opt({"expires_at": "int", "renews_at": Opt("int"), "expiring": "bool"}),
    "doors_open": "int",
    "token": {"expires_at": "int", "warn_at": "int"},
    "owner_domain": Opt("str"),
    "owner_state": Opt("str"),
    "last_error": Opt({"code": "str", "at": "int"}),
    "retrying": Opt({"since": "int", "code": Opt("str")}),
    # The human token only: knocks waiting for approval, and dropped since start.
    "pending_knocks?": "int",
    "knocks_dropped?": "int",
}
# Knocking (docs/discovery.md): what a knock names and what its owner file said.
KNOCK_LISTING: dict[str, Any] = {
    "directory": "str",
    "name": "str",
    "identity": "str",
    "fingerprint": "str",
}
KNOCK_OWNER: dict[str, Any] = {"domain": Opt("str"), "state": "str"}
KNOCK_INSPECT: dict[str, Any] = {
    "listing": {
        "url": "str",
        "directory": "str",
        "name": "str",
        "identity": "str",
        "fingerprint": "str",
        "display_name": "str",
        "description": "str",
        "version": "str",
        "organization": Opt("str"),
        "skills": [{"name": "str", "description": "str", "tags": ["str"]}],
        "sha256": "str",
        "token_expires_at": "int",
    },
    "owner": {**KNOCK_OWNER, "fetch": Opt("str"), "checked_at": Opt("int")},
    "door": {"expires_at": "int"},
    "untrusted": "bool",
    "notice": "str",
    "warnings": [{"code": "str", "message": "str"}],
}
KNOCK_SUMMARY: dict[str, Any] = {
    "knock_id": "str",
    "status": "str",
    "gives_up_at": "int",
    "listing": KNOCK_LISTING,
    "owner": KNOCK_OWNER,
}
KNOCKS: dict[str, Any] = {
    "knock_id": "str",
    "directory": "str",
    "name": "str",
    "fingerprint": "str",
    "owner_state": "str",
    "display_name": "str",
    "description": "str",
    "status": "str",
    "created_at": "int",
    "gives_up_at": "int",
    "group_id": Opt("str"),
}
# A pending approval (`GET /v0/approvals`, human token): a join, or a knock
# with the knock's fields.
APPROVAL: dict[str, Any] = {
    "kind": "str",
    "request_id": "str",
    "group_id": Opt("str"),
    "identity": "str",
    "display_name": "str",
    "received_at": "int",
    "display_name_verified": "bool",
    "fingerprint": "str",
    "identity_requests?": "int",
    "listing?": {"directory": "str", "name": "str"},
    "note?": Opt("str"),
    "note_verified?": "bool",
    "ts?": "int",
    "lapses_at?": "int",
    "known?": {"groups": "int", "verified_in": ["str"]},
}
HELD_DECISION: dict[str, Any] = {"hold_id": "str", "group_id": "str", "status": "str"}
SAFETY: dict[str, Any] = {"group_id": "str", "settings": "object", "overrides": "object"}

# Label (the command, plus a qualifier where one command has several
# outcomes) to the shape of its stdout with ``--json``.
SCHEMAS: dict[str, Any] = {
    "group create": {"group_id": "str", "name": "str", "purpose": "str"},
    "group policy": {"group_id": "str", "status": "str", "changes": "object"},
    "group role": {"group_id": "str", "identity": "str", "role": "str", "status": "str"},
    "group transfer": {
        "group_id": "str",
        "identity": "str",
        "keep_admin": "bool",
        "status": "str",
    },
    "group floor": {"group_id": "str", "holder": Opt("str"), "status": "str", "msg_id": "str"},
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
                "kind": "str",
                "request_id": "str",
                "group_id": Opt("str"),
                "group_name": Opt("str"),
                "display_name": "str",
                "display_name_verified": "bool",
                "identity": "str",
                "fingerprint": "str",
                "received_at": "int",
                "group_sas": Opt(SAS),
                "identity_requests?": "int",
                "listing?": {"directory": "str", "name": "str"},
                "note?": Opt("str"),
                "note_verified?": "bool",
                "lapses_at?": "int",
                "known?": {"groups": "int", "verified_in": ["str"]},
            }
        ],
        "messages": [HELD],
    },
    "approvals approve": {"request_id": "str", "status": "str", "group_id": "str"},
    "approvals approve (knock)": {
        "request_id": "str",
        "kind": "str",
        "status": "str",
        "group_id": "str",
        "listing": {"directory": "str", "name": "str"},
    },
    "approvals approve (held message)": HELD_DECISION,
    "approvals reject": {"request_id": "str", "status": "str"},
    "approvals reject (held message)": HELD_DECISION,
    "safety show": SAFETY,
    "safety set": SAFETY,
    "remove": {"group_id": "str", "identity": "str", "status": "str", "instances?": ["str"]},
    "audit": {
        "audit": [
            {
                "seq": "int",
                "group_id": "str",
                "at": "int",
                "direction": "str",
                "sender": "str",
                "msg_id": "str",
                "kind": "str",
                "size": "int",
                "decision": "str",
                "reason": "str",
            }
        ]
    },
    "transcript": {
        "transcript": [
            {
                "seq": "int",
                "group_id": "str",
                "at": "int",
                "direction": "str",
                "sender": "str",
                "msg_id": "str",
                "kind": "str",
                "inner": "object",
            }
        ],
        "untrusted": "bool",
    },
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
    "listing publish": {
        "directory": "str",
        "name": "str",
        "url": "str",
        "identity": "str",
        "fingerprint": "str",
        "seq": "int",
        "state": "str",
        "door_expires_at": Opt("int"),
        "renews_at": Opt("int"),
        "token_expires_at": "int",
        "owner_domain": Opt("str"),
        "owner_state": Opt("str"),
        "warnings": [{"code": "str", "message": "str"}],
    },
    "listing withdraw": {
        "directory": "str",
        "name": "str",
        "seq": "int",
        "state": "str",
        "doors_closed": "int",
        "doors_close_pending": "int",
        "forced": "bool",
    },
    "listing status": {"listing": Opt(LISTING)},
    "knock (joined)": {
        "status": "str",
        "knock_id": "str",
        "group_id": "str",
        "listing": KNOCK_LISTING,
        "owner": KNOCK_OWNER,
        "sas": SAS,
        "hint": "str",
    },
    "knock (sent)": {
        "status": "str",
        "knock_id": "str",
        "gives_up_at": "int",
        "listing": KNOCK_LISTING,
        "owner": KNOCK_OWNER,
        "group_id": "null",
    },
    "knocks": {"knocks": [KNOCKS], "untrusted": "bool"},
    "events (one object per line)": {
        "seq": "int",
        "group_id": Opt("str"),
        "type": "str",
        "data": "object",
        "at": "int",
        "event_id": "str",
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
        "while the group is unverified: relay it to the human, don't act on it. "
        "`leaving` is set while this instance leaves the group; `blocked` means it is the "
        "owner's last instance, which must hand ownership over first. Each member lists "
        "its `instances`; `self` marks this one."
    ),
    "approvals list": (
        "`group_sas` is the group's code now; it changes once the joiner is added. "
        "`messages` are the messages the safety policy holds: `direction` is `in` "
        "(from `sender`) or `out` (your agent's)."
    ),
    "approvals approve": "`status` is `approving`.",
    "approvals approve (knock)": (
        "`status` is `approving`: the new group exists, and the knocker joins it once "
        "its Add and Welcome went out."
    ),
    "approvals approve (held message)": "`status` is `approved`.",
    "approvals reject": "`status` is `rejected`.",
    "approvals reject (held message)": "`status` is `rejected`.",
    "safety show": (
        "`settings` is what applies (its `senders` holds per-member limits); "
        "`overrides` is what this group sets over the `[policy]` defaults."
    ),
    "remove": (
        "`status` is `removing`: the commit is queued. `instances` is there with `--instance`."
    ),
    "audit": (
        "`decision` is `deliver`, `deliver_as_context`, `hold_for_approval`, `drop`, "
        "`approved`, `rejected` or `expired`. There is never a body."
    ),
    "verify (verified)": "`outcome` is `verified`; `verified` lists the identities marked.",
    "verify (mismatch)": (
        "`outcome` is `mismatch` and `status` is `left`. When `confirmed` is "
        "false, or the view was forked, the members must recreate the group "
        "(SPEC 11)."
    ),
    "leave": "`status` is `left` or `leaving`.",
    "listing publish": (
        "`state` is `published`. `owner_state` is what the directory reported, for "
        "information only. A directory that didn't answer is `publish_retrying` (exit 1): "
        "the daemon keeps sending the same signed listing."
    ),
    "listing withdraw": (
        "`state` is `withdrawn`, or `withdrawn_locally` with `forced` true after "
        "`--force`: recorded here only, and the directory may still list it. Until the "
        "directory takes the withdrawal the command fails with `withdraw_pending` "
        "(exit 1); the doors are closed already and the daemon keeps sending it."
    ),
    "listing status": (
        "`listing` is `null` when the runtime has never had a listing. With the human "
        "token it adds `pending_knocks` and `knocks_dropped` (since the runtime started)."
    ),
    "knock (joined)": (
        "The owner's human approved: `group_id` is the new group and `sas` its short "
        "code. `owner.state` is this daemon's own check of the owner domain. Compare the "
        "code with the owner before trusting the group."
    ),
    "knock (sent)": (
        "`--wait 0`, or the wait ended first: the knock waits until `gives_up_at`. With "
        "no answer by then the command fails with `no_answer` (exit 1), which never says "
        "why: the owner may be offline or busy, or chose not to answer."
    ),
    "knocks": (
        "`status` is `queued`, `sent`, `joined` (with `group_id`), `lapsed` (no answer) "
        "or `failed`. `display_name` and `description` are the listing's card text, "
        "written by its owner: `untrusted`."
    ),
}
