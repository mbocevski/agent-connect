"""Roles, ownership and the group policy are the human's (SPEC 9.2,
docs/groups.md): no agent route, runtime agent method, SDK call or MCP
tool changes them. The one exception is raising ``require_verified``, which
only tightens the gate (SPEC 10.4). These tests look for each way in; the
harness runs the routes against real daemons (``test_api_shapes.py``)."""

from __future__ import annotations

import inspect
import json

import agentconnect_sdk
from agentconnect.mcp.tools import TOOLS
from agentconnect.runtime import AgentApi
from agentconnect.runtime.api import ROUTE_SPECS
from agentconnect_sdk import embedded

GOVERNING = ("role", "owner", "transfer", "admin", "remove", "verify", "mismatch")
ROLES_AND_POLICY = ("role", "owner", "transfer", "admin", "policy")


# Every route, classified. A new route fails this test until it is added to
# one of the two sets: a decision for a person goes in HUMAN.
HUMAN = {
    "POST /v0/groups/{gid}/members/{identity}/role",
    "POST /v0/groups/{gid}/owner",
    "GET /v0/approvals/messages/{hid}",
    "POST /v0/approvals/messages/{hid}/approve",
    "POST /v0/approvals/messages/{hid}/reject",
    "POST /v0/approvals/{rid}/approve",
    "POST /v0/approvals/{rid}/reject",
    "POST /v0/groups/{gid}/members/{identity}/verify",
    "POST /v0/groups/{gid}/members/{identity}/remove",
    "POST /v0/groups/{gid}/safety",
    "GET /v0/audit",
    "GET /v0/groups/{gid}/transcript",
    "POST /v0/groups/{gid}/sas/mismatch",
    "POST /v0/listing/preview",
    "POST /v0/listing/publish",
}
# Either token. `POST /v0/groups` and `/policy` take the agent token only for
# defaults and raising require_verified (test_api_shapes.py runs that).
EITHER = {
    "GET /v0/status",
    "GET /v0/groups",
    "POST /v0/groups",
    "GET /v0/groups/{gid}",
    "POST /v0/groups/{gid}/invites",
    "DELETE /v0/invites/{invite_id}",
    "POST /v0/invites/inspect",
    "POST /v0/invites/accept",
    "POST /v0/groups/{gid}/policy",
    "POST /v0/groups/{gid}/messages",
    "POST /v0/groups/{gid}/leave",
    "GET /v0/approvals",
    "GET /v0/groups/{gid}/safety",
    "POST /v0/listing/withdraw",
    "GET /v0/listing",
    "POST /v0/knocks/inspect",
    "POST /v0/knocks",
    "GET /v0/knocks",
    "GET /v0/events",
    "GET /v0/deliveries",
    "POST /v0/deliveries/ack",
    "POST /v0/deliveries/release",
}


def test_every_route_is_classified_and_the_deciding_ones_need_the_human_token() -> None:
    routes = {f"{s.method} {s.path}": s.human for s in ROUTE_SPECS}
    assert len(routes) == len(ROUTE_SPECS)
    assert {r for r, human in routes.items() if human} == HUMAN
    assert {r for r, human in routes.items() if not human} == EITHER


def test_role_and_ownership_routes_need_the_human_token() -> None:
    governing = {s.path: s.human for s in ROUTE_SPECS if s.path.endswith(("/role", "/owner"))}
    assert governing == {
        "/v0/groups/{gid}/members/{identity}/role": True,
        "/v0/groups/{gid}/owner": True,
    }


def test_the_agent_api_changes_no_role_and_only_raises_require_verified() -> None:
    names = [n for n, _ in inspect.getmembers(AgentApi) if not n.startswith("__")]
    assert not [n for n in names if any(w in n for w in GOVERNING)]
    assert [n for n in names if "policy" in n] == ["set_policy"]
    # Its only policy knob is require_verified, at creation too.
    assert list(inspect.signature(AgentApi.set_policy).parameters) == [
        "self",
        "group_id",
        "require_verified",
    ]
    assert list(inspect.signature(AgentApi.create_group).parameters) == [
        "self",
        "name",
        "purpose",
        "require_verified",
    ]


def test_the_sdk_changes_no_role_or_policy() -> None:
    public = [getattr(agentconnect_sdk, n) for n in agentconnect_sdk.__all__]
    sdk = (agentconnect_sdk.AgentConnect, agentconnect_sdk.Group, embedded, embedded.EmbeddedHost)
    for obj in (*public, *sdk):
        names = [n for n, _ in inspect.getmembers(obj) if not n.startswith("_")]
        assert not [n for n in names if any(w in n for w in ROLES_AND_POLICY)], obj


def test_no_mcp_tool_changes_a_role_or_the_policy() -> None:
    names = [t.name for t in TOOLS]
    assert not [n for n in names if any(w in n for w in (*GOVERNING, *ROLES_AND_POLICY))]


PROVISIONING = ("export", "import", "provision", "replica", "identity_key")


def test_provisioning_a_replica_is_the_clis_alone() -> None:
    """ADR-005: no route exports or imports the identity key, and no agent
    method, SDK call or MCP tool does either or creates a replica invite. A
    replica invite is `replica: true` on the invites route, which the human
    token alone may set (harness/tests/test_replica_provisioning.py)."""
    assert not [s.path for s in ROUTE_SPECS if any(w in s.path for w in PROVISIONING)]
    names = [n for n, _ in inspect.getmembers(AgentApi) if not n.startswith("__")]
    assert not [n for n in names if any(w in n for w in PROVISIONING)]
    assert list(inspect.signature(AgentApi.create_invite).parameters) == [
        "self",
        "group_id",
        "ttl_secs",
        "max_uses",
        "inviter_name",
    ]
    public = [getattr(agentconnect_sdk, n) for n in agentconnect_sdk.__all__]
    sdk = (agentconnect_sdk.AgentConnect, agentconnect_sdk.Group, embedded, embedded.EmbeddedHost)
    for obj in (*public, *sdk):
        members = [n for n, _ in inspect.getmembers(obj) if not n.startswith("_")]
        assert not [n for n in members if any(w in n for w in PROVISIONING)], obj
    for tool in TOOLS:
        assert not any(w in tool.name for w in PROVISIONING), tool.name
        assert "replica" not in json.dumps(tool.schema), tool.name
