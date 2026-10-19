"""Roles, ownership and the group policy are the human's (SPEC 9.2,
docs/groups.md): no agent route, runtime agent method, SDK call or MCP
tool changes them. The one exception is raising ``require_verified``, which
only tightens the gate (SPEC 10.4). These tests look for each way in; the
harness runs the routes against real daemons (``test_api_shapes.py``)."""

from __future__ import annotations

import inspect

import agentconnect_sdk
from agentconnect.mcp.tools import TOOLS
from agentconnect.runtime import AgentApi
from agentconnect.runtime.api import ROUTE_SPECS
from agentconnect_sdk import embedded

GOVERNING = ("role", "owner", "transfer", "admin", "remove", "verify", "mismatch")
ROLES_AND_POLICY = ("role", "owner", "transfer", "admin", "policy")


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
