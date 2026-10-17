"""Three LangGraph agents in one ``mention`` group.

``planner``, ``researcher`` and ``critic`` each run as their own daemon with
its own :class:`AgentConnect`. In ``mention`` mode (SPEC section 9.3) a
message triggers only the identities in its ``to`` list, and a human's
``to: ["*"]`` triggers everyone. Each agent answers only when
``addressed_to_me``, and replies to the sender alone, so replies never
trigger the other two and the loop guard has nothing to stop.

Run one agent per daemon::

    uv run --with langgraph --with claude-agent-sdk \
        python examples/langgraph-group/agents.py planner

The model call is a :data:`Responder` (role, text -> answer). The graph is a
single node around it, which is where a real graph's nodes would go. Tests
pass a stub responder.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from collections.abc import Awaitable, Callable
from typing import Any, TypedDict

from agentconnect_sdk import AgentConnect, Group, Message

Responder = Callable[[str, str], Awaitable[str]]
TextModel = Callable[[str], Awaitable[str]]

ROLES = {
    "planner": "Break the request into steps.",
    "researcher": "List the facts the plan needs.",
    "critic": "Point out the weakest part of the request.",
}


class State(TypedDict):
    role: str
    text: str
    answer: str


def claude_text_model() -> TextModel:
    """Prompt in, text out, through the Claude Agent SDK with no tools."""
    sdk = importlib.import_module("claude_agent_sdk")

    async def ask(prompt: str) -> str:
        options = sdk.ClaudeAgentOptions(allowed_tools=[])
        parts: list[str] = []
        async for message in sdk.query(prompt=prompt, options=options):
            for block in getattr(message, "content", None) or []:
                text = getattr(block, "text", None)
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)

    return ask


def langgraph_responder(model: TextModel) -> Responder:
    """A :data:`Responder` that runs a one-node LangGraph graph around
    ``model``. LangGraph is imported lazily."""
    graph_module = importlib.import_module("langgraph.graph")

    async def respond_node(state: State) -> dict[str, Any]:
        prompt = f"{ROLES[state['role']]}\n\n{state['text']}"
        return {"answer": await model(prompt)}

    builder = graph_module.StateGraph(State)
    builder.add_node("respond", respond_node)
    builder.add_edge(graph_module.START, "respond")
    builder.add_edge("respond", graph_module.END)
    graph = builder.compile()

    async def run(role: str, text: str) -> str:
        result = await graph.ainvoke({"role": role, "text": text, "answer": ""})
        return str(result["answer"])

    return run


def attach(ac: AgentConnect, role: str, respond: Responder) -> None:
    """Answer messages addressed to this agent; stay quiet on the rest."""

    @ac.on_message
    async def answer(msg: Message, group: Group) -> None:
        if not msg.addressed_to_me:
            return
        await group.reply(msg, await respond(role, msg.framed_text()))


async def main(role: str) -> None:
    async with AgentConnect() as ac:
        attach(ac, role, langgraph_responder(claude_text_model()))
        await ac.serve()


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ROLES:  # noqa: PLR2004
        sys.exit(f"usage: agents.py {'|'.join(ROLES)}")
    asyncio.run(main(sys.argv[1]))
