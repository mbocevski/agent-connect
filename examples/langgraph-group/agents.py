"""Three LangGraph agents in one ``mention`` group.

``planner``, ``researcher`` and ``critic`` each run in their own process
with the AgentConnect runtime embedded (``AgentConnect.embedded``): one
identity and data directory per agent, and no daemon to start. In
``mention`` mode (SPEC section 9.3) a message triggers only the identities
in its ``to`` list, and a human's
``to: ["*"]`` triggers everyone. Each agent answers only the questions
that are ``addressed_to_me`` (text that ends with ``?``), and replies to
the sender alone, so replies never trigger the other two.

Run one agent per process::

    uv run --with langgraph python examples/langgraph-group/agents.py planner

The model call is a :data:`Responder` (role, text -> answer). The default
is :func:`stub_responder`: fixed answers, no LangGraph and no API key.
``AC_EXAMPLE_MODEL=real`` runs :func:`langgraph_responder`, a one-node
LangGraph graph (which is where a real graph's nodes would go) around the
Claude Agent SDK; it needs the ``langgraph`` and ``claude-agent-sdk``
packages and ``ANTHROPIC_API_KEY``. ``AC_RELAY_URL`` names the relay.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from collections.abc import Awaitable, Callable
from typing import Any, TypedDict

from agentconnect_sdk import AgentConnect, Event, Group, Message

Responder = Callable[[str, str], Awaitable[str]]
TextModel = Callable[[str], Awaitable[str]]

ROLES = {
    "planner": "Break the request into steps.",
    "researcher": "List the facts the plan needs.",
    "critic": "Point out the weakest part of the request.",
}
QUOTE = 120


class State(TypedDict):
    role: str
    text: str
    answer: str


async def stub_responder(role: str, text: str) -> str:
    """Fixed answers per role that quote the peer's text (the last line)."""
    quoted = text.strip().splitlines()[-1].strip()[:QUOTE] if text.strip() else ""
    if "debat" in text.lower():
        return f"Let's keep debating ({quoted}): the {role} is not convinced. Why now?"
    return f"{role}: {ROLES[role]} For {quoted} the answer is to keep it small."


def claude_text_model() -> TextModel:
    """Prompt in, text out, through the Claude Agent SDK with no tools."""
    sdk = importlib.import_module("claude_agent_sdk")

    async def ask(prompt: str) -> str:
        options = sdk.ClaudeAgentOptions(tools=[], setting_sources=[], max_turns=1)
        parts: list[str] = []
        async for message in sdk.query(prompt=prompt, options=options):
            if isinstance(message, sdk.AssistantMessage):
                parts.extend(b.text for b in message.content if isinstance(b, sdk.TextBlock))
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


def choose_responder() -> Responder:
    """``AC_EXAMPLE_MODEL``: ``stub`` (the default) or ``real``."""
    choice = os.environ.get("AC_EXAMPLE_MODEL", "stub")
    if choice == "real":
        return langgraph_responder(claude_text_model())
    if choice != "stub":
        msg = f"AC_EXAMPLE_MODEL must be stub or real, not {choice!r}"
        raise SystemExit(msg)
    return stub_responder


def attach(ac: AgentConnect, role: str, respond: Responder) -> None:
    """Answer the questions addressed to this agent; stay quiet on the rest."""

    def log(line: str) -> None:
        print(f"[langgraph-{role}] {line}", flush=True)

    @ac.on_message
    async def answer(msg: Message, group: Group) -> None:
        who = msg.sender.display_name or msg.sender.identity[:16]
        if not msg.addressed_to_me or not msg.raw_text.rstrip().endswith("?"):
            log(f"context from {who}: {msg.raw_text[:QUOTE]!r}")
            return
        log(f"question from {who}: {msg.raw_text[:QUOTE]!r}")
        reply = await respond(role, msg.framed_text())
        log(f"answer: {reply[:QUOTE]!r}")
        await group.reply(msg, reply)

    @ac.on_event
    async def event(evt: Event, _group: Group | None) -> None:
        log(f"event {evt.type}")


async def main(role: str) -> None:
    respond = choose_responder()
    relay = os.environ.get("AC_RELAY_URL", "wss://relay.example.org")
    async with AgentConnect.embedded(name=f"langgraph-{role}", relay=relay) as ac:
        attach(ac, role, respond)
        await ac.serve()


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ROLES:  # noqa: PLR2004
        sys.exit(f"usage: agents.py {'|'.join(ROLES)}")
    asyncio.run(main(sys.argv[1]))
