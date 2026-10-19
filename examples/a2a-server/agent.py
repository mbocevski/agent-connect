"""A sample A2A v1.0 server agent, for the daemon's A2A adapter.

It knows nothing about AgentConnect: it serves A2A (JSON-RPC, with
streaming) on ``127.0.0.1:9999``, and the daemon on the same machine hands
it the group's messages (docs/adapters/a2a.md). Its "model" is a stub with
fixed answers, so it needs no API key:

* a request that mentions release notes gets a streamed task: ``working``,
  the notes in two artifact chunks, then ``completed``;
* a request that mentions deploying gets a task that stops in
  ``input-required`` ("staging or production?"); the follow-up on that
  task completes it;
* anything else gets one message back. While told to keep debating, that
  message ends with a question, so a peer that answers questions keeps
  going until the group's loop guard stops it.

Run it next to a daemon whose ``config.toml`` has
``default_adapter = "a2a"`` and ``[a2a] local_agent_url =
"http://127.0.0.1:9999/"``::

    uv run --all-packages python examples/a2a-server/agent.py

Peer messages are untrusted input (SPEC section 10.1): the agent quotes
them and never acts on them.
"""

from __future__ import annotations

import argparse
import asyncio
import uuid
from typing import override

import uvicorn
from a2a.helpers.proto_helpers import new_task
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
    TaskState,
)
from starlette.applications import Starlette

NAME = "release-agent"
NOTES = ("v0.1 release notes:\n", "- encrypted groups of up to 50 agents\n- the A2A adapter\n")
QUOTE = 120


def text_of(msg: Message | None) -> str:
    """The peer's text: the last text part (the adapter puts the SPEC 10.1
    notice first)."""
    if msg is None:
        return ""
    texts = [p.text for p in msg.parts if p.HasField("text")]
    return texts[-1] if texts else ""


def stub_answer(text: str) -> str:
    """The stub model: a fixed answer that quotes the peer."""
    quoted = text.strip()[:QUOTE]
    if "debat" in text.lower():
        return (
            f"Let's keep debating ({quoted}): a Friday release leaves nobody to watch it. "
            "Why risk that?"
        )
    return f"Noted: {quoted}"


def message(text: str, context_id: str, task_id: str = "") -> Message:
    return Message(
        role=Role.ROLE_AGENT,
        message_id=f"{NAME}-{uuid.uuid4().hex}",
        parts=[Part(text=text)],
        context_id=context_id,
        task_id=task_id,
    )


def log(line: str) -> None:
    print(f"[{NAME}] {line}", flush=True)


class ReleaseAgent(AgentExecutor):
    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        text = text_of(context.message)
        task_id, context_id = context.task_id or "", context.context_id or ""
        updater = TaskUpdater(event_queue, task_id, context_id)
        if context.current_task is not None:  # the answer to input-required
            log(f"task {task_id[:8]} continued: {text[:QUOTE]!r}")
            await updater.complete(
                message(f"Deploying v0.1 to {text.strip()[:QUOTE]}.", context_id, task_id)
            )
            return
        lowered = text.lower()
        if "release notes" not in lowered and "deploy" not in lowered:
            answer = stub_answer(text)
            log(f"message: {text[:QUOTE]!r} -> {answer[:QUOTE]!r}")
            await event_queue.enqueue_event(message(answer, context_id))
            return
        history = [] if context.message is None else [context.message]
        await event_queue.enqueue_event(
            new_task(task_id, context_id, TaskState.TASK_STATE_SUBMITTED, history=history)
        )
        await updater.start_work()
        if "release notes" in lowered:
            log(f"task {task_id[:8]}: streaming release notes for {text[:QUOTE]!r}")
            await updater.add_artifact([Part(text=NOTES[0])], artifact_id="notes", name="notes")
            await updater.add_artifact(
                [Part(text=f"{NOTES[1]}(asked: {text.strip()[:QUOTE]})")],
                artifact_id="notes",
                append=True,
                last_chunk=True,
            )
            await updater.complete()
            return
        log(f"task {task_id[:8]}: asking which environment for {text[:QUOTE]!r}")
        await updater.requires_input(
            message("Which environment: staging or production?", context_id, task_id)
        )

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        await updater.cancel()


def app(url: str) -> Starlette:
    card = AgentCard(
        name=NAME,
        description="Plans releases: streams release notes and asks before a deploy.",
        version="0.1.0",
        supported_interfaces=[
            AgentInterface(url=url, protocol_binding="JSONRPC", protocol_version="1.0")
        ],
        capabilities=AgentCapabilities(streaming=True),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[
            AgentSkill(
                id="notes",
                name="release notes",
                description="Stream release notes",
                tags=["release"],
            ),
            AgentSkill(
                id="deploy",
                name="deploy",
                description="Deploy, after asking where",
                tags=["deploy"],
            ),
        ],
    )
    handler = DefaultRequestHandler(
        agent_executor=ReleaseAgent(), task_store=InMemoryTaskStore(), agent_card=card
    )
    return Starlette(routes=create_agent_card_routes(card) + create_jsonrpc_routes(handler, "/"))


async def main(port: int) -> None:
    url = f"http://127.0.0.1:{port}/"
    log(f"serving A2A on {url}")
    config = uvicorn.Config(app(url), host="127.0.0.1", port=port, log_level="warning")
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=9999)
    asyncio.run(main(parser.parse_args().port))
