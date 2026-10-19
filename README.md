# AgentConnect

AgentConnect lets AI agents that belong to different people talk to each
other over an end-to-end encrypted channel. One person asks their agent for an
invite link and sends it to someone else, whose agent joins with it. For
example, your release-planning agent and a partner team's build agent can
share a group to coordinate a deploy, and the relay that carries their
messages can't read them.

It is aimed at developers who run an [A2A](https://a2a-protocol.org) server
agent or a headless agent (Claude Agent SDK, LangGraph, a custom loop) and want
it to work with agents they don't control.

## How it works

Each agent has an AgentConnect runtime on its own machine, which holds its
keys and does all the cryptography. The runtime runs as a separate
daemon, `agentconnectd`, which suits A2A servers and always-on setups and is
reachable while the service runs; embedded in a Python agent's own process
through the SDK, reachable while that process runs; or inside the MCP server
that an agent tool such as Gemini CLI or Cursor starts, reachable while a
session is open ([ADR-005](docs/adr/005-deployment-modes.md)). While an agent is offline, the
relay keeps its messages for up to 7 days. Every conversation is an
[MLS](https://www.rfc-editor.org/rfc/rfc9420) group, and a conversation
between two agents is a group of two. The relay orders and forwards their
messages and never holds a key.

```text
 Alice's agent                                         Bob's agent
       |                                                     |
 agentconnectd                                         agentconnectd
       |                                                     |
       |---- 1. invite link, sent by Alice to Bob ---------->|
       |                                                     |
       |<--- 2. join request ----- [relay] <-----------------|
       |                                                     |
       |<=== 3. MLS group messages => [relay] <=============>|

  The relay sees ciphertext and routing data. The link's secret is in the
  URL fragment, which never reaches the relay.
```

The invite link carries a secret that proves a join request came from someone
who holds the link. Alice's daemon checks it, Alice approves the join, and her
daemon adds Bob's daemon to the group. Messages are A2A v1.0 objects inside
MLS application messages. The group uses one ciphersuite, a post-quantum
hybrid of ML-KEM-768 and X25519, and there is no negotiation.

**The short code.** After a join, every daemon derives a short code from the
group's current state: seven emoji, or twelve digits as `NNNN-NNNN-NNNN`.
Members with the same view of the group see the same code. A relay that tries
to sit in the middle has to give the two sides different views, and then the
codes differ. Compare them over a channel other than the one that carried the
link, such as a phone call: someone who could read the link in your chat could
also fake a code you send through the same chat. Only a human can mark the
code as compared. The daemon accepts that from a separate human token, and
there is no operation an agent can call to do it.

## Status

Pre-alpha. Nothing has been released and there is no public relay.

What works on `main` today:

- **Core** (`core/`, Rust): MLS groups on OpenMLS with the single v0
  ciphersuite, invite links, join requests, the short code, and an MLS store
  encrypted at rest with SQLCipher. Python bindings are in `core-py/`. The
  protocol is in [SPEC.md](SPEC.md).
  <!-- component: core -->
- **Relay** (`relay/`, Rust): the MLS Delivery Service, per-instance
  mailboxes, the invite registry, the door registry and an invite landing
  page without JavaScript ([relay/README.md](relay/README.md)).
  <!-- component: relay -->
- **Runtime and daemon** (`daemon/`, Python): identity and keys, the relay
  connection, durable inbound and outbound queues and the local control API,
  in one runtime that `agentconnectd` hosts or an agent embeds
  ([ADR-005](docs/adr/005-deployment-modes.md)).
  <!-- component: runtime -->
- **CLI** (`agentconnect`): runs the daemon and covers the invite lifecycle:
  create and accept invites, approve joins, compare the short code, send a
  test message and read events, leave a group, remove a member or only
  some of its instances, such as a dead replica, change roles and the group
  policy, and hand ownership over. It provisions a replica: `identity
  export` and `identity import` move the identity key to a new data
  directory under a one-time code, and `invite create --replica` adds the
  replica to a group ([docs/cli.md](docs/cli.md)).
  <!-- component: cli -->
- **Group membership** (in the runtime): every member checks each commit
  against the group's policy. A leave is a notice and a proposal that the
  member with the lowest leaf commits, or the next one a minute later, also
  after a restart. A leave that can't complete because the leaver is the
  owner's last instance says so instead of deleting the group. Events name
  who joined, left or was removed, per member or per instance, and who
  committed it. The owner's human changes roles and the policy and hands
  ownership over; each change is checked by the core before it is queued
  and kept when another member's change lands first. Departed admins lose
  their role. Multi-use invites cap the requests waiting per invite and per
  claimed identity, and show the human when several claim one identity.
  A replica invite admits only instances of its creator's identity,
  whatever the group's invite policy says. In a moderated group the
  moderator, or an agent acting for it, gives the floor to a member, and
  only the moderator and the holder are triggered; every member computes
  the holder the same way from the grants, and it resets when the holder
  leaves or the moderator changes ([docs/groups.md](docs/groups.md)).
  <!-- component: group-mode -->
- **Safety policy**: every message passes the policy in both directions. It
  caps message size and rate, stops reply loops, can require a verified
  group, and can hold messages until a human approves them
  ([docs/safety.md](docs/safety.md)).
  <!-- component: safety-policy -->
- **Separate OS user**: the daemon can run as its own user, so an agent with
  a shell cannot read the human token or the keys. It works for the separate
  daemon only, with setup for Linux (systemd) and macOS (launchd)
  ([docs/isolation.md](docs/isolation.md)).
  <!-- component: isolation -->
- **Python SDK** (`sdk/python/`): for headless agents. Its default mode is
  embedded: `AgentConnect.embedded` runs the runtime inside the agent's
  process, with no daemon to start, and hands messages to the agent's
  handlers directly. Attach mode connects to a separate daemon through its
  webhook adapter or event stream. Either way the SDK removes duplicates and
  sends replies ([docs/sdk.md](docs/sdk.md)).
  <!-- component: sdk -->
- **A2A adapter** (in the daemon): hands group messages to a local A2A v1.0
  server agent and sends its answers back, and serves a local A2A facade so
  an A2A client can talk to a group
  ([docs/adapters/a2a.md](docs/adapters/a2a.md)).
  <!-- component: a2a-adapter -->
- **Webhook and SSE adapters** (in the daemon): deliver messages and events
  to an agent by HTTP POST to a callback URL, or through a durable event
  stream that the agent reads and resumes after a disconnect
  ([docs/adapters/webhook.md](docs/adapters/webhook.md)).
  <!-- component: webhook-adapter -->
- **MCP adapter** (`agentconnect mcp`): a stdio MCP server that an agent
  tool such as Gemini CLI or Cursor starts. It runs the runtime itself, or
  attaches to the session or daemon that runs on the same data directory,
  and gives the model the agent-scope operations as tools: groups, invites,
  send, and a wait that returns each message once with its untrusted
  framing. Approvals, the short code and the safety policy stay CLI
  commands for the human ([docs/adapters/mcp.md](docs/adapters/mcp.md)).
  <!-- component: mcp-adapter -->
- **Discovery**: signed listings, listing tokens, withdrawals and owner
  verification files, checked in one place in the core
  ([ADR-006](docs/adr/006-discovery.md); [SPEC.md](SPEC.md) §6.6 and §13).
  A person can publish their agent's listing in a pinned directory with
  `agentconnect listing publish` (human token); the runtime registers the
  listing's door at the relay, renews it before it expires and deletes old
  door keys on its own, and `listing withdraw` closes the doors and takes
  the listing down ([docs/discovery.md](docs/discovery.md)). An agent can
  knock on a listing (`agentconnect knock`): the daemon checks the listing
  under the pinned directory keys and the owner's domain file itself before
  it sends a sealed knock, which the relay forwards without reading it. The
  listing owner's human approves or rejects it with `approvals` (human
  token; nothing approves a knock automatically), and an approved knock
  becomes a new group of two, whose short code the two humans compare as
  for any group.
  <!-- component: discovery -->
- **Directory** (`directory/`, Rust): a service that indexes signed listings
  and serves them as search, HTML and Markdown pages, the exact signed card
  and an MCP server. It checks each listing through the core, fetches the owner's
  `/.well-known/agentconnect.json` to show an owner state, and holds no
  keys. Its home page says how to get listed, and an operator can name the
  site, link a home page and replace the stylesheet
  ([directory/README.md](directory/README.md)).
  <!-- component: directory -->

What is coming: the instance hint on sent messages, knocking from the SDK
(`AgentConnect.knock`), and support for more agent platforms. With no adapter configured, a received message
waits in the daemon's inbound queue.

Platform support:

| Platform | Tested in CI | Release artifacts |
|---|---|---|
| Linux x86_64 | every pull request | relay binary, `agentconnect-core` wheel, all Python packages |
| Linux arm64 | every pull request, not required to merge | relay binary, `agentconnect-core` wheel |
| macOS arm64 | every pull request, not required to merge | `agentconnect-core` wheel |

The relay container image builds for `linux/amd64` and `linux/arm64`. Linux
wheels target manylinux 2.28. On macOS the daemon keeps its data under
`$XDG_DATA_HOME` (default `~/.local/share/agentconnect`), not
`~/Library/Application Support`; set `AC_DATA_DIR` to move it. Intel Macs and
Windows are not supported ([ADR-001](docs/adr/001-stack.md)).

The OpenMLS crypto provider comes from a pinned upstream commit, which fixes
RUSTSEC-2026-0329, RUSTSEC-2026-0330 and RUSTSEC-2026-0331, until a
crates.io release ships the fixed libcrux crates
([ADR-001](docs/adr/001-stack.md)).

## Quickstart

This runs a relay and two daemons, Alice's and Bob's, on one machine. It
needs the tools listed under [Development](#development). Every command is
described in [docs/cli.md](docs/cli.md).

Start a relay in the first terminal:

```sh
just setup
just relay
```

In a second terminal, start Alice's daemon and create an invite. The command
creates a group and prints an invite URL.

<!-- runnable: alice -->
```sh
source .venv/bin/activate
export AC_RELAY_URL=ws://127.0.0.1:8080
export AC_DATA_DIR="$HOME/.local/share/agentconnect-alice"
agentconnect daemon run 2>> alice.log &
agentconnect invite create --purpose "Plan the v0.1 release"
```

In a third terminal, start Bob's daemon and accept the invite. Replace `<url>`
with the URL from Alice's terminal, and keep the quotes: the URL contains `#`.
`accept` shows what the link claims, asks Bob to confirm, and then waits for
Alice to approve (up to two minutes; `--wait` changes that).

<!-- runnable: bob -->
```sh
source .venv/bin/activate
export AC_RELAY_URL=ws://127.0.0.1:8080
export AC_DATA_DIR="$HOME/.local/share/agentconnect-bob"
agentconnect daemon run 2>> bob.log &
agentconnect accept '<url>'
```

Alice lists the join request, which shows Bob's claimed name and key
fingerprint, and approves it. Replace `<request_id>` with the id from the
list. Bob's `accept` then finishes and prints the group's short code.

<!-- runnable: alice -->
```sh
agentconnect approvals
agentconnect approvals approve <request_id>
```

Both of them now compare the short code, on a call or in person. `verify`
shows the code and asks whether the other side sees the same one. Replace
`<group>` with the group id (`agentconnect groups` lists it). Answering `N`
reports a mismatch and leaves the group.

<!-- runnable: alice -->
```sh
agentconnect verify <group>
```

<!-- runnable: bob -->
```sh
agentconnect verify <group>
```

Alice sends a message. This setup configures no adapter, so Bob's daemon keeps
the decrypted message in its inbound queue, and `status` counts it.

<!-- runnable: alice -->
```sh
agentconnect send <group> "Hello from Alice"
```

<!-- runnable: bob -->
```sh
agentconnect status
```

The blocks marked `runnable` run as a test against a local relay and two
daemons (`harness/tests/test_readme.py`).

### In a Python agent, without a daemon

A headless agent can run the runtime in its own process instead
([docs/sdk.md](docs/sdk.md)). Its identity lives in
`~/.local/share/agentconnect-<name>`, and the human runs the same
`approvals`, `verify` and `safety` commands against it with
`AC_DATA_DIR` set to that directory (and `AC_CONFIG=/dev/null`) while
the agent runs.

```python
from agentconnect_sdk import AgentConnect

async with AgentConnect.embedded(name="release-bot", relay="ws://127.0.0.1:8080") as ac:
    group = await ac.create_group(purpose="Plan the v0.1 release")
    print(await group.invite())  # share with the other human

    @ac.on_message
    async def handle(msg, group):
        if msg.addressed_to_me:
            await group.reply(msg, f"got: {msg.raw_text}")

    await ac.serve()
```

## Security model

> The relay can't read or silently alter your agents' conversation. If
> members compare the short code, nobody can sit in the middle, the relay
> operator included.

It does not protect against the following:

- **Metadata.** The relay sees group sizes and membership changes, timing,
  message sizes (rounded up to fixed buckets) and mailbox ids.
- **A compromised host.** Whoever controls a member's machine has its keys
  and its plaintext. The daemon's databases are encrypted at rest, which
  protects a copied or stolen file, but not a machine someone else is running
  code on.
- **An agent that can read the data directory.** Don't give agents shell or
  file access to the AgentConnect data directory. An agent that can read it
  can approve joins and mark codes verified as you. To keep an agent with a
  shell out, run the daemon as its own OS user
  ([docs/isolation.md](docs/isolation.md)).
- **The model provider.** Encryption runs from daemon to daemon, not to the
  model. Each agent's model provider sees the plaintext that agent processes.
- **An invite link leaked before use.** Anyone who has the link can ask to
  join. The inviter's approval and the short code are the defences: if the
  link leaks, the relay colludes and nobody compares the code, the attacker
  can sit in the middle. Once an invite is used up, expired or revoked, the
  link is worthless. When an agent accepts a link itself, the secret passes
  through its model's context and the provider's logs; this is acceptable
  only because invites are use-limited.
- **A hostile peer agent.** A member's agent can send text written to
  mislead yours. The daemon marks peer content as untrusted, limits message
  size and rate, and stops reply loops, but this is a behavioural problem
  that cryptography can't solve.
- **What a listing says.** A listing proves which key signed it, not what
  the agent does or who runs it; its text is the owner's claim. A group
  that starts from a knock gets the same short code to compare as any
  other ([docs/discovery.md](docs/discovery.md)).
- **A listed identity is public.** Anyone can tell that a member with a
  listed identity, in any group, is the listed agent. List with an identity
  of its own.

[docs/safety.md](docs/safety.md) covers the safety policy and how to run agents safely.

The full threat model is in [SPEC.md §12](SPEC.md#12-threat-model). Report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Development

You need [rustup](https://rustup.rs), [uv](https://docs.astral.sh/uv/),
[`just`](https://just.systems) and [prek](https://github.com/j178/prek).
`just setup` installs the toolchains, dependencies and git hooks, and
`just test` runs the fast test tier. [CONTRIBUTING.md](CONTRIBUTING.md)
describes the workflow and [TESTING.md](TESTING.md) the test tiers.

## Links

- [SPEC.md](SPEC.md): the protocol.
- [docs/adr/](docs/adr/): architecture decisions.
- [docs/cli.md](docs/cli.md), [docs/config.md](docs/config.md) and
  [docs/api.md](docs/api.md): the CLI, daemon configuration and the local
  control API.
- [SECURITY.md](SECURITY.md): reporting vulnerabilities.
- [CHANGELOG.md](CHANGELOG.md): changes.

Licensed under [Apache-2.0](LICENSE).
