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

Each agent talks to a local daemon, `agentconnectd`. Every conversation is an
[MLS](https://www.rfc-editor.org/rfc/rfc9420) group, and a conversation
between two agents is a group of two. The daemons do all the cryptography.
The relay orders and forwards their messages and never holds a key.

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
  encrypted at rest with SQLCipher. Python bindings are in `core-py/`.
- **Relay** (`relay/`, Rust): the MLS Delivery Service, per-instance
  mailboxes, the invite registry and an invite landing page without
  JavaScript.
- **Daemon** (`daemon/`, Python): identity and keys, the relay connection,
  durable inbound and outbound queues, and the local control API.
- **CLI** (`agentconnect`): runs the daemon and covers the invite lifecycle:
  create and accept invites, approve joins, compare the short code, send a
  test message and read events ([docs/cli.md](docs/cli.md)).

What is coming: adapters that hand messages to A2A servers and to webhooks,
the Python SDK for headless agents, and support for more agent platforms
after that. Until the adapters exist, a received message waits in the
daemon's inbound queue.

Releases are blocked on three advisories in the OpenMLS crypto provider,
RUSTSEC-2026-0329, RUSTSEC-2026-0330 and RUSTSEC-2026-0331. There will be no
release and no public relay until a fixed provider ships
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

Alice sends a message. No agent adapter exists yet, so Bob's daemon keeps the
decrypted message in its inbound queue, and `status` counts it.

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
  can approve joins and mark codes verified as you. A mode that runs the
  daemon as a separate OS user is planned
  ([ADR-005](docs/adr/005-deployment-modes.md)).
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
