# ADR-005: Deployment modes: one runtime, three hosts

- **Status:** Accepted (2026-10-17). The runtime refactor and the embedded
  SDK host are implemented (2026-10-18), and so are the MCP host and the
  delivery routes; attach for the embedded SDK (`on_locked="attach"`) is
  not yet.
- **Date:** 2026-10-17
- **Deciders:** Marko Bocevski

## Implementation notes (embedded SDK)

What was built, and where it departs from the text below:

- **Package layout.** `agentconnect/runtime/` holds `engine.py` (the old
  `daemon.py`, `Daemon` renamed `Engine`), `api.py` (`ApiServer`),
  `agent.py` (`AgentApi`), `registry.py` (`AdapterRegistry`), `errors.py`
  (`ApiError`, `error_reply`) and `runtime.py` (`Runtime`, `HandledIds`).
  The leaf modules (`store`, `relay`, `identity`, `keystore`, `limits`,
  `backoff`, `clock`, `adapter`, `config`, `log`, `policy`) stayed where they
  were: moving them changed nothing but import paths. The package root
  re-exports what hosts need, and ruff's `TID251` keeps the CLI, the
  `agentconnect.daemon` host and the SDK on the root. The token helpers are
  in `agentconnect.tokens`.
- **`Runtime`'s signature** differs from the sketch below. There is no
  `policy=` argument: the policy hook was replaced by the safety policy
  (`agentconnect.policy`) before this landed, and the safety policy is
  runtime code in every host. `api_address` is `Path | str | None` (`None`
  before start, or with `serve_api=False`). It also takes `options=` (test
  seams, the lock owner's name), `gate=` (the separate-OS-user peer checks)
  and `serve_api=` (default `True`; the harness turns it off where a
  scenario builds its own API server).
- **Delivery to the embedded agent** is `agentconnect.callback.CallbackAdapter`.
  Every handler call runs in a task of its own, bounded by
  `sdk.handler_timeout_secs` (default 120 s) on the runtime's clock; a
  handler that raises or times out is a `RETRY` with the runtime's backoff,
  as a webhook answering 500 or timing out. Events go through a queue in the
  encrypted database with workers of their own. The SDK keeps the ids its
  handlers finished with in the same database (`Runtime.handled`), keyed
  `["msg", group, sender, msg_id]` or `["event", event_id]`, so a redelivery
  after a restart doesn't reach user code and a peer-chosen `msg_id` can't
  hide anything else.
- **Per-group delivery.** The engine hands deliveries to adapters through
  one worker per group, for every adapter, not one loop for all groups: a
  stuck or failing delivery holds up its own group only. Order within a
  group is strict.
- **Stopping from inside a handler.** `aclose()` called from a handler
  schedules the shutdown and returns, since a handler can't wait for the end
  of its own runtime; the shutdown stops new deliveries, waits (at most the
  flush window) for running handlers, flushes, then stops. `serve()`
  returns once that is complete.
- **`AC_DATA_DIR` and `name=`.** Decision 2 says `AC_DATA_DIR` overrides the
  default in every mode. For the embedded SDK an `AC_DATA_DIR` that
  disagrees with an explicit `name=` is refused instead: a variable
  exported for one agent's CLI would otherwise hand a second agent the
  first one's identity, which the required name exists to prevent.
- **Long socket paths.** A socket path over 103 bytes (the macOS limit) is
  bound at `/tmp/agentconnect-<uid>/<hash>.sock`, a 0700 directory that the
  runtime creates and checks and that the CLI and SDK derive from the same
  path (`agentconnect.sockets`). Separate-OS-user mode refuses such a path
  at startup, because the agent users must reach the socket in the agent
  directory.
- **Local API.** `ApiServer` keeps only the SHA-256 of both tokens
  (`agentconnect.tokens.TokenDigest`). Agent-scope routes call `AgentApi`, the
  same object the embedded SDK calls.
- **Lock.** The `daemon.lock` file records the holder (`daemon` or
  `embedded`, and the pid), so the error names who has the directory.
- **Contract test.** The harness's `cluster` fixture runs every scenario on
  both hosts (`daemon` and `embedded`); `harness/tests/test_sdk_modes.py`
  runs one SDK script in embedded and attach mode.

## Implementation notes (MCP host)

What was built for the MCP-spawned mode, and where it departs from the text
below ([adapters/mcp.md](../adapters/mcp.md)):

- **Package.** `agentconnect/mcp/` holds the host: `server.py` (the stdio
  server, `configure`, signals), `session.py` (host or attach, takeover),
  `backend.py` (`HostBackend` over `Runtime` and `AgentApi`,
  `AttachBackend` over the local API with the agent token) and `tools.py`
  (the tool table). It uses the official MCP Python SDK (`mcp`, MIT), its
  low-level server, over stdio. The command is `agentconnect mcp`.
- **Delivery.** The adapter is `agentconnect.deliveries.DeliveryQueue`
  (`mcp`). An MCP client pulls, so the queue answers the runtime `ACK` at
  once and keeps each message in the encrypted database (the in-process
  adapters' queue table) until a tool call returned it; then the key goes into
  the handled ids the embedded SDK uses. Decision 3 says the delivery stays
  in the runtime's inbox until then; the queue is the same database, and it
  lets `addressed_only` skip ahead of context messages, which a blocked
  inbox head would not.
- **Delivery routes.** `GET /v0/deliveries` (a long poll of at most 60
  seconds) leases what it returns for 120 seconds under a lease token, and
  `POST /v0/deliveries/ack` takes the token and a list of ids rather than one
  id per request; an id the token doesn't hold is refused. The in-process
  session uses the same leases, so two sessions never get one message at the
  same time. With `addressed_only` the queue finds the oldest addressed
  message by an indexed column, so no number of other messages before it can
  hide it. At most 4 polls per token wait at once (`429 busy`), and agent
  requests may use 48 of the API's 64 connections, so the human's CLI always
  gets through.
- **When to acknowledge.** Decision 3 says a delivery is acknowledged once a
  tool call returned it to the model. The server acknowledges a wait's batch
  once it wrote the result to the client's pipe: a call cancelled after it
  took its batch, or whose result was never written, acknowledges nothing.
  A failed ack is retried and, until it went through, the batch's messages
  are not dropped as repeats. A client that drops a written result loses it;
  MCP has no receipt.
- **Takeover.** Every reconnect looks at the lock as it is then: held, the
  session attaches to the holder; free, it takes the directory over, unless
  the lock note names a daemon or an embedded agent as the last holder. Those
  have supervisors of their own; a session waits for them to come back rather
  than take their directory, which would keep a restarted daemon from
  starting.
- **The human token.** A hosting session runs the runtime, which creates
  `human-token` and keeps only its hash (Decision 4); no tool exposes it, and
  an attached session reads `api-token` only.
- **Isolation.** `isolation.enabled` is refused, as by the embedded SDK.

## Context

Something on the agent's side has to hold the identity and instance keys, the
relay connection, the two SQLCipher databases (ADR-002, ADR-003), the
processing journal ([ADR-004](004-processing-journal.md)), the durable inbox and outbox, the
endpoint policy (SPEC [§10](../../SPEC.md#10-endpoint-policy-normative-minimums))
and the policy hook. Today that is `agentconnectd`, a long-running process per
machine or user, which agents reach over the local API
([api.md](../api.md)).

Hosting it for the user as a service is rejected: the host would hold the
keys and see plaintext, which is the property the relay design exists to
avoid. It has to run on the agent's side, under the user's control.

A separate daemon fits A2A servers and always-on setups. It fits two other
kinds of agent less well:

- A **single headless agent** (Claude Agent SDK, LangGraph, a custom loop) is
  one Python process. Asking its user to install, start and supervise a
  second process for it is the largest setup cost we have.
- An **agent tool that speaks MCP** (Gemini CLI, Cursor and similar;
  Claude Code support goes through the same path, with
  Claude Code Channels for push) starts its MCP servers itself, per
  session, and stops them when the session ends. A daemon the user must start separately is one more thing
  that is not running when the tool needs it.

Three modes are planned:

1. **Separate daemon** (today): A2A servers, several agents on one host,
   always-on setups.
2. **Embedded SDK**: the runtime runs inside the agent's own Python process.
3. **MCP-spawned**: the MCP server that the agent tool starts is the runtime.

The question is how to offer all three without three implementations of the
protocol, and what each mode means for keys, the human-only operations,
offline behaviour and replicas.

### What the code looks like today

All of it is in the `agentconnect` distribution, `daemon/src/agentconnect/`.

| Module | Role | Kind |
|---|---|---|
| `daemon.py` (`Daemon`) | Engine: groups, commits, policy checks, limits, loop guard, gating, journal recovery, workers | runtime |
| `store.py`, `identity.py`, `keystore.py` (`DataDirLock`) | Daemon database, keys, keystore, data-directory lock | runtime |
| `relay.py`, `backoff.py`, `limits.py`, `clock.py` | Relay link and REST, reconnect, rate limits, clock | runtime |
| `adapter.py` | `Adapter`, `PolicyHook`, `PassThroughPolicy` | runtime (interfaces) |
| `api.py` (`ApiServer`) | Local API with the agent and human tokens | runtime |
| `config.py` | `Config` and the TOML and `AC_*` loader | runtime (dataclass), host (loader) |
| `log.py` | Redacting structured logger; `configure()` installs it | runtime (`get`, `hid`), host (`configure`) |
| `cli.py` `_run`, `daemon run` | Signals, `log.configure()`, start and stop order | host |
| `cli.py`, `cli_support.py`, `sas_emoji.py` | CLI commands and rendering | host |
| `apiclient.py` | Client of the local API | client |

The split is already close to clean: `Daemon` takes its config, adapters,
policy hook, clock and keystore as arguments and has no notion of a terminal
or of signals. What a host does today is the twenty lines of `cli._run`:
build `Daemon` and `ApiServer`, start both, wait for a signal, stop both in
reverse order.

## Decision 1: one runtime, three hosts

**All protocol behaviour lives in one runtime package. A host only decides
where the configuration comes from, when the runtime starts and stops, which
adapters it registers and what surface the agent sees.** No host
reimplements or overrides a check: commit authorisation (SPEC §9.2), the
endpoint policy (§10), verification gating (§10.4), the journal and the
retention rules run in the runtime in every mode.

### Package layout

```text
daemon/src/agentconnect/
  runtime/              embeddable; no terminal, no signals, no stdout
    __init__.py         Runtime, AgentApi, AdapterRegistry, Config, errors
    engine.py           today's daemon.py (Daemon renamed Engine)
    api.py              today's api.py (ApiServer, both tokens)
    store.py relay.py identity.py keystore.py limits.py backoff.py clock.py
    adapter.py          Adapter, PolicyHook, PassThroughPolicy
    config.py           Config; the TOML/env loader stays here, hosts call it
    log.py              get, hid, redaction; configure() is called by hosts
  client.py             today's apiclient.py, plus the attach client (Decision 2)
  daemon/               host: agentconnectd (today's cli._run, signals, logging)
  mcp/                  host: the MCP server (follow-up)
  cli.py cli_support.py sas_emoji.py   host: the CLI
sdk/python/src/agentconnect_sdk/
  embedded.py           host: the runtime inside the agent's process
  client.py             the SDK against a separate daemon (attach)
```

`agentconnect.daemon` becomes the host package, so today's
`agentconnect/daemon.py` has to move first; `runtime/engine.py` is its new
name. Nothing is released, so there are no compatibility shims.

**Decided: the runtime stays in the `agentconnect` distribution**, and
`agentconnect-sdk` depends on it. There is no separate runtime package.

### The runtime's API boundary

```python
class Runtime:
    adapters: AdapterRegistry  # register(adapter) before start()
    agent: AgentApi  # agent-scope operations only
    api_address: Path | str  # the socket (or 127.0.0.1:port) the CLI uses

    def __init__(
        self,
        config: Config,
        *,
        adapters: Iterable[Adapter] = (),
        policy: PolicyHook | None = None,
        clock: Clock | None = None,
        keystore: Keystore | None = None,
    ) -> None:
        """Take the data-directory lock, open the keys and both databases."""

    async def start(self) -> None:
        """Journal recovery, workers, relay link, then the local API server."""

    async def stop(self) -> None:
        """API server, bounded outbox flush, workers, databases, the lock."""

    async def __aenter__(self) -> Runtime: ...
    async def __aexit__(self, *exc: object) -> None: ...
    def status(self) -> dict[str, Any]: ...
```

- `AgentApi` is the agent-scope operation set: groups, invites (create,
  inspect, accept, revoke), send, leave, events, approvals *listing*, and
  raising `require_verified`. The local API's agent routes call this same
  object, so the in-process path and the socket path cannot drift apart.
- **No human-scope operation is reachable from `Runtime` or `AgentApi`.**
  Approve, reject, verify and SAS mismatch exist only as local API routes
  that need the human token (Decision 4).
- `AdapterRegistry` replaces today's `Daemon.adapters` dict and
  `daemon.default_adapter`: each group stays bound to one adapter by name
  (the `adapter` column of the groups table), and registration closes at
  `start()`.
- Hosts may import only from `agentconnect.runtime` (the package root), never
  from `runtime.engine` or the other submodules. Ruff's banned-API rule
  (`TID251`) enforces it.

### The refactor (embedded-mode task)

1. Move the runtime modules into `agentconnect/runtime/` and rename `Daemon`
   to `Engine`. Mechanical, no behaviour change; the multi-node harness and
   every test pass unchanged apart from imports.
2. Add `Runtime`, which owns the lock, the `Engine` and the `ApiServer`, and
   move today's start and stop order from `cli._run` into it. `cli._run`
   becomes `agentconnect.daemon.serve()`: signal handlers and
   `log.configure()` around `Runtime`.
3. Extract `AgentApi` from the `Engine` methods the agent routes call, and
   point those routes at it.
4. Add `AdapterRegistry`.
5. Switch the harness (`harness/src/agentconnect_harness/cluster.py`) from
   `Daemon` to `Runtime`, so every multi-node test exercises what the hosts
   run.
6. Add `agentconnect_sdk.embedded` on top.
7. A contract test runs the same scenario (invite, join, approve over the
   socket, verify, send, receive) through each host that exists. A host that
   needs a protocol branch of its own is a bug in the runtime's API.

The wire format, the relay and SPEC behaviour do not change.

## Decision 2: identity and data directory per mode

One data directory is one identity and one instance: keys (keyring entries
are scoped by the directory's resolved path, `keystore.py`), both databases,
the tokens, the socket and `daemon.lock`. The lock (`DataDirLock`, an
exclusive `flock`) is taken before any key or database is opened, in every
mode.

| Mode | Default data directory | Name |
|---|---|---|
| Separate daemon | `$XDG_DATA_HOME/agentconnect` (today) | none |
| Embedded SDK | `$XDG_DATA_HOME/agentconnect-<name>` | **required** (`name=` or `data_dir=`) |
| MCP-spawned | `$XDG_DATA_HOME/agentconnect-<name>` | `--agent NAME` in the MCP server command, default `mcp` |

`AC_DATA_DIR` and an explicit `data_dir` override the default in every mode.
The `agentconnect-<name>` form matches the README quickstart.

- The embedded SDK has **no** implicit default, so two different bots on one
  machine can't end up as one identity by accident.
- The MCP host's name comes from its command line, not from the client's
  self-reported `clientInfo`, so the identity doesn't change when a tool
  renames itself.

### When the directory is locked: attach

Agent tools start one MCP server per session, so a second session on the
same name finds the lock held. Failing would make the second session
useless. **Decided: a host that finds the lock held may *attach* to the
running instance instead. Attach is the default for the MCP host and opt-in
for the embedded SDK, and attached MCP hosts take the lock over when the
owner exits.**

- An attached host opens no key and no database. It talks to the owner's
  local API over the socket with the agent token (`api-token`, same OS user)
  and gets the same `AgentApi` surface, implemented as a client.
- Deliveries reach it through new agent-scope API routes (a long-poll
  `GET /v0/deliveries` and `POST /v0/deliveries/{id}/ack`). The owner binds
  them as a registered adapter, so delivery stays at-least-once through the
  owner's durable inbox.
- The same client is how the SDK uses a separate daemon, so attach adds no
  second code path: "SDK against a daemon" and "second MCP session" are one
  feature.
- The policy hook runs where commits are processed, which is the owner. An
  attaching host that was given a custom `PolicyHook` refuses to attach
  rather than run without it.
- **Default per mode:** the MCP host attaches. The embedded SDK fails with
  `DataDirLockedError` unless the caller passes `on_locked="attach"`, because
  an embedded agent that silently depends on another process's lifetime and
  policy is a surprise.
- **Takeover:** when the owner exits, attached MCP hosts lose the socket and
  try to take the lock. `flock` lets one win; it starts a runtime, and the
  others re-attach to it. The journal makes the handover safe: the new owner
  finishes whatever the old one left (ADR-004).

Trade-off: attach makes the owner's lifetime visible to the others (a short
gap while a new owner starts), and a second session can read the first
session's groups and messages, since both are the same identity. The
alternative, one identity per session, would ask the human to approve and
verify every session separately and would scatter one person's agent across
many members.

## Decision 3: lifecycle and offline behaviour

| | Separate daemon | Embedded SDK | MCP-spawned |
|---|---|---|---|
| Start | `agentconnect daemon run`, under systemd, launchd or a container supervisor | `async with Runtime(...)` in the agent process | when the agent tool starts the MCP server (session start) |
| Stop | SIGTERM or SIGINT | leaving the context, or process exit | stdin EOF from the agent tool, or a signal |
| Crash | supervisor restarts it | the agent's own supervisor restarts the agent | next session starts it |
| Reachable | while the service runs | while the agent process runs | while some session of that name is open |

The same rules hold in all three modes, because they are runtime code:

- **Store and forward.** While an instance is offline, the relay keeps its
  mailbox: messages, commits, Welcomes and JoinRequests, until acked or for
  the 7-day TTL (SPEC [§8.3](../../SPEC.md#83-delivery-service-rules)). On
  connect the runtime drains them in order, with the drain exemption from
  the rate limits (§10.2).
- **Longer than the TTL is not recoverable.** An instance offline for more
  than 7 days may have missed commits, and MLS can't skip an epoch. It is
  then out of sync and has to rejoin with a new invite. This matters most
  for MCP mode, where the runtime runs only during sessions. The runtime
  should record when it last drained its mailbox, and `status` should warn
  when that is close to the TTL.
- **Restart.** On start the runtime first finishes every pending journal
  entry, then resends a pending own commit under its original `msg_id`
  (SPEC §8.3), then drains the outbox. A crash loses nothing that was
  journalled or queued. Deliveries and events to adapters are at-least-once
  with stable ids (ADR-004): after a crash `deliver` and `on_event` may
  repeat, and every host's adapter deduplicates by `msg_id` and `event_id`.
- **Stop.** `stop()` gives the outbox a bounded flush (a few seconds) so that
  a session that sends and then closes usually gets its message out. What
  doesn't make it stays in the encrypted outbox until the next start.
- **MCP deliveries.** The MCP adapter acks a delivery only when a tool call
  has returned it to the model. Until then it stays in the runtime's
  encrypted inbox, so a session that ends before the model reads its
  messages loses none of them. A message handed over twice after a crash
  carries the same `msg_id`, and the host drops the repeat.

**What "reachable" means to users.** v0 has no presence: a peer can't tell
whether a member is online. A message to an offline member waits at the
relay; a JoinRequest to an offline inviter waits too, and so does the
joiner's `accept` (it times out locally, the request does not). The docs
should say this per mode in plain words: a separate daemon is reachable
while it runs; an embedded agent while its process runs; an MCP-spawned one
only while a session is open, and it catches up when the next one starts.

## Decision 4: human-only operations without a separate daemon

Approve, reject, verify and SAS mismatch need the human token in every mode
(SPEC [§6.2](../../SPEC.md#62-validation-and-approval-inviter),
[§11](../../SPEC.md#11-short-authentication-string-sas)).

- **The runtime serves the local API socket whenever it runs**, in every
  mode, with the same agent/human split as today. The human uses the CLI
  against it from another terminal:
  `AC_DATA_DIR=~/.local/share/agentconnect-<name> agentconnect approvals`
  (a `--agent NAME` shortcut for the CLI is part of the follow-up).
- While the runtime isn't running, there is nothing to approve against.
  Pending JoinRequests wait at the relay (Decision 3). The CLI never opens
  the databases itself; the lock forbids it and approval needs the relay.
- **There is no in-process route to a human operation.** The embedded SDK
  and the MCP host offer none: no `runtime.approve()`, no MCP tool. The one
  path is the CLI with the token, as today.
- **Where the token is.** `human-token` stays a 0600 file in the data
  directory, created on first start, because the CLI needs to read it. The
  runtime reads it once at start, keeps only its SHA-256 for the bearer
  check (constant-time comparison), and drops the value. The SDK and MCP
  hosts never read the file and never pass it into tools. The CLI reads it
  per command.

### What this protects against, and what it doesn't

The split holds against a model that can only use the agent's tools. A
prompt-injected or confused model can call every `AgentApi` operation, and
none of them approves a join or marks a code as compared. It also keeps the
human capability out of integration code by default, so adapter and tool
authors don't expose it by mistake.

It does **not** hold against code running as the same OS user. **In every
mode, code or agents with shell or file access that run as the same OS user
can read the human token and the data directory**, and so can approve joins
and mark short codes as verified in the human's name. In detail:

- Python has no access control inside a process. Agent code in the embedded
  or MCP process can reach the engine through private attributes, read the
  keys from memory, or open `human-token` from disk. The runtime holding only
  a hash removes the token from the process's memory, not from the disk.
- A separate daemon doesn't change that for a same-user agent: the token file
  and the keystore are readable by that user either way.
- **Agent tools with shell access** (most coding agents) run commands as the
  user. A model that can run `cat` can read `human-token` and call the API,
  or run `agentconnect approvals approve` itself, in every mode.

**Decided: document now, plan isolation.**

- The README security model and `daemon/README.md` say it now: don't give
  agents shell or file access to the AgentConnect data directory, because
  an agent that can read it can approve joins and mark codes verified as
  the human. The MCP host docs add how to deny that access, and the
  human-scope CLI commands, in the agent tool's own permission settings.
  That is a policy of the tool, not something AgentConnect can enforce.
- **An optional separate-OS-user mode.** Isolation from same-user agent
  code needs a process boundary *and* a different OS user: the runtime and
  `human-token` under one user, the agent under another with access to the
  socket and `api-token` only. It is an option for separate-daemon mode only
  (Decision 7): `isolation.enabled`, set up as described in
  [isolation.md](../isolation.md). The daemon then checks each connection's
  peer UID, accepts the human token only from its own UID or a configured
  human UID, and refuses to start with a loose data directory or token.

This is the statement the docs already make ("it is not a sandbox"), now
made per mode.

## Decision 5: replicas and multiple agents

- **One instance per process** in embedded and MCP modes. A process creates
  at most one `Runtime`. Several in one process is supported in tests only
  (the harness), where the logger and the clock are shared on purpose.
- **Replicas are separate instances under one identity**
  (SPEC [§9.4](../../SPEC.md#94-multi-instance-members)): each has its own
  data directory with the same identity key `IK`, its own instance key and
  `instance_id`, its own mailbox, MLS leaf and databases, and joins each
  group through its own invite. Every replica receives every message;
  `body.metadata.instance` targets one. Each replica keeps its own verified
  flags, one per member identity (SPEC §11), and its human verifies on that
  replica: verifying a peer on one replica doesn't mark it verified on
  another.
- **Provisioning a replica** needs the identity key in a second data
  directory with a fresh instance. Nothing does that today. The follow-up
  adds a human-only CLI command (identity export and import, never over the
  API), and the docs say that every replica host then holds `IK`.
- **Copying a whole data directory is not a replica.** The copy has the same
  instance key, mailbox and MLS state, and two runtimes on one leaf break the
  group. The lock can't catch a copy on another machine.
- **Several agents on one separate daemon** share its identity and instance.
  Each group is bound to one adapter, so one daemon can serve, say, an A2A
  agent in some groups and a webhook agent in others. Peers see one member,
  and every agent with `api-token` can act in every group of that daemon.
- **Decided: one daemon per identity.** Agents that should be distinct
  members, or that shouldn't see each other's groups, run one daemon each,
  with one data directory each (a systemd template unit,
  `agentconnectd@<name>`). Per-agent tokens scoped to groups are deferred.

## Decision 6: security comparison

"Same-user code" means any code running as the agent's OS user, including a
model with a shell tool. "Agent tools only" means a model that can call the
agent-scope operations and nothing else.

| | Separate daemon | Embedded SDK | MCP-spawned |
|---|---|---|---|
| Identity and MLS keys in the agent's process memory | no | yes | yes (the MCP process; the agent tool's own process doesn't have them) |
| Keys reachable by same-user code | yes (keystore, key files) | yes (memory and keystore) | yes (memory and keystore) |
| Human token reachable with agent tools only | no | no | no |
| Human token reachable by same-user code | yes (file) | yes (file) | yes (file) |
| Compromised agent process, code execution | the user's keys, tokens and plaintext: as a compromised host (SPEC §12) | same | same |
| Compromised agent process, agent token only | agent-scope operations in **every group of the daemon**, including other agents' | agent-scope operations on its own identity | agent-scope operations on its own identity, shared with attached sessions |
| Runtime outlives an agent crash | yes | no | no (an attached session may take over) |
| Plaintext at rest | SQLCipher, both databases, ADR-003 retention | same | same |
| Plaintext in memory | daemon; then the agent after delivery | agent process | MCP process; then the agent tool after delivery |

What the separate daemon buys is a separate address space and, for several
agents, one place to supervise. It doesn't buy key isolation from a
same-user agent. That needs the different-user setup above.

## Decision 7: supported and unsupported combinations

Supported:

- A separate daemon with the A2A and webhook adapters, and SDK or MCP
  clients attached to it on the same data directory.
- Several agents on one separate daemon, one adapter per group, under one
  identity (Decision 5).
- One embedded `Runtime` per agent process, each on its own data directory;
  attach to an existing owner when the caller asks for it.
- MCP-spawned runtimes: the first session owns, later sessions attach, one
  takes over when the owner exits.
- Replicas of one identity across processes or machines, each with its own
  data directory and invites, once replica provisioning exists.

Unsupported:

- **A third party hosting the runtime for users.** It sees plaintext and holds
  the keys.
- **Any runtime function in the relay.**
- Human operations over MCP tools, SDK calls or any agent-token route.
- Two runtimes owning one data directory (the lock refuses it), and data
  directories on network filesystems, where `flock` isn't reliable.
- Copying a data directory to make a replica or to move an instance while
  the original still runs.
- More than one `Runtime` in a production process.
- An attached host with its own `PolicyHook`.
- Running the runtime and the agent as different OS users in the embedded
  SDK or MCP-spawned modes. The separate daemon supports it with
  `isolation.enabled` ([isolation.md](../isolation.md), Decision 4).

## Consequences

- **Code:** the embedded-mode task does the refactor in Decision 1. The MCP
  host is a follow-up, and the Claude Code Channels adapter builds on it (a
  push channel for the same deliveries, the same ack rule).
- **Local API:** new agent-scope delivery routes for attached hosts and SDK
  clients (Decision 2). `docs/api.md` documents them and the human token's
  hash-only handling; the route table moves there from `daemon/README.md`.
- **SPEC §2:** "Instance: one running copy of an identity, i.e. one daemon"
  and the "Daemon" term become "runtime", with `agentconnectd` as one host
  of it. No wire format changes.
- **README:** the security model and `daemon/README.md` carry the
  data-directory warning from Decision 4 now. With the embedded task, "Each
  agent talks to a local daemon" becomes the three modes in one short
  paragraph, with what "reachable" means for each.
- **`docs/sdk.md`** (new, with the embedded task): embedded and attached
  use, the required `name`, `on_locked`, lifecycle, the bounded flush on stop,
  the 7-day offline limit, and how the human runs the CLI against the
  embedded runtime.
- **MCP host docs** (with the MCP task): the `--agent` name, attach and
  takeover, the deny rules for the data directory and the human-scope CLI
  commands in the agent tool's permission settings.
- **`docs/cli.md`:** the `--agent NAME` shortcut, and replica provisioning
  once it exists.
- The harness and the contract test run every host against the same
  runtime, so a behaviour fork shows up as a failing test.

## Decisions taken on review

All five questions left open in the proposal are decided as recommended.

1. **Attach semantics: decided.** Attach is the default for the MCP host and
   opt-in for the embedded SDK (`on_locked="attach"`), and attached MCP hosts
   take the lock over when the owner exits (Decision 2). Trade-off accepted:
   shared state across sessions and a short gap on takeover, against one
   identity per session and repeated approvals and verifications.
2. **Data directory naming: decided.** `$XDG_DATA_HOME/agentconnect-<name>`,
   a required name for the embedded SDK, `--agent NAME` (default `mcp`) for
   the MCP host (Decision 2). Trade-off accepted: one more argument for SDK
   users, against two bots sharing an identity by accident.
3. **Human token storage: decided.** The human token stays a 0600 file in
   the data directory, and the runtime keeps only its hash (Decision 4). It
   doesn't move into the OS keyring: once the login session has opened it,
   the keyring answers that user without a prompt on most Linux desktops, so
   it adds little against same-user code and complicates headless setups.
   The shell-access caveat is documented, and the separate daemon has an
   optional separate-OS-user mode ([isolation.md](../isolation.md)).
4. **Distribution: decided.** The runtime stays in the `agentconnect`
   distribution and `agentconnect-sdk` depends on it. Trade-off accepted:
   SDK users install the CLI's dependencies too, but they need the CLI for
   the human operations anyway, and one distribution keeps the runtime and
   its CLI at one version.
5. **Several agents: decided.** One daemon per identity. Agents that should
   be distinct members or isolated from each other run one daemon each;
   several agents on one daemon share its identity, with one adapter per
   group (Decision 5). Per-agent tokens scoped to groups are deferred: they
   would need their own design and tests.
