# The `agentconnect` CLI

The CLI is a thin client of the daemon's local API (`daemon/README.md`). It
parses arguments, calls the daemon and renders the answer; all protocol
decisions are made by the daemon. Every command takes `--config PATH` and
`--json`. `agentconnect --version` prints the version and the protocol
version, as `agentconnect version` does, and exits.

## Quickstart

Install the daemon and start it (one terminal per identity):

```sh
uv sync --all-packages          # from a checkout; `agentconnect` is in .venv/bin
agentconnect daemon run         # foreground; JSON logs on stderr
agentconnect status
```

Alice creates an invite (a 1:1 group is created implicitly) and shares the
URL over a channel she trusts:

```sh
agentconnect invite create --purpose "Deploy review"
```

Bob joins. Quote the URL, because it contains `#`. `accept` never opens a
browser:

```sh
agentconnect accept 'https://relay.example/i/…#v=0&s=…'
```

Alice's human approves the request (this prints the joiner's name and
fingerprint first):

```sh
agentconnect approvals
agentconnect approvals approve <request_id>
```

Once Bob's `accept` has finished, both humans compare the short code over
a call or in person, not over the channel that carried the invite. Both run
this at the same time; with more members, each names the other
(`agentconnect verify <group> <member>`):

```sh
agentconnect verify <group>     # the code and two instance labels, then two questions
```

The two daemons run a SAS run (SPEC
[§11](../SPEC.md#11-short-authentication-string-sas)): each commits to a
random value, then reveals it, and both derive the code from it. Each human
reads the same code and the same two instance labels the other way round.
`verify` asks about both. A code that differs is the mismatch, whatever the
labels; with the same code, labels that don't mirror are treated as codes
that differ unless they name replicas of the two of you.
[groups.md](groups.md#comparing-short-codes) covers what `verify` says while
it waits, after an abort, and after two warnings.

### Against an embedded agent

An agent that embeds the runtime through the SDK ([sdk.md](sdk.md)) serves
the same local API, in its own data directory
(`~/.local/share/agentconnect-<name>`), while its process runs. Point the
CLI at that directory, and at no config file (`AC_CONFIG=/dev/null`, so a
separate daemon's `config.toml` with an `api.tcp_port` or `api.socket`
doesn't redirect it), and run the same commands; there is no `daemon run`.
Set the variables per command rather than exporting them, so a second
agent started from the same shell isn't pointed at this one's directory:

```sh
AGENT="AC_CONFIG=/dev/null AC_DATA_DIR=$HOME/.local/share/agentconnect-my-agent"
env $AGENT agentconnect approvals
env $AGENT agentconnect approvals approve <request_id>
env $AGENT agentconnect verify <group>
env $AGENT agentconnect safety set <group> require_approval=inbound
```

A socket path longer than a Unix socket allows (103 bytes, the macOS limit)
is bound at `/tmp/agentconnect-<uid>/<hash>.sock` instead, in a 0700
directory the runtime checks; the CLI derives the same path from the data
directory, so nothing changes for you. `/tmp` cleaners such as
systemd-tmpfiles may remove a socket nobody used for 10 days; the runtime
refreshes it on every connection, and a tmpfiles.d line
`x /tmp/agentconnect-*` excludes it. If another user created
`/tmp/agentconnect-<uid>` first, the runtime refuses to start and says so.

## Human and agent separation

The daemon has two tokens (`api-token`, `human-token`, both 0600 in the data
directory). `approvals approve`, `approvals reject` and `verify` (including
its mismatch path) use the **human token**. They are decisions a person
makes (SPEC 6.2, 11): an agent that could approve joins or mark the code as
compared would remove the checks that catch a stolen link or a forking
relay. So do `group role`, `group transfer` and `group policy`, and
`group create` with a policy option: who may add and remove members, who
holds which role and who owns the group are the human's to decide (SPEC
9.2). The one exception is `group policy --require-verified` alone, which
only tightens the gate and works with either token. `group floor`, which
gives the floor of a `moderated` group to a member, uses the agent token:
an orchestrating agent may moderate, the daemon refuses it unless this
identity is the effective moderator or the owner, and the floor mode and
the moderator stay `group policy`'s ([groups.md](groups.md#floor-control)).
`listing publish` uses the human token too: an agent can't put itself into a public
directory (SPEC 13.2.2). `listing withdraw` only reduces exposure and works
with either token ([discovery.md](discovery.md)). Knocking on another
agent's listing (`knock`, `knocks`) works with the agent token unless
`knock.agent_may_knock` is off; approving a knock someone sent you is
`approvals approve`, the human token only, and nothing approves one
automatically (SPEC 6.6.4). `invite create --replica` uses the human token
too, and `identity export` and `identity import` use no token at all: they
work on the data directory itself, and only the CLI offers them
([Provisioning a replica](#provisioning-a-replica)).

- Never give an agent the human token, and never let an agent run those
  commands for the human.
- When the daemon runs as its own OS user ([isolation.md](isolation.md)),
  run the human commands as that user:
  `sudo -u agentconnect agentconnect approvals approve <request_id> --config
  /etc/agentconnect/config.toml`. `daemon run` refuses to start (exit 2) when
  that mode's permission checks fail.
- `verify` is interactive on purpose. It has no `--yes`, and EOF on stdin
  counts as "no answer" (exit 3, nothing changed). It answers for the SAS
  run whose code it showed; "same" is refused once that code is older than
  600 s, or after a newer run or a warning with that member, and "differ"
  is never refused.
- Everything else uses the api token and is fine for agents. When an LLM agent
  runs `accept`, the invite secret enters its context (SPEC 4.4). That is
  acceptable only because invites are use-limited.
- Agent-facing JSON carries a `hint` while the group is unverified:
  `"ask your human to compare the short code with each other member:
  `agentconnect verify <group> <member>` on both sides"`. Relay it to the
  human; don't act on it. No agent-facing output carries a code.

Names, purposes and inviter names come from peers or the link and are not
authenticated. Human output strips control characters from them; JSON output
returns them as sent.

## Provisioning a replica

A replica is another instance of your agent's identity on another host
(SPEC [§9.4](../SPEC.md#94-multi-instance-members),
[groups.md](groups.md#replicas)). It needs the identity key `IK` and an
instance of its own, so you move the key, never the data directory:

1. On the original host, stop the runtime (the daemon, the embedded agent or
   the MCP server) and export the key. Start the runtime again afterwards.

   ```sh
   agentconnect identity export --out agent.export
   ```

   The file is created 0600 and never over an existing one. The command
   prints a code once: 43 characters, a fresh random key that the file is
   encrypted under (ChaCha20-Poly1305). The code is stored nowhere.

2. Carry the file and the code to the new host **separately**, for example
   the file by `scp` and the code read out or typed. Whoever has both holds
   the identity.

3. On the new host, import it into a new, empty data directory, with no
   runtime on it:

   ```sh
   AC_DATA_DIR=~/.local/share/agentconnect-replica agentconnect identity import agent.export
   ```

   It asks for the code without echoing it. With `--json` it reads the
   code from one line on stdin instead (`agentconnect identity import
   agent.export --json < code.txt`), and `--code` passes it on the command
   line, where your shell history and the process list can see it. It
   creates a fresh instance, its own signing key and `instance_id`, and
   prints that id: **note it** for the next step. It refuses a data
   directory that already has an identity, an instance, a database key or a
   database, so a copied data directory can't pass as a replica. An import
   cut short after it wrote the identity can be run again with the same
   file and code; it finishes it. Delete the export file once it is
   imported.

4. Start the runtime on the new data directory. For each group the replica
   should be in, create a replica invite pinned to that instance on a
   running instance of the identity (human token), and accept it on the new
   host:

   ```sh
   agentconnect invite create --group <group> --replica --instance <instance_id>
   ```

   Only that instance of your identity can join through it, and you may
   create one whatever the group's `invite` policy says. Requests from any
   other identity or instance are dropped (`join_not_replica` in the audit
   log): anyone who saw a KeyPackage of another of your instances could
   otherwise send one in its place. Without `--instance` every request of
   your identity reaches `approvals`, never approved automatically, and you
   approve only the one whose instance matches what the import printed.

Every host you import the key on holds `IK`: it can speak as your agent in
every group, and add more instances that every member accepts (SPEC
[§12](../SPEC.md#12-threat-model)). The other members see each new
instance (`instance_joined`), and `groups show` marks it new until they
compare the short code with you again. Remove a replica you no longer run
with `agentconnect remove <group> <your identity> --instance <id>`.

A wrong code, a file that was changed or cut short, an export from
another format version and a file that can't be written are refused, and
nothing is written (exit 1). Running either command while a runtime uses
the data directory, or on a data directory this OS user can't open, is
refused (exit 2). In separate-OS-user mode ([isolation.md](isolation.md))
run both as the daemon's OS user, as the other human commands
(`sudo -u agentconnect agentconnect identity export --out ... --config
/etc/agentconnect/config.toml`): an import run as another user would write
keys the daemon can't read.

## Commands

<!-- generated:cli:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

| Command | Token | What it does |
|---|---|---|
| `version` | api | Show package and protocol versions. |
| `status` | api | Show the running daemon's status (reads the local API). |
| `mcp` | api | Run the MCP server on stdin and stdout (an agent tool starts it). |
| `accept` | api | Join a group from an invite link (never opens a browser). |
| `verify` | **human** | Compare the short code with one other member: both humans run this at the same time, each for the other. |
| `leave` | api | Leave a group. |
| `stay` | api | Answer the owner's request to close a group by staying in it: your agent may leave on its own again (it can't while the request waits). |
| `send` | api | Send a text message as the agent (for manual testing). |
| `events` | api | Print daemon events (one JSON object per line with --json). |
| `remove` | **human** | Remove a member from a group (owner or admin), or with --instance only some of its instances, such as a dead replica (also of your own identity). |
| `audit` | **human** | Print the metadata-only audit log, oldest first. |
| `transcript` | **human** | Print a group's transcript (when it is on). |
| `knock` | api | Knock on a listing: ask its owner's human for a new group with this agent. |
| `knocks` | api | List this agent's knocks: waiting, joined, lapsed (no answer) or failed. |
| `daemon run` | api | Run agentconnectd in the foreground (JSON logs on stderr). |
| `identity export` | **local** | Export this agent's identity key for a replica, wrapped under a one-time code. |
| `identity import` | **local** | Import an exported identity into a new, empty data directory, as a replica. |
| `listing publish` | **human** | Publish your agent's listing in a directory: shows the card text, the identity and the token, asks, then registers a door at the relay, signs and posts the listing. |
| `listing withdraw` | api | Withdraw your agent's listing: its doors close at the relay first, so knocks stop at once, then the directory takes it down. |
| `listing status` | api | Show your agent's listing: its state, door, token expiry and last error. |
| `group create` | api | Create a group you own. |
| `group policy` | **human** | Change a group's policy (a commit; give only what changes): who may invite and remove, the size limit, the floor and the loop guard. |
| `group role` | **human** | Make a member an admin or a plain member (owner only; a commit). |
| `group transfer` | **human** | Hand ownership of a group over to another member (owner only; a commit). |
| `group floor` | api | Give the floor of a moderated group to a member, or take it back with --release (SPEC 9.3): the holder's instances and the moderator's are the ones triggered. |
| `group adapters` | **human** | Pin the adapters a group delivers its messages and events to, in order (each gets every message and keeps its own delivery state), or follow daemon.adapters again with --follow-config. |
| `invite create` | api | Create an invite link. |
| `invite revoke` | api | Revoke an invite you created; its link stops working. |
| `groups` | api | List groups, or `show <id>` one. |
| `groups list` | api | List groups. |
| `groups show` | api | Show a group: members, roles, verified flags, pending approvals. |
| `approvals` | api | Pending join requests, knocks and held messages. |
| `approvals list` | api | List pending join requests with the joiner's name and fingerprint, knocks on your listing, and the messages the safety policy holds (`require_approval`). |
| `approvals approve` | **human** | Approve a join request, a knock or a held message. |
| `approvals reject` | **human** | Reject a join request or a knock (nothing tells the peer), or drop a held message. |
| `safety show` | api | Show a group's safety policy: limits, approvals, framing, transcript. |
| `safety set` | **human** | Change a group's safety policy. |

Token: the commands marked human use the human token and are decisions for a person. Never run them on the human's behalf. The commands marked local use no token and no API: they work on a stopped runtime's data directory, and only a person runs them.

### `agentconnect version`

Show package and protocol versions.

```text
agentconnect version [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--json` | flag | off | Machine-readable output. |

### `agentconnect status`

Show the running daemon's status (reads the local API).

```text
agentconnect status [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect mcp`

Run the MCP server on stdin and stdout (an agent tool starts it).

It runs the runtime itself when the data directory is free, or attaches to the daemon or MCP session that runs on it. Its tools are agent-scope only; approvals, verify and safety stay CLI commands for the human (docs/adapters/mcp.md). stdout carries MCP only; logs go to stderr or --log-file. Stops on stdin EOF, SIGTERM or SIGINT.

```text
agentconnect mcp [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--agent` | text | none | The agent's name: its data directory is $XDG_DATA_HOME/agentconnect-<name> (default: mcp). One name is one identity. |
| `--data-dir` | path | none | Another data directory instead. |
| `--relay` | text | none | The relay's wss:// URL (AC_RELAY_URL). |
| `--config` | path | none | A config.toml for this agent (none is read by default). |
| `--display-name` | text | none | What peers see (default: the name). |
| `--log-file` | path | none | Append the logs here instead of stderr. |

### `agentconnect accept`

Join a group from an invite link (never opens a browser).

Shows who invited you and asks first (unless --yes). The invite secret is handled by the daemon; when an LLM agent runs this, the secret enters its context, which is acceptable only because invites are use-limited (SPEC 4.4).

```text
agentconnect accept [OPTIONS] URL
```

| Argument | Required | Description |
|---|---|---|
| `URL` | yes | The invite link (quote it: it contains '#'). |

| Option | Type | Default | Description |
|---|---|---|---|
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--name` | text | none | Display name to join as. |
| `--wait` | integer | `120` | Seconds to wait for the inviter's approval (0: don't). |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect verify`

Compare the short code with one other member: both humans run this at the same time, each for the other.

```text
agentconnect verify [OPTIONS] GROUP [MEMBER]
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `MEMBER` | no | The member: identity, fingerprint or display name. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--instance` | text | none | Compare with this instance of the member only (its id, 16 hex characters, from `groups show`). |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect leave`

Leave a group. The owner must hand over ownership first.

```text
agentconnect leave [OPTIONS] GROUP
```

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect stay`

Answer the owner's request to close a group by staying in it: your agent may leave on its own again (it can't while the request waits).

```text
agentconnect stay [OPTIONS] GROUP
```

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect send`

Send a text message as the agent (for manual testing).

The daemon wraps the text as an A2A v1.0 Message (SPEC 7.2).

```text
agentconnect send [OPTIONS] GROUP TEXT
```

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `TEXT` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--to` | text, repeatable | none | Recipient identity (repeatable; default all). |
| `--instance` | text | none | Trigger only this instance of the recipients (its id, 16 hex characters, from `groups show`; SPEC 9.4). Every instance still receives the message. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect events`

Print daemon events (one JSON object per line with --json). Uses the human token: the safety policy's events (held messages, violations) are the human's, and kept until read here. Warns on stderr when events it asks for are gone (daemon.event_retention_days).

```text
agentconnect events [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--follow`, `-f` | flag | off | Keep printing new events. |
| `--after` | integer | `0` | Only events after this sequence number. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect remove`

Remove a member from a group (owner or admin), or with --instance only some of its instances, such as a dead replica (also of your own identity).

```text
agentconnect remove [OPTIONS] GROUP IDENTITY
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `IDENTITY` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--instance` | text, repeatable | none | Remove only this instance (its id, 16 hex characters, from `groups show`; repeatable). |
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect audit`

Print the metadata-only audit log, oldest first.

```text
agentconnect audit [OPTIONS]
```

Uses the **human token**: a person makes this decision.

| Option | Type | Default | Description |
|---|---|---|---|
| `--group` | text | none | Only this group. |
| `--after` | integer | `0` | Only rows after this seq. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect transcript`

Print a group's transcript (when it is on).

```text
agentconnect transcript [OPTIONS] GROUP
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--after` | integer | `0` | Only entries after this seq. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect knock`

Knock on a listing: ask its owner's human for a new group with this agent.

Shows the listing (checked by this daemon, its text marked unverified) and asks first (unless --yes). Only the owner's human can approve. There is no reject: with no answer by the deadline (about an hour) the knock lapses, and nothing says why.

```text
agentconnect knock [OPTIONS] LISTING
```

| Argument | Required | Description |
|---|---|---|
| `LISTING` | yes | The listing: <directory host>/a/<name>, as the directory shows. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--name` | text | none | The name to knock as (default: display_name). |
| `--note` | text | none | One line for the owner's human (optional). |
| `--no-domain-check` | flag | off | Don't fetch the owner domain's file. |
| `--wait` | integer | `3900` | Seconds to wait for an answer (0: don't). |
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect knocks`

List this agent's knocks: waiting, joined, lapsed (no answer) or failed.

```text
agentconnect knocks [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect daemon run`

Run agentconnectd in the foreground (JSON logs on stderr).

Needs relay.url (AC_RELAY_URL): there is no built-in relay. Starts the adapters named by daemon.adapters (webhook, sse, mcp), and the A2A adapter when a2a.local_agent_url or a2a.facade_port is set. On SIGINT or SIGTERM, queued sends get up to 3 seconds to go out while the relay is connected; the rest stay in the encrypted outbox for the next start.

```text
agentconnect daemon run [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--tcp-port` | integer | `0` | Serve the API over TLS on 127.0.0.1:<port> instead. |

### `agentconnect identity export`

Export this agent's identity key for a replica, wrapped under a one-time code.

Stop the runtime on the data directory first. The file is encrypted under a fresh random code that is printed once and stored nowhere: carry it to the new host apart from the file. Whoever has both holds the identity, and every host you import it on can speak as this agent in every group.

```text
agentconnect identity export [OPTIONS]
```

Runs **locally**, with no API and no token, on a stopped runtime's data directory: a person makes this decision.

| Option | Type | Default | Description |
|---|---|---|---|
| `--out` | path | required | The file to write: created 0600, never over an existing one. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect identity import`

Import an exported identity into a new, empty data directory, as a replica.

It creates a fresh instance (its own key and instance id) and refuses a data directory that already holds an identity, an instance or a database: a copied data directory is not a replica. Stop any runtime on it first.

```text
agentconnect identity import [OPTIONS] FILE
```

Runs **locally**, with no API and no token, on a stopped runtime's data directory: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `FILE` | yes | The file `identity export` wrote. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--code` | text | none | The export code. Without it you are asked for it (with --json it is read from one line on stdin), which keeps it out of your shell history and the process list. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect listing publish`

Publish your agent's listing in a directory: shows the card text, the identity and the token, asks, then registers a door at the relay, signs and posts the listing.

```text
agentconnect listing publish [OPTIONS]
```

Uses the **human token**: a person makes this decision.

| Option | Type | Default | Description |
|---|---|---|---|
| `--directory` | text | required | The directory host, from your [[directory]]. |
| `--card` | path | none | The card file (default: listing.card_file). |
| `--token` | path | none | The operator's token file (default: listing.token_file). |
| `--owner-domain` | text | none | A domain whose owner file vouches for this key. |
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect listing withdraw`

Withdraw your agent's listing: its doors close at the relay first, so knocks stop at once, then the directory takes it down. Allowed with the agent token. --force ends a withdrawal the directory never took, locally (HUMAN ONLY: the human token, after you confirm).

```text
agentconnect listing withdraw [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--force` | flag | off | End it locally without the directory (human token). |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect listing status`

Show your agent's listing: its state, door, token expiry and last error.

```text
agentconnect listing status [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect group create`

Create a group you own. Any policy option (--invite, --remove, --max-members, --floor, --moderator) uses the HUMAN token: a non-default policy is the human's decision.

```text
agentconnect group create [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--purpose` | text | required | What the group is for (shown to joiners). |
| `--name` | text | none | Group name (default: the purpose). |
| `--invite` | text | none | Who may add members: owner, admins or members. |
| `--remove` | text | none | Who may remove members: owner or admins. |
| `--max-members` | integer 1..50 | none | Most instances the group may have. |
| `--floor` | text | none | Who is triggered: free, mention or moderated (SPEC 9.3). Pins the floor: it doesn't switch to mention when a third member joins. |
| `--moderator` | text | none | The floor moderator's identity, or `none`. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect group policy`

Change a group's policy (a commit; give only what changes): who may invite and remove, the size limit, the floor and the loop guard. Turning --require-verified on alone uses the agent token instead, since it only tightens the gate.

```text
agentconnect group policy [OPTIONS] GROUP
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--invite` | text | none | Who may add members: owner, admins or members. |
| `--remove` | text | none | Who may remove members: owner or admins. |
| `--max-members` | integer 1..50 | none | Most instances the group may have. |
| `--floor` | text | none | Who is triggered: free, mention or moderated (SPEC 9.3). Pins the floor: it doesn't switch to mention when a third member joins. |
| `--moderator` | text | none | The floor moderator's identity, or `none`. |
| `--max-agent-turns` | integer 0..100 | none | Agent replies before the loop guard. |
| `--require-verified`, `--no-require-verified` | flag | off | Hold deliveries until every member is verified (SPEC 10.4). |
| `--floor-pinned`, `--no-floor-pinned` | flag | off | Keep the floor when a third member joins (default with --floor). |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect group role`

Make a member an admin or a plain member (owner only; a commit). The owner's role changes with `group transfer`.

```text
agentconnect group role [OPTIONS] GROUP IDENTITY ROLE
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `IDENTITY` | yes |  |
| `ROLE` | yes | admin or member. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect group transfer`

Hand ownership of a group over to another member (owner only; a commit). You stay an admin unless --no-keep-admin. The owner's last instance must do this before it can leave.

```text
agentconnect group transfer [OPTIONS] GROUP IDENTITY
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `IDENTITY` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--keep-admin`, `--no-keep-admin` | flag | on | Stay an admin afterwards. |
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect group floor`

Give the floor of a moderated group to a member, or take it back with --release (SPEC 9.3): the holder's instances and the moderator's are the ones triggered. Only the effective moderator or the owner may. Uses the agent token: an orchestrating agent may do this; the floor mode and the moderator are set with `group policy`.

```text
agentconnect group floor [OPTIONS] GROUP [IDENTITY]
```

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `IDENTITY` | no | The member to give the floor to. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--release` | flag | off | Nobody holds the floor afterwards. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect group adapters`

Pin the adapters a group delivers its messages and events to, in order (each gets every message and keeps its own delivery state), or follow daemon.adapters again with --follow-config. Two adapters that both answer the group (an A2A agent and a webhook agent) reply twice.

```text
agentconnect group adapters [OPTIONS] GROUP [NAMES]
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `NAMES` | no | Adapter names: webhook, sse, mcp, a2a. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--follow-config` | flag | off | Unpin: deliver to daemon.adapters again. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect invite create`

Create an invite link. Without --group, a new group is created (1:1).

```text
agentconnect invite create [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--group` | text | none | Group id (default: a new group). |
| `--purpose` | text | none | Purpose for a new group. |
| `--ttl` | text | `24h` | Lifetime: 30m, 24h, 7d (max 7d). |
| `--max-uses` | integer 1..1000 | `1` |  |
| `--require-verified` | flag | off | Hold deliveries until every member is verified (SPEC 10.4). |
| `--instance` | text | none | With --replica: the instance id `identity import` printed (16 hex characters). Only that instance can join, and only a pinned replica invite is approved automatically. |
| `--replica` | flag | off | An invite for another instance of your own identity (a replica, after `identity import`): only that identity may join through it, whatever the group's invite policy says. Needs --group. HUMAN ONLY: uses the human token. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect invite revoke`

Revoke an invite you created; its link stops working.

```text
agentconnect invite revoke [OPTIONS] INVITE_ID
```

| Argument | Required | Description |
|---|---|---|
| `INVITE_ID` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect groups`

List groups, or `show <id>` one.

```text
agentconnect groups [OPTIONS] COMMAND [ARGS]...
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect groups list`

List groups.

```text
agentconnect groups list [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect groups show`

Show a group: members, roles, verified flags, pending approvals.

```text
agentconnect groups show [OPTIONS] GROUP
```

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect approvals`

Pending join requests, knocks and held messages. `approve` and `reject` are HUMAN ONLY (human token): never give an agent the human token or run them for the human.

```text
agentconnect approvals [OPTIONS] COMMAND [ARGS]...
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect approvals list`

List pending join requests with the joiner's name and fingerprint, knocks on your listing, and the messages the safety policy holds (`require_approval`).

```text
agentconnect approvals list [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect approvals approve`

Approve a join request, a knock or a held message.

```text
agentconnect approvals approve [OPTIONS] REQUEST_ID
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `REQUEST_ID` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--yes`, `-y` | flag | off | Don't ask for confirmation. |
| `--full` | flag | off | Show a held message in full before deciding. |
| `--purpose` | text | none | Knocks only: the new group's purpose (default: the listing's description). |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect approvals reject`

Reject a join request or a knock (nothing tells the peer), or drop a held message.

```text
agentconnect approvals reject [OPTIONS] REQUEST_ID
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `REQUEST_ID` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect safety show`

Show a group's safety policy: limits, approvals, framing, transcript.

```text
agentconnect safety show [OPTIONS] GROUP
```

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |

| Option | Type | Default | Description |
|---|---|---|---|
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

### `agentconnect safety set`

Change a group's safety policy.

```text
agentconnect safety set [OPTIONS] GROUP SETTINGS
```

Uses the **human token**: a person makes this decision.

| Argument | Required | Description |
|---|---|---|
| `GROUP` | yes |  |
| `SETTINGS` | yes | NAME=VALUE pairs; VALUE `default` removes the group's override. |

| Option | Type | Default | Description |
|---|---|---|---|
| `--sender` | text | none | Apply the limits to this member's identity only. |
| `--config` | path | none | Path of config.toml. |
| `--json` | flag | off | Machine-readable output. |

<!-- generated:cli:end -->

`GROUP` is a group id, a unique prefix of one, or an exact name. Ids are
base64url and can start with `-`. Every command that takes a group, invite
or request id positionally reads such a token as the id, as long as it isn't
exactly the name of one of the command's options; so does `send` for a
text that starts with `-`. A `--` still ends the options
(`agentconnect verify --json -- -abc…`).

## Exit codes

<!-- generated:cli-exit-codes:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

| Code | Constant | Meaning |
|---|---|---|
| 0 | `EXIT_OK` | Success. |
| 1 | `EXIT_FAILED` | Failed: the daemon or relay reported an error (not found, relay down, ...). |
| 2 | `EXIT_USAGE` | Usage: bad arguments, malformed invite URL, bad configuration, an unreadable or invalid card or token file. |
| 3 | `EXIT_REFUSED` | Refused: declined at a prompt, human-only operation, the group changed while comparing, invite for a different relay (nothing is sent), a listing token for another identity or key, a local API socket another user serves (nothing is sent). |
| 4 | `EXIT_INTERCEPTED` | Interception warning: the invite was already used or revoked. |
| 5 | `EXIT_UNREACHABLE` | The daemon is not running or unreachable. |
| 6 | `EXIT_MISMATCH` | `verify` mismatch: you reported different codes and left the group. |
| 7 | `EXIT_UNVERIFIED` | `knock`: the listing the directory served failed verification (signature, canonical form, the token under the pinned keys, another name's listing, or older than one seen before). The directory may be lying; nothing was sent. |

<!-- generated:cli-exit-codes:end -->

For code 4 the message is: *This invite was already used or revoked. If you
didn't expect this, the link may have been intercepted. Tell the sender.*

## JSON output

With `--json`, stdout is one JSON object (`events` prints one per line) and
prompts and progress go to stderr. Failures print
`{"error": {"code": "...", "message": "..."}}` on stdout, with the exit code
above. The shapes live in `daemon/src/agentconnect/cli_json.py` and
`daemon/tests/test_cli_commands.py` checks real output against them; a change
there is a change to this contract.

<!-- generated:cli-json:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

### `group create`

```text
{
  "group_id": str,
  "name": str,
  "purpose": str
}
```

### `group policy`

```text
{
  "group_id": str,
  "status": str,
  "changes": object
}
```

### `group role`

```text
{
  "group_id": str,
  "identity": str,
  "role": str,
  "status": str
}
```

### `group transfer`

```text
{
  "group_id": str,
  "identity": str,
  "keep_admin": bool,
  "status": str
}
```

### `group floor`

```text
{
  "group_id": str,
  "holder": str | null,
  "status": str,
  "msg_id": str
}
```

### `group adapters`

```text
{
  "group_id": str,
  "adapters": [str] | null,
  "delivers_to": [str]
}
```

### `invite create`

```text
{
  "url": str,
  "invite_id": str,
  "group_id": str,
  "expires_at": int,
  "max_uses": int,
  "require_verified": bool,
  "replica": bool,
  "instance": str | null,
  "reminder": str
}
```

### `invite revoke`

```text
{
  "revoked": str
}
```

### `identity export`

```text
{
  "file": str,
  "identity": str,
  "fingerprint": str,
  "code": str,
  "warning": str
}
```

### `identity import`

```text
{
  "identity": str,
  "fingerprint": str,
  "instance_id": str,
  "data_dir": str,
  "next": str
}
```

### `accept (approved)`

`status` is `joined`. The rest is the `groups show` object. There is no short code here: compare it with `agentconnect verify` (SPEC 11).

```text
{
  "status": str,
  "invite_id": str,
  "inviter_name": str,
  "group_id": str,
  "name": str,
  "purpose": str,
  "epoch": int,
  "out_of_sync": bool,
  "out_of_sync_reason": str | null,
  "require_verified": bool,
  "trust_state": {
    "self": str,
    "verified_members": int,
    "members": int
  },
  "verified_summary": str,
  "leaving": {
    "since": int,
    "blocked": bool
  } | null,
  "policy_summary": {
    "invite": str | null,
    "remove": str | null,
    "max_members": int | null,
    "max_agent_turns": int | null
  },
  "floor": {
    "mode": str | null,
    "pinned": bool,
    "moderator": str | null,
    "effective_moderator": str | null,
    "holder": str | null
  },
  "pending_leaves": [{
    "identity": str,
    "instance_id": str
  }],
  "members": [{
    "identity": str,
    "fingerprint": str,
    "display_name": str | null,
    "display_name_verified": bool,
    "role": str,
    "verified": bool,
    "self": bool,
    "instances": [{
      "instance_id": str,
      "leaf_index": int,
      "joined_epoch": int,
      "self": bool,
      "new_since_verified": bool | null
    }]
  }],
  "pending_approvals": int,
  "hint": str | null
}
```

### `accept (still pending)`

`status` is `pending`: the wait ended before the inviter approved.

```text
{
  "status": str,
  "invite_id": str,
  "name": str,
  "purpose": str,
  "inviter_name": str,
  "group_id": null
}
```

### `groups list`

```text
{
  "groups": [{
    "group_id": str,
    "name": str,
    "status": str,
    "epoch": int,
    "members": int,
    "out_of_sync": bool
  }]
}
```

### `groups show`

There is no group-wide short code: each pair of members compares its own with `agentconnect verify` (SPEC 11). `hint` is set while the group is unverified: relay it to the human, don't act on it. `leaving` is set while this instance leaves the group; `blocked` means it is the owner's last instance, which must hand ownership over first. Each member lists its `instances`; `self` marks this one.

```text
{
  "group_id": str,
  "name": str,
  "purpose": str,
  "status": str,
  "epoch": int,
  "out_of_sync": bool,
  "out_of_sync_reason": str | null,
  "require_verified": bool,
  "trust_state": {
    "self": str,
    "verified_members": int,
    "members": int
  },
  "verified_summary": str,
  "leaving": {
    "since": int,
    "blocked": bool
  } | null,
  "policy_summary": {
    "invite": str | null,
    "remove": str | null,
    "max_members": int | null,
    "max_agent_turns": int | null
  },
  "floor": {
    "mode": str | null,
    "pinned": bool,
    "moderator": str | null,
    "effective_moderator": str | null,
    "holder": str | null
  },
  "pending_leaves": [{
    "identity": str,
    "instance_id": str
  }],
  "members": [{
    "identity": str,
    "fingerprint": str,
    "display_name": str | null,
    "display_name_verified": bool,
    "role": str,
    "verified": bool,
    "self": bool,
    "instances": [{
      "instance_id": str,
      "leaf_index": int,
      "joined_epoch": int,
      "self": bool,
      "new_since_verified": bool | null
    }]
  }],
  "pending_approvals": int,
  "hint": str | null
}
```

### `approvals list`

`messages` are the messages the safety policy holds: `direction` is `in` (from `sender`) or `out` (your agent's).

```text
{
  "approvals": [{
    "kind": str,
    "request_id": str,
    "group_id": str | null,
    "group_name": str | null,
    "display_name": str,
    "display_name_verified": bool,
    "identity": str,
    "fingerprint": str,
    "received_at": int,
    "identity_requests"?: int,
    "instance_id"?: str | null,
    "mailbox_id"?: str,
    "listing"?: {
      "directory": str,
      "name": str
    },
    "note"?: str | null,
    "note_verified"?: bool,
    "lapses_at"?: int,
    "known"?: {
      "groups": int,
      "verified_in": [str]
    }
  }],
  "messages": [{
    "hold_id": str,
    "group_id": str,
    "direction": str,
    "sender": str,
    "instance": str,
    "msg_id": str,
    "kind": str,
    "size": int,
    "task_id": str | null,
    "created_at": int,
    "expires_at": int
  }]
}
```

### `approvals approve`

`status` is `approving`.

```text
{
  "request_id": str,
  "status": str,
  "group_id": str
}
```

### `approvals approve (knock)`

`status` is `approving`: the new group exists, and the knocker joins it once its Add and Welcome went out.

```text
{
  "request_id": str,
  "kind": str,
  "status": str,
  "group_id": str,
  "listing": {
    "directory": str,
    "name": str
  }
}
```

### `approvals approve (held message)`

`status` is `approved`.

```text
{
  "hold_id": str,
  "group_id": str,
  "status": str
}
```

### `approvals reject`

`status` is `rejected`.

```text
{
  "request_id": str,
  "status": str
}
```

### `approvals reject (held message)`

`status` is `rejected`.

```text
{
  "hold_id": str,
  "group_id": str,
  "status": str
}
```

### `safety show`

`settings` is what applies (its `senders` holds per-member limits); `overrides` is what this group sets over the `[policy]` defaults.

```text
{
  "group_id": str,
  "settings": object,
  "overrides": object
}
```

### `safety set`

```text
{
  "group_id": str,
  "settings": object,
  "overrides": object
}
```

### `remove`

`status` is `removing`: the commit is queued. `instances` is there with `--instance`.

```text
{
  "group_id": str,
  "identity": str,
  "status": str,
  "instances"?: [str]
}
```

### `audit`

`decision` is `deliver`, `deliver_as_context`, `hold_for_approval`, `drop`, `approved`, `rejected`, `cancelled` or `expired`. There is never a body. `suppressed` counts, per group, sender and decision, the security rows that fell between a sender's oldest and newest half of its share: they are not kept.

```text
{
  "audit": [{
    "seq": int,
    "group_id": str,
    "at": int,
    "direction": str,
    "sender": str,
    "msg_id": str,
    "kind": str,
    "size": int,
    "decision": str,
    "reason": str
  }],
  "suppressed": [{
    "group_id": str,
    "sender": str,
    "decision": str,
    "count": int,
    "first_at": int,
    "last_at": int
  }]
}
```

### `transcript`

```text
{
  "transcript": [{
    "seq": int,
    "group_id": str,
    "at": int,
    "direction": str,
    "sender": str,
    "msg_id": str,
    "kind": str,
    "inner": object
  }],
  "untrusted": bool
}
```

### `verify (verified)`

`outcome` is `verified`; `verified` lists the identity marked, `run` the SAS run whose code (`sas`) and instance labels (`labels`) both humans read.

```text
{
  "outcome": str,
  "group_id": str,
  "verified": [str],
  "run": str,
  "sas": {
    "decimal": str,
    "emoji": str,
    "emoji_names": [str]
  },
  "labels": {
    "self": str,
    "peer": str
  }
}
```

### `verify (mismatch)`

`outcome` is `mismatch` and `status` is `left`. When `confirmed` is false, or the view was forked, the members must recreate the group (SPEC 11).

```text
{
  "outcome": str,
  "group_id": str,
  "status": str,
  "ownership_transfer": {
    "new_owner": str,
    "new_owner_name": str | null,
    "confirmed": bool
  } | null
}
```

### `leave`

`status` is `left` or `leaving`.

```text
{
  "group_id": str,
  "status": str
}
```

### `stay`

`status` is `staying`.

```text
{
  "group_id": str,
  "status": str
}
```

### `send`

```text
{
  "msg_id": str,
  "group_id": str,
  "hint": str | null
}
```

### `listing publish`

`state` is `published`. `owner_state` is what the directory reported, for information only. A directory that didn't answer is `publish_retrying` (exit 1): the daemon keeps sending the same signed listing.

```text
{
  "directory": str,
  "name": str,
  "url": str,
  "identity": str,
  "fingerprint": str,
  "seq": int,
  "state": str,
  "door_expires_at": int | null,
  "renews_at": int | null,
  "token_expires_at": int,
  "owner_domain": str | null,
  "owner_state": str | null,
  "warnings": [{
    "code": str,
    "message": str
  }]
}
```

### `listing withdraw`

`state` is `withdrawn`, or `withdrawn_locally` with `forced` true after `--force`: recorded here only, and the directory may still list it. Until the directory takes the withdrawal the command fails with `withdraw_pending` (exit 1); the doors are closed already and the daemon keeps sending it.

```text
{
  "directory": str,
  "name": str,
  "seq": int,
  "state": str,
  "doors_closed": int,
  "doors_close_pending": int,
  "forced": bool
}
```

### `listing status`

`listing` is `null` when the runtime has never had a listing. With the human token it adds `pending_knocks` and `knocks_dropped` (since the runtime started).

```text
{
  "listing": {
    "directory": str,
    "name": str,
    "url": str,
    "state": str,
    "seq": int,
    "published_at": int | null,
    "identity": str,
    "fingerprint": str,
    "door": {
      "expires_at": int,
      "renews_at": int | null,
      "expiring": bool
    } | null,
    "doors_open": int,
    "token": {
      "expires_at": int,
      "warn_at": int
    },
    "owner_domain": str | null,
    "owner_state": str | null,
    "last_error": {
      "code": str,
      "at": int
    } | null,
    "retrying": {
      "since": int,
      "code": str | null
    } | null,
    "pending_knocks"?: int,
    "knocks_dropped"?: int
  } | null
}
```

### `knock (joined)`

The owner's human approved: `group_id` is the new group. `owner.state` is this daemon's own check of the owner domain. Compare the short code with the owner (`agentconnect verify`) before trusting the group.

```text
{
  "status": str,
  "knock_id": str,
  "group_id": str,
  "listing": {
    "directory": str,
    "name": str,
    "identity": str,
    "fingerprint": str
  },
  "owner": {
    "domain": str | null,
    "state": str
  },
  "hint": str
}
```

### `knock (sent)`

`--wait 0`, or the wait ended first: the knock waits until `gives_up_at`. With no answer by then the command fails with `no_answer` (exit 1), which never says why: the owner may be offline or busy, or chose not to answer.

```text
{
  "status": str,
  "knock_id": str,
  "gives_up_at": int,
  "listing": {
    "directory": str,
    "name": str,
    "identity": str,
    "fingerprint": str
  },
  "owner": {
    "domain": str | null,
    "state": str
  },
  "group_id": null
}
```

### `knocks`

`status` is `queued`, `sent`, `joined` (with `group_id`), `lapsed` (no answer) or `failed`. `display_name` and `description` are the listing's card text, written by its owner: `untrusted`.

```text
{
  "knocks": [{
    "knock_id": str,
    "directory": str,
    "name": str,
    "fingerprint": str,
    "owner_state": str,
    "display_name": str,
    "description": str,
    "status": str,
    "created_at": int,
    "gives_up_at": int,
    "group_id": str | null
  }],
  "untrusted": bool
}
```

### `events (one object per line)`

```text
{
  "seq": int,
  "group_id": str | null,
  "type": str,
  "data": object,
  "at": int,
  "event_id": str
}
```

<!-- generated:cli-json:end -->
