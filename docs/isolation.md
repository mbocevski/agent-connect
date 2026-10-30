# Running the daemon as its own OS user

By default the daemon and its agents run as the same OS user. Code running
as that user can read every file the daemon can, including `human-token`
and the keys, so an agent with shell or file access can approve joins and
mark short codes verified in your name
([ADR-005](adr/005-deployment-modes.md#what-this-protects-against-and-what-it-doesnt)).

The separate-OS-user mode (`isolation.enabled = true`) closes that gap for
the separate daemon. The daemon runs as its own user, `agentconnect`. Agents
run as other users and reach only the agent-facing local API. They can't
read the human token, the keys or the data directory.

It is available for the separate daemon only. In the embedded SDK and
MCP-spawned modes the runtime runs inside the agent's own process, so there
is no user boundary to put between them.

## How it works

| Path | Owner | Mode | Holds |
|---|---|---|---|
| data directory (`/var/lib/agentconnect`) | `agentconnect` | 0700 | keys, both databases, `api-token`, `human-token`, `webhook-secret` (0600 each) |
| agent directory (`/run/agentconnect`) | `agentconnect:agentconnect` | 0750 | the API socket (0660), copies of `api-token` and `webhook-secret` (0640) |
| `/etc/agentconnect/config.toml` | `root:agentconnect` | 0640 | the configuration; no secrets |
| receiver directory (`/run/agentconnect-recv/<agent>`) | `<agent>:agentconnect-recv` | 2750 | the agent's webhook or A2A socket (0660) |

- **The socket is group-accessible.** Agents' users join the `agentconnect`
  group. The agent directory holds only agent-scope material: the human
  token is never copied there.
- **Every connection's peer UID is checked.** The daemon asks the kernel who
  is on the other end: `SO_PEERCRED` on Linux, `getpeereid(2)` on macOS and
  the BSDs (which reads `LOCAL_PEERCRED`). A UID that isn't the daemon's
  own, an `isolation.agent_users` entry or an `isolation.human_users` entry
  is logged (`api_peer_refused`, with the UID) and refused with
  `403 peer_refused` before the request is read. Group membership alone
  isn't enough: the user must be on the list.
- **One user can't crowd out another.** At most 8 connections per UID may
  be unfinished (their request line and headers not all in) before they
  give way: a user that opens more closes its own unfinished ones
  (`503 busy`), so an agent user can't open enough idle connections to
  keep the human's request out. A user may hold at most 16 event streams,
  so one agent user can't take all 48 of the agent token's requests in
  progress and leave another agent user's requests `503 busy`
  ([api.md](api.md#transport)).
- **Deliveries go only to the agents' users.** The webhook and A2A
  receivers are Unix sockets (`webhook.callback_socket`,
  `a2a.local_agent_socket`). Before the daemon writes a delivery, it checks
  that the socket's server runs as one of `isolation.agent_users`; another
  user's socket at that path gets nothing, and the delivery is retried
  (`webhook_receiver_refused`, `a2a_receiver_refused`, with both UIDs). A
  receiver on a port can't be checked, so the mode refuses one, and a
  receiver socket with no `isolation.agent_users` (nobody to deliver to)
  stops the start too. The receiver directory's permissions are defence in
  depth, not the boundary: its group, `agentconnect-recv`, has the
  daemon's user as its only member, so the daemon reaches each agent's
  socket and one agent user can't reach another's (they share
  `webhook-secret`, so one could otherwise post signed deliveries to
  another's handler).
- **The A2A facade is a socket too.** With the facade on, it must be on
  `a2a.facade_socket`, in the agent directory (so agents' users can reach
  it, and only the daemon's user can replace it); a `facade_port` or a
  socket elsewhere stops the start. The daemon closes a connection to
  it unless its user is the daemon's own or one of `isolation.agent_users`,
  before anything is read (`a2a_facade_peer_refused`, with the UID), so a
  user who isn't listed gets nothing even with the facade token
  ([adapters/a2a.md](adapters/a2a.md#facade-on-a-unix-socket)).
- **The human token is gated by UID as well.** A request that carries the
  human token is refused with `403 peer_refused` unless it comes from the
  daemon's own UID or an `isolation.human_users` entry. This is on top of the
  token, not instead of it: approve, reject, verify, SAS mismatch, turning
  `require_verified` off and the controls reserved to humans still need the
  human token, and the agent token is still refused there (`human_only`).
- **Loose permissions stop the start.** The daemon refuses to start (exit
  code 2, `refusing to start: ...`) when:
  - it runs as root;
  - the API is on TCP (`api.tcp_port`), where the peer's user can't be
    checked (TLS there authenticates the daemon to its clients, not the
    clients' users);
  - a webhook or local A2A agent is set without its socket
    (`webhook.callback_url` without `webhook.callback_socket`,
    `a2a.local_agent_url` without `a2a.local_agent_socket`), or the A2A
    facade is on a port (`a2a.facade_port`; use `a2a.facade_socket`) or
    its socket isn't in the agent directory;
  - the data directory isn't owned by the daemon's user with mode 0700, or a
    token or `webhook-secret` isn't a regular file owned by it with mode 0600;
  - the agent directory isn't owned by the daemon's user and
    `isolation.group`, gives others any access, gives the group write, or
    gives the group no access;
  - a directory above the agent directory (its real path) isn't owned by
    the daemon's user or root, or its group or others can write it and it
    isn't sticky: whoever can rename entries there could put their own
    agent directory in its place;
  - `api.socket` is outside the agent directory, or the agent and data
    directories contain each other;
  - a user is in both `agent_users` and `human_users`, or the daemon's own
    user is an agent user;
  - a user or group name doesn't exist.

## How the human reaches the human-only commands

The human runs the CLI **as the daemon's user**, with `sudo`:

```sh
sudo -u agentconnect agentconnect approvals --config /etc/agentconnect/config.toml
sudo -u agentconnect agentconnect approvals approve <request_id> --config /etc/agentconnect/config.toml
sudo -u agentconnect agentconnect verify <group> --config /etc/agentconnect/config.toml
sudo -u agentconnect agentconnect listing publish --directory directory.example.org \
  --card /etc/agentconnect/listing-card.json --token /etc/agentconnect/listing-token.json \
  --config /etc/agentconnect/config.toml
```

The CLI then reads `human-token` from the data directory and connects with
the daemon's UID, which passes both checks. `listing publish` reads the card
and token files as that user and sends their contents, so they must be
readable by it; the daemon never opens a path the caller names.

We chose this over a second, human-only socket:

- **One copy of the human token, readable by one user.** A human socket
  would need the human token, or a second credential, in a file the human's
  own account can read. If the agent runs as the human's login user, that
  file is readable by the agent again, which is the gap this mode exists to
  close.
- **The OS checks who the human is.** `sudo` asks for the human's password.
  An agent that can't authenticate to `sudo` can't switch to the daemon's
  user, whatever it runs.
- **No new daemon code path.** One listener, one route table, one place
  where the checks run.

The cost is a `sudo` rule and a longer command line. A shell alias
(`alias acadmin='sudo -u agentconnect agentconnect'`) shortens it.

Make sure the agent can't reuse your `sudo`:

- **Best: run the agent under a user of its own** (say `agent`) with no
  `sudo` rights. It joins the `agentconnect` group and is listed in
  `agent_users`. Your login user isn't in either list.
- **If the agent runs as your login user**, it can run `sudo` too. Require
  the password every time for the daemon's user, so the agent can't ride on
  a ticket you used a moment ago: `Defaults>agentconnect timestamp_timeout=0`
  in the sudoers drop-in. Don't give that user passwordless `sudo`.

Root can run `sudo agentconnect ... --config /etc/agentconnect/config.toml`
directly if you add `0` to `isolation.human_users`.

## Setup on Linux (systemd)

The files are in [`packaging/`](../packaging/).

1. Install `agentconnect` outside home directories, for example in
   `/opt/agentconnect` with a link at `/usr/bin/agentconnect`. The unit sets
   `ProtectHome=yes`, so the daemon can't run from a checkout in `~`.
2. Create the user and the directories:

   ```sh
   sudo install -m 0644 packaging/systemd/agentconnect.sysusers.conf /usr/lib/sysusers.d/agentconnect.conf
   sudo install -m 0644 packaging/systemd/agentconnect.tmpfiles.conf /usr/lib/tmpfiles.d/agentconnect.conf
   sudo systemd-sysusers
   sudo systemd-tmpfiles --create agentconnect.conf
   ```

3. Install the configuration and list the agents' users:

   ```sh
   sudo install -m 0640 -g agentconnect packaging/config.toml /etc/agentconnect/config.toml
   sudoedit /etc/agentconnect/config.toml   # agent_users = ["agent"]
   ```

4. Add each agent user to the group: `sudo usermod -aG agentconnect agent`.
   The user must log in again for the group to apply. For an agent that
   receives deliveries (webhook or A2A), add its receiver directory to the
   tmpfiles file (the commented line shows how), run
   `sudo systemd-tmpfiles --create agentconnect.conf` again, and point
   `webhook.callback_socket` or `a2a.local_agent_socket` at a socket in it.
   The directory is setgid `agentconnect-recv` (the sysusers file creates
   that group with the daemon's user as its only member; don't add agent
   users to it), so the agent's socket gets that group and only the daemon
   can connect. The daemon gets the group when it starts: after adding it to
   a running setup, restart the daemon
   (`sudo systemctl restart agentconnectd`). The SDK's receiver makes the
   socket 0660 when it reads `isolation.enabled` from the daemon's config
   (`AC_CONFIG=/etc/agentconnect/config.toml`); another server must do the
   same (for example `chmod 0660` after `uvicorn --uds`).
   Keep it out of `/tmp` and home directories: the unit gives the daemon a
   private `/tmp` and no homes.
5. Let the human run the CLI as the daemon's user. Edit
   `packaging/sudoers.d/agentconnect` (replace `alice`) and install it with
   `sudo visudo -f /etc/sudoers.d/agentconnect`.
6. Install and start the service:

   ```sh
   sudo install -m 0644 packaging/systemd/agentconnectd.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now agentconnectd
   journalctl -u agentconnectd    # api_listening, agent_dir_published
   ```

The unit runs `agentconnect daemon run` as `agentconnect` with
`AC_CONFIG=/etc/agentconnect/config.toml`, umask 0077,
`StateDirectory=agentconnect` (0700) and `RuntimeDirectory=agentconnect`
(0750). `/run/agentconnect` exists only while the service runs.

## Setup on macOS (launchd)

macOS has no sysusers, so create the user and group with `dscl`. Pick a free
ID below 500 (`450` here) and use the same paths as
[`packaging/launchd/`](../packaging/launchd/):

```sh
sudo dscl . -create /Groups/_agentconnect PrimaryGroupID 450
sudo dscl . -create /Users/_agentconnect UniqueID 450
sudo dscl . -create /Users/_agentconnect PrimaryGroupID 450
sudo dscl . -create /Users/_agentconnect UserShell /usr/bin/false
sudo dscl . -create /Users/_agentconnect NFSHomeDirectory /usr/local/var/agentconnect
sudo dseditgroup -o edit -a agent -t user _agentconnect
sudo install -d -m 0700 -o _agentconnect -g _agentconnect /usr/local/var/agentconnect
sudo install -d -m 0750 -o _agentconnect -g _agentconnect /usr/local/var/run/agentconnect
sudo install -d -m 0750 -o _agentconnect -g _agentconnect /usr/local/var/log/agentconnect
sudo install -d -m 0755 /usr/local/etc/agentconnect
sudo install -m 0640 -g _agentconnect packaging/config.toml /usr/local/etc/agentconnect/config.toml
```

In that `config.toml`, set `daemon.data_dir = "/usr/local/var/agentconnect"`,
`isolation.agent_dir = "/usr/local/var/run/agentconnect"` and
`isolation.group = "_agentconnect"`. The agent directory isn't under
`/var/run`, because macOS empties that at boot and the daemon's user can't
recreate it there. Every directory above it must be root's (or
`_agentconnect`'s): with Homebrew on an Intel Mac, `/usr/local/var` belongs
to your user, so pick a root-owned location instead, for example
`/Library/Application Support/agentconnect/run`. Then load the job:

```sh
sudo install -m 0644 packaging/launchd/network.yggdrasill.agentconnectd.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/network.yggdrasill.agentconnectd.plist
```

The human runs `sudo -u _agentconnect agentconnect ... --config
/usr/local/etc/agentconnect/config.toml`.

For an agent that receives deliveries, create a receiver group whose only
member is the daemon's user, once. Pick another free ID below 500 (`451`
here; `dscl . -list /Groups PrimaryGroupID` lists the ones in use), then
restart the daemon so it gets the group
(`sudo launchctl kickstart -k system/network.yggdrasill.agentconnectd`):

```sh
sudo dscl . -create /Groups/_agentconnect-recv PrimaryGroupID 451
sudo dseditgroup -o edit -a _agentconnect -t user _agentconnect-recv
sudo install -d -m 0755 /usr/local/var/run/agentconnect-recv
```

Then create the agent's receiver directory with the agent's user, that
group and the setgid bit, for example
`sudo install -d -m 2750 -o agent -g _agentconnect-recv /usr/local/var/run/agentconnect-recv/agent`,
and point `webhook.callback_socket` or `a2a.local_agent_socket` at a
socket in it. Don't add agent users to `_agentconnect-recv`.

## Agents

Agents use the agent directory as their data directory:

```sh
AC_DATA_DIR=/run/agentconnect agentconnect status
```

The Python SDK takes the same directory:
`AgentConnect(data_dir=Path("/run/agentconnect"))`, or `AC_DATA_DIR` in the
agent's environment. The webhook adapter's `webhook-secret` is copied there
too, so the SDK's receiver can check signatures. A human-only command run
as an agent user fails: the agent directory has no human token, the agent
token gets `human_only`, and the human token, should an agent get hold of
it, gets `peer_refused` from any user but the daemon's and the
`human_users`.

Agents check the daemon too. Before sending the token, the CLI, the SDK and
`agentconnect mcp` check that the socket's server runs as the owner of the
directory the token came from: `agentconnect` for the agent directory, and
for the human's `sudo -u agentconnect` commands, the data directory. A
socket that another user serves is refused with `peer_mismatch` and gets
nothing ([api.md](api.md#transport)). By design that leaves out the
daemon's user, whose socket is accepted, and root: both can read the
token anyway.

## What it doesn't cover

- **Root and the daemon's user.** Root can read everything; so can code that
  runs as `agentconnect`. Don't add tools or plugins to the daemon that run
  agent-supplied code.
- **Agent-scope operations.** Every listed agent user holds `api-token` and
  can do everything the agent token allows in every group of this daemon
  (ADR-005, Decision 5). Run one daemon, with its own user and agent
  directory, per set of agents that shouldn't share groups.
- **The human's account.** If the agent runs as your login user and can use
  your `sudo`, it can become the daemon's user. See the `sudo` advice above.
- **TCP.** The mode needs the Unix socket.

## Tests

The fast tier injects the peer's credentials, so it needs no second OS user
(`daemon/tests/test_isolation.py`, `harness/tests/test_isolation_api.py`).
A test with a real second user runs as root, behind a marker:

```sh
sudo AC_RUN_MULTIUSER=1 uv run --all-packages pytest -m multiuser
```
