# The `agentconnect` CLI

The CLI is a thin client of the daemon's local API (`daemon/README.md`). It
parses arguments, calls the daemon and renders the answer; all protocol
decisions are made by the daemon. Every command takes `--config PATH` and
`--json`.

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

Bob's `accept` then prints the group's short code. Both humans compare it
over a call or in person, not over the channel that carried the invite, and
each runs:

```sh
agentconnect verify <group>     # "Do the other members see exactly this code? [y/N]"
```

## Human and agent separation

The daemon has two tokens (`api-token`, `human-token`, both 0600 in the data
directory). `approvals approve`, `approvals reject` and `verify` (including
its mismatch path) use the **human token**. They are decisions a person
makes (SPEC 6.2, 11): an agent that could approve joins or mark the code as
compared would remove the checks that catch a stolen link or a forking
relay.

- Never give an agent the human token, and never let an agent run those
  commands for the human.
- `verify` is interactive on purpose. It has no `--yes`, and EOF on stdin
  counts as "no answer" (exit 3, nothing changed).
- Everything else uses the api token and is fine for agents. When an LLM agent
  runs `accept`, the invite secret enters its context (SPEC 4.4). That is
  acceptable only because invites are use-limited.
- Agent-facing JSON carries a `hint` while the group is unverified:
  `"ask your human to compare the short code 1234-5678-9012 with the other
  members"`. Relay it to the human; don't act on it.

Names, purposes and inviter names come from peers or the link and are not
authenticated. Human output strips control characters from them; JSON output
returns them as sent.

## Commands

| Command | Token | What it does |
|---|---|---|
| `group create --purpose TEXT [--name N]` | api | Create a group you own. |
| `invite create [--group ID] [--purpose TEXT] [--ttl 24h] [--max-uses 1] [--require-verified]` | api | Print an invite URL and the sharing reminder. Without `--group`, creates the group first. `--ttl` is `30m`, `24h`, `7d` (max 7d). `--require-verified` holds deliveries until every member is verified (SPEC 10.4). |
| `invite revoke INVITE_ID` | api | Revoke an invite. |
| `accept URL [--yes] [--name N] [--wait SECS]` | api | Inspect, show group, purpose, inviter and member count (all claimed by the link), confirm, send the join request, wait up to `--wait` seconds (default 120, 0 = don't) for approval, then print the short code. `--json` needs `--yes`. |
| `groups [list]` | api | List groups. |
| `groups show GROUP` | api | Members, roles, instances, verified flags, "N of M verified", the short code, `out_of_sync`, pending approvals. |
| `approvals [list]` | api | Pending join requests: claimed name, fingerprint, group and its current code. |
| `approvals approve ID [--yes]` | **human** | Approve a request (asks first). |
| `approvals reject ID` | **human** | Reject a request. |
| `verify GROUP` | **human** | Compare codes. `y` marks every other member verified; `N` reports a mismatch: the daemon leaves the group and the result includes the owner hand-over. |
| `leave GROUP` | api | Leave. The owner's last instance must hand over ownership first. |
| `send GROUP TEXT [--to IDENTITY]...` | api | Send a text message as the agent (for manual testing). |
| `events [--follow] [--after N]` | api | Print daemon events; with `--json`, one object per line. |
| `status`, `version`, `daemon run` | api | Daemon status, versions, run the daemon. |

`GROUP` is a group id, a unique prefix of one, or an exact name. Ids are
base64url and can start with `-`; put such an id after `--`
(`agentconnect verify --json -- -abc…`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failed: the daemon or relay reported an error (not found, relay down, ...). |
| 2 | Usage: bad arguments, malformed invite URL, bad configuration. |
| 3 | Refused: declined at a prompt, human-only operation, the group changed while comparing, invite for a different relay (nothing is sent). |
| 4 | Interception warning: the invite was already used or revoked. |
| 5 | The daemon is not running or unreachable. |
| 6 | `verify` mismatch: you reported different codes and left the group. |

For code 4 the message is: *This invite was already used or revoked. If you
didn't expect this, the link may have been intercepted. Tell the sender.*

## JSON output

With `--json`, stdout is one JSON object (`events` prints one per line) and
prompts and progress go to stderr. Failures print
`{"error": {"code": "...", "message": "..."}}` on stdout, with the exit code
above. The shapes are fixed by `daemon/tests/test_cli_commands.py`; a change
there is a change to this contract.

`group create`: `{group_id, name, purpose}`

`invite create`: `{url, invite_id, group_id, expires_at, max_uses,
require_verified, reminder}`

`invite revoke`: `{revoked}`

`accept`, when approved: `{status: "joined", invite_id, inviter_name, ...
the groups show object}`. When the wait ends first: `{status: "pending",
invite_id, name, purpose, inviter_name, group_id: null}`.

`groups list`: `{groups: [{group_id, name, status, epoch, members,
out_of_sync}]}`

`groups show` (also embedded in `accept`):

```text
{group_id, name, purpose, status, epoch, out_of_sync, out_of_sync_reason,
 require_verified,
 trust_state: {self: "verified"|"unverified", verified_members, members},
 verified_summary: "N of M verified",
 sas: {decimal, emoji, emoji_names: [..]} | null,
 members: [{identity, fingerprint, display_name, display_name_verified, role,
            verified, self, instances}],
 pending_approvals, hint: string | null}
```

`approvals list`: `{approvals: [{request_id, group_id, group_name,
display_name, display_name_verified, identity, fingerprint, received_at,
group_sas}]}`. `group_sas` is the group's code now; it changes once the
joiner is added.

`approvals approve`: `{request_id, status: "approving", group_id}`;
`approvals reject`: `{request_id, status: "rejected"}`

`verify`: `{outcome: "verified", group_id, verified: [identity]}`, or on
mismatch `{outcome: "mismatch", group_id, status: "left",
ownership_transfer: null | {new_owner, new_owner_name, confirmed}}`. After a
mismatch where `confirmed` is false, or the view was forked, the members must
recreate the group (SPEC 11).

`leave`: `{group_id, status: "left"|"leaving"}`

`send`: `{msg_id, group_id, hint}`

`events`: `{seq, group_id, type, data, at}`
