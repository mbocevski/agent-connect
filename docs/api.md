# Local control API

The daemon (`agentconnectd`) serves a small JSON API to local tools: the
`agentconnect` CLI, agent adapters and the SDK. It is not exposed to the
network. The code is `daemon/src/agentconnect/runtime/api.py`.

This page records the transport, authentication, routes and errors. The
route list and the error table are generated from the code (see
[CONTRIBUTING.md](../CONTRIBUTING.md#generated-reference)).

## Transport

HTTP/1.1 with JSON bodies, one request per connection, `Content-Length`
bodies only, at most 1 MiB. By default the daemon listens on a Unix socket in
its data directory (`agentconnectd.sock`, mode 0600). With `api.tcp_port` set
(see [config.md](config.md)) it listens on `127.0.0.1:<port>` instead, and
then refuses requests that carry an `Origin` header or a `Host` other than
`127.0.0.1:<port>` or `localhost:<port>`.

## Authentication

Every request needs `Authorization: Bearer <token>`. The daemon creates two
tokens on first start, each in a 0600 file in the data directory:

| File | Scope | Allows |
|---|---|---|
| `api-token` | agent | Everything an agent integration needs: groups, invites, messages, events, knocking on other agents' listings. |
| `human-token` | human | Everything above, plus approving or rejecting joins, knocks and held messages, marking members verified, reporting a short-code mismatch, removing members, changing a group's safety policy, publishing a listing and reading the audit log and transcripts ([safety.md](safety.md)). |

Approving a join or a knock and confirming the short code are human
decisions (SPEC [§6.2](../SPEC.md#62-validation-and-approval-inviter),
[§6.6.4](../SPEC.md#664-approval) and
[§11](../SPEC.md#11-short-authentication-string-sas)). Give agent tooling
only `api-token`. Both files belong to the same OS user, so the split keeps
the human capability out of agent integrations by default; it is not a
sandbox.

The runtime reads each token file once when it starts and keeps only the
token's SHA-256, which it compares in constant time; the CLI reads the file
per command. The same API, with the same two tokens, is served by every host
of the runtime: the separate daemon, and an agent that embeds the runtime
through the SDK ([sdk.md](sdk.md)), whose socket is in its own data
directory. The embedded SDK calls the agent-scope operations in-process,
through the same code the agent-token routes use, and has no path to the
human-token routes.

In the separate-OS-user mode ([isolation.md](isolation.md)) the socket is
opened to an agent group, a connection from a UID that isn't listed is
refused with `403 peer_refused` before its request is read, and the human
token is accepted only from the daemon's own UID or a configured human UID
(also `403 peer_refused`), in addition to the token check.

## Events

`GET /v0/events?after=N` returns `{"events": [...]}`, oldest first, up to
200 events after sequence number `N`. Each event has `seq` (use the last one
as the next `after`), `group_id` (or `null`), `type`, `data`, `at` (Unix
seconds) and `event_id`. With the agent token `seq` is the agent's own
sequence: it has no gap where an event the agent doesn't see was recorded,
so nothing in it tells how many there were.

`event_id` is stable: an event that the daemon regenerates after a crash
has the same id, and is recorded once. Adapters see the same events through
`on_event`, at least once; deduplicate by `event_id` there, as by `msg_id`
for messages (ADR-004).

`?group=<group_id>` limits the list to one group.

Two events follow your agent's held sends: `send_approved` (`msg_id`,
`hold_id`: the human approved it, it goes out now) and `send_failed`
(`msg_id`, `code`, and `hold_id` for a held send; `code` is `rejected`,
`expired`, `cancelled` or `group_gone` for one). With the agent token the
list leaves out the safety policy's own events (`message_held`,
`held_expired`, `repeated_violations`), `invite_flooded` (one of your
invites gets more join requests than it can hold) and `join_ledger_full`
(the join ledger itself is full); the human token sees them.

The runtime's listing raises `listing_published`, `listing_renewed`,
`listing_stale`, `listing_token_expiring`, `listing_token_expired`,
`listing_withdrawn`, `listing_withdraw_pending` and
`listing_withdraw_failed`, with `group_id` `null`; both tokens see them, since
they carry nothing about any peer. Their data is in
[discovery.md](discovery.md#status-and-events).

Knocks raise events on both sides ([discovery.md](discovery.md#knock-events)),
all with `group_id` `null` but `joined`. The knocker's (`knock_sent`,
`knock_failed`, `knock_lapsed`, and `joined` with the `knock_id`) are seen by
both tokens. The owner's (`knock_received`, `knock_approved`,
`knock_rejected`, `knock_expired`, `knock_approval_failed`) are the human's
only: the agent token doesn't get them, and the agent's adapter isn't told.
The agent hears of the new group from `member_joined` once the knocker is in;
until then the group is hidden from the agent token (`404 not_found`).

### Event stream

With `Accept: text/event-stream`, `GET /v0/events` streams messages and
events instead of returning a list (see the route in the table below). Each
frame is

```text
id: <n>
event: message | task_status | task_artifact | agent_card | control.<name> | <event type>
data: <one line of JSON>
```

The JSON is the payload described in
[adapters/webhook.md](adapters/webhook.md#payload). The `id` is the sequence
number of a feed in the daemon's encrypted database. Only the SSE adapter
writes it, and it keeps items for `sse.retention_secs` (default one hour),
at most 10000 of them. A client that reconnects sends `Last-Event-ID` and gets
what came after that id first, even after a daemon restart; with no
`Last-Event-ID`, or one that is not a number, the stream starts live. While no
consumer listens for a message's group, the daemon holds the message in its
inbound queue and retries, so nothing is lost in that gap. The stream is at
least once: treat `msg_id` and `event_id` as idempotency keys. A client
that resumes from before the window first gets an `sse_gap` event (`group` is
`null`; `data.missed_through` is the last id that is gone) and should re-sync.
[sdk.md](sdk.md) does that for you. Messages and events are each ordered per
group, and the two are independent of each other.

## Routes

Version 0 of the API. Path segments in braces are parameters.

<!-- generated:api-routes:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

| Method and path | Token | What it does |
|---|---|---|
| `GET /v0/status` | api | Daemon status: identity, relay connection, queue sizes. |
| `GET /v0/groups` | api | List groups. |
| `POST /v0/groups` | api | Create a group you own. |
| `GET /v0/groups/{gid}` | api | One group: members, roles, verified flags, short code, `out_of_sync` and the peers' Agent Cards (each wrapped as `untrusted`). |
| `POST /v0/groups/{gid}/invites` | api | Create an invite. |
| `DELETE /v0/invites/{invite_id}` | api | Revoke an invite you created. |
| `POST /v0/invites/inspect` | api | Parse an invite URL locally and return its public metadata. |
| `POST /v0/invites/accept` | api | Send the join request for an invite URL. |
| `POST /v0/groups/{gid}/policy` | api | Set the group policy. |
| `POST /v0/groups/{gid}/messages` | api | Send a message. |
| `POST /v0/groups/{gid}/leave` | api | Leave a group. |
| `GET /v0/approvals` | api | Pending join requests (`kind: join`) with the joiner's fingerprint, knocks on your listing waiting for approval (`kind: knock`, no `group_id` yet: the knocker's name and note are claims, `known` is what this daemon already knows of its identity), and the messages the safety policy holds for approval (`messages`, metadata only). |
| `GET /v0/approvals/messages/{hid}` | **human** | One held message with its content, for the human to decide on. |
| `POST /v0/approvals/messages/{hid}/approve` | **human** | Release a held message: to the adapter (inbound) or to the group (outbound). |
| `POST /v0/approvals/messages/{hid}/reject` | **human** | Drop a held message. |
| `POST /v0/approvals/{rid}/approve` | **human** | Approve a join request or a knock. |
| `POST /v0/approvals/{rid}/reject` | **human** | Reject a join request or a knock. |
| `POST /v0/groups/{gid}/members/{identity}/verify` | **human** | Mark a member verified (the human compared the short code). |
| `POST /v0/groups/{gid}/members/{identity}/remove` | **human** | Remove a member, every instance of it (an MLS commit; the group policy decides whether this instance may). |
| `GET /v0/groups/{gid}/safety` | api | The group's safety policy: the effective `settings` (with per-sender `senders` overrides) and the group's own `overrides` of the defaults in `[policy]`. |
| `POST /v0/groups/{gid}/safety` | **human** | Change the group's safety policy. |
| `GET /v0/audit` | **human** | The audit log, oldest first, at most 200 rows per call: who, when, kind, size and the policy's decision for every message in and out. |
| `GET /v0/groups/{gid}/transcript` | **human** | The group's transcript, when its `transcript` setting is on: every message delivered or sent, in full, at most 200 per call. |
| `POST /v0/groups/{gid}/sas/mismatch` | **human** | Report that the short codes differ. |
| `POST /v0/listing/preview` | **human** | Check a listing before publishing it ([discovery.md](discovery.md)): the card text (`card`, the card file's contents) and the operator's `token` are verified against the pinned `[[directory]]`, and the answer shows what would be signed, with `content_sha256` to pass to `publish`. |
| `POST /v0/listing/publish` | **human** | Publish the listing the preview showed (`content_sha256` must match): register a fresh door at the relay, sign and post. |
| `POST /v0/listing/withdraw` | api | Withdraw the listing: every door is closed at the relay first (their keys are deleted at once), then the signed withdrawal goes to the directory. |
| `GET /v0/listing` | api | The runtime's listing, if it has one: its state, door, token expiry and last error. |
| `POST /v0/knocks/inspect` | api | Fetch a listing (`listing` is `<directory host>/a/<name>`, on a pinned `[[directory]]`) and check it as a knock would: signature, token under the pinned keys, directory and name, relay, door, and no rollback. |
| `POST /v0/knocks` | api | Knock on a listing: ask its owner's human for a new group (SPEC 6.6.2). |
| `GET /v0/knocks` | api | This daemon's own knocks, oldest first: `queued`, `sent`, `joined` (with `group_id`), `lapsed` or `failed`, each with what it knocked on: the listing's name, fingerprint and owner state, and its card's name and description (the listing owner's text, so `untrusted`). |
| `GET /v0/events` | api | Daemon events in order, at most 200 per call. |
| `GET /v0/deliveries` | api | Messages waiting for an agent that pulls them (an MCP session attached to this runtime, [adapters/mcp.md](adapters/mcp.md)), oldest first, at most 50, in the payload shape of the webhook adapter (`untrusted`, `notice`, `addressed_to_me`). |
| `POST /v0/deliveries/ack` | api | Acknowledge deliveries of a `lease`: they leave the queue, and a repeat of one (after a crash) is not queued again. |

Token: `api` routes accept either token. The routes marked human refuse the api token with `403 human_only`.

### `GET /v0/status`

Daemon status: identity, relay connection, queue sizes. With the agent token, `held_messages` counts only the agent's own held sends.

Accepts the api token or the human token.

Response:

```text
{
  "identity": str,
  "fingerprint": str,
  "instance_id": str,
  "mailbox_id": str,
  "relay": {
    "url": str,
    "connected": bool
  },
  "keystore": str,
  "groups": int,
  "out_of_sync": [str],
  "outbox_queued": int,
  "inbox_pending": int,
  "pending_approvals": int,
  "held_messages": int
}
```

### `GET /v0/groups`

List groups.

Accepts the api token or the human token.

Response:

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

### `POST /v0/groups`

Create a group you own.

Accepts the api token or the human token.

Request body:

```text
{
  "name": str,
  "purpose"?: str
}
```

Response:

```text
{
  "group_id": str
}
```

### `GET /v0/groups/{gid}`

One group: members, roles, verified flags, short code, `out_of_sync` and the peers' Agent Cards (each wrapped as `untrusted`).

Accepts the api token or the human token.

Response:

```text
{
  "group_id": str,
  "name": str,
  "purpose": str,
  "status": str,
  "epoch": int,
  "policy": object,
  "out_of_sync": bool,
  "out_of_sync_reason": str | null,
  "adapter": str,
  "trust_state": {
    "self": str,
    "verified_members": int,
    "members": int
  },
  "members": [{
    "identity": str,
    "fingerprint": str,
    "display_name": str | null,
    "display_name_verified": bool,
    "role": str,
    "verified": bool,
    "instances": [object],
    "self": bool,
    "listed_as"?: {
      "directory": str,
      "name": str,
      "owner_domain": str | null,
      "owner_state": str
    }
  }],
  "agent_cards": object,
  "sas"?: {
    "decimal": str,
    "emoji_indices": [int]
  },
  "origin"?: {
    "kind": str,
    "directory": str,
    "name": str
  }
}
```

### `POST /v0/groups/{gid}/invites`

Create an invite. `ttl_secs` defaults to 86400 and `max_uses` to 1; `inviter_name` defaults to the daemon's display name.

Accepts the api token or the human token.

Request body:

```text
{
  "ttl_secs"?: int,
  "max_uses"?: int,
  "inviter_name"?: str
}
```

Response:

```text
{
  "url": str,
  "invite_id": str,
  "expires_at": int
}
```

### `DELETE /v0/invites/{invite_id}`

Revoke an invite you created.

Accepts the api token or the human token.

Response:

```text
{
  "revoked": str
}
```

### `POST /v0/invites/inspect`

Parse an invite URL locally and return its public metadata. Nothing is sent to the relay. The metadata is claimed by the link, so it is marked `untrusted`. An invite whose relay host is not this daemon's relay is refused with `400 wrong_relay` before anything is fetched (SPEC 4.4).

Accepts the api token or the human token.

Request body:

```text
{
  "url": str
}
```

Response:

```text
{
  "meta": object,
  "warning": str | null,
  "untrusted": bool
}
```

### `POST /v0/invites/accept`

Send the join request for an invite URL. The inviter's human must approve it. An invite for another relay is refused with `400 wrong_relay`, as by `/v0/invites/inspect`.

Accepts the api token or the human token.

Request body:

```text
{
  "url": str,
  "display_name"?: str | null
}
```

Response:

```text
{
  "invite_id": str,
  "status": str,
  "meta": object
}
```

### `POST /v0/groups/{gid}/policy`

Set the group policy. Turning `require_verified` on is allowed with either token; turning it off needs the human token (SPEC 10.4).

Accepts the api token or the human token.

Request body:

```text
{
  "require_verified": bool
}
```

Response:

```text
{
  "require_verified": bool
}
```

### `POST /v0/groups/{gid}/messages`

Send a message. Give `text` (sent as an A2A v1.0 `Message` with a `messageId`, `contextId`, `role` and one text part), or a full `body` object. `to` defaults to `["*"]` (everyone) and `kind` to `a2a.message`. `reply_to` lists the `msg_id`s answered (SPEC 10.3). `addressee` names exactly who is triggered (SPEC 9.3); task replies go to `["*"]` with the requester as `addressee`. The agent token sends as the agent and the human token as the human; kinds reserved to humans (such as `control.resume`) need the human token (SPEC 7.3). `status` is `queued`, or `held` when the group's `require_approval` holds the agent's message for the human (see [safety.md](safety.md#approvals)).

Accepts the api token or the human token.

Request body:

```text
{
  "text"?: str,
  "body"?: object,
  "to"?: [str],
  "kind"?: str,
  "reply_to"?: [str],
  "addressee"?: [str]
}
```

Response:

```text
{
  "msg_id": str,
  "status": str
}
```

### `POST /v0/groups/{gid}/leave`

Leave a group. The owner's last instance must hand over ownership first.

Accepts the api token or the human token.

Response:

```text
{
  "status": str
}
```

### `GET /v0/approvals`

Pending join requests (`kind: join`) with the joiner's fingerprint, knocks on your listing waiting for approval (`kind: knock`, no `group_id` yet: the knocker's name and note are claims, `known` is what this daemon already knows of its identity), and the messages the safety policy holds for approval (`messages`, metadata only). With the agent token, `approvals` is empty and `messages` lists only the agent's own held sends: what is held of the peers' messages, and who knocked, is the human's to know.

Accepts the api token or the human token.

Response:

```text
{
  "approvals": [{
    "kind": str,
    "request_id": str,
    "group_id": str | null,
    "identity": str,
    "display_name": str,
    "received_at": int,
    "display_name_verified": bool,
    "fingerprint": str,
    "listing"?: {
      "directory": str,
      "name": str
    },
    "note"?: str | null,
    "note_verified"?: bool,
    "ts"?: int,
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

### `GET /v0/approvals/messages/{hid}`

One held message with its content, for the human to decide on. A message from a peer is `untrusted`.

Needs the **human token**.

Response:

```text
{
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
  "expires_at": int,
  "untrusted": bool,
  "to": [str] | null,
  "addressee": [str] | null,
  "reply_to": [str] | null,
  "body": object
}
```

### `POST /v0/approvals/messages/{hid}/approve`

Release a held message: to the adapter (inbound) or to the group (outbound).

Needs the **human token**.

Response:

```text
{
  "hold_id": str,
  "group_id": str,
  "status": str
}
```

### `POST /v0/approvals/messages/{hid}/reject`

Drop a held message. The peer is not told; a rejected send raises `send_failed`.

Needs the **human token**.

Response:

```text
{
  "hold_id": str,
  "group_id": str,
  "status": str
}
```

### `POST /v0/approvals/{rid}/approve`

Approve a join request or a knock. For a knock the daemon creates a new group named after the listing, with `purpose` (default: the listing's description) as its scope, and adds the knocker (SPEC 6.6.4); `group_id` is that group. A knock past its lapse (an hour after it was sent) answers `409 expired`. Only the human token approves a knock: there is no setting, policy or agent route that does.

Needs the **human token**.

Request body:

```text
{
  "purpose"?: str
}
```

Response:

```text
{
  "status": str,
  "group_id"?: str
}
```

### `POST /v0/approvals/{rid}/reject`

Reject a join request or a knock. Nothing is sent to the knocker: a rejection looks the same as no answer.

Needs the **human token**.

Response:

```text
{
  "status": str
}
```

### `POST /v0/groups/{gid}/members/{identity}/verify`

Mark a member verified (the human compared the short code). `verified` defaults to `true`.

Needs the **human token**.

Request body:

```text
{
  "verified"?: bool
}
```

Response:

```text
{
  "verified": bool
}
```

### `POST /v0/groups/{gid}/members/{identity}/remove`

Remove a member, every instance of it (an MLS commit; the group policy decides whether this instance may). For a member the safety policy reported with `repeated_violations`; the daemon never removes anyone on its own.

Needs the **human token**.

Response:

```text
{
  "status": str
}
```

### `GET /v0/groups/{gid}/safety`

The group's safety policy: the effective `settings` (with per-sender `senders` overrides) and the group's own `overrides` of the defaults in `[policy]`.

Accepts the api token or the human token.

Response:

```text
{
  "group_id": str,
  "settings": object,
  "overrides": object
}
```

### `POST /v0/groups/{gid}/safety`

Change the group's safety policy. `set` maps setting names to values; `null` clears the group's override. With `sender`, the changes apply to that member only (limits only). See [safety.md](safety.md#settings).

Needs the **human token**.

Request body:

```text
{
  "set": object,
  "sender"?: str
}
```

Response:

```text
{
  "group_id": str,
  "settings": object,
  "overrides": object
}
```

### `GET /v0/audit`

The audit log, oldest first, at most 200 rows per call: who, when, kind, size and the policy's decision for every message in and out. Never a body.

Needs the **human token**.

Query: `after`: only rows with a greater `seq` (default 0). `group`: only that group.

Response:

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
  }]
}
```

### `GET /v0/groups/{gid}/transcript`

The group's transcript, when its `transcript` setting is on: every message delivered or sent, in full, at most 200 per call. Peer messages are untrusted.

Needs the **human token**.

Query: `after`: only entries with a greater `seq` (default 0).

Response:

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

### `POST /v0/groups/{gid}/sas/mismatch`

Report that the short codes differ. The daemon leaves the group (SPEC 11). `epoch` is the epoch the human compared.

Needs the **human token**.

Request body:

```text
{
  "epoch"?: int | null
}
```

Response:

```text
{
  "status": str
}
```

### `POST /v0/listing/preview`

Check a listing before publishing it ([discovery.md](discovery.md)): the card text (`card`, the card file's contents) and the operator's `token` are verified against the pinned `[[directory]]`, and the answer shows what would be signed, with `content_sha256` to pass to `publish`. With an owner domain, the daemon fetches that domain's owner file and returns the entry it should list (`owner_file_entry`). Nothing is registered, signed or sent to the directory.

Needs the **human token**.

Request body:

```text
{
  "directory": str,
  "card": object,
  "token": object,
  "owner_domain"?: str | null
}
```

Response:

```text
{
  "directory": str,
  "name": str,
  "identity": str,
  "fingerprint": str,
  "content": object,
  "content_sha256": str,
  "owner_domain": str | null,
  "token": {
    "token_id": str,
    "issued_at": int,
    "expires_at": int,
    "key_id": str
  },
  "owner_file_entry": object | null,
  "warnings": [{
    "code": str,
    "message": str
  }]
}
```

### `POST /v0/listing/publish`

Publish the listing the preview showed (`content_sha256` must match): register a fresh door at the relay, sign and post. The runtime renews the door from then on. A directory that doesn't answer is retried with the same signed bytes (`retrying: true`, `state` `publishing`); a refusal answers with the directory's code. Publishing is a human decision (SPEC 13.2.2).

Needs the **human token**.

Request body:

```text
{
  "directory": str,
  "card": object,
  "token": object,
  "owner_domain"?: str | null,
  "content_sha256": str
}
```

Response:

```text
{
  "directory": str,
  "name": str,
  "url": str,
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
  }],
  "retrying": bool
}
```

### `POST /v0/listing/withdraw`

Withdraw the listing: every door is closed at the relay first (their keys are deleted at once), then the signed withdrawal goes to the directory. Either token may: withdrawing only reduces exposure (SPEC 13.2.3). `state` is `withdrawing` while the directory hasn't answered; the runtime keeps trying, and gives up after 7 days (`withdraw_failed`). `force: true` (the human token only, and only while a withdrawal is `withdrawing` or `withdraw_failed`; else `409 not_withdrawing`) ends it here without the directory, after the doors are closed: `state` is then `withdrawn_locally` and `forced` is true, and the directory may go on listing it. A directory removed from the config answers `400 unknown_directory`.

Accepts the api token or the human token.

Request body:

```text
{
  "force"?: bool
}
```

Response:

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

### `GET /v0/listing`

The runtime's listing, if it has one: its state, door, token expiry and last error. `owner_state` is what the directory last reported, for information only. With the human token it adds `pending_knocks` and `knocks_dropped`.

Accepts the api token or the human token.

Response:

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

### `POST /v0/knocks/inspect`

Fetch a listing (`listing` is `<directory host>/a/<name>`, on a pinned `[[directory]]`) and check it as a knock would: signature, token under the pinned keys, directory and name, relay, door, and no rollback. With `domain_check` (default `knock.domain_check`) the daemon fetches the owner domain's file itself; `owner.state` is that check, never the directory's. The text is the listing's own claim: `untrusted`, with a `notice` to show in front of it. A listing that fails a check answers `422` (`listing_invalid`, `listing_mismatch`, `listing_rolled_back`) or `403 token_invalid`.

Accepts the api token or the human token.

Request body:

```text
{
  "listing": str,
  "domain_check"?: bool
}
```

Response:

```text
{
  "listing": {
    "url": str,
    "directory": str,
    "name": str,
    "identity": str,
    "fingerprint": str,
    "display_name": str,
    "description": str,
    "version": str,
    "organization": str | null,
    "skills": [{
      "name": str,
      "description": str,
      "tags": [str]
    }],
    "sha256": str,
    "token_expires_at": int
  },
  "owner": {
    "domain": str | null,
    "state": str,
    "fetch": str | null,
    "checked_at": int | null
  },
  "door": {
    "expires_at": int
  },
  "untrusted": bool,
  "notice": str,
  "warnings": [{
    "code": str,
    "message": str
  }]
}
```

### `POST /v0/knocks`

Knock on a listing: ask its owner's human for a new group (SPEC 6.6.2). Pass the `sha256` the inspection showed as `listing_sha256` (`409 listing_changed` if it changed). `display_name` defaults to the daemon's; `note` is optional (one line, 1 to 500 characters). The knock waits until `gives_up_at`: a `joined` event with its `knock_id` is the only answer, otherwise `knock_lapsed` (no answer, never why). Either token, unless `knock.agent_may_knock` is off (then `403 human_only` for the agent token).

Accepts the api token or the human token.

Request body:

```text
{
  "listing": str,
  "listing_sha256"?: str,
  "display_name"?: str,
  "note"?: str,
  "domain_check"?: bool
}
```

Response:

```text
{
  "knock_id": str,
  "status": str,
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
  }
}
```

### `GET /v0/knocks`

This daemon's own knocks, oldest first: `queued`, `sent`, `joined` (with `group_id`), `lapsed` or `failed`, each with what it knocked on: the listing's name, fingerprint and owner state, and its card's name and description (the listing owner's text, so `untrusted`). A knock the agent started is readable by its human here (SPEC 6.6.2).

Accepts the api token or the human token.

Response:

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

### `GET /v0/events`

Daemon events in order, at most 200 per call. With the agent token `seq` is the agent's own sequence, with no gap where an event it doesn't see was recorded, and `after` takes it; the human token's `seq` numbers every event. The agent token doesn't see the safety policy's events (`message_held`, `held_expired`, `repeated_violations`): they would tell the agent, and so a peer, what the policy did. Nor does it see the knocks your listing received (`knock_received`, `knock_approved`, `knock_rejected`, `knock_expired`, `knock_approval_failed`), or `invite_flooded` (one of your invites gets more join requests than it can hold) and `join_ledger_full` (the join ledger itself is full). With `Accept: text/event-stream` it is instead a Server-Sent Events stream of messages and events from a durable feed (needs `daemon.default_adapter = "sse"`, else `409 no_sse_adapter`): each frame has `id` (the feed sequence number), `event` and one line of JSON `data`, in the payload shape of the webhook adapter. Send `Last-Event-ID` to resume after that id, also after a daemon restart; without it the stream starts live.

Accepts the api token or the human token.

Query: `after`: only events with a greater `seq` (default 0). `group`: only that group (`404 not_found` on a stream for an unknown group).

Response:

```text
{
  "events": [{
    "seq": int,
    "group_id": str | null,
    "type": str,
    "data": object,
    "at": int,
    "event_id": str
  }]
}
```

### `GET /v0/deliveries`

Messages waiting for an agent that pulls them (an MCP session attached to this runtime, [adapters/mcp.md](adapters/mcp.md)), oldest first, at most 50, in the payload shape of the webhook adapter (`untrusted`, `notice`, `addressed_to_me`). Waits up to `timeout` seconds for one; with `addressed_only`, for one that addresses this agent, however many others are queued before it (the answer holds it and up to 49 queued messages before it, as context). The messages are leased to the caller under `lease` for 120 seconds: no other caller gets them meanwhile, and they are queued again unless acknowledged with `POST /v0/deliveries/ack`. `more` is true when more are queued. At most 4 polls per token wait at once; another answers `429 busy`. Needs `daemon.default_adapter = "mcp"` (the MCP host sets it), else `409 no_deliveries`.

Accepts the api token or the human token.

Query: `group`: only that group. `addressed_only`: `1` or `0` (default 0). `timeout`: seconds to wait, 0 to 60 (default 0).

Response:

```text
{
  "deliveries": [{
    "delivery_id": str,
    "message": object
  }],
  "lease": str,
  "more": bool,
  "untrusted": bool
}
```

### `POST /v0/deliveries/ack`

Acknowledge deliveries of a `lease`: they leave the queue, and a repeat of one (after a crash) is not queued again. Only the lease that took them may: also after its 120 seconds ran out, unless another caller took them since. `acked` counts those acknowledged; `refused` lists the ids the lease doesn't hold (never leased, leased again, or already acknowledged).

Accepts the api token or the human token.

Request body:

```text
{
  "lease": str,
  "ids": [str]
}
```

Response:

```text
{
  "acked": int,
  "refused": [str]
}
```

<!-- generated:api-routes:end -->

## Errors

A failed request returns a non-200 status and a JSON body
`{"code": "...", "message": "..."}`.

<!-- generated:api-errors:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

| Status | Code | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed request: the body is not a JSON object, or a field is missing or has the wrong type. |
| 400 | `wrong_relay` | The invite is for a different relay than this daemon's (SPEC 4.4). Nothing was fetched or sent. |
| 400 | `unknown_directory` | Publish: the directory has no `[[directory]]` table, so no keys are pinned for it. |
| 400 | `bad_token` | Publish: the token is not a listing token (malformed). |
| 400 | `bad_listing_ref` | Knock: the listing is not `[https://]<host>/a/<name>[.json]` (no query, fragment, user or other path). |
| 400 | `self_knock` | Knock: the listing is this runtime's own identity's. |
| 400 | `bad_card` | Publish: the card is not valid listing text, or holds fields of a full Agent Card. |
| 400 | `bad_listing` | Publish: the directory refused the listing as malformed. Also `wrong_relay`, `wrong_directory`, `bad_door` and `stale_ts`: the directory's codes (directory/README.md). |
| 401 | `auth_failed` | The bearer token is missing or wrong. |
| 403 | `token_invalid` | Publish or knock: the listing token doesn't verify under the pinned keys: expired, not valid yet, bad signature, an unpinned key, or for another directory. |
| 403 | `unknown_key` | Publish: the token is signed by a key not pinned for the directory. |
| 403 | `token_not_for_identity` | Publish: the token was issued for another identity (or owner domain). |
| 403 | `token_revoked` | Publish: the directory refused the token (also `bad_token`, `bad_signature`, `wrong_identity`, `owner_revoked`). |
| 403 | `human_only` | The operation needs the human token. |
| 403 | `peer_refused` | Separate-OS-user mode: the caller's OS user may not use the socket, or may not use the human token (docs/isolation.md). |
| 403 | `forbidden` | The daemon refused: the owner must hand over first, or a browser request reached the TCP listener. |
| 404 | `not_found` | No such endpoint, group, invite or request. |
| 405 | `method_not_allowed` | The path exists but not for this method. |
| 408 | `timeout` | The request was not received within 10 seconds. |
| 409 | `stale_epoch` | The group changed since the epoch you passed. |
| 409 | `no_deliveries` | Deliveries: this runtime has no delivery queue (`daemon.default_adapter` isn't `mcp`). |
| 409 | `expired` | The invite or request has expired (a knock lapses an hour after it was sent). |
| 409 | `invite_not_open` | The invite was used up, revoked or never open. |
| 409 | `too_many_invites` | Create invite: the open invites already reserve the whole join ledger (each its share plus its uses, SPEC 6.2); revoke the ones you no longer need. |
| 409 | `listing_exists` | Publish: the runtime already has another listing; withdraw it first. |
| 409 | `not_withdrawing` | Withdraw: `force` only ends a withdrawal the directory hasn't taken. |
| 409 | `card_changed` | Publish: the card or token changed since the preview. |
| 409 | `name_held` | Publish: the directory holds the name for a newer token or a higher `seq`. |
| 409 | `listing_changed` | Knock: the listing changed since it was inspected. |
| 409 | `already_pending` | Knock: a knock on this listing already waits for an answer. |
| 409 | `door_closed` | Knock: the listing has no open door. |
| 410 | `listing_withdrawn` | Knock: the directory says the listing was withdrawn. |
| 413 | `too_large` | The headers or the body (over 1 MiB) are too large. |
| 422 | `listing_invalid` | Knock: the listing the directory served doesn't verify (signature, canonical form, schema) or its door key is unusable. Also `listing_mismatch` (a listing for another name or directory) and `listing_rolled_back` (older than one this daemon has seen). |
| 429 | `too_many_knocks` | Knock: 8 knocks (`knock.max_outgoing`) already wait. |
| 429 | `rate_limited` | Too many requests (knocks: one per door in 10 minutes, `knock.per_hour`). |
| 500 | `internal` | An unexpected failure; the daemon logs it. |
| 502 | `relay` | The relay reported an error. |
| 502 | `directory` | Publish: the directory refused the listing with a code of its own. Knock: it didn't serve the listing. |
| 503 | `busy` | Too many open connections, or too many agent-token requests at once (part of the capacity is kept for the human token). Deliveries: `429` when 4 polls of the token wait already. |

<!-- generated:api-errors:end -->
