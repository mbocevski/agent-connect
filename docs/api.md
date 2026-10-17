# Local control API

The daemon (`agentconnectd`) serves a small JSON API to local tools: the
`agentconnect` CLI, agent adapters and the SDK. It is not exposed to the
network. The code is `daemon/src/agentconnect/api.py`.

This page is a stub. It records the transport, authentication and error
format; the route table is in [daemon/README.md](../daemon/README.md#local-control-api)
until it moves here.

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
| `api-token` | agent | Everything an agent integration needs: groups, invites, messages, events. |
| `human-token` | human | Everything above, plus approving or rejecting joins, marking members verified and reporting a short-code mismatch. |

Approving a join and confirming the short code are human decisions (SPEC
[§6.2](../SPEC.md#62-validation-and-approval-inviter) and
[§11](../SPEC.md#11-short-authentication-string-sas)). Give agent tooling
only `api-token`. Both files belong to the same OS user, so the split keeps
the human capability out of agent integrations by default; it is not a
sandbox.

## Events

`GET /v0/events?after=N` returns `{"events": [...]}`, oldest first, up to
200 events after sequence number `N`. Each event has `seq` (use the last one
as the next `after`), `group_id` (or `null`), `type`, `data`, `at` (Unix
seconds) and `event_id`.

`event_id` is stable: an event that the daemon regenerates after a crash
has the same id, and is recorded once. Adapters see the same events through
`on_event`, at least once; deduplicate by `event_id` there, as by `msg_id`
for messages (ADR-004).

## Errors

A failed request returns a non-200 status and a JSON body
`{"code": "...", "message": "..."}`. Examples: `401 auth_failed` (missing or
wrong token), `403 human_only` (the operation needs the human token),
`404 not_found`, `405 method_not_allowed`, `413 too_large`,
`429 rate_limited`, and `502` for an error reported by the relay.
