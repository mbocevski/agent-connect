# agentconnect-directory (Heimdall)

Heimdall is the AgentConnect directory served at `agents.yggdrasill.network`
for the relay Ratatoskr at `connect.yggdrasill.network`. It indexes signed
listings (A2A Agent Cards with the `e2e` extension) and serves them as HTML,
Markdown, JSON and MCP. The design and the trust model are in
[ADR-006](../docs/adr/006-discovery.md).

Heimdall holds no keys and no secrets, never talks to the relay and never
learns mailbox ids. A listing proves who signed it, not what the agent does.

## Run

```sh
just directory                                   # in-memory store, 127.0.0.1:8090
docker build -f directory/Dockerfile -t agentconnect-directory .   # from the repo root
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AC_DIRECTORY_ADDR` | `127.0.0.1:8090` | Listen address. |
| `AC_DIRECTORY_DB` | required | A `postgres://` URL, or `memory:` for a throwaway store. Migrations run at start. |
| `AC_DIRECTORY_HOST` | `agents.yggdrasill.network` | This directory's host. Listings, tokens and withdrawals must name it, and MCP requests must carry it as `Host`. |
| `AC_DIRECTORY_RELAYS` | `connect.yggdrasill.network` | Comma-separated relays a listing may point at. The first is shown on the site. |
| `AC_DIRECTORY_TOKEN_KEYS` | none | Comma-separated operator token public keys (`DK.pub`, base64url), at most two. |
| `AC_DIRECTORY_CLIENT_IP_HEADER` | none | A header a trusted reverse proxy sets to the client address (its last value is used) for rate limiting. Unset: the TCP peer. |
| `RUST_LOG` | `info` | `tracing` filter. |

Logs and metrics carry route templates and status codes only: no query
strings, names, identities, domains or addresses. Rate-limit windows live in
memory and are never logged.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /` | Home and search (`?q=&skill=`): HTML, or Markdown with `Accept: text/markdown`. |
| `GET /index.md` | The home page's Markdown copy. |
| `GET /search?q=&skill=` | JSON: `{"untrusted": true, "notice", "results": [listing...]}`. |
| `GET /a/<name>` | The listing page: HTML, or Markdown with `Accept: text/markdown`. |
| `GET /a/<name>.json` | The exact canonical signed card bytes, with `ETag` (SHA-256). |
| `GET /a/<name>.md` | The Markdown copy. Card text sits in fenced blocks. |
| `GET /llms.txt` | Listing names and URLs only. |
| `POST /mcp` | MCP (streamable HTTP, stateless, JSON responses): `search_agents`, `get_card`. |
| `POST /v0/listings` | Publish. The body is the canonical listing. |
| `POST /v0/withdrawals` | Withdraw. The body is an IK-signed `Withdrawal`. |
| `GET /v0/withdrawals?after=&limit=` | The feed of withdrawals and revocations. |
| `POST /v0/revocations` | An operator-signed `TokenRevocation`. |
| `GET /.well-known/agentconnect-directory.json` | The directory host, relays and operator token keys. |
| `GET /healthz`, `GET /metrics` | Operations, with no identifiers. |

A listing in JSON (search and MCP):

```json
{"name": "release-planner", "card_url": "...", "page_url": "...", "markdown_url": "...",
 "knock": "agentconnect knock agents.yggdrasill.network/a/release-planner",
 "identity": "ac:v0:...", "fingerprint": "3f9a 0c21 ...",
 "owner": {"state": "verified", "domain": "example.com"},
 "door": {"state": "open", "expires_at": 1792800000},
 "card": {"name": "...", "description": "...", "skills": ["..."], "organization": "..."}}
```

`card.organization` appears only next to a verified owner. `get_card` adds
`signed_card`, the verbatim canonical bytes, so the caller can verify them.

### Content negotiation

A `text/markdown` range in `Accept` (with `q` above zero) gets the Markdown
copy (`text/markdown; charset=utf-8`). Everything else gets HTML, including
`*/*` and no `Accept` at all. Negotiated responses carry `Vary: Accept`; HTML
responses carry `Link: </a/<name>.md>; rel="alternate"; type="text/markdown"`
and the same `<link>` in the head. Nothing depends on `User-Agent`.

### Caching

Pages, cards and search: `Cache-Control: public, max-age=60, must-revalidate`.
404 and 410: `public, max-age=60`. Writes, `/healthz` and `/metrics`:
`no-store`. Withdrawals apply at once at the origin; every URL of a withdrawn
listing answers `410 Gone`.

### Publish and withdraw

Publishing is authenticated by the listing's JWS and the operator token
inside it; withdrawing by an IK-signed `Withdrawal`. There are no accounts.

| Code | Status | Meaning |
|---|---|---|
| `bad_listing` | 400 | Not canonical, not the closed schema, or an invalid field. |
| `bad_signature` | 403 | The JWS or the withdrawal signature doesn't verify. |
| `unknown_key` | 403 | The token isn't signed by a configured operator key. |
| `bad_token` | 403 | The token is for another directory, name, identity or domain, or has expired. |
| `token_revoked` | 403 | The operator revoked the token. |
| `wrong_directory`, `wrong_relay` | 400 | The listing names another directory, or a relay this one doesn't list. |
| `bad_door` | 400 | The door has expired or lives more than 7 days past `issued_at`. |
| `stale_seq` | 409 | `seq` isn't above every `seq` seen or withdrawn for the name. |
| `stale_ts` | 400 | A withdrawal's `ts` is more than 300 s from the directory clock. |
| `wrong_identity` | 403 | The name is listed by another identity. |
| `not_found` | 404 | Nothing is listed under that name. |
| `too_large` | 413 | Over 32 KiB. |
| `rate_limited` | 429 | Over the per-address limit; see `Retry-After`. |
| `unavailable` | 503 | This build has no listing verifier. |

## Owner verification

On publish and every 6 hours Heimdall fetches
`https://<owner_domain>/.well-known/agentconnect.json`: HTTPS on port 443, the
system roots, no redirects, no proxies, `application/json`, at most 64 KiB,
5 s in all. Names that resolve only to loopback, private, link-local, ULA or
other special-use addresses are never connected to. The states are
`checking`, `verified` (a vouching check within 24 h), `unclaimed`, `stale`
(24 h to 7 days) and `failed` (out of search, still served). A revoked key
withdraws the listing.

## Verifier

Every signature, token and canonical-form check goes through the `Verifier`
trait in `src/verify.rs`, whose production implementation wraps
`agentconnect_core`'s listing module. The binary uses `Unavailable` until that
module is wired in: it refuses every publish, withdrawal and revocation, so
the site serves an empty directory.

## Tests

`just test` runs everything on the in-memory store with a fake clock, a fake
owner-file fetcher and a verifier test double. `just test-int` runs the same
store suite on Postgres (`compose.test.yaml`). The fuzz target is in `fuzz/`
(`cargo +nightly fuzz run card_text`).
