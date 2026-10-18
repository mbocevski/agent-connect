# agentconnect-directory

The directory is the server side of AgentConnect discovery. It indexes signed
listings (A2A Agent Cards with the `e2e` extension) of agents reachable
through an AgentConnect relay, and serves them as HTML, Markdown, JSON and
MCP. The design and the trust model are in
[ADR-006](../docs/adr/006-discovery.md). The examples use
`directory.example.org` as the directory's host.

The directory holds no keys and no secrets, never talks to the relay and
never learns mailbox ids. A listing proves who signed it, not what the agent
does.

The pages are a plain, unbranded default: system fonts, a light and a dark
scheme, no JavaScript. To restyle them, point `AC_DIRECTORY_STYLESHEET` at a
CSS file; it is served instead of `static/directory.css` at
`/static/directory.css`.

## Run

```sh
AC_DIRECTORY_HOST=directory.example.org AC_DIRECTORY_TOKEN_KEYS=<DK.pub> just directory   # in-memory store, 127.0.0.1:8090
docker build -f directory/Dockerfile -t agentconnect-directory .   # from the repo root
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AC_DIRECTORY_ADDR` | `127.0.0.1:8090` | Listen address. |
| `AC_DIRECTORY_DB` | required | A `postgres://` URL, or `memory:` for a throwaway store (everything, name marks included, is lost on restart). Migrations run at start. A server that isn't on this machine (a Unix socket, `localhost` or loopback) is reached with TLS and `sslmode=verify-full`; a URL asking for a weaker `sslmode` is refused. |
| `AC_DIRECTORY_DB_INSECURE` | unset | `1` allows a remote Postgres without verified TLS, with a warning at start. |
| `AC_DIRECTORY_HOST` | required | This directory's public host, e.g. `directory.example.org`. Listings, tokens and withdrawals must name it, and MCP requests must carry it as `Host`. |
| `AC_DIRECTORY_RELAYS` | `connect.yggdrasill.network` | Comma-separated relays a listing may point at. The first is shown on the site. |
| `AC_DIRECTORY_TOKEN_KEYS` | required | Comma-separated operator token public keys (`DK.pub`, base64url): one, or two while rotating. Tokens, revocations and the well-known file use them. |
| `AC_DIRECTORY_CLIENT_IP_HEADER` | none | A header a reverse proxy sets to the client address (its last value is used) for rate limiting. Believed only on connections from `AC_DIRECTORY_TRUSTED_PROXIES`, which it requires. |
| `AC_DIRECTORY_TRUSTED_PROXIES` | none | Comma-separated address blocks (`10.0.0.0/8`, `::1`) of the reverse proxies whose client-address header is believed. |
| `AC_DIRECTORY_METRICS_ADDR` | none | Serve `/metrics` only on this address (a private interface) instead of the public listener. |
| `AC_DIRECTORY_STYLESHEET` | none | A CSS file served instead of the default stylesheet. |
| `RUST_LOG` | `info` | `tracing` filter. |

Logs and metrics carry route templates and status codes only: no query
strings, names, identities, domains or addresses. The MCP library's own logs
are held to errors, because its warnings quote request headers. Rate-limit
windows live in memory, are never logged, and are capped in number.

### Behind a reverse proxy

The binary speaks plain HTTP, so production runs it behind a TLS proxy.
That proxy should add `Strict-Transport-Security`. Without
`AC_DIRECTORY_CLIENT_IP_HEADER`, every request is limited as the proxy's own
address, so one client can use up everyone's budget: set the header the proxy
writes (for example `x-forwarded-for`, where the proxy appends the client's
address last) and `AC_DIRECTORY_TRUSTED_PROXIES` to the proxy's addresses.
The header is ignored on any other connection, so a client that reaches the
port directly can't choose its own bucket. Writes are limited per address
and also per (address, listing name), so a flood against one name doesn't
block publishing or withdrawing the others.

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
 "knock": "agentconnect knock directory.example.org/a/release-planner",
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

Refusals are `{"code", "detail", "kind"?}`. When the core decided, `kind` is
the core's stable error kind (`malformed`, `signature`, `unknown_key`,
`expired`, `not_yet_valid`, `token_mismatch`, `door_expired`,
`wrong_directory`, `stale_timestamp`, `superseded`, ...), which picks the code, and
`detail` is the core's reason.

| Code | Status | Meaning |
|---|---|---|
| `bad_listing` | 400 | Not canonical, not the closed schema, or an invalid field. |
| `bad_signature` | 403 | The JWS, withdrawal or revocation signature doesn't verify. |
| `unknown_key` | 403 | The token isn't signed by a pinned operator key. |
| `bad_token` | 403 | The token binds other params, has expired or isn't valid yet. |
| `token_revoked` | 403 | The operator revoked the token. |
| `wrong_directory`, `wrong_relay` | 400 | The object names another directory, or a relay this one doesn't list. |
| `bad_door` | 400 | The door has expired. (A door more than 7 days past `issued_at` is `bad_listing`.) |
| `stale_ts` | 400 | `issued_at` more than 300 s ahead, or a withdrawal's `ts` more than 300 s off. |
| `name_held` | 409 | Kind `superseded`: the core's `NameRecord` doesn't admit the listing (a token older than the name's newest, no `seq` above the stored one, or a tombstone of this identity). |
| `stale_seq` | 409 | A withdrawal below the listed `seq`. |
| `conflict` | 409 | The name changed during the publish; retry. |
| `wrong_identity` | 403 | A withdrawal by an identity that doesn't hold the name. |
| `not_found` | 404 | Nothing is listed under that name. |
| `too_large` | 413 | Over 32 KiB. |
| `rate_limited` | 429 | Over the per-address limit; see `Retry-After`. |

Who may publish a name is the core's `NameRecord`: per name the
directory stores the high-water mark (the newest accepted token's `issued_at` and its
identity, kept through withdrawal, expiry and revocation, so a name can't go
back to a key it was rotated away from) and per-identity tombstones. A
publish is admitted with `NameRecord::admits` against the stored listing and
recorded with `accept`; a withdrawal's tombstone comes from
`NameRecord::tombstone`. The store applies either only if the name hasn't
changed since the decision.

## Owner verification

On publish and every 6 hours the directory fetches
`https://<owner_domain>/.well-known/agentconnect.json`: HTTPS on port 443, the
system roots, no redirects, no proxies, `application/json`, at most 64 KiB,
5 s in all. Names that resolve only to loopback, private, link-local, ULA or
other special-use addresses are never connected to. Each fetch is recorded
in the core's history (`OwnerChecks::record`) and the state is the core's
`owner_state`: `checking` (no fetch has finished), `verified` (vouched within
24 h), `unclaimed`, `stale` (24 h to 7 days) and `failed` (a file that
doesn't vouch, which sticks until a later fetch vouches, or nothing for 7
days; out of search, still served). Fetches are folded into the stored
history atomically, in the order they complete, so overlapping checks can't
lose a negative result. Owner domains are resolved as absolute names, so
resolver search domains never apply. Expired listings are no longer checked,
and are purged 30 days after their token expires.

A file that revokes the key withdraws the listing at once, and the directory
records the revocation against the (name, identity): that identity can list
the name again, with or without an owner domain, only under an operator
token issued after the revocation.

Tombstones are kept as long as the name (SPEC §13.2.2), so a withdrawn
listing's public bytes can't be re-posted, however long ago it was
withdrawn.

## Verifier

Every signature, token and canonical-form check goes through the `Verifier`
trait in `src/verify.rs`, implemented by `CoreVerifier` on
`agentconnect_core::listing` with the pinned operator keys. The `detail` of a
`bad_listing`, `bad_token` or `bad_request` refusal is the core's reason.
The directory itself keeps only what needs its own state: its host and relays,
the stored listing, tombstones and name marks, and revoked token ids. The
token is checked before the publish-time rules, so an unauthorised listing
is refused as such.

## Tests

`just test` runs everything on the in-memory store with a fake clock, a fake
owner-file fetcher and the real verifier, with keys from the per-run seed.
`tests/vectors.rs` runs the core's `testdata/` vectors (`listings.json`,
`listing-tokens.json`, `withdrawals.json`, `owner-files.json`) end to end
through the endpoints, with the keys and secrets the files publish.
`just test-int` runs the same
store suite on Postgres (`compose.test.yaml`). The fuzz target is in `fuzz/`
(`cargo +nightly fuzz run card_text`).
