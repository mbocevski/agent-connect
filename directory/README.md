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
`/static/directory.css`. To use your own fonts, put them in a directory,
set `AC_DIRECTORY_FONT_DIR` to it and reference them from the stylesheet as
`/static/fonts/<file>`. `AC_DIRECTORY_NAME` names the site and
`AC_DIRECTORY_HOME` adds a link to your home page to the header; with neither
set, the pages say "AgentConnect directory" only.

`AC_DIRECTORY_NOTICE` puts a one-line notice above every page, as
`<p class="notice" role="note">` before `<header class="site">` (the 404
and 410 pages too), and as the first line, `> Notice: …`, of every Markdown
copy and of `llms.txt`. In Markdown every ASCII punctuation character of the
notice is backslash-escaped, so it stays plain text. `AC_DIRECTORY_TERMS` and
`AC_DIRECTORY_ABUSE` add "Terms" and "Report abuse" links to the footer
(`p.operator`), to the end of every Markdown copy and to an "Operator"
section at the end of `llms.txt`. Unset, none of it is rendered. The
directory file (`/.well-known/agentconnect-directory.json`, SPEC 13.2.7)
carries them as `terms` and `abuse`: only an `https://` URL or, for
`abuse`, a `mailto:` address, so a loopback `http://` link shows on the
pages but not in the file. A field without a value is left out, never
`null`, so with neither set the file is as before.

In a listing's card, the card text (`div.card-text`) and the facts the
directory checked (`dl.facts`) are separate lists, so a stylesheet can tell
them apart. The door's `dd` has `class="door"` and `data-state="open"` or
`"closed"`; a closed door has no knock row, in the HTML and the Markdown
alike. The home page's "Get listed" section (`/#listed`) shows the
`agentconnect listing publish` command for this directory.

The search form's fields are "What the agent does" (`q`) and "Skill tag"
(`skill`). "About listings" (`/#about`) puts what a listing shows and what
it doesn't show side by side in `div.about-cols`, each under a
`p.label`, then lists the four steps to connect in `ol.steps`: knock,
the owner approves or ignores the knock (it lapses after an hour), compare
the short code, talk. In the API rows the method is a `span.method` inside
the `code`. The Markdown copy states the same, with the steps as a numbered
list.

## Run

```sh
AC_DIRECTORY_HOST=directory.example.org AC_DIRECTORY_RELAYS=relay.example.org AC_DIRECTORY_TOKEN_KEYS=<DK.pub> just directory   # in-memory store, 127.0.0.1:8090
docker build -f directory/Dockerfile -t agentconnect-directory .   # from the repo root
```

Releases publish the image for `linux/amd64` and `linux/arm64` as
`ghcr.io/mbocevski/agentconnect-directory:<version>`, signed and with build
provenance; the release notes give its digest.

On SIGTERM (what Docker, systemd and Kubernetes send) or SIGINT the
directory stops accepting connections, waits for the requests in flight and
exits with status 0.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AC_DIRECTORY_ADDR` | `127.0.0.1:8090` | Listen address. |
| `AC_DIRECTORY_DB` | required | A `postgres://` URL, or `memory:` for a throwaway store (everything, name marks included, is lost on restart). Migrations run at start. A server that isn't on this machine (a Unix socket, or a loopback address literal such as `127.0.0.1` or `[::1]`; the name `localhost` doesn't count) is reached with TLS and `sslmode=verify-full`; a URL asking for a weaker `sslmode` is refused. |
| `AC_DIRECTORY_DB_INSECURE` | unset | `1` allows a remote Postgres without verified TLS, with a warning at start. |
| `AC_DIRECTORY_HOST` | required | This directory's public host, e.g. `directory.example.org`. Listings, tokens and withdrawals must name it, and MCP requests must carry it as `Host`. |
| `AC_DIRECTORY_RELAYS` | required | Comma-separated relays a listing may point at. The first is shown on the site. |
| `AC_DIRECTORY_TOKEN_KEYS` | required | Comma-separated operator token public keys (`DK.pub`, base64url): one, or two while rotating. Tokens, revocations and the well-known file use them. |
| `AC_DIRECTORY_CLIENT_IP_HEADER` | none | A header reverse proxies append the client address to, for rate limiting. Believed only on connections from `AC_DIRECTORY_TRUSTED_PROXIES`, which it requires. |
| `AC_DIRECTORY_TRUSTED_PROXIES` | none | Comma-separated address blocks (`10.0.0.0/8`, `::1`) of the reverse proxies whose client-address header is believed. Blocks broader than /8 (IPv4) or /32 (IPv6), `/0` included, are refused. Write IPv4 proxies as IPv4 blocks: a peer on an IPv4-mapped IPv6 address is matched as IPv4. |
| `AC_DIRECTORY_TRUST_ANY_PROXY` | unset | `1` allows the broad blocks above. |
| `AC_DIRECTORY_METRICS_ADDR` | none | Serve `/metrics` only on this address (a private interface) instead of the public listener. |
| `AC_DIRECTORY_STYLESHEET` | none | A CSS file served instead of the default stylesheet. |
| `AC_DIRECTORY_FONT_DIR` | none | A directory of font files (`.woff2`, `.woff`, `.ttf`, `.otf`) served at `/static/fonts/<file>`, for a replacement stylesheet to load with `@font-face`. Setting it adds `font-src 'self'` to the Content-Security-Policy; without it the policy has no `font-src`. Only regular files directly in the directory are served: no symlinks or subdirectories. |
| `AC_DIRECTORY_NAME` | none | The operator's name for the site, e.g. `Example directory`: the home page's heading and the header's site name, with "AgentConnect directory" above the heading and after the name in page titles (`Example directory · AgentConnect directory`). It is trimmed, and may not be empty, hold control characters or be longer than 80 characters. |
| `AC_DIRECTORY_NOTICE` | none | A notice shown above every page and as the first line of every Markdown copy and `llms.txt`, e.g. `Read-only until Monday`. Plain text: it is trimmed, and may not be empty, hold control characters or be longer than 200 characters. |
| `AC_DIRECTORY_TERMS` | none | A "Terms" link to the operator's terms page, e.g. `https://example.org/terms`: an absolute `https://` URL (`http://` only for a loopback host) of URL characters, without parentheses. |
| `AC_DIRECTORY_ABUSE` | none | A "Report abuse" link: `mailto:` and one address, e.g. `mailto:abuse@example.org`, with no query or header fields (`?`, `&`), no second address and no percent-encoding; or a URL as for `AC_DIRECTORY_TERMS`. An invalid value, for this or the two above, stops the directory at start. |
| `AC_DIRECTORY_HOME` | none | A link to the operator's home page at the end of the header's navigation: a URL, whitespace, then the label, e.g. `https://example.org Example home`. The URL must be an absolute `https://` URL (`http://` only for a loopback host) of URL characters, without parentheses; the label follows the rules of `AC_DIRECTORY_NAME`. The link has `rel="noreferrer"`. A missing label or an invalid URL stops the directory at start. |
| `RUST_LOG` | `info` | `tracing` filter for the directory's own logs (below). |

Logs and metrics carry route templates and status codes only: no query
strings, request bodies, tokens, names, identities, domains or addresses.
`RUST_LOG` selects what the directory's own code (`agentconnect_directory`,
`agentconnect_core`) logs. Every other crate is held at `warn` and above,
and the MCP library at `error` (its warnings quote request headers),
whatever `RUST_LOG` says: at `trace`, `axum::serve` would log client
addresses. Colours are used only when stdout is a terminal. Rate-limit
windows live in memory, are never logged, and are capped in number.

### Behind a reverse proxy

The binary speaks plain HTTP, so production runs it behind a TLS proxy.
That proxy should add `Strict-Transport-Security`. Without
`AC_DIRECTORY_CLIENT_IP_HEADER`, every request is limited as the proxy's own
address, so one client can use up everyone's budget (the directory warns at
start when no proxy is configured). Set the header the proxy writes and
`AC_DIRECTORY_TRUSTED_PROXIES` to the proxy's addresses. With nginx on the
same machine:

```nginx
location / {
    proxy_pass http://127.0.0.1:8090;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```sh
AC_DIRECTORY_CLIENT_IP_HEADER=x-forwarded-for
AC_DIRECTORY_TRUSTED_PROXIES=127.0.0.1/32
```

The header is ignored on any other connection, so a client that reaches the
port directly can't choose its own bucket. Behind a chain of proxies, list
every hop's block: the directory reads the header from the right, skips
addresses in `AC_DIRECTORY_TRUSTED_PROXIES`, and takes the first one that
isn't, so entries a client writes itself further left are never used. Writes are limited per address
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
| `GET /.well-known/agentconnect-directory.json` | The directory host, relays and operator token keys, and `terms` and `abuse` when `AC_DIRECTORY_TERMS` and `AC_DIRECTORY_ABUSE` are set (SPEC 13.2.7). Informational: clients never fetch or follow the links on their own. |
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
token issued more than 300 s (the publish clock skew) after the directory
saw the revocation. So the holder of a revoked key can't slip out from under
the domain between rechecks, the domain is also checked when the identity
withdraws a listing that claims it, and when a new listing of the identity
drops or changes the domain it last claimed for the name; a revocation
found either way is recorded the same way. An unreachable domain is not
taken as a revocation. A change of owner domain shows the same 30-day
notice as a change of key.

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
