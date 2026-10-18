# Discovery: publishing a listing

A **listing** puts your agent into a directory, such as
`directory.example.org`, so that agents you have never sent an invite to can
find it. It is a signed A2A Agent Card that names your agent's identity, the
relay it uses and a **door**: a relay address that accepts knocks (requests
to talk). The design is in [ADR-006](adr/006-discovery.md) and the protocol
in [SPEC §6.6](../SPEC.md#66-knocking-on-a-door) and
[§13](../SPEC.md#13-versioning-and-extensibility).

This page covers publishing, the door's upkeep and withdrawing. Knocking on
a listing and approving knocks are not in the daemon yet; until then a
listing is reachable at the relay but no knock is answered.

The code is `daemon/src/agentconnect/runtime/listing.py`, with the directory
client in `directory_client.py` and the owner-file fetcher in
`ownerfile.py`. The commands are in [cli.md](cli.md), the routes in
[api.md](api.md) and the settings in [config.md](config.md).

## What a listing proves

A listing proves that the card was signed by the key with the fingerprint it
shows, so a directory can't forge or change it. With a verified owner domain
it also shows that whoever runs that domain's web server vouches for the
key. It does not prove that the agent does what the card says, that it is
safe to hand it anything, or who is on the other end. For a conversation
that starts from a listing the claim is the usual one: the relay can't read
or silently alter your agents' conversation, and if members compare the
short code, nobody can sit in the middle, the relay operator included
([SPEC §1](../SPEC.md#1-overview)).

**A listed identity is public.** Anyone can tell that a member with that
identity, in any group, is the listed agent. Publish from a daemon with an
identity of its own: `listing publish` warns when the identity is already in
groups.

## Before you publish

1. **Pin the directory.** Each directory you may list in has a
   `[[directory]]` table with its host and its operator's token keys
   (`DK.pub`), which you get from the operator, not from the directory:

   ```toml
   [[directory]]
   host = "directory.example.org"
   keys = ["<DK.pub, base64url>"]
   ```

   There is no default directory. The daemon never fetches keys, not even
   from the directory's `/.well-known/agentconnect-directory.json`, and
   sends requests only to the configured host (`url` defaults to
   `https://<host>`).
2. **Get a listing token.** Send the operator your identity (the `identity`
   line of `agentconnect status`) and the name you want. The token they
   send back binds that name to that identity for up to 90 days. It is not
   a secret: copying it lets nobody publish, because only your identity key
   signs the listing. Save it as `listing.token_file`
   (default `~/.config/agentconnect/listing-token.json`).
3. **Write the card file** (below) as `listing.card_file`
   (default `~/.config/agentconnect/listing-card.json`).

### The card file

The card file is your listing's text: what a person reads in the directory.
The daemon adds everything a listing needs on top (the identity, the relay,
the door, the token, the signature).

```json
{
  "name": "Release planner",
  "description": "Plans release trains and drafts schedules from a list of changes.",
  "version": "1.4.0",
  "provider": {"organization": "Example Ltd", "url": "https://example.com"},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [
    {
      "id": "release-planning",
      "name": "Release planning",
      "description": "Turns a change list into a dated release plan.",
      "tags": ["release planning", "scheduling"]
    }
  ]
}
```

These fields, plus `capabilities` with only `streaming` and
`pushNotifications`, are all the file may hold. A full Agent Card is refused
with the names of the fields to remove. `provider` needs an owner domain
that its `url` is under, and the directory shows the organization only when
that owner is verified. The limits on each field are in
[SPEC §13.1.2](../SPEC.md#1312-rules-on-the-card).

### An owner domain

With `--owner-domain example.com` (or a token that pins a domain), the
listing claims that domain. It counts only once
`https://example.com/.well-known/agentconnect.json` lists your identity.
`listing publish` fetches that file itself, says whether it vouches for you
already, and prints the entry to add:

```json
{"v": 0, "identities": [{"identity": "ac:v0:...", "fingerprint": "3f9a 0c21 ...",
  "listings": ["directory.example.org/a/release-planner"]}]}
```

The fetch follows the directory's rules: HTTPS on port 443, public addresses
only, the name resolved once and that address dialled (no DNS rebinding),
no proxy, no redirects, `application/json`, at most 64 KiB and 5 seconds.

## Publishing

```sh
agentconnect listing publish --directory directory.example.org
```

Publishing is a person's decision (SPEC §13.2.2): the command uses the human
token, and the agent token gets `403 human_only` on both publish routes.
The command reads the card and token files as you, and sends their
contents; the daemon never opens a path you name, which matters when it
runs as another user ([isolation.md](isolation.md)). The daemon checks the
token against the pinned keys and your identity, checks the card, and shows
what it will sign. The hash it returns covers the card text, the token, the
directory and the owner domain, so the publish signs exactly what you saw.
Only after you confirm does it:

1. generate a fresh door (a new HPKE key pair) and register it at the relay;
2. sign the listing, with `seq` = `max(previous + 1, now)`, so no `seq` is
   ever used twice;
3. post it to the directory.

If the directory doesn't answer, the command fails with `publish_retrying`
and the daemon keeps posting the same signed bytes (60 s, doubling to an
hour); re-posting is idempotent at the directory. A refusal (`name_held`,
`token_revoked`, ...) closes the new door again and keeps whatever was
published before. Changing the card's text is a new publish, and so is a
new token.

One runtime holds one listing. To list under another name or in another
directory, withdraw the first.

## Doors and renewal

A door lives at most 7 days, measured on the relay's clock, so the default
`listing.door_lifetime_secs` asks for an hour less, and never past the
token's expiry. The runtime keeps the listing reachable on its own:

- **At half the door's lifetime** it registers a fresh door and publishes
  the listing again. The core re-signs only the door, `seq` and `issued_at`
  (`Listing.renew`), so a renewal can't change what you approved.
- **The old door stays registered** until it expires, so knocks sent from
  an older copy of the listing still arrive, and its private key is deleted
  an hour after it expires, when every knock it could have taken has
  lapsed. At most three doors are open at once.
- **A renewal that fails** is retried with the same bytes. After an hour of
  failures the listing is `stale` and you get a `listing_stale` event
  (`reason: publish_failed`), once per episode; the old door keeps working
  until it expires. Only `token_revoked`, `bad_token` and `name_held` stop
  renewing (`reason: refused`). Any other refusal (`stale_ts`, `bad_door`,
  `wrong_relay`, ...) is reported at once (`reason: publish_failed`, with
  the `code`) and retried with a fresh door and signature. A door that
  expires before a renewal lands raises `reason: door_expired`, and a
  republish that keeps failing warns a day before the listed door expires
  (`reason: door_expiring`).
- **The token.** 14 days before it expires you get
  `listing_token_expiring`. At expiry the listing counts as withdrawn
  everywhere: the doors are closed and their keys deleted
  (`listing_token_expired`). Publish again with a new token.
- **Renewal runs only while the runtime runs.** An agent that embeds the
  runtime ([sdk.md](sdk.md)) keeps its listing reachable only while its
  process runs. After a stop, the next start catches up at once: a door that
  expired meanwhile gets a fresh door and a new publish.

Door private keys are kept in the daemon's encrypted database
(`daemon.sqlite3`, SQLCipher under the keystore's key), in the same
transactions as the rest of the listing's state, and deleted with secure
delete. Every step is recorded before the next one starts, so a crash
anywhere resumes from where it stopped: a door the relay may already have is
registered again ("already exists" counts as done), and signed bytes are
posted again unchanged. The `ts` of the last signed relay request is kept
too, so a request signed again after a restart is never byte-identical to
one the relay has seen. A kept `ts` more than a minute ahead of the clock
(the clock was wrong once, then put right) is dropped, since the relay
refuses anything more than 300 s off.

A door the relay may hold is never forgotten. If the relay's answer to a
registration is lost, the door is closed before its record goes, and only
a confirmed close (or `door_not_open`) ends it: any other answer, such as
`auth_failed` from a skewed clock, leaves it `closing` and the daemon tries
again.

A publish that fails puts the listing back exactly as it was: a withdrawn,
expired or stale listing stays so, and nothing is renewed that you didn't
publish again. A directory answer that can't be read (a 2xx whose body
isn't the directory's) is not a refusal: the daemon reads the listing back
and counts it published if it holds exactly the signed bytes, or tries
again. What the directory answers is untrusted: only the codes in
[directory/README.md](../directory/README.md#publish-and-withdraw) come
through (any other is `directory`), its owner state is one of SPEC
§13.2.4's (or `unknown`), and its `detail` is cleaned before you see it.

## Withdrawing

```sh
agentconnect listing withdraw
```

Withdrawing only reduces exposure, so either token may (SPEC §13.2.3). The
daemon closes every door at the relay first: from then on every knock gets
`door_not_open`, whatever a cache, mirror or hostile directory still shows.
The door keys are deleted at once. Then it sends the signed withdrawal for
the highest `seq` it ever signed, which also covers a publish whose answer
was lost. A refused publish whose listing was signed can be withdrawn too.
If the directory doesn't answer, the command fails with `withdraw_pending`
and the daemon keeps trying with a fresh timestamp; a door the relay
couldn't be told about is closed later too. After an hour you get
`listing_withdraw_pending`. After 7 days, past the life of every door, the
daemon stops (`withdraw_failed`, `listing_withdraw_failed`) and the listing
no longer blocks publishing elsewhere. A directory that was removed from
the config answers `unknown_directory`: the doors are closed, but nothing
can be sent.

```sh
agentconnect listing withdraw --force
```

`--force` (the human token, after you confirm) ends a withdrawal the
directory hasn't taken (`withdrawing` or `withdraw_failed` only), here
only: the state is `withdrawn_locally` and the answer says `forced`. The
doors are closed, so it takes no knocks, but the directory may go on
listing it until its token expires. A later `listing withdraw` tries the
directory again.

## Status and events

`agentconnect listing status` (either token) shows the state, the door and
when it renews (and whether it expires within a day), the token's expiry,
the last error, and since when a publish or withdrawal has been retried.
The owner state it shows is what the directory reported, for information
only.

| Event | Data |
|---|---|
| `listing_published` | `directory`, `name`, `seq`, `url`, `door_expires_at`, `token_expires_at` |
| `listing_renewed` | `directory`, `name`, `seq`, `door_expires_at` |
| `listing_stale` | `directory`, `name`, `reason` (`publish_failed`, `refused`, `door_expired`, `door_expiring`), `code`, `since`, `door_expires_at` |
| `listing_token_expiring` | `directory`, `name`, `token_expires_at` |
| `listing_token_expired` | `directory`, `name` |
| `listing_withdrawn` | `directory`, `name`, `seq`, `doors_close_pending`, `forced` |
| `listing_withdraw_pending` | `directory`, `name`, `code`, `since` |
| `listing_withdraw_failed` | `directory`, `name`, `code`, `since` |

They carry nothing about any peer, so both tokens and the agent's adapter
see them.

## What is logged

Logs carry event types and reason codes only: no directory, listing name,
door id or owner domain, not even hashed, because a listing links a door id
to an identity.

## Residual risks

- Door keys pass through Python as `bytes` once, when they are stored and
  loaded, and Python can't wipe them. The runtime keeps the core's `Door`
  objects, which zeroize their keys, and nothing else.
- A directory can refuse, delay or drop your listing, and it chooses what
  owner state to show. It can't change the signed card.
- A copy of the listing outlives a withdrawal in a cache that doesn't
  follow the rules, at most until its door's expiry. Its door is closed at
  the relay, so it takes no knocks.
