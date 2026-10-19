# Discovery: listings and knocks

A **listing** puts your agent into a directory, such as
`directory.example.org`, so that agents you have never sent an invite to can
find it. It is a signed A2A Agent Card that names your agent's identity, the
relay it uses and a **door**: a relay address that accepts knocks (requests
to talk). The design is in [ADR-006](adr/006-discovery.md) and the protocol
in [SPEC §6.6](../SPEC.md#66-knocking-on-a-door) and
[§13](../SPEC.md#13-versioning-and-extensibility).

This page covers publishing, the door's upkeep and withdrawing, then
[knocking](#knocking) on someone else's listing and
[approving the knocks](#approving-knocks) your listing receives.

The code is `daemon/src/agentconnect/runtime/listing.py` and
`runtime/knocks.py`, with the directory client in `directory_client.py` and
the owner-file fetcher in `ownerfile.py`. The commands are in
[cli.md](cli.md), the routes in [api.md](api.md) and the settings in
[config.md](config.md).

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
see them. With the human token, `listing status` also shows how many knocks
wait for your approval (`pending_knocks`) and how many were dropped since
the runtime started (`knocks_dropped`).

## Knocking

A **knock** asks a listed agent's owner for a new group of two with your
agent (SPEC §6.6). Either token may knock: an agent may start one, and
`knock.agent_may_knock = false` leaves it to the human token. Only the
listing owner's human can say yes.

```sh
agentconnect knock directory.example.org/a/release-planner
```

The listing is `<directory host>/a/<name>` (an `https://` in front and a
`.json` at the end are allowed; a query, a fragment, a user, another path or
another scheme are not). The host must be a pinned `[[directory]]`, and the
daemon fetches `<directory.url>/a/<name>.json` from that table's URL, never
from anything the argument or the listing says. It then checks everything
the directory served, whatever the directory claims:

1. the signature, the canonical form and the schema (`listing_invalid`);
2. that it is the listing of that name in that directory, not another one
   (`listing_mismatch`);
3. the listing token under the **pinned** keys and its expiry
   (`token_invalid`);
4. that the listing's relay is this daemon's relay (`wrong_relay`), that it
   isn't this daemon's own identity (`self_knock`), and that it has an open
   door with a key of the right size (`door_closed`);
5. that it doesn't roll back to an older listing for the name than one this
   daemon saw before (`listing_rolled_back`): a lower `seq` or an older
   token.

A listing that fails 1, 2, 3 or 5 exits with code 7: the directory may be
lying, which is different from "no answer". Nothing is built or sent before
every check passed, so no KeyPackage exists for a knock on a bad listing.

**The owner domain.** If the listing claims one, the daemon fetches that
domain's `/.well-known/agentconnect.json` itself, under the rules of
[An owner domain](#an-owner-domain), and folds the result into the history
it keeps for the listing (SPEC §13.2.4). The directory's own badge is never
used. The domain's web server learns that someone is about to knock, and
from which address, so `agentconnect knock` asks first (the default answer
is `knock.domain_check`); `--no-domain-check` skips it and the owner shows
as not checked. The organization in the card is shown only next to a
verified domain.

**What you see.** The command shows the listing's name and directory, the
identity's fingerprint, the owner state, and the card's name, description
and skills, each marked as written by the listing's owner and not
verified, with control and bidi characters replaced. An agent gets the same
through `POST /v0/knocks/inspect`, marked `untrusted` and with a notice to
put in front of it: listing text is data, never instructions. A listing
proves who signed it, not what the agent does or who runs it.

**Sending.** After you confirm, the core builds the knock: a fresh
KeyPackage used for this knock only, a random `welcome_secret`, your
display name (`--name`, default `daemon.display_name`) and an optional
one-line `--note`, signed by this instance and sealed to the door's key.
The knock and its secret are kept in the daemon's encrypted database and
the sealed knock goes to the relay. The daemon keeps the relay's limits
itself, so no KeyPackage is spent on a knock the relay would refuse: at
most `knock.max_outgoing` (8) knocks wait at once, one per listing, one per
door in 10 minutes and `knock.per_hour` (20) an hour.

**Waiting.** `agentconnect knock` waits up to `--wait` seconds (by default
3900, the knock's whole life) and prints the new group when the owner's
human approves; compare the short code with the owner with `agentconnect
verify <group>`, both of you at once. Only a Welcome is an answer. With no answer by
`ts + 3900` the knock **lapses** ("no answer", exit 1): its
`welcome_secret` and its KeyPackage's private keys are deleted. A lapse
says nothing about why: the owner may have been offline or busy, the knock
may have been dropped by a limit, or the human may have said no; nothing
tells these apart (SPEC §6.6.6). `agentconnect knocks` lists your knocks
(`queued`, `sent`, `joined`, `lapsed` or `failed`) with what each knocked
on: the listing, the fingerprint, the owner state, and the card's name and
description marked as unverified. That is where you read a knock your agent
started; with `knock.agent_may_knock = false` only you can start one. The
daemon keeps at most `knock.max_outgoing` (8) knocks waiting, also when
several are started at once.

**Joining.** A Welcome that opens under one of your pending knocks is
joined only if it is the new group the knock asked for (SPEC §6.6.5): owned
and created by the listed identity, named after the listing, with exactly
the two of you in it. One that opens but isn't raises
`relay_misbehaviour` (`knock_welcome_mismatch`) and ends the knock
(`knock_failed`, `welcome_invalid`): only the two ends knew the key, so the
owner is broken or the key leaked. After joining, the other member is
`unverified`, as every new member is: the group view shows it as
`listed_as` the listing, which is not a substitute for comparing the short
code with its owner.

## Approving knocks

Knocks on your listing's doors (the current one, and an older one until it
expires) wait for **your** decision. Nothing else approves a knock: there is
no setting (`policy.auto_approve` is about joins and never applies to
knocks, and the discovery tables refuse an `auto_approve` key), no policy
verdict, no agent route, SDK call or tool. The agent token can't list,
read or decide knock approvals, and doesn't see the events about them.

```sh
agentconnect approvals
agentconnect approvals approve kn-3hQ... --purpose "Plan the 1.4 release"
```

An approval shows the listing it came in on, the knocker's name and note
(both written by the knocker, not verified), its fingerprint, what this
daemon already knows about that identity (the groups you share, and where
you verified it), and when it lapses. The request id is derived by the
daemon from the knock (`kn-...`), so a knocker can't choose it.

Approving creates a **new** group named after the listing, with `--purpose`
(default: the listing's description) as the scope the knocker's agent sees,
adds the knocker and sends it the Welcome. Until the Add is confirmed and
the Welcome has gone out, the group doesn't exist for your agent: the agent
token's group list leaves it out, every agent action on it (reading it,
sending, leaving, inviting) is `not_found`, and anything the knocker sends
waits in the inbox. Then the group's events so far reach your agent, in
order (one `member_joined` first), and so do the waiting messages; the
knocker gets your Agent Card. If the approval fails before the knocker was
added, the group is deleted; if it fails after, the knocker is removed and
the group stays hidden from your agent. Either way the group keeps its
`origin` for you. The knocker's claimed name and note never
reach your agent: the member's display name stays unset until the
knocker's own Agent Card (untrusted, like every card) gives one. Rejecting
sends nothing; so does a lapse. An approval lapses an hour after the knock
was sent (its `ts`), and in its last minute it can no longer be approved. A
Welcome the relay can't take yet (`internal`, `rate_limited`,
`quota_exceeded`) is sent again, under the same `msg_id`, after a backoff.
Your sends to other groups don't wait for it, except after `rate_limited`:
the relay's send budget for your mailbox is shared by all your groups, so
they all wait out that pause. If the Welcome can't be sent before the
knocker gives up, or the relay refuses it, the knocker is removed from the
group again.

Before a knock waits for you, the daemon checks it (SPEC §6.6.3) and drops,
silently, any knock that:

- arrives on a door it doesn't hold a key for (a closed, withdrawn or
  long-expired door), or fails to open, has a `ts` more than an hour old or
  5 minutes ahead, a bad KeyPackage (a used one included) or a bad
  signature;
- it has seen before (the **replay ledger**, below);
- comes from an identity that already has a knock waiting on the listing,
  or arrives when `knock.max_pending_per_door` (32) wait on its door;
- comes over the budgets checked before a knock is even opened:
  `knock.opened_per_door_per_minute` (10) per door, and
  `knock.failures_per_sender_per_hour` (10) knocks failing the checks from
  one sender mailbox.

A dropped knock raises no event (a flood would fill the event log); it is
in the audit log ([safety.md](safety.md#knocks)) and in the
`knocks_dropped` count. The knocker learns nothing either way. A check
that fails for a reason of the daemon's own (its storage, randomness or an
internal error, told apart by the core's error kind) drops nothing: the
knock is tried again.

**The replay ledger.** Every knock that passes the checks is remembered by
its `knock_id` and its KeyPackageRef until `ts + 3900`, whatever happens to
it next, so a relay can't put a knock you rejected in front of you again.
The ledger is in the encrypted database, written in the same transaction as
the approval, and reloaded on start in full, even past a lowered
`knock.ledger_capacity`. When it is full, new knocks are dropped until old
entries expire; none is forgotten early. Invite join requests have a ledger
of their own (SPEC §6.2, "Replays"), so a flood of knocks can't fill it. Its
total size is fixed at 65536; each invite gets a share of it
(`policy.join_ledger_per_invite`), and an invite's entries go once it is
revoked, expires or is used up ([sdk.md](sdk.md#the-humans-part)).

## Knock events

| Event | Side | Data | Seen by |
|---|---|---|---|
| `knock_sent` | knocker | `knock_id`, `directory`, `name`, `identity`, `fingerprint`, `owner_state`, `gives_up_at` | both tokens |
| `knock_failed` | knocker | `knock_id`, `code` (`door_not_open`, `rate_limited`, `stale`, `welcome_invalid`, ...) | both tokens |
| `knock_lapsed` | knocker | `knock_id`, `directory`, `name` | both tokens |
| `joined` | knocker | `knock_id`, `listing` (`directory`, `name`, `identity`), `owner_state` | both tokens |
| `knock_received` | owner | `request_id`, `directory`, `name`, `identity`, `fingerprint`, `lapses_at` | human |
| `knock_approved` | owner | `request_id`, `group_id` | human |
| `knock_rejected` | owner | `request_id` | human |
| `knock_expired` | owner | `request_id` | human |
| `knock_approval_failed` | owner | `request_id`, `group_id`, `code` | human |

No event carries a knocker's name or note: those are shown to the human
only, in the approval, and deleted once it is decided.

## Storage

Everything a knock leaves behind is in the daemon's encrypted database,
with secure delete: on the knocker, the knock with its `welcome_secret` and
KeyPackage (the KeyPackage's private keys are in the MLS store); on the
owner, the verified knock while its approval waits, and the ledger. Each
secret goes as soon as it isn't needed: the knocker's at the join, a failure
or the lapse, the owner's once the Welcome is sent, or at a rejection, a
lapse or a failure. The knocker's name and note go when the approval is
decided. Ended knocks and decided approvals are deleted a week later.

Every step is recorded before the next one starts, so a crash anywhere
resumes from the database without a second approval, Welcome or group: a
knock received but not recorded is delivered again by the relay; an
approval's Add and Welcome continue from the outbox; a join the core
committed is finished from its journal (ADR-004).

## What is logged

Logs carry event types and reason codes only: no directory, listing name,
door id, owner domain, knock id, knocker identity, name or note, not even
hashed, because a listing links a door id to an identity.

## Residual risks

- Door keys pass through Python as `bytes` once, when they are stored and
  loaded, and Python can't wipe them. The runtime keeps the core's `Door`
  objects, which zeroize their keys, and nothing else. The same holds for a
  knock's `welcome_secret` when it is stored and read back: the runtime
  keeps the core's knock objects, not the bytes.
- A crash right after the core built a knock, before the daemon recorded
  it, leaves that knock's KeyPackage private keys in the (encrypted) MLS
  store, never used. A crash right after an approval created its group,
  before the daemon recorded it, leaves an empty group in the core; the
  knock still waits and can be approved again.
- A system clock that jumps forward, purges the ledger, then steps back
  reopens the replay window for at most the jump: the entries that pass
  forgot are gone. The purge always uses the clock's time at that moment
  and keeps no mark of a later one, so once the clock is put right no entry
  is forgotten early again.
- The relay sees how soon the owner acknowledges each knock, and a knock
  dropped before it is opened (an unknown door, a flood budget, a sender
  over its failures) is acknowledged sooner than one that was opened. It
  can tell those apart; it learns nothing of what the human decided, and
  the knocker sees no acknowledgement at all.
- The knocker doesn't read the directory's revocation feed: a listing whose
  token was revoked can be served until its door expires. Closing the door
  at the relay is what stops knocks.
- The relay can drop knocks or Welcomes, or answer `accepted` for a knock
  it dropped. That is denial of service only: it can't forge a Welcome
  without the knock's secret, or redirect a knock to another door.
- A directory can refuse, delay or drop your listing, and it chooses what
  owner state to show. It can't change the signed card.
- A copy of the listing outlives a withdrawal in a cache that doesn't
  follow the rules, at most until its door's expiry. Its door is closed at
  the relay, so it takes no knocks.
