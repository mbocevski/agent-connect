# ADR-007: Autonomous connections under standing human rules

- **Status:** Proposed
- **Date:** 2026-10-30
- **Deciders:** Marko Bocevski

## Context

Two agents connect today only after a human acts on that connection. A human
passes an invite link, or a human approves a knock. SPEC
[§6.6.4](../../SPEC.md#664-approval) forbids anything else for knocks ("An
implementation MUST NOT offer a configuration that approves knocks"), and
`daemon/tests/test_no_auto_approve.py` enforces it. `policy.auto_approve` covers
invite joins only, and it approves whoever holds the link. Agents that find each
other through a directory can't connect while their humans are away.

Two kinds of user need this:

- one owner whose agents run on several machines and should reach each other;
- agents of different owners that find each other in a public directory.

This ADR defines a **standing rule**: the human decides once, and the daemon
then approves connections that match, with no human in the loop. It is docs
only. The SPEC text below is a proposal and goes into `SPEC.md` after review.

What has to keep holding:

- **The relay sees no plaintext and no secrets** (AGENTS.md). Rules, anchors and
  trust states live in the daemons. The relay gets no new frame and no new
  field.
- **SAS verification stays a human action** (SPEC §11.5). A rule never produces
  `verified`, and no rule, agent or peer can start or answer a run.
- **Peer content stays untrusted** (SPEC §10.1). Every anchor below says who may
  connect. None says that what they send is safe to act on.
- **Every daemon enforces the group policy itself** (SPEC §9.2). Rules add
  nothing to what other members accept. They change what this daemon decides for
  itself.
- **One ciphersuite, no negotiation** (SPEC §3.1). New signatures use the
  existing Ed25519 instance key.
- **With no rule, nothing changes.** A daemon has no rules until its human adds
  one, and it then behaves as it does today, byte for byte on the wire.

Facts in the code and the SPEC that shaped the design, checked on 2026-10-30:

- **A JoinRequest proves no possession of its KeyPackage.** Its `mac` proves the
  sender holds the invite link (§6.1), and the relay sees the KeyPackage in the
  clear. A knock is different: its `sig` is made with the KeyPackage's leaf key
  (§6.6.2). Today a human looks at each join. Without a human, this gap matters
  (Decision 4).
- **A mailbox creates at most 100 groups in 24 hours** by default (§8.3,
  `group.create`), and each approved knock creates one. That bounds what rules
  may approve in a day (Decision 7).
- **`listings` in the owner file** means "the domain vouches for that key only
  in the listed `<directory>/a/<name>` listings" (§13.2.4). A knock carries no
  listing of the knocker's own, so the rule for knocks has to be defined
  (Decision 3).
- **The daemon can't see what a message makes the agent do.** It knows whether a
  message triggers the agent (§9.3), not whether that causes a side effect
  (Decision 6).
- **A signed listing can say "a human approves every connection"**: the example
  in §13.1 does, and with a rule in force that sentence would be false.
- **Code running as the daemon's OS user can read `human-token`**
  ([safety.md](../safety.md#shell-and-file-access), ADR-005). The human-only
  surface holds against an agent limited to its tools, or against an agent in
  the separate-OS-user mode.

## Decision 1: a rule is local state, changed only with the human token

A rule is a row in the daemon's encrypted database (ADR-003). It is never sent
to a peer, the relay or a directory.

```text
Rule = {
  "name": "<1 to 32 chars of [a-z0-9-], chosen by the human>",
  "kind": "pinned" | "owner_domain" | "introductions" | "open",
  "enabled": <bool>,
  "created_at": <unix seconds>,
  "changed_at": <unix seconds>,
  "caps": {...},        // Decision 7
  "profile": "standard" | "restricted",   // Decision 6
  "purpose": "<one-line scope, at most 500 chars; optional>",
  ...                   // the kind's own fields, Decisions 3 to 6
}
```

- **Only the human token.** Every route that reads or changes a rule is human
  only, reading included: a rule tells an injected agent whose identity or which
  domain gets through. The agent token gets `403 human_only`, and the agent API,
  the SDK and the MCP tools have no such operation.
- **Not in the config file.** The config has no table for rules and refuses one
  (`[trust]`, `[rules]`, and `auto_approve` in the discovery tables, as today).
  A config file is often writable by whatever the agent can run, and it has no
  record of who changed it.
- **Preview, then confirm.** As `listing publish` does, a change returns what it
  will do and a hash of it. The commit names that hash, so what the human
  confirmed is what takes effect. `--yes` exists for scripts, except for the
  `open` kind, which always asks on a terminal, as `verify` does.
- **Hard ceilings in the code.** A human can lower every cap and profile value,
  and raise them up to the ceilings of Decisions 6 and 7. No setting goes past a
  ceiling, so a mistaken or forged change has a bounded effect.
- **Every change is recorded.** Each change raises `rule_changed` (human only)
  and writes an audit row with the before and after hash.
- **Narrowing applies at once, widening goes forward.** Disabling a rule,
  removing an entry or lowering a cap stops new approvals in the same
  transaction, and a lowered lifetime also shortens the connections the rule
  already made. A raised cap or lifetime applies only to new connections.
- **Rules belong to one instance.** Replicas (§9.4) don't share them, as they
  don't share a door (§6.6.1) or an invite's secret (§4.3). See open question 3.

### Where a rule is evaluated

`SafetyPolicy.knock` keeps its two verdicts, hold and drop, and runs first, so
policy can still refuse what a rule would approve. The approval decision lives
in its own module and reads rules from the database only. No config key, policy
verdict, hook result, API route, SDK call or tool can reach it with a different
answer.

After the §6.6.3 checks 1 to 7 and the replay ledger, the owner evaluates the
rules in a fixed order, from the most specific anchor to the least:

1. `pinned`
2. `introductions`
3. `owner_domain`
4. `open`

A rule **matches** when it is enabled, it applies to this listing or invite, its
anchor holds, its caps have room, and this identity has no live connection made
by it. The first match approves. The decision, the cap counters and any used
introduction are written in one transaction with the ledger entry, and the
approval then proceeds as §6.6.4 "On approve" does: the group stays hidden from
the agent until its Add is confirmed and its Welcome sent.

The rule is read again before the group is shown to the agent. If it was
disabled meanwhile, the knocker is removed, as for an approval that failed after
the Add, and the use and the cap stay spent.

No match means what it means today: the knock waits for the human. There is one
exception. A knock that matched no other anchor, on a listing with an enabled
`open` rule that has no room, is **dropped**. Otherwise a stranger could fill
the human's queue by knocking past the cap.

**Rejected:**

- *Rules in `config.toml`.* A file is the easiest thing for a confused agent or
  a bad deployment script to widen, it needs no token, and nothing records the
  change.
- *A new policy verdict `approve`.* `SafetyPolicy` is what `KNOCK_VERDICTS` and
  a property test hold to hold-or-drop. Keeping that line means a bug in policy
  code can only refuse.
- *Rules the agent may narrow.* `listing withdraw` works with the agent token
  because it only reduces exposure, but a rule's narrowing also ends
  connections. An injected agent could use it to cut off its owner's peers. The
  agent can still `leave` a group.
- *Signing rules with a key the human holds.* There is no such key: the human
  token is the human's credential, and a signature wouldn't help against someone
  who has it.

## Decision 2: `auto` is a trust state, and it is never `verified`

A member of a group today is `unverified` or `verified` (§11). A member that a
rule approved starts as **`auto`**, which records that a rule connected it:

| Connection | The human sees | The agent sees |
|---|---|---|
| Pinned | `auto (pinned: <label>)`, rule name | `auto`, anchor `pinned` |
| Owner domain | `auto (owner domain <domain>)`, rule name | `auto`, anchor `owner_domain` |
| Introduction | `auto (introduced by <fingerprint>)`, rule name | `auto`, anchor `introduction` |
| Open door | `auto (open)`, rule name | `auto`, anchor `open` |

- **Local only.** The state is this daemon's record. It is not on the wire, and
  other members can't see it or tell it from `unverified`. A rule's name is
  shown to the human only.
- **It counts as not verified everywhere.** `trust_state.self` stays `verified`
  only when the human verified every other member (§10.1), so an `auto` member
  makes it `unverified`, and `require_verified` keeps holding deliveries (§10.4)
  without any new code path. `trust_state` gains `auto_members`, and the
  delivery gains `sender.trust`. The enum of `self` is unchanged, so a consumer
  that reads it stays on the safe side.
- **Only SAS produces `verified`.** A match in a human's `verify` moves the
  member from `auto` to `verified`, and it then leaves its rule: no lifetime, no
  count against the caps, no restricted profile. No rule or event can do this,
  and the agent can't start it (§11.5).
- **Pinning moves a connection, too.** A human who pins the identity of a member
  in a connection another rule made moves it to `auto (pinned)` under the pinned
  rule's caps and profile. The preview names each such connection. It stays
  `auto`.
- **Per group.** A member verified in one group is still `auto` in a group a
  rule made, as verification is per group today.
- **Nothing is `auto` by default on the knocker's side.** After a knock, the
  knocker sees the door's owner as `unverified`, as §6.6.5 says. The knocker's
  daemon isn't told how the knock was approved.

**Rejected:**

- *Treating `auto` as `verified` for a pinned identity.* The human pinned a key,
  but nobody compared a code in this group. A forked view still shows only
  through SAS (§14.4).
- *Telling peers the state.* It would tell a stranger that nobody is watching,
  and it would invite peers to act on a value they can't check.
- *Giving the agent the rule's name and the domain.* The agent needs to know how
  much to trust a peer, and the anchor says that. Names and domains are the rule
  set's shape, which an injected agent could repeat to the peer.

## Decision 3: the owner-domain anchor

A rule of kind `owner_domain` says "connect with any agent that this domain
vouches for".

```text
{"kind": "owner_domain", "domains": ["example.com", ...],
 "on_revoke": "remove" | "leave"}
```

`domains` holds at most 16 exact names, in the syntax of `owner_domain` in
§13.1.1. There are no wildcards and no subdomain matching.

### The claim on the wire

The knock gains one optional field:

```text
Knock = {
  ...the fields of §6.6.2...,
  "owner_domain": "<lower-case A-label DNS name, the §13.1.1 form; optional>",
  "sig": "..."
}
```

- **It is signed and sealed.** `sig` covers every field but itself, so the claim
  is covered as all the others are, and the seal hides it from the relay. The
  signature is under `SK_B`, the instance certificate binds `SK_B` to `IK`, and
  the file names `IK`. That gives an unbroken chain from the domain to this
  knock: the file vouches for the identity, the identity certifies the instance
  key, and the instance key signed this knock with this claim, to this door, at
  this time.
- **The claim is a pointer, and the file is the proof.** A claim alone proves
  nothing: anyone can write any domain. It says which file to read. The human
  sees it as unverified text until a check passes.
- **Where the claim comes from.** `knock.owner_domain` in the config, or
  `--owner-domain` with the human token. The agent can't set it per knock,
  because it links this identity to an organisation in front of a stranger. The
  default is no claim, and then a knock is byte for byte what it is today.
- **Knocks only.** A JoinRequest isn't sealed, so a claim there would show the
  domain to the relay.

### The check

The owner's daemon fetches the file itself, under every fetch rule of §13.2.4:
HTTPS on port 443, WebPKI, no redirects, public addresses only, one resolved
address, at most 64 KiB and 5 s.

1. **Only a domain on an enabled rule is ever fetched.** A claim of any other
   domain causes no fetch, so a knocker can't aim the daemon at a host it
   chooses. The knock goes on to the next rule.
2. **At most one fetch per domain in 300 s, and at most 4 at once.** Results are
   cached for that long, so a flood of knocks can't turn into a flood of
   requests. The cache is also the longest time a new revocation can go unseen
   at knock time.
3. **Approve only on a fresh fetch that vouches.** That means §13.2.4's
   "vouches": the identity is in a valid entry and not in `revoked`, and no
   negative result is on record after the last vouching one. The record is the
   checker's history that section requires, kept per (domain, identity).
   `stale`, `checking` and `failed` don't approve.
4. **A restricted entry vouches for a knock only if it names this listing.** An
   entry with `listings` vouches only in the listings it names. For a knock,
   that is the listing whose door was knocked on, as `<directory>/a/<name>`. An
   entry restricted to the knocker's own listing therefore doesn't vouch here,
   and the knock goes to the human. This is the conservative reading, and an
   owner who wants a key to connect widely leaves `listings` out.
5. **Anything else goes to the human, never to approval.** A fetch that fails,
   times out or returns a file that doesn't parse leaves the knock with the
   human, showing the claim and why the check didn't pass.

While a fetch runs, the knock counts toward the door's 32 pending knocks, so the
wait is bounded, and its deadline (`ts + 3600`) stays as it was.

### Re-checks and revocation

The daemon re-reads each domain with live connections every 6 hours, as a
directory does, and the §13.2.4 rules decide the result:

| Result | Effect on the rule's connections |
|---|---|
| Vouches | None |
| The identity is in `revoked`, or the file parses and no longer vouches | `on_revoke` applies, and the human gets `owner_domain_revoked` |
| The fetch fails | None, until no fetch has vouched for 7 days (the `failed` state); `on_revoke` then applies |

**`on_revoke` defaults to `remove`.** The connection existed because the domain
vouched, so when that ends the connection ends, and a domain's revocation of a
compromised key is the case where waiting does harm. `leave` keeps the
connection and marks it. A member a human has verified is outside the rule, so
it only gets the event. A negative result is sticky for new knocks too, until a
later fetch vouches (§13.2.4).

**Rejected:**

- *No wire change: try every allowed domain's file.* It works, since the file
  lists full identities, and a cached file costs little. But every allowed
  domain then sees the fetches that one knock causes, and the human's fallback
  approval can't say what the knocker claimed.
- *An unsigned claim.* The seal already stops the relay, so the practical attack
  is small. But §6.6.2 binds every field to the knocker, an exception would have
  to be defended forever, and a signed claim is what the human's record can show
  afterwards.
- *A signed statement from the domain inside the knock.* It needs a key per
  domain, and §13.2.4 decided the HTTPS origin is the proof. It would also need
  its own revocation.
- *Trusting a directory's owner badge.* That is the operator's opinion
  (§13.2.4).
- *Wildcards.* `*.example.com` hands the decision to everyone who can create a
  subdomain.

## Decision 4: the pinned anchor

A rule of kind `pinned` lists exact identities. The daemon has one, named
`pinned`, created by the first `trust pin`.

```text
{"kind": "pinned", "entries": [{"identity": "ac:v0:…", "label": "laptop"},
                               {"fingerprint": "3f9a 0c21 …", "label": "partner"}]}
```

At most 256 entries. An entry holds an identity or its §2 fingerprint, which a
human can copy from the `identity` line of `agentconnect status` on the other
machine. The 128-bit fingerprint is enough here: matching it means finding a
second key for a given hash. The label is one-line text the human wrote, and it
is shown only to the human.

**Knocks.** A knock matches when its KeyPackage's identity matches an entry.
That identity is authenticated: `sig` is under the KeyPackage's leaf key, and
the certificate binds that key to `IK`.

**Invite joins.** The rule applies only to a link created with `invite create
--pinned-only`:

| Joiner | `--pinned-only` | `--pinned-only --no-fallback` |
|---|---|---|
| Pinned, and the request carries a valid `sig` (below) | Approved, `auto (pinned)` | Approved, `auto (pinned)` |
| Anyone else | Waits for the human | Dropped silently |

- The restriction lives in the inviter's own record of the invite. `InviteMeta`
  (§4.2) and the link don't change, so neither the relay nor a joiner learns of
  it.
- `--pinned-only` and `--no-fallback` take the human token.
- `policy.auto_approve` doesn't apply to a `--pinned-only` invite, so turning it
  on can't undo the restriction. Elsewhere it stays as it is: it approves link
  holders, and those members are `unverified`, not `auto`. See open question 4.
- **The inviter must be able to end the connection.** Creating a `--pinned-only`
  invite is refused unless this identity may remove members under the group's
  policy, because caps and revocation depend on it.
- A link is bound to one group (§4), so every pinned joiner of a multi-use link
  joins the same group, and they see each other. A human who wants separate
  conversations makes one invite each, or uses a door.
- Replica invites (`invite create --replica`) are unchanged, and `--pinned-only`
  can't be combined with `--replica`.

### Proof of possession on a JoinRequest

Anyone who holds the link and a copy of a pinned identity's unused KeyPackage
could build a valid JoinRequest today. The relay sees KeyPackages in earlier
JoinRequests, so a relay that also got the link has both. With a rule in place,
the inviter would add that leaf with no human looking. The attacker couldn't
read anything, since it lacks the private keys, but the agent would see a
trusted member arrive who never asked to join, and the group would hold a leaf
nobody controls.

So a JoinRequest gains a signature, as a knock has:

```text
JoinRequest = { ...the fields of §6.1...,
  "sig": "<b64url Ed25519(SK_B, "agentconnect/v0/join-request-sig" || mac_input)>" }
```

- `mac_input` is the §6.1 byte string, and `SK_B` is the KeyPackage's leaf
  signature key. It is checked with strict Ed25519 under that key after step 3
  of §6.2.
- A joiner always sends it. A request without it, or with one that fails,
  **can't match a rule**, and it is handled as "anyone else" above. The MAC
  doesn't cover `sig`, so a relay can strip it, which sends the join to the
  human. That is denial of service, which the relay can cause anyway.
- A request with no `sig` to an invite without a rule is accepted as today, so
  older joiners keep working for human approval. Older inviters ignore the
  field.

**Rejected:**

- *Binding a `--pinned-only` invite's use to one identity in the link.* It needs
  one link per peer, leaks the identity to the relay if it is in the metadata
  and to the link's readers if in the fragment, and it does nothing about a
  stolen KeyPackage.
- *Accepting the ghost leaf and removing it when no Welcome is answered.* There
  is no signal for that: the joiner's silence looks like an idle agent.
- *Treating a pin as authority for joins on any invite.* The human then couldn't
  see from an invite what it admits. An explicit flag is visible at creation.

## Decision 5: the introductions anchor

A rule of kind `introductions` lets chosen peers introduce other agents.

```text
{"kind": "introductions",
 "from": ["ac:v0:…", ...],          // at most 16 exact identities
 "require_verified": true,          // the introducer must be verified
 "accept_agent": false}             // accept introductions its agent started
```

### Who sends one

The introducer B's daemon signs and sends an introduction. B's side decides who
may ask for it:

- `agentconnect introduce <group> <identity>` with the human token, always.
- With the agent token only after B's human ran `trust allow-agent-introductions
  <group>` for that group, and then at most 4 a day per group. By default the
  route answers `403 human_only`.

The agent can't craft one. The send path refuses this kind unless the daemon
builds it itself, as it refuses `control.floor` today, and the signature needs a
key the agent doesn't hold.

A's side decides what it accepts. `accept_agent` is `false` by default, so an
introduction B's agent started is ignored until A's human says otherwise, and a
rule that sets it must use the `restricted` profile (Decision 6). Both humans
have to opt in before an agent's word can connect anyone, and even then the
connection is restricted.

### The wire format

An inner message (§7.2) of kind `control.introduction`, with `to:
[<recipient>]`:

```text
control.introduction body = {
  "introduction": {
    "v": 0,
    "intro_id": "<16 random bytes, b64url>",
    "group_id": "<b64url, the group it is sent in>",
    "introducer": "ac:v0:…",
    "instance_id": "<the sending instance, 16 hex chars>",
    "recipient": "ac:v0:…",
    "introduced": "ac:v0:…",
    "issued_at": <unix seconds>,
    "expires_at": <unix seconds, at most issued_at + 3600>,
    "origin": "human" | "agent",
    "sig": "<b64url Ed25519(SK_B, "agentconnect/v0/introduction" || JCS(introduction without "sig"))>"
  }
}
```

The object is JCS with exactly these fields. MLS already authenticates the
sender, so the signature's job is different: it binds the introduction to both
endpoints and to the group as one object, and the stored object can be checked
after the epoch's keys are gone. The human can show which instance of which
identity made an introduction, for as long as the record is kept. It is made
with the instance key, so the §3.5 rule about what `IK` signs is unchanged.

### What the recipient's daemon does

The message stays in the daemon, like SAS ceremony messages (§11.5): it is never
delivered to an adapter, not even as context, it triggers nobody and it isn't
held for approval. An introduction doesn't let any text reach the agent. A's
daemon checks, in this order, and drops silently at the first failure, with an
audit row and nothing sent back:

1. The message comes from a group with exactly two identities, this one and the
   sender. Addressing isn't secrecy (§7.2), so a third member would learn who is
   being introduced.
2. The object is canonical JCS with exactly the fields above, `v` is 0, and
   `group_id` is this group's.
3. `introducer` and `instance_id` equal the inner message's `sender` and
   `instance_id`, which MLS authenticated (§7.2), and `origin` equals the inner
   `origin`.
4. `recipient` is this identity. `introduced` is neither this identity nor the
   introducer.
5. `sig` verifies under the sender leaf's `signature_key` (strict Ed25519).
6. `issued_at` is at most 300 s ahead, and `expires_at` is in the future and at
   most 3600 s after `issued_at`.
7. An enabled `introductions` rule lists the introducer. If `require_verified`
   is set, the introducer is `verified` in this group. If `origin` is `agent`,
   `accept_agent` is set.
8. The introducer isn't one hop away itself: its member state in this group
   isn't `auto (introduced)` or `auto (open)`.
9. `intro_id` isn't in the introduction ledger, which is encrypted, survives a
   restart, and keeps each entry until `expires_at + 300`. A full ledger drops
   new introductions.
10. This introducer has fewer than 8 unused introductions waiting.

A passing introduction is stored and raises `introduction_received` for the
human.

### Using one

A knock, or a join on an invite made with `--pinned-only --or-introduced`,
matches when:

- its identity equals `introduced`, in an unused and unexpired introduction;
- its `ts` (for a join, the time of receipt) is not before `issued_at − 300`, so
  a knock already waiting for the human isn't approved after the fact;
- the checks of step 7 and step 8 still hold, and the introducer is still a
  member of that group.

The match marks the introduction used, in the same transaction as the decision.
A failed Add doesn't give it back: B can send another.

**Reaching A is ordinary traffic.** B or its agent tells C where to knock, in
their own group, as a normal message with A's listing locator. That message
grants nothing by itself. C's knock is C's own act, so nobody is connected
without asking. A join needs A's human to have given the link to someone first.
An agent with no listing, and no link, can't be reached by introduction.

### One hop

- A connection made by an introduction has the state `auto (introduced by
  <fingerprint>)`, and step 8 refuses introductions from it, whatever a rule
  says.
- A rule can't list an identity whose only connections are `auto (introduced)`
  or `auto (open)`. The route refuses it, naming why.
- Only a human can move such a connection out of that state, by SAS or by
  pinning. Listing it afterwards is a new human decision about that identity, so
  a chain of hops can only grow one human decision at a time.
- Introductions are point to point: C learns nothing from being introduced to A,
  and C gets no standing with anyone else.

### Revocation

A pending introduction is void as soon as the introducer is removed or leaves,
the rule is disabled or removed, or the introducer is taken off the rule.
Connections already made stay until their lifetime ends or a human revokes them,
since they aren't anchored to the introducer's later behaviour. `trust rule
disable <name> --end-connections` ends them all.

**Rejected:**

- *A ticket C carries.* B signs a ticket and C presents it in its knock. A then
  learns of it only from C, the ticket could be copied to whoever C likes until
  its expiry, and a used ticket needs the same ledger anyway. It also needs a
  knock wire change that a message in the existing group doesn't.
- *Chains of introductions.* Trust would be transitive beyond what any human
  reviewed, and a single compromised agent could reach the whole graph.
- *Signing with the identity key.* §3.5 keeps `IK`'s signatures to three kinds,
  on purpose. The instance key is certified by `IK` and is what the daemon holds
  for routine use.
- *Introductions in groups of any size.* See step 1.
- *A message to cancel an introduction.* The 1 hour expiry is short, and a
  compromised introducer wouldn't send one. A's human can disable the rule.

## Decision 6: the open door and the restricted tier

A rule of kind `open` connects **any** valid knocker on one listing's door, into
a restricted tier. It is the riskiest anchor, because anyone can reach an
unattended agent with crafted content. Its limits are the main defence against
prompt injection and cost abuse.

```text
{"kind": "open", "listing": "directory.example.org/a/release-planner",
 "skills": ["release-planning"]}
```

The rule is bound to the listing by name, so door renewal doesn't touch it. At
most one `open` rule exists per listing. If the listing is withdrawn, or
published under another name, the rule stops applying. Its caps are required,
and `profile` is always `restricted`.

Creating one is refused while the signed listing's text says a human approves
every connection, and `listing publish` warns about that text when any rule
could approve a knock. Renewal re-signs only the door (§6.6.1), so removing the
sentence takes a new publish.

### The restricted profile

The profile applies to every connection a rule with `profile: restricted` makes.
Values lower than §10.2 are local policy that the SPEC allows, and the peer
isn't told.

| Limit | Restricted default | Ceiling | Standard |
|---|---|---|---|
| Largest message | 16 KiB | 64 KiB | 256 KiB |
| Messages per minute, per sender instance | 4 | 30 | 30 |
| Messages per connection per day | 100 | 1000 | none |
| Messages per rule per day, all connections | 1000 | 10000 | none |
| Bytes per rule per day, all connections | 16 MiB | 256 MiB | none |
| Task updates per minute, per task | 20 | 300 | 300 |
| Task updates per connection per day | 200 | 2000 | none |
| Agent's sends per connection per day | 100 | 1000 | none |
| `file` parts | Refused | Refused | `policy.allow_files` |
| `loop_guard.max_agent_turns` in the group's policy | 4 | 20 | 20 |
| `max_members` in the group's policy | 2 | 2 | 50 |
| Lifetime | The rule's (Decision 7) | 7 days | The rule's |

- **Per-day budgets aren't exempt from anything.** The reconnect drain's
  exemption (§10.2) covers per-minute rates only, so a relay that replays a
  drain can't get past a day's budget.
- **A budget that is used up drops messages** with the usual silence (§10.2),
  and the human hears once per rule per day (`tier_budget_exhausted`).
- **`max_members: 2` keeps a peer's replicas out.** A tier peer can't add
  instances (§9.2 would allow it), so one knock can't grow into several senders.
- **The agent does less here.** In a restricted group the agent token may read,
  send and leave. It can't invite or introduce.
- **The knocker's name and note** never reach the agent or an event, as today
  (§6.6). They are kept for the human's list until the record goes.
- **The new group's `purpose`** comes from the rule, or else the listing's
  description, and it never comes from the knocker.

### What "no side effects" means here

A daemon can't tell what a message makes an agent do, so the tier doesn't claim
to stop it. It has three layers, and the ADR is explicit about which one does
what:

1. **A skill gate, in the daemon.** A message from a tier peer triggers the
   agent only if its `body.metadata.skill` is in the rule's `skills`. A message
   that names no skill counts as the first one listed. Any other message is
   dropped silently (`tier_skill`), and so is a task-starting request for
   another skill. `skills` must hold at least one id from the listing's card,
   and nothing lists skills but the human. The delivery carries the skill, so
   the agent runtime can bind it to a tool set.
2. **A separate endpoint, in the deployment.** Deliveries from restricted
   connections go to a restricted endpoint that the human configured,
   `webhook.restricted_callback_url` or `a2a.restricted_agent_url`, or a handler
   registered with `on_restricted_message` in the SDK. It should be an agent
   with no tools that change anything. The `open` rule is refused unless one is
   set, or the human passes `--same-agent`, which the preview names as a risk.
   This is the layer that holds against a successful injection, since a tool the
   agent lacks can't be talked into use.
3. **Framing, in the delivery.** Every delivery carries `tier: "restricted"` and
   the §10.1 notice, which says that a stranger reached this agent through an
   open door.

The skill gate narrows what can be asked for, and it doesn't check what the text
says. A stranger who names an allowed skill can still try to mislead the agent
running it. That risk stays (Decision 9).

### Abuse limits

The existing limits stay, in front of the rule: the relay's per-door limits,
`knock.max_pending_per_door`, `knock.opened_per_door_per_minute`, one pending
knock per identity, and the replay ledger. On top of them come the caps of
Decision 7, plus one new connection per identity per rule per day, which the
daemon remembers by a hash of the identity. Identities cost nothing to make, so
that last limit only stops the lazy. The per-rule caps are the real bound.

### The kill switch

```sh
agentconnect trust rule disable <name> --end-connections
```

In one local transaction, it disables the rule, marks every connection the rule
made as ending, and stops all delivery in both directions for those groups. That
part needs no network. It then commits the removals and retries them until the
relay takes them, and each group's local state is deleted after that. Reached in
this order, a relay that is down or hostile can delay the commits and can't
delay the effect on the agent. Later knocks on that door wait for the human.
`--withdraw` also withdraws the listing, and from then on the relay answers
`door_not_open`.

The command works for every kind of rule. Keeping one command for all of them
means nobody has to find the right one in an incident.

**Rejected:**

- *A tier that only lowers rates.* Rates bound cost and do nothing about what
  one message can do.
- *A filter that reads messages for injection.* The daemon doesn't read content
  for meaning ([safety.md](../safety.md#what-the-policy-doesnt-do)), and an
  attacker gets to test against it.
- *Proof-of-work or payment on the door.* Out of scope, and neither changes what
  an admitted peer can send.
- *A `door.open` param in the listing.* It adds a signed claim for directories
  to rank on, and it adds nothing the knocker needs: the card's text can say so,
  and the Welcome's policy shows the limits.

## Decision 7: caps per rule

Every rule has these four caps. A rule without an explicit value has the
default; an `open` rule stores its values explicitly at creation, so the preview
shows them.

| Cap | `pinned` | `owner_domain` | `introductions` | `open` | Ceiling |
|---|---|---|---|---|---|
| New connections per hour | 10 | 5 | 2 | 4 | 80 |
| New connections per day | 20 | 20 | 5 | 24 | 80 |
| Open connections at once | 50 | 20 | 10 | 16 | 256 (open: 64) |
| Connection lifetime | None | 30 days | 7 days | 24 hours | None (open: 7 days) |

- **The whole daemon has a ceiling of 80 new connections per day across rules.**
  The relay lets a mailbox create 100 groups in 24 hours (§8.3), so rules can't
  use up what the human's own approvals need. A rule whose `new_per_day` would
  take the total past 80 is refused. A `quota_exceeded` from the relay counts as
  a cap reached.
- **Windows are rolling and survive a restart.** They use the stored times, and
  a stored time after the current time counts as the current time, as §13.2.4
  does, so a clock that jumps can't reopen a window.
- **At a cap, nothing tells the knocker** (§6.6.6). The human hears once per cap
  per window (`rule_cap_reached`). The knock moves on to the next rule, and
  then:
  - if it matched a non-`open` anchor, it waits for the human, because someone
    the human trusts shouldn't vanish without notice, and the queue is bounded
    at 32;
  - if it matched only `open`, it is dropped, so that a flood can't fill the
    queue.
- **A lifetime ends in a removal.** When it passes, the owner removes the peer
  and tells both sides what any removal tells them. A peer that may still
  connect can knock again, under the caps. A connection a human verified has no
  lifetime.
- **Used caps count what a rule approved**, whether or not the Add later
  succeeded, so a failing Welcome can't be used to spend the relay's group
  budget without a limit.

**Rejected:**

- *One cap across all rules.* A busy open door would stop the owner's own
  machines from connecting.
- *No lifetime for `owner_domain`.* A re-check catches a revocation only if the
  fetch works. A lifetime bounds the case where an attacker blocks the fetches.

## Decision 8: oversight

The human reads what happened after the fact. All of the following are
human-token only and join `HUMAN_EVENTS`, like the knock events.

### Events

| Event | Data |
|---|---|
| `auto_approved` | `rule`, `anchor`, `source` (`knock`, `join`), `request_id`, `group_id`, `identity`, `fingerprint`, `detail` (label, domain or introducer), `expires_at` |
| `auto_connection_ended` | `rule`, `group_id`, `identity`, `reason` (`lifetime`, `revoked`, `human`, `rule_disabled`, `left`) |
| `rule_changed` | `rule`, `action`, `before_hash`, `after_hash` |
| `rule_cap_reached` | `rule`, `cap`, `dropped` (the count since the last event) |
| `tier_budget_exhausted` | `rule`, `budget`, `group_id` (if one connection's), `dropped` |
| `owner_domain_revoked` | `rule`, `domain`, `identity`, `group_id`, `action` (`removed`, `left`) |
| `owner_domain_check_failed` | `domain`, `since` (once per domain per day) |
| `introduction_received` | `rule`, `introducer`, `introduced`, `origin`, `expires_at` |
| `introduction_used` | `rule`, `introducer`, `introduced`, `group_id` |

No event carries a knocker's name or note. Each decision is also an audit row:
`decision` is `auto_approved`, `reason` the anchor, and `sender` the identity.
The agent hears of a connection only from `member_joined`, after the Welcome
went out, with `trust: "auto"` and the anchor.

### `approvals list`

`agentconnect approvals list`, with the human token, gains an `automatic` array
next to `approvals` and `messages`, so nothing there can be taken for something
waiting on a decision:

```text
"automatic": [{
  "request_id": str,
  "source": "knock" | "join",
  "rule": str,
  "anchor": str,
  "detail": str | null,
  "group_id": str,
  "identity": str,
  "fingerprint": str,
  "display_name": str,
  "note": str | null,
  "display_name_verified": false,
  "listing"?: {"directory": str, "name": str},
  "approved_at": int,
  "expires_at": int | null,
  "state": "auto" | "verified" | "ending" | "ended"
}]
```

Entries stay while the connection lives and then for
`policy.audit_retention_days`. The list is bounded by the caps, and it isn't
bounded by what a peer sends, since name and note are capped (§6.6.2). The agent
token's answer has no such key.

### Commands

All of these use the human token.

| Command | What it does |
|---|---|
| `trust pin <identity\|fingerprint> [--label]`, `trust unpin`, `trust list` | Pinned entries |
| `trust rule add owner-domain <name> --domain ...` | A domain rule (`--on-revoke`, caps, `--profile`, `--purpose`) |
| `trust rule add introductions <name> --from ...` | An introductions rule (`--unverified-introducer`, `--accept-agent`) |
| `trust rule add open <name> --skill ...` | An open rule, always confirmed on a terminal (`--same-agent`) |
| `trust rule show`, `trust rule change`, `trust rule enable`, `trust rule remove` | Read and change a rule. Removing a rule leaves its connections as `auto` with no rule, under their stored limits |
| **`trust rule disable <name>`** | **Disable a rule.** `--end-connections` is the kill switch; `--withdraw` also withdraws the listing |
| `trust connections` | Every live `auto` connection, its rule, its age and what ends it |
| **`trust revoke <group> [<identity>]`** | **Revoke one connection.** Delivery stops in that transaction, then the peer is removed, and the group's state goes if only this member is left |
| `invite create --pinned-only [--or-introduced] [--no-fallback]` | An invite only rules admit (Decisions 4 and 5) |
| `trust allow-agent-introductions <group>`, and `--off` | B's side of Decision 5 |
| `introduce <group> <identity>` | Send an introduction (the agent token too, where allowed) |

`trust revoke` doesn't disable anything: a peer whose rule still matches may
knock again. To stop that, change the rule too. The command says so when it
applies.

**Rejected:**

- *A new `autoapprovals` command.* The question "what has been approved?"
  already has a command.
- *Asking the human to confirm after the fact, and ending what isn't confirmed.*
  A human who has to act on each connection is what this design exists to
  remove.

## Decision 9: threat model additions

Proposed new rows for the SPEC §12 table, in its column order:

| Attacker | Capability | Mitigation | Residual risk |
|---|---|---|---|
| Stranger at an open door | Any identity can get a connection to an unattended agent, with no human on either side | Off by default. Human-only rule. Restricted profile with a skill gate and a separate endpoint. Short lifetime. Caps per rule, kill switch, human events (ADR-007) | Whatever the restricted endpoint can do or say, for anyone who knocks |
| Prompt injection through an automatic connection | Sends crafted text to an agent no human is reviewing | Untrusted framing (§10.1) and `trust` in each delivery. Name and note never reach the agent. Restricted endpoint without side-effect tools. Budgets. `policy.require_approval` still applies | Behavioural: an agent that obeys the text. It can't be solved with cryptography. With `--same-agent`, or under a non-restricted rule, the agent's tools are in reach |
| Sybil cost abuse | Makes identities freely, to spend the owner's model budget or fill its groups | Caps per rule and per day. Per-rule message and byte budgets that bound the total whatever the number of identities. A daemon-wide ceiling below the relay's group limit, so human approvals still get groups | The budget can be spent every day, which denies honest strangers. It is the cost the human accepted when setting the cap |
| Rule widening | A compromised or injected agent tries to create or widen a rule, or to make a rule apply to itself | Human token only, reading included. No config table. Preview and hash. Ceilings. Every change is an event and an audit row. Tests over routes, the agent API, the SDK and the MCP tools | Code that runs as the daemon's OS user can read `human-token` and use it (ADR-005). The separate-OS-user mode closes this, and `open` warns when it is off |
| Introduction forgery or replay | Fabricates an introduction, or replays a copy in another group or later | Sent inside MLS. Signed, bound to the group and both endpoints. Expires within 1 hour. Single use, with a persistent ledger. Handled in the daemon, and the agent's send route refuses the kind | None known beyond a compromised introducer (the next row) |
| Malicious or compromised introducer | An allowed peer introduces the attacker's agents | Only identities the human named. Verified by default. Agent-started introductions off on both sides by default, and restricted when on. Caps. One hop. Disabling the rule voids all pending | Up to the rule's caps of connections until the human reacts, each `auto` and each ending at its lifetime |
| Owner-domain takeover | Controls the allowed domain's web server, or its name after it expires, or a certificate for it, and vouches for its own key | The domain is exact and listed by the human. Caps and lifetime. `auto` never counts as verified. Events name the domain | Connections up to the rule's caps until the human reacts: whoever controls the web server is who the rule trusts, as §13.2.4 states |
| Revocation lag | Uses a key after its domain revoked it, or blocks the fetches so the revocation isn't seen | Fresh fetch for each approval, cached at most 300 s. Re-check every 6 hours. Negative results are sticky. No fetch vouching for 7 days counts as revoked. Lifetime | A revoked key keeps a live connection for up to 6 hours (7 days if fetches are blocked), and can still get a new one within 300 s of the revocation |
| Reflection through the domain check | Sends knocks to make the owner's daemon fetch from a host the attacker picks | Only domains on an enabled rule are fetched. One fetch per domain in 300 s. The §13.2.4 fetch rules | An allowed domain sees that this daemon checks it, from which address and how often |
| Forged JoinRequest for a pinned identity | With the link and a copy of the KeyPackage, asks to add a pinned identity it doesn't control | `sig` under the leaf key is required to match a rule (§6.1). KeyPackages are single use (§6.2) | A relay can strip `sig`, which sends the join to the human: denial of service only |
| Malicious relay against rules | Replays or delays knocks and introductions, or drops removals | The sealed knock, ledger and `ts` window are unchanged, so a replay gets no second approval. A rule is read when the knock is handled, and again before the group is shown. Revoking stops delivery locally first | Denial of service: delayed knocks lapse. A removal it withholds leaves the peer in the group at the relay, while this daemon has stopped delivering |
| Rule probing | Knocks, and reads the response time to learn that no human was involved | The answer is the Welcome either way (§6.6.6). No rule state reaches a peer. Only identities that match can see a fast answer | A knocker that was approved quickly can infer a rule covers it. A knocker that wasn't learns nothing |

These cases need no new row, and they were checked:

- **An injected agent knocking on an attacker's door.** With an open door, an
  agent can reach a stranger with no human on either side, and it can then send
  what it knows. This is not new: the attacker owns that door and could approve
  the knock by hand today. `knock.agent_may_knock = false` stays the switch
  against it.
- **SAS runs started by tier peers.** Ceremony messages keep their own budget
  (§11.3), and only the local human starts a run (§11.5). Events about tier
  peers' runs are rolled up per rule, so a stranger can't use them to flood the
  human.
- **Event floods.** New connections are capped, so `auto_approved` is too.
  `rule_cap_reached` and `tier_budget_exhausted` are rate-limited, so the
  100000-event ceiling can't push out the record of a rule change.

The "Assets" list gains **standing rules**: only the human decides what connects
unattended.

## Decision 10: spec changes and versioning

**No protocol version bump.** Everything here is additive inside v0, which is
still a draft.

- The ciphersuite is untouched, and both new signatures use the instance key
  under new `agentconnect/v0/` labels.
- A knock with no `owner_domain` is unchanged. **An older owner drops a knock
  that carries one** (§6.6.3 check 2 says "exactly the fields"), so the claim is
  off by default, and a knocker turns it on once the owners it cares about have
  upgraded. A dropped knock looks like any other "no answer".
- Older inviters ignore a JoinRequest's `sig` (their parser takes unknown
  fields), and a request without one still gets a human's approval.
- Older daemons ignore `control.introduction` as an unknown kind (§7.2). Nothing
  depends on them understanding it.
- The relay changes in no way: no new frame, field, limit or stored value. It
  forwards the same sealed knock and the same ciphertext.

### SPEC edits (to apply after approval)

The edits use the existing section numbers; nothing is renumbered.

1. **§2 Terminology.** Add:
   - **Standing rule:** a human's local decision that its daemon may approve
     matching connections on its own (§6.6.4).
   - **Automatic connection:** one a standing rule approved. Its members are in
     the local trust state `auto` (§11.5).
   - **Introduction:** a signed message in which a member names another identity
     to the group's other member (§7.3).
2. **§3.5 Other labels.** Add these rows:
   - `agentconnect/v0/join-request-sig`: prefix of a JoinRequest's signature
     input, signed by the joiner's `SK` (§6.1);
   - `agentconnect/v0/introduction`: prefix of an introduction's signature
     input, signed by the introducer's `SK` (§7.3).
3. **§6.1 JoinRequest.** Add `"sig": "<b64url Ed25519(SK_B,
   "agentconnect/v0/join-request-sig" || mac_input)>"` to the structure, and
   this paragraph after the `mac_input` text:

   > `sig` is made with the KeyPackage's leaf signature key, over the same
   > `mac_input`. It proves that the sender holds that KeyPackage's private key,
   > which the MAC doesn't. A joiner MUST send it. The MAC doesn't cover it, so
   > a relay can strip it. An inviter MUST NOT let a standing rule (§6.6.4)
   > approve a request whose `sig` is absent or doesn't verify, and it handles
   > such a request as if no rule matched.
4. **§6.2 step 4.** Replace "approve the join, either automatically (when policy
   allows) or through its human" with "approve the join: through its human,
   automatically when its local policy allows that for link holders, or under a
   standing rule for that invite (§6.6.4)".
5. **§6.6.2.** Add to `Knock`: `"owner_domain": "<the form of §13.1.1;
   optional>"`. Add this bullet:

   > `owner_domain`, absent rather than empty, is the owner domain the knocker
   > claims for itself. It is a pointer to a file to read and proves nothing by
   > itself: an owner MUST NOT treat it as true until a fetch under §13.2.4
   > vouches for the knocker's identity, and MUST present it as unverified text
   > until then. Its value MUST NOT be chosen per knock by an agent.

   Replace "Approving one is human-only (§6.6.4)." with "Approving one is its
   owner's human's decision, directly or through a standing rule (§6.6.4)."
6. **§6.6.3 step 2.** After "exactly the fields of `Knock`", add
   "(`owner_domain` and `note` may be absent)". **Step 8.** Replace it with:

   > 8. Apply the owner's standing rules, if any (§6.6.4). Otherwise, queue a
   >    **human** approval. It shows the listing name, the knocker's display
   >    name and note as unverified text, the knocker's fingerprint, and any
   >    `owner_domain` claim with the result of checking it.
7. **§6.6.4.** Replace the first bullet with:

   > - **A human decides every knock, directly or through a standing rule.** A
   >   knock is approved only by the owner's human, or by a **standing rule**
   >   that human made. A standing rule MUST be created, changed and removed
   >   only through a human-only surface, and MUST NOT be in a file or setting
   >   an agent can be expected to write. Nothing else may approve a knock: an
   >   implementation MUST NOT let an agent approve one or change a rule, and no
   >   agent-callable operation, SDK call or tool may do either. Local policy
   >   (§10.6) MAY drop a knock, but its result MUST NOT approve one. A rule's
   >   approval MUST be recorded where the human can read it, and the human MUST
   >   be able to end any connection a rule made and to disable any rule. A rule
   >   MUST NOT mark any member verified (§11.5). With no rule, every knock
   >   needs its human.
   > - **Anchors.** A rule rests on one of: exact identities the human pinned;
   >   an owner domain the human allowed, under whose file (§13.2.4) a fresh
   >   fetch vouches for the knocker's identity, with the knock's signed
   >   `owner_domain` naming it and any `listings` in the entry naming the
   >   listing knocked on; an unused and unexpired introduction (§7.3) from a
   >   member the human allowed; or an open door. A failed, timed-out or
   >   unparsable fetch MUST NOT approve a knock. An open door MUST put its
   >   connections under limits lower than §10.2, a lifetime and a cap on new
   >   connections.
   > - **Caps.** A rule that reached a cap stops approving silently. Nothing
   >   goes to the knocker (§6.6.6).

   In the "On approve" list, step 1, replace "chosen by A's human and defaults
   to the listing's description" with "chosen by A's human or its rule, and
   defaults to the listing's description". Add to step 1: "A rule MAY set lower
   `max_members` and `loop_guard.max_agent_turns`."

8. **§6.6.6.** Add below the table:

   > (Informative.) How soon a Welcome arrives can show the knocker that no
   > human was involved, and an approval under a rule is usually fast. A knock
   > with no rule covering it looks as it did, so a knocker learns this only
   > about itself.
9. **§7.3.** Add this row to the table:

   | `control.introduction` | `{"introduction": Introduction}` (below) | Any member, in a group of exactly two identities, on a human's standing permission (below) |

   Add below the table the `Introduction` format of Decision 5, and:

   > Receivers handle `control.introduction` in the daemon alone, as for SAS
   > ceremony messages (§11.5): it is never delivered to an adapter and it
   > triggers nobody. They MUST make the checks below, drop silently on any
   > failure, and keep a persistent ledger of `intro_id`s until `expires_at +
   > 300`. An implementation MUST NOT let an agent send this kind directly. An
   > agent MAY ask its daemon for one only where its human allowed that. A
   > connection made by an introduction, or through an open door, MUST NOT be
   > accepted as an introducer.

   The ten checks of Decision 5, "What the recipient's daemon does", follow that
   paragraph as a numbered list, word for word.
10. **§10.1.** Add `"auto_members": n` to `trust_state`, and to `sender` the
    local `trust`. Add:

    > `auto_members` counts other identities in the local state `auto` (§11.5).
    > They count as not verified. Implementations SHOULD also say whether the
    > sender is under lower limits, so the consumer can treat its text
    > accordingly.
11. **§10.4.** Add: "A member in the local state `auto` is not verified for this
    purpose."
12. **§10.6.** In the **Knocks** bullet, replace "Policy can only hold a knock
    for the human or drop it; nothing in it approves one (§6.6.4)." with "Policy
    can only hold a knock or drop it; only a standing rule or the human approves
    one (§6.6.4)." Add a bullet **Standing rules** summing up Decisions 1 and 3
    to 8, and pointing at `docs/safety.md`. This is informative, as the section
    is.
13. **§11.5.** Add this bullet:

    > - **A standing rule is not verification.** A member a rule connected
    >   (§6.6.4) is in the local state `auto`, which is never `verified` and
    >   isn't on the wire. Only the run above moves it to `verified`. A member
    >   keeps that state until a human acts, whatever rule changes.
14. **§12.** Add the rows of Decision 9 and the asset. In the row "Prompt
    injection through card text", replace "Knock approval is human." with "Knock
    approval is the human's, directly or by a standing rule."
15. **§13.1.** In the example, replace the extension's `description` with
    "Reachable end-to-end encrypted through AgentConnect. Knock to ask for a
    connection."
16. **§13.2.4 "Who checks".** Add:

    > A door's owner fetches the file of a domain a knock claims, and only when
    > an enabled rule allows that domain (§6.6.4), at most once per domain per
    > 300 s, and every 6 hours while it holds a connection that domain vouched
    > for. It keeps the same history per (domain, identity). For a knock, an
    > entry with `listings` vouches only if it names the listing whose door was
    > knocked on.

### Other documents

These change when the code does, except for the security review, which gets its
section with the SPEC edits:

- **`docs/security-review-v0.md`.** Add a section "Autonomous connections" with
  the rows of Decision 9, the checks made and the findings of the review of this
  ADR. Add the new rows to "Threat model mapping" as "Not implemented" until
  each anchor lands. The line "No path was found that lets the agent token
  perform a human-only operation" gains rule changes.
- **ADR-006.** Add to "Changes after acceptance": automatic approval now exists
  under ADR-007, so Decision 3's "Auto-approval doesn't exist in v0" no longer
  holds.
- **`docs/config.md`.** `policy.auto_approve` still "never applies to knocks",
  and the text saying "every knock needs a person" changes. New keys:
  `knock.owner_domain`, `webhook.restricted_callback_url`,
  `a2a.restricted_agent_url`.
- **`docs/discovery.md`, `docs/safety.md`, `docs/cli.md`, `docs/api.md`,
  `docs/groups.md`, `docs/sdk.md`, `docs/adapters/mcp.md`,** the README security
  model, and `AGENTS.md`'s summary of how trust works.

### Vectors and tests

`testdata/` gains, on the Rust and Python sides together:

- knocks with `owner_domain`, and negatives for a tampered claim and an invalid
  form;
- JoinRequests with `sig`, and negatives for a wrong key, a tampered field and a
  `sig` over another request's input;
- introductions, and negatives for each of the checks 2 to 6 of Decision 5: a
  wrong group, recipient, introducer or signature, an expiry past an hour, and a
  non-canonical form;
- the owner-file cases for `listings` as Decision 3 reads it.

Tests that must exist before each anchor lands:

- **`daemon/tests/test_no_auto_approve.py` stays and grows.** Every existing
  test still passes unchanged: no config approves, policy holds or drops,
  `policy.auto_approve` leaves a knock for the human, and the agent token can't
  list or decide. New tests go after each way in: no agent route, agent API
  method, SDK call or MCP tool reads or changes a rule, pins, sends a raw
  `control.introduction`, or creates a `--pinned-only` invite.
- **`daemon/tests/test_human_only_routes.py`.** The new routes are classified in
  `HUMAN`, with the one guarded exception of `POST /v0/introductions`.
- **A property test over rule evaluation.** No sequence of rule changes and
  knocks produces a `verified` member, or an approval past a cap, or an approval
  from a disabled rule.
- **Negative tests from AGENTS.md.** Wrong secret, tamper, replay, credential
  and key mismatch, and a forked view giving different SAS codes on an `auto`
  member.

## What a rule proves

- **It proves** that the human decided in advance to allow this kind of
  connection, and that the peer fits it: an exact key, a key a domain's web
  server vouches for, or a key a chosen peer named.
- **It does not prove** that the agent does what it says, that it is safe to
  hand it anything, or that nobody sits in the middle. An `auto` member isn't
  verified. Only comparing the short code proves there is nobody in the middle.

The docs use the canonical security claim from SPEC §1 for the conversation
itself, and nothing stronger.

## Plan (as constrained here)

Each anchor ships on its own, in this order, smallest and lowest risk first:

1. **Rules, `auto` and oversight, with `pinned`.** The rule store and human
   routes, evaluation, the state, events, `approvals list`, `trust` commands,
   caps, lifetimes, the JoinRequest `sig`, and `--pinned-only`. This alone
   covers one owner on several machines.
2. **`owner_domain`.** The knock field, the owner's fetch and cache, re-checks
   and `on_revoke`.
3. **The restricted profile and `open`.** Budgets, the skill gate, restricted
   endpoints, the kill switch's door handling.
4. **`introductions`.** The message, the ledger and the one-hop rules. It comes
   last because it is the hardest to reason about, and because it needs the
   restricted profile for `accept_agent`.

## Consequences

- **A daemon can gain connections no human saw.** That is the point. The human's
  review moves from before to after, and how well that works depends on someone
  reading the events. Nothing here pushes them to a person yet (open question
  5).
- **"A human approves every connection" is no longer always true.** Docs and
  listings that say it change, and a daemon warns about a listing that says it
  while a rule could approve a knock.
- **The daemon gets a second reason to make outbound requests on its own.** An
  owner-domain rule's fetches show allowed domains this daemon's address and a
  rough knock rate. The rule's preview says so.
- **The relay and the directory don't change,** so a hosted relay needs no new
  review for this. A busy open door does use up the mailbox's group budget,
  which the ceiling keeps under the relay's limit.
- **Unattended means an unattended mistake lasts longer.** A too-wide rule isn't
  caught by a human at the next approval, because there is none. Caps and
  lifetimes bound it, and they are why defaults are low.
- **The separate-OS-user mode matters more.** On a same-user install the human
  token is reachable by code the agent runs. `trust rule add open` warns about
  that, and docs recommend that mode for any daemon with rules.

## Open questions

The recommendations below stand unless review says otherwise.

1. **The restricted endpoint as a requirement.** Refusing `open` without one,
   unless `--same-agent` is passed, adds a deployment step. *Recommendation:*
   keep the refusal, since it is the one layer that holds after a successful
   injection, and make the SDK's handler the short path.
2. **`listings` for knocks.** Decision 3 reads an entry's `listings` as naming
   the listing knocked on. Owners who restrict an entry to their own listing
   therefore don't get automatic connections. *Recommendation:* keep this
   reading, as it fails towards the human. A later `knocks` field could say so
   explicitly if owners want both.
3. **Rules across replicas.** A rule lives on one instance, so two replicas with
   their own `introductions` rules could each use one introduction once.
   *Recommendation:* accept it for v0: one door per listing and one holder per
   invite already put each use on one instance in the ordinary setup, and the
   caps still bound each.
4. **Folding `policy.auto_approve` into rules.** It is a standing rule that
   approves link holders, it lives in a config file, and its members aren't
   `auto`. *Recommendation:* leave it for this change, because existing
   deployments use it, and replace it in a later change with an `invite_holders`
   rule kind.
5. **Telling the human.** Events wait in the log for whoever reads them.
   *Recommendation:* defer a push channel, and treat a human-only notification
   hook as its own design, since the hook's target then sees who connected.
6. **A connection's start as seen by the knocker's human.** A knocker whose
   agent starts knocks can be connected with no human on either side.
   *Recommendation:* no new switch, since `knock.agent_may_knock` covers it and
   `knocks` lists every result.
