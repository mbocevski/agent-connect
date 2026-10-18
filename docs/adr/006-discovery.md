# ADR-006: Discovery: signed listings, doors and the directory

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** Marko Bocevski

## Context

Today two agents can only meet if their humans already know each other: one
creates an invite (SPEC [§4](../../SPEC.md#4-invites)) and sends the link
out of band. There's no way to find an agent you haven't been told about.

A **directory** is a service that indexes agents that can be reached
through an AgentConnect relay, for example one served at
`directory.example.org`. A listing says "this agent exists, this is its
key, this is what it says it does, and you can knock here". A knock is a
request to talk. The owner's human approves or ignores it, and an
approved knock becomes an ordinary two-member MLS group.

This ADR decides the protocol and trust model. It is docs only. The SPEC
text below is a proposal and goes into `SPEC.md` after review. Phase 2
(the `directory/` service) and phase 3 (the daemon and CLI) are constrained
here only as far as these decisions require.

What has to keep holding:

- **The relay sees no plaintext and no secrets** (AGENTS.md). The directory is a
  second server run by the same operator, so it gets the same rule. It
  must not become a way to tie identities to mailboxes, and it must not
  hold keys.
- **Peer content is untrusted** (SPEC §10.1, [§10.5](../../SPEC.md#105-agent-cards)).
  A card's name, description and skills are written by whoever signed the
  card. Agents will read them through MCP and `llms.txt`, so they are a
  prompt-injection channel.
- **Human-only decisions stay human-only.** These are: SAS verification
  (§11), join approval (§6.2), and here also publishing a listing and
  approving a knock.
- **One ciphersuite, no negotiation** (§3.1). Every new primitive here
  uses the v0 suite's own algorithms.

Why invites don't fit. An invite's secret is what authenticates a join
(§4.3). It also stops a relay that doesn't hold the link from joining or
forging a Welcome (§12, "Malicious relay without the invite link"). A
listed door is public by definition: whatever sits in the listing is known
to everyone, the relay included. A door secret therefore authenticates
nothing, and it would give the relay the "has the link" position from §12
for every listed agent. An invite is also bound to one group. If knockers
used a shared invite, every knocker would join the *same* group.

Upstream facts this design relies on, checked on 2026-10-17:

- **A2A v1.0 spec, §8.4.1:** a signed Agent Card is canonicalised with JCS
  (RFC 8785). The `signatures` field is excluded, and fields with default
  values are omitted.
- **A2A v1.0 spec, §8.4.2:** each signature is a JWS (RFC 7515) with
  `protected`, `signature` and an optional unprotected `header`. The
  protected header carries `alg`, `typ` (SHOULD be `JOSE`), `kid`, and
  optionally `jku`.
- **A2A v1.0 spec, §8.4.3:** clients SHOULD verify at least one signature
  before trusting a card.
- **A2A v1.0 spec, §4.4.4 and §4.6.3:** an `AgentExtension` has `uri`,
  `description`, `required` and `params`. `required: true` means "the
  client must understand and comply". A breaking change needs a new URI,
  and an agent MUST NOT fall back to an older version.
- **A2A v1.0 spec, §8.2:** lists "Registries/Catalogs" as a discovery
  mechanism, next to `/.well-known/agent-card.json`. The spec is at
  <https://a2a-protocol.org/v1.0.0/specification/>.
- **a2a-sdk 1.2.2:** `a2a.utils.signing` signs and verifies exactly as
  follows. It canonicalises with `MessageToDict(card)`, drops `signatures`,
  removes empty strings, lists and objects, applies JCS (`a2a.utils._jcs`),
  and uses that string as the JWS payload. The verifier calls a
  caller-supplied `key_provider(kid, jku)` and takes an allow-list of
  algorithms. `AgentExtension.params` is a protobuf `Struct`, so its
  numbers are doubles.
- **PyJWT 2.15.1** (the a2a-sdk signing extra) implements `EdDSA`
  (RFC 8037) for Ed25519 keys. It does not implement the fully-specified
  `Ed25519` algorithm name from RFC 9864.

Note on numbering: the threat model is SPEC §12 (§11 is the SAS). New rows
below are for §12. SPEC §10.6, "Local policy" (approvals, framing, local
limits), is on another branch. This ADR refers to it as forthcoming.

## Decision 1: the listing is a signed A2A AgentCard with the `e2e` extension

A **listing** is an A2A v1.0 `AgentCard` in proto3 JSON form (camelCase
field names). It carries one AgentConnect extension and exactly one JWS
signature by the agent's identity key `IK`.

### Shape

Example (wrapped for reading; the real thing is one canonical line):

```json
{
  "capabilities": {
    "extensions": [{
      "description": "Reachable end-to-end encrypted through AgentConnect. Knock to connect; a human approves every connection.",
      "params": {
        "directory": "directory.example.org",
        "door": {
          "expires_at": 1792800000,
          "id": "q3J0bXhH4mTb0cJ2Zb8m1A",
          "key": "<b64url, 1216-byte MLKEM768-X25519 public key>"
        },
        "identity": "ac:v0:<b64url IK.pub>",
        "issued_at": 1792497600,
        "name": "release-planner",
        "owner_domain": "example.com",
        "relay": "relay.example.org",
        "seq": 7,
        "token": { "...": "ListingToken, Decision 6" },
        "v": 0
      },
      "required": true,
      "uri": "https://yggdrasill.network/ext/agentconnect/e2e/v0"
    }]
  },
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "description": "Plans release trains and drafts schedules from a list of changes.",
  "name": "Release planner",
  "provider": {"organization": "Example Ltd", "url": "https://example.com"},
  "signatures": [{"protected": "<b64url JCS protected header>", "signature": "<b64url Ed25519>"}],
  "skills": [{
    "description": "Turns a change list into a dated release plan.",
    "id": "release-planning",
    "name": "Release planning",
    "tags": ["release planning", "scheduling"]
  }],
  "supportedInterfaces": [{
    "protocolBinding": "AGENTCONNECT",
    "protocolVersion": "0",
    "url": "https://directory.example.org/a/release-planner.json"
  }],
  "version": "1.4.0"
}
```

### Extension params (`https://yggdrasill.network/ext/agentconnect/e2e/v0`)

| Field | Rule |
|---|---|
| `v` | `0`. |
| `identity` | The listed identity, `ac:v0:<b64url IK.pub>` (§2). |
| `name` | The listing name (slug): 3 to 32 characters of `[a-z0-9-]`. It starts and ends with a letter or digit. It equals the name in `token`. |
| `directory` | The directory host the listing is for, in the §8.1.1 canonical host form. It equals the one in `token`. |
| `relay` | The relay host a knock goes through, in canonical form. v0 is single-relay (§4.4): a knocker MUST refuse a listing whose relay is not its own. |
| `seq` | Positive integer. It increases with every listing this identity signs for this name. |
| `issued_at` | Unix seconds. Informational, apart from the publish check (Decision 6). |
| `door` | Optional. When it is absent, the door is closed and the listing is "not taking new connections". `id` is 16 random bytes in base64url (22 characters). `key` is the door's HPKE public key (Decision 3). `expires_at` is at most 7 days after `issued_at`. |
| `owner_domain` | Optional. A lower-case ASCII DNS name (A-labels), with no port, no IP literal and no trailing dot. |
| `token` | The operator-issued `ListingToken` (Decision 6). |

### Rules on the card itself

- **Exactly one interface.** `supportedInterfaces` has exactly one entry:
  `protocolBinding` `AGENTCONNECT`, `protocolVersion` `"0"`, and a `url`
  that is the listing's canonical URL `https://<directory>/a/<name>.json`.
  It is stable across door rotations. "Reaching" the agent means
  "fetch this listing and knock". Plaintext A2A endpoints are not allowed
  in v0 listings: a listing that also advertised one would point people
  around the end-to-end path.
- **`required: true`.** A2A clients that don't speak the extension can't
  reach the agent, and A2A says to fail rather than guess (§4.6.3).
- **`provider`.** If present, `provider.url` MUST be
  `https://<owner_domain>` or a path under it. A directory shows
  `provider.organization` only next to a verified domain (Decision 2).
  Otherwise any listing could claim to be "Example Ltd".
- **Text limits.** All text is attacker-controlled (§10.5) and MUST NOT
  contain control characters (Unicode Cc). Newlines are Cc, so every field
  is one line.
  - `name`: at most 80 characters.
  - `description`: at most 500.
  - `version`: at most 32.
  - At most 16 skills. Each has an `id` and a `name` of at most 80, a
    `description` of at most 500, at most 8 `tags` of at most 32, and at
    most 4 `examples` of at most 200.
  - At most 8 media types in each mode list.
  - The whole canonical card is at most 32 KiB.
- **Closed schema.** Only `AgentCard` fields from A2A v1.0 may appear, and
  only the params above. `securitySchemes`, `securityRequirements`,
  `iconUrl`, `documentationUrl` and `capabilities.extendedAgentCard` MUST be
  absent in v0: they are URLs or auth hooks that lead outside the
  encrypted path. Receivers MUST reject anything else, as §3.2 does for
  extensions.

### Canonical serialisation

**JCS (RFC 8785), with the I-JSON integer rule of §3.2.** This reuses the
code that canonicalises instance certificates, plus a profile that makes
our verifier and a2a-sdk's verifier compute the same bytes:

1. A listing MUST NOT contain an empty string, an empty array, an empty
   object or `null` anywhere. Outside `params`, it MUST NOT set a field to
   its proto3 default (`false`, `0`). Optional fields are left out instead.
   With these rules, a2a-sdk's clean-up step changes nothing and the A2A
   "omit defaults" rule (§8.4.1) is already met.
2. Integers are at most 2^53 − 1. `params` is a protobuf `Struct`, so
   a2a-sdk reads them as doubles. JCS writes an integral double and the
   integer the same way, so both sides produce `1792800000`. Floats are
   not allowed.
3. The **published bytes** are the JCS form of the whole card, signatures
   included. A receiver MUST reject a listing that isn't byte-for-byte
   canonical, as §3.2 does. One accepted byte string per listing means no
   parser differentials, stable ETags, and a cache key that is the hash of
   the bytes.
4. The **signed payload** is JCS(card without `signatures`), as A2A §8.4.1
   says.

### Signature: the A2A `signatures` JWS, and nothing else

- `signatures` has **exactly one** entry, with no unprotected `header`.
- The protected header is the base64url encoding of the JCS of exactly
  `{"alg":"EdDSA","kid":"ac:v0:<b64url IK.pub>","typ":"JOSE"}`. It has no
  `jku`, `jwk`, `x5u`, `x5c` or `crit`. `kid` MUST equal `params.identity`.
- `signature` = Ed25519(IK, ASCII(`protected` ‖ "." ‖
  base64url(JCS(card without signatures)))). This is a JWS with a detached
  payload (RFC 7515 Appendix F).
- Verification uses the key encoded in `kid`, with strict Ed25519 (as for
  the instance certificate, §3.3). It allows only `EdDSA` and ignores any
  key location. The listing is **self-certifying**: it proves that the
  holder of the named `IK` wrote it, and nothing else. This doesn't
  conflict with §10.5 ("check card signatures only against pinned keys").
  A listing names its own key, and the knock flow later requires the MLS
  member to be that same identity (Decision 3). §10.5 gains a paragraph
  saying so (Decision 7).
- **Domain separation.** IK now signs two kinds of message:
  - instance certificates, whose input starts with
    `agentconnect/v0/instance-cert`;
  - JWS signing inputs, which start with the base64url of `{"`, that is
    `eyJ`.
  The prefixes are disjoint, so neither signature can be passed off as the
  other. Withdrawals (Decision 6) get their own label. The rule becomes:
  every IK signature is either a listing JWS or starts with an
  `agentconnect/v0/` label.

**Rejected:**

- *A detached signature inside the extension params.* The signature would
  sit inside the signed object, so it would need its own exclusion rule.
  It would also be invisible to every A2A tool that checks
  `AgentCard.signatures`.
- *Both signatures.* That gives two signatures over almost the same bytes,
  with two verifiers that can disagree. One signature that a2a-sdk's
  `create_signature_verifier` can check (given a `key_provider` that reads
  `kid` and refuses `jku`) gives interoperability for free.
- *Signing with the instance key `SK`.* Listings outlive instances.
  Replicas share IK (ADR-005, Decision 5), and IK is what peers see in
  MLS credentials.
- *`alg: "Ed25519"` (RFC 9864).* It is the cleaner name, but PyJWT 2.15.1
  and so a2a-sdk 1.2.2 can't verify it. See open question 3.

### Fingerprint shown to humans

**The existing §2 fingerprint, unchanged.** That is the first 16 bytes of
SHA-256(IK.pub), as 8 groups of 4 lower-case hex characters, for example
`3f9a 0c21 77de 41b0 9e5c d2a8 16f4 b03e`. It is the format used
in `approvals list` and in `groups show`. It is a
truncation (128 bits) of the hash of the identity key, not a new value.
Its use is human comparison. Machines compare the full `ac:v0:` identity
(the well-known file in Decision 2 lists full identities for that
reason).

The fingerprint is **not** a SAS. It shows that a listing and a later MLS
member are the same key. Only comparing the group's short code (§11)
shows there's nobody in the middle. The UI says so ("What a listing
proves", below).

## Decision 2: owner verification through `/.well-known/agentconnect.json`

A listing may claim an `owner_domain`. The claim counts only if the domain
publishes, over HTTPS:

```text
https://<owner_domain>/.well-known/agentconnect.json
```

```json
{
  "v": 0,
  "identities": [
    {
      "identity": "ac:v0:2l3k…",
      "fingerprint": "3f9a 0c21 77de 41b0 9e5c d2a8 16f4 b03e",
      "listings": ["directory.example.org/a/release-planner"]
    }
  ],
  "revoked": [
    {"identity": "ac:v0:9xQe…", "revoked_at": 1792000000, "reason": "superseded"}
  ]
}
```

- **Format rules:**
  - The file is I-JSON (RFC 7493), at most 64 KiB, with no duplicate
    keys. It is meant to be edited by hand, so it need not be JCS.
  - `identity` is required.
  - `fingerprint` is optional. If present, it MUST match `identity`; a
    mismatch makes the entry invalid. It's there for the humans who edit
    the file.
  - `listings` is optional. If present, the domain vouches for that key
    only in the listed `<directory>/a/<name>` listings.
  - `reason` is `superseded` or `compromised`.
  - Unknown fields are ignored. That's unlike protocol objects: a hosting
    team's own notes must not break verification.
- **The fetch:**
  - `https`, port 443, a valid WebPKI certificate, no redirects.
  - `Content-Type: application/json`, a 5 s timeout.
  - Only public addresses after DNS resolution. Loopback, private,
    link-local and ULA addresses are refused (this is the SSRF guard).
- **No signature on the file.** What is being proved is "whoever controls
  this domain's web server vouches for this key". The HTTPS origin proves
  exactly that, and a signature would need another key to anchor it.

### Who checks, and when

- **The directory** checks on every publish, every 6 hours afterwards, and when
  a withdrawal or revocation names the identity. Every check must succeed
  on its own; it is never assumed.
- **The knocker's daemon** fetches the file itself before it knocks, and
  shows the result to its human. A directory's badge is the operator's
  opinion, and a malicious operator can fake it (§12 row below). The
  daemon's own fetch is what the knock records. The fetch tells the
  owner's web server that someone is about to knock, and from which
  address, before the owner has approved anything. The CLI says so, and
  `--no-domain-check` skips the fetch; the knock then records the owner
  state as unchecked.

### States a directory shows

| State | Condition | What the page shows |
|---|---|---|
| `verified` | Last successful check within 24 h lists the identity (and this listing, if `listings` is set) | "owner verified · example.com", plus `provider.organization` |
| `unclaimed` | No `owner_domain` | "no verified owner"; organization hidden |
| `stale` | Last success between 24 h and 7 days ago, later fetches failing | "owner last confirmed <date> · example.com" in a muted style; organization hidden |
| `failed` | The file fetched but doesn't list the identity, or no success for 7 days | Red "example.com does not vouch for this key"; badge and organization hidden; left out of search, still served at its URL |
| `revoked` | The identity is in `revoked` | Withdrawn: 410 at every URL, and a revocation entry in the feed (Decision 6) |

### Rotation and revocation

- **Rotation.** A new key is a new identity, so it needs a new
  `ListingToken` (Decision 6). The steps are:
  1. Add the new identity to the file.
  2. Publish the new listing under the same name. The operator issues the
     token for the new identity.
  3. Move the old identity to `revoked` with `superseded`.

  For 30 days the directory shows "key changed on <date>" on that listing, the
  way SSH warns about a changed host key. People who pinned the old
  fingerprint must notice the change.
- **Revocation** (`compromised`). The directory withdraws every listing of that
  identity at its next check. To make it immediate, the owner also sends a
  withdrawal, or the operator revokes the token. The daemon's
  `listing withdraw` does all of it (phase 3).

**Rejected:**

- *DNS TXT records.* Many owners can't edit DNS. TXT size limits make
  several identities awkward. It also needs a DNS client in the directory with
  DNSSEC questions attached.
- *The key inside the owner's own `/.well-known/agent-card.json`.* That
  forces the owner to run a public A2A card, ties AgentConnect to a file
  with other semantics, and an A2A card describes one agent, not a set of
  keys.
- *Listing fingerprints only.* A 128-bit truncation is enough for a human
  to compare, but machines should compare the full key. The file carries
  `identity` and allows `fingerprint` next to it.

## Decision 3: doors and knocking are their own flow, not invites

**A door** is a public, relay-registered address that accepts **knocks**.
**A knock** asks the door's owner for a new two-member group. It is sealed
to the door's key and signed by the knocker's instance key. **Approving a
knock** creates that group and sends a wrapped Welcome. Rejection and
timeout send nothing.

On naming: a door is **not** an invite. It has no secret, isn't bound to a group, and is never consumed.
This ADR uses "door" and "knock" throughout, and SPEC §4 is unchanged.

### Why not reuse §4

- An invite secret in a public listing authenticates nothing, and it gives
  the relay the "holds the link" position of §12 for every listed agent.
- An invite is bound to one group and is used up. A door has to create a
  **new** group per approved knock, or knockers would end up in a group
  together.
- Two meanings of `invite_id` in one registry and one landing page
  (`/i/…`) is a confusion we'd pay for in every check of §4.1–4.4.

### Door key and relay registration

- The **door key** is an HPKE (RFC 9180) key pair of the v0 suite's own
  HPKE algorithms: KEM `MLKEM768-X25519` (the §3.1 hybrid), KDF
  HKDF-SHA256, AEAD AES-128-GCM. This adds no algorithm. Knocks are
  protected against record-now-decrypt-later like everything else. The
  public key is 1216 bytes and goes in `params.door.key`. The private key
  stays in the owning instance's encrypted store (ADR-002).
- **One door per listing, held by one instance.** The relay maps
  `door_id` to that instance's mailbox (see "Relay interactions" below).
- **Renewal.** A door lives at most 7 days, like an invite (§4.2). The
  daemon creates a **fresh** door (new `door_id`, new key) when half the
  lifetime has passed. It registers the new door, then publishes a
  re-signed listing (`seq` + 1, new `door`, new `issued_at`). The old door
  stays registered until its own `expires_at`, so cached copies of the
  previous listing still work. Its private key is deleted 1 hour after
  that, once every knock it could have received has timed out. A fresh key
  per door bounds how much past knock traffic one leaked door key exposes
  to 7 days.
- If the listing can't be published, the old door is kept until it
  expires, and the daemon raises a `listing_stale` event to its human.
  Renewal re-signs the door fields only. A change to the card's text is a
  new publish, which is a human decision (Decision 6).

### The knock

The knocker instance B fetches the listing and verifies it (Decision 1;
the token as in Decision 6). It checks that `relay` is its relay, that
`door` is present, and that `door.expires_at` is in the future. It fetches
the owner's well-known file (Decision 2) and shows its human the listing
name, fingerprint, owner state and description, marked as unverified
text. Then it builds:

```text
Knock = {
  "v": 0,
  "door_id": "<22 b64url>",
  "knock_id": "<16 random bytes, b64url>",
  "ts": <unix seconds>,
  "display_name": "<≤ 80 chars, no Cc>",
  "note": "<≤ 500 chars, no Cc; optional>",
  "key_package": "<b64url MLS KeyPackage, v0 suite, with ac_instance_cert, fresh, used for this knock only>",
  "mailbox_id": "<B's mailbox>",
  "welcome_secret": "<32 random bytes, b64url>",
  "sig": "<b64url Ed25519(SK_B, \"agentconnect/v0/knock\" || JCS(knock without sig))>"
}
SealedKnock = enc(1120) ‖ HPKE.Seal(door.key, info = "agentconnect/v0/knock" ‖ door_id_raw16, aad = "", JCS(Knock))
```

- **The signature** binds every field, including `door_id`, to the
  KeyPackage's leaf key `SK_B`. The KeyPackage's instance certificate binds
  `SK_B` to B's identity (§3.3).
  - Without it, a relay that saw one of B's KeyPackages, for example in a
    JoinRequest, could knock "as B" with a note of its choosing. It could
    never decrypt the Welcome, but it would put words in B's name in front
    of the owner's human.
  - `door_id` inside the signature stops a knock from being redirected to
    another door.
- **The seal** hides the knocker's identity, display name, note and
  KeyPackage from the relay. JoinRequests don't get that protection today:
  the relay sees their KeyPackage. The relay sees a sender mailbox, a
  `door_id`, a size and a time.
- **`welcome_secret`** is the knock's equivalent of the invite secret for
  the Welcome wrap. Only B and the door's owner know it.

### The owner's checks (instance A, holding the door)

A MUST, in this order:

1. Find the door by the envelope's `door_id`. It must be one A holds a key
   for and that has not expired more than 1 hour ago.
2. Open the seal. Check that the plaintext is canonical JCS with exactly
   the fields above and that its `door_id` equals the envelope's.
3. Check that `ts` is within [now − 3600 s, now + 300 s].
4. Check the KeyPackage as in §6.2 step 3: suite, HPKE key lengths,
   signature, instance certificate, capabilities, no extensions, not last
   resort, **unused**, and `mailbox_id` derived from its leaf
   `signature_key`.
5. Verify `sig` under that leaf `signature_key`.
6. Deduplicate:
   - at most one pending approval per KeyPackageRef (as §6.2);
   - at most one per `knock_id`;
   - at most one per knocker identity per door.
7. Apply the local limits: at most 32 pending knocks per door; the rest are
   dropped. The forthcoming §10.6 holds these limits, which local policy may
   only tighten.
8. Queue a **human** approval. It shows the listing name, the knocker's
   display name and note (unverified text), and its fingerprint.

Every failure drops the knock **silently**. A knock that fails steps 1–5
counts toward local rate limiting.

### Approval

- **Every knock needs its human's approval. Auto-approval doesn't exist in
  v0.**
  - There is no config switch for it.
  - The local policy layer (`policy.py`, §10.6) can drop a knock (for example a blocklist), but its
    result can't approve one.
  - No agent-scope route, SDK call or MCP tool approves one.
  - Phase 3 tests that each of these is refused.
- **Timeout:** the approval lapses at `ts + 3600`, matching §6.2's hour. It
  is measured from the knocker's timestamp, not from receipt, so the
  knocker knows when to stop waiting even if the owner was offline. A lapse
  is silent.
- **On approve**, A:
  1. Creates a new group (§5) with `owner` = A's identity and
     `floor: "free"`. `ac_group_meta.name` is the listing's `name`.
     `purpose` is chosen by A's human, defaulting to the listing's
     description.
  2. Sends `group.create`.
  3. Commits `Add(B.key_package)`.
  4. Wraps the Welcome:
     `welcome_key` = HKDF(ikm = welcome_secret, salt = knock_id_raw16,
     info = "agentconnect/v0/knock-welcome", L = 32). The wrap is the
     §6.4 `WrappedWelcome`, with
     aad = "agentconnect/v0/knock-welcome" ‖ knock_id_raw16.
  5. Sends it to `mailbox_id` as `welcome_wrapped`.
  6. Deletes the knock's `welcome_secret`.

  The envelope kind is unchanged, so §6.4's "only wrapped Welcomes" still
  holds. There is no consume step.

### The knocker's checks on the Welcome

These are the §6.3 checks, except that the comparison with `InviteMeta` is
replaced by:

- The Welcome unwraps under one of B's pending knock keys. B tries each
  pending knock in turn, as it does for pending joins. An instance has at
  most 8 pending knocks.
- `ac_group_policy.owner` and `ac_group_meta.created_by` both equal the
  listing's `identity`.
- The group has exactly two leaves: B's own, and one leaf of the listed
  identity whose instance certificate verifies.
- `ac_group_meta.name` equals the listing's `name`.

A Welcome that unwraps but fails these checks is dropped and raises
`relay_misbehaviour`: only the knock's two ends know the key, so either the
owner is broken or the knock key leaked. After a successful join, B
deletes `welcome_secret`. B's daemon records that the peer is "the
identity listed as `<name>` on `<directory>`", together with the owner
state from its own fetch. The member then starts `unverified`, as every
new member does (§11).

### Relay interactions

The relay forwards knocks and never parses them.

| Interaction | Who | Purpose |
|---|---|---|
| `POST /v0/doors` (signed, §8.1.1) | Owner instance | Register `{door_id, expires_at, owner_mailbox}`. `expires_at` is at most 7 days away. At most 4 open doors per mailbox, so renewal can overlap. |
| `DELETE /v0/doors/{door_id}` (signed) | Owner instance | Close the door now. |
| WS `{"t": "knock", "door_id", "env": Envelope(kind = knock)}` | Knocker | Forward a sealed knock to the door's mailbox. |
| WS `deliver` of the `knock` envelope | Relay → owner | Delivery. |
| `group.create`, `send(commit)`, `send(welcome_wrapped)` | Owner, on approve | Unchanged §8 traffic. |

There is no `GET` for doors: everything a knocker needs is in the signed
listing, and one fewer probe surface is better.

**Relay rules for `knock`:**

- The envelope is `{v, kind: "knock", door_id, msg_id, sender, ct}`, with
  no `group_id` or `to`. `ct` is at most 16 KiB.
- If the door is unknown, expired or closed, the relay answers
  `door_not_open`. That state is public anyway: the signed listing carries
  the expiry, and closing is the owner's public act.
- These limits are answered with `rate_limited`, which only tells the
  knocker about its own behaviour:
  - 1 knock per (door, sender mailbox) per 10 minutes;
  - 20 knocks per sender mailbox per hour, across all doors.
- These conditions are answered with **`accepted`**, and the knock is
  dropped:
  - more than 10 knocks per door per minute;
  - the owner's queue is full (this is unlike `join`, §8.3).

  Otherwise these answers would reveal how busy the owner's door is and
  whether its queue is full.
- Mailboxes cost nothing to create, so per-mailbox limits can be evaded by
  creating more. The relay MAY also limit per source address, in memory
  only and never logged. The owner's per-identity and per-door caps
  (step 6 and step 7 above) are the backstop.

### What the knocker learns, and when

| When | It learns | Depends on the owner's decision? |
|---|---|---|
| On sending | `accepted`, `door_not_open` or `rate_limited` | No. `accepted` also covers per-door overflow and a full owner queue. |
| While pending | Nothing. The relay sends no delivery receipt, the owner's acks aren't visible, and there's no reject frame. | No |
| On approval | A Welcome arrives, so it is approved | Yes. This is the one signal, and the owner chose to send it. |
| At `ts + 3600 + 300` with no Welcome | "No answer." The daemon deletes the knock's `welcome_secret` and KeyPackage and reports `knock_lapsed`, never "rejected" | No. Rejected, timed out, owner offline, dropped by a limit and a failed check all look the same. |

That is what makes rejection silent: until the deadline, every outcome
other than approval produces the same observation. The timing of an approval does reveal
when the human approved, which is inherent to approving.

**Rejected:**

- *A plaintext knock with an unwrapped Welcome.* It exposes the knocker's
  identity and note to the relay, and it adds a second Welcome format
  against §6.4.
- *A plaintext knock carrying `welcome_secret`.* The relay would learn the
  wrap key, so the wrap would add nothing.
- *A knock-reject message.* It is an oracle for whoever knocks, including
  someone probing whether a human is watching.
- *A door that is a long-lived group knockers join.* Knockers would see
  each other.

## Decision 4: what the directory stores and sees

The directory indexes signed listings and serves them.

- **It never talks to the relay.** It has no relay credentials, opens no
  WebSocket and checks no doors. It can't tell whether a door is
  registered, only whether the signed door has expired. Closing a door goes through the relay *and* a re-published
  listing without `door` (Decision 6), so the two stay in step.
- **It holds no keys and no secrets.**
  - Publishing is authenticated by the listing's own JWS and the
    operator-signed token inside it.
  - Withdrawing is authenticated by an IK-signed `Withdrawal`.
  - There are no accounts, passwords, sessions or bearer tokens.
  - The operator's token-signing key stays with the operator's offline
    tool. The directory has only the public key.
- **It never learns mailbox ids.** The listing carries:
  - `door.id`, a random relay-side handle that only the relay maps to a
    mailbox;
  - `door.key`, a public key;
  - the relay host, which is public.

  None of them derives from `SK` or the mailbox (§2). Knocks go
  knocker → relay → owner, and the directory isn't on that path.
- **It stores:**
  - per listing: the exact canonical bytes, their SHA-256, and `name`,
    `identity`, `seq`, `token_id`, `owner_domain`, the owner state and
    check time, `door.expires_at`, the publish time, and a full-text index
    of the card's text;
  - withdrawal and revocation tombstones (signed entries, kept 30 days);
  - the revoked token ids.

  It stores nothing about readers or searchers.
- **Logs and metrics carry no identifiers**, as in the relay (§8.3). No
  addresses, no query strings or search terms, and no names or identities.
  Routes are logged as templates (`/a/:name`). Metrics count by route
  template and status. Per-address rate limits live in memory only.

### Is everything in the card safe to be public?

| Field | Why it is safe |
|---|---|
| `identity`, fingerprint | Public by the owner's choice. It does link the listed identity to any group where it is a member, so a dedicated identity for listing is recommended ("Decided in review", item 3). |
| `door.id` | It authenticates nothing. All it allows is sending knocks, which are rate-limited and approved by a human. Only the relay can map it to a mailbox, and the relay knows every mailbox already. |
| `door.key` | A public key. Rotated with every door. |
| `relay` | A public host. |
| `token` | A public, operator-signed authorisation bound to one identity and one name (Decision 6). It is not a bearer secret: copying it lets nobody publish, because only IK can sign the listing. |

A knocker learns the owner's `mailbox_id` only when the Welcome arrives
(its envelope `sender`). Every group member learns that today.

## Decision 5: threat model additions

Proposed new rows for the SPEC §12 table, in its column order:

| Attacker | Capability | Mitigation | Residual risk |
|---|---|---|---|
| **Spam lister** | Publishes junk or lookalike listings | Listing only by operator-issued token, bound to one name and identity (§13.2). Per-address publish limits. Instant operator revocation | Whatever the operator lets through. Curation is a judgement, not a cryptographic check |
| **Impersonator** (claims another org's name or text) | Signs a card that copies a real agent's name, description or skills | The signature binds the card to its own IK only. The owner domain is shown only when `/.well-known/agentconnect.json` lists the key, and `provider.organization` only next to a verified domain. Slugs are ASCII-only. "Key changed" banner for 30 days. The knocker's daemon fetches the domain file itself. Then the SAS | Humans who trust the name or text over the fingerprint and domain. An attacker who controls the owner's web server can vouch for its own key |
| **Scraper / enumerator** | Downloads every listing, tracks door rotations and owner domains over time | Listings are public by design. Rate limits. Listings carry no mailbox id, no relay secret and no contact data beyond what the owner signed. Doors rotate weekly | The set of listed identities and their published text, and a weekly rotation cadence. Listing makes an identity public |
| **Malicious directory operator** | Hides, delays or reorders listings. Serves stale versions. Fakes owner badges. Ignores withdrawals. Logs who reads what. Issues tokens to identities of its own | Listings and withdrawals are signed by IK, and tokens are checked against a key pinned in the daemon, so it **can't forge or alter** a listing. The knocker re-verifies the JWS, the token and the expiry, and fetches the domain file itself. Rollback is bounded by the door's 7-day expiry, and by the owner closing the door at the relay | Censorship and delay. Stale but validly signed listings until their door expires. Reader metadata. Names are operator-assigned, so a name proves nothing about who holds it |
| **Relay and directory colluding** (same operator) | Joins reads of a listing to knocks on its door, and knocks to their mailboxes | Knocks are sealed (§6.6), so the relay sees a sender mailbox, a door and a time. the directory logs no addresses | Who knocked on whom and when, if both sides keep data they're told not to keep. **Metadata**, as for the relay |
| **Stale door** (expired, rotated or closed) | A cached or replayed listing points at a door that is gone, or at an old door key | Door `expires_at` is at most 7 days and the knocker checks it. The relay answers `door_not_open`. The owner drops knocks for doors expired more than 1 h ago. The listing `seq` and tombstones stop older listings from being re-published | A knock to a closed door fails openly. A cached listing can show a door as open until its signed expiry |
| **Knock flooder** | Sends many knocks to tire the owner's human, or to crowd out real knocks | Relay limits per (door, sender) and per sender, and per door, where overflow is dropped silently. Owner caps: one pending knock per identity per door, 32 per door. The 1 h lapse. Local policy (§10.6) drops | Denial of service on a popular door. Mailboxes are free, so the relay limits slow Sybils down rather than stop them |
| **Prompt injection through card text** | Card name, description, skills and examples are attacker-controlled and are read by agents through MCP, `.md`, `llms.txt` and `knock` | Cards are untrusted content (§10.1, §10.5). Directories MUST present card text as data: MCP results carry `untrusted: true`, Markdown escapes card text inside fenced blocks, and `llms.txt` lists names and URLs only. Single-line fields with length caps. No links from card text are rendered. Knock approval is human. Knocking only asks to talk | Behavioural: an agent that obeys card text anyway. Can't be solved with cryptography (as the existing row) |

The "Assets" list gains **listing integrity** (only IK can say what its
listing says).

## Decision 6: curation by operator-issued listing token; instant withdrawal

### ListingToken

```text
ListingToken = {
  "v": 0,
  "token_id": "<16 random bytes, b64url>",
  "directory": "directory.example.org",
  "name": "release-planner",
  "identity": "ac:v0:…",
  "owner_domain": "example.com",        // optional: pins the domain the listing may claim
  "issued_at": <unix seconds>,
  "expires_at": <unix seconds>,
  "key_id": "<b64url SHA-256(DK.pub)[0..16]>",
  "sig": "<b64url Ed25519(DK, \"agentconnect/v0/listing-token\" || JCS(token without sig))>"
}
```

- **Issuer.** `DK` is the directory operator's token key, an Ed25519 key
  held by the operator's offline tool, never by the directory.
  - Daemons ship its public key, pinned per directory in their config,
    with `directory.example.org` as the default. They never fetch it
    from a URL a listing names (as §10.5).
  - The directory is configured with the same public key. It also publishes the
    key at `/.well-known/agentconnect-directory.json`, for information
    only.
  - Up to two `key_id`s are valid at once, so DK can be rotated.
- **Scope.** One directory, one name and one identity, plus optionally one
  domain. The owner sends the operator their identity (`agentconnect id`)
  when they ask to be listed, and the token is bound to it at issue.
  - The token is not a secret. Leaking it lets nobody publish, because
    only IK can sign the listing.
  - It is embedded in `params.token`, so mirrors and knockers check
    curation themselves.
- **Lifetime.** At most 90 days (open question 1). Re-issuing is an
  operator action. A listing whose token has expired is hidden as if it
  were withdrawn, and the daemon warns its human 14 days ahead.
- **Revocation.** The operator signs
  `TokenRevocation = {v, token_id, revoked_at, reason, key_id, sig}`
  (label `agentconnect/v0/listing-token-revoke`) and posts it. The directory
  stores the token id and withdraws the listing in the same transaction.

### Publish (human decision)

`POST /v0/listings`, whose body is the canonical listing. The directory
accepts it only if all of the following hold:

- The listing passes Decision 1.
- The token verifies against a configured DK. Its `directory` is this
  host, and its `name` and `identity` equal the params. It hasn't expired
  and isn't revoked. Its `owner_domain` (if set) equals the params.
- `seq` is greater than both the stored `seq` and any tombstoned `seq` for
  this name.
- `issued_at` ≤ now + 300 s.
- If a door is present, its `expires_at` is in the future and at most
  7 days after `issued_at`. `relay` is one this directory lists.

The domain check (Decision 2) then runs, and the state shows as
`checking` until it finishes. Re-posting the same bytes is idempotent.

Choosing to publish, and any change to the card's text, is a **human**
command. An agent can't put itself into a public directory. Automatic
door renewal re-signs only `door`, `seq` and `issued_at` of the listing
the human approved.

### Withdraw (instant)

```text
Withdrawal = {
  "v": 0, "directory": "directory.example.org", "name": "release-planner",
  "identity": "ac:v0:…", "seq": <the highest seq withdrawn>, "ts": <unix seconds>,
  "sig": "<b64url Ed25519(IK, \"agentconnect/v0/listing-withdraw\" || JCS(withdrawal without sig))>"
}
```

- `POST /v0/withdrawals`. The directory checks the signature and that `ts` is
  within 300 s. In **one transaction** it deletes the listing, writes the
  tombstone, and appends the signed entry to the feed. A repeat of the
  same withdrawal changes nothing.
- The daemon's `listing withdraw` first closes the door at the relay
  (`DELETE /v0/doors/{id}`), then withdraws. **Closing at the relay is what
  makes withdrawal instant everywhere.** From that moment every knock gets
  `door_not_open`, whatever any cache, mirror or hostile directory still
  shows.
- `listing withdraw` is allowed with the **agent** token as well as the
  human's. It only reduces exposure, like `invite revoke` today.

### Propagation to caches and mirrors

- **Caching.** Listings are served with
  `Cache-Control: public, max-age=60, must-revalidate`, an `ETag` (the
  bytes' hash) and `Vary: Accept`.
- **After withdrawal**, every URL of the listing returns
  `410 Gone` with `Cache-Control: max-age=60`. A CDN in front of the directory
  is purged on every withdrawal.
- **The feed.** `GET /v0/withdrawals?after=<cursor>` lists withdrawals and
  token revocations in order. Each entry is signed by the owner or the
  operator, so a mirror verifies it without trusting the directory.
  - A conforming mirror polls at least every 60 s and applies an entry
    before it serves the listing again.
  - A mirror re-verifies every listing (Decision 1 and the token) and
    MUST NOT serve one older than the newest `seq` it has seen, or one
    with a tombstone.
- **Worst case.** For a non-conforming cache, the worst case is bounded by
  the door's signed expiry (at most 7 days), and the closed door already
  refuses knocks.

**Rejected:**

- *Open self-service listing in v0.* It invites spam and impersonation
  before any reputation system exists.
- *An opaque bearer token stored hashed in the directory.* The directory would hold a
  credential-equivalent. Mirrors and knockers couldn't check curation. A
  leaked token would let anyone publish under the name until it was
  revoked.
- *Withdrawal only at the directory.* "Instant" would then depend on every cache
  and mirror behaving well.

## Decision 7: spec changes and versioning

**No protocol version bump. Everything is additive inside v0, which is
still a draft** ("Every part may change until v0 is tagged"):

- No existing message, field or check changes meaning. §6.4's rule that a
  Welcome is always wrapped holds for knocks too.
- The new envelope kind `knock` is delivered only to mailboxes that
  registered a door, so an implementation without doors never sees one.
  The relay answers `door_not_open` for unknown doors.
- Every new label is under `agentconnect/v0/`, the extension URI ends in
  `/v0`, and every new object carries `"v": 0`. A v1 would change these
  together, as §13 requires.
- The ciphersuite is untouched. The door HPKE uses the suite's own KEM, KDF
  and AEAD.

Even if v0 had been tagged, this would still be additive, so it would not
need v1.

### SPEC edits (to apply after approval)

The edits use the existing section numbers; nothing is renumbered.

1. **§2 Terminology.** Add these terms:
   - **Listing:** a signed A2A AgentCard with the `e2e` extension (§13.1).
   - **Directory:** a server that indexes and serves listings (§13.2).
   - **Door:** a relay-registered public handle `door_id` with an HPKE key,
     that accepts knocks (§6.6).
   - **Knock:** a sealed, signed request for a new group through a door
     (§6.6).
   - **Listing token:** an operator-signed authorisation to list one
     identity under one name (§13.2).
2. **§3.5 Key derivation.** Add these rows:
   - knock `welcome_key` = HKDF(ikm = welcome_secret, salt = knock_id,
     info = "agentconnect/v0/knock-welcome", L = 32);
   - the HPKE info `agentconnect/v0/knock` ‖ door_id;
   - the signature labels `agentconnect/v0/knock`,
     `agentconnect/v0/listing-withdraw`, `agentconnect/v0/listing-token`
     and `agentconnect/v0/listing-token-revoke`.

   Add one sentence: every IK signature is an instance certificate, a
   listing JWS (§13.1) or a withdrawal.
3. **New §6.6 "Knocking on a door".** Normative text for Decision 3:
   - the `Knock` and `SealedKnock` formats;
   - the owner's checks 1–8;
   - human-only approval with no automatic approval, and the lapse at
     `ts + 3600`;
   - group creation and the knock-wrapped Welcome;
   - the knocker's Welcome checks;
   - the "what the knocker learns" rule as a MUST ("an owner MUST NOT send
     anything to a knocker except the Welcome of an approved knock");
   - door renewal and key deletion.
4. **§7.1 Envelope.** Add the `"knock"` kind and the field
   `"door_id"` (knock only). The drop-on-bad-type rule covers both.
5. **§8.1 REST.** Add rows for `POST /v0/doors` and
   `DELETE /v0/doors/{door_id}` (signed as §8.1.1;
   `owner_mailbox` MUST equal the authenticated mailbox).
6. **§8.2 WebSocket.** Add the client frame
   `{"t": "knock", "door_id": "...", "env": Envelope(kind=knock)}`. No new
   server frame: knocks are `deliver`ed.
7. **§8.3 Delivery Service rules.** Add a **`knock`** bullet with the
   door registry, the size cap, the three limits and which answer each
   gives, the silent drop on per-door overflow and on a full owner queue,
   and the 4 doors per mailbox. Add a **logging** line: door ids are
   identifiers, so they are hashed in logs.
8. **§8.4 Errors.** Add `door_not_open` (HTTP 404 on REST), with mapping
   rows for an unknown, expired or closed door, and for `DELETE` by a
   mailbox that isn't the door's owner (`auth_failed`).
9. **§10.5 Agent Cards.** Add: "A listing (§13.1) is self-certifying. Its
   JWS is checked against the key its `kid` names. That proves only
   authorship. After a knock, the member's MLS identity MUST equal the
   listing's `identity`. A card received in a group from a member whose
   identity matches a listing the human knocked on MAY be shown as
   'matches listing <name>'. It is still untrusted content."
10. **§10.6 (forthcoming, Local policy).** Add the knock limits (one pending
    knock per identity per door, 32 per door, at most 8 outgoing per
    instance), which local policy may only tighten. Add the rule that knock
    approval is human-only with no automatic approval.
11. **§12 Threat model.** Add the rows of Decision 5 and the asset.
    Extend the "Non-goals" list with "directory availability and
    censorship resistance".
12. **§13 Versioning and extensibility.** Replace the future-work bullet
    about the extension URI
    `https://yggdrasill.network/ext/agentconnect/e2e/v0` with:
    - **§13.1 "The `e2e` extension and signed listings":** Decision 1 in
      full, meaning the params, the card rules, the canonical form profile,
      the JWS, and the fingerprint.
    - **§13.2 "Directories":** the owner well-known file and its states
      (Decision 2); `ListingToken`, `TokenRevocation`, `Withdrawal` and
      the publish checks (Decision 6); the withdrawal feed and the cache
      rules; the "directories present card text as data" rule; and
      "directories MUST NOT connect to the relay or store mailbox ids".
13. **§15 Open questions.** Move item 4's A2A-extension part to "decided".
14. **§16 References.** Add RFC 7515 (JWS), RFC 8037 (EdDSA in JOSE),
    RFC 9180 (HPKE), RFC 8615 (well-known URIs) and RFC 7493 (already
    cited).

`testdata/` gains vectors for all of the following (see phase 2):

- canonical listings, plus negatives:
  - not canonical;
  - empty value;
  - an extra field;
  - `jku` present;
  - the wrong `kid`;
  - tampered text;
  - an expired door;
- tokens with the wrong key, the wrong name and an expired lifetime;
- withdrawals;
- sealed knocks, with a fixed-seed HPKE and negatives for:
  - the wrong door;
  - a skewed `ts`;
  - a bad signature;
  - a reused KeyPackage;
- the knock Welcome wrap;
- the well-known file parser cases.

## What a listing proves

- **It proves** that the card was signed by the key with that
  fingerprint, so the directory can't forge or alter it. With a `verified`
  state, it also proves that whoever controls the domain vouches for that
  key.
- **It does not prove** that the agent does what its card says, or that
  it's safe to hand it anything. It also doesn't prove who is on the other
  end. Only comparing the short code (SAS) with its owner proves that.

The docs use the canonical security claim from SPEC §1 for the
conversation itself, and nothing stronger.

## Plan for phases 2 and 3 (as constrained here)

### Phase 2: `directory/` (Rust, in the style of `relay/`)

- **Crate:** `agentconnect-directory` (axum 0.8, tokio, sqlx 0.9 on
  Postgres).
  - It depends on `agentconnect-core` for **every** signature and
    canonical-form check: listing JWS, token, revocation, withdrawal. No
    second JCS or Ed25519 path is allowed.
  - Like the relay, it inherits the SQLCipher link from `core` (ADR-002
    Consequences) without using it.
  - `core` gains a `listing` module (parse, canonical check, verify, sign)
    and an HPKE knock module (seal and open), both with vectors and
    negative tests.
- **The `Store` trait:**
  - a Postgres implementation, with a `tsvector` over the name,
    description, skill names and tags, and `websearch_to_tsquery`;
  - an in-memory implementation for the fast test tier.
  - Postgres tests run in `just test-int`.
- **The domain fetcher** sits behind a trait with the Decision 2 SSRF
  rules. The fast tier uses a fake fetcher and the fake `Clock`. A real
  fetcher with network access is integration-tier only.
- **Endpoints**, all rate-limited per address in memory:
  - `GET /search?q=` (HTML, or JSON with `Accept: application/json`);
  - `GET /a/<name>`, negotiated by `Accept` (HTML by default,
    `text/markdown`, `application/json`), with `Vary: Accept` and never
    keyed on `User-Agent`;
  - `GET /a/<name>.json` (the exact signed bytes) and `GET /a/<name>.md`;
  - `GET /llms.txt` (names and URLs only, no card text);
  - HTML with no JavaScript, card text HTML-escaped and never linked;
  - MCP at `/mcp` with `search_agents` and `get_card`. Results carry
    `untrusted: true`, the owner state, the door state, and the verbatim
    signed card for the caller to verify;
  - `POST /v0/listings`, `POST /v0/withdrawals`, `POST /v0/revocations`
    (operator-signed), `GET /v0/withdrawals?after=`;
  - `GET /.well-known/agentconnect-directory.json`;
  - `GET /healthz` and `GET /metrics`, with no identifiers.
- **MAP.toml** gets a `directory-protocol` rule: changes to the directory's
  protocol files must come with `SPEC.md` and `directory/README.md`.
- **Never in phase 2:** a relay client, a mailbox column, a key or secret
  column, or IP addresses in logs.

### Phase 3: the daemon and CLI

- **`agentconnect listing publish --directory directory.example.org`.**
  Human token.
  - It needs a token file from the operator.
  - It shows the card it will sign, then registers a door, signs and
    publishes.
  - It warns when the identity already has private groups ("Decided
    in review", item 3).
- **`agentconnect listing withdraw`.** Agent or human token. It closes the
  door at the relay, then withdraws.
- **`agentconnect listing status`.** It shows the owner state, the door
  expiry and the token expiry.
- **The door renewal worker** (Decision 3): it renews at half-life,
  deletes keys 1 h after each door expires, and raises `listing_stale` and
  token-expiry events.
- **`agentconnect knock <listing>`.** Agent token, like `accept`.
  - The argument is `<directory-host>/a/<name>`, with or without `https://`
    and `.json`. A query, fragment, userinfo or any other path is refused.
  - The directory must be configured (that's where the pinned DK comes
    from), and the listing's `relay` must be the configured relay.
  - The command fetches and verifies the listing, fetches the owner's
    well-known file, shows both, sends the knock and waits. `--wait`
    defaults to 3900 s.
  - It reports `knock_lapsed` as "no answer", never as "rejected".
- **Knock approvals** appear in the existing `approvals` list with
  `kind: "knock"`. Each shows the listing, the display name and note as
  unverified text, and the fingerprint. `approvals approve` and
  `approvals reject` stay human-only.
  - The local policy layer can drop a knock and can't approve one.
  - Phase 3 has tests that no config, hook result, API route, SDK call or
    MCP tool approves a knock.
- **Docs** that change with it: `docs/cli.md`, `docs/api.md`,
  `docs/config.md` (the `[directory]` table with pinned DKs), and the
  README security model ("what a listing proves").

## Consequences

- **A listed identity is public.** Anyone can tell that a member with that
  identity in any group is the listed agent. This is the price of being
  findable, and a separate identity is recommended ("Decided in review", item 3).
- **The relay grows a small door registry and one frame.** It still parses
  no `ct` and holds no secret. Its new metadata (who knocks on which door,
  and when) is of the same kind as `join` today, with the knock contents
  hidden.
- **The directory can censor, delay and fake badges, but can't forge.** Every
  trust decision that matters (signature, token, door expiry, domain file,
  SAS) is checked again by the knocker's daemon.
- **Names are operator-assigned.** A slug proves nothing about who holds
  it. The UI gives the domain and the fingerprint more weight than the
  name.
- **Owners' daemons must run.** A door's knocks are approved only while
  the owning instance runs (ADR-005 Decision 3). A knock to an offline
  owner lapses after an hour, and the knocker can try again later.
- **Core gets HPKE seal and open on the v0 suite's KEM.** The provider
  already implements it for MLS; the new code is a thin, vector-tested
  wrapper.
- **Card interop holds both ways.** a2a-sdk's own verifier accepts our
  listings when it is given a `key_provider` that reads `kid`. Python tests
  check this against the shared vectors.

## Decided in review

1. **Extension URI.** `https://yggdrasill.network/ext/agentconnect/e2e/v0`.
   The project's protocol URIs and the default relay all live on
   `yggdrasill.network`. A page describing the extension is served at that
   URI before v0 is tagged. Changing the URI later would be a new extension version, which
   is why it's settled now.
2. **Well-known name.** `/.well-known/agentconnect.json` on the owner's
   domain. It's registered with IANA (RFC 8615) before v0 is tagged.
3. **A dedicated identity for listing.** SHOULD, not MUST. `listing
   publish` warns when the identity already has groups, and the docs
   explain the linkage. Enforcing it would mean a second daemon per listed
   agent (ADR-005, one daemon per identity).
4. **Who may knock.** The agent token, like `accept`. The decision that
   matters is on the owner's side and is human, and knocking only reveals
   the knocker's identity to the owner it chose. A local policy switch to
   require human confirmation of outgoing knocks comes with §10.6.

## Open questions

The recommendations below stand unless review says otherwise.

1. **Token lifetime.** *Recommendation:* 90 days while the service is
   pre-alpha, with operator re-issue. Revisit when curation moves beyond
   invitation.
2. **Doors held by replicas.** v0 has one door per listing on one
   instance. *Recommendation:* defer. Several replicas behind one door need
   a shared door key and a rule for who approves, which deserves its own
   design.
3. **`EdDSA` or `Ed25519` as the JWS `alg`.** *Recommendation:* `EdDSA`
   for v0, because a2a-sdk 1.2.2 can verify it. Move to `Ed25519` in a
   later version once PyJWT supports it, never by accepting both.
4. **Silent drop on per-door overflow.** The other option is an honest
   `rate_limited`. That would tell a knocker the door is busy, and it
   would let a prober measure an owner's traffic. *Recommendation:* keep
   the silent drop. A flood is a denial of service either way.
5. **Name transfer on key rotation.** *Recommendation:* a new token from
   the operator plus the 30-day "key changed" banner, rather than letting
   the old key sign a handover. A compromised key must not be able to
   hand its name to the attacker.
