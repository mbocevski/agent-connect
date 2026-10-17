# Spike: OpenMLS with the X-Wing ciphersuite

- **Date:** 2026-10-17
- **Code:** `spikes/mls-xwing/` (each item is an integration test under
  `tests/`)
- **Question:** Can `core/` be built on OpenMLS with the post-quantum hybrid
  ciphersuite of SPEC §3.1, and what has to change in SPEC first?

## Decisions (maintainer, 2026-10-17)

| Question | Decision |
|---|---|
| Go / no-go | **GO** on OpenMLS 0.9 with `openmls_libcrux_crypto`. |
| hpke-rs MPL-2.0 | **Allowed, scoped** to the three hpke-rs crates (ADR-001 §4). |
| Ciphersuite | **WG track:** `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`, draft-ietf-mls-pq-ciphersuites TBD1, OpenMLS provisional `0x004F`. `0x004D` (X-Wing) is not used. |
| Provider advisories | **Build `core` now, mitigate:** check HPKE key lengths before OpenMLS; the `deny.toml` ignores are temporary; no release or public relay until a fixed provider ships (ADR-001 §2). |
| Invite binding | **AEAD-wrapped Welcome only** (SPEC §6.4); the PSK binding is dropped. |

The proposed SPEC edits below are applied in a follow-up change with these
choices.

## Recommendation: GO, with conditions

OpenMLS 0.9.1 with `openmls_libcrux_crypto` 0.4.0 does everything SPEC v0
needs from MLS:

- groups with the X-Wing suite
- SQLite persistence
- custom extensions with `RequiredCapabilities` enforcement
- epoch conflict recovery
- SAS fork detection
- an invite binding that works

The classical fallback (`0x0003`) is **not** needed.

Before `core/` depends on it, though, four things have to be settled:

1. **Wait for the next provider release (blocker).**
   `openmls_libcrux_crypto` 0.4.0 pins `libcrux-kem` 0.0.9, which is affected
   by RUSTSEC-2026-0330 and RUSTSEC-2026-0331, and `libcrux-hmac-drbg` 0.0.1,
   which is affected by RUSTSEC-2026-0329.
   - RUSTSEC-2026-0331 is **reachable**: a validly signed KeyPackage with a
     32-byte `init_key` passes `KeyPackageIn::validate` and then panics the
     inviter inside `add_members` (test
     `t9_advisories::malicious_key_package_crashes_the_inviter`). Anyone
     holding an invite link can therefore crash the inviter's daemon.
   - Upstream `main` already depends on the fixed crates (`hpke-rs` 0.8,
     `libcrux-kem` 0.0.10, `libcrux-hmac-drbg` 0.0.2), but they haven't been
     released as a provider yet.
   - Until they are, `core/` MUST check the length of every HPKE public key
     it accepts (1216 bytes for X-Wing) before calling OpenMLS.
2. **Approve the hpke-rs licence (maintainer sign-off).** `hpke-rs`,
   `hpke-rs-crypto` and `hpke-rs-libcrux` are **MPL-2.0**.
   - Both OpenMLS providers depend on them, so there's no OpenMLS without
     them.
   - MPL-2.0 is file-level copyleft. Using the crates unmodified is
     compatible with our Apache-2.0 licence and a hosted service, but it
     isn't on the ADR-001 §4 allowlist.
   - This branch adds crate-scoped `cargo-deny` exceptions marked
     PROVISIONAL.
3. **Pick the ciphersuite codepoint (maintainer decision).** `0x004D`
   (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`) comes from an expired
   individual draft.
   - The MLS WG draft doesn't define it.
   - Upstream `main` already calls it the "legacy X-Wing ciphersuite" and is
     changing its HPKE key derivation; compatibility with 0.4.0 needs an
     opt-in feature.
   - See [item 9](#9-maintenance-risk) and the proposed SPEC edits.
4. **Use the AEAD-wrapped Welcome (SPEC §6.4), not the PSK (SPEC §6.2).** The
   PSK works for 1:1 but breaks group mode (item 2).

## Versions

| Crate | Version | Licence | Notes |
|---|---|---|---|
| `openmls` | 0.9.1 (2026-10-07) | MIT | feature `draft-ietf-mls-pq-ciphersuites` is required for X-Wing |
| `openmls_libcrux_crypto` | 0.4.0 (2026-08-25) | MIT | same feature; pins vulnerable libcrux crates |
| `openmls_traits` | 0.6.0 | MIT | |
| `openmls_basic_credential` | 0.6.0 | MIT | |
| `openmls_sqlite_storage` | 0.3.0 | MIT | rusqlite 0.37, bundled SQLite (C) |
| `openmls_memory_storage` | 0.6.0 | MIT | transitive (the libcrux `Provider` uses it) |
| `hpke-rs`, `hpke-rs-crypto`, `hpke-rs-libcrux` | 0.7.0 | **MPL-2.0** | transitive |
| `libcrux-kem` | 0.0.9 | Apache-2.0 | RUSTSEC-2026-0330, -0331 |
| `libcrux-hmac-drbg` | 0.0.1 | Apache-2.0 | RUSTSEC-2026-0329 |
| `hkdf` / `sha2` | 0.13.0 / 0.11.1 | MIT/Apache-2.0 | SPEC §3.5 KDFs |

`openmls_sqlx_storage` 0.3.0 exists too, but wasn't tried. Its manifest
lists no `draft-ietf-mls-pq-ciphersuites` feature.

## Findings per item

### 1. Group lifecycle with X-Wing — works

Test: `t1_lifecycle`. The test covers:

- create
- add 3 members in one commit (one Welcome)
- app messages both ways
- remove 2 members

Member B stores its state in a **SQLite file**. The test closes and reopens
the connection between steps, then reloads the group with `MlsGroup::load`.

A removed member gets nothing from next-epoch messages:

- If it processed its removal, OpenMLS refuses with
  `MlsGroupStateError::UseAfterEviction`.
- If it never saw the removal, it fails with `ValidationError::WrongEpoch`.
  It has no secrets for the new epoch.

SQLite needs a provider of our own. `openmls_libcrux_crypto::Provider`
hard-wires `MemoryStorage`, so `SqliteProvider` in `src/lib.rs` pairs
libcrux's `CryptoProvider` with `SqliteStorageProvider`. The whole thing is
about 20 lines.

### 2. Invite binding — PSK works mechanically, but use the AEAD wrap

Test: `t2_invite_binding`.

**PSK in the Welcome (SPEC §6.2).** This works through the `commit_builder`:
`propose_adds` + `add_proposal(Proposal::PreSharedKey(..))` + `load_psks`.

- The psk_id is `"ac:v0:invite:" ‖ invite_id` and the PSK is HKDF-SHA256 per
  §3.5.
- A joiner without the PSK fails with `WelcomeError::Psk(..)`. A wrong secret
  also fails. The right PSK joins.

Two problems make the PSK unsuitable:

- **Every existing member needs the PSK too.** A PSK proposal feeds the key
  schedule of the new epoch for *all* members.
  - An existing member without it fails with
    `InvalidCommit(PskError(KeyNotFound))` and can't advance.
  - That contradicts §4.3 ("only the creating instance holds the invite
    secret").
  - Worse, the failed attempt consumes the commit's decryption key: a retry
    after learning the PSK fails with `SecretReuseError`. The member is
    permanently forked off.
  - The only fix would be for the inviter to distribute the PSK to every
    member before each Add. That's an extra round trip and spreads
    invite-derived secrets.
- **A failed Welcome burns the joiner's KeyPackage.**
  `ProcessedWelcome::new_from_welcome` deletes the KeyPackage private key
  *before* it loads PSKs, so storing the PSK and retrying gives
  `NoMatchingKeyPackage`. §6.1 already says to store the PSK first; this
  makes it mandatory.

**AEAD-wrapped Welcome (SPEC §6.4).** This works and has neither problem:

- The commit is a plain Add, which existing members process without any
  invite material.
- A wrong secret or a tampered wrapper is rejected *before* MLS touches the
  KeyPackage.

The prototype uses `OpenMlsCrypto::aead_encrypt`/`aead_decrypt` (libcrux
ChaCha20-Poly1305), so it needs no extra dependency.

The security argument is equivalent for v0:

- Only someone with `invite_secret` can produce a wrapper the joiner
  accepts.
- The JoinRequest MAC covers the other direction.

### 3. SAS from `epoch_authenticator` — works

Test: `t3_sas`.

- All members at the same epoch derive the same `sas_bytes`, and the code
  changes with each epoch.
- **Relay fork:** A and B commit concurrently. The relay gives A's commit to
  C and drops it for B. All three end at the same epoch *number*, but
  SAS(A) = SAS(C) ≠ SAS(B).
- **Two parallel groups** with the same `group_id` (SPEC §14.4) give
  different codes.
- A decimal rendering vector is included.

The derivation follows §3.5 exactly:
`HKDF(ikm = epoch_authenticator, salt = group_id, info = label ‖ u64be(epoch), L = 6)`.

### 4. Epoch conflict — works

Test: `t4_epoch_conflict`. A toy relay accepts only commits for its current
epoch. Two members build commits from epoch *n*:

- The winner's commit is accepted and fanned out.
- The loser runs `clear_pending_commit`, processes the winner's commit,
  rebuilds at *n + 1*, and its commit applies at everyone.

OpenMLS also lets the loser process the winning commit without discarding
its own first. Merging the winning commit drops the stale pending commit.

**Important:** a sender must not merge its own commit until the relay
confirms it. Merging an unconfirmed commit is exactly how item 3's fork
arises.

### 5. Custom extensions and RequiredCapabilities — works, with caveats

Test: `t5_extensions`.

What works:

- `ac_group_policy` (0xF0A1) and `ac_group_meta` (0xF0A2) as
  `Extension::Unknown` in the GroupContext round-trip through the Welcome.
- `ac_instance_cert` (0xF0A3) in each LeafNode round-trips, and is readable
  via `public_group().leaf(i).extensions().unknown(..)`.
- A policy change via a GroupContextExtensions commit round-trips.
- `ratchet_tree` may be listed in `RequiredCapabilities`.

What gets rejected:

- A member whose leaf doesn't advertise the extensions:
  `ProposalValidationError::InsufficientCapabilities`.
- A leaf extension missing from the leaf's own capabilities:
  `LeafNodeValidation(UnsupportedExtensions)`. This is checked when the Add
  is committed; `KeyPackage::builder()` doesn't check it.

Caveats:

- `RequiredCapabilities` only means "supports". A leaf that advertises 0xF0A3
  but carries no `ac_instance_cert` is accepted, so the §3.1 presence check
  is ours to do.
- A GroupContextExtensions proposal **replaces the whole set**, so every
  policy change must resend `ac_group_meta` and `RequiredCapabilities`.

### 6. SelfRemove — supported, but not under our wire format policy

Test: `t6_self_remove`. OpenMLS 0.9 implements the SelfRemove proposal
(`leave_group_via_self_remove`), but only as a `PublicMessage`.

- Under `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` it returns
  `CannotSelfRemoveWithPureCiphertext`.
- It works with `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY`. That would mean
  accepting plaintext handshakes, which SPEC §3.1 forbids.

What works under PrivateMessage-only is `leave_group()`, a Remove proposal
for one's own leaf that any other member commits. Use that for v0.

### 7. Sizes and latency

Test: `t7_measure` (`#[ignore]`d). Run it with:

```
cargo test --release -p agentconnect-spike-mls-xwing --test t7_measure -- --ignored --nocapture
```

Setup:

- Release build on an Intel Core Ultra 7 155U laptop.
- 20-round averages; single-shot for join.
- 256-byte app payload; PrivateMessage throughout.

| N | KeyPackage B | Welcome B (add Nth) | Add commit B | Update commit B | App msg B | create commit ms | process commit ms | join ms |
|---|---|---|---|---|---|---|---|---|
| 2 | 2663 | 5462 | 5455 | 3960 | 402 | 0.43 | 0.41 | 0.49 |
| 5 | 2663 | 12105 | 11408 | 9913 | 402 | 1.14 | 0.85 | 1.74 |
| 20 | 2663 | 35313 | 31418 | 29922 | 402 | 2.04 | 1.11 | 2.04 |

How to read the table:

- An X-Wing public key is 1216 bytes and an HPKE ciphertext about 1.1 KB, so
  a KeyPackage carries two keys.
- Commit size grows roughly linearly here. The group was built by one bulk
  Add, so parent nodes are blank and path secrets are encrypted to whole
  resolutions. As members commit their own updates the tree fills, and
  commits trend towards O(log N).
- Everything fits comfortably in the 1 MiB frame limit (§8.3) at the
  50-member cap.
- CPU cost is negligible.

### 8. PyO3 feasibility — feasible, sync, bytes in and bytes out

Test: `t8_pyo3_shape` is a compile-time check plus a working handle.

- PyO3 ≥ 0.23 requires `#[pyclass]` types to be `Send + Sync`.
  - `MlsGroup`, `SignatureKeyPair`, the libcrux `Provider`, `KeyPackage` and
    `MlsMessageOut` all are.
  - `rusqlite::Connection` is `Send` but **not `Sync`**. Hold a
    `Mutex<Connection>` and build a borrowed `SqliteProvider<&Connection>`
    per call. `SqliteStorageProvider` is generic over `Borrow<Connection>`,
    so this costs nothing.
  - `t8` shows a `GroupHandle { Mutex<Connection>, GroupId, SignatureKeyPair }`
    that loads the group, encrypts and returns bytes.
- **Storage ownership.** OpenMLS writes through to storage on every mutating
  call, and `MlsGroup` is a cache of it. A binding can reload per call, as
  `t8` does, or keep the `MlsGroup` inside the same lock.
- **Async.**
  - 0.9.1 is sync, so call it from Python with the GIL released
    (`Python::detach` / `allow_threads`). Operations take about 1–2 ms.
  - Upstream `main` adds an `async` storage feature, but enabling it in
    *any* crate switches the whole build to async. Stay sync behind PyO3.
- **abi3.** Nothing in OpenMLS touches the Python C API, so `abi3-py312` is
  fine. The bundled SQLite needs a C compiler in the wheel build, which
  maturin already handles.
- **API surface.** OpenMLS error types are generic over the storage error,
  and the API is pre-1.0. Keep every OpenMLS type out of the Python API:
  `core` exposes bytes and its own error enum.
- **Panics.** PyO3 turns a Rust panic into `PanicException`, which contains
  the item 9 DoS when called from Python. The group's storage may be left
  half-written, though, so don't rely on that.

### 9. Maintenance risk

**OpenMLS release cadence.** Minor (breaking) releases:

| Version | Date |
|---|---|
| 0.5 | 2023-07 |
| 0.6 | 2024-09 |
| 0.7 | 2025-07 |
| 0.8 | 2026-02 |
| 0.9 | 2026-08-25 |

- Patch releases ship for advisories, with backports: 0.9.1 and 0.8.2 came
  out the same day (2026-10-07) for GHSA-gc79-23g3-8g52.
- There were five GHSAs between 2025-09 and 2026-10: three DoS-class and two
  validation/persistence bugs. All were fixed promptly. 0.9.1 includes all
  of them.
- Development is active; the last commit to `main` was 2026-10-14.
- Unreleased `main` already breaks API again:
  - `Capabilities` lose their defaults.
  - Secret exports return a zeroizing `ExportedSecret`.
  - MSRV 1.94.
  - An optional async mode.
- Expect a migration roughly every six months. Wrapping OpenMLS behind
  `core`'s API (ADR-001) is the right call.

**libcrux stability.**

- The crates are 0.0.x. Under Cargo semver every bump is breaking, so fixes
  only reach us through a provider release; we can't `cargo update` them.
- `libcrux-kem` shipped 0.0.7 → 0.0.10 between March and October 2026.
- Three RUSTSEC advisories landed in October 2026. Two are in key
  (de)serialisation glue, not the verified ML-KEM core.
- The build pulls in `hax-lib-macros` → `proc-macro-error2`, which is
  unmaintained (RUSTSEC-2026-0173). That code runs at build time only.

**X-Wing and codepoint status.**

- *The KEM.* `draft-connolly-cfrg-xwing-kem` is at -09 (2025-09) or -10
  (2026-03); the datatracker pages disagree. The CFRG declined to adopt it,
  and the authors are taking it to the Independent Stream. OpenMLS 0.4.0
  uses X-Wing **draft-06**.
- *The MLS suite.* `0x004D` comes from `draft-mahy-mls-xwing-00`, an
  individual draft from March 2024 that has expired. It has no IANA
  registration.
- *The WG standard.* `draft-ietf-mls-pq-ciphersuites-06` (2026-07-21, in WG
  Last Call):
  - It defines **no X-Wing suite**.
  - Its X25519 hybrid suites are `MLS_128_MLKEM768X25519_*`, using the
    `MLKEM768-X25519` KEM (`0x647a`) from `draft-ietf-hpke-pq-05`.
  - Their codepoints are TBD; OpenMLS uses provisional values `0x004F`
    (TBD1, AES-128-GCM/SHA-256) and `0x004E` (TBD2, AES-256-GCM/SHA-384).
- *OpenMLS's mapping.* OpenMLS 0.4.0 maps those WG suites to the same
  X-Wing draft-06 KEM. `t9::wg_track_suite_0x004f_also_runs_on_libcrux`
  shows that a group can be created with TBD1 on the current provider.
- *Upstream direction.* Upstream `main` switches PQ key derivation to
  `draft-ietf-hpke-pq` and keeps the old derivation for `0x004D` behind an
  opt-in `legacy-pq-key-derivation` feature. 0.4.0 groups won't interoperate
  with the next provider by default.
- *Naming.* The suite name claims `MLS_256`, but X-Wing gives ML-KEM-768
  strength (NIST level 3). The WG names the comparable suite `MLS_128`.

Whatever we pick, wire compatibility of a draft codepoint isn't stable. SPEC
§13 already ties the suite to the protocol version, so a codepoint change
means a protocol version bump.

## API gotchas

- **Two `OpenMlsProvider` traits.** Generic code needs
  `openmls::storage::OpenMlsProvider` (it has `StorageError`). The prelude
  re-exports the `openmls_traits` one, and implementing a provider uses
  that one.
- **PSK types aren't in the prelude.** Use
  `openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk}`.
- **`PreSharedKeyId::store` ignores the nonce.** The storage key is the PSK
  id, so a joiner can store `PreSharedKeyId::external(id, vec![])`.
- **Builder order matters.** `MlsGroupCreateConfig::builder()` checks leaf
  extensions against capabilities set *earlier*. Call `.capabilities(..)`
  before `.with_leaf_node_extensions(..)`.
- **`KeyPackage::builder()` checks little.** It doesn't check leaf
  extensions against capabilities, and `KeyPackageIn::validate` doesn't check
  public key lengths. Both are caught (or crash, item 9) only when committing.
- **Failed processing consumes key material.** A failed Welcome burns the
  KeyPackage. A failed commit or app message burns its secret-tree key, so
  retrying gives `SecretReuseError`. Validate everything you can *before*
  calling OpenMLS, and treat processing as one-shot.
- **`add_members` and the commit bundle.** `add_members` returns
  `(commit, welcome, group_info)`, where the Welcome is already an
  `MlsMessageOut`. `commit_builder` returns a bundle: use `.commit()` and
  `.to_welcome_msg()`.
- **Echoed own commits.** When the relay fans a sender's own commit back to
  it, 0.9 returns `ProcessedMessageContent::OwnPendingCommit`, and the sender
  must call `merge_pending_commit`. This is from the changelog and isn't
  exercised in the spike.
- **No injectable RNG.** The libcrux provider seeds its DRBG from the OS,
  and `SignatureKeyPair::new` uses its own RNG. Deterministic test vectors
  (AGENTS.md) need a `core` provider whose `RandProvider` is a seeded RNG,
  with libcrux used only for `CryptoProvider`. The trait split allows this.
  Every spike test is random but asserts only on relationships between
  values.
- **The X-Wing suite is feature-gated.** It doesn't exist without
  `draft-ietf-mls-pq-ciphersuites` on `openmls`, `openmls_traits`,
  `openmls_libcrux_crypto`, `openmls_basic_credential` and
  `openmls_sqlite_storage`. Enable it workspace-wide.

## Proposed SPEC.md changes

These aren't applied here; they need the maintainer's review.

1. **§3.1 ciphersuite.** Choose one:
   - **(a)** Keep `0x004D`, pinning a provider with
     `legacy-pq-key-derivation` from the next release onwards. This is the
     least work, but it's off the standards track and upstream calls it
     legacy.
   - **(b) Recommended:** switch v0 to
     `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
     (draft-ietf-mls-pq-ciphersuites TBD1, OpenMLS provisional `0x004F`).
     This is the WG track with the same hybrid KEM family.

   Either way:
   - Record the exact codepoint and the KEM draft revision.
   - Note that the suite is gated behind an OpenMLS draft feature.
   - Fix the AGENTS.md rule that names the suite.
   - Drop the "256" claim, or explain it.
   - Freeze test vectors only once the next provider release (with the new
     HPKE-PQ derivation) is out.
2. **§3.1 and §6.2 step 3: key lengths.** Add "every HPKE public key in a
   KeyPackage or LeafNode MUST have the suite's public key length (1216
   bytes for X-Wing) and is checked before MLS processing". This is defence
   in depth, and needed until the libcrux fix ships.
3. **§3.1 Required extensions.** Note that `RequiredCapabilities` doesn't
   enforce presence; the existing MUST on `ac_instance_cert` stands.
   `ratchet_tree` may stay in the list (it's accepted) or be dropped as a
   default extension.
4. **§3.5.** Remove the `invite_psk` row.
5. **§6.1.** Remove "B stores `invite_psk` …". B keeps `welcome_key` until
   it joins or the invite expires.
6. **§6.2 step 5.** The commit carries `Add(B.key_package)`, plus
   GroupContextExtensions when §9.1's floor switch applies, and no PSK.
   - Step 6: send `WrappedWelcome` (envelope `kind: welcome_wrapped`).
   - Add the reason: a PSK proposal would require every existing member to
     hold the invite PSK.
7. **§6.3.** Unwrap with `welcome_key` and abort on AEAD failure. Note that
   any failure processing a Welcome consumes B's KeyPackage, so a retry needs
   a new KeyPackage and JoinRequest. Replace "with the stored PSK" and the
   PSK-deletion bullet with "delete `welcome_key` and the invite secret".
8. **§6.4.** Make the AEAD wrap the normative mode, rename the section
   (no longer a fallback), and remove the "decided in the spike" sentence.
   Make `welcome_wrapped` the only Welcome envelope kind in v0.
9. **§8.3 commit ordering.** Add "a sender MUST NOT merge its own commit
   until the relay confirms it (`accepted`, or its own commit delivered
   back)". On `epoch_conflict` it calls `clear_pending_commit` as already
   described.
10. **§9.2 Remove self.** Replace with "a Remove proposal for its own leaf,
    sent as PrivateMessage and committed by any other member". Note that
    SelfRemove needs PublicMessage in OpenMLS 0.9 and isn't used in v0. A
    sole remaining member just deletes its state.
11. **§9.2 Policy change.** A GroupContextExtensions proposal replaces the
    whole set: it MUST carry `ac_group_meta` and `RequiredCapabilities` along
    with the new `ac_group_policy`. Receivers check that the immutable parts
    are unchanged.
12. **§15.** Resolve questions 1 (AEAD), 2 (no SelfRemove under
    PrivateMessage) and 3 (per the §3.1 choice).

Outside SPEC:

- **ADR-001 §2.** The OpenMLS version is fine. Add the advisory status of
  the 0.4.0 provider, and the decision to wait for its successor.
- **ADR-001 §4.** If the hpke-rs exception is approved, add MPL-2.0
  (crate-scoped to hpke-rs) to the licence policy. Then drop "PROVISIONAL"
  from `deny.toml`.

## Sources

- OpenMLS changelog and libcrux provider manifest (`main`):
  <https://github.com/openmls/openmls/blob/main/CHANGELOG.md>,
  <https://github.com/openmls/openmls/blob/main/libcrux_crypto/Cargo.toml>
- OpenMLS security advisories:
  <https://github.com/openmls/openmls/security/advisories>
- RustSec: RUSTSEC-2026-0329, -0330, -0331, -0173 (<https://rustsec.org>)
- <https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/>
- <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>
- <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>
- <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/>
- `draft-mahy-mls-xwing-00`:
  <https://www.ietf.org/archive/id/draft-mahy-mls-xwing-00.html>
- Cryspen, "Post-Quantum OpenMLS": <https://cryspen.com/post/pq-openmls/>
- crates.io release history for `openmls`, `openmls_libcrux_crypto`,
  `hpke-rs-libcrux` and `libcrux-kem`
