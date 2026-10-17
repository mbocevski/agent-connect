# Testing

How we test AgentConnect. The goal: tests that are fast, deterministic and
hard to skip. The protocol is in `SPEC.md`; commands live in the `justfile`.

## Tiers

| Command | Contents | Budget | Network / docker | Runs |
|---|---|---|---|---|
| `just test` | Rust and Python unit, property and contract tests (`just contract`) | < 60 s | none | pre-push, CI |
| `just test-int` | docker compose integration (relay + daemons) and demos | < 10 min | docker | CI (once populated) |
| `just test-nightly` | mutation testing, long property runs (`HYPOTHESIS_PROFILE=nightly`), quarantined tests; fuzzing and criterion benchmarks as they land | hours | as needed | nightly workflow, non-gating |
| `just ci` | exactly the PR pipeline: `lint`, `test`, `cov` (gates and ratchet), `changelog-check` | minutes | none | PR CI (`ci-ok`) |

`just test` must stay under 60 seconds on a laptop. If it gets slower, move
the slow test to a higher tier or make it faster. Do not raise the budget.

## Where tests live

| Kind | Location |
|---|---|
| Rust unit tests | inline `#[cfg(test)] mod tests` in the file under test |
| Rust integration tests | `<crate>/tests/*.rs` |
| Python tests | `<package>/tests/` (`core-py/tests`, `daemon/tests`, `sdk/python/tests`, `scripts/tests`) |
| Shared vectors and schemas | `testdata/`, listed in `testdata/MANIFEST.json` |
| Multi-node harness (phase 2) | `harness/` |

`conftest.py` at the repository root is shared by every Python test directory.

## Rules

- **Every bug fix ships with a regression test** that fails without the fix.
- **Test first for protocol and crypto code** (`core/`, wire formats). Crypto
  changes need vectors plus negative tests (see `AGENTS.md`).
- **No sleeps.** Code under test takes a `Clock`; tests drive a `FakeClock`.
- **No network and no docker in the fast tier.** Bind to loopback only in
  integration tests.
- Tests are independent and order-insensitive. No shared mutable state, no
  writes outside a temp directory.

## Determinism

- **Clock.** Rust: `agentconnect_core::clock::{Clock, SystemClock, FakeClock}`.
  Python: `agentconnect.clock.{Clock, SystemClock, FakeClock}` and the
  `fake_clock` fixture. Both fake clocks start at 2025-01-01T00:00:00Z, move
  only through `advance`/`set`, and are thread-safe.
- **Seeded randomness.** One seed per run, taken from `AC_TEST_SEED` (an
  integer) or chosen at random. pytest prints it in the report header and
  repeats it after any failure; reproduce with `AC_TEST_SEED=<n> just test-py`.
  Python tests use the `rng` fixture (a `random.Random` derived from the seed
  and the test id) or `test_seed`. Rust property tests read the same variable
  when `proptest` is added to `core`; until then there is no Rust randomness to
  seed.
- **Hypothesis profiles** (`conftest.py`): `dev` (default locally), `ci`
  (derandomized, no example database; selected automatically when `CI` is set)
  and `nightly` (2000 examples, no deadline). Override with
  `HYPOTHESIS_PROFILE`.
- **Timeouts.** pytest: 10 s per test (`pytest-timeout`). nextest: slow after
  10 s, terminated after 30 s (`.config/nextest.toml`). A timeout is a failure.

## Contract tests

`testdata/` holds the wire formats and vectors that Rust and Python must both
honour. `testdata/MANIFEST.json` lists every file, the suites (`rust`,
`python`) that must consume it and, for vendored files, the provenance (source
URL, commit, checksum, licence). `scripts/check_manifest.py` (`just contract`,
part of `just test` and a CI job) fails when:

- a file in `testdata/` is not in the manifest, or an entry has no file;
- a declared suite has no test source that mentions the file name.

Vendored vectors are kept byte-for-byte; the pre-commit hooks exempt them from
the end-of-file fixer, the typo check and the attribution scan. First vector: `testdata/sas-emoji.json`, the Matrix SAS
emoji table (64 entries, Apache-2.0) used by SPEC section 11. It is checked
by `core/tests/sas_emoji_vector.rs` and `daemon/tests/test_sas_emoji_vector.py`.

To add a vector: add the file, add its manifest entry, write the Rust and
Python tests that load it, run `just contract`.

## Coverage

| Component | Gate (`just cov`) | Metric |
|---|---|---|
| `core` | >= 90% | lines (`cargo llvm-cov`) |
| `relay` | >= 80% | lines (`cargo llvm-cov`, `main.rs` excluded) |
| Python | >= 85% | lines + branches (`coverage.py`, `branch = true`) |

**Rust branch coverage is not gated.** `cargo llvm-cov --branch` requires a
nightly compiler and is flagged unstable upstream, and the main toolchain
stays on pinned stable. The nightly workflow runs `just cov-rust-branch` on a
nightly toolchain (`rust-branch-coverage` job) and reports the numbers without
gating. Revisit when `--branch` stabilises.

**Ratchet.** `coverage-baseline.json` records current coverage per component.
`just cov-rust` and `just cov-py` run `scripts/cov_ratchet.py check`, which
fails if a component is more than 0.5 percentage points below its baseline,
even when it is still above the gate. Raise the baseline when coverage
improves: after a PR merges, run `just cov-baseline` on an up-to-date `main`
checkout and commit the result as `chore(ci): update coverage baseline`. Never
lower it to make a failure pass; add tests instead.

## Flaky tests

- `core` and `relay`: **no retries**. nextest runs with `retries = 0`. A flaky
  test there is a bug in the test or the code and is fixed, not retried.
- Elsewhere: at most one retry, and a test that needed it is reported as
  flaky.
- A test that is flaky twice is marked `@pytest.mark.quarantine` and gets an
  issue. Quarantined tests are excluded from gating runs (deselected unless
  `AC_RUN_QUARANTINE=1`) and run in the nightly tier. A quarantine expires
  after 14 days: fix the test or delete it.

## Benchmarks

Criterion benchmarks for `core` (group operations, envelope seal/open, SAS)
are added with the core and run in the nightly workflow. They are
non-gating: results are stored as artifacts and compared by hand until there
is enough history to alert on regressions.

## Phase 2: multi-node harness (spec)

Lands with the daemon. It lives in `harness/` and runs inside `just test`.

- **In-process.** One relay and N daemons in a single process, wired over
  in-memory transports. No sockets, no docker, no threads that sleep.
- **Shared fake clock.** Every component takes the same `FakeClock`;
  `advance(time)` is the only way time moves, and it runs timers
  deterministically.
- **Recording adapter.** A test adapter on each daemon records every
  delivered, rejected and policy-blocked message so tests assert on what
  agents saw.
- **Fixtures:**
  - `group(n, mode)`: a group of `n` members in the given mode, fully joined
    and with one epoch settled.
  - `invite`: create and redeem an invite link, with options for use limits,
    expiry and a wrong secret.
  - `partition(member)`: cut a member off from the relay, and heal it later.
  - `advance(time)`: advance the shared clock.
  - `malicious_relay(...)`: a relay that drops, delays, reorders, replays,
    injects or forks, to exercise the threat model in SPEC section 12.
- **Seeded.** Scheduling and fault injection draw from `AC_TEST_SEED`.
- **Budget.** A 5-member scenario (create, join, message round, one commit,
  SAS compare) finishes in under 2 s.
