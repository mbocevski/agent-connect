# Testing

How we test AgentConnect. The goal: tests that are fast, deterministic and
hard to skip. The protocol is in `SPEC.md`; commands live in the `justfile`.

## Tiers

| Command | Contents | Budget | Network / docker | Runs |
|---|---|---|---|---|
| `just test` | Rust and Python unit, property and contract tests (`just contract`), multi-node harness scenarios | < 60 s | loopback only | pre-push, CI |
| `just test-int` | docker compose integration (relay + daemons) and demos | < 10 min | docker | CI (once populated) |
| `just test-nightly` | mutation testing, long property runs (`HYPOTHESIS_PROFILE=nightly`), quarantined tests; fuzzing and criterion benchmarks as they land | hours | as needed | nightly workflow, non-gating |
| `just ci` | exactly the PR pipeline: `lint`, `test`, `cov` (gates and ratchet), `changelog-check`, `docs-check` | minutes | none | PR CI (`ci-ok`) |

`just test` must stay under 60 seconds on a laptop. If it gets slower, move
the slow test to a higher tier or make it faster. Do not raise the budget.
The Python suite runs on every core (`pytest -n auto`, pytest-xdist); each
worker starts its own relay, and every worker uses the controller's seed.

## Where tests live

| Kind | Location |
|---|---|
| Rust unit tests | inline `#[cfg(test)] mod tests` in the file under test |
| Rust integration tests | `<crate>/tests/*.rs` |
| Python tests | `<package>/tests/` (`core-py/tests`, `daemon/tests`, `harness/tests`, `sdk/python/tests`, `scripts/tests`) |
| Shared vectors and schemas | `testdata/`, listed in `testdata/MANIFEST.json` |
| Multi-node harness (phase 2) | `harness/src` (fixtures), `harness/tests` (scenarios) |

`conftest.py` at the repository root is shared by every Python test directory.

## Rules

- **Every bug fix ships with a regression test** that fails without the fix.
- **Test first for protocol and crypto code** (`core/`, wire formats). Crypto
  changes need vectors plus negative tests (see `AGENTS.md`).
- **No sleeps.** Code under test takes a `Clock`; tests drive a `FakeClock`.
- **No external network and no docker in the fast tier.** Loopback only:
  the relay's tests and the multi-node harness bind `127.0.0.1`.
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
  and the test id) or `test_seed`. Rust tests take key material from
  `agentconnect_core::Rng::for_test(label)`, a ChaCha20 stream seeded with
  SHA-256(seed ‖ label); `core`'s property tests seed proptest from the same
  variable. Never write keys, secrets, nonces or RNG seeds as literals in
  tests.
- **No hard-coded key material.** Tests never write keys, secrets or nonces
  as literal bytes (code scanning flags this as a hard-coded cryptographic
  value). Generate them at random, or, when a test needs the same key for the
  same label within a run, derive it from a per-run seed (`AC_TEST_SEED` when
  set): e.g. `SHA-256(seed || n)`. Fixed bytes belong only in `testdata/`
  vectors, whose inputs are published test values.
- **Hypothesis profiles** (`conftest.py`): `dev` (default locally), `ci`
  (derandomized, no example database; selected automatically when `CI` is set)
  and `nightly` (2000 examples, no deadline). Override with
  `HYPOTHESIS_PROFILE`.
- **Timeouts.** pytest: 10 s per test (`pytest-timeout`), and 30 s for tests
  under `harness/`, whose setup and teardown start and stop a real relay and
  several daemons (set in the harness plugin; an explicit
  `@pytest.mark.timeout` wins). nextest: slow after
  10 s, terminated after 30 s (`.config/nextest.toml`). A timeout is a failure.
  An intermittent one is usually a hang, not slowness: don't raise the limit.
  Reproduce it with many parallel loops under coverage (CI runs `just cov-py`)
  and `-o faulthandler_timeout=20`, which dumps the stacks. A busy loop shows up
  as a different Python frame in each dump.

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

The `core` vectors (`invite-kdf.json`, `sas-vectors.json`,
`padding-vectors.json`, `instance-cert.json`, `invite-urls.json`) are
generated by `core/src/vectors.rs`. Each file stores the seed its inputs
come from; the check reads it and recomputes the outputs. `just vectors`
regenerates them with a fresh seed (`AC_TEST_SEED=<n> just vectors` is
reproducible); review the diff before committing.

## README quickstart

The README's quickstart is a test. A shell block is runnable when the line
before its fence is `<!-- runnable: <actor> -->` (`alice` or `bob`).
`harness/tests/test_readme.py` runs the blocks in order against the harness
relay, in the fast tier:

- The test owns each actor's environment. `source .venv/bin/activate` and
  `export AC_*=...` lines are checked, not run: the test puts the workspace's
  `agentconnect` on PATH and sets the same variables to its own values.
- `agentconnect daemon run ...` starts that actor's daemon in-process (no
  auto-approve) with the local API on its Unix socket.
- Every other line runs in bash as that actor and must exit 0. `<url>` is
  replaced by the last invite URL a command printed, `<request_id>` by the
  actor's pending approval and `<group>` by its group, after every daemon
  has joined and settled. Prompts (`accept`, `approvals approve`, `verify`)
  are answered `y`.
- `accept` waits for the inviter's approval, so it runs in the background,
  as in its own terminal; that actor's next step waits for it to finish.
- At the end, Bob's daemon must have received Alice's message and each side
  must have marked the other verified.

Separate tests cover the parser, the README's shape (actors, exported
variables, only commands the CLI has) and the runner. A quickstart that
uses a new command or placeholder needs the runner taught about it. When
you change the quickstart, run `just test-py`.

## Docs checks

`just lint` (and the pre-commit hook) also checks Markdown:

| Check | Tool | Config |
|---|---|---|
| Markdown lint | `rumdl` | `.rumdl.toml` |
| Relative links and anchors (offline) | `lychee --offline` | `lychee.toml` |
| Prose rules: filler, hype, absolute security claims, emoji | Vale | `.vale.ini`, `styles/AgentConnect/` |

Vale reports errors in `README.md` and `docs/` and warnings elsewhere. The
nightly workflow runs lychee with network access to check external links.
`just docs-check` is the docs gate (CONTRIBUTING.md).

## Generated reference

`scripts/gen_reference.py` writes the reference sections of `docs/cli.md`,
`docs/api.md` and `docs/config.md` from the code (`just docs-gen`):

| Docs section | Source |
|---|---|
| CLI commands, options, defaults, help | the typer app (`agentconnect.cli.app`), introspected |
| Exit codes | `agentconnect.cli_support.EXIT_CODES` |
| `--json` shapes | `agentconnect.cli_json.SCHEMAS` |
| Local API routes and errors | `ROUTE_SPECS` and `API_ERRORS` in `agentconnect.runtime.api`; the server is built from the same table |
| Config keys and environment overrides | `CONFIG_KEYS` in `agentconnect.config` and the `Config` dataclass |

Tests keep the sources honest:

- `scripts/tests/test_gen_reference.py` regenerates in memory and fails when
  the committed docs differ, telling you to run `just docs-gen`. It runs in
  `just test`.
- `daemon/tests/test_cli_commands.py` checks real `--json` output against the
  same shapes the docs show (`agentconnect.shapes.conforms`).
- `harness/tests/test_api_shapes.py` checks real API requests and responses
  against `ROUTE_SPECS`.
- `daemon/tests/test_reference_sources.py` checks that every exit code,
  config field and route handler is covered by its table.

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
even when it is still above the gate. Raise the baseline in the same PR that
improves coverage: run `just cov-baseline` on the branch and commit the
updated `coverage-baseline.json` with the change. (`main` only changes through
PRs, so there is no separate baseline step after merging.) Never lower the
baseline to make a failure pass; add tests instead.

## Flaky tests

- `core` and `relay`: **no retries**. nextest runs with `retries = 0`. A flaky
  test there is a bug in the test or the code and is fixed, not retried.
- Elsewhere: at most one retry, and a test that needed it is reported as
  flaky.
- A test that is flaky twice is marked `@pytest.mark.quarantine` and gets an
  issue. Quarantined tests are excluded from gating runs (deselected unless
  `AC_RUN_QUARANTINE=1`) and run in the nightly tier. A quarantine expires
  after 14 days: fix the test or delete it.

## Tests that need a second OS user

The separate-OS-user mode (`docs/isolation.md`) is tested in the fast tier
with an injected peer-credential provider. The one test that connects as a
real second user (`nobody`) is marked `@pytest.mark.multiuser` and skipped
unless it runs as root with `AC_RUN_MULTIUSER=1`:
`sudo AC_RUN_MULTIUSER=1 uv run --all-packages pytest -m multiuser`.

## Benchmarks

Criterion benchmarks for `core` (group operations, envelope seal/open, SAS)
are added with the core and run in the nightly workflow. They are
non-gating: results are stored as artifacts and compared by hand until there
is enough history to alert on regressions.

## Phase 2: multi-node harness

The harness lives in `harness/` (package `agentconnect_harness`, fixtures
registered by the root `conftest.py`) and runs inside `just test`. The
scenarios are in `harness/tests/`.

- **Real relay, in-process daemons.** The relay is the real binary,
  built once per session (`just build-relay-dev`, which `test-py` and the
  coverage run invoke first; the fixture rebuilds only if the binary is
  missing or older than `relay/src` and `core/src`; `AC_RELAY_BIN` points at
  a prebuilt one). It runs on a random loopback port with a temporary SQLite
  database and is torn down at the end of the session. Daemons run in the
  test process, so coverage measures them directly. Traffic is loopback
  only; there is no docker and nothing sleeps.
- **One proxy per daemon.** Each daemon reaches the relay through a small
  WebSocket proxy (`proxy.py`). It is honest by default and is how
  `partition` and `malicious_relay` work. REST calls go straight to the
  relay.
- **Shared fake clock, daemons only.** Every daemon takes the cluster's
  `FakeClock`, which starts at the real current time so signed REST
  timestamps and invite expiries agree with the relay. `advance(time)` is
  the only way daemon time moves; reconnect backoff, delivery retries and
  rate-limit pauses all wait on it. **The relay uses the system clock**, so
  relay-side time behaviour (message and invite TTLs, replay-cache expiry)
  stays covered by the relay's own Rust tests, not by the harness.
- **Recording adapter.** `agentconnect.adapter.RecordingAdapter` records
  every delivery (with its untrusted framing) and every event, and can
  return `retry` on demand.
- **Both hosts, one suite.** Every node is a `Runtime` (ADR-005), and the
  `cluster` fixture runs each scenario twice: on the `daemon` host (what
  `agentconnectd` runs) and on the `embedded` host (what
  `AgentConnect.embedded` runs: the SDK's embedded host with its in-process
  callback adapter, stored deduplication and dispatch to handlers). On the
  embedded host the node's recording adapter sits in front of the callback
  adapter, so a scenario's assertions hold on both, and `node.handled`
  records what reached user code; `node.sdk` is the SDK client. A scenario
  that is about one host itself carries `@pytest.mark.hosts("daemon")`.
- **Fixtures:**
  - `cluster`: `await cluster.node(name, auto_approve=..., identity_of=...)`
    starts a node; `identity_of` makes a replica of another node's
    identity, `host=` picks a host for one node, and `serve_api=True`
    serves its local API as the hosts do.
  - `group(n, mode)`: `n` members fully joined and settled; `mode` is
    `"distinct"` (one identity each) or `"replicas"` (instances of one
    identity).
  - `invite(inviter, joiner, group_id)`: create, redeem and approve an
    invite, waiting until every member is on the new epoch.
  - `partition(node)` / `heal(node)`: cut a daemon's connection; healing
    advances the clock past its reconnect backoff.
  - `advance(seconds)`: move daemon time.
  - `malicious_relay(node)`: that node's proxy. It can drop, reorder,
    replay and inject frames, rewrite routing hints, forge replies (an
    `epoch_conflict` for a commit it did forward, any error for any
    frame), hold a Welcome back, and fork (confirm a node's commits without
    forwarding them).
- **Seeded.** Each daemon's core randomness and backoff jitter come from the
  `rng` fixture (so from `AC_TEST_SEED`), with a fresh derived seed on every
  restart so a restarted daemon never replays its previous keys.
- **Budget.** Each scenario takes well under 2 s; the whole harness, both
  hosts, takes a few seconds across the xdist workers.

## Failpoints (crash consistency)

Every step boundary of receive, own-commit confirmation and Welcome
processing has a test-only failpoint, in the core and in the daemon
(ADR-004). A point is inert unless a test arms it: the core checks one
atomic flag, the daemon one empty dict. Failpoints are per client and per
daemon, so in-process daemons don't affect each other.

| Layer | Arm | Points | Actions |
|---|---|---|---|
| core | `client.failpoints().arm(name, Action, times)` (Rust); `Client._arm_failpoint_for_testing(name, "error"\|"panic", times)` (Python) | `process.before_mls`, `process.after_mls`, `process.after_merge`, `process.before_commit`, `confirm.after_merge`, `confirm.before_commit`, `join.after_stage`, `join.before_commit`, `consume.before_commit` (`agentconnect_core::failpoint::POINTS`) | `error`: a storage error (the daemon retries it); `panic`: a panic. Both fire inside the operation's transaction, so the store rolls back as after a crash at that point. |
| daemon | `daemon.failpoints.arm(name, "raise"\|"crash", times)` | `receive.*`, `confirm.*`, `welcome.*` at `before_core`, `after_core`, `in_tx` (inside the daemon transaction), `after_tx`, `after_consume` (before the relay ack); `invite.after_register`; `event.after_record` and `event.after_notify` (around telling the adapter about a recorded event); `held_timer.expire` (the safety policy's expiry timer, before it expires held messages); `delivery.after_adapter` (the adapter accepted a message, the inbox doesn't record it yet) (`agentconnect.failpoints.POINTS`) | `raise`: `FailpointError`, a transient failure the daemon retries after a backoff; `crash`: `SimulatedCrash`, a `BaseException` nothing in the daemon catches, so the worker dies there; the test restarts the node. |

`core/tests/journal.rs` runs every core point with both actions and checks
that the state is unchanged, the retry succeeds and a second retry gets the
journalled result. `harness/tests/test_crash_consistency.py` runs the daemon
and core points on the real relay, restarts or lets the daemon retry, and
asserts that every message is delivered exactly once, every own commit is
confirmed once, every Welcome joins once, and epochs and SAS converge with
an empty journal, and that an event (a security alert included) reaches the
adapter exactly once per `event_id` after a crash before or after notifying.
