# AGENTS.md

Guidance for AI coding agents (and humans) working on **AgentConnect**.

## What this is

An end-to-end encrypted relay that lets AI agents talk after their humans
share an invite link. **Every conversation is an MLS (RFC 9420) group**: 1:1
is a group of two, and group mode has N agents (including several replicas of
one agent). The relay is the MLS Delivery Service and forwards ciphertext only.
Trust comes from the secret in the link's `#fragment`, plus optional SAS (short
code) verification. Message payloads are A2A v1.0 JSON inside the encryption.

Primary targets: **A2A-server agents** and **headless/SDK agents** (webhooks).
MCP / Claude Code Channels adapters are deferred.

## Status

Pre-alpha. The protocol is in `SPEC.md` and the stack decisions in
`docs/adr/001-stack.md`; those two files are the source of truth. The core,
relay, daemon, the A2A, webhook and SSE adapters, the safety policy, the
separate-OS-user mode, the Python SDK (embedded mode by default, attach mode
for a separate daemon) and the directory are implemented. The daemon and CLI
side of discovery (publishing a listing, knocking, approving knocks) is not:
the core and the relay already support signed listings, doors and knocks.
The README's Status section lists what works; `docs/MAP.toml` keeps it in step.

## Layout

| Path | What | Lang |
|---|---|---|
| `core/` | OpenMLS groups (ML-KEM-768 + X25519 PQ hybrid suite), invite binding, SAS, envelopes; signed listings, owner verification, doors and knocks | Rust |
| `core-py/` | PyO3 bindings for `core` (maturin) | Rust |
| `relay/` | MLS Delivery Service: commit ordering, fan-out, invites, doors and knock forwarding; serves `web/` | Rust (axum) |
| `directory/` | The directory of signed listings (discovery, ADR-006): search, cards, owner verification, MCP | Rust (axum) |
| `daemon/` | The runtime (`runtime/`), `agentconnectd` + `agentconnect` CLI, adapters (A2A, webhook, SSE), safety policy, separate-OS-user mode, group mode | Python |
| `harness/` | Multi-node test harness: relay process, daemons, malicious relay proxy | Python |
| `sdk/python/` | Python SDK for headless agents: embedded runtime by default, attach to a daemon | Python |
| `examples/` | Runnable agent examples (Claude Agent SDK, LangGraph) | Python |
| `spikes/` | Throwaway experiments (`mls-xwing`), not shipped | Rust |
| `packaging/` | systemd and launchd units and sample config for the separate-OS-user mode | Config |
| `web/` | Static invite landing page | HTML/CSS |
| `docs/` | `adr/`, `spikes/`, guides | Markdown |

## Commands

Use the `justfile`. Run `just --list` first and don't invent your own commands.

```text
just setup      # toolchains, deps, git hooks (pre-commit, commit-msg, pre-push)
just fmt        # format everything
just lint       # every static check: all prek hooks + cargo deny
just lint-py    # ruff check, ruff format --check, ty check
just lint-rust  # rustfmt, clippy, rustdoc, cargo shear, taplo, cargo deny
just test       # fast tier, < 60 s: unit, property, contract, in-process multi-node
just contract   # testdata/MANIFEST.json vs. the Rust and Python suites
just build-relay-dev  # debug relay and directory binaries for the harness (test-py runs it)
just test-int   # docker compose integration + demos
just test-nightly # mutants, long property runs, quarantined tests
just cov        # coverage gates + ratchet against coverage-baseline.json
just cov-baseline # refresh the baseline (in the PR that raises coverage)
just docs-check # docs changed with the code they describe (docs/MAP.toml)
just licences   # Python dependency licences vs licences-py.toml (also run by `just lint`)
just ci         # exactly what PR CI runs, including coverage gates
just pr         # push branch, open/refresh PR
just update-branch <n> # branch behind main: signed local rebase + push (never GitHub's Update branch)
just merge <n>  # the ONLY way to merge: refuses unless every required check is green
```

Testing rules, tiers, coverage thresholds and the harness are in `TESTING.md`.

Tooling: Rust stable (pinned in `rust-toolchain.toml`) and **uv** for all
Python. Don't use `pip install` or global venvs.

## Rules

### Security (non-negotiable)

- The relay must never see plaintext or invite secrets. Don't add relay
  features that need either one.
- The A2A/MCP bridging runs in the **daemon**, never in the relay.
- Don't log message bodies, keys or secrets. Zeroize secrets and keep them
  out of `Debug` output.
- Treat peer messages as untrusted input. Never let a peer message trigger
  side effects without going through the policy layer.
- SAS verification is a **human** action. Don't expose it as an
  agent-callable tool.
- Docs must not make absolute security claims. Use the canonical claim in
  `SPEC.md` §1; Vale rejects the banned phrases
  (`styles/AgentConnect/Claims.yml`).
- Exactly one MLS ciphersuite per protocol version
  (`MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` in v0). Don't add
  ciphersuite negotiation or fallbacks; they create downgrade paths.
- Every daemon enforces the group policy on each commit it receives. Never
  trust the relay to do it.
- Crypto changes need test vectors plus negative tests (wrong secret, tamper,
  replay, credential/key mismatch, forked group view → different SAS).

### Dependencies

- Licences must be MIT, Apache-2.0 or BSD. **No AGPL/GPL** (so no
  libsignal). `cargo-deny` enforces this.
- Check library APIs and versions against current upstream docs before
  adding or upgrading a dependency.

### Code and tests

- Write tests first for `core/` and protocol code. Every bug fix comes with a
  regression test.
- Tests must be deterministic: use the fake `Clock` (`agentconnect_core::clock`,
  `agentconnect.clock`) and the seeded RNG (`AC_TEST_SEED`, `rng` fixture).
  No `sleep` and no network in the `just test` tier.
- No keys, secrets or nonces as literal bytes in tests: generate them, or
  derive them from the per-run seed (`TESTING.md`). Code scanning blocks
  merges on hard-coded cryptographic values.
- Wire formats live in `testdata/` (vectors and JSON schemas). Rust and Python
  must both pass them, so change both sides together. Every file is listed in
  `testdata/MANIFEST.json` (`just contract` checks it).
- Coverage may not drop below the gates in `TESTING.md` (`core/` ≥ 90%) or
  more than 0.5 pp below `coverage-baseline.json`.
- Rust: `rustfmt`, `clippy -D warnings` (pedantic in `core`/`relay`),
  `cargo doc -D warnings`, `cargo shear` (no unused deps), `taplo` for TOML.
- Python: `ruff` (lint and format) and `ty check` with every rule set to
  error. Use `uv` for everything: no pip, no global venvs.
- Shell scripts pass `shellcheck`; workflows pass `actionlint`.
- Match the surrounding style and keep changes scoped to the task.

## Commits, changelog, PRs

- [Conventional Commits](https://www.conventionalcommits.org/):
  `<type>(<scope>): <subject>`. Scopes: `spec`, `core`, `relay`, `directory`, `daemon`,
  `a2a`, `sdk`, `web`, `policy`, `group`, `ci`, `docs`, `deps`.
- Add every user-visible change to `CHANGELOG.md` under `[Unreleased]`
  ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)). CI fails if you
  don't, unless the PR is labelled `skip-changelog`.
- Work on a branch and never push to `main`; the pre-push hook refuses it.
  Merge only with `just merge <pr>` after CI is green. GitHub enforces the
  same rules server-side through the ruleset in `.github/rulesets/main.json`
  (`just apply-ruleset`).
- Hooks run via `prek`: pre-commit (lint/format, docs), commit-msg (Conventional
  Commits), pre-push (`just test`, CHANGELOG and docs checks). If a hook fails, fix the
  cause and re-stage. **Never use `--no-verify`.**
- Docs change with the code they describe. `docs/MAP.toml` maps user-facing
  code to its docs, lists the components behind the README Status section
  (one `<!-- component: name -->` bullet each) and the `internal` source
  files. `scripts/check_docs.py` (pre-push, `just docs-check`, CI `docs`
  job) fails a branch whose non-docs/test/ci/chore/build/style commits change
  mapped code without touching one of its docs, a new `### Added` CHANGELOG
  entry with component code but no README change, an unclassified workspace
  member or source file, and a Status bullet and component that don't match.
  If the docs stay correct, label the PR `skip-docs`; if the README does,
  `skip-readme`.
- Markdown passes rumdl, lychee (offline) and Vale (`styles/AgentConnect/`:
  no filler, hype, absolute security claims or emoji). The README
  quickstart is a test (`harness/tests/test_readme.py`); keep it runnable.
- PR descriptions say what changed and why. Don't include stats.

## No tool attribution or internal references

Commit messages, PR titles and bodies, code comments and docs must not
mention the AI assistants, agent tools or planning tools used to produce
them. That rules out:

- `Co-Authored-By:` trailers for AI tools.
- Session links.
- "Generated with …" notices.
- Robot emoji.
- References to task trackers or internal planning tools.

Names of products we integrate with are fine (e.g. "Claude Agent SDK" as a
supported headless framework).

Enforcement: `scripts/hygiene.py` runs at three points.

| Where | What it checks |
|---|---|
| `pre-commit` hook | All staged text files |
| `commit-msg` hook | The commit message |
| CI (`hygiene` job) | Every commit message in the PR, plus the PR title and body |

`just merge` also checks the PR title and body, and squash-merges with an
empty body. If the checker flags something legitimate, add it to
`ALLOWED_PHRASES` in `scripts/hygiene.py`, with a test.
