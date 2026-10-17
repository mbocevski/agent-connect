# Contributing

## Setup

You need [rustup](https://rustup.rs), [uv](https://docs.astral.sh/uv/),
[`just`](https://just.systems) and [prek](https://github.com/j178/prek)
(`uv tool install prek`), plus the Rust test and lint tools:
`cargo install --locked cargo-nextest cargo-llvm-cov cargo-deny cargo-shear
taplo-cli`. The Markdown hooks (rumdl, lychee, Vale) install themselves on
first run; Vale's hook needs Go.

```sh
just setup
```

`just setup` installs the pinned Rust toolchain (`rust-toolchain.toml`), the
Python workspace (`uv sync --all-packages`), and all git hooks via prek.

## Workflow

1. Branch from `main`: `git switch -c feat/<topic>`.
2. Commit using [Conventional Commits](https://www.conventionalcommits.org/).
   The `commit-msg` hook checks the type and scope. Scopes: `spec`, `core`,
   `relay`, `daemon`, `a2a`, `sdk`, `web`, `policy`, `group`, `ci`, `docs`,
   `deps`.
3. Add user-facing changes to `CHANGELOG.md` under `[Unreleased]`.
4. `just pr` pushes the branch and opens a PR. Use a Conventional Commit PR
   title; it becomes the squash commit.
5. Once CI is green: `just merge <pr-number>`.

## Merge gating

Gates are enforced both locally (hooks and `just merge`) and server-side by
a GitHub ruleset on `main`:

| Gate | Where |
|---|---|
| Formatting, lint, types, typos, secrets | `pre-commit` hook (prek) |
| Conventional Commit message | `commit-msg` hook |
| No direct pushes to `main` | `pre-push` hook (`scripts/hooks/no-push-main.sh`) |
| Fast test tier passes | `pre-push` hook (`just test`) |
| CHANGELOG updated | `pre-push` hook and the CI `changelog` job (`scripts/check-changelog.sh`) |
| Docs changed with mapped code | `pre-push` hook, `just docs-check` and the CI `docs` job (`scripts/check_docs.py`) |
| Markdown lint, offline link check, prose rules | `pre-commit` hook and the CI `lint` job (rumdl, lychee, Vale) |
| All required CI checks green, branch up to date, title OK | `just merge` (`scripts/merge.sh`) |
| PR required, `ci-ok` green and up to date, squash-only, linear history, signed commits, no force-push or deletion | GitHub ruleset (`.github/rulesets/main.json`) |

The required checks are listed in `.github/required-checks.txt`, currently
only `ci-ok`, which aggregates every CI job. After changing that file or the
ruleset JSON, run `just apply-ruleset` to sync it to GitHub.

Never bypass hooks with `--no-verify`. If a hook fails, fix the cause.

### No tool attribution

Commits, PR text, comments and docs must not mention the AI assistants,
agent tools or planning tools used to produce them. `scripts/hygiene.py`
enforces this in the `pre-commit` and `commit-msg` hooks, in the CI `hygiene`
job, and in `just merge`. See AGENTS.md for the details and how to allow a
legitimate product name.

### Skipping the changelog

Commits whose types are all `docs`, `ci`, `chore`, `test`, `build` or `style`
don't need a changelog entry. For anything else that genuinely isn't
user-facing, add the `skip-changelog` label to the PR.

### Docs that must change with code

`docs/MAP.toml` lists the user-facing code whose behaviour is documented,
and the docs that describe it:

| Code | Docs (any one) |
|---|---|
| `daemon/src/agentconnect/cli.py` | `docs/cli.md` |
| `daemon/src/agentconnect/api.py` (local API routes) | `docs/api.md` |
| `daemon/src/agentconnect/config.py` | `docs/config.md` |
| `relay/src/proto.rs`, `rest.rs`, `ws.rs` | `SPEC.md` or `relay/README.md` |
| `testdata/*.json` (not `MANIFEST.json`) | `SPEC.md` |

`scripts/check_docs.py` fails a branch when a commit changes mapped code and
none of that rule's docs changed anywhere on the branch. Commits of type
`docs`, `test`, `ci`, `chore`, `build` or `style` don't count, and merge
commits are ignored. When a change leaves the docs correct, for
example a refactor inside `cli.py`, add the `skip-docs` label to the PR (CI
sets `SKIP_DOCS=true` from it; set it yourself to skip the pre-push hook for
that push). Keep the map small: add a rule only for code whose behaviour
users read about.

### Writing docs

Markdown is checked by rumdl (`.rumdl.toml`), lychee (`lychee.toml`, offline
in the hooks and PR CI) and Vale (`.vale.ini`, rules in
`styles/AgentConnect/`). Vale rejects filler and hype words, absolute
security claims (use the canonical claim in SPEC.md §1) and emoji. Write for
an engineer: plain words, short sentences, prose where prose reads better
than a list, and only claims that are true of `main`. The README quickstart
is tested (TESTING.md).

## Tests

| Command | Tier |
|---|---|
| `just test` | Fast (< 60 s): unit, property and contract tests. Runs on pre-push. |
| `just contract` | `testdata/` manifest check (part of `just test`) |
| `just cov` | Coverage with gates (core ≥ 90%, relay ≥ 80%, Python ≥ 85%) and the ratchet against `coverage-baseline.json` |
| `just test-int` | Integration (docker compose, < 10 min) |
| `just test-nightly` | Mutation testing, long property runs, quarantined tests (fuzzing and benchmarks to come) |
| `just ci` | Everything PR CI runs |

Rules, determinism helpers, coverage policy and the flaky-test policy are in
[`TESTING.md`](TESTING.md).

## Releases

Tag `vX.Y.Z` on `main` after moving `[Unreleased]` entries into a version
section. The `release` workflow builds, signs (Sigstore) and attests (SLSA
provenance) the artifacts. Verify a release with `just release-verify X.Y.Z`.
