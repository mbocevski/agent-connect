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
5. If `main` moved on, run `just update-branch <pr-number>` from the branch's
   checkout. It rebases onto `origin/main`, re-signs every commit, checks the
   signatures and pushes with `--force-with-lease`. It stops on conflicts and
   tells you how to continue. Don't use GitHub's "Update branch" button or
   `gh pr update-branch`: they rewrite your commits without signatures and the
   ruleset then blocks the merge.
6. Once CI is green: `just merge <pr-number>`.

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
| All required CI checks green, branch up to date, every commit verified on GitHub, title OK | `just merge` (`scripts/merge.sh`) |
| Rust and Python dependency licences on the allowlist | `just lint`, the CI `rust` and `licences` jobs, nightly audit (`cargo deny`, `scripts/check_licences.py`) |
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

`docs/MAP.toml` has three parts. Each rule maps user-facing code to the docs
that describe it, for example:

| Code | Docs (any one) |
|---|---|
| `daemon/src/agentconnect/cli.py` | `docs/cli.md` |
| `daemon/src/agentconnect/runtime/api.py` (local API routes) | `docs/api.md` |
| `daemon/src/agentconnect/config.py` | `docs/config.md` |
| `daemon/src/agentconnect/isolation.py` | `docs/isolation.md` |
| `core/src/listing/`, `core/src/knock*` | `SPEC.md` |
| `relay/src/proto.rs`, `rest.rs`, `ws.rs` | `SPEC.md` or `relay/README.md` |
| `testdata/*.json` (not `MANIFEST.json`) | `SPEC.md` |

`scripts/check_docs.py` fails a branch when a commit changes a rule's code and
none of that rule's docs changed anywhere on the branch. Commits of type
`docs`, `test`, `ci`, `chore`, `build` or `style` don't count, and merge
commits are ignored. When a change leaves the docs correct, for
example a refactor inside `cli.py`, add the `skip-docs` label to the PR (CI
sets `SKIP_DOCS=true` from it; set it yourself to skip the pre-push hook for
that push).

The components are the inventory behind the README's Status section. Each
`[[component]]` has a name, `paths` and a `doc`, and exactly one bullet in
the Status section, which links the doc and ends with an invisible marker:

```markdown
- **CLI** (`agentconnect`): what it does ([docs/cli.md](docs/cli.md)).
  <!-- component: cli -->
```

A branch that adds an entry under `### Added` in the CHANGELOG and changes a
component's `paths` must also change `README.md`. When the README stays
correct, add the `skip-readme` label (CI sets `SKIP_README=true` from it; it
is separate from `skip-docs`). A part with no Status bullet, such as test
tooling, sets `readme = false`.

The check also fails when a Status bullet has no component or a component has
no bullet, when a bullet links a missing file, when a Cargo or uv workspace
member is in no component (give a new crate or package a component, or extend
one's `paths` to `<dir>/**`), and when a `.rs` or `.py` file under a `src`
directory is in no rule's `code` and not in `internal`. Put a new file in a
rule if users read about its behaviour, and in `internal` if not.

### Writing docs

Markdown is checked by rumdl (`.rumdl.toml`), lychee (`lychee.toml`, offline
in the hooks and PR CI) and Vale (`.vale.ini`, rules in
`styles/AgentConnect/`). Vale rejects filler and hype words, absolute
security claims (use the canonical claim in SPEC.md §1) and emoji. Write for
an engineer: plain words, short sentences, prose where prose reads better
than a list, and only claims that are true of `main`. The README quickstart
is tested (TESTING.md).

### Generated reference

The command, route, error, exit-code, config-key and `--json` tables in
`docs/cli.md`, `docs/api.md` and `docs/config.md` are generated from the
code, between `<!-- generated:NAME:start -->` and `<!-- generated:NAME:end -->`
markers. Don't edit them by hand and don't move the markers; the prose around
them is yours.

After you change a CLI command or option, a local API route
(`ROUTE_SPECS` in `daemon/src/agentconnect/runtime/api.py`), a config key
(`CONFIG_KEYS` in `config.py`), an exit code (`EXIT_CODES` in
`cli_support.py`) or a `--json` shape (`cli_json.py`), run:

```sh
just docs-gen
```

and commit the result. A drift test in `just test` fails with the same
instruction when the committed docs are stale. New commands and options
appear on their own; a new route, config key or `--json` shape needs its entry
in the table named above, and tests fail until it has one. The generator is
`scripts/gen_reference.py`.

## Tests

| Command | Tier |
|---|---|
| `just test` | Fast (< 60 s): unit, property and contract tests. Runs on pre-push. |
| `just contract` | `testdata/` manifest check (part of `just test`) |
| `just docs-gen` | Regenerate the reference sections of `docs/cli.md`, `docs/api.md`, `docs/config.md` |
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
