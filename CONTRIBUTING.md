# Contributing

## Setup

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
| All required CI checks green, branch up to date, title OK | `just merge` (`scripts/merge.sh`) |
| PR required, `ci-ok` green and up to date, squash-only, linear history, signed commits, no force-push or deletion | GitHub ruleset (`.github/rulesets/main.json`) |

The required checks are listed in `.github/required-checks.txt`, currently
just `ci-ok`, which aggregates every CI job. After changing that file or the
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
