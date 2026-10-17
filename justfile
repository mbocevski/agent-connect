# AgentConnect task runner. `just --list` shows every recipe.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Coverage gates (see TESTING.md)
cov_core := "90"
cov_relay := "80"
cov_python := "85"

default:
    @just --list

# Install toolchains, dependencies and git hooks
setup:
    rustup show active-toolchain || rustup toolchain install
    uv sync --all-packages
    prek install --install-hooks

# Format all code (Rust, Python, TOML)
fmt:
    cargo fmt --all
    uv run --all-packages ruff check --fix .
    uv run --all-packages ruff format .
    taplo format

# All static checks: every prek hook on all files + dependency policy
lint: && deny
    prek run --all-files

# Python only: ruff (lint + format check) and ty
lint-py:
    uv run --all-packages --frozen ruff check .
    uv run --all-packages --frozen ruff format --check .
    uv run --all-packages --frozen ty check

# Rust only: rustfmt, clippy, rustdoc, unused deps, TOML, dependency policy
lint-rust: && deny
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps --locked --quiet
    cargo shear
    taplo format --check
    taplo lint

# Dependency policy: licences, advisories, bans, sources
deny:
    cargo deny check

# Fast test tier (< 60 s): unit, property, contract
test: test-rust test-py contract

test-rust:
    cargo nextest run --workspace --exclude agentconnect-core-py --locked

test-py:
    uv run --all-packages --frozen pytest -q

# Contract data: every testdata/ file is in MANIFEST.json and used by its suites
contract:
    uv run --no-project python scripts/check_manifest.py

# Integration tier (docker compose); populated as components land
test-int:
    @echo "no integration tests yet (added with the relay and daemon)"

# Nightly tier: mutation testing, quarantined tests, long property runs
# (fuzzing and benchmarks are added with the core)
test-nightly: nightly-mutants nightly-py

nightly-mutants:
    cargo mutants -p agentconnect-core --no-shuffle

nightly-py:
    AC_RUN_QUARANTINE=1 HYPOTHESIS_PROFILE=nightly uv run --all-packages --frozen pytest -q

# Rust branch coverage (non-gating, needs a nightly toolchain)
cov-rust-branch:
    cargo +nightly llvm-cov nextest --branch -p agentconnect-core --locked --summary-only

# Coverage with gates
cov: cov-rust cov-py

# Coverage gates plus the ratchet against coverage-baseline.json
cov-rust: _cov-rust-run
    uv run --no-project python scripts/cov_ratchet.py check core=target/cov/core.json relay=target/cov/relay.json

cov-py: _cov-py-run
    uv run --no-project python scripts/cov_ratchet.py check python=target/cov/python.json

# Rewrite coverage-baseline.json from a fresh run. Run on main after merge.
cov-baseline: _cov-rust-run _cov-py-run
    uv run --no-project python scripts/cov_ratchet.py update core=target/cov/core.json relay=target/cov/relay.json python=target/cov/python.json

_cov-rust-run:
    mkdir -p target/cov
    cargo llvm-cov nextest -p agentconnect-core --locked --fail-under-lines {{ cov_core }} --json --summary-only --output-path target/cov/core.json
    cargo llvm-cov nextest -p agentconnect-relay --locked --fail-under-lines {{ cov_relay }} --ignore-filename-regex 'main\.rs$' --json --summary-only --output-path target/cov/relay.json

_cov-py-run:
    mkdir -p target/cov
    uv run --all-packages --frozen pytest -q --cov --cov-report=term-missing --cov-report=json:target/cov/python.json --cov-fail-under={{ cov_python }}


# CHANGELOG [Unreleased] must change for user-facing commits
changelog-check base="origin/main":
    scripts/check-changelog.sh {{ base }}

# Everything PR CI runs
ci: lint test cov changelog-check

# Run the relay locally (AC_RELAY_ADDR, default 127.0.0.1:8080)
relay:
    cargo run -p agentconnect-relay

# Release builds: relay binary and Python wheels
build:
    cargo build --release --locked -p agentconnect-relay
    uv build --all-packages --sdist --wheel --out-dir dist

# Push branch and open/refresh its PR
pr:
    scripts/pr.sh

# Gated merge: refuses unless every required check is green
merge pr:
    scripts/merge.sh {{ pr }}

# Sync .github/rulesets/main.json and required checks to GitHub
apply-ruleset:
    scripts/apply-ruleset.sh

# Verify a release's signatures and provenance
release-verify version:
    gh release download v{{ version }} --dir dist/verify-{{ version }} --clobber
    cd dist/verify-{{ version }} && for f in *; do case "$f" in *.sigstore.json) ;; *) gh attestation verify "$f" --repo "$(gh repo view --json nameWithOwner --jq .nameWithOwner)" ;; esac; done
