# AgentConnect task runner. `just --list` shows every recipe.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Coverage gates (see TESTING.md)
cov_core := "90"
cov_relay := "80"
cov_directory := "80"
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
lint: && deny licences
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

# Python dependency licences vs licences-py.toml (a throwaway venv, no Rust build)
licences:
    mkdir -p target/licences
    uv export --all-packages --no-emit-workspace --no-hashes --frozen --quiet --format requirements-txt --output-file target/licences/requirements.txt
    uv venv --quiet --clear target/licences/venv
    uv pip install --quiet --python target/licences/venv -r target/licences/requirements.txt
    uvx pip-licenses==5.5.5 --python target/licences/venv/bin/python --from=mixed --format=json --output-file target/licences/report.json
    uv run --no-project python scripts/check_licences.py target/licences/report.json

# Fast test tier (< 60 s): unit, property, contract
test: test-rust test-py contract

test-rust:
    cargo nextest run --workspace --exclude agentconnect-core-py --locked

# The harness (harness/) runs the real relay and directory binaries; build them first.
test-py: build-relay-dev
    uv run --all-packages --frozen pytest -q -n auto

# Regenerate the core test vectors in testdata/ (review the diff before committing)
vectors:
    AC_REGENERATE_VECTORS=1 cargo test -p agentconnect-core --lib --locked vectors

# Contract data: every testdata/ file is in MANIFEST.json and used by its suites
contract:
    uv run --no-project python scripts/check_manifest.py

# Postgres for the directory's store comes from compose.test.yaml (loopback only);
# the demos and the malicious relay double run in demo/compose.yaml.
# Integration tier: the directory's Postgres store, the relay binary's connection limits on real time, the docker demos, the malicious relay
test-int: demo-image
    cargo nextest run -p agentconnect-relay --locked --run-ignored only
    docker compose -f compose.test.yaml up -d --wait
    status=0; AC_DIRECTORY_TEST_DB=postgres://directory@127.0.0.1:55432/directory?sslmode=disable cargo nextest run -p agentconnect-directory --locked --run-ignored only || status=$?; docker compose -f compose.test.yaml down; exit "$status"
    uv run --all-packages --frozen pytest -q integration/tests

# The image every demo service runs (demo/Dockerfile); never pushed
demo-image:
    docker build -f demo/Dockerfile -t agentconnect-demo:dev {{ if env("AC_EXAMPLE_MODEL", "stub") == "real" { "--build-arg REAL_MODELS=1" } else { "" } }} .

# Demo 1 in docker compose: an A2A agent and a Claude Agent SDK agent, 1:1 (README, "Demos")
demo: demo-image
    uv run --no-project python demo/run.py one-to-one --no-build

# Demo 2 in docker compose: an A2A, a Claude Agent SDK and a LangGraph agent in one group
demo-group: demo-image
    uv run --no-project python demo/run.py group --no-build

# Record both demos with asciinema into docs/demos/ (needs asciinema on PATH)
demo-record: demo-image
    @command -v asciinema >/dev/null || { echo "demo-record needs asciinema (https://asciinema.org)" >&2; exit 1; }
    mkdir -p docs/demos
    asciinema rec --overwrite -q -c "uv run --no-project python demo/run.py one-to-one --no-build" docs/demos/one-to-one.cast
    asciinema rec --overwrite -q -c "uv run --no-project python demo/run.py group --no-build" docs/demos/group.cast

# The nightly workflow also runs nightly-fuzz for each crate.
# Nightly tier: mutation testing, quarantined tests, long property runs
test-nightly: nightly-mutants nightly-py nightly-relay-load

# Needs a nightly toolchain and cargo-fuzz. A crash stops it, with the input
# in <crate>/fuzz/artifacts/<target>/.
# Fuzz every target of one crate (core, relay or directory) for secs seconds each
nightly-fuzz crate secs="300":
    #!/usr/bin/env bash
    set -euo pipefail
    crate={{ quote(crate) }}
    secs={{ quote(secs) }}
    case "$crate" in
        core | relay | directory) ;;
        *) echo "nightly-fuzz: crate must be core, relay or directory" >&2; exit 2 ;;
    esac
    case "$secs" in
        '' | *[!0-9]*) echo "nightly-fuzz: secs must be a whole number" >&2; exit 2 ;;
    esac
    cd "$crate"
    targets="$(cargo +nightly fuzz list)"
    test -n "$targets" || { echo "no fuzz targets in $crate" >&2; exit 1; }
    cargo +nightly fuzz build
    # The fuzzer's output and crashing inputs stay on this machine: the CI
    # log is public, and a crash is an undisclosed finding (SECURITY.md).
    out="$(mktemp -d)"
    failed=()
    for t in $targets; do
        echo "fuzzing $crate/$t for $secs s"
        mkdir "$out/$t"
        if cargo +nightly fuzz run "$t" -- -max_total_time="$secs" \
            -artifact_prefix="$out/$t/" >"$out/$t.log" 2>&1; then
            grep -E '^Done [0-9]+ runs' "$out/$t.log" || true
        else
            failed+=("$t")
            for f in "$out/$t"/*; do
                test -f "$f" || continue
                echo "crash in $crate/$t: input sha256 $(sha256sum <"$f" | cut -d' ' -f1)" >&2
            done
        fi
    done
    if [ "${#failed[@]}" -gt 0 ]; then
        echo "fuzz targets that failed in $crate: ${failed[*]} (output and inputs in $out)" >&2
        exit 1
    fi
    rm -rf "$out"

# Mutation testing of the core, every mutant (hours; config in .cargo/mutants.toml)
nightly-mutants *args:
    cargo mutants -p agentconnect-core --no-shuffle {{ args }}

# One shard of it, as the nightly matrix runs it: just nightly-mutants-shard 3/24
nightly-mutants-shard shard *args:
    cargo mutants -p agentconnect-core --no-shuffle --shard {{ shard }} {{ args }}

# The relay's load tests (budgets, stalls, the purge) and the wire sizes its caps rely on (ignored by `just test`)
nightly-relay-load:
    cargo nextest run --release -p agentconnect-relay --locked --run-ignored only
    cargo nextest run --release -p agentconnect-core --locked --run-ignored only -E 'test(wire_sizes_fit_the_relay_caps)'

nightly-py: build-relay-dev
    AC_RUN_QUARANTINE=1 HYPOTHESIS_PROFILE=nightly uv run --all-packages --frozen pytest -q -n auto

# Rust branch coverage (non-gating, needs a nightly toolchain)
cov-rust-branch:
    cargo +nightly llvm-cov nextest --branch -p agentconnect-core --locked --summary-only

# Coverage with gates
cov: cov-rust cov-py

# Coverage gates plus the ratchet against coverage-baseline.json
cov-rust: _cov-rust-run
    uv run --no-project python scripts/cov_ratchet.py check core=target/cov/core.json relay=target/cov/relay.json directory=target/cov/directory.json

cov-py: _cov-py-run
    uv run --no-project python scripts/cov_ratchet.py check python=target/cov/python.json

# Rewrite coverage-baseline.json from a fresh run. Commit it in the PR that raises coverage.
cov-baseline: _cov-rust-run _cov-py-run
    uv run --no-project python scripts/cov_ratchet.py update core=target/cov/core.json relay=target/cov/relay.json directory=target/cov/directory.json python=target/cov/python.json

_cov-rust-run:
    mkdir -p target/cov
    cargo llvm-cov nextest -p agentconnect-core --locked --fail-under-lines {{ cov_core }} --json --summary-only --output-path target/cov/core.json
    cargo llvm-cov nextest -p agentconnect-relay --locked --fail-under-lines {{ cov_relay }} --ignore-filename-regex 'main\.rs$' --json --summary-only --output-path target/cov/relay.json
    cargo llvm-cov nextest -p agentconnect-directory --locked --fail-under-lines {{ cov_directory }} --ignore-filename-regex '(main|postgres)\.rs$' --json --summary-only --output-path target/cov/directory.json

# Debug relay and directory binaries for the multi-node harness (a no-op when up to date)
build-relay-dev:
    cargo build --quiet --locked -p agentconnect-relay -p agentconnect-directory

_cov-py-run: build-relay-dev
    mkdir -p target/cov
    uv run --all-packages --frozen pytest -q -n auto --cov --cov-report=term-missing --cov-report=json:target/cov/python.json --cov-fail-under={{ cov_python }}


# CHANGELOG [Unreleased] must change for user-facing commits
changelog-check base="origin/main":
    scripts/check-changelog.sh {{ base }}

# Docs must change with the user-facing code they describe (docs/MAP.toml). SKIP_DOCS=true and SKIP_README=true mirror the skip-docs and skip-readme PR labels.
docs-check base="origin/main":
    uv run --no-project python scripts/check_docs.py {{ base }}

# Regenerate the reference sections of docs/cli.md, api.md and config.md from the code
docs-gen:
    uv run --all-packages --frozen python scripts/gen_reference.py

# Everything PR CI runs
ci: lint test cov changelog-check docs-check

# Run the relay locally (AC_RELAY_ADDR, default 127.0.0.1:8080)
relay:
    cargo run -p agentconnect-relay

# Run the directory locally on the in-memory store (needs AC_DIRECTORY_HOST, AC_DIRECTORY_RELAYS and AC_DIRECTORY_TOKEN_KEYS; AC_DIRECTORY_ADDR, default 127.0.0.1:8090)
directory:
    AC_DIRECTORY_DB="${AC_DIRECTORY_DB:-memory:}" cargo run -p agentconnect-directory

# Release builds: relay and directory binaries and Python wheels
build:
    cargo build --release --locked -p agentconnect-relay -p agentconnect-directory
    uv build --all-packages --sdist --wheel --out-dir dist
    uv run --no-project python scripts/check_wheel_hooks.py dist/agentconnect_core-*.whl

# Push branch and open/refresh its PR
pr:
    scripts/pr.sh

# Rebase a PR branch onto main, re-sign every commit and push (run from its checkout)
update-branch pr:
    scripts/update-branch.sh {{ pr }}

# Gated merge: refuses unless every required check is green
merge pr:
    scripts/merge.sh {{ pr }}

# Sync .github/rulesets/main.json and required checks to GitHub
apply-ruleset:
    scripts/apply-ruleset.sh

# Cut CHANGELOG [Unreleased] into a release section, in the release PR (version without the v; date defaults to today, UTC)
changelog-cut version date="":
    scripts/changelog-cut.sh {{ version }} {{ date }}

# Verify a release's provenance: every release file and both images (version without the v, e.g. 0.1.0a1)
release-verify version:
    gh release download v{{ version }} --dir dist/verify-{{ version }} --clobber
    cd dist/verify-{{ version }} && for f in *; do case "$f" in *.sigstore.json) ;; *) gh attestation verify "$f" --repo "$(gh repo view --json nameWithOwner --jq .nameWithOwner)" ;; esac; done
    repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"; owner="$(tr '[:upper:]' '[:lower:]' <<<"${repo%%/*}")"; for c in relay directory; do gh attestation verify "oci://ghcr.io/$owner/agentconnect-$c:{{ version }}" --repo "$repo"; done
