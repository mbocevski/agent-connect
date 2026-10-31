#!/usr/bin/env bash
# Require a new changelog fragment (changelog.d/<slug>.<section>.md, see
# scripts/changelog_fragments.py) on a branch, unless every commit is a
# non-user-facing type or SKIP_CHANGELOG=true (CI sets it from the
# `skip-changelog` PR label). Every fragment in the tree must be well formed,
# so that the release cut can't fail on one.
#
# usage: scripts/check-changelog.sh [base-ref]   (default: origin/main)
set -euo pipefail

base="${1:-origin/main}"
here=$(cd "$(dirname "$0")" && pwd)

python3 "$here/changelog_fragments.py" validate

if [[ "${SKIP_CHANGELOG:-false}" == "true" ]]; then
    echo "changelog: skipped (skip-changelog label)"
    exit 0
fi

if ! git rev-parse --verify --quiet "$base" >/dev/null; then
    echo "changelog: base '$base' not found; skipping (no remote yet?)"
    exit 0
fi

if ! merge_base="$(git merge-base "$base" HEAD)"; then
    echo "changelog: no common history with '$base'; skipping (initial push?)"
    exit 0
fi
range="$merge_base..HEAD"
# --no-merges: CI checks out GitHub's synthetic "Merge X into Y" commit.
subjects="$(git log --no-merges --format=%s "$range")"

if [[ -z "$subjects" ]]; then
    echo "changelog: no commits ahead of $base"
    exit 0
fi

exempt='^(docs|ci|chore|test|build|style)(\([a-z0-9,-]+\))?: '
if ! grep -Evq "$exempt" <<<"$subjects"; then
    echo "changelog: all commits are docs/ci/chore/test/build/style; not required"
    exit 0
fi

fragment='^changelog\.d/[a-z0-9][a-z0-9-]*\.(added|changed|deprecated|removed|fixed|security)\.md$'
if git diff --name-only --no-renames --diff-filter=A "$range" -- changelog.d | grep -Eq "$fragment"; then
    echo "changelog: fragment added"
    exit 0
fi

echo "error: user-facing commits without a changelog fragment." >&2
echo "       add changelog.d/<slug>.<section>.md with one bullet (see changelog.d/README.md)" >&2
echo "       or label the PR skip-changelog." >&2
exit 1
