#!/usr/bin/env bash
# Push the current branch and open (or show) its PR.
set -euo pipefail

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" == "main" ]]; then
    echo "error: create a branch first (git switch -c <type>/<topic>)" >&2
    exit 1
fi

git push -u origin "$branch"

if gh pr view "$branch" --json url --jq .url 2>/dev/null; then
    exit 0
fi
gh pr create --fill --base main --head "$branch"
