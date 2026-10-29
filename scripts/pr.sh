#!/usr/bin/env bash
# Push the current branch and open (or show) its PR.
set -euo pipefail

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" == "main" ]]; then
    echo "error: create a branch first (git switch -c <type>/<topic>)" >&2
    exit 1
fi

git push -u origin "$branch"

open_url="$(gh pr list --head "$branch" --state open --json url --jq '.[0].url // empty')"
if [[ -n "$open_url" ]]; then
    echo "$open_url"
    exit 0
fi
# The title and body come from the first commit, so a branch with several
# commits still gets a Conventional title (--fill would use the branch name).
gh pr create --fill-first --base main --head "$branch"
