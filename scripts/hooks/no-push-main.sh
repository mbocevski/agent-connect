#!/usr/bin/env bash
# pre-push: refuse pushing directly to main. Merge through `just merge <pr>`.
# The only exception is the initial push that creates the repository, when the
# remote has no branches at all.
set -euo pipefail

remote_branch="${PRE_COMMIT_REMOTE_BRANCH:-}"
if [[ -z "$remote_branch" ]]; then
    remote_branch="refs/heads/$(git rev-parse --abbrev-ref HEAD)"
fi

if [[ "$remote_branch" != "refs/heads/main" ]]; then
    exit 0
fi

remote="${PRE_COMMIT_REMOTE_NAME:-origin}"
if [[ -z "$(git ls-remote --heads "$remote" 2>/dev/null)" ]]; then
    echo "no-push-main: remote '$remote' has no branches; allowing the initial push of main"
    exit 0
fi

echo "error: direct pushes to main are not allowed." >&2
echo "       push a branch, open a PR (just pr), and merge with: just merge <pr>" >&2
exit 1
