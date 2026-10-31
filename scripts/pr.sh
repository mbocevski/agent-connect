#!/usr/bin/env bash
# Push the current branch and open (or show) its PR, with the given labels
# (`just pr skip-changelog`). Every label has to exist in the repository, and
# that is checked before anything is pushed. On a PR that is already open the
# labels are added to it.
#
# usage: scripts/pr.sh [label...]
set -euo pipefail

labels=("$@")

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" == "main" ]]; then
    echo "error: create a branch first (git switch -c <type>/<topic>)" >&2
    exit 1
fi

if [[ ${#labels[@]} -gt 0 ]]; then
    known="$(gh label list --limit 200 --json name --jq '.[].name')"
    for label in "${labels[@]}"; do
        if ! grep -qxF -- "$label" <<<"$known"; then
            echo "error: the repository has no label '$label'" >&2
            exit 1
        fi
    done
fi

git push -u origin "$branch"

label_args=() add_args=()
for label in ${labels[@]+"${labels[@]}"}; do
    label_args+=(--label "$label")
    add_args+=(--add-label "$label")
done

open_url="$(gh pr list --head "$branch" --state open --json url --jq '.[0].url // empty')"
if [[ -n "$open_url" ]]; then
    if [[ ${#labels[@]} -gt 0 ]]; then
        gh pr edit "$open_url" "${add_args[@]}"
        echo "labels added; the changelog and docs checks read them when they run," >&2
        echo "so re-run those jobs if they already failed (gh run rerun <id> --failed)" >&2
    fi
    echo "$open_url"
    exit 0
fi
# The title and body come from the first commit, so a branch with several
# commits still gets a Conventional title (--fill would use the branch name).
gh pr create --fill-first --base main --head "$branch" ${label_args[@]+"${label_args[@]}"}
