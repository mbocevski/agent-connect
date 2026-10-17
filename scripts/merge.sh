#!/usr/bin/env bash
# Gated merge: the sanctioned way to merge into main. It mirrors the GitHub
# ruleset and adds checks the ruleset can't express (title format, hygiene).
#
# Refuses unless: PR is open, not draft, targets main, has no do-not-merge
# label, is up to date with main, has a Conventional Commit title, and every
# check listed in .github/required-checks.txt has passed.
#
# usage: scripts/merge.sh <pr-number>
set -euo pipefail

pr="${1:?usage: just merge <pr-number>}"
root="$(git rev-parse --show-toplevel)"
fail() { echo "merge refused: $*" >&2; exit 1; }

pr_json="$(gh pr view "$pr" --json state,isDraft,baseRefName,mergeStateStatus,labels,title,body)"
field() { jq -r "$1" <<<"$pr_json"; }

[[ "$(field .state)" == "OPEN" ]] || fail "PR #$pr is $(field .state)"
[[ "$(field .isDraft)" == "false" ]] || fail "PR #$pr is a draft"
[[ "$(field .baseRefName)" == "main" ]] || fail "PR #$pr targets $(field .baseRefName), not main"
if jq -e '.labels[].name | select(. == "do-not-merge")' <<<"$pr_json" >/dev/null; then
    fail "PR #$pr has the do-not-merge label"
fi

case "$(field .mergeStateStatus)" in
    BEHIND) fail "branch is behind main; update it (gh pr update-branch $pr --rebase)" ;;
    DIRTY) fail "branch has merge conflicts" ;;
esac

title="$(field .title)"
cc='^(feat|fix|docs|test|refactor|perf|build|ci|chore|revert|style)(\([a-z0-9,-]+\))?!?: .+'
[[ "$title" =~ $cc ]] || fail "PR title is not a Conventional Commit: '$title'"
jq -r '.title + "\n" + (.body // "")' <<<"$pr_json" \
    | uv run --frozen python "$root/scripts/hygiene.py" text \
    || fail "PR title/body contains AI-tool attribution or tooling references"

checks_json="$(gh pr checks "$pr" --json name,bucket 2>/dev/null || echo '[]')"
missing=0
while IFS= read -r check; do
    [[ -z "$check" || "$check" == \#* ]] && continue
    bucket="$(jq -r --arg n "$check" '[.[] | select(.name == $n)][0].bucket // "missing"' <<<"$checks_json")"
    if [[ "$bucket" != "pass" ]]; then
        echo "  required check '$check': $bucket" >&2
        missing=1
    fi
done <"$root/.github/required-checks.txt"
[[ "$missing" -eq 0 ]] || fail "required checks are not all green"

echo "all gates passed; squash-merging #$pr"
# Empty body: GitHub's default squash body would concatenate every branch
# commit message.
gh pr merge "$pr" --squash --delete-branch --subject "$title (#$pr)" --body ""
