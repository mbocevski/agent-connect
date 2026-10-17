#!/usr/bin/env bash
# Gated merge: the sanctioned way to merge into main. It mirrors the GitHub
# ruleset and adds checks the ruleset can't express (title format, hygiene).
#
# Refuses unless: PR is open, not draft, targets main, has no do-not-merge
# label, is up to date with main, has only GitHub-verified (signed) commits, has
# a Conventional Commit title, and every check listed in
# .github/required-checks.txt has passed.
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
    BEHIND) fail "branch is behind main; run 'just update-branch $pr' (a signed local rebase; GitHub's Update branch drops the signatures and the ruleset then blocks the merge)" ;;
    DIRTY) fail "branch has merge conflicts" ;;
esac

# The ruleset requires verified signatures. GitHub's own rebase/update-branch
# strips them, so check here rather than failing at the merge API.
repo="$(gh repo view --json owner,name --jq '.owner.login + "/" + .name')"
# shellcheck disable=SC2016  # GraphQL variables, not shell ones
sig_query='query($owner: String!, $name: String!, $pr: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $pr) {
      commits(first: 100) {
        totalCount
        nodes { commit { abbreviatedOid signature { isValid state } } }
      }
    }
  }
}'
sig_json="$(gh api graphql -F owner="${repo%%/*}" -F name="${repo##*/}" -F pr="$pr" -f query="$sig_query")"
commits_total="$(jq -r '.data.repository.pullRequest.commits.totalCount' <<<"$sig_json")"
[[ "$commits_total" -le 100 ]] || fail "PR #$pr has $commits_total commits; the signature check covers 100"
unverified="$(jq -r '.data.repository.pullRequest.commits.nodes[].commit
    | select((.signature.isValid // false) | not)
    | "  " + .abbreviatedOid + ": " + (.signature.state // "UNSIGNED")' <<<"$sig_json")"
if [[ -n "$unverified" ]]; then
    echo "$unverified" >&2
    fail "the commits above are not verified on GitHub; re-sign them with 'just update-branch $pr'"
fi

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
