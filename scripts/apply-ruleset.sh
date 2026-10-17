#!/usr/bin/env bash
# Sync every ruleset in .github/rulesets/*.json to the GitHub repo, matched by
# name. Required status checks come from .github/required-checks.txt.
# Rulesets need a public repo or a paid plan.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
checks="$(grep -Ev '^\s*(#|$)' "$root/.github/required-checks.txt" | jq -R '{context: .}' | jq -s .)"

for file in "$root"/.github/rulesets/*.json; do
    body="$(jq --argjson checks "$checks" \
        '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks) = $checks' \
        "$file")"
    name="$(jq -r .name <<<"$body")"
    existing="$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id" || true)"
    if [[ -n "$existing" ]]; then
        gh api -X PUT "repos/$repo/rulesets/$existing" --input - <<<"$body" >/dev/null
        echo "updated ruleset '$name' on $repo"
    else
        gh api -X POST "repos/$repo/rulesets" --input - <<<"$body" >/dev/null
        echo "created ruleset '$name' on $repo"
    fi
done
