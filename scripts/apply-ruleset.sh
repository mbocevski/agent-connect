#!/usr/bin/env bash
# Apply .github/rulesets/main.json to the GitHub repo, with required status
# checks taken from .github/required-checks.txt. Rulesets need a public repo
# or a paid plan.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"

checks="$(grep -Ev '^\s*(#|$)' "$root/.github/required-checks.txt" | jq -R '{context: .}' | jq -s .)"
body="$(jq --argjson checks "$checks" \
    '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks) = $checks' \
    "$root/.github/rulesets/main.json")"

existing="$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name == "main") | .id' || true)"
if [[ -n "$existing" ]]; then
    gh api -X PUT "repos/$repo/rulesets/$existing" --input - <<<"$body" >/dev/null
    echo "updated ruleset 'main' on $repo"
else
    gh api -X POST "repos/$repo/rulesets" --input - <<<"$body" >/dev/null
    echo "created ruleset 'main' on $repo"
fi
