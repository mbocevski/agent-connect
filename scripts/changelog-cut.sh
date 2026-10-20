#!/usr/bin/env bash
# Cut CHANGELOG.md's [Unreleased] section into a release section: every entry
# under [Unreleased], and any note above its first `###` heading (such as the
# compatibility note of a preview), moves under `## [<version>] - <date>`,
# and a new, empty [Unreleased] goes above it.
#
# usage: scripts/changelog-cut.sh <version-without-v> [<YYYY-MM-DD>]   (default: today, UTC)
set -euo pipefail

version=${1:?usage: changelog-cut.sh <version> [<date>]}
date=${2:-$(date -u +%F)}
file=${CHANGELOG:-CHANGELOG.md}

if ! [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "error: date must be YYYY-MM-DD, got '$date'" >&2
  exit 2
fi
if grep -q "^## \[$version\]" "$file"; then
  echo "error: $file already has a [$version] section" >&2
  exit 1
fi
if [[ "$(grep -c '^## \[Unreleased\]$' "$file")" != 1 ]]; then
  echo "error: $file needs exactly one '## [Unreleased]' heading" >&2
  exit 1
fi
section=$(awk '/^## \[Unreleased\]$/ { on = 1; next } on && /^## \[/ { exit } on { print }' "$file")
if [[ -z "$(tr -d '[:space:]' <<<"$section")" ]]; then
  echo "error: [Unreleased] is empty; nothing to release" >&2
  exit 1
fi

tmp=$(mktemp "$file.XXXXXX")
awk -v head="## [$version] - $date" '
  /^## \[Unreleased\]$/ && !done { print; print ""; print head; done = 1; next }
  { print }
' "$file" > "$tmp"
mv "$tmp" "$file"
echo "$file: [Unreleased] is now [$version] - $date"
