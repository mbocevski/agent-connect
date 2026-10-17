#!/usr/bin/env bash
# Print the CHANGELOG.md section for a version (used for release notes).
# usage: scripts/changelog-section.sh <version-without-v>
set -euo pipefail

version="${1:?usage: changelog-section.sh <version>}"
awk -v v="$version" '
    $0 ~ "^## \\[" v "\\]" { found = 1; next }
    found && /^## \[/ { exit }
    found { print }
' CHANGELOG.md
