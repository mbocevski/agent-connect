#!/usr/bin/env bash
# Cut CHANGELOG.md's [Unreleased] section and the fragments in changelog.d/
# into a release section: every entry under [Unreleased], and any note above
# its first `###` heading (such as the compatibility note of a preview), moves
# under `## [<version>] - <date>`, the fragments follow the existing entries of
# their section, the fragments are deleted, and a new, empty [Unreleased] goes
# above it. See scripts/changelog_fragments.py.
#
# usage: scripts/changelog-cut.sh <version-without-v> [<YYYY-MM-DD>]   (default: today, UTC)
set -euo pipefail

: "${1:?usage: changelog-cut.sh <version> [<date>]}"
here=$(cd "$(dirname "$0")" && pwd)
exec python3 "$here/changelog_fragments.py" cut "$@"
