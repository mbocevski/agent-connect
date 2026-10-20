#!/usr/bin/env bash
# Print a release's notes: its CHANGELOG.md section and the install command,
# or docs/releases/<version>.md in their place when it exists (a release
# whose section is too long for a GitHub Release body, 125000 characters),
# then the container images with their digests (release.yml).
#
# usage: scripts/release-notes.sh <version-without-v> [<images-dir>]
#
# <images-dir> holds one file per image (relay, directory), each with one
# line `ghcr.io/<owner>/agentconnect-<name>:<version>@sha256:<digest>`. A dry
# run has none, and the notes say so.
# The backticks in single quotes are Markdown, not command substitutions.
# shellcheck disable=SC2016
set -euo pipefail

version=${1:?usage: release-notes.sh <version> [<images-dir>]}
images=${2:-}
here=$(cd "$(dirname "$0")" && pwd)

curated="$here/../docs/releases/$version.md"
if [[ -f "$curated" ]]; then
  cat "$curated"
  printf '\nEvery change is in the [CHANGELOG](https://github.com/mbocevski/agent-connect/blob/v%s/CHANGELOG.md).\n' "$version"
else
  "$here/changelog-section.sh" "$version"

  # The README "Install" command (scripts/check_version.py keeps them equal).
  printf '\n## Install\n\n```sh\nuv tool install agentconnect-cli==%s\n```\n' "$version"
  printf '\nOr, in a virtual environment, `pip install agentconnect-cli==%s`.\n' "$version"
fi

printf '\n## Container images\n\n'
found=0
for name in relay directory; do
  if [[ -n "$images" && -s "$images/$name" ]]; then
    printf -- '- `%s`\n' "$(head -n1 "$images/$name")"
    found=1
  fi
done
if [[ "$found" == 1 ]]; then
  printf '\nBoth are `linux/amd64` and `linux/arm64` indexes, signed with cosign and\n'
  printf 'attested: `gh attestation verify oci://<image>@<digest> --repo <owner>/<repo>`.\n'
else
  printf 'None: this is a dry run, which pushes no images.\n'
fi
