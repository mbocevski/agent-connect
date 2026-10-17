#!/usr/bin/env bash
# Print the dynamic libraries of macOS build outputs and fail if any is not
# part of macOS itself (Homebrew, MacPorts or another prefix). Vendored
# OpenSSL/SQLCipher and libcrux must be linked statically.
set -euo pipefail

status=0
for bin in "$@"; do
  echo "== otool -L $bin"
  out="$(otool -L "$bin")"
  echo "$out"
  # The first line is the file name; every dependency must be a system path.
  if echo "$out" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)'; then
    echo "error: $bin links a library outside /usr/lib and /System" >&2
    status=1
  fi
done
exit "$status"
