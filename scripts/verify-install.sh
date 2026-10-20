#!/usr/bin/env bash
# Install agentconnect-cli the documented way in a fresh environment and
# smoke-test it (release.yml, after publishing; scripts/release_smoke.py).
#
# usage: scripts/verify-install.sh <version> <relay-url>
#
# Runs the README "Install" command verbatim (scripts/check_version.py checks
# that the README carries exactly this line), then the pip form in a virtual
# environment. A release reaches PyPI's CDN with a delay, so each install is
# retried with backoff for up to ten minutes. The dry run sets UV_FIND_LINKS
# and PIP_FIND_LINKS to the built distributions instead.
set -euo pipefail

version=${1:?usage: verify-install.sh <version> <relay-url>}
relay=${2:?relay url}
here=$(cd "$(dirname "$0")" && pwd)
python=${PYTHON:-python3}

# Each attempt asks the index again instead of a cached answer.
export UV_NO_CACHE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

retry() {
  local delay=10 deadline=$((SECONDS + 600))
  until "$@"; do
    if ((SECONDS + delay > deadline)); then
      echo "error: '$*' kept failing for ten minutes" >&2
      return 1
    fi
    echo "'$*' failed; retrying in ${delay}s (PyPI's CDN may not serve the release yet)" >&2
    sleep "$delay"
    delay=$((delay * 2 > 60 ? 60 : delay * 2))
  done
}

"$python" --version
if ! command -v uv >/dev/null; then
  "$python" -m pip install --quiet uv
fi
uv --version

echo "== uv tool install agentconnect-cli==$version"
retry uv tool install "agentconnect-cli==$version"
PATH="$(uv tool dir --bin):$PATH" "$python" -I "$here/release_smoke.py" "$version" "$relay"
uv tool uninstall agentconnect-cli

echo "== pip install agentconnect-cli==$version (virtual environment)"
venv=$(mktemp -d)/venv
"$python" -m venv "$venv"
retry "$venv/bin/python" -m pip install --quiet "agentconnect-cli==$version"
PATH="$venv/bin:$PATH" "$python" -I "$here/release_smoke.py" "$version" "$relay"
