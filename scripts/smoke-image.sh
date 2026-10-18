#!/usr/bin/env bash
# Smoke-test a built relay or directory image: print the binary's NEEDED
# libraries, start the container and wait for /healthz to answer 200.
# Usage: scripts/smoke-image.sh <relay|directory> <image> [platform]
set -euo pipefail

component=${1:?usage: smoke-image.sh <relay|directory> <image> [platform]}
image=${2:?image}
platform=${3:-}

platform_args=()
if [ -n "$platform" ]; then
  platform_args=(--platform "$platform")
fi

case "$component" in
  relay)
    port=8080
    env_args=(-e AC_RELAY_HOST=localhost)
    tmpfs_opts="/data:uid=65532,gid=65532,mode=0700"
    run_args=(--tmpfs "$tmpfs_opts")
    ;;
  directory)
    port=8090
    # A throwaway Ed25519 public key, generated per run (the last 32 bytes of
    # its DER encoding), as base64url.
    key=$(openssl genpkey -algorithm ed25519 | openssl pkey -pubout -outform DER |
      tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')
    env_args=(-e AC_DIRECTORY_DB=memory: -e AC_DIRECTORY_HOST=localhost
      -e AC_DIRECTORY_RELAYS=relay.example.org -e "AC_DIRECTORY_TOKEN_KEYS=$key")
    run_args=()
    ;;
  *)
    echo "unknown component: $component" >&2
    exit 2
    ;;
esac

binary=/usr/local/bin/agentconnect-$component
workdir=$(mktemp -d)
cid=""
cleanup() {
  if [ -n "$cid" ]; then docker rm -f "$cid" >/dev/null 2>&1 || true; fi
  rm -rf "$workdir"
}
trap cleanup EXIT

# NEEDED libraries of the binary inside the image.
copy_id=$(docker create "${platform_args[@]}" "$image" "$binary")
docker cp "$copy_id:$binary" "$workdir/binary"
docker rm "$copy_id" >/dev/null
echo "NEEDED libraries ($component, ${platform:-native}):"
readelf -d "$workdir/binary" | grep NEEDED

# Run it and poll /healthz.
cid=$(docker run -d "${platform_args[@]}" "${env_args[@]}" "${run_args[@]}" \
  -p "127.0.0.1::$port" "$image")
host_port=$(docker port "$cid" "$port/tcp" 2>/dev/null | head -n1 | sed 's/.*://' || true)
if [ -z "$host_port" ]; then
  echo "no published port for $component; container logs:" >&2
  docker logs "$cid" >&2 || true
  exit 1
fi
if curl --silent --show-error --fail --output /dev/null \
  --retry 30 --retry-delay 1 --retry-connrefused --retry-all-errors --retry-max-time 60 \
  "http://127.0.0.1:$host_port/healthz"; then
  echo "healthz: 200 ($component, ${platform:-native})"
else
  echo "healthz failed ($component, ${platform:-native}); container logs:" >&2
  docker logs "$cid" >&2 || true
  exit 1
fi
