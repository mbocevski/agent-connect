#!/usr/bin/env bash
# Verify cosign keyless signatures made by REPO's release workflow at REF
# (a tag, refs/tags/vX.Y.Z, or the dry run's branch).
#
#   verify-signatures.sh blobs DIR REPO REF    every file in DIR against its
#                                              <file>.sigstore.json bundle
#   verify-signatures.sh image IMAGE REPO REF  an image's signature
#
# The release workflow runs it right after signing; `just release-verify`
# runs it on a published release.
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 blobs DIR REPO REF | image IMAGE REPO REF" >&2
    exit 2
fi
mode=$1 target=$2 repo=$3 ref=$4
identity="https://github.com/$repo/.github/workflows/release.yml@$ref"
issuer=https://token.actions.githubusercontent.com

case "$mode" in
blobs)
    shopt -s dotglob nullglob
    n=0
    for f in "$target"/*; do
        if [[ ! -f "$f" || -L "$f" || "$(basename "$f")" == .* ]]; then
            echo "unexpected entry $(basename "$f") in $target" >&2
            exit 1
        fi
        case "$f" in
        *.sigstore.json)
            test -f "${f%.sigstore.json}" || {
                echo "a cosign bundle without its file: $(basename "${f%.sigstore.json}")" >&2
                exit 1
            }
            continue
            ;;
        esac
        test -f "$f.sigstore.json" || {
            echo "no cosign bundle for $(basename "$f")" >&2
            exit 1
        }
        cosign verify-blob --bundle "$f.sigstore.json" \
            --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$f"
        n=$((n + 1))
    done
    test "$n" -gt 0 || {
        echo "nothing to verify in $target" >&2
        exit 1
    }
    echo "verified $n cosign bundles in $target"
    ;;
image)
    cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$target"
    ;;
*)
    echo "unknown mode $mode (blobs or image)" >&2
    exit 2
    ;;
esac
