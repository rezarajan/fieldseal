#!/usr/bin/env bash
# Builds the per-release service images with Nix and tags them for a registry (DEP, ADR 0025).
#
#   tools/release-images.sh <registry/prefix> <tag> [--push] [--sign]
#
# Without --push the images are only loaded and tagged locally (`just release-images` checks it).
# With --sign each pushed image is signed by digest with cosign (keyless in CI). Writes the list
# of references (and digests, when pushed) to release-docs/images.txt.
set -euo pipefail
prefix="${1:?registry/prefix}" tag="${2:?tag}"; shift 2
push=0 sign=0
for a in "$@"; do case "$a" in --push) push=1 ;; --sign) sign=1 ;; *) echo "unknown option $a" >&2; exit 2 ;; esac; done
engine="${FIELDSEAL_CONTAINER_ENGINE:-docker}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/release-docs"
: > "$ROOT/release-docs/images.txt"
for svc in factory intake translog web cli; do
  out="$(nix build "path:$ROOT#$svc-image" --no-link --print-out-paths)"
  "$engine" load < "$out" >/dev/null
  ref="$prefix/$svc:$tag"
  "$engine" tag "fieldseal-$svc:local" "$ref"
  line="$ref"
  if [ "$push" = 1 ]; then
    "$engine" push "$ref" >/dev/null
    digest="$("$engine" inspect --format '{{index .RepoDigests 0}}' "$ref")"
    line="$ref $digest"
    if [ "$sign" = 1 ]; then nix shell nixpkgs#cosign --command cosign sign --yes "$digest"; fi
  fi
  printf '%s\n' "$line" | tee -a "$ROOT/release-docs/images.txt"
done
