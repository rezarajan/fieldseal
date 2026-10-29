#!/usr/bin/env bash
# Builds the stack's images with Nix and loads them into the engine; an image whose store path is
# already loaded is skipped.
#
#   tools/stack-images.sh [name ...]      names: factory intake translog cli web demo (default: all but demo)
set -euo pipefail
# shellcheck source=stack-engine.sh
. "$(dirname "${BASH_SOURCE[0]}")/stack-engine.sh"
command -v nix >/dev/null || die "building the images needs nix"
STAMPS="$LOCAL/.generated/images-$ENGINE"; mkdir -p "$STAMPS"
[ "$#" -gt 0 ] || set -- factory intake translog cli web
for name in "$@"; do
  tag="fieldseal-$name"
  say "== building $name-image with nix"
  out="$(stage "build-$name" nix build "path:$ROOT#$name-image" --no-link --print-out-paths)"
  if [ "$(cat "$STAMPS/$name" 2>/dev/null)" = "$out" ] && "$ENGINE" image inspect "$tag:local" >/dev/null 2>&1; then
    say "   $tag:local is loaded already"
    mkdir -p "$(dirname "$TIMING_TSV")"; printf 'load-%s\t0.000\n' "$name" >> "$TIMING_TSV"
  else
    say "   loading $tag:local into $ENGINE"
    load_image() { "$ENGINE" load < "$out" >/dev/null || die "could not load $tag:local into $ENGINE"; }
    stage "load-$name" load_image
    echo "$out" > "$STAMPS/$name"
  fi
done
