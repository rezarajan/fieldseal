#!/usr/bin/env bash
# Creates the signed release record for a tag and its documentation bundle (DEP, CLI-018, #54).
#
#   tools/release-docs.sh <tag> <out-dir>
#
# The builds are the Nix-built service images (factory, intake = upload, publishing = translog).
# The release is signed with the key in $FIELDSEAL_RELEASE_SIGNING_KEY_FILE (CI: a secret);
# without one it is a practice release for development only, which `deployment release` refuses
# for production (DEP-023). Writes <out-dir>/release.cbor, the documentation bundle and a summary.
set -euo pipefail
tag="${1:?tag}" out="${2:?out-dir}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$ROOT/examples/deployments/sample.yaml"
environment="${FIELDSEAL_RELEASE_ENVIRONMENT:-development}"
FS="${FIELDSEAL_BIN:-$(nix build "path:$ROOT#fieldseal" --no-link --print-out-paths)/bin/fieldseal}"
mkdir -p "$out"
image() { nix build "path:$ROOT#$1-image" --no-link --print-out-paths; }
address="$("$FS" deployment validate "$manifest" --json | jq -r .address)"
if [ -n "${FIELDSEAL_RELEASE_SIGNING_KEY_FILE:-}" ]; then sign=(--signing-key-file "$FIELDSEAL_RELEASE_SIGNING_KEY_FILE"); else sign=(--practice); fi
release="$("$FS" deployment release "$manifest" --publication "$address" \
  --build "factory=$(image factory)" --build "intake=$(image upload)" --build "publishing=$(image translog)" \
  "${sign[@]}" --environment "$environment" --out "$out/release.cbor" --json | jq -r 'select(.release and .ok) | .release')"
[ -n "$release" ] || { echo "release-docs: no release address" >&2; exit 1; }
"$FS" docs build "$manifest" --environment "$environment" --release "$release" -o "$out/docs" \
  --instrument "$ROOT/examples/surveys/school-meals-baseline" \
  --instrument "$ROOT/examples/surveys/household-water-access" \
  --policy "$ROOT/examples/deployments/policy/deployment-default.yaml"
printf 'tag %s\nmanifest %s\nrelease %s\nsigning %s\n' "$tag" "$address" "$release" "${sign[0]#--}" | tee "$out/release.txt"
