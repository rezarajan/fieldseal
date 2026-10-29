#!/usr/bin/env bash
# Walks docs/tutorials/hands-on.md exactly: every `just <step>` the tutorial shows, in its order,
# against a fresh stack (headless: `just enrol` stands in for the manual passkey steps). The
# step list is read from the tutorial itself, so the tutorial and this test cannot drift.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUTORIAL="$ROOT/docs/tutorials/hands-on.md"
# Lines of the form `just <step> [args]` inside the tutorial's ```sh blocks marked "# step".
mapfile -t steps < <(awk '/^```sh/{b=1;next} /^```/{b=0} b && /# step$/{sub(/[[:space:]]*# step$/,""); print}' "$TUTORIAL")
[ "${#steps[@]}" -gt 0 ] || { echo "acceptance: no steps found in $TUTORIAL" >&2; exit 1; }
cd "$ROOT"
just purge
for s in "${steps[@]}"; do
  printf '\n######## %s\n' "$s"
  # shellcheck disable=SC2086
  eval "$s" || { echo "acceptance: FAILED at: $s" >&2; exit 1; }
done
# The rendered instrument the tutorial asks you to open exists and carries the enforcement script.
html=(deploy/local/.out/school-meals-baseline-*.html)
[ -s "${html[0]}" ] || { echo "acceptance: the rendered instrument is missing" >&2; exit 1; }
printf '\nacceptance: all %d tutorial steps passed\n' "${#steps[@]}"
