#!/usr/bin/env bash
# WCAG 2.2 AA checks of the rendered instruments and, when a base URL is given, the web app
# (WEB-192, INS-257): axe-core (vendored, pinned) for the A/AA rules of WCAG 2.0, 2.1 and 2.2 on
# every step and tab, plus the 2.2 checks axe cannot make (focus not obscured, target size,
# reflow at 320 px, text spacing), at 1280 and 320 px. Exit 0 only with no finding.
#
#   tools/browser-tests/wcag.sh [web-base-url]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$here/../.."
out="$(mktemp -d)"
FS="${FIELDSEAL_BIN:-$root/target/debug/fieldseal}"
[ -x "$FS" ] || (cd "$root" && cargo build -p fieldseal-cli --locked -q)
for c in compact expanded; do "$FS" instrument preview "$root/examples/surveys/school-meals-baseline/instrument.yaml" --layout "$root/examples/surveys/school-meals-baseline/layouts/$c.yaml" --window "$c" -o "$out/food-$c.html" >/dev/null; done
"$FS" instrument preview "$root/examples/surveys/household-water-access/instrument.yaml" --lang es -o "$out/water-es.html" >/dev/null
pages=("file://$out/food-compact.html" "file://$out/food-expanded.html" "file://$out/water-es.html")
if [ -n "${1:-}" ]; then
  for p in /demo /demo/{1..8} /instruments /instruments/school-meals-baseline /publishing /registration /device; do pages+=("$1$p"); done
fi
# shellcheck disable=SC2016  # a Nix expression, not shell
py="$(nix build --no-link --print-out-paths --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}.python3.withPackages (p: [p.websockets])')"
ch="$(nix build --no-link --print-out-paths nixpkgs#chromium)"
export PATH="$ch/bin:$py/bin:$PATH"
status=0
echo "== axe-core, 1280 px";  python3 "$here/axe_run.py" 1280x900 "${pages[@]}" || status=1
echo "== axe-core, 390 px";   python3 "$here/axe_run.py" 390x844 "${pages[@]}" || status=1
echo "== WCAG 2.2 checks axe cannot make"; python3 "$here/wcag22.py" "${pages[@]}" || status=1
rm -rf "$out"
exit "$status"
