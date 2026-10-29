#!/usr/bin/env bash
# Runs the browser device flow (tools/browser-tests/device-flow.js) against a running
# fieldseal-web with the demo authority. Needs chromium and python3 with `websockets`;
# without them on the PATH it asks nix for both.
#
#   FIELDSEAL_WEB_DEMO_AUTHORITY=true fieldseal-web &      # (see the web crate's README)
#   BASE=http://127.0.0.1:18110 INSTRUMENT=school-meals-baseline SHOTS=/tmp/shots \
#     tools/browser-tests/device-flow.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
[ -z "${SHOTS:-}" ] || mkdir -p "$SHOTS"
if command -v chromium >/dev/null && python3 -c 'import websockets' 2>/dev/null; then
  exec python3 "$here/device-flow.py" "$@"
fi
exec nix shell nixpkgs#chromium --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.python3.withPackages (p: [p.websockets])' \
  --command python3 "$here/device-flow.py" "$@"
