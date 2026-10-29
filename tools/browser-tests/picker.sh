#!/usr/bin/env bash
# The survey picker of the browser device (issue #48): an account assigned two surveys for one
# cohort sees one group, chooses each survey in turn on the roster, starts a capture for a person
# and backs out. Headless, against a running `just web` that has issued
# tools/browser-tests/fixtures/picker-a.yaml and assigned both example surveys to picker-a for
# the account collector2; `tools/dev-web.sh --check --browser` runs it after the phone-fit check.
# It registers a device for that account and retires it afterwards. Needs chromium and python3
# with `websockets`; without them on the PATH it asks nix for both.
#
#   tools/browser-tests/picker.sh [--collector URL] [--factory URL] [--state DIR]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if command -v chromium >/dev/null && python3 -c 'import websockets' 2>/dev/null; then
  exec python3 "$here/picker.py" "$@"
fi
# shellcheck disable=SC2016  # a Nix expression, not shell
exec nix shell nixpkgs#chromium --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.python3.withPackages (p: [p.websockets])' \
  --command python3 "$here/picker.py" "$@"
