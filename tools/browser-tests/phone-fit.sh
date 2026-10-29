#!/usr/bin/env bash
# The browser device on a phone (issue #47): every screen of the device (your surveys, the
# roster, each step of both examples' compact layouts, the review) fits a 390x844 window without
# scrolling. Headless, against a running `just web` that has assigned household-water-access to
# the presenter and school-meals-baseline to collector1; `tools/dev-web.sh --check --browser` runs
# it after the guided demo. It registers a device for each account and retires it afterwards.
# Needs chromium and python3 with `websockets`; without them on the PATH it asks nix for both.
#
#   tools/browser-tests/phone-fit.sh [--collector URL] [--factory URL] [--state DIR]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if command -v chromium >/dev/null && python3 -c 'import websockets' 2>/dev/null; then
  exec python3 "$here/phone-fit.py" "$@"
fi
# shellcheck disable=SC2016  # a Nix expression, not shell
exec nix shell nixpkgs#chromium --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.python3.withPackages (p: [p.websockets])' \
  --command python3 "$here/phone-fit.py" "$@"
