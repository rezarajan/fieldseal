#!/usr/bin/env bash
# Control 4 of the design's section 7.2 (WEB-155): the browser sends no cookie of the factory or
# the intake portal (on localhost) to the collector stand-in (on 127.0.0.1). Needs chromium and
# python3 with `websockets`; without them on the PATH it asks nix for both. Run it against a
# running `just web` (tools/dev-web.sh --check --browser does) or a running stack
# (tools/stack-smoke.sh --browser does).
#
#   tools/browser-tests/cookies.sh [--login NAME] [collector-url [factory-url [portal-url]]]
#
# With --login NAME the sign-in is completed at the development IdP as that login (`just web`);
# without it the check uses the cookies the two sign-ins set on the way to the identity provider
# (the stack's Keycloak asks for a passkey, which this script does not have).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if command -v chromium >/dev/null && python3 -c 'import websockets' 2>/dev/null; then
  exec python3 "$here/cookies.py" "$@"
fi
# shellcheck disable=SC2016  # a Nix expression, not shell
exec nix shell nixpkgs#chromium --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.python3.withPackages (p: [p.websockets])' \
  --command python3 "$here/cookies.py" "$@"
