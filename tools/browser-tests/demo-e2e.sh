#!/usr/bin/env bash
# CUJ 4 end to end (entry 490): the eight steps of the guided demo, headless, against a running
# `just web`. Run from a second terminal, or let `tools/dev-web.sh --check --browser` run it. It
# issues roster version 4 and registers a device, so use it on state you can throw away
# (remove deploy/local/.state/dev-web before the next demo). Needs chromium and python3 with
# `websockets`; without them on the PATH it asks nix for both.
#
#   tools/browser-tests/demo-e2e.sh [--collector URL] [--factory URL] [--results URL] [--log URL] [--state DIR]
#
# Environment: FIELDSEAL_BIN (the CLI; built when unset).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$here/../.."
export FIELDSEAL_BIN="${FIELDSEAL_BIN:-$("$root/tools/stack-cli.sh")}"
if command -v chromium >/dev/null && python3 -c 'import websockets' 2>/dev/null; then
  exec python3 "$here/demo-e2e.py" "$@"
fi
# shellcheck disable=SC2016  # a Nix expression, not shell
exec nix shell nixpkgs#chromium --impure --expr '(builtins.getFlake "nixpkgs").legacyPackages.x86_64-linux.python3.withPackages (p: [p.websockets])' \
  --command python3 "$here/demo-e2e.py" "$@"
