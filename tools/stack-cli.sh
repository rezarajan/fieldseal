#!/usr/bin/env bash
# Prints the path of the fieldseal CLI. It is built on demand by Nix (cached in the store), so
# the dev shell, and the recipes that only need the container engine, never depend on the Rust
# workspace compiling. FIELDSEAL_BIN overrides.
set -euo pipefail
if [ -n "${FIELDSEAL_BIN:-}" ]; then printf '%s\n' "$FIELDSEAL_BIN"; exit 0; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(nix build "path:$ROOT#fieldseal" --no-link --print-out-paths)"
printf '%s/bin/fieldseal\n' "$out"
