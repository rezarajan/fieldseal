#!/usr/bin/env bash
# Run the Python binding's golden-vector tests against a freshly built module, without
# installing anything: builds the cdylib, copies it as fieldseal.abi3.so into a scratch
# directory and runs the unittest suite there (WIRE section 8).
#   usage: tools/test-python-vectors.sh      (inside `nix develop path:.`)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
cargo build --locked -p fieldseal-py
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
[ "$(uname -s)" = Darwin ] && src=libfieldseal.dylib || src=libfieldseal.so
cp "target/debug/$src" "$work/fieldseal.abi3.so"
PYTHONPATH="$work" python3 -m unittest discover -v -s crates/bindings/python/tests
