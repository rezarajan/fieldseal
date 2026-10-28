#!/usr/bin/env bash
# The whole test suite, under its budget: every test (cargo-nextest, in parallel) and the doc
# tests must finish within FIELDSEAL_TEST_BUDGET seconds (default 20), building excluded.
set -euo pipefail
budget="${FIELDSEAL_TEST_BUDGET:-20}"
cargo nextest run --workspace --locked --no-run >/dev/null
cargo test --workspace --locked --doc --no-run >/dev/null 2>&1 || true
start=$(date +%s%N)
cargo nextest run --workspace --locked
cargo test --workspace --locked --doc -q
elapsed_ms=$(( ($(date +%s%N) - start) / 1000000 ))
printf 'test suite: %d.%03d s (budget %d s)\n' $((elapsed_ms / 1000)) $((elapsed_ms % 1000)) "$budget"
[ "$elapsed_ms" -le $((budget * 1000)) ] || { echo "test suite: over its ${budget} s budget" >&2; exit 1; }
