# Fuzzing the decoders (manual)

`cargo test -p fieldseal-security-tests` already runs a seeded, deterministic version of this
(`tests/decoder_hardening.rs`) over every decoder in `src/decoders.rs`. For open-ended runs use
`cargo-fuzz` (nightly toolchain; it is not in the dev shell):

```sh
cargo install cargo-fuzz
cd crates/apps/security-tests
cargo +nightly fuzz run decoders -- -max_len=65536 -timeout=2 -rss_limit_mb=512
```

The first input byte picks the decoder (index modulo the table), the rest is its input. Seed the
corpus from the golden vectors (hex strings in `crates/**/tests/vectors/*.json`) for faster
coverage. A crash is a security bug: add the input as a regression case to the seeded test.
Not wired to CI.

## Interface
- Package `fieldseal-fuzz` (`fuzz/Cargo.toml`, its own `[workspace]`, `cargo-fuzz = true`), one binary target `decoders` at `fuzz_targets/decoders.rs`.
- The target takes `&[u8]`; the first byte selects an entry of `fieldseal_security_tests::decoders::targets()` (index modulo the table length), the rest is the decoder input.

## Invariants
- Properties checked: no panic, and an accepted input re-encodes to exactly itself (canonical form); otherwise it asserts `"<name>: accepted a non-canonical encoding"`.
- An empty input returns immediately.
- A crash is a security bug and becomes a regression case in the seeded test.

## Side Effects
- Runs only under `cargo +nightly fuzz run decoders`; writes the libFuzzer corpus and artifacts under `fuzz/` (corpus/artifacts directories). Not part of the main workspace and not wired to CI. No network.

## Verification
- Seeded, deterministic equivalent: `cargo test -p fieldseal-security-tests` (repo-wide: `just test`).
- Open-ended: `cd crates/apps/security-tests && cargo +nightly fuzz run decoders -- -max_len=65536 -timeout=2 -rss_limit_mb=512` (needs `cargo install cargo-fuzz`; the justfile has no fuzz recipe).
