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
