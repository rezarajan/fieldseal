# fieldseal-py (Python bindings)

## Overview

PyO3 bindings of the Fieldseal core for authority-side tools. An interface adapter (ADR 0028): it only
converts types and errors. It wraps [fieldseal-kernel](../../kernel/README.md) only. Cargo package
`fieldseal-py`; the extension module is named `fieldseal` (`cdylib`, abi3 for Python 3.11+).

## Interface

Python module `fieldseal` (source `src/lib.rs`):

- `core_version() -> str`: the version of the core the bindings were built from.
- `content_address(data: bytes) -> str`: `sha256:` plus 64 lowercase hex digits.
- `key_id(public_key: bytes) -> bytes`: the 16-byte key identifier.
- `fingerprint(salt: bytes, canonical: bytes) -> bytes`: the 32-byte salted instrument fingerprint
  (raises `ValueError` for a bad salt length).
- `canonical_cbor_from_json(text: str) -> bytes`: deterministic CBOR from JSON text. Objects become
  maps (duplicate keys refused), numbers with a fraction or exponent become decimals keeping every
  written digit; `null`, `NaN` and infinities are refused; nesting deeper than 16 is `E_SIZE`.
- `WireError`: subclass of `ValueError`; `args` are `(code, offset, message)` and the message starts with
  the WIRE section 6.8 code.

Build configuration is in `pyproject.toml` (maturin backend). `tests/test_vectors.py` checks the
binding against the kernel's golden vectors.

## Invariants

- No rules live here; every result comes from the kernel.
- Output is byte-identical to the kernel's golden vectors in `crates/kernel/tests/vectors`.

## Side Effects

None at runtime. Building produces a `cdylib`; `tools/build.sh` makes a manylinux_2_28 abi3 wheel into
`dist/python` with maturin.

## Verification

- Run: `cargo test -p fieldseal-py` (Rust side)
- Golden-vector tests: `tools/test-python-vectors.sh` (inside `nix develop path:.`)
