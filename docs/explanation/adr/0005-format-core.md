# ADR 0005: One format core as the shared kernel

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Implement formats, cryptography and rules once, in a Rust core bound to every platform.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The device writes and the authority verifies the same bytes. Two implementations of a format drift apart, and verification bugs become data loss.

## Decision

- The shared kernel (wire formats, cryptography, rule evaluation, merge) MUST be implemented once, in Rust, as the **format core**.
- It MUST be exposed through bindings (UniFFI for Kotlin and Swift, PyO3 for Python, a C ABI where needed) and used directly by the CLI and services.
- The core MUST NOT perform I/O itself; platform needs MUST reach it through driven ports.

## Consequences

- One set of golden test vectors serves every implementation.
- Platform teams write adapters and UI, not formats or cryptography.

## Specs

[wire-formats](../../reference/spec/wire-formats.md)
