# ADR 0003: Domain-driven design, materialised as hexagonal components

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Build each part as a hexagon: pure domain, use cases, ports, and swappable adapters per technology.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Fieldseal must run on several operating systems, with different identity providers, key stores, HSMs and data platforms per authority. If each component is written against concrete technologies, every new platform or authority is a rewrite, and developers spend their time on plumbing instead of the specs.

## Decision

- The domain MUST be split into bounded contexts ([ADR 0004](./0004-bounded-contexts.md)), each with its own model, language and spec.
- Each context MUST be built as a hexagon: a pure **domain** (no I/O, platform calls or clock), **application** use cases, **driving ports** (what it offers), **driven ports** (what it needs, as interfaces) and **adapters** (one per technology, chosen by configuration).
- Specs MUST define the domain model, ports and port contracts, and SHOULD name adapters only as examples, except in platform profiles.
- Every driven port MUST have a contract test suite and an in-memory adapter.

## Consequences

- New platforms, identity providers or HSMs are new adapters, tested against the port's contract tests.
- Developers implement against specs; much of the work is adapters.
- Every port needs a contract test suite and an in-memory adapter for tests.

## Specs

[spec index](../../reference/spec/README.md)
