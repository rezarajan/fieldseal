# ADR 0023: Generic intake and landing

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Intake verifies every export in a fixed order and lands any instrument in one generic long format.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Intake and storage must handle any published instrument, not one questionnaire.

## Decision

- Intake MUST verify exports in a fixed sequence (handle, signature, parity, manifest, certificate, record signatures, chain, ticks, consent, replay).
- It MUST land records in a generic long format `(instrument, subject, item path, value, source record)`.
- Data contracts SHOULD be generated from instruments; instrument-specific models SHOULD be downstream, per deployment.
- The data platform MUST be a driven port.

## Consequences

- Adding an instrument needs no intake code.

## Specs

[intake](../../reference/spec/intake.md)
