# ADR 0020: Monotonic ticks

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Should · **Date:** 2026-10-26

**In one line:** Order and bound record times with Cardano-style ticks (signed anchors plus an unsettable elapsed counter).

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Device wall clocks can be set to anything; records still need order and provable time bounds.

## Decision

- Every record MUST carry a tick: latest anchor hash, elapsed time by the platform's monotonic clock (continued across reboots), boot count; the wall clock MAY be added as an untrusted hint.
- Anchors MUST include the release anchor, bundles and receipts, and SHOULD include time tokens when online or scanned.
- Intake MUST check monotonicity, lower bounds and fast running.
- Device time MUST NOT trigger anything irreversible.

## Consequences

- A device kept powered off can hide elapsed time; that residual is accepted and stated.

## Specs

[wire-formats](../../reference/spec/wire-formats.md) · [intake](../../reference/spec/intake.md)
