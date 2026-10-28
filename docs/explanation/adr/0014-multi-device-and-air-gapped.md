# ADR 0014: Multi-device and air-gapped registration

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Should · **Date:** 2026-10-26

**In one line:** Each device registers separately (limits by policy); every exchange also works air-gapped via QR codes and files.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Collectors may use several devices; some devices never connect to a network.

## Decision

- Each device MUST be registered separately with its own token, keys and bundles.
- Device, cohort and batch-token limits MUST be factory policy.
- The portal SHOULD list a collector's devices with roll keys, mark as lost and retire.
- Every exchange SHOULD work air-gapped: small signed messages as QR codes from a screen, larger ones as files (or MAY be animated QR). The factory, not the device, MUST check token expiry.
- A deployment MAY run the factory on an isolated network.

## Consequences

- No step of the protocol needs the device to be online.

## Specs

[registration](../../reference/spec/registration.md) · [wire-formats](../../reference/spec/wire-formats.md)
