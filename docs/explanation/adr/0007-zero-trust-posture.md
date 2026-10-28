# ADR 0007: Zero-trust posture

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Trust no network, transport or storage: authenticate before parsing, seal every output end to end.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Devices are shared and may be online or offline; data travels by any route; transport, storage locations and networks are not trusted.

## Decision

- Components MUST NOT grant trust from network location, transport or storage.
- Every inbound artefact MUST get a minimal, bounded parse, then authentication, then decryption, then strict schema validation, before use.
- Every outbound artefact MUST be sealed to its recipient and signed by its sender, independent of TLS.
- Device posture MUST be checked at registration and SHOULD be re-checked when online; failures MUST pause releases of sensitive data and MUST NOT block collection or delivery.
- Decisions MUST be made by policy evaluation and logged.

## Consequences

- Any transport is acceptable, including none (files carried by hand).
- TLS is still used, but no guarantee depends on it.

## Specs

[trust](../../reference/spec/trust.md) · [wire-formats](../../reference/spec/wire-formats.md)
