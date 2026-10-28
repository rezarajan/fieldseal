# ADR 0012: Local-first device keys with platform attestation evidence

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Devices make and use hardware-backed keys at once; only releasing rosters waits for registration.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

A collector must be able to start immediately, with or without a network, while the authority still gets hardware-backed assurance before releasing sensitive data.

## Decision

- The runtime MUST generate a tenancy's signing and agreement keys locally, in the platform's secure key store, without waiting for the factory.
- Attestation evidence MUST be captured at key creation, with the factory's challenge when available and a local nonce otherwise.
- Attestation MUST be platform-specific evidence behind one port (`Attestor`, `AttestationVerifier`).
- Everything that doesn't need the authority's verdict MUST work locally; releasing a bundle containing rosters MUST wait for registration.
- A device without hardware-backed keys MAY be used for practice, but MUST NOT be registered.

## Consequences

- A device without hardware-backed keys can be used for practice, but its tenancies are never registered.
- Keys can be rolled at any time; a rolled key gets fresh evidence and is registered like a new one.

## Specs

[registration](../../reference/spec/registration.md) · [platform-profiles](../../reference/spec/platform-profiles.md)
