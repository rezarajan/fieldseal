# ADR 0013: Registration via authority-issued tokens

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Collectors sign in only at the portal (any IdP); the portal's one-time token goes to the device, never a code from the device.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The runtime must be portable across authorities and identity providers, so it can't run an identity provider's flow. Cross-device sign-in flows in which a device shows a code for a person to enter are open to code phishing.

## Decision

- The runtime MUST NOT talk to an identity provider; collectors MUST authenticate only at the portal, through an identity adapter, with phishing-resistant authentication required by policy.
- Registration tokens MUST flow from the signed-in portal to the device: the portal issues a single-use token (factory URL, trust-root fingerprint, factory nonce), the device sends a registration request with attestation evidence and proof of possession.
- The portal MUST show the request's fingerprint words and require the collector to confirm them against the device for cross-device routes.
- After registration the runtime MUST authenticate with its own keys (proof-of-possession tokens).

## Consequences

- An attacker can't complete registration by sending a collector a code; they would have to obtain a token from the collector's own signed-in portal, and the fingerprint words would still differ.
- One runtime build works with any identity provider.

## Specs

[registration](../../reference/spec/registration.md)
