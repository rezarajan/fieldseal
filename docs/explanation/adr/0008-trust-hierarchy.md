# ADR 0008: Trust hierarchy and trust bundles

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** An offline root per authority certifies purpose-tagged keys; one runtime build trusts any authority via configuration.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Components must verify each other without sharing secrets, keys must rotate without app updates, and one runtime build must serve many authorities.

## Decision

- Each authority MUST have an offline root that certifies online, purpose-tagged keys with validity periods (factory, publisher, receipt and time, record keys per collection period, registration).
- Every signature MUST carry a domain tag (`fieldseal.dev/<purpose>/<version>`).
- A runtime MUST get its trust bundle from device configuration at provisioning, never from code.
- Revocation MUST use short validity plus revocation lists carried in anchors and bundles.

## Consequences

- Adding an authority to a runtime is a configuration change.
- Root compromise requires re-provisioning; online-key compromise is a rotation.

## Specs

[trust](../../reference/spec/trust.md)
