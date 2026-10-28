# ADR 0016: Tenancies with crypto-erase

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** A tenancy is one collector on one device for a window; closing it crypto-erases everything except sealed data awaiting delivery.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Devices are shared over time and between people; one collector's data must be unreadable to the next.

## Decision

- A tenancy MUST be one collector, one device, one window, with one active tenancy per device.
- Closing MUST seal a closing record and manifest, delete the tenancy's keys and local data, and move its sealed journal to the outbox.
- The authority MUST be able to force-close a tenancy with a signed close certificate carrying a cutoff sequence.
- Erasure MUST be cryptographic: identifying data MUST NOT be stored in plaintext.

## Consequences

- A device can serve any number of collectors, one after another, with no residue.

## Specs

[collection](../../reference/spec/collection.md)
