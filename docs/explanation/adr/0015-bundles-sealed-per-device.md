# ADR 0015: Bundles sealed per device key

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** The factory seals each bundle to one device key and signs it; the device verifies before loading.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

A bundle carries rosters that identify subjects. It must be readable only on the device it was built for, and its contents must be verifiable on that device.

## Decision

- The factory MUST build each bundle for one registered agreement key, containing the instrument with its publishing evidence, rosters, runtime policy, trust updates and anchors.
- Bundles MUST be sealed with HPKE to that key and signed by the factory.
- The runtime MUST check envelope, signature, then decrypt, then validate, then verify publisher signatures and log inclusion, before loading.
- Bundles MAY be delivered in-app or imported from any route; file names MUST be neutral.

## Consequences

- Rolling an agreement key makes old bundles unreadable; the runtime fetches or the collector downloads new ones.

## Specs

[distribution](../../reference/spec/distribution.md) · [wire-formats](../../reference/spec/wire-formats.md)
