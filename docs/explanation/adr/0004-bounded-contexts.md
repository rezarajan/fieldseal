# ADR 0004: Bounded contexts and the context map

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Split the domain into 10 bounded contexts sharing one set of wire formats.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The grain of decomposition decides what can change independently. Too coarse, and the runtime and factory drag each other along; too fine, and every feature crosses five contexts.

## Decision

- Fieldseal MUST have these bounded contexts: **Trust**, **Publishing**, **Instrument**, **Policy**, **Registration**, **Distribution**, **Collection**, **Delivery**, **Intake**, **Deployment** (responsibilities in the [overview](../overview.md)).
- The **shared kernel** MUST be the wire formats spec (records, journal, bundles, exports, registration messages, receipts, tokens), implemented once.
- Identity providers, platforms, HSMs and data platforms MUST sit behind adapters (anti-corruption layers).
- A change to the shared kernel MUST be agreed by every context that uses it and MUST bump the format version.

## Consequences

- One spec per context, plus the wire formats spec and one spec per platform profile.
- A change to the shared kernel needs agreement from every context that uses it, and a format version bump.

## Specs

[spec index](../../reference/spec/README.md)
