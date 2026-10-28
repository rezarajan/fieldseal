# ADR 0010: Instruments are declarative and schema-versioned

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26 · **Extended by:** [ADR 0032](./0032-standard-survey-elements.md) (survey elements), [ADR 0033](./0033-presentation-layouts.md) (layouts)

**In one line:** Instruments are declarative documents rendered from a fixed control catalogue, with a bounded rule language and semver.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

One runtime should collect any instrument an authority publishes, without app releases, and without letting an instrument run code on a device.

## Decision

- An instrument MUST be a declarative document (`kind: Instrument`) of items, catalogue controls, rules, field checks, consent requirements and data-contract hints.
- The rule language MUST be total and bounded (no loops, recursion, I/O); runtime and intake MUST evaluate it with the same core code.
- Instruments MUST NOT add UI; they MAY only choose and configure catalogue controls. Grouping on screen is a separate layout ([ADR 0033](./0033-presentation-layouts.md)), which is likewise declarative.
- The instrument schema MUST be semantic-versioned; a runtime MUST accept an instrument only if the major version matches and its minor version is at least the one required, and MUST still reject unknown fields.

## Consequences

- New instrument types need no runtime release while they stay within the schema.
- New control types need a runtime minor release and a schema minor version.

## Specs

[instrument](../../reference/spec/instrument.md)
