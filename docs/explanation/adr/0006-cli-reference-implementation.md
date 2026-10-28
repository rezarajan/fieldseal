# ADR 0006: The CLI is the reference implementation

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** The `fieldseal` CLI performs every protocol operation and is the reference for conformance.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Spec-driven development needs an executable reference: something that performs every protocol operation exactly as specified, for authors, operators, CI and conformance tests, without a device.

## Decision

- `fieldseal` MUST implement every operation in the specs, from artefact validation to intake and documentation generation.
- It MUST run as a twelve-factor admin process using the same ports and adapters as the services.
- Conformance MUST be CLI-driven: an implementation conforms when its outputs pass `fieldseal verify` and match the golden vectors.
- The CLI MAY simulate a device with software keys; such keys MUST be marked unattested, and production factory policy MUST refuse them.

## Consequences

- The CLI can simulate a device with software keys; such keys are always marked as unattested, and no factory policy may accept them in production.

## Specs

[cli](../../reference/spec/cli.md)
