# ADR 0026: Supersede the v0.x design documents

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Archive the v0.x design; only ADRs and specs are normative.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Designs v0.2–v0.4 were written for one programme and one platform, with domain-specific names. Their reasoning remains useful but their terms and scope don't.

## Decision

- The v0.x design documents MUST NOT be normative. They were first kept in `docs/archive/`, marked superseded; they are no longer part of the repository.
- The ADRs and specs MUST be the only normative design; where an archived document disagrees, they win.
- New documents MUST NOT use the archived documents' programme-specific terms.

## Consequences

- Readers start from the glossary, the ADR index and the spec index.

## Specs

[spec index](../../reference/spec/README.md)
