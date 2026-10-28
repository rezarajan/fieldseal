# ADR 0011: Policy as signed files, with invariant floors

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Every tunable control is a signed policy file; layers may only tighten security; code-level invariants can't be loosened.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Thresholds and limits differ by authority and programme and change over time. Hard-coding them forces releases; letting them be anything risks a policy that disables security.

## Decision

- Every tunable control MUST be expressed in a published policy (`kind: Policy`) for the factory, runtime or intake.
- Policies MUST layer deployment → programme → instrument, and for security controls a later layer MUST only tighten.
- Invariants MUST be in code; a policy that goes below them MUST be rejected (sealing, authenticate-before-parse, secure display, runtime PIN ≥ 6, no plaintext identity on storage, no biometric-only unlock).
- The factory and intake MUST evaluate policy through a policy-engine port; the runtime MUST evaluate its typed schema directly.
- Every decision MUST record the content address of the policy that produced it.

## Consequences

- Operators change behaviour by publishing policy, never by redeploying code.
- `fieldseal policy validate` checks schema, layering and invariant floors before review.

## Specs

[policy](../../reference/spec/policy.md)
