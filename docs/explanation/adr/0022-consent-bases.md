# ADR 0022: Consent bases and risk-based review

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Consent is granted, refused or unknown; collectors may attest unknown consent with optional photo evidence; intake reviews by risk.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Consent records held by authorities are often incomplete and not machine-verifiable; data about people must still have a recorded basis.

## Decision

- Rosters MUST carry consent as `granted`, `refused` or `unknown`; a refused subject MUST get no record of any kind.
- For `unknown`, the collector MAY attest consent with a basis, a versioned statement and optional in-app photo evidence.
- Every record about a subject MUST reference its consent basis, and intake MUST check it against roster history.
- Intake SHOULD review by risk: automatic acceptance where rules pass and evidence exists, a sample, triggers, and a custodian rule for attestations without evidence.

## Consequences

- Whether an instrument needs consent at all is part of the instrument.

## Specs

[collection](../../reference/spec/collection.md) · [intake](../../reference/spec/intake.md)
