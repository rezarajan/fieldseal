# ADR 0001: Record architecture decisions

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Record each decision as a short ADR with a MoSCoW priority and RFC 2119 wording; specs hold the detail.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Fieldseal is built spec-first: a decision has to be findable, argued and traceable to the spec requirements and tests that implement it. Earlier design versions kept decisions in a single log mixed with explanation.

## Decision

- Every architecturally significant decision MUST be an ADR in `docs/explanation/adr/`, numbered, with sections Status, Priority, Context, Decision, Consequences, Specs.
- Decisions and specs MUST use the key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY as described in RFC 2119 and RFC 8174, and only when in capitals.
- Every ADR MUST carry a **MoSCoW priority** for the current delivery: **Must** (the system isn't viable without it), **Should** (important, but the system works without it for now), **Could** (desirable if time allows), **Won't** (agreed out of scope for now). Issues implementing an ADR MUST carry the same scale, as a `priority:` label.
- Status MUST be one of **Proposed**, **Accepted**, **Superseded by NNNN** or **Rejected**. An accepted ADR MUST NOT be edited except to change its status; a change MUST be a new ADR.
- Normative detail MUST live in the specs; an ADR SHOULD say what and why in under a page.
- ADRs are approved, changed or dropped together through the architecture review issue.

## Consequences

- Reviewers read one short file per decision.
- Specs cite ADRs; tests cite spec requirement IDs; the chain from decision to test is explicit.

## Specs

[spec index](../../reference/spec/README.md)
