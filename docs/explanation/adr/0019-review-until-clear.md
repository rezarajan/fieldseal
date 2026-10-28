# ADR 0019: Review until export, then clear

**Status:** Superseded by [0029](./0029-clear-anytime-with-pin-confirmation.md) (2026-10-26) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Collectors can review all their records, with field checks, until delivery is confirmed and they explicitly clear.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Problems in the field (a miscalibrated scale, a misunderstood question, a skipped section) are cheapest to fix while the collector is still on site. The collector needs to see everything collected, with checks that point out patterns, until the data is safely delivered.

## Decision

- The collector MUST be able to review every record in the local record during a session, until it is cleared.
- Review MUST show the field checks declared in the instrument.
- Clear MUST delete the local record and journal through a sequence number and append a checkpoint record.
- Clear MUST be allowed only when runtime policy's delivery condition is met (default: an authority receipt).
- Clear MUST be an explicit, hold-to-confirm action; the runtime SHOULD remind and MUST NOT clear automatically.

## Consequences

- The local record's lifetime is bounded by delivery, not by the tenancy.

## Specs

[collection](../../reference/spec/collection.md) · [delivery](../../reference/spec/delivery.md)
