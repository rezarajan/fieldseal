# ADR 0018: Dual-write records: sealed journal and local record

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Seal each record twice: to the authority's journal (source of truth) and to a local record the collector can read.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Collectors need to see and correct their own work; the authority needs a copy no device event can alter or lose.

## Decision

- Each record MUST be written to the journal, sealed to the authority's record key, and to the local record, encrypted under the session key.
- Records MUST be immutable diffs of what was set: no defaults; absent means not collected; a correction MUST be a new record.
- The journal MUST be append-only and hash-chained, and each record MUST be signed and carry a tick.

## Consequences

- Resume, resurvey, review and correction show current values.
- Losing the local record (forgotten PIN, forced close) loses no data.

## Specs

[collection](../../reference/spec/collection.md) · [wire-formats](../../reference/spec/wire-formats.md)
