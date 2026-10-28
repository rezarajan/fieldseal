# ADR 0030: A public transparency log, privacy-safe by construction

**Status:** Accepted (2026-10-26, decided by the project lead in architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Publications are logged in a public transparency log through a port whose entry type can only hold a hash, a signature and a pseudonymous key, so nothing sensitive can ever be logged; Rekor is one adapter.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

[ADR 0009](./0009-publishing-with-provenance.md) requires a transparency log. A self-hosted log alone can't show outsiders that it gives every device the same history, and independent witnesses need outside parties to be recruited. A public log (for example Sigstore's Rekor) already provides public monitoring at scale. Its entries are public and permanent, so it is safe only if no entry can ever carry anything sensitive. That must be guaranteed by the design and proven by conformance tests, not left to each developer's care.

## Decision

- Publications and withdrawals MUST be logged in a **public, append-only transparency log**, reached only through the `TransparencyLog` port. Any log that passes the port's contract tests is acceptable; Rekor is the first adapter.
- **Condition 1: only hashes are logged.** The domain's `LogEntry` type MUST be constructible only from an entry type (`publish` or `withdraw`), a 32-byte digest, one signature and one public key. It MUST have no other fields and no extension mechanism. The digest MUST be of a signed statement containing only hashes and enumerations (the instrument fingerprint, the provenance digest). Artefacts, provenance documents, names, versions and source locations MUST NOT be logged.
- **Condition 2: no names in certificates.** Key certificates MUST identify their subject only by key ID. The Trust context MUST reject any signing request carrying a name, email address or other identity attribute. The key-ID-to-person mapping MUST be held only in a private `KeyHolderRegistry` port, never in bundles, trust bundles or logs. Provenance MUST name reviewers by pseudonymous IDs.
- **Condition 3: permanence is safe.** Because conditions 1 and 2 are enforced by type, nothing personal can reach the log, so permanence creates no erasure obligations. Any port operation that would send other data MUST NOT exist.
- **Offline verification.** Every publication MUST carry its inclusion proofs and a signed checkpoint, and the trust bundle MUST pin the log's public key, so devices verify inclusion without contacting the log.
- **Enforced by conformance.** Every `TransparencyLog` adapter MUST pass a contract suite that records the exact bytes it sends and fails on any field outside the allowed set. CI MUST run it for every adapter.

## Consequences

- A compromised factory or registry can't show one device a different instrument from everyone else without that being visible in public.
- Publishing depends on the public log being reachable; collection doesn't.
- The authority's publication volume and timing are visible under pseudonymous keys; nothing else is.
- Supersedes nothing; resolves the transparency-log open questions in the publishing spec.

## Specs

[publishing](../../reference/spec/publishing.md) · [trust](../../reference/spec/trust.md) · [wire-formats](../../reference/spec/wire-formats.md)
