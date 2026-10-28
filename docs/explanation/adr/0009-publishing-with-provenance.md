# ADR 0009: Publish artefacts with provenance and a transparency log

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Instruments and policies are reviewed, signed by a publisher threshold, logged in a transparency log, and verified on the device.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

An instrument decides what is collected from people, and a policy decides who may do what. If a compromised factory, a careless author or a single insider can change either, the data and its subjects are at risk. Artefacts need provenance and assurance of their own, independent of the factory.

## Decision

- Instruments, policies, trust bundles and deployment manifests MUST be published through one flow: author → validate → review (policy sets approvals; default 2, author excluded) → CI canonicalises and content-addresses → signed provenance (in-toto, SLSA) → threshold publisher signatures (default 2 of N) → transparency log → registry.
- The registry MUST accept an artefact only if signatures, provenance and log inclusion verify.
- The factory MUST build bundles only from published artefacts, carrying their signatures, provenance and inclusion proofs.
- The runtime MUST verify an instrument's publisher signatures itself.
- Withdrawal MUST be a logged event; factories MUST stop using withdrawn artefacts and runtimes SHOULD refuse them once informed.

## Consequences

- Separation of duties: authoring, reviewing, publishing and bundle building are different roles and keys.
- Every record names the content address of the instrument it answers, which ties data to an exact, logged definition.
- The transparency log is a driven port; a deployment may use a self-hosted log or a public one.

## Specs

[publishing](../../reference/spec/publishing.md) · [trust](../../reference/spec/trust.md)
