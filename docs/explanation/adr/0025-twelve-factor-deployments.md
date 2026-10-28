# ADR 0025: Twelve-factor, across the whole system, with bundled documentation

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Apply all twelve factors to every component (services fully, runtime and CLI wherever meaningful), with docs generated per release.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

Each authority runs its own deployment with its own identity provider, HSM, storage and data platform, and its devices run the same runtime build as every other authority's. Deployments must be reproducible, configurable without code changes, and documented in a way that matches what is actually running. The twelve-factor app methodology gives the discipline; it was written for services, so it has to be applied deliberately to a device runtime and a CLI.

## Decision

**Every Fieldseal component MUST follow the twelve factors to the highest degree its environment allows**: the factory, portal, intake and publishing pipeline fully; the runtime and the CLI wherever a factor has a meaningful equivalent.

| Factor | Services (factory, portal, intake, publishing) | Runtime (on devices) | CLI |
|---|---|---|---|
| I. Codebase | One repository, many deployments | Same: one runtime build per platform, used by every authority | Same |
| II. Dependencies | Declared and locked; container images | Declared and locked; no runtime downloads of code | Locked; single static binary where possible |
| III. Config | Environment variables and mounted, referenced secrets; nothing in code | Device configuration (platform managed configuration, provisioning extras), trust bundles and signed runtime policy; nothing authority-specific in the build | Environment variables and flags; config files only as an explicit override |
| IV. Backing services | Identity provider, HSM/KMS, transparency log, object store, data platform, policy engine: attached resources behind adapters, swappable by config | Factory, upload endpoint and time source are attached resources named in configuration and bundles | Same adapters as the services |
| V. Build, release, run | Strict separation; a release is an immutable build + deployment manifest | Build = signed app package; release = build + the deployment's provisioning configuration; run = a tenancy | Build = binary; release = binary + environment |
| VI. Processes | Stateless; state in backing services | All durable state is the journal, local record and outbox, behind storage ports; UI processes can be killed at any time | Stateless one-shot processes |
| VII. Port binding | Services export HTTP by binding a port | Not applicable (no inbound services; an invariant) | Not applicable |
| VIII. Concurrency | Scale out by process type | Not applicable beyond the platform's own | Parallel by invocation |
| IX. Disposability | Fast start, graceful shutdown, idempotent operations | Crash-safe: every write is atomic, every multi-step operation (seal, export, clear, close) resumes from a persisted marker | Idempotent, resumable operations |
| X. Dev/prod parity | Same images and adapters in every environment; only config differs | Same build for development and production; only the trust bundle and policy differ, and production policy refuses unattested keys | Same binary everywhere |
| XI. Logs | Structured event streams to stdout; never personal data | Structured events to a local, bounded, sealed diagnostic stream, uploaded with telemetry when online; never personal data | Structured events to stderr; machine-readable output with `--json` |
| XII. Admin processes | One-off tasks run as `fieldseal` CLI commands against the same release and config | Not applicable on device; operator tasks go through the factory | Is the admin-process tool |

**Deployment manifests.** A deployment manifest (`kind: Deployment`) MUST declare the adapters, attached-resource references, trust bundles, policies and artefact registries. Secrets MUST be referenced and MUST NOT be embedded. The manifest MUST be an artefact, published with provenance ([ADR 0009](./0009-publishing-with-provenance.md)).

**Bundled documentation.** `fieldseal docs build` MUST generate the deployment's documentation from the manifest and its published artefacts (policy tables, instrument codebooks and data dictionaries, trust fingerprints, adapter inventory, runbooks) and the release MUST bundle it, versioned with it.

## Consequences

- One runtime build serves every authority; a new authority is a new manifest and provisioning configuration, never a fork.
- What a deployment's documentation says is what its release runs.
- Each component's spec has a twelve-factor section stating how it complies and where a factor doesn't apply.
- Factor VII is deliberately inverted on devices: a runtime never listens for inbound connections.

## Specs

[deployment](../../reference/spec/deployment.md) · [cli](../../reference/spec/cli.md)
