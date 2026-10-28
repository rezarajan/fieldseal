# Fieldseal

Fieldseal collects structured data about people in the field, on devices that may be shared, offline or both, and delivers it to an authority by any route. Every step carries proof, from the definition of what is collected to the record that lands:
- **Instruments are published** with review, threshold signatures, provenance and a transparency log.
- **Devices make their own hardware-backed keys** and register them with the authority's factory through a portal. The factory doesn't care which identity provider the authority uses.
- **Bundles are sealed to one device**, and the runtime verifies the instrument's own signatures before rendering it.
- **Records are sealed to the authority** as they are written, and stay reviewable by the collector until delivery is confirmed and the local copy is cleared.
- **Intake verifies everything** before landing records in a generic format.

## Documentation

Start at [`docs/index.md`](docs/index.md):
- [System overview](docs/explanation/overview.md): architecture diagram, bounded contexts, hexagonal structure.
- [ADRs](docs/explanation/adr/README.md): every decision, one per file.
- [Specifications](docs/reference/spec/README.md): normative, per bounded context, with requirement IDs for spec-driven development.
- [Glossary](docs/reference/glossary.md).

## Status

**Design:** `fieldseal.dev/v1alpha1`, proposed. It is accepted through the architecture review issue.

**Code:** the format core, the bounded contexts, their adapters, the `fieldseal` CLI, the factory, the transparency log, the intake upload endpoint and the web app with its browser device, built against the specs. `just up` runs them as a local compose stack; [the hands-on tutorial](docs/tutorials/hands-on.md) walks every step.

> This repository contains design intent for handling personal data, including data about minors. Keep it private.

## Subdirectories & System Boundaries

- crates: [crates/README.md](crates/README.md) - The Cargo workspace by layer: kernel, the ten bounded contexts, adapters, bindings and apps.
- tools: [tools/README.md](tools/README.md) - Build, check, test-budget, local-stack and release scripts, and the [browser and accessibility tests](tools/browser-tests/README.md).
- examples: [examples/README.md](examples/README.md) - Sample instruments, layouts, rosters, scenarios and deployment manifests used by the tests, the demo and the tutorial (data, no code).
- deploy: `deploy/local` - The compose file, container-engine configuration and Keycloak realm for the local stack (configuration, no code).
- docs: [docs/index.md](docs/index.md) - Explanations, how-tos, the reference (specs, glossary) and the tutorial.
- CI and build environment: `.github/workflows` (`ci.yml`, `build.yml`), `.config/nextest.toml` (the nextest profile behind the 20 s test budget), `Containerfile` (runs `tools/build.sh` and `tools/check-portable.sh`), and `flake.nix` (the dev shell, flake checks and the wasm bundle).

## Global Invariants

- Dependencies point inward only: `kernel <- contexts <- adapters <- bindings, apps`, with the context-to-context edges listed in [`architecture.toml`](architecture.toml) ([ADR 0028](docs/explanation/adr/0028-clean-architecture.md)). `tools/check-architecture.py` enforces this.
- The kernel and contexts are pure: no I/O, clocks or ambient randomness, and only allow-listed pure third-party crates. Everything with side effects lives behind ports in adapters.
- Wire formats are deterministic CBOR, decoded strictly; unknown fields, versions and oversized inputs are refused.
- Verification fails closed: chains to the trust bundle, threshold signatures, attestation, policy decisions (never Allow on error) and the intake gate all refuse on any failure. A record is landed only after every check passes.
- Development-only settings are refused in production at the composition roots: the factory refuses dev identity, dev and file custody, file state and unattested keys, and the web app refuses to start. The development adapters themselves (file custody, the demo authority) are marked "not for production" but do not check the environment.
- Requirement IDs in [the specs](docs/reference/spec/README.md) are the unit of conformance; `fieldseal conformance` reports results against them.

## Global Side Effects

- Local stack (`just up`): containers, volumes, secrets and env files under `deploy/local`, image stamps under `deploy/local/.generated`, walkthrough output in `deploy/local/.out`, and ports bound on 127.0.0.1 only for the factory, upload endpoint, transparency log, web app and Keycloak. `just purge` (also run first by `just acceptance`) deletes all stack state.
- External integrations through adapters: OIDC identity providers, Sigstore Rekor or the self-hosted transparency log, Open Policy Agent, and TPM attestation roots.
- On disk: key custody directories, registry journals, decision logs, submission stores and landing files (CSV/JSON), written by the adapters and binaries that own them.
- Build outputs: `target/`, `dist/` (Android libs and bindings, wheels), `release-docs/`, and the generated `docs/reference/test-inventory.md`.

## System Verification

- Run: `just test` (test inventory check, nextest and doc tests within the 20 s budget, clippy and the architecture check)
- CI parity: `just check` (the flake's clippy, tests and architecture checks; builds `checks.x86_64-linux.*` only)
- Per crate: `cargo test -p <package>`
