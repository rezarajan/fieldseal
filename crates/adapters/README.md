# adapters

## Overview

Implementations of the driven ports declared by [`crates/contexts`](../contexts/README.md), plus driving adapters (HTTP servers, renderers) that call context use cases. Adapters may depend on the kernel, the contexts and other adapters, never on bindings or apps ([ADR 0028](../../docs/explanation/adr/0028-clean-architecture.md)). For example, `file` and `landing-files` build on `memory`, `upload-http` on `memory`, `file` and `landing-files`, and `web-demo` on `factory-http` and `upload-http`. Real I/O (filesystem, network, child processes, OS randomness) lives here. Several adapters are development-only and say so in their own contracts.

## Subdirectories & Boundaries

- attestation: [./attestation/README.md](./attestation/README.md) - TPM 2.0 key-certification `AttestationVerifier`, which verifies offline against trust-bundle roots. Pure: time and revocation are injected.
- authoring: [./authoring/README.md](./authoring/README.md) - Strict YAML/JSON authoring-document decoder to the kernel `Value`, and compact-dialect expansion with gettext catalogues.
- factory-http: [./factory-http/README.md](./factory-http/README.md) - Registration HTTP API and server-rendered portal (sessions, CSRF), plus a blocking client.
- file: [./file/README.md](./file/README.md) - Development-only file-backed custody, registry store, tenancy view, roster history, submission store and instrument source.
- html: [./html/README.md](./html/README.md) - Deterministic, self-contained HTML renderer for instrument render plans (inline assets, CSP hashes, embedded fonts).
- landing-files: [./landing-files/README.md](./landing-files/README.md) - File-based Intake `DataPlatform` that writes CSV observations, findings and losses, and JSON data contracts.
- memory: [./memory/README.md](./memory/README.md) - Deterministic in-memory adapters for every driven port, simulated authorities and devices, and the conformance contract-case catalogue.
- oidc: [./oidc/README.md](./oidc/README.md) - OIDC (auth code + PKCE) `IdentityProvider`; verifies RS256/ES256 ID tokens against the issuer's JWKS.
- opa: [./opa/README.md](./opa/README.md) - Open Policy Agent `PolicyEngine` via `opa eval` or REST, with bundled Rego mirroring the built-in engine. Fails closed.
- policy: [./policy/README.md](./policy/README.md) - Registry- and bundle-backed `PolicySource`, and a file-backed hash-chained `DecisionLog`.
- portal: [./portal/README.md](./portal/README.md) - Portal sessions shared by the HTTP apps: session store, pending sign-ins, session cookie, CSRF check, and the framework-free HTTP request and response types.
- rekor: [./rekor/README.md](./rekor/README.md) - Sigstore Rekor `TransparencyLog` (hashedrekord entries) over HTTP; checks every answer it gets.
- translog: [./translog/README.md](./translog/README.md) - Self-hosted RFC 9162 Merkle log store, HTTP client and server handler (the binary is [`crates/apps/translog`](../apps/translog/README.md)).
- upload-http: [./upload-http/README.md](./upload-http/README.md) - Runtime `UploadTransport` client, the Intake upload HTTP server, and the development `fieldseal-upload-server` binary.
- web: [./web/README.md](./web/README.md) - Development-only web platform profile: `WebDevice`, browser storage, key, clock and download ports, and the instrument workbench.
- web-demo: [./web-demo/README.md](./web-demo/README.md) - Development-only in-memory demo authority (factory portal and upload endpoint) for the showcase web app.
