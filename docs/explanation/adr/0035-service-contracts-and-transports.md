# ADR 0035: Service contracts and transports

**Status:** Accepted (2026-10-27) · **Priority:** Should · **Date:** 2026-10-27

**In one line:** Define each service's bounded operation set once as a protobuf contract, carry canonical CBOR as opaque bytes, and let HTTP and gRPC be two adapters of the same contract, chosen by URL scheme and held to one conformance suite.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The factory, the upload endpoint and the transparency log each expose a small, known, bounded set of operations. Today those operations exist only as HTTP routes documented in adapter comments (`factory-http`, `upload-http`, `translog`) and in the registration, delivery and publishing specs. The `fieldseal` CLI is gaining client ports for them, with HTTP as the first adapter. Operators have asked that the CLI support HTTP and/or gRPC, because the functionality is known and bounded and the services are Fieldseal's own.

Without a single definition, a second transport would restate each operation by hand, and the two could drift. The payloads are the harder constraint: signatures, content addresses and PoP tokens are computed over canonical CBOR ([wire-formats](../../reference/spec/wire-formats.md)), so any transport that re-encodes a payload breaks verification. The decision must add a transport without adding a second source of truth for bytes, and without letting a framework type into a pure context ([ADR 0028](./0028-clean-architecture.md)).

## Decision

- **One contract per service, defined once.** Each service's operations MUST be defined in a protobuf file under one directory, `contracts/proto/fieldseal/v1/{factory,upload,translog}.proto`. The contract is the list of operations, their request and response envelopes and their error cases. It is unary only.
- **HTTP is a mapping of the contract.** The existing HTTP routes stay as they are; the specs MUST carry a table mapping each rpc to its method and path, and an HTTP adapter MUST NOT offer an operation the contract lacks.

| Service | rpc | HTTP | Authentication |
|---|---|---|---|
| `Factory` | `SubmitRegistration` | `POST /v1/registrations` | none (the sealed request proves possession) |
| `Factory` | `GetRegistrationStatus` | `GET /v1/registrations/{tenancy}` | none (state only) |
| `Factory` | `GetCertificate` | `GET /v1/certificate` | PoP |
| `Factory` | `IssueApiToken` | `POST /v1/api-token` | PoP |
| `Factory` | `PostureNonce` | `POST /v1/posture/nonce` | PoP |
| `Factory` | `CheckPosture` | `POST /v1/posture` | PoP |
| `Factory` | `IssueRoster` | `POST /v1/rosters` | operator Bearer access token |
| `Factory` | `AssignCohort` | `POST /v1/assignments` | operator Bearer access token |
| `Factory` | `ListAssignments` | `GET /v1/assignments` | operator Bearer access token |
| `Upload` | `Challenge` | `POST /v1/challenge` | none |
| `Upload` | `Upload` | `POST /v1/upload` | PoP |
| `Upload` | `UploadOutbox` | `POST /v1/upload/outbox` | none (closing manifests are verified) |
| `TransLog` | `AddEntry` | `POST /append` | none |
| `TransLog` | `GetCheckpoint` | `GET /checkpoint` | none |
| `TransLog` | `GetInclusionProof` | `GET /inclusion/{leaf_index}/{tree_size}` | none |
| `TransLog` | `GetConsistencyProof` | `GET /consistency/{old_size}/{new_size}` | none |

  The portal pages, sign-in and the OIDC flow served by the factory are a browser flow ([REG-002](../../reference/spec/registration.md)) and MUST stay HTTP only. They are not part of the contract. The log's HTTP routes are the ones the Fieldseal log adapter speaks; a public log such as Rekor keeps its own API behind its own adapter ([ADR 0030](./0030-public-transparency-log.md)) and is not described by this contract.
- **Payloads stay canonical CBOR, as opaque `bytes`.** Each request and response envelope carries its payload as a `bytes` field holding the exact CBOR the HTTP body carries today (the sealed registration request, the challenge and its answer, the export file, the receipts, the log entry, the checkpoint note and proofs). Protobuf is only the envelope. Servers and clients MUST pass these bytes through unchanged and MUST verify signatures over them, never over a re-encoding. Hashes, content addresses, signatures and the golden vectors are therefore identical on both transports.
- **gRPC through tonic and prost.** The gRPC adapters MUST use `tonic` and `prost`, with `protoc` supplied by Nix: the flake dev shell and the crane build inputs both provide it, so builds stay hermetic and `--locked`. Code generation runs at build time in one dedicated crate, `crates/adapters/contracts`, that holds the generated types and nothing else. Contexts, the kernel and the CLI app layer MUST NOT depend on it or on `tonic`; only the gRPC adapters and the composition roots do. `tools/check-architecture.py` MUST enforce this.
- **Authentication is the same token, in metadata.** The Fieldseal-PoP token (WIRE-170) MUST travel as the `fieldseal-pop` gRPC metadata entry and as the `Fieldseal-PoP` HTTP header, in the same encoding. WIRE-170 binds a token to a method and a URL. For gRPC the bound `method` is `POST` (the HTTP/2 method gRPC always uses) and the bound `url` is `https://<authority>/<package>.<Service>/<Method>`, for example `https://factory.example/fieldseal.v1.Factory/GetCertificate`, where the authority is the one the client dialled. The server accepts a base authority only from its configured set, as with HTTP (DEL-066). No new token format is introduced; a token minted for one transport and operation is invalid for any other.
- **Transport security.** `grpcs://` means TLS, `grpc://` means plaintext. As with HTTP today, TLS SHOULD be terminated in front of the service (a gateway or mesh that speaks HTTP/2), and a server MAY terminate it itself with tonic's rustls support when configured with a certificate reference. A client MUST use rustls with the platform or configured roots. TLS never replaces PoP, receiver-key proofs or sealed payloads (ADR 0007); the transport is untrusted either way.
- **Health and reflection.** Each gRPC listener MUST implement `grpc.health.v1.Health`, reporting liveness and readiness with the same meaning as `GET /healthz` and `GET /readyz`, which stay. The reflection service MUST be available only when the deployment is configured as development and MUST be off by default and in production.
- **Error mapping.** Failures map one to one, and the existing JSON error body maps to a `google.rpc.Status` detail carrying the same stage, code and message (no personal data):

| HTTP | gRPC status | Meaning |
|---|---|---|
| `400` | `INVALID_ARGUMENT` | malformed |
| `401` | `UNAUTHENTICATED` | token refused (DEL-003) |
| `403` | `PERMISSION_DENIED` | authenticated but not allowed |
| `404` | `NOT_FOUND` | no such tenancy, leaf or size |
| `405` | `UNIMPLEMENTED` | operation not in the contract |
| `409` | `ALREADY_EXISTS` or `FAILED_PRECONDITION` | replay or state conflict |
| `413` | `RESOURCE_EXHAUSTED` | message over the limit |
| `422` | `FAILED_PRECONDITION` | the gate refused the body; detail names stage and code |
| `429` | `RESOURCE_EXHAUSTED` | rate limited |
| `503` | `UNAVAILABLE` | a backing service failed; retry (DEL-005) |
| `504` | `DEADLINE_EXCEEDED` | timeout |

- **Limits, timeouts, idempotency, streaming.** The maximum message size on gRPC MUST equal the HTTP body limit for the same operation, set explicitly (tonic's default is not relied on). Every client call MUST carry a deadline (`grpc-timeout` or the HTTP client timeout), with the CLI default configurable by flag. Retry rules are unchanged: operations already idempotent (receipts, `jti` replay protection) stay so, and a client MAY retry only on `UNAVAILABLE` or `DEADLINE_EXCEEDED`. There is no streaming now; upload remains one unary call of one export file. Streaming would need a new contract version.
- **Client ports in the CLI app layer; adapters per transport (built in slice 1).** The CLI app layer declares transport-neutral client ports in `crates/apps/cli/src/clients.rs`: `FactoryClient` (submit a sealed request, read its status, fetch the certificate with a PoP token) and `UploadClient` (upload an export, receive receipts). The log commands use the Publishing context's `TransparencyLog` port. Ports take and return plain values and CBOR bytes, never HTTP or protobuf types; each transport is an adapter behind them (CLI-022).
- **Transport chosen by URL scheme (built in slice 1).** The scheme of the service URL selects the adapter, the same way for every command: `--factory-url` / `FIELDSEAL_FACTORY_URL`, `--to` / `FIELDSEAL_INTAKE_URL`, and `FIELDSEAL_TRANSLOG_URL` for the log (CLI-021). The scheme-dispatching functions `connect_factory` and `connect_upload` build `http://` and `https://`; `grpc://` and `grpcs://` are recognised and refused with exit `3` and a "not built" message, and an unknown scheme is refused with exit `3` (CLI-023). The log commands will refuse `grpc(s)://` the same way. Slice 2 replaces the refusal with the gRPC adapters without changing any command.
- **One conformance suite, two transports.** The contract tests MUST be a table of cases written once (operation, request, expected outcome and error class) and executed through each adapter against the same in-memory service. A new operation or transport is not done until its row passes on both. The golden CBOR vectors are transport independent and run unchanged.
- **Twelve-factor effects (ADR 0025).** Each service binds one HTTP port and, when enabled, one separate gRPC port (factor VII); both are configuration, not code. URLs are attached resources named in `FIELDSEAL_*_URL` variables. Compose files expose both ports for development. The CLI stays a stateless one-shot process whichever transport it uses.

## Alternatives considered

- **HTTP only.** Simplest, and already built. Rejected as the only path because the operation sets are bounded and internal, and a typed contract with generated clients and servers removes hand-kept route tables. HTTP remains fully supported.
- **gRPC only.** Rejected: browsers, simple `curl` debugging and existing gateways rely on HTTP, and the portal is HTTP regardless.
- **OpenAPI as the contract.** Describes HTTP well but not gRPC; a second contract language would be needed for the second transport.
- **Model payloads as proto messages.** Rejected. Protobuf serialisation is not canonical (field order, default omission and unknown fields vary between implementations), so re-encoding a signed payload would break signatures and content addresses; clients and servers would hold two definitions of every structure (the CBOR specs and the `.proto`), which would drift; and the golden vectors would have to be defined twice. Opaque `bytes` keeps one source of truth.
- **gRPC-Web or a gRPC-to-HTTP gateway only.** Adds a moving part for no gain over a native adapter, and hides which transport a deployment really runs.
- **A separate gRPC-only CLI.** Splits the reference implementation (ADR 0006); rejected.

## Consequences

- The operation sets are defined once; the HTTP routes and the gRPC services cannot silently diverge, and the conformance table catches any that do.
- Verification is unchanged on both transports because the signed bytes are never re-encoded.
- The build gains a Nix-supplied `protoc` and a generated-code crate; the architecture check gains a rule keeping them out of the inner layers.
- Two listeners per service in deployments that enable gRPC, with two sets of health checks to monitor.
- Error semantics must be kept in step by the mapping table; mismatches fail the shared suite.
- A contract change is a versioned change (`v1`, then `v2`), reviewed like a spec change.

## Risks and open questions

- **URL binding.** Binding the PoP URL to the service full method name is new wording for WIRE-170; a gateway that rewrites the authority would need its host listed in configuration. To confirm in review.
- **Tonic and prost versions** are a new supply-chain surface (ADR 0007); pin and lock them, and review `protoc` provenance in the Nix inputs.
- **Public log.** Whether a `grpc://` log is ever worth offering beyond the Fieldseal log adapter is open; the default answer is no.
- **Android.** The Android runtime SHOULD use gRPC when it is simple, through a gRPC client in the shared Rust core (tonic over rustls, compiled for the Android targets and exposed through the UniFFI binding behind the same client ports), so no Kotlin gRPC stack is added; HTTP stays the fallback. The runtime still opens no inbound listeners.

## Rollout

1. **Slice 1 (done):** transport-neutral client ports in the CLI app layer and the HTTP adapters for the factory, upload endpoint and log.
2. **Approval of this ADR.**
3. **Slice 2:** the contracts crate and `.proto` files, tonic servers beside the existing HTTP servers, the gRPC client adapters, scheme dispatch replacing the "transport not built" exit, health checks, the dual-transport conformance suite, and compose and Nix changes.
4. **Slice 3:** the Android binding exposes the Rust gRPC clients, done with the Android app (#51).

## Spec changes this implies

The slice 2 requirements below are now written into the specs (each notes that gRPC is built in slice 2).

- [cli](../../reference/spec/cli.md): already specified in slice 1 and not proposed here: transport chosen by URL scheme (CLI-021), transport-neutral client ports (CLI-022), unbuilt or unknown transport refused with exit `3` (CLI-023). Slice 2 only changes CLI-021 and CLI-023 to say `grpc://` and `grpcs://` are built, and adds the call deadline default and flag (CLI-028), with the gRPC client adapters (CLI-029).
- [registration](../../reference/spec/registration.md): rewrite the factory operations in transport-neutral wording and add the rpc-to-HTTP mapping table (REG-085); state that the portal and sign-in are HTTP only (REG-086).
- [delivery](../../reference/spec/delivery.md): same for challenge, upload and outbox (DEL-072); the PoP URL binding for gRPC (DEL-073); error mapping table (DEL-074).
- [publishing](../../reference/spec/publishing.md): transport-neutral log operations and the mapping table (PUB-110).
- [wire-formats](../../reference/spec/wire-formats.md): payloads are carried as opaque `bytes` and are never re-encoded (WIRE-196); `fieldseal-pop` metadata carries the WIRE-170 token and binds the full method name and authority (WIRE-197).
- [deployment](../../reference/spec/deployment.md): gRPC listener and port configuration, TLS options, `grpc.health.v1`, and reflection only in development (DEP-058, DEP-059, DEP-060).
- [platform-profiles](../../reference/spec/platform-profiles.md): an informative transports note, including Android over the Rust gRPC clients.
- Conformance sections of the registration, delivery and publishing specs: the dual-transport contract suite and its CLI command (REG-087, DEL-075, PUB-111).

## Specs

[cli](../../reference/spec/cli.md) · [registration](../../reference/spec/registration.md) · [delivery](../../reference/spec/delivery.md) · [publishing](../../reference/spec/publishing.md) · [wire-formats](../../reference/spec/wire-formats.md) · [deployment](../../reference/spec/deployment.md)
