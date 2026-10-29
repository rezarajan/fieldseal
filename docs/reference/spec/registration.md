# Registration

**Prefix:** `REG` · **Kinds:** `RegistrationToken`, `RegistrationRequest`, `TenancyCertificate`, `CloseCertificate` · **apiVersion:** `fieldseal.dev/v1alpha1` · **Status:** Draft

## 1. Scope

**Owns:**
- binding a tenancy's device keys to a collector's account at the factory: accounts, devices and tenancies as the factory knows them;
- registration tokens, registration requests, proof of possession and fingerprint words;
- tenancy certificates;
- multi-device management, batch tokens and the air-gapped route;
- key roll, revocation and deny-list cutoffs;
- close and reset certificates;
- authentication of the runtime to factory APIs after registration;
- posture re-checks.

**Does not own:**
- how people sign in, which is the identity provider behind an adapter;
- what a device does with its keys ([Collection](./collection.md));
- attestation evidence formats ([Platform profiles](./platform-profiles.md), [Trust](./trust.md));
- bundles ([Distribution](./distribution.md));
- byte encodings (WIRE §registration-messages, WIRE §certificates).

## 2. Domain model

| Element | Type | Meaning |
|---|---|---|
| `Account` | Aggregate root | A collector or operator known to the factory, keyed by the identity provider's stable subject identifier. Holds roles and the list of devices. |
| `RegisteredDevice` | Entity (in `Account`) | A device as the factory knows it: a nickname, fingerprint words, the attested hardware identity if any, its tenancies, its state. |
| `Tenancy` | Aggregate root | One collector, one device, one window. Holds the registered keys (with history), the window, cohort assignments, state and cutoff, and the profile its runtime reported at registration (REG-091). |
| `TenancyId` | Value object | `sha256` of the tenancy's first signing public key (WIRE §identifiers). |
| `RegisteredKey` | Entity (in `Tenancy`) | A signing or agreement public key, with its attestation evidence, verification result, validity and state (`active`, `rolled`, `revoked`). |
| `RegistrationToken` | Value object | Single-use, short-lived, bound to an account; carries factory URL, trust-root fingerprint, token secret and factory nonce. |
| `RegistrationRequest` | Value object | Public keys, attestation evidence, proof of possession, the runtime's reported profile (instrument-schema version and, when it has one, UI reference-catalogue version), previous-tenancy reference; sealed to the factory. |
| `FingerprintWords` | Value object | Four words from a 2048-word list, derived from the request body. |
| `TenancyCertificate` | Value object | The factory's signed statement of a registered tenancy: keys, window, cohorts with generations, record-key certificate. |
| `CloseCertificate` | Value object | The factory's signed instruction to close a tenancy, with `cutoff_seq` and a reason (`absent`, `forgotten-pin`, `returned`, `lost`, `other`). |
| `PostureReport` | Value object | Fresh evidence from a registered device: proof of possession over a factory nonce, platform state, the `DevicePolicy` mode and `effectiveRestrictions()` result. |

**States of a `Tenancy`:**
- `pending`: the request has been received and is awaiting the collector's confirmation;
- `held`: a policy check failed and the request awaits an operator;
- `registered`;
- `flagged`: a posture or anomaly finding;
- `lost`;
- `closing`;
- `closed`;
- `retired`.

**Domain events:**
- `TokenIssued`, `RequestReceived`, `FingerprintConfirmed`, `TenancyRegistered`, `RegistrationHeld`;
- `KeyRolled`, `DeviceMarkedLost`, `DeviceRetired`;
- `CloseCertificateIssued`, `PostureChecked`, `PostureFlagged`.

**Invariants:**
- A token registers at most one tenancy.
- A tenancy belongs to exactly one account and one device.
- At most one tenancy per device is in `registered` or `flagged` state.
- Keys are never deleted from history.

## 3. Driving ports

| Port | Caller | Input | Output | Errors |
|---|---|---|---|---|
| `IssueToken` | Portal (signed-in collector or operator) | Account, route (`online` or `air-gapped`), batch size (operators only) | `RegistrationToken` | `PolicyDenied`, `DeviceLimitReached` |
| `SubmitRequest` | Runtime, or portal upload | `RegistrationRequest` | `pending` tenancy and fingerprint words | `TokenInvalid`, `TokenExpired`, `TokenUsed`, `EvidenceRejected`, `ProofInvalid` |
| `ConfirmFingerprint` | Portal (same account) | Tenancy, confirmation | Registered, or held, tenancy | `NotPending` |
| `ApproveHeld` / `RejectHeld` | Portal (operator) | Tenancy, reason | Registered or rejected tenancy | `NotHeld` |
| `GetCertificate` | Runtime | Proof-of-possession token | `TenancyCertificate` | `NotRegistered` |
| `RollKey` | Runtime (with a token from the portal) | New key, evidence, signature by the current key | Updated tenancy | as `SubmitRequest` |
| `ListDevices` | Portal | Account | Devices with words, state, last seen | — |
| `MarkLost` / `Retire` | Portal (collector) or operator | Device | Cutoff set, tenancy state changed | — |
| `IssueCloseCertificate` | Operator, or policy on `MarkLost` | Tenancy, reason | `CloseCertificate` | — |
| `CheckPosture` | Runtime, when online | `PostureReport` | `ok` or `flagged` | `ProofInvalid` |
| `IssueApiToken` | Runtime | Proof of possession over a factory nonce | Short-lived token bound to the signing key | `NotRegistered`, `Revoked` |

## 4. Driven ports

| Port | Contract |
|---|---|
| `IdentityProvider` | Authenticates people at the portal and returns a stable subject identifier, the authentication methods used, and roles. MUST report whether a phishing-resistant method was used. Example adapters: OIDC (Entra ID, Keycloak). The runtime never uses this port. |
| `AttestationVerifier` | Verifies attestation evidence for a platform profile and returns normalised claims: hardware level, key origin, purposes, auth binding, app identity and version, OS patch level, boot state, challenge, optional hardware identity. MUST fail closed. One adapter per platform profile ([Platform profiles](./platform-profiles.md)). |
| `PolicyEngine` | Evaluates factory policy for each decision and returns the verdict with the policy content address. MUST be deterministic for the same inputs. |
| `RegistryStore` | Durable storage for accounts, tenancies and keys. MUST support atomic single-use token consumption. |
| `Signer` | Signs certificates with the factory registration key, through the HSM or KMS. Keys never leave it. |
| `Unsealer` | Opens requests sealed to the factory registration key, through the HSM or KMS. |
| `NonceSource` | Cryptographically random nonces, at least 128 bits. |
| `Notifier` | Optional. Shows events in the portal's device list. MUST NOT be required for any security property. |

## 5. Requirements

### 5.1 Identity and tokens

- **REG-001** The runtime MUST NOT contain or use any identity-provider client, client identifier, tenant setting or identity-provider token.
- **REG-002** The portal MUST authenticate collectors through the `IdentityProvider` port. Factory policy MUST be able to require a phishing-resistant method (for example passkeys); the default deployment policy MUST require it.
- **REG-002a** An `IdentityProvider` adapter MUST obtain the authentication methods it reports (REG-002) from the identity provider's own assertion (for example the `amr` and `acr` claims), never from configuration. An identity broker between the portal and the identity provider MAY be used only if it passes these claims through unchanged; otherwise the adapter MUST report the method as `asserted`, and factory policy MUST explicitly accept `asserted` methods (`factory.registration.acceptAssertedAuthMethods`) before any registration relies on one, recording it on the registration. A deployment MAY name, per issuer, extra `amr` or `acr` values that the issuer uses to mean phishing-resistant (the built-in set stays the default); that widens only what a token's own claims can say, and a token with none of those claims is never taken to be phishing-resistant.
- **REG-003** A registration token MUST be issued only to a signed-in account, through the portal.
- **REG-004** A token MUST carry the factory URL, the fingerprint of the trust root the device must accept, a token secret of at least 128 bits, a factory nonce of at least 128 bits and the route (WIRE §registration-messages). The factory MUST record the token's expiry with it and show it on the portal; the expiry is not in the token's bytes, because only the factory evaluates it (REG-006, WIRE-124).
- **REG-005** A token MUST be single use: the factory MUST consume it atomically when a request is accepted, and MUST reject any later request with it.
- **REG-006** Token expiry MUST be evaluated by the factory on its own clock when the request arrives, never by the device. Lifetimes are factory policy (`factory.registration.tokenTtl`, `factory.registration.airGappedTokenTtl`).
- **REG-007** The portal MUST show the token as a QR code and as text, and MUST warn the collector not to share it.

### 5.2 Registration request

- **REG-010** On reading a token, the runtime MUST check that the token's trust-root fingerprint is in its trust bundle, and MUST refuse the token otherwise.
- **REG-011** The runtime MUST use the token's factory nonce as the attestation challenge when it creates keys for this registration. When registering keys that already exist, it MUST include their original evidence and a proof of possession over the nonce.
- **REG-012** A request MUST contain:
  - the tenancy's signing and agreement public keys;
  - attestation evidence for each key;
  - a proof of possession: the signing key's signature over the domain-tagged nonce and request body;
  - the runtime's supported instrument-schema and policy-schema versions;
  - the previous tenancy on this device, if any;
  - the token secret.
- **REG-013** The whole request MUST be sealed to the factory's registration key (WIRE §registration-messages), so a relaying device or file carrier cannot read or alter it.
- **REG-014** The factory MUST verify, in order:
  1. the token (valid, unused, unexpired);
  2. the proof of possession;
  3. the attestation evidence, through `AttestationVerifier`;
  4. policy, through `PolicyEngine`.

  Any failure MUST stop processing. Steps 1–3 MUST fail with a specific error; step 4 MUST either deny or hold.
- **REG-015** Policy MUST be able to require, for every key:
  - a minimum hardware level;
  - generated origin;
  - the expected purposes;
  - authentication or unlock binding;
  - an accepted app identity and version range;
  - a minimum OS patch level;
  - a verified boot state;
  - a matching challenge.
- **REG-016** A hardware-identity check against a fleet registry MUST be a policy option: `off`, `optional` (flag on mismatch) or `required` (hold on mismatch).
- **REG-017** Keys whose evidence shows no hardware backing (including software keys from `fieldseal device simulate`) MUST be rejected unless a non-production policy explicitly allows them, and MUST NOT be allowed by any policy whose deployment is marked production ([Deployment](./deployment.md)).

### 5.3 Fingerprint words and confirmation

- **REG-020** Fingerprint words MUST be four words from a fixed 2048-word list, derived from `SHA-256` of the request body (WIRE §fingerprint-words), and shown both by the runtime and by the portal.
- **REG-021** A received request MUST stay `pending` until the same account confirms its fingerprint words on the portal. The portal MUST show the words and ask the collector to compare them with the device.
- **REG-022** A pending request MUST expire if not confirmed within the token's lifetime.
- **REG-023** The word list MUST be the one fixed by WIRE §fingerprint-words, whatever the display language of the runtime or portal. Both MUST also show each word's index (0–2047) as a number, so collectors who cannot read the list's script can compare indices ([ADR 0034](../../explanation/adr/0034-internationalisation-and-localisation.md)).

### 5.4 Approval and certificates

- **REG-030** When every check passes and the fingerprint is confirmed, the factory MUST register the tenancy automatically, without operator action.
- **REG-031** A request that fails a policy check marked `hold` MUST go to the `held` state for an operator; one marked `deny` MUST be rejected with the reason shown on the portal.
- **REG-032** The factory MUST issue a `TenancyCertificate` signed by its registration key, containing:
  - tenancy ID;
  - account reference;
  - device reference;
  - agreement and signing public keys;
  - window (`not_before`, `not_after`, `grace`);
  - cohort assignments with their generations;
  - the record-key certificate for the collection period.
- **REG-032a** When a tenancy's cohort set changes, the factory MUST reissue its certificate from the tenancy record, sign it again, and store it in the record, so that `GetCertificate` returns it. The `serial` field stays the attested device serial.
- **REG-033** The runtime MUST verify a tenancy certificate's chain to its trust bundle before using it.

### 5.5 Multiple devices and batch tokens

- **REG-040** Each device MUST be registered with its own token, its own keys and its own tenancy.
- **REG-041** Limits MUST be factory policy, never hard-coded:
  - devices per account (`factory.registration.maxDevicesPerAccount`);
  - active tenancies per cohort (`factory.cohorts.maxActiveTenanciesPerCohort`);
  - tenancies per device.
- **REG-042** When an account is at its device limit, `IssueToken` MUST fail with `DeviceLimitReached`, and the portal MUST offer to retire a device.
- **REG-043** The portal MUST list an account's devices with nickname, fingerprint words, state, last seen, and the actions *roll keys*, *mark as lost* and *retire*.
- **REG-044** Policy MAY allow **batch tokens** for an operator role, valid for up to `factory.registration.batchTokens.maxUses` devices within `factory.registration.batchTokens.ttl`. Each device registered with a batch token MUST still create its own keys and tenancy, and MUST still be confirmed by fingerprint words, listed together for the operator. Batch tokens MUST NOT be issued to collector roles.
- **REG-046** The factory MUST keep survey-to-cohort assignments in its tenancy registry and change them only through `AssignCohort`. `AssignCohort` MUST require an `operator` account signed in by a phishing-resistant method, MUST name the account the assignment targets (the collector's bare OIDC subject, which the factory maps to the account id the identity provider adapter gives that person at sign-in, so the assignment reaches the tenancies they register; the subject MUST NOT be empty, longer than 255 bytes, or hold a control character, and MAY hold `|`; the account is created with no roles when it does not exist), MUST refuse an unknown survey or cohort, MUST record generation 1 for each cohort on each tenancy it reaches (DIS-014), and MUST NOT remove an assignment. An assignment MUST apply to the target account's tenancies, current and later, and to no other account's. The journal record MUST be written before the tenancies are updated, and a tenancy that is created or registered after the record is written MUST read it (and be issued a new certificate if it already holds one), so that no order of the two leaves a tenancy without the cohort. An identical assignment answers `unchanged` and writes no record. Each assignment MUST be journaled with the operator's account, roles and methods, the time and the change.
- **REG-047** The factory MUST accept a new roster version only through `IssueRoster`, with the same authentication, the DIS-063 check and the version rule of DIS-014, and MUST NOT remove a version. Each issue MUST be journaled with the operator's account, roles and methods, the time, and the cohort, version and content digest, never subject data. The roster store write comes before the journal record; issuing the same bytes again writes a missing record. The roster body MUST NOT be logged.
- **REG-045** Moving a cohort to another tenancy MUST record a succession with `generation + 1` ([Distribution](./distribution.md)).

### 5.6 Air-gapped route

- **REG-050** Every registration step MUST be possible without the device ever having a network connection.
- **REG-051** Messages under 300 bytes (tokens, close certificates, posture nonces) MUST be transferable as a single QR code shown on a screen.
- **REG-052** Registration requests MUST be transferable as a file. A runtime MAY also offer an animated QR sequence for them (WIRE §animated-qr).
- **REG-053** A request submitted out of the app MUST be accepted only through an upload by the account the token was issued to.
- **REG-054** An air-gapped registration's `TenancyCertificate` and bundles MUST be downloadable from the portal as files for import.

### 5.7 Key roll, loss and revocation

- **REG-060** A collector MAY roll a tenancy's keys at any time. A roll MUST use a fresh token from the portal; the new key's evidence MUST use that token's nonce; the request MUST also be signed by the current signing key.
- **REG-061** A rolled key MUST be kept in the tenancy's key history as `rolled`, so records it signed still verify at intake.
- **REG-062** *Mark as lost* MUST set the tenancy's **cutoff** to the highest `seq` the authority has received, mark the device `lost`, and issue a close certificate.
- **REG-063** Revocation MUST NOT depend on the device receiving anything. Intake enforces cutoffs from the registry ([Intake](./intake.md)).
- **REG-064** A close certificate MUST contain the tenancy ID, `cutoff_seq`, reason and issue time, signed by the factory registration key. It MUST be deliverable as a QR code, a file or by API.
- **REG-065** A forgotten runtime PIN MUST be handled with a close certificate with reason `forgotten-pin` ([Collection](./collection.md)).

### 5.8 After registration

- **REG-070** The runtime MUST authenticate to factory and upload APIs with short-lived tokens bound to its signing key (proof-of-possession, for example DPoP per RFC 9449), obtained through `IssueApiToken`.
- **REG-070a** Operator API routes MUST authenticate an `Authorization: Bearer` JWT access token (RFC 9068 profile) from the configured identity provider, and MUST verify its signature (`RS256` or `ES256` only), issuer, audience (the factory API identifier), expiry (`iat` and `nbf` too, with clock leeway), a non-empty subject, the header `typ` (`at+jwt`; a plain `JWT` only when the deployment accepts it, and then only with the payload `typ: Bearer`), the absence of a `nonce` claim (only ID tokens carry one), the client (`client_id`, or `azp` when `client_id` is absent, is the operator CLI's public client), the `operator` role and a phishing-resistant sign-in method. The roles and the authentication methods MUST be read from the access token and from no other source, and a token MUST NOT be cached.
- **REG-071** When online, the runtime SHOULD perform a posture re-check at the interval set by runtime policy. The factory MUST evaluate the result by policy.
- **REG-072** A failed posture check MUST flag the tenancy and pause new bundle releases ([Distribution](./distribution.md)). It MUST NOT block collection, sealing or delivery.

### 5.9 Attack analysis

| Attack | Defence | Requirements |
|---|---|---|
| **Code phishing:** an attacker gets a collector to enter a code that the attacker's device produced | There is no such code: tokens flow from the signed-in collector to the device. An attacker would need a token from the collector's own portal. | REG-001, REG-003, REG-007 |
| **Token theft:** the collector is persuaded to share a token | Single use, short lifetime, and the fingerprint words on the portal won't match the collector's device | REG-005, REG-006, REG-021 |
| **Key substitution:** a relaying device or file carrier swaps keys | The request is sealed to the factory, and the proof of possession covers the body | REG-012, REG-013 |
| **Replay of an old request** | Token consumed; nonce bound into attestation and proof of possession | REG-005, REG-011 |
| **Emulated or modified runtime** | Attestation evidence checked against policy | REG-014, REG-015, REG-017 |
| **Account takeover** | Phishing-resistant sign-in; device limit; device list with mark as lost; optional hardware-identity check | REG-002, REG-016, REG-041, REG-043 |
| **Lost or stolen device** | Cutoff and close certificate, enforced at intake | REG-062, REG-063 |
| **Stolen API token** | Bound to the signing key | REG-070 |

### Device-policy posture ([ADR 0031](../../explanation/adr/0031-device-management-adapters.md))

- **REG-080** A posture report MUST carry the device's `DevicePolicy` mode and its effective restrictions (PLAT-042).
- **REG-081** The factory MUST evaluate the report at decision point `posture.recheck`; for any required restriction reported `missing`, or `unknown` when policy `posture.unknownRestriction` is `flag`, it MUST flag the tenancy and MUST pause new bundle releases to it until a clean report arrives.
- **REG-082** A flag MUST NOT revoke the tenancy or affect intake of its records.

### Closed schemas

- **REG-090** Every reader of a Registration input (token, request body and sealed plaintext, request file, tenancy certificate, close and reset certificate, posture report, and the token and account records the CLI persists) MUST reject unknown fields, enforce exact types and enumerations, and enforce every declared constraint: required fields, fixed byte lengths, the factory URL form and size (WIRE-121), non-empty evidence with one entry per key kind and a named format, a non-empty build, a tenancy ID equal to the SHA-256 of the signing key (WIRE-131), at least one certified key with unique indices, a window that does not end before it starts, unique cohorts, restriction states from the closed set, and no bytes after the structure. A malformed input is refused with its WIRE code; it is never partly read. Documents whose format a third party owns and defines as open (OpenID Connect discovery and key-set documents, ID-token claims) are the one exception to the unknown-field rule: the adapter reads the members it needs by name, requires each to have its exact type (a malformed `aud`, `iat`, `exp`, `azp`, `acr`, `amr` or role claim, or a non-string `alg` or `kid`, or a `crit` header, is refused rather than skipped), and ignores the rest. The adapter's own pending-sign-in record is closed.

### Reported runtime profile

- **REG-091** (provisional) The factory MUST record the instrument-schema version and the reference-catalogue version (if any) of a registration request with the tenancy, in the tenancy registry journal, and MUST NOT accept them from any other source. A key roll replaces the recorded profile with the one in the roll request, which the new key and the current key have both signed; a roll that carries no valid profile is refused as malformed (WIRE-130). Because the replacement may be lower as well as higher, a runtime that was downgraded narrows what the tenancy receives and never widens it (DIS-012). The request body change is a signed-content change (WIRE-130, WIRE-132) and was reviewed as such (SR-1).

### Portal sessions

- **REG-092** (provisional) Portal sessions and CSRF. A portal session MUST be kept in a cookie that is `HttpOnly`, `SameSite=Lax` and, when the portal's public URL is https, `Secure`. Session identifiers and CSRF tokens MUST come from the operating system's CSPRNG. Each session MUST have its own CSRF token, and every state-changing portal request MUST carry it. Signing out MUST end the session. A pending sign-in MUST be usable once.

### Development custody and durable state

- **REG-083** A factory MUST NOT lose what it has registered across a restart: tokens (and how many uses of each are spent), accounts, tenancies, devices, nonces and access tokens survive it. A deployment that keeps them in memory is a development deployment. The `RegistryStore` adapter that keeps them in a journal on local disk (`file-dev`, environment `FIELDSEAL_STATE_DIR`) is a development adapter and MUST be refused in an environment marked production (REG-017, DEP-023); replaying the journal MUST give the store it recorded.
- **REG-084** A factory's authority MUST be configurable rather than generated at start-up when it has to outlive the process: the `KeyCustody` adapter `file-dev` (environment `FIELDSEAL_CUSTODY=file-dev`, `FIELDSEAL_CUSTODY_DIR`, `FIELDSEAL_TRUST_BUNDLE`) loads the `registration` keys from a key directory and the trust bundle from a file, so one authority can serve the factory, the upload endpoint and the CLI. It is development custody (software keys, unattested, CLI-007, CLI-019) and MUST be refused in production; `memory-dev` remains for tests.

### Service contract and transports ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md))

*gRPC is built in slice 2; the HTTP routes below are built.*

- **REG-085** The factory's registration operations are the `Factory` contract (`fieldseal.v1.Factory`), defined once; HTTP is a mapping of it, and an adapter MUST NOT offer an operation the contract lacks. Each payload is carried as opaque canonical CBOR `bytes` and MUST NOT be re-encoded (WIRE-196).

| rpc | HTTP | Authentication |
|---|---|---|
| `SubmitRegistration` | `POST /v1/registrations` | none (the sealed request proves possession) |
| `GetRegistrationStatus` | `GET /v1/registrations/{tenancy}` | none (state only) |
| `GetCertificate` | `GET /v1/certificate` | PoP |
| `IssueApiToken` | `POST /v1/api-token` | PoP |
| `PostureNonce` | `POST /v1/posture/nonce` | PoP |
| `CheckPosture` | `POST /v1/posture` | PoP |
| `IssueRoster` | `POST /v1/rosters` | operator Bearer access token (REG-070a) |
| `AssignCohort` | `POST /v1/assignments` | operator Bearer access token |
| `ListAssignments` | `GET /v1/assignments` | operator Bearer access token |

- **REG-086** The portal pages, sign-in and the identity-provider flow (REG-002, REG-002a) MUST be served over HTTP only; they are not part of the `Factory` contract.

- **REG-087** The `Factory` contract suite MUST be one table of cases (operation, request, expected outcome and error class) executed through every transport adapter against the same in-memory factory, and a transport is not complete until every row passes through it. Built in slice 2.

## 6. Resources and formats

Authoring and display forms only; bytes are in WIRE §registration-messages and WIRE §certificates.

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: RegistrationToken
spec:
  factory: https://factory.example.org
  trustRoot: sha256:9f2c…
  route: air-gapped
  expires: 2026-11-02T10:00:00Z
  nonce: base64url…
  secret: base64url…
```

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: TenancyCertificate
spec:
  tenancy: sha256:41ab…
  account: acct:7f3e…
  device: dev:c09d…
  keys:
    signing: { alg: ES256, public: base64url… }
    agreement: { alg: P256-HPKE, public: base64url… }
  window: { notBefore: 2026-11-01, notAfter: 2026-12-15, grace: 30d }
  cohorts: [{ id: cohort:12a, generation: 1 }]
  recordKey: sha256:5d0e…
```

## 7. Twelve-factor

- **Config (III):** factory URL, identity-provider settings, HSM key references and token lifetimes come from the environment and factory policy. The runtime's factory URL and trust root come from the token and its trust bundle, never from the build.
- **Backing services (IV):** the identity provider, HSM or KMS, registry store and policy engine are attached resources behind ports.
- **Processes (VI):** factory processes are stateless. Pending and registered state lives in `RegistryStore`.
- **Disposability (IX):** token consumption and registration are idempotent and atomic. A retried request returns the existing result.
- **Logs (XI):** registration events go to the event stream with account and tenancy references, never personal data beyond the account reference.
- **Admin processes (XII):** operator actions (`approve`, close certificates, batch tokens) are available as `fieldseal registration` commands against the same release.
- **Port binding (VII), on device:** the runtime never listens. All registration traffic is outbound or by file.

## 8. Conformance

| Test | Requirements | Command |
|---|---|---|
| Token fields, single use, factory-side expiry | REG-004–REG-006 | `fieldseal registration token`, `fieldseal conformance run --suite reg-token` |
| Request contents and sealing | REG-011–REG-013 | `fieldseal registration request`, `fieldseal registration inspect` |
| Verification order and fail-closed | REG-014, REG-015, REG-017 | `fieldseal conformance run --suite reg-verify` with tampered fixtures |
| Fingerprint words match on both sides | REG-020, REG-021 | `fieldseal registration inspect --words`, `fieldseal device simulate` |
| Automatic approval and held path | REG-030, REG-031 | `fieldseal registration approve` |
| Certificate chain | REG-032, REG-033 | `fieldseal trust verify` |
| Device limits and batch tokens by policy | REG-041–REG-044 | `fieldseal policy evaluate` over registration scenarios |
| Air-gapped round trip | REG-050–REG-054 | `fieldseal device simulate --air-gapped` |
| Roll, lost, close certificate, cutoff | REG-060–REG-065 | `fieldseal keys roll`, `fieldseal conformance run --suite reg-revoke` |
| Attack scenarios in §5.9 | as listed | `fieldseal conformance run --suite reg-attacks` |
| Factory contract table (REG-085) passes through the HTTP and gRPC adapters | REG-085, REG-087 | `fieldseal conformance run --suite service-contracts --service factory` |
| Identity-provider adapter contract | REG-002 | Adapter contract tests in the port's suite |
| Closed schemas: unknown field, wrong type, broken constraint, missing field, valid input | REG-090 | `cargo test -p fieldseal-registration --test strict` |
| Reported profile recorded as signed; a changed profile breaks the proof; unknown keys and over-long values refused | REG-091, WIRE-130 | `cargo test -p fieldseal-security-tests --test registration_profile`, `cargo test -p fieldseal-registration --test vectors` |
| Portal sessions: cookie attributes, per-session CSRF token, sign-out, single-use pending sign-in | REG-092 | `cargo test -p fieldseal-adapters-factory-http --test portal_session`, `cargo test -p fieldseal-adapters-portal` |

## 9. Open questions

1. Should fingerprint confirmation be skippable by policy for batch tokens on an operator's bench, where the operator sees every device?
2. Default lifetimes: 10 minutes online and 24 hours air-gapped, or longer for the air-gapped route?
3. Should posture re-check failures above a severity automatically issue a close certificate, or always wait for an operator?

## 10. References

- [ADR 0007](../../explanation/adr/0007-zero-trust-posture.md), [ADR 0008](../../explanation/adr/0008-trust-hierarchy.md), [ADR 0011](../../explanation/adr/0011-policy-as-signed-files.md), [ADR 0012](../../explanation/adr/0012-local-first-device-keys.md), [ADR 0013](../../explanation/adr/0013-registration-via-authority-tokens.md), [ADR 0014](../../explanation/adr/0014-multi-device-and-air-gapped.md), [ADR 0016](../../explanation/adr/0016-tenancies-with-crypto-erase.md), [ADR 0024](../../explanation/adr/0024-platform-profiles.md), [ADR 0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- [Wire formats](./wire-formats.md), [Trust](./trust.md), [Policy](./policy.md), [Distribution](./distribution.md), [Collection](./collection.md), [Intake](./intake.md), [Platform profiles](./platform-profiles.md)
- RFC 9449 (DPoP); NIST SP 800-63B-4 (phishing-resistant authenticators)
