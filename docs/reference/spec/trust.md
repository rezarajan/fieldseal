# Trust

**Prefix:** `TRU` · **Context:** Trust · **Status:** Draft · **ADRs:** [0007](../../explanation/adr/0007-zero-trust-posture.md), [0008](../../explanation/adr/0008-trust-hierarchy.md), [0012](../../explanation/adr/0012-local-first-device-keys.md), [0017](../../explanation/adr/0017-runtime-authentication.md), [0024](../../explanation/adr/0024-platform-profiles.md)

## 1. Scope

Trust owns who may sign or decrypt what: the authority's offline root, its purpose-tagged keys, collection-period record keys, trust bundles, revocation, attestation evidence and its verification, device key custody, and session key derivation.

It does not own *decisions* that use these facts (whether a registration is approved, whether a key's evidence is good enough): those are policy evaluations ([Policy](./policy.md)) made by [Registration](./registration.md) and [Intake](./intake.md). Byte layouts of signatures and seals are in [Wire formats](./wire-formats.md).

## 2. Domain model

| Element | Kind | Meaning |
|---|---|---|
| `Root` | Aggregate | An authority's offline root key, its custodians and its ceremony record |
| `PurposeKey` | Entity | An online authority key certified by the root for exactly one purpose, with a validity period |
| `Purpose` | Value object | One of the purposes in §6.1 |
| `KeyCertificate` | Value object | A root's signed statement binding a public key to a purpose and validity |
| `CollectionPeriod` | Entity | A named time span with its own record key; records are sealed to the period's key |
| `TrustBundle` | Aggregate, artefact | The roots, key certificates, attestation roots and revocations a component accepts |
| `Revocation` | Value object | A signed statement that a key or certificate is no longer valid, with an effective time |
| `DeviceKey` | Entity | A key generated in a device's secure key store for one tenancy: signing, agreement or storage |
| `AttestationEvidence` | Value object | Platform-specific bytes proving where and how a device key was created |
| `AttestationClaims` | Value object | The platform-neutral facts extracted from evidence (§6.3) |
| `Custody` | Value object | How an authority key's private part is held: an operating `mode` (`cold` or `hot`) and an `assurance` (`development`, `custody-bound` or `attested`) (§6.7). Kept in the authority's private issuance record, never in a certificate. |
| `IssuanceRecord` | Value object | The authority-private record of one issuance decision: key ID, purpose, mode, assurance, evidence digest and the policy layers (TRU-111). Held in the `DecisionLog`. |
| `SessionKey` | Value object | The key that encrypts a tenancy's local data, derived from a key-store secret and the runtime PIN |

Domain events: `RootInitialised`, `PurposeKeyIssued`, `PurposeKeyRotated`, `KeyRevoked`, `TrustBundleBuilt`, `DeviceKeyGenerated`, `DeviceKeyDeleted`, `EvidenceVerified`.

Invariants:
- A key has exactly one purpose.
- A root never signs anything except key certificates, trust bundles and revocations.
- A device private key never leaves its key store.

## 3. Driving ports

| Port | Used by | Input | Output |
|---|---|---|---|
| `InitRoot` | Operators (ceremony) | Custodian set, threshold | Root public key, ceremony record |
| `IssuePurposeKey` | Operators | Purpose, validity, public key from custody | Key certificate |
| `RotatePurposeKey` | Operators | Purpose | New certificate; old key's end of validity |
| `OpenCollectionPeriod` | Operators | Period name, start, end | Record key certificate |
| `Revoke` | Operators, Registration | Key or certificate ID, reason, effective time | Revocation |
| `BuildTrustBundle` | Operators, Publishing | Roots, certificates, attestation roots, revocations | `TrustBundle` artefact (published through [Publishing](./publishing.md)) |
| `VerifyChain` | Every context | Signer key ID, chain, purpose, time, trust bundle | Verdict |
| `VerifyEvidence` | Registration, Intake | `AttestationEvidence`, expected challenge, key | `AttestationClaims` or failure |
| `GenerateDeviceKeys` | Collection | Tenancy, challenge | Device keys and evidence |
| `DeriveSessionKey` | Collection | Runtime PIN, tenancy | Session key handle |

## 4. Driven ports

| Port | Contract every adapter MUST meet | Example adapters |
|---|---|---|
| `KeyHolderRegistry` | Private mapping of key IDs and reviewer IDs to people, for audit and revocation; access-controlled; never exported | Directory service, access-controlled database |
| `KeyCustody` | Generates authority keys inside a hardware boundary; signs and performs HPKE decapsulation without exporting private keys; logs every use with a caller identity; refuses a purpose other than the key's own | Cloud KMS, PKCS#11 HSM, offline signing workstation for the root |
| `SecureKeyStore` | On a device: generates non-exportable P-256 signing and agreement keys and AES-256 wrapping keys; signs, performs ECDH and unwraps only inside the store; enforces "usable only while the device is unlocked"; deletes keys irrecoverably on request | Android keystore, Apple Secure Enclave, TPM 2.0 |
| `Attestor` | On a device: produces `AttestationEvidence` for a key at creation, binding a supplied challenge | Android key attestation, Apple App Attest, TPM 2.0 quote |
| `AttestationVerifier` | At the factory or intake: verifies one evidence format against its platform roots and revocation source, and returns `AttestationClaims`; never returns claims it did not verify | One adapter per evidence format |
| `RevocationSource` | Returns the platform vendor's current revocation status for attestation certificates, with its retrieval time | Android attestation status list, vendor CRLs |
| `AuthorityClock` | Returns trusted authority time; used only by authority-side components | NTP-disciplined host clock |
| `RandomSource` | Cryptographically secure randomness | OS CSPRNG |

Every port MUST have a contract test suite and an in-memory or software adapter for tests. Software adapters MUST mark everything they produce as unattested (TRU-061).

## 5. Requirements

### 5.1 Root

- **TRU-001** Each authority MUST have exactly one active root key, P-256, generated and used only on an offline machine or in an HSM partition with no network path.
- **TRU-002** Root operations MUST require a threshold of custodians (default 2 of 3), recorded in a signed ceremony record.
- **TRU-003** The root MUST sign only key certificates, trust bundles and revocations.
- **TRU-004** A root's validity MUST NOT exceed 10 years. Replacing a root MUST be published as a trust bundle signed by both the old and new roots.

### 5.2 Purpose keys

- **TRU-010** Every online authority key MUST be certified by the root for exactly one purpose from §6.1.
- **TRU-011** A verifier MUST reject a signature by a key whose certificate's purpose doesn't match the domain tag's purpose ([Wire formats](./wire-formats.md) §6.1), with `E_SIG`.
- **TRU-012** Purpose-key validity MUST NOT exceed the limits in §6.1. A verifier MUST reject a signature whose signing time (the authority time in the signed structure, or the verifier's authority time for live checks) is outside the certificate's validity.
- **TRU-013** Purpose keys MUST be held in `KeyCustody`. Their private parts MUST NOT be exportable from it.
- **TRU-014** Certificate chains MUST have depth 1: root → purpose key. Verifiers MUST reject longer chains.
- **TRU-015** Rotating a purpose key MUST NOT invalidate signatures made within the old key's validity.
- **TRU-016** A certificate request for a P-256 key MUST carry that key's signature over the request without `sig`, under tag `fieldseal.dev/csr/v1` (proof of possession). `IssuePurposeKey` MUST refuse a P-256 request whose signature is missing or invalid, with `E_SIG`. A request for an X25519 key (a `record` key, or a `registration` key's agreement half) carries no signature, because the key can't sign: possession is proved at first use, when the key opens what is sealed to it.

### 5.3 Collection periods and record keys

- **TRU-020** Each collection period MUST have its own X25519 record key, certified for purpose `record` with the period's ID.
- **TRU-021** Records and export manifests for a tenancy MUST be sealed to the record key of the period named in its tenancy certificate.
- **TRU-022** A record key's private part MUST be usable only by intake through `KeyCustody`.
- **TRU-023** A record key MUST remain available for decryption for the deployment's retention period; it MUST NOT be destroyed while sealed data for its period may still arrive or be held.

### 5.4 Trust bundles

- **TRU-030** A trust bundle (`kind: TrustBundle`) MUST list: roots, purpose-key certificates, attestation roots per evidence format, accepted runtime build identities, and revocations.
- **TRU-031** A trust bundle MUST be signed by a root it lists and published as an artefact ([Publishing](./publishing.md)).
- **TRU-032** A runtime's initial trust bundle MUST come from device configuration at provisioning. It MUST NOT be compiled into the runtime build.
- **TRU-033** A component MUST accept a newer trust bundle only if it is signed by a root in the bundle it currently holds, and its version is higher.
- **TRU-034** A component MUST trust exactly the roots in its current trust bundle; a registration token, bundle or artefact chaining to any other root MUST be rejected.
- **TRU-035** A runtime MAY hold trust bundles for several authorities at once; it MUST keep each tenancy bound to the authority it registered with.

### 5.5 Revocation

- **TRU-040** A revocation MUST name the key or certificate, a reason and an effective time, and MUST be signed by the root.
- **TRU-041** Revocations MUST be carried in trust bundles, and bundles and anchors MUST carry revocations issued since the recipient's trust-bundle version.
- **TRU-042** A verifier MUST treat a signature as invalid if the signer's certificate was revoked with an effective time at or before the signing time.
- **TRU-043** Device keys are revoked by the factory's device registry ([Registration](./registration.md)), not by root revocation.

### 5.6 Device keys

- **TRU-050** A runtime MUST generate, per tenancy, one P-256 signing key, one P-256 agreement key and one AES-256 wrapping key in `SecureKeyStore`.
- **TRU-051** Device keys MUST be non-exportable and MUST be usable only while the device is unlocked.
- **TRU-052** Device keys MUST NOT carry validity dates enforced by the device clock.
- **TRU-053** A device key's evidence MUST be captured at creation through `Attestor`, with the challenge supplied by the caller: the factory nonce from a registration token when available, otherwise a device-generated nonce, recorded as such.
- **TRU-054** Deleting a tenancy MUST delete all its device keys through `SecureKeyStore`. Deletion MUST be the means of erasure for everything encrypted under them.
- **TRU-055** A signing key MAY be rolled at any time; the roll MUST be recorded in the journal ([Wire formats](./wire-formats.md) `key-roll`) and signed by the outgoing key, with evidence for the new key.

### 5.7 Attestation evidence

- **TRU-060** Each platform profile MUST register an evidence format name (§6.2) and supply an `Attestor` and an `AttestationVerifier` for it.
- **TRU-061** Evidence from a software key store MUST use format `software` and MUST yield `security_level = software`. No adapter may produce any other level for a software key.
- **TRU-062** An `AttestationVerifier` MUST verify the evidence chain to an attestation root listed in the trust bundle for that format, check the vendor's revocation status through `RevocationSource`, check that the attested key equals the presented key, and check that the attested challenge equals the expected one.
- **TRU-063** An `AttestationVerifier` MUST return `AttestationClaims` (§6.3) only for facts it verified; a fact it can't establish MUST be absent, never defaulted.
- **TRU-064** Verified claims MUST be stored with the registration so that intake checks only revocation later; full chain re-validation MUST NOT be required at intake, because intermediate certificates may expire.
- **TRU-065** Whether claims are sufficient MUST be decided by policy ([Policy](./policy.md)), never inside a verifier.

### 5.8 Session keys

- **TRU-070** The session key MUST be `HKDF-SHA256(ikm = unwrap(wrapped_secret) ‖ Argon2id(PIN, salt), info = "fieldseal.dev/session-key/v1" ‖ tenancy_id)`, where `wrapped_secret` is 32 random bytes wrapped by the tenancy's AES wrapping key.
- **TRU-071** Argon2id parameters MUST be at least m = 64 MiB, t = 3, p = 1; runtime policy MAY raise them.
- **TRU-072** The PIN MUST NOT be stored, and no value derived from the PIN alone MUST be stored.
- **TRU-073** The session key MUST exist only in memory during an open session, and MUST be zeroised when the session locks.

### Receiver keys ([ADR 0021](../../explanation/adr/0021-export-upload-receipts.md))

- **TRU-080** Every destination that accepts uploads MUST hold a `receiver` purpose key certified by the authority root.
- **TRU-081** A runtime MUST authorise a destination solely by its `receiver` certificate chaining to a root in the runtime's trust bundle; it MUST NOT authorise by address, domain name or TLS certificate.
- **TRU-082** A `receiver` key MUST be revocable like any purpose key, and runtimes MUST honour revocations carried in anchors and bundles.

### 5.9 Pseudonymous certificates and pinned logs ([ADR 0030](../../explanation/adr/0030-public-transparency-log.md))

- **TRU-090** A `KeyCertificate` MUST identify its subject only by key ID (the first 16 bytes of the SHA-256 of the encoded public key, WIRE-010). The domain type MUST NOT have a field for names, email addresses, organisations or other identity attributes.
- **TRU-091** `IssuePurposeKey` MUST reject a signing request that carries a subject name, email address, alternative name or any attribute beyond the public key and requested purpose.
- **TRU-092** The mapping from key IDs and `ReviewerId`s to people MUST be held only in the `KeyHolderRegistry` port, which MUST be access-controlled and MUST NOT be exported into bundles, trust bundles, provenance or logs.
- **TRU-093** A trust bundle MUST pin each accepted transparency log by origin and public key, with the checkpoint format it signs. A checkpoint signed by any other key MUST be rejected.
- **TRU-094** The mapping from key IDs and reviewer IDs to people MUST stay private to the authority. It MUST NOT enter a certificate, trust bundle, transparency-log entry, export or any other published artefact. Only the authority's own tooling reads it, through a `KeyHolderRegistry` that is access-controlled, bounds each holding in time, and lists only one holder's keys at a time, never the whole mapping. The registry port MUST support registering a holder (with optional validity bounds), resolving a key's holder, listing a holder's keys and ending a holding.
- **TRU-095** Every reader of a Trust structure (key request, key certificate, revocation, trust bundle and its entries, ceremony record) and of the authoring files that feed `fieldseal trust` (ceremony parameters, runtime-build lists, publisher lists) MUST reject unknown fields, enforce exact types (no coercion of text to numbers, of numbers to booleans or of a scalar to a list) and enforce every declared constraint: required fields, fixed byte lengths, enumerations, `2 <= m <= n`, non-empty `[+ …]` lists, a certificate's `not_after` after its `not_before` and within the purpose's maximum validity (TRU-012) when it is read as well as when it is issued, and uniqueness of roots, certificates per issuer and serial, publisher keys per kind, attestation roots per format, runtime builds per platform and app ID, signing digests per build, logs per origin and revocations. Nothing is skipped silently.

### 5.10 Authority key custody ([ADR 0038](../../explanation/adr/0038-authority-key-custody-classes.md))

An authority key has a custody on two independent axes. The **mode** is how it is used: `cold` (offline, in a recorded ceremony) or `hot` (online, by a running service). The **assurance** is what is known about how it was made: `development` (a software key), `custody-bound` (generated inside a hardware custody the deployment binds to the purpose) or `attested` (custody-bound, and the module supplied verified key-attestation evidence at generation). Assurance is ordered `development` < `custody-bound` < `attested`, and mode `hot` < `cold`. These requirements add no field to any wire structure and no method to any port. Custody is decided at issuance, kept by the authority, and enforced by policy ([Policy](./policy.md), POL-065) and deployment validation ([Deployment](./deployment.md), DEP-074).

- **TRU-106** Every authority key (purposes `root`, `factory`, `registration`, `publisher`, `builder`, `receipt`, `receiver` and `record`) MUST have exactly one mode and one assurance at issuance. Policy sets a minimum on each axis per purpose (POL-065).
- **TRU-107** The mode and assurance MUST NOT be encoded in a `KeyCertificate`, a `key-request`, a trust bundle, a purpose name or any other wire structure. A verifier, device, runtime or intake MUST NOT need to read or infer them: it verifies the chain to a root in its trust bundle (TRU-010–TRU-014), and the custody gate is at issuance (TRU-108, TRU-109).
- **TRU-108** `IssuePurposeKey` (and `OpenCollectionPeriod` and `RotatePurposeKey`) MUST establish a request's assurance by exactly one of these means, and MUST refuse a request that shows none (a `deny` at `key.issue`, POL-067). The mode is the one the purpose's custody binding declares (TRU-112).
  1. *Software custody:* the request came from a software `KeyCustody` adapter. The assurance is `development`.
  2. *Bound custody generation:* the request was produced in the issuing ceremony by a hardware `KeyCustody` adapter that the deployment manifest binds to the purpose, and for a P-256 key carries that key's own proof of possession (TRU-016). The assurance is `custody-bound`.
  3. *Verified evidence:* evidence in a registered authority-evidence format was verified by the `AttestationVerifier` for that format against attestation roots in the trust bundle, for the request's key and a challenge the issuer chose (TRU-110). The assurance is `attested`.
- **TRU-109** A `development` key MUST be certified only by a development root. A production trust bundle MUST NOT list a development root, and a bundle that lists a development root MUST NOT list a production root (TRU-034). A root that certifies keys for an environment of tier `production` (DEP-073) MUST refuse a `development` request. Software custody MUST say so in its output (CLI-019).
- **TRU-110** The registry of evidence formats (§6.2) MUST accept authority-evidence formats. An evidence verifier for an authority key MUST verify the chain to a root in `attestation_roots` for its format (TRU-062), that the attested key is the presented key, that the attested challenge is the issuer's, and that the key was generated inside the module and is non-exportable. It MUST return only the claims of §6.3 that it verified, and MUST leave the device-only claims absent (TRU-063, TRU-118). `security_level` MUST be `tpm` for a TPM and `secure-element` for a PKCS#11 or cloud HSM or KMS key attested as hardware-protected.
- **TRU-111** Each issuance MUST be decided at the decision point `key.issue` ([Policy](./policy.md) §6.2) and recorded in the `DecisionLog` (POL-040) with the key ID, purpose, mode, assurance, the SHA-256 of any evidence, the verified claims and the policy layer addresses. The record MUST NOT contain a person's name, and the evidence MUST NOT be published or logged (PUB-104). It MAY be read only by the authority's own tooling (TRU-094).
- **TRU-112** A `KeyCustody` adapter MUST be bound to a purpose in the deployment manifest with a declared `assurance` and `mode` (DEP-074), and MUST NOT be bound to a purpose whose policy minimums (POL-065) it does not meet. A software adapter MUST be declared `development`.
- **TRU-113** A `hot` key MUST be rotated with `RotatePurposeKey` (TRU-015) at least `custody.hotKey.rotateBefore` before its certificate expires, with overlapping validity. Its validity MUST NOT exceed `custody.hotKey.maxValidity` (POL-066), which MUST NOT exceed the limit in §6.1. The successor's assurance MUST meet the same policy minimum, and MUST NOT be lower than the predecessor's. The predecessor MUST be revoked with reason `superseded`, effective at the end of the overlap, and both certificates MUST be carried in the next trust bundle (TRU-041). A new version of a managed key (a cloud KMS key version) is a new key and needs its own certificate. After a compromise, the predecessor MUST be revoked with reason `compromised`, effective at the earliest time it could have been misused (TRU-040).
- **TRU-114** A `development` key MUST NOT be promoted. A key whose public key has ever been certified by a development root MUST NOT be certified by a production root: promotion is a new key, generated in qualifying custody (TRU-108, means 2 or 3) and certified by the production root, and the development key is retired at the development root. A production root MUST refuse a request whose public key is recorded as `development` in any issuance record (TRU-111), and `fieldseal trust verify --audit` MUST fail if one key ID appears under both a development and a production root.
- **TRU-115** An X25519 key (a `record` key, or a `registration` key's agreement half) cannot be attested through an `AttestationVerifier`, which takes a P-256 key. Its assurance MUST therefore be `development` or `custody-bound` until a P-256 record-key suite exists (WIRE open question 1).
- **TRU-116** A `cold` key MUST be used only offline. Its uses MUST appear in the custody usage log (§7, Logs), and a root's uses also require the custodian threshold (TRU-002). A `cold` key's signatures reach the online system as files (for a publisher, a signature over the content address, PUB-041); the key itself MUST NOT be bound to an online adapter (DEP-074).
- **TRU-117** The mode, assurance and evidence digest of every key in a trust bundle MUST be available to the authority's auditors: the documentation bundle MUST list them (DEP-031, DEP-075), and `fieldseal trust verify --audit` MUST compare each certificate in a bundle with its issuance record and fail on a missing record or a custody the effective policy does not accept.
- **TRU-118** The device-only claims of `AttestationClaims` (`unlocked_required`, `app_id`, `app_version`, `boot_state`, `bootloader_locked`) MUST be optional: present only when the evidence format establishes them, absent otherwise (TRU-063). Policy decisions that use them (POL §6.3, `attestation.*`) MUST treat an absent claim as not satisfying a requirement on it.

## 6. Resources and formats

### 6.1 Purposes

| Purpose | Signs or decrypts | Maximum validity |
|---|---|---|
| `factory` | Bundles | 1 year |
| `registration` | Registration tokens; tenancy, close and reset certificates; decrypts registration requests | 1 year |
| `publisher` | Artefact signatures ([Publishing](./publishing.md)) | 2 years |
| `builder` | Provenance statements | 1 year |
| `log` | *Not an authority key.* The public log's own checkpoint key, pinned in the trust bundle (TRU-093) | As published by the log |
| `receipt` | Receipts and time tokens | 1 year |
| `receiver` | Proves a destination is authorised to receive uploads (challenge signatures) | 1 year |
| `record` | Decrypts records and export manifests for one collection period | The period plus retention |

### 6.2 Evidence formats

| Format | Platform | Evidence |
|---|---|---|
| `android-key-attestation` | Android | The key's attestation certificate chain |
| `apple-app-attest` | iOS, iPadOS | App Attest attestation object, plus Secure Enclave key binding |
| `tpm2-quote` | Windows, Linux | TPM 2.0 key creation data, certification and EK chain |
| `software` | Any (tests, practice) | None; always unattested |
| `hsm-key-attestation` | Authority keys in a PKCS#11 HSM | The vendor's key attestation statement and its certificate chain; roots under this name in `attestation_roots` |
| `cloud-kms-attestation` | Authority keys in a cloud KMS or managed HSM | The provider's key attestation statement and chain; roots under this name in `attestation_roots` |

TPM 2.0 key certification for an authority key uses the existing `tpm2-quote` format. Authority-evidence formats are registered exactly as device formats are (TRU-060), and a device ignores a format it has no verifier for.

### 6.3 Attestation claims

| Claim | Type | Meaning |
|---|---|---|
| `security_level` | `strongbox` / `secure-element` / `tee` / `tpm` / `software` | Where the key lives |
| `origin_generated` | bool | The key was generated inside the store, not imported |
| `purposes` | list | Operations the key permits |
| `unlocked_required` | bool | The key works only while the device is unlocked |
| `challenge` | bytes | The challenge bound into the evidence |
| `app_id` | text | Runtime identity (package and signing digest, or team and bundle ID) |
| `app_version` | text | Runtime build version |
| `os_patch_level` | date | Platform security patch level |
| `boot_state` | `verified` / `self-signed` / `unverified` | Verified-boot state |
| `bootloader_locked` | bool | Bootloader lock state |
| `device_serial` | text | Only when the platform attests it |

The device-only claims (`unlocked_required`, `app_id`, `app_version`, `boot_state`, `bootloader_locked`) are optional: an evidence format that cannot establish one leaves it absent (TRU-063, TRU-118). An authority-key verifier (TRU-110) returns `security_level`, `origin_generated`, `purposes` and `challenge`.

### 6.4 Key certificate

```cddl
key-certificate = {
  "v": 1, "key_id": key-id, "public_key": p256-pub / x25519-pub,
  "purpose": tstr, ? "period": tstr,
  "not_before": ms-time, "not_after": ms-time,
  "issuer": key-id, "serial": uint, "sig": signature   ; tag fieldseal.dev/key-certificate/v1
}
; A root certificate is the root's own: "purpose": "root", "issuer" = "key_id", P-256.
; "period" is present exactly on "record" certificates; "not_after" is inclusive.

key-request = { "v": 1, "public_key": p256-pub, ? "purpose": tstr, "sig": signature }
            / { "v": 1, "public_key": x25519-pub, ? "purpose": tstr }
; "sig": the key's own signature over the request without "sig", tag fieldseal.dev/csr/v1
; (TRU-016). Any other key is an identity attribute and is refused (TRU-091).

revocation = {
  "v": 1, "key_id": key-id, ? "serial": uint,   ; without "serial": every certificate for the key
  "reason": "compromised" / "superseded" / "holder-left" / "retired",
  "effective": ms-time, "issued": ms-time,
  "issuer": key-id, "sig": signature            ; tag fieldseal.dev/revocation/v1, by the root
}
```

### 6.5 Trust bundle

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: TrustBundle
metadata:
  name: example-authority
  version: 4.0.0
spec:
  roots:
    - keyId: 3f1c…            # SHA-256 prefix of the root public key
      publicKey: BASE64…
  certificates: [ … ]         # purpose-key certificates, canonical form
  attestationRoots:
    android-key-attestation: [ BASE64…, BASE64… ]
    apple-app-attest: [ BASE64… ]
  runtimeBuilds:
    - platform: android
      appId: dev.fieldseal.collect
      signingDigests: [ sha256:… ]
  revocations: [ … ]
```

Its canonical form, which the roots sign and which is published as the artefact's bytes:

```cddl
trust-bundle = {
  "v": 1, "name": tstr, "version": tstr,        ; MAJOR.MINOR.PATCH, compared numerically (TRU-033)
  "issued": ms-time,
  "roots": [+ key-certificate],                 ; root certificates
  "certificates": [* key-certificate],          ; purpose-key certificates issued by a listed root
  "publishers": { * tstr => [+ key-id] },       ; publisher keys per artefact kind (PUB-040)
  "attestation_roots": { * tstr => [+ bstr] },  ; per evidence format (§6.2)
  "runtime_builds": [* { "platform": tstr, "app_id": tstr, "signing_digests": [+ hash] }],
  "logs": [* { "origin": tstr, "public_key": bstr, "format": tstr }],   ; TRU-093
  "revocations": [* revocation],
  "signatures": [+ { "signer": key-id, "sig": signature }]
}
; Each signature is over tag fieldseal.dev/trust-bundle/v1 and the bundle without
; "signatures", by a root the bundle lists that is valid at "issued" (TRU-031).
; A decoder reports a "version" not of the form MAJOR.MINOR.PATCH with E_UNKNOWN_FIELD, and a
; certificate or revocation not issued by a listed root with E_SIG (its signer is not trusted).
```

### 6.6 Ceremony record

```cddl
ceremony-record = {
  "v": 1, "authority": tstr, "root": key-certificate,
  "threshold": { "m": uint, "n": uint },        ; 2 <= m <= n (TRU-002)
  "custodians": [+ tstr], "witnesses": [+ tstr], "held": ms-time
}
```

The root does not sign the record (TRU-003); the participants sign its content address in the ceremony log.

### 6.7 Custody ([ADR 0038](../../explanation/adr/0038-authority-key-custody-classes.md))

| Axis | Value | Meaning | Established by (TRU-108) |
|---|---|---|---|
| Assurance | `development` | A software key; refused in production (INV-15) | Software custody (1) |
| | `custody-bound` | Generated inside a hardware custody (KMS, HSM, offline signer) the manifest binds to the purpose | Bound custody generation (2) |
| | `attested` | Custody-bound, and the module supplied verified key-attestation evidence | Verified evidence (3) |
| Mode | `hot` | Used online by a service through `KeyCustody` | The binding's declaration (TRU-112) |
| | `cold` | Used only offline, in a recorded ceremony | The binding's declaration, with `offline: true` (DEP-074) |

The minimum on each axis, per purpose and environment, is policy (`custody.minAssurance`, `custody.minMode`, POL-065).

## 7. Twelve-factor

- **Config (III):** which `KeyCustody`, `AttestationVerifier` and `RevocationSource` adapters a service uses, and their resource references, come from the environment. Key material never appears in config; config names keys by ID.
- **Backing services (IV):** HSM/KMS, revocation sources and attestation roots are attached resources.
- **Build, release, run (V):** the runtime build carries no trust material (TRU-032); trust bundles arrive with the release's provisioning configuration and in bundles.
- **Disposability (IX):** every operation is idempotent by key ID and serial.
- **Logs (XI):** every `KeyCustody` use is emitted as a structured event with key ID, purpose and caller; never key material or plaintext.
- **Admin processes (XII):** root ceremonies, issuing and rotation run as `fieldseal trust` commands.
- **Port binding (VII), concurrency (VIII):** not applicable to a library context; the services that embed it follow their own specs.

## 8. Conformance

- `fieldseal trust root-init`, `trust issue`, `trust bundle` and `trust verify` implement the authority side; tests MUST cover purpose mismatch, expired and revoked certificates, chains of depth 2, and a trust-bundle update signed by an unknown root.
- `fieldseal keys generate` and `keys roll` exercise `SecureKeyStore` and `Attestor` through the software adapter; `fieldseal device simulate` runs a whole tenancy with it.
- Each `AttestationVerifier` adapter MUST pass a shared suite of recorded evidence: valid, wrong challenge, wrong key, revoked chain, software-backed, unlocked bootloader.
- Closed-schema tests (TRU-095) cover, for each reader, an unknown field, a wrong type, a broken constraint, a missing required field and a valid input (`crates/contexts/trust/tests/strict.rs`, and the CLI authoring-file tests in `trust_cmd.rs`).
- Every port's contract suite runs under `fieldseal conformance run --suite trust`.
- Tests MUST cover: issuance of each assurance by its means; a request with no means refused (TRU-108); a development request refused by a production root (TRU-109); a key certified under a development root and then presented to a production root (TRU-114); attestation evidence with a wrong challenge, a wrong key, a revoked chain and software-backed evidence, for each authority-evidence format (TRU-110); a hot-key rotation that tries to lower the assurance (TRU-113); and `trust verify --audit` on a bundle with a missing issuance record (TRU-117). Evidence verifiers for authority keys pass the shared recorded-evidence suite of this section.

## 9. Open questions

1. Does the authority's HSM support X25519 for record keys, or is a P-256 record-key suite needed ([Wire formats](./wire-formats.md) open question 1)?
2. Should trust bundles also accept witness cosignatures for root changes?
3. What is the retention period that bounds record-key lifetime (TRU-023)? It belongs in the deployment manifest, set with the custodian.
4. Does every target platform attest `unlocked_required`? If not, policy needs a rule for platforms that can't.
5. *Resolved ([ADR 0038](../../explanation/adr/0038-authority-key-custody-classes.md)):* mode and assurance are separate axes (§6.7).
6. *Resolved (ADR 0038):* the device-only claims are optional (TRU-118).
7. *Resolved (ADR 0038):* no runtime self-check method; deployment validation and the start-up check suffice (DEP-074). A signed custody statement for relying parties is a possible future option.

## 10. References

- ADR [0038](../../explanation/adr/0038-authority-key-custody-classes.md)
- ADRs [0008](../../explanation/adr/0008-trust-hierarchy.md), [0012](../../explanation/adr/0012-local-first-device-keys.md), [0017](../../explanation/adr/0017-runtime-authentication.md), [0024](../../explanation/adr/0024-platform-profiles.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- RFC 5869 (HKDF), RFC 9106 (Argon2), RFC 9180 (HPKE), NIST SP 800-57 Part 1 Rev. 5 (key management), Android key attestation, Apple App Attest, TCG TPM 2.0 Library
