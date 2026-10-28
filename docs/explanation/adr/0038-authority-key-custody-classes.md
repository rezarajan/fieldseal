# ADR 0038: Authority key custody: an operating mode and an assurance level

**Status:** Accepted (2026-10-27, decided by the project lead) · **Priority:** Must · **Date:** 2026-10-27

**In one line:** Every authority key (root, publisher, builder, registration, receipt, record) has a custody on two independent axes, an operating *mode* (`cold` or `hot`) and an *assurance* (`development`, `custody-bound` or `attested`). Both are fixed at issuance with the existing `KeyCustody`, `AttestationVerifier` and CSR proof of possession, recorded privately, and enforced by tighten-only policy minimums and deployment validation. They never appear on the wire, and a development key can never be promoted.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The project lead's decision: "While production requires hardware-backed keys, we may also allow development key enrolment, or attested keys (like those a hardware module would have attested to), i.e., cold and hot keys (ensure that this fits the model we are working with cleanly, without modification of the core itself)."

Today the specs treat authority custody as one thing. TRU-013 says purpose keys are held in `KeyCustody` and aren't exportable. Device keys have a richer model: attestation evidence (§6.2), claims (§6.3), a verifier port, and policy that decides sufficiency (TRU-065). Authority keys have no way to say how they were made or how they are used, and no way for policy to demand more of a root than of a development workstation.

The first draft of this ADR had four classes (`cold`, `hot`, `attested`, `development`). They overlap: an attested key can be used hot or cold. The project lead resolved this as **two axes**, which this ADR now uses.

## What the existing model already offers

I read the specs and the code for a place to carry custody evidence or a class.

| Question | Finding | Evidence |
|---|---|---|
| Does the key certificate have an extensible place? | **No.** It is a closed map; any extra field is `E_UNKNOWN_FIELD`. "Extension happens only through a new structure version." | `docs/reference/spec/wire-formats.md` WIRE-005; `docs/reference/spec/trust.md` §6.4 (`key-certificate`); `crates/contexts/trust/src/domain/certificate.rs:537` (`f.finish()?`) |
| Does the CSR (`key-request`)? | **No.** Any key besides `v`, `public_key`, `purpose` and `sig` is treated as an identity attribute and refused. This is deliberate (TRU-091, ADR 0030). | `trust.md` §6.4; `certificate.rs:186-192` (`IdentityAttributes`) |
| Does the trust bundle? | **Only one map is open: `attestation_roots`**, keyed by any evidence-format name. Everything else is closed. | `trust.md` §6.5; `crates/contexts/trust/src/domain/bundle.rs:93` (`BTreeMap<String, Vec<Vec<u8>>>`) |
| Can purposes carry it (for example `publisher-dev`)? | **No.** `Purpose` is a closed enum, and `KeyRole::parse` rejects an unknown purpose. | `crates/kernel/src/crypto.rs:8-23`; `crypto.rs:52`, `certificate.rs:521` |
| Is the evidence-format registry open? | **Yes.** A format is a string; verifiers are registered per format; unknown formats are `UnsupportedFormat`, not parse errors. | `trust.md` §6.2, TRU-060; `ports.rs:198-210` (`AttestationVerifier::format`); `application.rs:222-244` |
| Can `AttestationVerifier` verify an authority key? | **Mostly.** The port takes a P-256 key and a challenge and returns claims. But `AttestationClaims` has device-only fields that are not optional: `unlocked_required`, `app_id`, `app_version`, `boot_state`, `bootloader_locked`. An HSM has none of these facts. | `crates/contexts/trust/src/domain/mod.rs:91-111`; compare TRU-063 ("a fact it can't establish MUST be absent, never defaulted") |
| Can the claims say "HSM"? | **Yes, by the existing enumeration.** `security_level` has `tpm` and `secure-element`; a PKCS#11 or cloud HSM is a tamper-resistant module, so it maps to `secure-element` and a TPM to `tpm`. | `trust.md` §6.3; `domain/mod.rs:33-44` |
| Can X25519 keys be attested? | **No.** The verifier takes a `P256PublicKey`. `record` keys are X25519 (TRU-020). | `ports.rs:203-209` |
| Does custody generation return evidence? | **No.** `CustodyKey` is `{id, public_key, role}`. Evidence has to be collected by the adapter and presented to the issuing command. | `domain/mod.rs:190-197` |

## Decision

### Two axes

| Axis | Values (weakest first) | Meaning |
|---|---|---|
| **Assurance** | `development` < `custody-bound` < `attested` | What is known about how the key was made. `development`: a software key. `custody-bound`: generated inside a hardware custody (KMS, HSM, offline signer) that the deployment manifest binds to the purpose. `attested`: custody-bound, and the module supplied verified key-attestation evidence (a PKCS#11 vendor attestation, a cloud KMS key attestation, a TPM 2.0 key certification). |
| **Mode** | `hot` < `cold` | How the key is used. `hot`: online, by a running service. `cold`: offline, in a recorded ceremony. |

Policy sets a **minimum on each axis per purpose** (`custody.minAssurance.<purpose>`, `custody.minMode.<purpose>`; both tighten, so a later layer can only raise them). Defaults: every purpose `custody-bound`; `root` and `publisher` `cold`, all others `hot`. An environment of tier `production` can never have a `development` minimum (INV-15).

### Custody lives outside the wire (no core change)

- **Assurance is established at issuance by exactly one of three existing means:**
  1. *Software custody:* a software `KeyCustody` adapter, always `development` (as TRU-061 already says of software device keys).
  2. *Bound custody generation:* the CSR is produced by the bound hardware adapter in the issuing ceremony, under `fieldseal.dev/csr/v1` (TRU-016), so the hardware key itself proves possession. Assurance is `custody-bound`.
  3. *Verified evidence:* the vendor's evidence goes, with a challenge the issuer chose, to the `AttestationVerifier` for its format (TRU-060 to TRU-065). Assurance is `attested`.

  A CSR that arrives as a bare file, with none of these, is refused.
- **Mode** is the mode the manifest declares for the bound adapter (`cold` needs `offline: true`).
- **Private record, public effect.** The issuance decision is a policy decision at a new decision point, `key.issue`, in the existing `DecisionLog`. It holds the key ID, purpose, mode, assurance, the digest of the evidence and the policy layers. Nothing is put into a certificate, a CSR, a trust bundle or a purpose string.
- **Devices and intake don't need to know.** They verify chains to a root. The custody gate is at issuance. A production trust bundle never lists a development root, so a development key cannot produce a signature a production verifier accepts.
- **Auditors can see it.** The documentation bundle lists each key's mode, assurance and evidence digest, and `fieldseal trust verify --audit` compares every certificate in a bundle with its issuance record. Auditor-only visibility is enough for now. A signed custody statement that relying parties could verify is recorded as a future option; it would need a new structure or artefact kind, which is a core change.

### Attestation roots travel in the existing trust-bundle map

HSM vendor roots are added to `attestation_roots` under new evidence-format names: `hsm-key-attestation` (a PKCS#11 vendor chain) and `cloud-kms-attestation`, plus the existing `tpm2-quote` for TPM 2.0 certification. The map is open by design, the root signs the bundle, and TRU-062 already requires verification against these roots. A device ignores formats it has no verifier for.

### Optional device-only claims

`AttestationClaims` makes its five device-only fields (`unlocked_required`, `app_id`, `app_version`, `boot_state`, `bootloader_locked`) optional, absent when the format does not establish them. This is an additive change to the Trust context. It brings the type in line with TRU-063 ("absent, never defaulted"), which the spec already said. An absent claim never satisfies a policy requirement on it.

### Hot-key rotation uses the existing machinery

Hot keys rotate with `RotatePurposeKey` (TRU-015): a new key is generated in custody, certified with overlapping validity, and both certificates ride the next trust bundle (TRU-041). Policy shortens the allowed validity of hot keys below the TRU §6.1 maximum and sets a rotation lead time. The successor's assurance must meet the policy minimum and not be lower than the predecessor's. A cloud KMS "key version" is a new key with a new key ID. An emergency rotation is a revocation with reason `compromised`.

### A development key can never be promoted

- A development key is certified only by a **development root**, a different root in a different trust bundle. A production bundle never lists it (TRU-034).
- A production root refuses a `development` request, and any request that cannot show means 2 or 3.
- Promotion is not a state change. It is **a new key**, generated in qualifying custody and certified by the production root. The development key is retired at the development root.
- `trust verify --audit` fails if one key ID appears under both a development and a production root.

### Deployment validation refuses custody below policy

The deployment manifest declares, for each authority purpose and environment, the assurance and mode of the custody adapter bound to it. `ValidateManifest` returns `PolicyFloorViolation` when either is below the effective minimum, when a development binding is in a production environment, or when a cold binding is not offline. Services refuse to start on the same check. The declaration is an assertion; the issuance record is the proof, and the audit compares the two. There is no runtime self-check method on `KeyCustody`.

## Does this fit without modifying the core?

**Yes for the kernel, the wire formats, the certificate and CSR structures, the port signatures and the policy engine. One additive change is made to the Trust context's domain type, as the project lead approved.**

| Part | Verdict |
|---|---|
| Kernel (`crates/kernel`) | Unchanged. |
| Wire structures: certificate, CSR, trust bundle, bundles | Unchanged. Custody is deliberately not in them. |
| Driven ports (`KeyCustody`, `AttestationVerifier`, `DecisionLog`) | Signatures unchanged. |
| Policy | New data (controls, a decision point, an invariant), not new engine behaviour. |
| Trust context `AttestationClaims` | The five device-only fields become optional. Additive; fixes the TRU-063 mismatch. |
| X25519 record keys | Cannot be attested through the P-256 port; their assurance tops out at `custody-bound` until a P-256 record suite exists (TRU-115). |

## Consequences

- One issuance flow serves every combination of the two axes, and policy, not code, decides what a deployment accepts.
- Development keys are real and usable in the local stack, and cannot reach production by any path.
- The custody is not visible to a relying party from a certificate alone. The documentation bundle and the audit command are the visible channels.
- The declared custody in a manifest is an assertion until the audit compares it with the issuance record.
- Supersedes nothing. Refines ADR 0008 (trust hierarchy) and ADR 0011 (policy), and consumes ADR 0025 and ADR 0028.

## Specs

[trust](../../reference/spec/trust.md) TRU-106 to TRU-118 and §6.7, [policy](../../reference/spec/policy.md) POL-065 to POL-067 and INV-15, [deployment](../../reference/spec/deployment.md) DEP-073 to DEP-075
