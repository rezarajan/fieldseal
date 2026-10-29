# Publishing

**Prefix:** `PUB` · **Context:** Publishing · **Status:** Draft · **ADRs:** [0009](../../explanation/adr/0009-publishing-with-provenance.md), [0010](../../explanation/adr/0010-declarative-instruments.md), [0011](../../explanation/adr/0011-policy-as-signed-files.md), [0008](../../explanation/adr/0008-trust-hierarchy.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)

## 1. Scope

Publishing turns an authored artefact into one that every other context may rely on: validated, reviewed, built reproducibly, described by signed provenance, signed by a threshold of publishers, logged in a transparency log, and placed in the artefact registry. It also withdraws artefacts. The artefact kinds are `Instrument`, `Layout` ([ADR 0033](../../explanation/adr/0033-presentation-layouts.md)), `Localisation` ([ADR 0034](../../explanation/adr/0034-internationalisation-and-localisation.md)), `Extension` , `Policy`, `TrustBundle` and `Deployment`. For an instrument, the review MUST include a reviewer for each declared language (INS-083).

It does not define what an instrument or policy contains ([Instrument](./instrument.md), [Policy](./policy.md)), how bundles are built from published artefacts ([Distribution](./distribution.md)), or key custody ([Trust](./trust.md)). Rosters are never published.

## 2. Domain model

| Element | Kind | Meaning |
|---|---|---|
| `Artefact` | Aggregate | One version of one artefact: kind, name, semantic version, canonical bytes, content address |
| `Review` | Entity | A reviewer's approval or rejection of an artefact version, tied to its content address |
| `Provenance` | Value object | A signed in-toto statement with an SLSA build-provenance predicate |
| `PublisherSignature` | Value object | One publisher key's signature over an artefact's content address and provenance digest |
| `PublicationStatement` | Value object | What a publisher signs: `{type, fingerprint, provenance_digest}`. Only an enumeration and two 32-byte hashes; no names, versions or locations |
| `LogEntry` | Value object | What is logged: exactly `{type, digest, signature, public_key}`, where `digest` is the SHA-256 of a signed `PublicationStatement`. The **only** type the `TransparencyLog` port accepts ([ADR 0030](../../explanation/adr/0030-public-transparency-log.md)) |
| `ReviewerId` | Value object | A pseudonymous reviewer identifier; the mapping to a person is held only in the private `KeyHolderRegistry` ([Trust](./trust.md)) |
| `SignedCheckpoint` | Value object | The log's signed size and root hash at a point in time, with optional witness cosignatures |
| `InclusionProof`, `ConsistencyProof` | Value objects | Merkle proofs of an entry's presence, and of one tree head extending another |
| `Publication` | Value object | Everything a consumer needs to verify an artefact offline: canonical bytes, provenance, signatures, one `LogEntry` and inclusion proof per signature, and the `SignedCheckpoint` they were proven against |
| `Withdrawal` | Value object | A signed, logged statement that an artefact version must no longer be used |

Domain events: `ArtefactSubmitted`, `ArtefactApproved`, `ArtefactRejected`, `ArtefactBuilt`, `ArtefactSigned`, `ArtefactLogged`, `ArtefactPublished`, `ArtefactWithdrawn`.

Invariants:
- An artefact's content address never changes; any change is a new version.
- A publication is valid only as a whole: missing provenance, signatures or proof makes it unpublished.
- A version number is used once per artefact name.
- A `LogEntry` can't carry anything but its four fields: the type has no extension mechanism, so sensitive data can't reach a public, permanent log by construction.

## 3. Driving ports

| Port | Used by | Input | Output |
|---|---|---|---|
| `ValidateArtefact` | Authors, CI | Source document | Diagnostics |
| `SubmitForReview` | Authors | Artefact version | Review request |
| `RecordReview` | Reviewers | Content address, decision, comment | `Review` |
| `BuildArtefact` | CI | Source revision | Canonical bytes, content address, `Provenance` |
| `SignArtefact` | Publishers | Content address, provenance | `PublisherSignature` |
| `PublishArtefact` | CI | Artefact, provenance, signatures | `Publication` |
| `WithdrawArtefact` | Publishers | Content address, reason | `Withdrawal` |
| `VerifyPublication` | Factory, runtime, intake, operators | `Publication`, trust bundle, publishing policy | Verdict |
| `ResolveArtefact` | Factory, intake | Kind, name, version range | `Publication` |

## 4. Driven ports

| Port | Contract every adapter MUST meet | Example adapters |
|---|---|---|
| `SourceRepository` | Returns an artefact's source at an immutable revision ID; reports the revision's author identity | Git hosting |
| `ReviewSystem` | Records approvals by authenticated identity against an exact revision; can't be altered after the fact; supplies the roles each reviewer holds (artefact kinds, and for instruments the languages they review) | Pull-request reviews, a review service |
| `Builder` | Runs the canonicalisation in an isolated, ephemeral environment from a pinned definition; attests its own identity | CI runner with workload identity |
| `KeyCustody` | As in [Trust](./trust.md); used for publisher and builder keys | HSM, KMS |
| `TransparencyLog` | Accepts **only** `LogEntry` values; transmits exactly their four fields and nothing else (no artefact, provenance, labels, metadata or tags); returns inclusion proofs and signed checkpoints; append-only and publicly verifiable. Every adapter MUST pass the contract suite in §8, which records the outbound bytes. | Sigstore Rekor (`hashedrekord` entries), a self-hosted Tessera log |
| `LogTransport` | The outbound boundary every `TransparencyLog` adapter sends through: one `Transmission` (named fields and values) per request. Contract tests build adapters over a recording transport and inspect every transmission (PUB-104). | HTTPS client, recording transport (tests) |
| `ArtefactRegistry` | Stores publications by content address; immutable; lists versions by kind and name | Object store, OCI registry |
| `PolicyEngine` | As in [Policy](./policy.md); evaluates the publishing policy | Open Policy Agent |

## 5. Requirements

### 5.1 Authoring and validation

- **PUB-001** Every artefact MUST be authored as a resource with `apiVersion: fieldseal.dev/v1alpha1`, a `kind` from §1, and `metadata.name` and `metadata.version` (semantic version).
- **PUB-002** An artefact's source MUST live in a `SourceRepository` at an immutable revision.
- **PUB-003** An artefact MUST pass its kind's validation (`fieldseal <kind> validate`) and lint before it can be submitted for review.
- **PUB-004** An artefact MUST NOT contain secrets or data about subjects. Validation MUST reject recognisable key material, credentials and embedded rosters.

### 5.2 Review

- **PUB-010** An artefact MUST receive at least the number of approving reviews set by publishing policy (`publishing.requiredApprovals`, default 2) before it can be signed.
- **PUB-011** An approval MUST be tied to the artefact's content address; any change after approval MUST void it.
- **PUB-012** The author of a revision MUST NOT count as one of its reviewers unless publishing policy allows it (`publishing.authorMayApprove`, default false).
- **PUB-013** Reviewers MUST be identified by the review system's authenticated identity and hold a reviewer role for the artefact kind. The `ReviewSystem` port supplies the roles; an approval or rejection by an identity without the role for the kind is ignored, so it neither counts toward PUB-010 nor blocks the version.
- **PUB-014** For an instrument, the approving reviewers counted toward PUB-010 MUST include one holding the language role for each translation the instrument declares (INS-083): every declared language but `defaultLanguage`, which any reviewer of the kind covers.

### 5.3 Build, canonicalisation and content addressing

- **PUB-020** The canonical bytes of an artefact MUST be its deterministic CBOR encoding ([Wire formats](./wire-formats.md) §5.1), produced from the authoring form (YAML or JSON) by the format core.
- **PUB-021** The content address MUST be SHA-256 of the canonical bytes ([Wire formats](./wire-formats.md) WIRE-011).
- **PUB-022** Canonicalisation MUST be reproducible: building the same revision twice MUST yield identical bytes. `fieldseal instrument hash` (and the equivalent for other kinds) MUST compute the same address locally.
- **PUB-023** The build MUST run in a `Builder` whose identity is in the publishing policy's `allowedBuilders`.

### 5.4 Provenance

- **PUB-030** Each build MUST emit an in-toto Statement v1 whose subject is the artefact's name and content address, with an SLSA Provenance v1 predicate.
- **PUB-031** The predicate MUST state the source repository and revision, the builder identity, the build definition's digest, and the identities of the approving reviewers.
- **PUB-032** The provenance MUST be signed by a `builder` key ([Trust](./trust.md) §6.1) over tag `fieldseal.dev/provenance/v1`.
- **PUB-033** The source repository MUST be in publishing policy's `allowedSources`.

### 5.5 Publisher signatures

- **PUB-040** A publication MUST carry signatures from at least `publishing.publisherThreshold.m` distinct `publisher` keys, out of the publisher keys listed in the trust bundle for that artefact kind.
- **PUB-041** Each signature MUST be over tag `fieldseal.dev/artefact/v1` and the structure `{kind, name, version, address, provenance_sha256}`.
- **PUB-042** A publisher MUST NOT sign an artefact whose reviews, provenance or validation do not pass. `fieldseal artefact sign` MUST check all three before signing.
- **PUB-043** One person MUST NOT hold more than one of the publisher keys counted toward a single publication's threshold. A verifier that has the authority's `KeyHolderRegistry` MUST count distinct holders toward the threshold, so a publication met only by two keys of one holder is refused. The check is optional where no registry is available (devices); signatures and certificates stay pseudonymous (TRU-094).

### 5.6 Transparency log

- **PUB-050** Every publication and withdrawal MUST be appended to the authority's `TransparencyLog` before it is placed in the registry.
- **PUB-051** The log MUST be a Merkle tree per RFC 9162: leaf hash `SHA-256(0x00 ‖ entry)`, node hash `SHA-256(0x01 ‖ left ‖ right)`.
- **PUB-052** *Withdrawn ([ADR 0030](../../explanation/adr/0030-public-transparency-log.md)): the entry carried names and versions. Replaced by PUB-100–PUB-104.*
- **PUB-053** *Withdrawn ([ADR 0030](../../explanation/adr/0030-public-transparency-log.md)): the log is external and signs its own checkpoints. Replaced by PUB-106.*
- **PUB-054** The log MUST provide an inclusion proof for any entry against any tree head that includes it, and a consistency proof between any two tree heads.
- **PUB-055** A component that sees a tree head MUST keep the latest one it has verified, and MUST verify consistency before accepting a later one. An inconsistency MUST be reported as a security event and MUST stop the component from accepting further publications from that log.

### 5.7 Registry and publication

- **PUB-060** The `ArtefactRegistry` MUST accept a publication only if PUB-010 to PUB-054 verify for it.
- **PUB-061** A `Publication` MUST carry everything needed to verify it offline: canonical bytes, provenance, signatures, a `LogEntry` and inclusion proof per signature, and the `SignedCheckpoint` they were proven against, with the authority time token or receipt that accompanied it (PUB-072).
- **PUB-062** The registry MUST be immutable: a content address, once stored, MUST always return the same publication.

### 5.8 Verification by consumers

- **PUB-070** The factory MUST build bundles only from publications that pass `VerifyPublication` against its trust bundle and the current publishing policy, and that are not withdrawn.
- **PUB-071** A runtime MUST verify, for every publication in a bundle: the publisher threshold signatures against publisher keys in its own trust bundle, the inclusion proof, and the tree head's signature. It MUST reject the bundle if any check fails, independently of the factory's signature.
- **PUB-072** A runtime MUST reject a tree head older than `runtime.publishing.maxTreeHeadAge`, and MUST verify consistency with the latest tree head it holds (PUB-055). C2SP checkpoints carry no time, so a tree head's age is measured from the authority time token or receipt that accompanied the checkpoint when it was obtained, to the bundle's time token. A tree head with no such token or receipt MUST be treated as too old.
- **PUB-073** A runtime MAY skip verifying provenance contents; the factory and intake MUST verify them.
- **PUB-074** Intake MUST resolve the instrument named in every record by content address and verify its publication before replaying rules against it.
- **PUB-075** Every record, bundle and decision MUST name artefacts by content address, never by name and version alone.

### 5.9 Withdrawal

- **PUB-080** A withdrawal MUST be signed by the publisher threshold for the artefact kind over tag `fieldseal.dev/withdrawal/v1` and logged (PUB-050).
- **PUB-081** The factory MUST stop building bundles from a withdrawn artefact as soon as the withdrawal is logged.
- **PUB-082** Bundles MUST carry withdrawals logged since the recipient's last bundle; a runtime MUST refuse to start new records against a withdrawn instrument, and MUST still allow review, export and clear of records already made.
- **PUB-083** Intake MUST land records made against a withdrawn instrument if they were made before the withdrawal reached the device (by tick and import records), and MUST flag them otherwise.

### Instrument salts ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md))

- **PUB-090** When an instrument version is first built for publishing, CI MUST generate a 32-byte random salt and MUST keep it fixed for that version.
- **PUB-091** The salt MUST be recorded in the artefact and its provenance statement, and MUST NOT be logged; the log holds only the digest of the publication statement (PUB-101).
- **PUB-092** For instruments, the registry's content address MUST be the fingerprint; reviews and publisher signatures MUST be over the fingerprint.

### 5.10 Public transparency log ([ADR 0030](../../explanation/adr/0030-public-transparency-log.md))

- **PUB-100** Publications and withdrawals MUST be logged in a public, append-only transparency log through the `TransparencyLog` port only.
- **PUB-101** A publisher MUST sign a `PublicationStatement` `{type, fingerprint, provenance_digest}` (WIRE §log-entry), and nothing else, for logging.
- **PUB-102** The domain MUST construct a `LogEntry` only from: `type` (`publish` or `withdraw`), `digest` (SHA-256 of the signed `PublicationStatement`), one `signature` and one `public_key`. The type MUST NOT have optional, free-form or extension fields.
- **PUB-103** One `LogEntry` MUST be logged per publisher signature counted toward the threshold.
- **PUB-104** Artefact bytes, provenance documents, names, versions, source locations, builder identities and reviewer identities MUST NOT be sent to the transparency log, in any field, header or tag.
- **PUB-105** A `TransparencyLog` adapter MUST map a `LogEntry` to the backend's minimal hash-only entry type (for Rekor, `hashedrekord`) and MUST NOT set any optional backend field that carries data.
- **PUB-106** Inclusion MUST be verified against a `SignedCheckpoint` signed by a log key pinned in the trust bundle ([Trust](./trust.md), TRU-093).
- **PUB-107** Provenance MUST name reviewers by `ReviewerId`, never by name or email address.
- **PUB-108** The registry MUST reject a publication whose provenance or certificates contain an identity attribute other than a key ID or `ReviewerId`.
- **PUB-109** Policy MAY require witness cosignatures on checkpoints (`publishing.requiredWitnessCosignatures`, default 0); a consumer MUST verify any it requires.
- **PUB-112** Every reader of a Publishing input (publication, draft, withdrawal and withdrawal draft, provenance statement and its signed wrapper, publication statement, log entry, checkpoint note, and an artefact file submitted to `fieldseal artefact provenance`) MUST reject unknown fields, enforce exact types, and enforce every declared constraint: required fields, fixed byte lengths, enumerations (`kind`, `type`, `leaf`) matched exactly, non-empty `[+ …]` lists, the artefact name and semantic-version forms (PUB-001), non-empty source, revision and builder identity, distinct reviewers, and a decimal tree size without sign or leading zeros. Signature and log-record cardinality (one record per counted signature, distinct signers) is enforced by verification, which reports it with a specific error (PUB-040, PUB-103). An external log backend's response (Rekor) is a third party's format and is read by name for the fields this context needs, each of exact type; everything read from it is verified cryptographically against the pinned log key (PUB-106).

- **PUB-110** The Fieldseal log adapter's operations are the `TransLog` contract (`fieldseal.v1.TransLog`), defined once; HTTP is a mapping of it. The contract also has `GetEntries`, which lists the stored entries; over HTTP it is `GET /entries/{from}/{to}`, answering the canonical `LogEntry` bytes without re-encoding (WIRE-199). Entries, checkpoint notes and proofs are opaque `bytes` and MUST NOT be re-encoded (WIRE-196), and the contract has no operation that sends anything but a `LogEntry` (PUB-102). Public logs such as Rekor keep their own API behind their own adapter. gRPC is built in slice 2 ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md)).

| rpc | HTTP |
|---|---|
| `AddEntry` | `POST /append` |
| `GetCheckpoint` | `GET /checkpoint` |
| `GetInclusionProof` | `GET /inclusion/{leaf_index}/{tree_size}` |
| `GetConsistencyProof` | `GET /consistency/{old_size}/{new_size}` |

- **PUB-111** The `TransparencyLog` contract suite (below) MUST run its recording check through every transport adapter of the Fieldseal log, so that the gRPC messages are held to the same four-field rule as the HTTP body.

### 5.11 Extensions ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **PUB-122** `Extension` MUST be an artefact kind published through this flow without exception: review (PUB-010), reproducible build and provenance (PUB-020–PUB-033), the publisher threshold from the keys the trust bundle lists for the kind `Extension` (PUB-040), the transparency log (PUB-050) and withdrawal (PUB-080). Its content address MUST be WIRE-011 (not salted).
- **PUB-123** An extension MUST pass `fieldseal extension validate` (the closed meta-schema, additive-only and naming rules of INS-239–INS-251) before it can be submitted (PUB-003). Approving reviewers MUST include one for each language the extension declares, as PUB-014 requires of instruments.
- **PUB-124** Publishing MUST refuse a minor or patch version of a named extension that removes an entry or changes an entry's meaning compared with the previous published version (`fieldseal extension diff`, INS-250).
- **PUB-125** The provenance predicate of an instrument MUST list the standard catalogue and every extension the instrument references as `resolvedDependencies` (name and content address as digest), in addition to PUB-031. The builder MUST resolve each through the registry and MUST fail the build if one is unpublished, withdrawn or not allowed by publishing policy. The registry MUST reject an instrument publication whose extension is not published.
- **PUB-126** When an extension is withdrawn (PUB-080), the factory MUST stop building bundles that contain any instrument referencing it (PUB-081). Bundles MUST carry the withdrawal (PUB-082). A runtime MUST refuse to start new records against such an instrument and MUST still allow review, export and clear of records already made. Intake MUST treat records as PUB-083 does.
- **PUB-127** The `artefact.publish` decision for an `Extension`, and for an instrument that references one, MUST evaluate the effective `publishing.extensions` control (POL-063): the extension's name or address MUST be in `allow`, every provided kind in `kinds`, and the count per instrument within `maxPerInstrument`.

## 6. Resources and formats

### 6.1 Publication

```cddl
artefact-fields = (
  "kind": "Instrument" / "Layout" / "Localisation" / "Extension" / "Policy" / "TrustBundle" / "Deployment",   ; "Extension": ADR 0037
  "name": tstr, "version": tstr,
  "address": hash,                        ; fingerprint for an instrument (PUB-092), else WIRE-011
  "artefact": bstr,                       ; canonical bytes
  ? "salt": bstr .size 32                 ; present exactly for an instrument (PUB-090, PUB-091)
)
signer-sig = { "signer": key-id, "sig": signature }
log-record = { "entry": bstr,             ; a LogEntry (WIRE-191)
               "leaf": "fieldseal/v1" / "hashedrekord/v0.0.1",   ; how the log hashed it (WIRE-194)
               "index": uint, "inclusion": [* hash] }             ; RFC 9162 audit path
provenance = { "statement": bstr, "signer": key-id, "sig": signature }
              ; statement: canonical in-toto Statement v1 with an SLSA Provenance v1 predicate;
              ; sig: builder key over fieldseal.dev/provenance/v1 (PUB-032)

publication = {
  artefact-fields,
  "provenance": provenance,
  "signatures": [+ signer-sig],           ; fieldseal.dev/artefact/v1 over
                                          ; {kind, name, version, address, provenance_sha256} (PUB-041)
  "log": [+ log-record],                  ; exactly one per signature (PUB-103, WIRE-193)
  "checkpoint": bstr,                     ; the C2SP signed note every proof is against (WIRE-192)
  ? "checkpoint_time": bstr               ; the authority time token that accompanied it (PUB-061, PUB-072)
}
publication-draft = { artefact-fields, "provenance": provenance,
                      "approvals": [* { "signer": key-id, "sig": signature, "entry": bstr }] }

withdrawal-fields = ( "address": hash, "provenance_sha256": hash, "reason": tstr, "issued": ms-time )
withdrawal = { withdrawal-fields,
               "signatures": [+ signer-sig],   ; fieldseal.dev/withdrawal/v1 over withdrawal-fields
               "log": [+ log-record], "checkpoint": bstr }
withdrawal-draft = { withdrawal-fields, "approvals": [* { "signer": key-id, "sig": signature, "entry": bstr }] }
```

- `provenance_sha256` is SHA-256 of the provenance `statement` bytes. A withdrawal names the withdrawn publication's `provenance_sha256`, and its log entries sign the `PublicationStatement` `{withdraw, address, provenance_sha256}`; the `reason` is signed, never logged.
- Publisher and builder certificates are checked at the provenance's `finishedOn` time; a withdrawal's at its `issued` time. A key revoked with effect at or before that time is refused (TRU-042); a later revocation or rotation doesn't invalidate what the key signed while valid (TRU-015).
- `checkpoint_time` is the encoded authority time token (a `receipt`-key `time-token`, [Distribution](./distribution.md)) obtained with the checkpoint. It is not covered by the publisher signatures; a consumer verifies the token itself against its trust bundle, and measures the tree head's age from it (PUB-072). A publication without it is valid but its tree head is too old for any runtime.
- A publication is refused as a whole if any signature in it is invalid, duplicated, or by a key not listed for the kind: signatures are not skipped.
- The log signs its own checkpoints (PUB-053 withdrawn), so the tag `fieldseal.dev/tree-head/v1` is reserved and unused.

### 6.2 Artefact metadata (common to every kind)

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Instrument            # or Layout, Localisation, Extension , Policy, TrustBundle, Deployment
metadata:
  name: baseline-intake     # lower-case, hyphenated, unique per kind within an authority
  version: 1.2.0            # semantic version of this artefact
  labels: { programme: example }
spec: { … }                 # defined by the kind's spec
```

### 6.3 Publishing policy fields

These live in a `Policy` under `spec.publishing` ([Policy](./policy.md)):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `requiredApprovals` | int ≥ 1, per kind | 2 | Approving reviews needed |
| `authorMayApprove` | bool | false | Whether the author counts as a reviewer |
| `publisherThreshold` | `{m, n}` per kind | `{2, 3}` | Signatures needed from listed publisher keys |
| `allowedBuilders` | list of builder identities | — | Builders whose provenance is accepted |
| `allowedSources` | list of repository URLs | — | Sources whose revisions may be published |
| `requireTransparencyLog` | bool | true; MUST be true in production | Whether inclusion is required |
| `requiredWitnessCosignatures` | int | 0 | Witness cosignatures a checkpoint needs (PUB-109) |
| `withdrawalThreshold` | `{m, n}` | same as publishing | Signatures needed to withdraw |
| `extensions` | `{allow, kinds, maxPerInstrument}` | `{[], [units, codeLists, conceptSchemes], 4}` | Which extensions may be published and used (POL-063): `allow` is a list of extension names or content addresses and merges by intersection; `kinds` is a subset of what an extension may provide and intersects; `maxPerInstrument` is a ceiling and tightens |
| `layoutLint` | `{maxDecisionsPerScreen, maxVisibleOptions, maxScaleStepsCompact, blocking}` | `{7, 9, 7, []}` | Thresholds for the choice-load lints INS-210 to INS-213, and which of them block publication |

## 7. Twelve-factor

- **Codebase (I):** artefacts live in source repositories, separate from the Fieldseal codebase; one pipeline definition publishes any artefact kind.
- **Config (III):** the log, registry, builder identity and key references come from the environment.
- **Backing services (IV):** the review system, transparency log, registry and key custody are attached resources.
- **Build, release, run (V):** build is canonicalisation and provenance; release is signing, logging and registry upload; nothing is edited after build.
- **Processes (VI), disposability (IX):** pipeline steps are stateless and idempotent by content address; re-running a step yields the same result.
- **Logs (XI):** every step emits structured events naming the content address.
- **Admin processes (XII):** signing, publishing and withdrawal run as `fieldseal artefact` commands.
- **Port binding (VII), concurrency (VIII):** the log and registry services bind ports and scale as their adapters allow.

## 8. Conformance

- `fieldseal instrument validate | lint | hash`, `fieldseal policy validate` and the equivalent for other kinds check PUB-001 to PUB-004 and PUB-020 to PUB-022.
- `fieldseal artefact provenance | sign | verify | publish | withdraw` implement the pipeline; `fieldseal log append | prove | verify` exercise the log port.
- Tests MUST cover: a change after approval, author self-approval, a below-threshold signature set, a signature from a non-publisher key, a forged provenance builder, a missing or wrong inclusion proof, an inconsistent tree head, a withdrawn artefact in a bundle, and a runtime rejecting a factory-signed bundle whose instrument lacks publisher signatures.
- **`TransparencyLog` contract suite** (`fieldseal conformance run --suite transparency-log [--adapter <name>]`), MUST pass for every adapter before it is used:
  - a recording backend captures every outbound request; the test fails if any field, header, tag or body content other than the four `LogEntry` fields (in the backend's mapped form) is sent (PUB-104, PUB-105);
  - the domain API offers no way to append anything but a `LogEntry` (a compile-time check in typed languages, a schema check otherwise) (PUB-102);
  - inclusion proofs and checkpoints returned by the adapter verify offline against the pinned log key (PUB-106);
  - malformed or oversized responses are rejected;
  - the same table of cases passes through the HTTP and the gRPC adapter (PUB-110, PUB-111).
- **Identity tests:** a certificate signing request with a subject name, email or extra attribute is rejected; provenance naming a reviewer by email fails registry acceptance (PUB-107, PUB-108; TRU-090–TRU-092).
- `fieldseal conformance run --suite publishing` runs the suite against an implementation.

## 9. Open questions

1. *Resolved by [ADR 0030](../../explanation/adr/0030-public-transparency-log.md):* a public transparency log; witness cosignatures optional by policy.
2. *Resolved by [ADR 0030](../../explanation/adr/0030-public-transparency-log.md).*
3. Should `Deployment` manifests need the same review and signature thresholds as instruments, or a separate operator threshold?
4. What `maxTreeHeadAge` suits devices that stay offline for long campaigns?

## 10. References

- ADRs [0009](../../explanation/adr/0009-publishing-with-provenance.md), [0010](../../explanation/adr/0010-declarative-instruments.md), [0011](../../explanation/adr/0011-policy-as-signed-files.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- in-toto Attestation Framework (Statement v1), SLSA Build Provenance v1, RFC 9162 (Certificate Transparency v2.0, Merkle tree and proofs), Semantic Versioning 2.0.0
