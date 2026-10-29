# Delivery

**Prefix:** `DEL` · **Context:** Delivery · **Runs in:** runtime, intake · **Status:** Draft

## 1. Scope

Delivery moves sealed records from a tenancy to the authority and tells the collector, honestly, what is known to have arrived. It owns:

- background upload, and the receipts that come back;
- export files: building, self-verifying, optional parity, naming, and handing them to a destination;
- destination classes and the labels shown to the collector;
- outbox exports for closed tenancies;
- receipts as anchors and as the delivery condition for clear.

It does not own the byte formats (WIRE §export, WIRE §receipt, WIRE §record), the decision to clear (Collection), or verification at the authority (Intake).

## 2. Domain model

| Element | Kind | Description |
|---|---|---|
| `DeliveryState` | Aggregate (per tenancy) | For each record `seq`: whether it is covered by a receipt, a checked copy, or a handed-over copy. |
| `Export` | Entity | One export file built from the journal (or an outbox part): `export_id`, `seq` range, parity flag, content hash, destination attempts. |
| `DestinationAttempt` | Value object | One hand-over of an export: destination class, outcome, label, time hint. |
| `DestinationClass` | Value object | `upload`, `local`, `removable`, `cloud`, `share`. Decided from the destination, never from the collector's word. |
| `DeliveryLabel` | Value object | `Received`, `Saved and checked`, `Handed over — not confirmed`, `Failed`. |
| `Receipt` | Value object | Authority-signed acknowledgement: tenancy, last `seq`, journal hash through that `seq`, authority time (WIRE §receipt). |
| `UploadSession` | Entity | One background upload: records sent, proof-of-possession tokens, receipt expected. |

**Invariants**

- A record counts as delivered only through a receipt or a checked copy; a handed-over copy never counts.
- A receipt covers exactly the records whose `seq` is at or below its `last_seq` and whose chain hashes to its journal hash.
- Delivery state only moves forward.

**Domain events:** `ExportBuilt`, `ExportVerified`, `CopySavedAndChecked`, `CopyHandedOver`, `UploadAccepted`, `ReceiptVerified`, `DeliveryConditionMet`.

## 3. Driving ports

| Port | Input | Output | Errors |
|---|---|---|---|
| `StartBackgroundUpload` | tenancy | `UploadSession` | `NoNetwork`, `NotRegistered`, `TokenRejected` |
| `BuildExport` | tenancy or outbox part, parity choice | `Export` (in private storage) | `VerificationFailed`, `StorageFull` |
| `DeliverExport` | `Export`, destination handle | `DestinationAttempt` | `WriteFailed`, `ReadBackMismatch`, `DestinationNotAllowed` |
| `ImportReceipt` | receipt bytes (from upload, file or QR) | updated `DeliveryState` | `BadSignature`, `UnknownTenancy`, `HashMismatch` |
| `QueryDeliveryState` | tenancy | per-`seq` delivery state, outstanding count | — |

## 4. Driven ports

| Port | Contract |
|---|---|
| `UploadEndpoint` | Accepts an upload body and a proof-of-possession token; returns a receipt or a typed error. MUST be idempotent: re-sending the same records returns an equivalent receipt. In code it is `UploadTransport`, which also carries the receiver challenge (DEL-062): `challenge(address, challenge)` returns the receiver's answer, `upload(destination, request)` takes only a destination that passed it. |
| `ReceiverCheck` | Judges a destination's answer to the receiver challenge against the trust bundle (TRU): a current, unrevoked `receiver` certificate chaining to the root, and its signature over exactly this challenge. Never judges by address, domain name or TLS certificate. |
| `RegistrationRecords` | The tenancy certificate and registration request that WIRE-104 puts in a manifest, where the runtime doesn't hold them itself. |
| `ProofSigner` | Signs a proof-of-possession token with the tenancy's signing key (PLAT §KeyStore). |
| `FileAccess` | Writes to a destination chosen by the platform's file picker, syncs it to storage, and reads it back (PLAT §FileAccess). Reports the destination's provider identity so the class can be decided. |
| `ShareTarget` | Hands a file to another app; reports only success or failure. |
| `PrivateStorage` | Device-encrypted storage for exports being built (PLAT §Storage). |
| `ReceiptVerifier` | Verifies a receipt against the trust bundle (TRU). Owned by [Collection](./collection.md) as `ReceiptCheck`, because only a verified receipt may authorise journal deletion (COL-105); Delivery uses that port. |
| `QrScanner` | Reads a QR code from the camera into memory (PLAT §Camera). |

## 5. Requirements

### Background upload

- **DEL-001** When the device has a network connection and the tenancy is registered, the runtime MUST upload records not yet covered by a receipt, without collector action.
- **DEL-002** Each upload request MUST carry a proof-of-possession token: a short-lived token signed by the tenancy's signing key, bound to the request method, the endpoint URL and a fresh nonce or timestamp from the endpoint (WIRE §pop-token).
- **DEL-003** The upload endpoint MUST reject a request whose token is expired, replayed, bound to another request, or signed by a key that isn't registered and unrevoked.
- **DEL-004** The runtime MUST NOT use identity-provider tokens for upload.
- **DEL-005** Upload failures MUST be retried with exponential backoff and jitter. A failure MUST NOT block collection, export or close.
- **DEL-006** The upload endpoint MUST return a receipt for every accepted upload, signed by the authority's receipt key (TRU).
- **DEL-007** The runtime MUST verify a receipt's signature, tenancy and journal hash before changing any delivery state.
- **DEL-008** Uploading MUST be idempotent: records already received MUST NOT be duplicated, and the receipt MUST cover the highest contiguous `seq` the authority holds.

### Building an export

- **DEL-010** An export MUST contain the tenancy's journal from the first record not yet cleared through the last record, in the WIRE §export format.
- **DEL-011** The export MUST be built in private, device-encrypted storage before it is offered to any destination.
- **DEL-012** Before an export is offered, the runtime MUST verify it in full with the same format-core verifier intake uses, minus decryption: envelope, record signatures, chain, ticks, manifest seal, parity (if present) and file signature.
- **DEL-013** An export that fails self-verification MUST NOT be offered to any destination, and the runtime MUST tell the collector that export failed.
- **DEL-014** The runtime MUST include Reed–Solomon parity (WIRE §parity) when runtime policy `runtime.export.parityDefault` is `on` and the collector hasn't turned it off for this export. For file exports the policy default MUST be `on` unless the deployment's runtime policy says otherwise.
- **DEL-015** The collector MAY turn parity off for a single export; the choice MUST NOT persist to the next export.
- **DEL-016** Upload MUST NOT include parity.
- **DEL-017** The export file name MUST be `<prefix> export <YYYY-MM-DD> (<n>).<ext>`, where the prefix and extension come from the deployment's runtime policy, the date is the device's wall-clock date, and `n` increments per tenancy. The name MUST NOT contain any subject, cohort, collector, device or count information.
- **DEL-018** The export MUST be cumulative: building a new export MUST NOT depend on earlier exports having arrived.

### Destinations and labels

- **DEL-020** The runtime MUST decide the destination class from the platform's report of the destination provider (PLAT §FileAccess), never from what the collector selects or types.
- **DEL-021** The runtime MUST offer only destinations allowed by runtime policy `runtime.export.destinations`.
- **DEL-022** For `local` and `removable` destinations, the runtime MUST write the file, sync it to the storage device, read it back through the same destination handle, and compare its SHA-256 with the built export.
- **DEL-023** If the read-back hash matches, the label MUST be **Saved and checked**. If it doesn't, the label MUST be **Failed** and the attempt MUST NOT count as a copy.
- **DEL-024** For `cloud` destinations, the runtime MUST NOT claim a read-back check, and the label MUST be **Handed over — not confirmed**.
- **DEL-025** For `share` destinations, the label MUST be **Handed over — not confirmed**.
- **DEL-026** For `upload`, the label MUST be **Received** once a verified receipt covers the export's last `seq`.
- **DEL-027** Labels MUST be exactly the strings above, translated only through the runtime's localisation catalogue with the same meaning.
- **DEL-028** The runtime MUST NOT store a destination's name, path or account after the delivery screen closes. It MAY store the destination class and label.
- **DEL-029** Exporting the active tenancy MUST require an unlocked session. Exporting the outbox MUST NOT require one, because the outbox holds only sealed data.

### Delivery condition and clear

- **DEL-030** A record's delivery state MUST be one of `none`, `handed-over`, `saved-and-checked`, `received`.
- **DEL-031** *Withdrawn ([ADR 0029](../../explanation/adr/0029-clear-anytime-with-pin-confirmation.md)): clearing no longer depends on a delivery condition.*
- **DEL-070** Delivery MUST tell Collection which `seq` ranges are covered by a verified receipt; only those journal records may be deleted (COL-105, COL-106).
- **DEL-071** An upload endpoint MUST resolve the tenancies it accepts from Registration's registry through the `TenancyRegistry` port, and sign receipts and its receiver answer with the keys of the authority whose trust bundle the devices hold. A device registered through the factory therefore uploads to that authority's endpoint, and its receipts verify against the same trust bundle (DEL-064). With `FIELDSEAL_INTAKE_PUBLISHED_DIR` and `FIELDSEAL_INTAKE_ROSTERS_DIR` its gate validates answers against the instruments published through the authority's log (each publication verified against the trust bundle, INT-070) and checks consent against the rosters the authority issued to each tenancy. The endpoint is served by the intake app (`fieldseal-intake`), which has no authority switch: it serves the authority named by its custody and trust bundle. A practice mode with its own authority and devices (`fieldseal-upload-practice`) is for development and conformance runs only.
- **DEL-032** Delivery MUST report to Collection, for any `seq` range, whether the delivery condition is met for every record in it.
- **DEL-033** A handed-over copy MUST NOT satisfy any delivery condition.

### Receipts

- **DEL-040** A verified receipt MUST be appended to the journal as an anchor record (WIRE §anchor), so its authority time bounds later ticks.
- **DEL-041** A receipt for a closed tenancy MUST mark the matching outbox part as delivered; the runtime MAY then delete that part.
- **DEL-042** The runtime MUST accept receipts from upload responses, from files, and from QR codes scanned from a screen, with the same verification.
- **DEL-043** A receipt in QR form MUST fit in a single QR code (WIRE §receipt sets the compact encoding).
- **DEL-044** The portal MUST offer the receipt of any accepted upload or uploaded export as a QR code and as a file, so an air-gapped device can import it.

### Outbox

- **DEL-050** An outbox export MUST contain one part per closed tenancy whose journal hasn't been receipted, each signed by its closing manifest (WIRE §export), and MUST be buildable without any live key.
- **DEL-051** The outbox export MUST be offered from the device's management screen without a session, and from any active tenancy's delivery screen.
- **DEL-052** Uploading the outbox MUST use a proof-of-possession token from the active tenancy if there is one; otherwise it MUST use the outbox upload route, which accepts only parts whose closing manifests verify.

### Authorised destinations ([ADR 0021](../../explanation/adr/0021-export-upload-receipts.md))

- **DEL-060** The runtime build MUST NOT contain any destination address.
- **DEL-061** The runtime MAY learn destination addresses from device configuration, a scanned QR code, collector entry, a previous successful upload, or an advisory hint in a bundle, and MUST treat every address as untrusted.
- **DEL-062** Before sending any record, the runtime MUST complete the receiver challenge (WIRE §receiver-challenge) and MUST NOT upload unless the `receiver` certificate chains to its trust root, is current and unrevoked, and the signature verifies.
- **DEL-063** A failed challenge MUST NOT be retried at the same address within the same session, and MUST be logged without personal data.
- **DEL-064** The runtime MUST accept a receipt only if it is signed by a `receipt` key chaining to the same trust root, whatever address it came from.
- **DEL-065** When several authorised destinations are known, the runtime SHOULD try them in the order last-successful, configured, hinted.
- **DEL-066** A change of an authority's domain names or hosts MUST NOT require any change to runtimes or bundles.
- **DEL-076** Every reader of a Delivery input (the receiver challenge and proof, a receipt and an upload response, the retry state kept in private storage, and the opened export manifest a verifier reads) MUST reject unknown fields, enforce exact types and fixed byte lengths, require every required field, and enforce every declared constraint (versions, enumerations, key-entry shape, sizes before parsing). A verifier MUST report a manifest that breaks the closed WIRE manifest schema as an error; it MUST NOT skip the offending field.

### Service contract and transports ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md))

*gRPC is built in slice 2; the HTTP routes are built.*

- **DEL-072** The upload endpoint's operations are the `Upload` contract (`fieldseal.v1.Upload`), defined once; HTTP is a mapping of it. Payloads (the challenge and answer, the export file, the receipts) are opaque canonical CBOR `bytes` and MUST NOT be re-encoded (WIRE-196).

| rpc | HTTP | Authentication |
|---|---|---|
| `Challenge` | `POST /v1/challenge` | none |
| `Upload` | `POST /v1/upload` | PoP |
| `UploadOutbox` | `POST /v1/upload/outbox` | none (closing manifests are verified) |

- **DEL-073** Over gRPC the PoP token (WIRE-170) MUST be bound to method `POST` and to the URL `https://<authority>/fieldseal.v1.Upload/<Method>`, where the authority is one the endpoint is configured to answer at (DEL-066); a token minted for one operation or transport MUST be refused on any other.
- **DEL-074** Failures MUST map between HTTP and gRPC as follows, with the stage and code carried as a `google.rpc.ErrorInfo` detail of the `google.rpc.Status` (`reason` = the code, `domain` = `fieldseal.dev`, `metadata.stage`), and no personal data:

| HTTP | gRPC status |
|---|---|
| `400` | `INVALID_ARGUMENT` |
| `401` | `UNAUTHENTICATED` |
| `403` | `PERMISSION_DENIED` |
| `404` | `NOT_FOUND` |
| `405` | `UNIMPLEMENTED` |
| `409` | `ALREADY_EXISTS` or `FAILED_PRECONDITION` |
| `413` | `RESOURCE_EXHAUSTED` (message over the limit, which MUST equal the HTTP body limit) |
| `422` | `FAILED_PRECONDITION` (the gate refused the body) |
| `429` | `RESOURCE_EXHAUSTED` |
| `503` | `UNAVAILABLE` (retry, DEL-005) |
| `504` | `DEADLINE_EXCEEDED` |

- **DEL-075** The `Upload` contract suite MUST be one table of cases executed through every transport adapter against the same in-memory endpoint (REG-087). Built in slice 2.

## 6. Resources and formats

Delivery defines no resource kinds. It defines the upload endpoint's HTTP binding, which carries only structures from WIRE:

| Method and path | Auth | Body | Answer |
|---|---|---|---|
| `POST /v1/challenge` | none | the challenge (WIRE-180, canonical CBOR) | the receiver's answer (WIRE-181, canonical CBOR) |
| `POST /v1/upload` | `Fieldseal-PoP` (WIRE-172) | an export file without parity | a canonical CBOR array of receipts (WIRE-142), one per tenancy part acknowledged |
| `POST /v1/upload/outbox` | none; the gate verifies each closing manifest (DEL-052) | an export file without parity | as above |

A token is bound to `POST` and to `<base URL><path>` for a base URL the endpoint is configured to answer at (factor III); an authority that adds or changes a host name adds it to the endpoint's configuration and to nothing on a runtime or in a bundle (DEL-066). Refusals are `401` (token, DEL-003), `422` (the gate refused the body; the answer names its stage and code, no personal data), `400` (malformed) and `503` (a backing service failed; retry, DEL-005).

It uses:

| Format | Defined in |
|---|---|
| Export file, header, manifest, parity | WIRE §export, WIRE §parity |
| Receipt and its compact QR encoding | WIRE §receipt |
| Proof-of-possession token | WIRE §pop-token |
| Anchor record | WIRE §anchor |

Runtime policy keys used (POL):

```yaml
runtime:
  export:
    parityDefault: on            # on | off
    allowParityOff: true
    destinations: [upload, local, removable, cloud, share]
    filePrefix: "Fieldseal"
    fileExtension: "fieldseal"
  upload:
    background: true
    retryBackoff: [1m, 5m, 30m, 2h]
  retention:
    offerClearOnReceipt: true
```

## 7. Twelve-factor

| Factor | Runtime side | Upload endpoint (intake) |
|---|---|---|
| III. Config | Destinations, parity default, naming and upload settings come from signed runtime policy; destination addresses are untrusted hints from any source; authorisation is by receiver key (DEL-060–DEL-066) | Endpoint URL, receipt key reference and limits from the environment |
| IV. Backing services | The upload endpoint is an attached resource named in the bundle | Object store and receipt signer are attached resources |
| VI. Processes | Delivery state is in the journal and private storage; the UI can be killed at any time | Stateless; uploaded bodies go to the object store |
| VII. Port binding | Not applicable on the device | Binds an HTTPS port |
| IX. Disposability | Building, writing and checking an export resume from a persisted marker; a half-written export is discarded | Uploads are idempotent; a retried request yields an equivalent receipt |
| XI. Logs | Structured events (`ExportBuilt`, label outcomes) with no destination names or personal data | Structured events to stdout, no personal data |

## 8. Conformance

| Test | Covers | Check |
|---|---|---|
| Upload with a valid token returns a receipt; replayed, expired or mis-bound tokens are rejected | DEL-001–008 | `fieldseal device simulate --upload`, `fieldseal receipt verify` |
| Self-verification refuses a corrupted export | DEL-012–013 | `fieldseal export verify` on golden corrupted files |
| Parity on by default for files, off for upload; one-off opt-out doesn't persist | DEL-014–016 | `fieldseal export inspect --json` |
| File names carry only date and counter | DEL-017 | Golden name list |
| Labels by destination class, including a read-back mismatch | DEL-020–028 | Platform contract tests with fake providers |
| Receipt marks records delivered and becomes an anchor | DEL-030–044 | `fieldseal receipt issue` then `device simulate --import-receipt` |
| Upload contract table passes through HTTP and gRPC; error mapping | DEL-072–DEL-075 | `fieldseal conformance run --suite service-contracts --service upload` |
| Outbox export builds without live keys and uploads on the outbox route | DEL-050–052 | `fieldseal device simulate --close` then `export verify` |
| Closed schemas on the retry state and the opened export manifest | DEL-076 | `del_076_*` in `application.rs`; `del_076_manifest_*` in `export.rs` |

## 9. Open questions

1. Should `cloud` destinations from an allow-list of providers with server-side checksums ever count as checked? (Default: no.)
2. Prefix and extension defaults: is a neutral default (`Fieldseal`, `.fieldseal`) acceptable, or must each deployment set its own?

## 10. References

- ADRs: [0007](../../explanation/adr/0007-zero-trust-posture.md), [0014](../../explanation/adr/0014-multi-device-and-air-gapped.md), [0016](../../explanation/adr/0016-tenancies-with-crypto-erase.md), [0019](../../explanation/adr/0019-review-until-clear.md), [0020](../../explanation/adr/0020-monotonic-ticks.md), [0021](../../explanation/adr/0021-export-upload-receipts.md), [0025](../../explanation/adr/0025-twelve-factor-deployments.md)
- RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession), whose token shape the proof-of-possession token follows
