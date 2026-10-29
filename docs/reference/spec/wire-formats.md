# Wire formats

**Prefix:** `WIRE` · **Context:** Shared kernel · **Status:** Draft · **ADRs:** [0004](../../explanation/adr/0004-bounded-contexts.md), [0005](../../explanation/adr/0005-format-core.md), [0007](../../explanation/adr/0007-zero-trust-posture.md), [0018](../../explanation/adr/0018-dual-write-records.md), [0020](../../explanation/adr/0020-monotonic-ticks.md), [0021](../../explanation/adr/0021-export-upload-receipts.md)

## 1. Scope

This spec defines every byte that crosses a context boundary: records and the journal, the local record envelope, bundles, export files, registration tokens and requests, certificates, receipts and time tokens, and the rules for encoding, signing and sealing them. It is the published language between contexts and is implemented once, in the format core.

It does **not** define what the bytes mean for a context's behaviour (when a record is written, when a bundle is released). That is in the context specs, which cite these structures. Trust material (key certificates, trust bundles) is in [Trust](./trust.md); artefacts and publishing evidence are in [Publishing](./publishing.md).

## 2. Domain model

The shared kernel has no behaviour of its own. Its value objects are:

| Value object | Meaning |
|---|---|
| `ContentAddress` | `sha256:` and the SHA-256 of an object's canonical bytes |
| `DomainTag` | A text string `fieldseal.dev/<purpose>/<version>` naming what a signature or seal is for |
| `Signature` | An ECDSA P-256 signature over a domain-tagged structure |
| `Sealed<T>` | An HPKE encapsulation and ciphertext whose plaintext is a canonical `T` |
| `Frame` | A length-prefixed, checksummed container for one record |
| `RecordHeader` | The plaintext part of a record: identity, order and chain fields only |
| `RecordPayload` | The sealed part of a record, one of the record types below |
| `Tick` | A record's monotonic time |
| `ExportFile`, `BundleFile`, `RegistrationToken`, `RegistrationRequest`, `TenancyCertificate`, `CloseCertificate`, `ResetCertificate`, `Receipt`, `TimeToken` | The exchanged objects |

Invariant: a value object that fails any check in this spec does not exist. Decoders return an error code (§6.12), never a partial object.

## 3. Driving ports

The format core offers these operations to every context, through bindings:

| Port | Input | Output | Errors |
|---|---|---|---|
| `Encode<T>` / `Decode<T>` | value / bytes | canonical bytes / value | `E_CBOR_*`, `E_SIZE`, `E_UNKNOWN_FIELD` |
| `Sign` / `Verify` | tag, structure, key | signature / verdict | `E_SIG`, `E_TAG` |
| `Seal` / `Open` | tag, plaintext, recipient key | `Sealed<T>` / plaintext | `E_SUITE`, `E_DECRYPT` |
| `FrameRecord` / `ReadFrames` | record / bytes | frame / records and damage report | `E_FRAME_*`, `E_CRC` |
| `VerifyChain` | records | verdict, gaps | `E_CHAIN`, `E_SEQ` |
| `BuildExport` / `VerifyExport` / `RepairExport` | journal, manifest / file | file / verdict / repaired file | `E_EXPORT_*`, `E_PARITY` |
| `FingerprintWords` | registration request body | four words | — |

## 4. Driven ports

The format core performs no I/O. Signing, agreement and decryption with keys it does not hold go through the [Trust](./trust.md) ports `SecureKeyStore` and `KeyCustody`. Randomness comes from a `RandomSource` port, whose adapters MUST use the platform's cryptographically secure generator.

## 5. Requirements

Other specs refer to sections of this one by topic name, written **WIRE §topic**:

| Topic | Section |
|---|---|
| `canonical`, `canonical-encoding`, `content-address`, `identifiers` | §5.1, §6.2 |
| `signatures`, `seals`, `attestation` (the evidence envelope) | §5.2, §5.10 (WIRE-133), §6.1 |
| `record`, `records`, `journal`, `record-payload`, `anchor`, `anchors` | §5.3, §5.4, §6.3 |
| `ticks` | §5.5 |
| `local-record`, `session-key` (envelope; derivation is in [Trust](./trust.md)) | §5.6 |
| `bundle` | §5.7, §6.4 |
| `export`, `parity` | §5.8, §6.5 |
| `registration-messages`, `fingerprint-words` | §5.9, §5.10, §6.6 |
| `certificates`, `receipt` | §5.11, §6.6 |
| `pop-token` | §5.13 |
| `animated-qr` | §5.14 |
| `receiver-challenge` | §5.15 |
| `log-entry`, `checkpoint`, log leaves | §5.17 |
| `instrument-fingerprint` | §5.16 |


### 5.1 Encoding

- **WIRE-001** Every structure in this spec MUST be encoded as deterministic CBOR following RFC 8949 §4.2.1 (core deterministic encoding): shortest-form integers and lengths, definite lengths only, map keys sorted by the bytewise order of their encodings.
- **WIRE-002** A decoder MUST reject input that is not in deterministic encoding, with `E_CBOR_NONCANONICAL`. Re-encoding a decoded value MUST yield the input bytes exactly.
- **WIRE-003** Maps MUST NOT contain duplicate keys. A decoder MUST reject duplicates with `E_CBOR_DUPLICATE`.
- **WIRE-004** Map keys in this spec's structures MUST be text strings. Text MUST be valid UTF-8 in Unicode Normalization Form C.
- **WIRE-005** A decoder MUST reject any map key not defined for the structure's version, with `E_UNKNOWN_FIELD`. Extension happens only through a new structure version.
- **WIRE-006** Floating-point values MUST NOT appear. Non-integer numbers MUST be decimal fractions (CBOR tag 4, `[exponent, mantissa]`) with the exponent equal to the scale declared for that value, so that one number has one encoding.
- **WIRE-007** The only CBOR tags permitted are tag 4 (decimal fraction). Any other tag MUST be rejected with `E_CBOR_TAG`.
- **WIRE-008** Times issued by the authority MUST be unsigned integers counting milliseconds since the Unix epoch, UTC. Durations MUST be unsigned integers in milliseconds.
- **WIRE-009** Public keys MUST be encoded as: P-256 keys in uncompressed SEC1 form (65 bytes); X25519 keys as 32 raw bytes.
- **WIRE-010** A key identifier (`key_id`) MUST be the first 16 bytes of SHA-256 over the encoded public key.
- **WIRE-011** A `ContentAddress` MUST be the 32-byte SHA-256 of an object's canonical bytes; its text form MUST be `sha256:` followed by 64 lowercase hexadecimal digits.

### 5.2 Domain tags, signatures and seals

- **WIRE-020** Every signature and every seal MUST be bound to exactly one domain tag from §6.1. A verifier MUST check the tag before the signature, and MUST reject an unknown or unexpected tag with `E_TAG`.
- **WIRE-021** The signed message for structure `S` under tag `t` MUST be the canonical CBOR array `[t, S]`, where `S` is the structure without its signature field. The signature MUST be ECDSA over P-256 with SHA-256 of that message.
- **WIRE-022** Signatures MUST be encoded as 64 bytes, `r ‖ s`, each 32 bytes big-endian, with `s` in low form (`s ≤ n/2`). A verifier MUST reject high-`s` signatures with `E_SIG`.
- **WIRE-023** Sealing MUST use HPKE (RFC 9180) in base mode, with the `info` parameter set to the domain tag's UTF-8 bytes, followed, where a structure names a context, by a zero byte and the context (a bundle's context is its tenancy ID, WIRE-091). The suites are fixed per recipient key type:

  | Recipient | KEM | KDF | AEAD | Suite ID |
  |---|---|---|---|---|
  | Authority keys (record, registration) | DHKEM(X25519, HKDF-SHA256) `0x0020` | HKDF-SHA256 `0x0001` | ChaCha20-Poly1305 `0x0003` | `fs1-x` |
  | Device agreement keys | DHKEM(P-256, HKDF-SHA256) `0x0010` | HKDF-SHA256 `0x0001` | AES-256-GCM `0x0002` | `fs1-p` |

- **WIRE-024** A `Sealed<T>` MUST be encoded as `{"suite": tstr, "recipient": key_id, "enc": bstr, "ct": bstr}`. A recipient MUST reject a suite it does not expect for its key type with `E_SUITE`, and a `recipient` other than its own key with `E_RECIPIENT`.
- **WIRE-025** Where a structure is both sealed and signed, the signature MUST cover the sealed form (encrypt-then-sign), so verification precedes decryption.
- **WIRE-026** Implementations MUST perform the HPKE DH step through the key-store port when the private key is held by a key store, and MUST zeroise shared secrets and derived keys after use.

### 5.3 Records and the journal

- **WIRE-030** A journal MUST be a byte sequence of frames, each holding one record, in strictly increasing `seq` starting at 0.
- **WIRE-031** A frame MUST be laid out as: magic `46 53 52 31` ("FSR1"), version (1 byte, `0x01`), flags (1 byte, `0x00`; other values reserved), body length (4 bytes, big-endian), CRC-32C of the body (4 bytes, big-endian), body.
- **WIRE-032** A reader MUST locate frames by scanning for the magic, MUST verify length and CRC before decoding a body, and MUST report every damaged frame by byte offset instead of stopping at the first one.
- **WIRE-033** A record body MUST be the canonical CBOR `Record` (§6.3): a plaintext header, the payload sealed to the authority's record key for the tenancy's collection period, and the signature of the tenancy key named in the header.
- **WIRE-034** The record header MUST contain only `record_id`, `seq`, `prev`, `key` and `period`. Record type, subject, instrument, consent reference and tick MUST be inside the sealed payload.
- **WIRE-035** `record_id` MUST be 16 bytes from the random source, with the UUIDv4 version and variant bits set. It MUST NOT be used for ordering.
- **WIRE-036** The record hash MUST be SHA-256 of the canonical record body. `prev` MUST be the record hash of the record at `seq − 1`, and 32 zero bytes for `seq = 0`.
- **WIRE-037** The record signature MUST be over tag `fieldseal.dev/record/v1` and MUST cover the header and the sealed payload.
- **WIRE-038** The payload seal MUST use tag `fieldseal.dev/record-seal/v1` and suite `fs1-x`.
- **WIRE-039** The record at `seq = 0` MUST be of type `open`. A record of type `closing` MUST be the last record of a journal; a verifier MUST reject any record after it with `E_CHAIN`.
- **WIRE-040** A verifier MUST check, in this order: frame, header decoding, signature with the key named by `key` from the tenancy's key history, `prev` chain, `seq` continuity. Only then MAY it open the payload.
- **WIRE-041** After a `checkpoint` record, the journal MAY omit frames for `seq ≤ cleared_through`. The next present frame's `prev` MUST still be the hash of the record at its `seq − 1`, which the checkpoint states; a verifier MUST accept the chain across the gap by checking `prev` against the checkpoint's `hash_at`.
- **WIRE-042** A record MUST NOT exceed 4 MiB; an `evidence` record's `bytes` MUST NOT exceed 3 MiB.

### 5.4 Record payload types

- **WIRE-050** Every payload MUST carry `type` and `tick`. Types are: `open`, `items`, `status`, `consent`, `evidence`, `anchor`, `import`, `key-roll`, `checkpoint`, `closing`.
- **WIRE-051** An `items` payload MUST name the instrument's content address, the `layout` it was collected with (its content address, or `"default"` for the generated default layout, INS-209), `lang` (the BCP 47 tags of every instrument language shown during the capture, in order of first use, INS-087), the `subject`, the `consent_ref`, the `mode` (`first`, `resume`, `resurvey` or `correction`) and a `values` map from item path to value. The map MUST contain only items the collector set; an unset item MUST be absent, never null, zero or a default.
- **WIRE-052** An item value MUST be a text string, integer, decimal fraction, boolean, or array of these, or the single-key map `{"nr": "dont-know" / "refused"}` for a nonresponse (INS-141). The single-key map `{"retracted": true}` means the earlier value is withdrawn with no replacement. These two maps are the only permitted map values.
- **WIRE-053** An `items` payload MAY carry `overrides` (item path to reason code, for soft rules the collector confirmed) and `flags` (rule identifiers raised at sealing).
- **WIRE-054** A `status` payload MUST name the instrument, the subject and a status code (`absent`, `declined` or `not-subject`); it carries no item values.
- **WIRE-055** A `consent` payload MUST name the instrument, the subject, the basis code (from the instrument's list), the consent statement's content address, and zero or more evidence references `{blob_id, sha256, media_type, size}`.
- **WIRE-056** An `evidence` payload MUST carry `blob_id` (16 random bytes), `media_type` and `bytes`; the SHA-256 of `bytes` MUST equal the referencing consent record's `sha256`.
- **WIRE-214** The `media_type` of an `evidence` payload, and of each evidence reference in a `consent` payload, MUST be one of `image/jpeg`, `image/png` or `image/webp`. Readers MUST reject any other value, and writers MUST NOT emit one. (Evidence is a photograph captured on the device; the instrument media set of INS-180 does not apply.)
- **WIRE-057** An `anchor` payload MUST carry the anchor's kind (`build`, `bundle`, `receipt`, `time-token`), its content address and the authority time it states.
- **WIRE-058** An `import` payload MUST carry the content address of an imported bundle and of each artefact and roster version it loaded.
- **WIRE-059** A `key-roll` payload MUST carry the new key's index, public key and the content address of its attestation evidence. It MUST be signed by the outgoing key; records after it MUST name the new key.
- **WIRE-060** A `checkpoint` payload MUST carry `cleared_through` (a `seq`), `hash_at` (the record hash at that `seq`), and the delivery evidence that allowed the clear (a receipt's content address, or a saved-copy hash).
- **WIRE-061** A `closing` payload MUST carry `last_seq` (its own `seq`), the record hash of the record before it, and a reason (`collector`, `close-certificate`, `reset-certificate`, `returned`).
- **WIRE-062** An `open` payload MUST carry the tenancy ID, the signing and agreement public keys, the content addresses of their attestation evidence, and the runtime build's release anchor.

### 5.5 Ticks

- **WIRE-070** A tick MUST be `{anchor, slot, boot}` and MAY carry `wall`. `anchor` is the content address of the latest anchor chained into the journal (or the build anchor); `slot` is milliseconds elapsed since that anchor by the platform's monotonic clock; `boot` is the platform's boot counter; `wall` is the device's wall-clock time as an untrusted hint.
- **WIRE-071** Along a journal, `(anchor position, slot)` MUST strictly increase: a verifier MUST reject a tick whose anchor appears earlier in the chain than the previous record's anchor, or whose `slot` does not exceed the previous record's `slot` under the same anchor, with `E_TICK`.
- **WIRE-072** When `boot` increases under the same anchor, `slot` MUST continue from the persisted high-water mark, so it never decreases.

### 5.6 Local record envelope

- **WIRE-080** Each local record entry MUST be `{seq, nonce, ct}`: the plaintext record payload encrypted with AES-256-GCM under the session storage key, with a 12-byte random `nonce`.
- **WIRE-081** The AEAD additional data MUST be the canonical CBOR array `["fieldseal.dev/local-record/v1", tenancy_id, seq]`.
- **WIRE-082** A nonce MUST NOT be reused under one key; an implementation MUST rotate the storage key before 2³² encryptions.

### 5.7 Bundle file

- **WIRE-090** A bundle file MUST be: magic `46 53 42 31` ("FSB1"), then the canonical CBOR `BundleFile`: `{"sealed": Sealed<BundleContent>, "signer": key_id, "chain": [KeyCertificate], "sig": Signature}`.
- **WIRE-091** `sealed` MUST use tag `fieldseal.dev/bundle-seal/v1` and suite `fs1-p`, addressed to one registered agreement key, with the tenancy ID (32 bytes) as the HPKE context (WIRE-023).
- **WIRE-092** `sig` MUST be over tag `fieldseal.dev/bundle/v1` and the structure `{"sealed": …, "signer": key_id}` (the signed envelope, not the plaintext, and not `chain`, which is verified on its own), by a factory signing key whose chain reaches a root in the recipient's trust bundle. `chain` MUST hold at most the signer's own certificate, and MAY be empty when the recipient's trust bundle pins the signer.
- **WIRE-093** A bundle file MUST NOT exceed 64 MiB. A runtime MUST check the size before reading further, then `signer`, `chain` and `sig`, before opening `sealed`.
- **WIRE-094** `BundleContent` MUST carry: tenancy ID, the bundle sequence number (DIS-015), the factory's issue time (equal to the time token's authority time), a time token, each instrument as a `Publication` ([Publishing](./publishing.md); at least one, unless the bundle carries rosters and every assignment of its account was dropped, DIS-018, and no two sharing a survey name), the runtime policy as one `Publication` per contributing layer, outermost first (POL-050), and rosters; and MAY carry the tenancy certificate (omitted only for a practice bundle with no rosters, DIS-004), assignments (DIS-018), layouts (DIS-016), localisations (DIS-017), trust-bundle updates and withdrawals. An optional list MUST be left out when empty.
- **WIRE-096** An assignment in `BundleContent` MUST be `{survey, instrument, cohort, generation}`: `survey` the instrument's name as text, `instrument` the content address of an instrument in the same bundle (bstr(32)), and `cohort` and `generation` those of a roster in the same bundle. A decoder MUST refuse an assignment whose instrument is not in the bundle or does not have the survey's name, whose cohort and generation match no roster of the bundle, and a survey assigned twice to one cohort. `BundleManifest` lists the same assignments.
- **WIRE-095** A roster MUST carry `cohort`, `version`, `generation` and subjects `{ordinal, subject, display, attributes, consent, prior_status?}`, where `display` is the text shown to the collector, `attributes` carries values the instrument declares as roster-supplied, and `consent` is `granted`, `refused` or `unknown`. A roster MAY also carry `consent_covers`, a non-empty list of survey names (instrument names as text, without whitespace), sorted and without repeats, and MUST leave it out when it would be empty. A `granted` consent counts only for the surveys listed (COL-031, INT-031); `refused` is a refusal for every survey. A reader MUST refuse an empty, unsorted or repeating list and a name that is not text. This is an additive in-place amendment to the v1alpha1 roster: a roster without the key covers no survey. The roster issue form (WIRE-198) names the same list `consent-covers`.

- **WIRE-198** The `IssueRoster` request body is the roster issue form, canonical CBOR (WIRE-196): `{cohort, version, subjects, consent-covers?}`, each subject `{ordinal?, subject, display, consent?, prior_status?, fields?}` with `subject` as text and `fields` in place of WIRE-095's `attributes`. It MAY carry `consent-covers`, a list of survey names (possibly empty) that is stored as the roster's `consent_covers` (WIRE-095); when it carries none, the factory stores the surveys assigned to the cohort, in any account, when it accepts the roster (DIS-013). It carries no `generation`: a generation belongs to one cohort on one tenancy (DIS-014) and is assigned when the cohort reaches a tenancy. A body that carries `generation` or any unknown key MUST be refused as `roster-invalid`. The factory stores the roster in the WIRE-095 form with a placeholder generation that bundle building replaces.
- **WIRE-199** (provisional) The answer to `GET /entries/{from}/{to}` of the Fieldseal log MUST be, for each entry in order, a 4-byte big-endian length and the canonical `LogEntry` bytes (WIRE-191), at most 256 entries. Clients MUST refuse an entry that is not canonical and trailing bytes (PUB-110).

### 5.8 Export file

- **WIRE-100** An export file MUST be: magic `46 53 58 31` ("FSX1"), then a sequence of sections, each laid out as: section type (1 byte), length (4 bytes, big-endian), CRC-32C of the body (4 bytes, big-endian), body.
- **WIRE-101** Section types MUST be: `0x01` header, `0x02` sealed manifest, `0x03` journal, `0x04` parity, `0x05` signature, in that order; `0x04` is optional.
- **WIRE-102** The header body MUST be `{"format": "fieldseal.dev/export/v1", "handle": bstr(16), "parts": uint}`; whether a part has parity is shown only by the presence of its `0x04` section, so that parity stays outside the signature (WIRE-108). `handle` MUST be an opaque value issued in the tenancy certificate, or random for an unregistered tenancy; it MUST NOT be derived from any identifier.
- **WIRE-103** The manifest MUST be sealed with tag `fieldseal.dev/export-manifest-seal/v1` and suite `fs1-x`, to the authority record key for the tenancy's collection period (or the registration key, for an unregistered tenancy).
- **WIRE-104** The manifest MUST carry: tenancy ID; the tenancy certificate if held; the latest registration request; the key history `[{index, public_key, evidence}]`; record count; first and last `seq`; first and last record hash; SHA-256 of the journal section body; the closing record hash or the close or reset certificate; the runtime build anchor; content addresses of the instruments and policy in use.
- **WIRE-105** The journal section body MUST be the journal's frames, unmodified.
- **WIRE-106** The signature section MUST carry `{"key": index, "sig": Signature}` over tag `fieldseal.dev/export/v1` and the structure `{header, manifest_sha256, journal_sha256}`. It MUST be made by the tenancy's current signing key, or, for an outbox part, at close, before the keys are deleted.
- **WIRE-107** When present, the parity section MUST carry Reed–Solomon parity over the concatenated bodies of the header, manifest and journal sections of its part, split into k = 10 data shards of equal size with m = 4 parity shards over GF(2⁸): `{"k": 10, "m": 4, "shard_size": uint, "data_hashes": [10 × bstr(32)], "parity_shards": [4 × bstr]}`. The construction is fixed byte for byte, so that every implementation produces the same parity:
  - the field is GF(2⁸) with the reducing polynomial x⁸ + x⁴ + x³ + x² + 1 (`0x11D`) and generator 2;
  - the code is systematic, built from the 14 × 10 Vandermonde matrix `V[r][c] = r^c` (with `0^0 = 1`) multiplied on the right by the inverse of its top 10 × 10 block; rows 10 to 13 of the product give the parity shards. This is the construction of Backblaze's JavaReedSolomon and the Rust `reed-solomon-erasure` crate;
  - `shard_size = max(1, ceil(len / 10))`, where `len` is the length of the concatenated bytes; the data is zero-padded at the end to `10 × shard_size`, and the padding is never written to the file;
  - `data_hashes[i]` is the SHA-256 of the i-th zero-padded data shard (so the last shard's hash covers its padding);
  - in a multi-part export (WIRE-110), each part has its own parity section, computed over that part's data only, with the header body included in every part's data.
- **WIRE-108** The parity section MUST NOT be covered by the export signature; repaired output MUST be verified against the signed hashes, so parity can be added or removed without re-signing and cannot forge content.
- **WIRE-109** A repairer MUST identify damaged data shards by their hashes and MUST recover up to 4 damaged shards. With more than 4 it MUST report `E_PARITY` and salvage intact frames.
- **WIRE-110** An outbox export MUST set `parts` to the number of closed tenancies and repeat sections `0x02`–`0x05` once per part.
- **WIRE-111** An export file's name MUST NOT encode any identifier; the format places no meaning in the name.

### 5.9 Registration token

- **WIRE-120** A registration token MUST be `{"v": 1, "factory": tstr, "root": bstr(32), "token": bstr(16), "nonce": bstr(32), "mode": "online" / "air-gapped", "issued": uint, "signer": key_id, "sig": Signature}`, signed over tag `fieldseal.dev/registration-token/v1` by the factory's registration key.
- **WIRE-121** `factory` MUST be an `https` URL of at most 256 bytes; `root` MUST be the SHA-256 of a root public key.
- **WIRE-122** The token's text form MUST be `FS1T:` followed by the Crockford base32 encoding of its canonical CBOR and a 2-character check value: CRC-10/ATM (polynomial `0x233`, initial value 0, unreflected, no final XOR; check value `0x199` over `"123456789"`) over the CBOR bytes, as 10 bits in base32. The QR form MUST encode the text form in alphanumeric mode, upper case.
- **WIRE-123** The canonical CBOR of a token MUST NOT exceed 300 bytes.
- **WIRE-124** A device MUST NOT evaluate a token's expiry; only the factory does.

### 5.10 Registration request

- **WIRE-130** A registration request body MUST be `{"v": 1, "token": bstr(16), "nonce": bstr(32), "nonce_source": "factory" / "device", "tenancy": bstr(32), "sign_pub": bstr(65), "agree_pub": bstr(65), "evidence": [Evidence], "build": tstr, "schema": tstr, "catalogue": tstr?, "prev_closing": bstr(32)?, "label": tstr?}`. `schema` is the instrument-schema version the runtime implements, as semantic version text `major.minor.patch` (decimal numbers without sign or leading zeros, no pre-release or build part, at most 32 bytes), and is required. `catalogue` is the UI reference-catalogue version of the runtime build (non-empty text of printable ASCII only, bytes 0x21 to 0x7e, so no spaces, control characters or direction overrides such as U+202E; at most 64 bytes) and is present only when the build has one; nothing reads it yet, and it is in the body now so that Localisation artefacts, when they arrive, need no second signed-content change. The body is a closed map: an unknown key, a body without `schema`, a malformed or over-long `schema` or `catalogue` is refused. Both fields are inside `body_sha256` and so covered by the proof of possession (WIRE-132). `"v"` stays `1` while the specifications are `v1alpha1`.
- **WIRE-131** `tenancy` MUST equal SHA-256 of `sign_pub`.
- **WIRE-132** The request MUST carry `pop`: a signature by the key `sign_pub` over tag `fieldseal.dev/registration-pop/v1` and the structure `{nonce, body_sha256}`, where `body_sha256` is SHA-256 of the canonical body.
- **WIRE-133** `Evidence` MUST be `{"key": "sign" / "agree" / "storage", "format": tstr, "data": bstr}`, where `format` names a platform evidence format registered in [Trust](./trust.md).
- **WIRE-134** The whole request `{body, pop}` MUST be sealed with tag `fieldseal.dev/registration-seal/v1` and suite `fs1-x` to the factory's X25519 `registration` key certified in the device's trust bundle (the token's `signer` names the P-256 registration key that signed it). A key roll (REG-060) adds `"roll": {"tenancy": hash, "sig": signature}` to the sealed plaintext: the current signing key's signature over the same `{nonce, body_sha256}`.
- **WIRE-135** **Fingerprint words** MUST be the first 44 bits of SHA-256 over the canonical body, read as four 11-bit indices into the BIP-39 English word list (2048 words), joined by ` · `.
- **WIRE-136** The text form for files MUST be the sealed request's canonical CBOR, prefixed by magic `46 53 52 51` ("FSRQ").

### 5.11 Certificates, receipts and time tokens

- **WIRE-140** A tenancy certificate MUST be signed over tag `fieldseal.dev/tenancy-certificate/v1` by the factory's registration key and MUST carry: tenancy ID, the opaque collector reference, the export handle, the key history, the agreement public key, the collection period and its record-key ID, the window `{not_before, not_after, grace}`, cohorts `[{cohort, generation}]`, the device serial if attested and required by policy, the issue time and the content address of the factory policy that approved it.
- **WIRE-141** A close certificate and a reset certificate MUST be signed over tags `fieldseal.dev/close-certificate/v1` and `fieldseal.dev/reset-certificate/v1` respectively, and carry tenancy ID, `cutoff_seq`, reason and issue time.
- **WIRE-142** A receipt MUST be signed over tag `fieldseal.dev/receipt/v1` by an intake receipt key and carry tenancy ID, `last_seq`, the record hash at `last_seq`, the authority's receive time, and the content address of the export or upload it acknowledges.
- **WIRE-143** A time token MUST be signed over tag `fieldseal.dev/time-token/v1` by a receipt key and carry the authority time and, when requested online, the device's 16-byte nonce.
- **WIRE-144** Close and reset certificates, receipts and time tokens MUST each encode to at most 300 bytes of canonical CBOR, so they fit a single QR code; their text form MUST follow WIRE-122 with prefixes `FS1C:`, `FS1R:` and `FS1N:`.

### 5.12 Versions

- **WIRE-150** Every top-level structure MUST carry a format version (`v` or `format`). A decoder MUST reject an unknown version with `E_VERSION`.
- **WIRE-151** A change to any structure in this spec MUST bump its version and MUST be reflected in the golden vectors (§8).

### 5.13 Proof-of-possession API tokens

- **WIRE-170** After registration, every request a runtime makes to the factory or the upload endpoint MUST carry a proof-of-possession token: `{"v": 1, "tenancy": bstr(32), "method": tstr, "url": tstr, "iat": uint, "jti": bstr(16), "ath": bstr(32)?, "sig": Signature}`, where `iat` is in milliseconds (WIRE-008), signed (without `sig`) over tag `fieldseal.dev/api-pop/v1` by the tenancy's current signing key. `ath` is the SHA-256 of the access token when one is used.
- **WIRE-171** The server MUST reject a token whose `method` or `url` doesn't match the request, whose `iat` is more than 300 seconds from its own clock, or whose `jti` it has seen within that window. The `url` of the token is the request URL without its query string: a server MUST NOT require the query to be signed and a client MUST NOT sign it. A query only narrows the answer (for example `held` on `GET /v1/bundle`); a proxy that rewrites it has the same effect as a dropped response, because the device verifies every answer before it uses it.
- **WIRE-172** The token MUST be sent in the `Fieldseal-PoP` HTTP header as base64url of its canonical CBOR. The semantics follow DPoP (RFC 9449), with Fieldseal's signature format instead of JWS.

- **WIRE-196** Service contracts ([ADR 0035](../../explanation/adr/0035-service-contracts-and-transports.md)) MUST carry every payload defined in this spec as opaque `bytes` holding its canonical CBOR, unchanged from the HTTP body. A transport MUST NOT re-encode, re-order or normalise those bytes, and signatures, hashes and content addresses MUST be computed and verified over them as sent. Protobuf is only the envelope. gRPC is built in slice 2.
- **WIRE-197** Over gRPC the WIRE-170 token MUST be sent in the `fieldseal-pop` metadata entry, with the same encoding as WIRE-172, and its `method` MUST be `POST` and its `url` `https://<authority>/<package>.<Service>/<Method>` (for example `https://factory.example/fieldseal.v1.Factory/GetCertificate`), the authority being the one dialled. WIRE-171 applies unchanged. Built in slice 2.

### 5.14 Animated QR sequences

- **WIRE-175** An object too large for one QR code (for example a registration request) MAY be shown as an animated sequence of frames, each with the text form `FS1A:<seq>/<total>:<message-id>:<payload>`, where `payload` is base32 and `message-id` is the first 8 bytes of the object's SHA-256, base32.
- **WIRE-176** A frame's text MUST NOT exceed 600 characters, and frames MUST be shown in a loop until the receiver confirms.
- **WIRE-177** The receiver MUST reassemble frames by `message-id`, verify the object's SHA-256, and then process the object exactly as if it had arrived as a file.
- **WIRE-178** `seq` counts from 1 and `total` is at most 1000; both are decimal with no sign or leading zeros. `message-id` and `payload` are Crockford base32 (as in WIRE-122), unpadded, upper case on output and read case-insensitively. Every frame but the last MUST carry exactly 356 object bytes, so one object has exactly one sequence; the last carries 1 to 356. A sequence therefore carries at most 356,000 bytes and no frame exceeds 599 characters.
- **WIRE-179** A receiver MUST accept frames in any order and any number of times, MUST follow interleaved messages separately (and MAY bound the messages it follows at once; the kernel allows 8), and MUST refuse a frame whose `total` differs from the message's or that repeats a `seq` with a different payload. After a hash mismatch it MUST drop the message so the loop can restart it.

### 5.15 Receiver challenge

- **WIRE-180** Before an upload, the runtime MUST send a challenge `{"v": 1, "nonce": bstr(32), "tenancy_handle": bstr(16), "purpose": "upload"}`.
- **WIRE-181** The destination MUST answer `{"v": 1, "cert": KeyCertificate, "sig": Signature}`, where `cert` certifies a `receiver` key and `sig` is that key's signature over tag `fieldseal.dev/receiver-challenge/v1` and the canonical challenge.
- **WIRE-182** The answer MUST NOT contain or depend on the destination's address, so the same key answers at any address.

### 5.16 Instrument fingerprints ([ADR 0027](../../explanation/adr/0027-salted-instrument-fingerprints.md))

- **WIRE-185** An instrument's fingerprint MUST be `SHA-256("fieldseal.dev/instrument-fingerprint/v1" ‖ salt ‖ canonical bytes)`, where `salt` is 32 bytes carried in the artefact envelope.
- **WIRE-186** Wherever a format names an instrument (record payloads, consent payloads, bundles, imports), it MUST use the fingerprint, encoded as `bstr(32)`.
- **WIRE-187** The short form for display MUST be the first 8 bytes of the fingerprint in Crockford base32.

### 5.17 Log entries and checkpoints ([ADR 0030](../../explanation/adr/0030-public-transparency-log.md))

- **WIRE-190** A `PublicationStatement` MUST be the canonical CBOR `{"type": "publish" / "withdraw", "fingerprint": bstr(32), "provenance": bstr(32)}`, signed over tag `fieldseal.dev/publication/v1`. Decoders MUST reject any other key. `fingerprint` is the artefact's identity (an instrument's fingerprint, any other artefact's content address); `provenance` is the SHA-256 of the provenance statement, and for a withdrawal that of the withdrawn publication.
- **WIRE-191** A `LogEntry` MUST be the canonical CBOR `{"type": "publish" / "withdraw", "digest": bstr(32), "sig": bstr, "pub": bstr(65)}`, where `digest` is the SHA-256 of the signed message of WIRE-190 (WIRE-021). Decoders MUST reject any other key.
- **WIRE-192** Checkpoints MUST be accepted in the C2SP `tlog-checkpoint` signed-note format, with inclusion proofs as RFC 9162 audit paths.
- **WIRE-193** A `Publication` MUST carry, per signature, the `LogEntry`, its leaf index and inclusion proof, and one checkpoint covering them all.
- **WIRE-194** A log leaf MUST be one of these encodings of a `LogEntry`, and a `Publication` MUST name which one each log record used, so a consumer recomputes the leaf from the entry alone: `fieldseal/v1`, the entry's canonical CBOR (WIRE-191); or `hashedrekord/v0.0.1`, the Rekor entry `{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha256","value":<digest, lowercase hex>}},"signature":{"content":<base64 of the ASN.1 DER signature>,"publicKey":{"content":<base64 of the PEM SubjectPublicKeyInfo, 64-column lines>}}}}` in RFC 8785 canonical JSON. No other field is set; the entry type is not carried, since the digest commits to it.
- **WIRE-195** A pinned log key with format `c2sp-tlog-checkpoint` MUST be a P-256 key in uncompressed SEC1 form (WIRE-009). Its note signature line MUST carry the first four bytes of SHA-256 over the key's DER `SubjectPublicKeyInfo`, then an ASN.1 DER ECDSA signature with SHA-256 over the checkpoint body (as Rekor signs). A verifier MUST accept a high-`s` signature from a log key (the log is not bound by WIRE-022) and MUST refuse a note larger than 16 KiB or with more than 32 signature lines.

### 5.18 Strict schemas for every document ([ADR 0037](../../explanation/adr/0037-extensions-and-strict-schema-enforcement.md))

- **WIRE-208** Every artefact, manifest and input file MUST have a closed schema: the instrument, layout, localisation, policy, trust bundle, deployment manifest, extension, standard catalogue, roster, and every other document a Fieldseal component reads, in its authoring form (YAML or JSON) as well as in canonical CBOR. A reader MUST reject an unknown field at any depth, a missing required field, a value of the wrong type, a value outside an enumeration (enumerations are exact and case-sensitive), and a duplicate key. It MUST NOT coerce (the text `"5"` is not the integer 5, and an absent field is not `null`). Authoring YAML MUST be read as YAML 1.2 core schema with duplicate keys, anchors, aliases, merge keys and non-core tags rejected. No document has a vendor-extension field: the only way to add a field is a new schema version.
- **WIRE-209** Each schema MUST be defined once, in the format core, and published as a closed JSON Schema (draft 2020-12, `additionalProperties: false` throughout) addressed by content. `fieldseal schema export` MUST print it. No component MAY keep a hand-written copy of a schema; the bindings, the web and HTML renderers and the services MUST validate with the format core's validator or with the exported schema, and the conformance corpus (WIRE-213) MUST run against whichever they use.
- **WIRE-210** Every reader MUST validate every document it reads against its schema before using any of it. This covers the CLI, the factory and portal, upload and intake endpoints, the device runtimes, the HTML and web renderers, the language bindings, the deployment tooling and the conformance suite. There MUST be no lenient mode, flag or environment variable.
- **WIRE-211** A failure MUST be reported, never ignored, dropped or defaulted. Binary structures use the codes of §6.8 (`E_UNKNOWN_FIELD`, WIRE-162). Authoring documents use findings with a JSON Pointer to the offending location and one of `UnknownField`, `MissingField`, `TypeMismatch`, `EnumValue`, `DuplicateKey` or `CoercionRefused`.
- **WIRE-212** `bundle-content` MUST be able to carry `? "extensions": [+ publication]` (DIS-074), and the `kind` of an `artefact-fields` MUST include `"Extension"` (PUB-122). Both are added to structure version 1 before its first release; the golden vectors MUST be regenerated (WIRE-151).
- **WIRE-213** The format core MUST ship an invalid-document corpus (`tests/schema-corpus/`) that, for every schema, has one document for each of: an unknown field at every nesting level, a missing required field, a wrong type, an out-of-enumeration value, a duplicate key, and a coerced value. Every reader in WIRE-210 MUST reject every document in it, as the conformance suite `strict-schema`.

## 6. Resources and formats

### 6.1 Domain tags

| Tag | Used for | Signer or recipient |
|---|---|---|
| `fieldseal.dev/record/v1` | Record signature | Tenancy signing key |
| `fieldseal.dev/record-seal/v1` | Record payload seal | Authority record key |
| `fieldseal.dev/local-record/v1` | Local record AEAD context | Session storage key |
| `fieldseal.dev/bundle/v1` | Bundle signature | Factory signing key |
| `fieldseal.dev/bundle-seal/v1` | Bundle seal | Device agreement key |
| `fieldseal.dev/export/v1` | Export signature | Tenancy signing key |
| `fieldseal.dev/export-manifest-seal/v1` | Export manifest seal | Authority record key |
| `fieldseal.dev/registration-token/v1` | Token signature | Factory registration key |
| `fieldseal.dev/registration-pop/v1` | Proof of possession | Tenancy signing key |
| `fieldseal.dev/registration-seal/v1` | Request seal | Factory registration key |
| `fieldseal.dev/tenancy-certificate/v1`, `…/close-certificate/v1`, `…/reset-certificate/v1` | Certificates | Factory registration key |
| `fieldseal.dev/receipt/v1`, `fieldseal.dev/time-token/v1` | Receipts, time tokens | Intake receipt key |
| `fieldseal.dev/key-certificate/v1`, `fieldseal.dev/trust-bundle/v1`, `fieldseal.dev/revocation/v1` | Trust material | Authority root ([Trust](./trust.md) TRU-003) |
| `fieldseal.dev/csr/v1` | Certificate request proof of possession | The requested P-256 key itself ([Trust](./trust.md) TRU-016) |
| `fieldseal.dev/api-pop/v1`, `fieldseal.dev/receiver-challenge/v1`, `fieldseal.dev/publication/v1` | PoP tokens (WIRE-170), receiver answers (WIRE-181), publication statements (WIRE-190) | Tenancy signing key, receiver key, publisher key |
| `fieldseal.dev/artefact/v1`, `fieldseal.dev/provenance/v1`, `fieldseal.dev/tree-head/v1`, `fieldseal.dev/withdrawal/v1` | Publishing | Publisher, builder and log keys ([Publishing](./publishing.md)) |

### 6.2 Common CDDL

```cddl
key-id        = bstr .size 16
hash          = bstr .size 32
p256-pub      = bstr .size 65
x25519-pub    = bstr .size 32
signature     = bstr .size 64
ms-time       = uint
decimal       = #6.4([exponent: int, mantissa: int])
sealed        = { "suite": "fs1-x" / "fs1-p", "recipient": key-id, "enc": bstr, "ct": bstr }
```

### 6.3 Records

```cddl
record = {
  "header": record-header,
  "payload": sealed,              ; fs1-x, tag fieldseal.dev/record-seal/v1
  "sig": signature                ; tag fieldseal.dev/record/v1 over {header, payload}
}
record-header = {
  "record_id": bstr .size 16,
  "seq": uint,
  "prev": hash,
  "key": uint,                    ; index into the tenancy's key history
  "period": key-id                ; authority record key the payload is sealed to
}
tick = { "anchor": hash, "slot": uint, "boot": uint, ? "wall": ms-time }

payload = open / items / status / consent / evidence / anchor / import
        / key-roll / checkpoint / closing

value     = tstr / int / decimal / bool / [* (tstr / int / decimal / bool)]
            / { "retracted": true } / { "nr": "dont-know" / "refused" }
items = {
  "type": "items", "tick": tick,
  "instrument": hash, "layout": hash / "default", "lang": [+ tstr], "subject": bstr, "consent_ref": consent-ref,
  "mode": "first" / "resume" / "resurvey" / "correction",
  "values": { * tstr => value },
  ? "overrides": { * tstr => tstr },
  ? "flags": [* tstr]
}
consent-ref = { "record": bstr .size 16 } / { "roster": hash, "version": uint }
status   = { "type": "status", "tick": tick, "instrument": hash, "subject": bstr,
             "status": "absent" / "declined" / "not-subject" }
consent  = { "type": "consent", "tick": tick, "instrument": hash, "subject": bstr,
             "basis": tstr, "statement": hash,
             "evidence": [* { "blob_id": bstr .size 16, "sha256": hash,
                              "media_type": tstr, "size": uint }] }
evidence = { "type": "evidence", "tick": tick, "blob_id": bstr .size 16,
             "media_type": tstr, "bytes": bstr }
anchor   = { "type": "anchor", "tick": tick,
             "kind": "build" / "bundle" / "receipt" / "time-token",
             "address": hash, "authority_time": ms-time }
import   = { "type": "import", "tick": tick, "bundle": hash, "artefacts": [* hash],
             "rosters": [* { "cohort": tstr, "version": uint, "address": hash }] }
key-roll = { "type": "key-roll", "tick": tick, "index": uint,
             "public_key": p256-pub, "evidence": hash }
checkpoint = { "type": "checkpoint", "tick": tick, "cleared_through": uint,
               "hash_at": hash, "delivery": hash }
closing  = { "type": "closing", "tick": tick, "last_seq": uint, "prev_hash": hash,
             "reason": "collector" / "close-certificate" / "reset-certificate" / "returned" }
open     = { "type": "open", "tick": tick, "tenancy": hash, "sign_pub": p256-pub,
             "agree_pub": p256-pub, "evidence": [* hash], "build_anchor": hash }
```

### 6.4 Bundles

```cddl
bundle-file = { "sealed": sealed, "signer": key-id, "chain": [* key-certificate], "sig": signature }
bundle-content = {
  "v": 1, "tenancy": hash, "seq": uint, "issued": ms-time,
  ? "certificate": tenancy-certificate, "time_token": time-token,
  "instruments": [+ publication], ? "layouts": [+ publication],
  ? "localisations": [+ publication], "policy": [+ publication],
  "rosters": [* roster],
  ? "trust_updates": [+ publication], ? "withdrawals": [+ withdrawal],
  ? "extensions": [+ publication]      : every extension an instrument or layout here references (DIS-074)
}
roster = { "cohort": tstr, "version": uint, "generation": uint,
           "subjects": [* { "ordinal": uint, "subject": bstr, "display": tstr,
                            "attributes": { * tstr => value },
                            "consent": "granted" / "refused" / "unknown",
                            ? "prior_status": tstr }] }
```

`publication`, `withdrawal` and `key-certificate` are defined in [Publishing](./publishing.md) and [Trust](./trust.md).

### 6.5 Export files

```cddl
export-header   = { "format": "fieldseal.dev/export/v1", "handle": bstr .size 16,
                    "parts": uint }
export-manifest = {
  "tenancy": hash, ? "certificate": tenancy-certificate,
  ? "registration": sealed, "keys": [* { "index": uint, "public_key": p256-pub, "evidence": hash }],
  "records": uint, "first_seq": uint, "last_seq": uint,
  "first_hash": hash, "last_hash": hash, "journal_sha256": hash,
  ? "end": hash / close-certificate / reset-certificate,
  "build_anchor": hash, "instruments": [* hash], "policy": hash
}
export-signature = { "key": uint, "sig": signature }  ; over {header, manifest_sha256, journal_sha256}
parity = { "k": 10, "m": 4, "shard_size": uint,
           "data_hashes": [10*10 hash], "parity_shards": [4*4 bstr] }
```

### 6.6 Registration, certificates, receipts, time tokens

```cddl
registration-token = { "v": 1, "factory": tstr, "root": hash, "token": bstr .size 16,
                       "nonce": bstr .size 32, "mode": "online" / "air-gapped",
                       "issued": ms-time, "signer": key-id, "sig": signature }
registration-body = { "v": 1, "token": bstr .size 16, "nonce": bstr .size 32,
                      "nonce_source": "factory" / "device", "tenancy": hash,
                      "sign_pub": p256-pub, "agree_pub": p256-pub,
                      "evidence": [+ { "key": "sign" / "agree" / "storage",
                                       "format": tstr, "data": bstr }],
                      "build": tstr, ? "prev_closing": hash, ? "label": tstr }
registration-request = sealed   ; plaintext { "body": registration-body, "pop": signature }

tenancy-certificate = {
  "v": 1, "tenancy": hash, "collector": bstr, "handle": bstr .size 16,
  "keys": [* { "index": uint, "public_key": p256-pub }], "agree_pub": p256-pub,
  "period": key-id, "window": { "not_before": ms-time, "not_after": ms-time, "grace": uint },
  "cohorts": [* { "cohort": tstr, "generation": uint }], ? "serial": tstr,
  "issued": ms-time, "policy": hash, "signer": key-id, "sig": signature }
close-certificate = { "v": 1, "tenancy": hash, "cutoff_seq": uint, "reason": tstr,
                      "issued": ms-time, "signer": key-id, "sig": signature }
reset-certificate = close-certificate
receipt    = { "v": 1, "tenancy": hash, "last_seq": uint, "hash_at": hash,
               "received": ms-time, "of": hash, "signer": key-id, "sig": signature }
time-token = { "v": 1, "authority_time": ms-time, ? "nonce": bstr .size 16,
               "signer": key-id, "sig": signature }
```

### 6.7 Size limits

| Object | Limit |
|---|---|
| Record | 4 MiB |
| Evidence bytes | 3 MiB |
| Bundle file | 64 MiB |
| Export file | 4 GiB |
| Token, certificate, receipt, time token (canonical CBOR) | 300 bytes |
| Registration request | 64 KiB |
| Any text string | 64 KiB, unless a structure states less |
| Any array | 1 048 576 elements |
| CBOR nesting depth | 16 |

A decoder MUST enforce these before allocating, with `E_SIZE` (WIRE-160).

### 6.8 Error codes

| Code | Meaning |
|---|---|
| `E_FRAME_MAGIC`, `E_FRAME_LENGTH`, `E_CRC` | Frame or section is damaged |
| `E_CBOR_NONCANONICAL`, `E_CBOR_DUPLICATE`, `E_CBOR_TAG`, `E_UNKNOWN_FIELD` | Encoding is not canonical or not allowed |
| `E_SIZE` | A limit in §6.7 is exceeded |
| `E_VERSION` | Unknown structure version |
| `E_TAG` | Wrong or unknown domain tag |
| `E_SIG` | Signature invalid, high-`s`, or signer not trusted |
| `E_SUITE`, `E_RECIPIENT`, `E_DECRYPT` | Sealing suite, recipient or AEAD failure |
| `E_CHAIN`, `E_SEQ` | Hash chain broken, sequence gap, record after closing |
| `E_TICK` | Tick not monotonic |
| `E_EXPORT_SECTION` | Export sections missing or out of order |
| `E_PARITY` | Damage exceeds parity |
| `E_HASH` | A stated hash does not match content |

- **WIRE-160** Decoders MUST enforce every limit in §6.7 before allocating memory for the object.
- **WIRE-161** Every failure MUST be reported with exactly one code from §6.8 and the byte offset where it was found.
- **WIRE-162** For cases the §6.8 table doesn't name, implementations MUST use these codes, which the golden vectors pin:

| Case | Code |
|---|---|
| Malformed or truncated CBOR (trailing bytes, truncated item, empty input, reserved additional information, a lone break, a decimal that is not `[exponent, mantissa]`, text that is not UTF-8 or not NFC, a map key that is not text, keys out of order, an integer outside −2⁶⁴…2⁶⁴−1) | `E_CBOR_NONCANONICAL` |
| A required key missing or of the wrong type, or an extra key, in a structure, payload or parity section; or a field that breaks a declared constraint (a `record_id` without the UUIDv4 bits, a sealed box `enc` of the wrong size for its suite, a local entry `ct` shorter than the AEAD tag, `parts` of 0, a parity shard that is not `shard_size` bytes, a PoP `method` that is not upper case or a `url` with a query or fragment, duplicate or empty `lang` tags) | `E_UNKNOWN_FIELD` |
| A frame with an unknown version, reserved flags set, or bytes outside any frame | `E_FRAME_MAGIC` |
| A frame or section header truncated, or a length that runs past the input | `E_FRAME_LENGTH` |
| An unknown structure version, or an unknown export format string | `E_VERSION` |
| A record, export or text form that fails to decode because of a bad prefix or character | `E_FRAME_MAGIC` |
| A text-form check value that doesn't match | `E_CRC` |
| An animated-QR frame over 600 characters, or `total` above 1000 | `E_SIZE` |
| An animated-QR frame with a bad prefix, field, message ID or character | `E_FRAME_MAGIC` |
| An animated-QR `seq` outside `1..=total`, a `total` that differs within a message, or a repeated `seq` with a different payload | `E_SEQ` |
| An animated-QR payload that is empty, over 356 bytes, or short before the last frame | `E_FRAME_LENGTH` |
| An animated-QR object whose SHA-256 does not match the message ID | `E_HASH` |
| A receiver answer whose certificate is not for a `receiver` key | `E_SIG` |
| A key index that is not in the key history | `E_SIG` |
| A signature that is not exactly 64 bytes (DER, truncated), or a tag that is known but not the one required for the structure | `E_SIG` |
| A tag that is not in the registry | `E_TAG` |
| A seal with a tag other than the one it was sealed under | `E_DECRYPT` |
| A seal under a suite not expected for the key type, or an unknown suite | `E_SUITE` |
| A record payload not sealed with `fs1-x` | `E_SUITE` |
| A malformed content address (wrong prefix, case, length or algorithm), or parity whose shard size doesn't match the data | `E_HASH` |
| A journal that doesn't start at `seq` 0, a repeated or reordered `seq`, or a gap not covered by a checkpoint | `E_SEQ` |
| `seq` 0 with a non-zero `prev`, or `prev` not the previous record's hash | `E_CHAIN` |
| A damaged part whose parity section is absent, or a damaged parity or signature section | `E_PARITY` |
| `parts` not matching the parts present, or a missing header section | `E_EXPORT_SECTION` |
| A section length above 4 GiB, a record above 4 MiB, or a length that doesn't fit memory | `E_SIZE` |

For checks above the byte level (a signature, a chain link, a missing field), the offset is that of the object being checked within the input the caller passed, usually 0. Verifying a journal reports every failure it finds, not only the first; each carries one code.

- **WIRE-163** Every reader of a structure defined in this spec (record headers and payloads, ticks, local entries, sealed boxes, export headers, parity and signature sections, PoP tokens, tokens, requests, certificates, challenges, and the authoring documents that become them) MUST reject unknown fields, enforce exact types (no text for an integer, no integer for a boolean, no decimal for an integer), and enforce every constraint this spec declares for the field: lengths, ranges, cardinality, enumerations, uniqueness, and the bits a field fixes (for example the UUIDv4 bits of `record_id`, WIRE-035). A reader MUST NOT supply a default for a missing required field, and MUST reject trailing bytes and duplicate map keys (WIRE-002, WIRE-003). Extension happens only through a new structure version (WIRE-005).
- **WIRE-164** The authoring decoder (YAML and JSON to the canonical data model) MUST be at least as strict as WIRE-163 for syntax: no duplicate keys under any spelling, no non-text keys, no `null`, no floats or exponents, no anchors, aliases, merge keys or tags (except `!!binary`), no non-NFC text, and no implicit typing of unquoted scalars beyond `true`, `false` and canonical numbers. Number-like scalars that are not canonical (`.5`, `1e3`, `007`, `+1`, `0x1F`) MUST be errors, never text.

## 7. Twelve-factor

The format core is a library, not a process. It has no configuration (III), no backing services (IV) and no logs of its own (XI): it returns errors and lets the calling process log them. It is a declared, locked dependency (II) of every component, built once per release (V). Factors VI–IX and XII don't apply to a library.

## 8. Conformance

- Golden vectors for every structure, valid and invalid, live in `tests/vectors/` of the crate that owns the encoding (JSON files, one per structure family, regenerable with `FIELDSEAL_REGENERATE_VECTORS=1`): the kernel for the primitives, the local record envelope, proof-of-possession tokens and animated QR sequences; Intake for receipts; Distribution for time tokens; Delivery for the receiver challenge; Registration, Trust and Publishing for theirs. Each invalid vector names the error code and requirement ID it tests.
- `fieldseal conformance run --suite wire` checks an implementation's encoder and decoder against the vectors.
- `fieldseal conformance run --suite strict-schema` runs the invalid-document corpus (WIRE-213) through every reader (WIRE-208–WIRE-211).
- `fieldseal export inspect | verify | repair`, `fieldseal bundle inspect | verify | open`, `fieldseal registration inspect`, `fieldseal receipt verify` and `fieldseal device simulate` exercise the formats end to end.
- Fault-injection tests MUST cover truncation, bit flips in every section, reordered and duplicated frames, records after a closing record, high-`s` signatures, non-canonical encodings, and parity repair at 4 and 5 damaged shards.

## 9. Open questions

1. Authority sealing keys use X25519 (suite `fs1-x`). If a deployment's HSM can't perform X25519, should a P-256 authority suite be added, or should record-key private keys be unwrapped into intake memory?
2. Should the `wall` hint be removed from ticks entirely, since the payload is sealed and the hint adds little?
3. Is CRC-10 enough as the check value for typed text forms, or should it be a truncated SHA-256?
4. Is 3 MiB right for one evidence image, or should evidence be chunked across records?

## 10. References

- ADRs [0005](../../explanation/adr/0005-format-core.md), [0007](../../explanation/adr/0007-zero-trust-posture.md), [0018](../../explanation/adr/0018-dual-write-records.md), [0019](../../explanation/adr/0019-review-until-clear.md), [0020](../../explanation/adr/0020-monotonic-ticks.md), [0021](../../explanation/adr/0021-export-upload-receipts.md), [0013](../../explanation/adr/0013-registration-via-authority-tokens.md), [0015](../../explanation/adr/0015-bundles-sealed-per-device.md)
- RFC 8949 (CBOR), RFC 8610 (CDDL), RFC 9180 (HPKE), RFC 3720 §B.4 (CRC-32C), SEC 1 v2 (EC point encoding), BIP-39 English word list
