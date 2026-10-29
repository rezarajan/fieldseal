# fieldseal-kernel

## Overview

The shared kernel and format core: the innermost ring of the architecture (layering in
[architecture.toml](../../architecture.toml); ADR [0004](../../docs/explanation/adr/0004-bounded-contexts.md),
[0005](../../docs/explanation/adr/0005-format-core.md),
[0028](../../docs/explanation/adr/0028-clean-architecture.md)). It holds the value types every
bounded context agrees on and the code that gives them their bytes, as specified in
[wire-formats.md](../../docs/reference/spec/wire-formats.md) (WIRE-nnn). The crate is pure: no I/O, no
clock, no ambient randomness or environment. Randomness enters through a caller-supplied
`CryptoRng` (re-exported as `fieldseal_kernel::CryptoRng`); time enters as values (`time`).

`data/bip39-english.txt` is data, not code: the fixed 2048-word BIP-39 English list that `words.rs`
embeds for fingerprint words.

## Interface

Crate root re-exports: `ErrorCode`, `KernelError`, `WireError`, `Decimal`, `Value`, `CryptoRng`.

| Module | Public surface |
|---|---|
| `value` | `Value` (Int, Decimal, Bytes, Text, Bool, Array, Map; no null, no float), `Decimal`, `DecimalError` |
| `cbor` | `encode`, `encode_into`, `decode`, `decode_limited`, `map`; limits `MAX_DEPTH` (16), `MAX_TEXT` (64 KiB), `MAX_ELEMENTS` (1,048,576), `INT_MIN`, `INT_MAX` |
| `schema` | The declarative schema of the compact authoring dialect (WIRE-209 to WIRE-211; pure, no I/O): `DocKind` (`Survey`, `Layout`, `Roster`; `detect`), the table (`shapes`, `shape`, `root`, `keys_of`, `resolve`, `paths`), `check(doc, kind) -> Vec<SchemaError>` and `check_shape`, `shapes_in`, `json_schema(kind)` (closed JSON Schema, draft 2020-12, generated from the same table), `Reader` (typed reads that refuse an undeclared key in debug builds), `SchemaError { pointer, kind, message }` and `SchemaErrorKind` (the six WIRE-211 kinds), `escape_segment`, `child_pointer` |
| `structure` | `Fields` (typed reads, then `finish` rejects leftovers), `expect_bytes`, `expect_bytes_n`, `expect_uint` |
| `error` | `KernelError` (constructor invariant failures), `ErrorCode` (WIRE section 6.8 codes), `WireError` (code plus byte offset) |
| `id` | Fixed-length byte ids `Digest`, `KeyId` (16 bytes), `Fingerprint`, `ContentAddress`, `TenancyId`, `TenancyHandle`, `RecordId`, `Challenge`, `Salt`; text ids `SubjectId`, `CohortId`, `CollectionPeriodId`, `ReviewerId`, `CollectorRef`; `ItemPath`, `Seq`, `Generation` |
| `digest` | `sha256`, `sha256_parts`, `key_id`, `instrument_fingerprint`, `lower_hex`, `crockford_base32`, `CONTENT_ADDRESS_PREFIX` (`sha256:`), `FINGERPRINT_DOMAIN` |
| `crypto` | `Purpose` (factory, registration, publisher, builder, receipt, receiver, record; `ALL`, `as_str`, `parse`), `DomainTag`, `TagUsage`, `tags::*` domain-tag constants (`RECORD`, `BUNDLE`, `EXPORT`, `RECEIPT`, `API_POP`, ...), `P256PublicKey`, `Signature`, `Sealed`, `check_x25519_public` |
| `sign` | `SigningKey` (`from_scalar`, `sign`, `sign_message`), `signed_message`, `verify`, `verify_message`, `SIGNATURE_LEN` (64) |
| `seal` | HPKE seals: `Suite` (`fs1-x`, `fs1-p`), `RecipientKey`, `RecipientSecret`, `SealedBox`, `seal`, `seal_value`, `seal_with_context`, `seal_info`, `open`, `open_value`, `open_with_context` |
| `frame` | Journal frames: `frame`, `read_frames`, `FoundFrame`, `FrameScan`, `FRAME_MAGIC` (`FSR1`), `FRAME_HEADER_LEN` (14), `MAX_RECORD` (4 MiB) |
| `record` | `RecordHeader`, `Record`, `record_signed_structure`, `record_hash`, `ChainLink`, `verify_chain`, `JournalEntry`, `JournalReport`, `read_journal`, `record_id_from_random`, `is_uuid_v4` |
| `payload` | `Payload` and its variants (`ItemsPayload`, `OpenPayload`, `StatusPayload`, `ConsentPayload`, `EvidencePayload`, `AnchorPayload`, `ImportPayload`, `KeyRollPayload`, `CheckpointPayload`, `ClosingPayload`), `Tick`, `Layout`, `ConsentRef`, `Mode`, `EvidenceRef`, `ImportedRoster`, `is_bcp47`, `is_item_value`, `MAX_EVIDENCE_BYTES`, `EVIDENCE_MEDIA_TYPES` |
| `export` | Export files: `ExportFile`, `ExportPart`, `ExportHeader`, `ExportSignature`, `SectionType`, `repair`, `salvage_frames`, `export_signed_structure`, `parity_to_value`, `parity_from_value`, `EXPORT_MAGIC` (`FSX1`), `EXPORT_FORMAT`, `SECTION_HEADER_LEN` |
| `parity` | Reed-Solomon over GF(2^8): `K` = 10, `M` = 4, `Parity`, `shard_size`, `compute`, `repair` |
| `crc` | `crc32c` |
| `local_record` | `SessionKey`, `derive_session_key`, `LocalEntry`, `local_record_aad`, `SESSION_KEY_INFO`, `NONCE_LEN` (12), `MAX_ENCRYPTIONS` (2^32) |
| `pop` | Proof-of-possession tokens: `PopToken`, `POP_HEADER` (`Fieldseal-PoP`), `MAX_POP_TOKEN` (4 KiB) |
| `qr_sequence` | Animated QR frames `FS1A:<seq>/<total>:<message-id>:<payload>`: `message_id`, `encode_sequence`, `Frame`, `Reassembler`, `FRAME_PREFIX`, `MAX_FRAME_CHARS`, `CHUNK_BYTES`, `MAX_FRAMES`, `MAX_OBJECT`, `MAX_OPEN_MESSAGES` |
| `text` | Typed text forms (prefix, Crockford base32, CRC-10 check): `encode`, `decode`, `crc10`, `crockford_base32_decode`, prefixes `FS1T:`, `FS1C:`, `FS1R:`, `FS1N:`, `MAX_QR_OBJECT` |
| `base64url` | `base64url_encode`, `base64url_decode` (unpadded, RFC 4648 section 5) |
| `words` | Fingerprint words over the BIP-39 list: `word`, `index_of`, `indices`, `indices_of_digest`, `join`, `LIST_LEN` (2048), `SEPARATOR` |
| `time` | `AuthorityTime` (ms since epoch), `ElapsedReading`, `Tick` |

Golden vectors live in `tests/vectors/*.json` and are checked by `tests/vectors.rs`; the Python
binding reuses them ([../bindings/python/README.md](../bindings/python/README.md)).

## Invariants

- Encoding is deterministic CBOR (RFC 8949 section 4.2.1 restricted to the data model): integers within
  -2^64..=2^64-1, tag-4 decimals as the only tag, NFC text, text-keyed maps, no null, floats or simple
  values. A decoder accepts exactly the bytes the encoder produces.
- Signatures are ECDSA P-256 over the canonical CBOR array `[domain-tag, structure]`, 64-byte `r || s`
  with low `s`, deterministic (RFC 6979).
- Seals are HPKE (RFC 9180 base mode) with `info` set to the domain tag; suites `fs1-x` and `fs1-p`.
- Structure readers are closed: unknown or missing/mistyped fields fail with `E_UNKNOWN_FIELD`.
- Every wire-level failure carries exactly one `ErrorCode` (WIRE-161).
- Journal frames use magic `FSR1`, CRC-32C of the body; export sections use CRC-32C; the record chain
  links each header's `prev` to the previous record hash.
- Parity is fixed byte for byte (k = 10, m = 4, polynomial `0x11D`, generator 2) so independent
  implementations agree.
- Distinct id types prevent passing one identifier where another is expected.
- Vector files must match what the generator produces (`vectors_are_current`); fixed randomness exists
  only in tests.

## Side Effects

None. The crate performs no I/O and reads no clock, randomness or environment. Secret material uses
zeroizing types (`SessionKey`, opened plaintext).

## Verification

- Run: `cargo test -p fieldseal-kernel`
- Regenerate vectors after an intended format change: `FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-kernel --test vectors`
