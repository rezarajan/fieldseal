//! Golden vectors for the wire formats (WIRE §8).
//!
//! The vectors live in `tests/vectors/*.json`: inputs, expected hex outputs, and invalid
//! inputs with the error code (and byte offset) a decoder must report. Each `wire_*` test
//! below checks every vector in one file against the library, independently of how the file
//! was made. `vectors_are_current` regenerates every file in memory and fails if the result
//! differs from what is on disk.
//!
//! To regenerate after an intended format change (WIRE-151):
//!
//! ```text
//! FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-kernel --test vectors
//! ```
//!
//! Generation is deterministic: every key, salt, record ID and HPKE ephemeral key is derived
//! from a fixed label with SHA-256 (`seed(label)`), and HPKE's randomness comes from
//! [`FixedRng`], which yields exactly the recorded `ikm_e` bytes. Fixed randomness exists
//! only here, never in the library.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::PathBuf;

use fieldseal_kernel::cbor::{self, map};
use fieldseal_kernel::crc::crc32c;
use fieldseal_kernel::crypto::{DomainTag, P256PublicKey, Signature, tags};
use fieldseal_kernel::digest::{instrument_fingerprint, key_id, lower_hex, sha256};
use fieldseal_kernel::export::{EXPORT_MAGIC, ExportFile, ExportHeader, ExportPart, salvage_frames};
use fieldseal_kernel::frame::{frame, read_frames};
use fieldseal_kernel::id::{ContentAddress, Digest, Salt, TenancyHandle, TenancyId};
use fieldseal_kernel::local_record::{LocalEntry, MAX_ENCRYPTIONS, derive_session_key, local_record_aad};
use fieldseal_kernel::pop::{MAX_POP_TOKEN, PopToken};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::qr_sequence::{CHUNK_BYTES, Frame, MAX_FRAMES, MAX_FRAME_CHARS, Reassembler, encode_sequence, message_id};
use fieldseal_kernel::digest::crockford_base32;
use fieldseal_kernel::record::{Record, RecordHeader, read_journal, record_hash, record_id_from_random};
use fieldseal_kernel::seal::{RecipientSecret, SealedBox, Suite, open, seal, seal_value};
use fieldseal_kernel::sign::{SigningKey, signed_message, verify};
use fieldseal_kernel::{Decimal, ErrorCode, Value, WireError};
use serde_json::{Value as J, json};

// ---------------------------------------------------------------------------------------
// Helpers shared by generation and verification.

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn hex(bytes: &[u8]) -> String {
    lower_hex(bytes)
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn seed(label: &str) -> [u8; 32] {
    *sha256(format!("fieldseal.dev/vectors/{label}").as_bytes()).as_bytes()
}

fn seed16(label: &str) -> [u8; 16] {
    seed(label)[..16].try_into().unwrap()
}

/// A random source that yields exactly the given bytes, then panics.
struct FixedRng(Vec<u8>);

impl rand_core::TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(dst.len() <= self.0.len(), "FixedRng exhausted");
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}
impl rand_core::TryCryptoRng for FixedRng {}

/// The typed JSON form of a [`Value`]: `{"int": "<decimal>"}`, `{"decimal": {"exponent",
/// "mantissa"}}`, `{"bytes": "<hex>"}`, `{"text": ...}`, `{"bool": ...}`, `{"array": [...]}`,
/// `{"map": {...}}`. Integers are strings because they range over −2⁶⁴..2⁶⁴−1.
fn to_j(v: &Value) -> J {
    match v {
        Value::Int(i) => json!({"int": i.to_string()}),
        Value::Decimal(d) => json!({"decimal": {"exponent": d.exponent, "mantissa": d.mantissa.to_string()}}),
        Value::Bytes(b) => json!({"bytes": hex(b)}),
        Value::Text(t) => json!({"text": t}),
        Value::Bool(b) => json!({"bool": b}),
        Value::Array(a) => json!({"array": a.iter().map(to_j).collect::<Vec<_>>()}),
        Value::Map(m) => json!({"map": m.iter().map(|(k, v)| (k.clone(), to_j(v))).collect::<serde_json::Map<_, _>>()}),
    }
}

fn from_j(j: &J) -> Value {
    let (kind, inner) = j.as_object().and_then(|o| o.iter().next()).expect("typed value");
    match kind.as_str() {
        "int" => Value::Int(inner.as_str().unwrap().parse().unwrap()),
        "decimal" => Value::Decimal(Decimal {
            exponent: inner["exponent"].as_i64().unwrap() as i32,
            mantissa: inner["mantissa"].as_str().unwrap().parse().unwrap(),
        }),
        "bytes" => Value::Bytes(unhex(inner.as_str().unwrap())),
        "text" => Value::Text(inner.as_str().unwrap().to_owned()),
        "bool" => Value::Bool(inner.as_bool().unwrap()),
        "array" => Value::Array(inner.as_array().unwrap().iter().map(from_j).collect()),
        "map" => Value::Map(inner.as_object().unwrap().iter().map(|(k, v)| (k.clone(), from_j(v))).collect()),
        other => panic!("unknown typed value {other}"),
    }
}

fn err_j(e: &WireError) -> J {
    json!({"error": e.code.as_str(), "offset": e.offset})
}

fn code_of(j: &J) -> ErrorCode {
    ErrorCode::parse(j["error"].as_str().unwrap()).expect("known code")
}

fn int(i: i128) -> Value {
    Value::Int(i)
}
fn text(t: &str) -> Value {
    Value::Text(t.to_owned())
}
fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}
fn dec(mantissa: i128, exponent: i32) -> Value {
    Value::Decimal(Decimal { mantissa, exponent })
}

fn header(description: &str) -> J {
    json!({
        "description": description,
        "spec": "docs/reference/spec/wire-formats.md",
        "regenerate": "FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-kernel --test vectors",
    })
}

fn with(mut base: J, extra: J) -> J {
    base.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    base
}

/// The fixed keys of the vectors.
struct Keys {
    tenancy: SigningKey,
    signer: SigningKey,
    record: RecipientSecret,
    agree: RecipientSecret,
}

fn keys() -> Keys {
    Keys {
        tenancy: SigningKey::from_scalar(&seed("tenancy-signing-key")).unwrap(),
        signer: SigningKey::from_scalar(&seed("authority-signing-key")).unwrap(),
        record: RecipientSecret::from_bytes(Suite::Fs1X, &seed("authority-record-key")).unwrap(),
        agree: RecipientSecret::from_bytes(Suite::Fs1P, &seed("device-agreement-key")).unwrap(),
    }
}

// ---------------------------------------------------------------------------------------
// cbor.json

fn gen_cbor() -> J {
    let nested = (0..15).fold(int(0), |v, _| Value::Array(vec![v]));
    let valid: Vec<(&str, &str, Value)> = vec![
        ("uint-0", "WIRE-001", int(0)),
        ("uint-23", "WIRE-001", int(23)),
        ("uint-24", "WIRE-001", int(24)),
        ("uint-255", "WIRE-001", int(255)),
        ("uint-256", "WIRE-001", int(256)),
        ("uint-65535", "WIRE-001", int(65535)),
        ("uint-65536", "WIRE-001", int(65536)),
        ("uint-2^32-1", "WIRE-001", int(0xffff_ffff)),
        ("uint-2^32", "WIRE-001", int(0x1_0000_0000)),
        ("uint-max", "WIRE-001", int((1 << 64) - 1)),
        ("nint-1", "WIRE-001", int(-1)),
        ("nint-24", "WIRE-001", int(-24)),
        ("nint-25", "WIRE-001", int(-25)),
        ("nint-min", "WIRE-001", int(-(1 << 64))),
        ("decimal-98.40", "WIRE-006", dec(9840, -2)),
        ("decimal-98.4", "WIRE-006", dec(984, -1)),
        ("decimal-negative", "WIRE-006", dec(-5, -2)),
        ("decimal-big-mantissa", "WIRE-006", dec((1 << 64) - 1, -30)),
        ("bytes-empty", "WIRE-001", bytes(&[])),
        ("bytes-24", "WIRE-001", bytes(&[0xab; 24])),
        ("text-empty", "WIRE-004", text("")),
        ("text-nfc", "WIRE-004", text("Café 名前")),
        ("bool-false", "WIRE-001", Value::Bool(false)),
        ("bool-true", "WIRE-001", Value::Bool(true)),
        ("array-mixed", "WIRE-052", Value::Array(vec![text("a"), int(1), dec(15, -1), Value::Bool(true)])),
        ("map-key-order-length-first", "WIRE-001", map([("aa", int(1)), ("b", int(2)), ("a", int(3))])),
        ("map-nonresponse", "WIRE-052", map([("nr", text("dont-know"))])),
        ("map-retracted", "WIRE-052", map([("retracted", Value::Bool(true))])),
        ("map-empty", "WIRE-001", map([])),
        ("depth-16", "WIRE-160", Value::Array(vec![nested])),
    ];
    let valid: Vec<J> = valid
        .into_iter()
        .map(|(id, req, v)| json!({"id": id, "requirement": req, "value": to_j(&v), "cbor": hex(&cbor::encode(&v).unwrap())}))
        .collect();

    let invalid: Vec<(&str, &str, String, ErrorCode)> = vec![
        ("nonshortest-uint8", "WIRE-002", "1817".into(), ErrorCode::CborNoncanonical),
        ("nonshortest-uint16", "WIRE-002", "1900ff".into(), ErrorCode::CborNoncanonical),
        ("nonshortest-uint32", "WIRE-002", "1a0000ffff".into(), ErrorCode::CborNoncanonical),
        ("nonshortest-uint64", "WIRE-002", "1b00000000ffffffff".into(), ErrorCode::CborNoncanonical),
        ("nonshortest-length", "WIRE-002", "580161".into(), ErrorCode::CborNoncanonical),
        ("nonshortest-map-length", "WIRE-002", "b800".into(), ErrorCode::CborNoncanonical),
        ("indefinite-bytes", "WIRE-001", "5f4101ff".into(), ErrorCode::CborNoncanonical),
        ("indefinite-text", "WIRE-001", "7f6161ff".into(), ErrorCode::CborNoncanonical),
        ("indefinite-array", "WIRE-001", "9f01ff".into(), ErrorCode::CborNoncanonical),
        ("indefinite-map", "WIRE-001", "bf616101ff".into(), ErrorCode::CborNoncanonical),
        ("reserved-ai-28", "WIRE-002", "1c".into(), ErrorCode::CborNoncanonical),
        ("lone-break", "WIRE-002", "ff".into(), ErrorCode::CborNoncanonical),
        ("unsorted-keys", "WIRE-001", "a2616201616102".into(), ErrorCode::CborNoncanonical),
        ("unsorted-keys-length-first", "WIRE-001", "a262616101616202".into(), ErrorCode::CborNoncanonical),
        ("duplicate-key", "WIRE-003", "a2616101616102".into(), ErrorCode::CborDuplicate),
        ("duplicate-key-nested", "WIRE-003", "a1616ba2617801617802".into(), ErrorCode::CborDuplicate),
        ("int-key", "WIRE-004", "a10101".into(), ErrorCode::CborNoncanonical),
        ("bytes-key", "WIRE-004", "a1416101".into(), ErrorCode::CborNoncanonical),
        ("text-nfd", "WIRE-004", "6365cc81".into(), ErrorCode::CborNoncanonical),
        ("key-nfd", "WIRE-004", "a16365cc8101".into(), ErrorCode::CborNoncanonical),
        ("text-invalid-utf8", "WIRE-004", "62c328".into(), ErrorCode::CborNoncanonical),
        ("float16", "WIRE-006", "f93c00".into(), ErrorCode::CborNoncanonical),
        ("float32", "WIRE-006", "fa47c35000".into(), ErrorCode::CborNoncanonical),
        ("float64", "WIRE-006", "fb3ff199999999999a".into(), ErrorCode::CborNoncanonical),
        ("decimal-float-mantissa", "WIRE-006", "c48221f93c00".into(), ErrorCode::CborNoncanonical),
        ("decimal-three-elements", "WIRE-006", "c483210102".into(), ErrorCode::CborNoncanonical),
        ("decimal-exponent-beyond-i32", "WIRE-006", "c4821b000000010000000001".into(), ErrorCode::CborNoncanonical),
        ("null", "WIRE-006", "f6".into(), ErrorCode::CborNoncanonical),
        ("undefined", "WIRE-006", "f7".into(), ErrorCode::CborNoncanonical),
        ("simple-16", "WIRE-006", "f0".into(), ErrorCode::CborNoncanonical),
        ("tag-0-datetime", "WIRE-007", "c074323031332d30332d32315432303a30343a30305a".into(), ErrorCode::CborTag),
        ("tag-1-epoch", "WIRE-007", "c11a514b67b0".into(), ErrorCode::CborTag),
        ("tag-2-bignum", "WIRE-007", "c249010000000000000000".into(), ErrorCode::CborTag),
        ("tag-5-bigfloat", "WIRE-007", "c5822003".into(), ErrorCode::CborTag),
        ("decimal-bignum-mantissa", "WIRE-007", "c48221c249010000000000000000".into(), ErrorCode::CborTag),
        ("tag-in-array", "WIRE-007", "8201d82076".into(), ErrorCode::CborTag),
        ("trailing-bytes", "WIRE-002", "0000".into(), ErrorCode::CborNoncanonical),
        ("truncated-uint", "WIRE-002", "19ff".into(), ErrorCode::CborNoncanonical),
        ("truncated-text", "WIRE-002", "6461".into(), ErrorCode::CborNoncanonical),
        ("truncated-array", "WIRE-002", "8301".into(), ErrorCode::CborNoncanonical),
        ("empty-input", "WIRE-002", "".into(), ErrorCode::CborNoncanonical),
        ("depth-17", "WIRE-160", format!("{}00", "81".repeat(17)), ErrorCode::Size),
        ("text-over-64k", "WIRE-160", "7a00010001".into(), ErrorCode::Size),
        ("array-over-limit", "WIRE-160", "9a00100001".into(), ErrorCode::Size),
        ("map-over-limit", "WIRE-160", "ba00100001".into(), ErrorCode::Size),
    ];
    let invalid: Vec<J> = invalid
        .into_iter()
        .map(|(id, req, h, code)| {
            let e = cbor::decode(&unhex(&h)).expect_err(id);
            assert_eq!(e.code, code, "{id}");
            with(json!({"id": id, "requirement": req, "cbor": h}), err_j(&e))
        })
        .collect();

    let invalid_encode: Vec<(&str, &str, Value, ErrorCode)> = vec![
        ("int-2^64", "WIRE-001", int(1 << 64), ErrorCode::CborNoncanonical),
        ("int-below-min", "WIRE-001", int(-(1 << 64) - 1), ErrorCode::CborNoncanonical),
        ("text-nfd", "WIRE-004", text("e\u{301}"), ErrorCode::CborNoncanonical),
        ("key-nfd", "WIRE-004", map([("e\u{301}", int(1))]), ErrorCode::CborNoncanonical),
    ];
    let invalid_encode: Vec<J> = invalid_encode
        .into_iter()
        .map(|(id, req, v, code)| {
            let e = cbor::encode(&v).expect_err(id);
            assert_eq!(e.code, code, "{id}");
            json!({"id": id, "requirement": req, "value": to_j(&v), "error": code.as_str()})
        })
        .collect();

    // Plain JSON inputs for bindings that build values from JSON (numbers with a fraction or
    // exponent become decimals keeping every written digit; integers stay integers).
    let from_json: Vec<(&str, &str, Value)> = vec![
        ("json-object", r#"{"b": 1.50, "aa": [1, "x", true, -2], "c": {"nr": "refused"}}"#,
            map([("b", dec(150, -2)), ("aa", Value::Array(vec![int(1), text("x"), Value::Bool(true), int(-2)])), ("c", map([("nr", text("refused"))]))])),
        ("json-decimal-exponent", r#"[1.5e3, -0.05, 2E-3, 10]"#, Value::Array(vec![dec(15, 2), dec(-5, -2), dec(2, -3), int(10)])),
        ("json-big-integers", r#"[18446744073709551615, -18446744073709551616]"#, Value::Array(vec![int((1 << 64) - 1), int(-(1 << 64))])),
        ("json-text", r#"{"name": "Café", "empty": ""}"#, map([("name", text("Café")), ("empty", text(""))])),
    ];
    let from_json: Vec<J> = from_json
        .into_iter()
        .map(|(id, j, v)| json!({"id": id, "requirement": "WIRE-006", "json": j, "value": to_j(&v), "cbor": hex(&cbor::encode(&v).unwrap())}))
        .collect();

    with(
        header("Deterministic CBOR (WIRE §5.1): valid values with their only encoding, and inputs a decoder must reject."),
        json!({"valid": valid, "invalid": invalid, "invalid_encode": invalid_encode, "from_json": from_json}),
    )
}

#[test]
fn wire_001_to_007_cbor_vectors() {
    let v = load("cbor.json");
    for case in v["valid"].as_array().unwrap() {
        let value = from_j(&case["value"]);
        let bytes = unhex(case["cbor"].as_str().unwrap());
        assert_eq!(cbor::encode(&value).unwrap(), bytes, "{}", case["id"]);
        assert_eq!(cbor::decode(&bytes).unwrap(), value, "{}", case["id"]);
    }
    for case in v["invalid"].as_array().unwrap() {
        let e = cbor::decode(&unhex(case["cbor"].as_str().unwrap())).expect_err(case["id"].as_str().unwrap());
        assert_eq!(e.code, code_of(case), "{}", case["id"]);
        assert_eq!(e.offset as u64, case["offset"].as_u64().unwrap(), "{}", case["id"]);
    }
    for case in v["invalid_encode"].as_array().unwrap() {
        let e = cbor::encode(&from_j(&case["value"])).expect_err(case["id"].as_str().unwrap());
        assert_eq!(e.code, code_of(case), "{}", case["id"]);
    }
    for case in v["from_json"].as_array().unwrap() {
        assert_eq!(hex(&cbor::encode(&from_j(&case["value"])).unwrap()), case["cbor"].as_str().unwrap());
    }
}

// ---------------------------------------------------------------------------------------
// identifiers.json

fn gen_identifiers() -> J {
    let k = keys();
    let objects: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("abc", b"abc".to_vec()),
        ("canonical-map", cbor::encode(&map([("v", int(1)), ("name", text("x"))])).unwrap()),
    ];
    let addresses: Vec<J> = objects
        .iter()
        .map(|(id, b)| json!({"id": id, "requirement": "WIRE-011", "bytes": hex(b), "address": ContentAddress::of(b).to_text()}))
        .collect();
    let invalid_addresses: Vec<J> = [
        ("uppercase-hex", "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
        ("missing-prefix", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("short", "sha256:e3b0c442"),
        ("wrong-algorithm", "sha512:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ]
    .into_iter()
    .map(|(id, t)| with(json!({"id": id, "requirement": "WIRE-011", "text": t}), err_j(&ContentAddress::parse_text(t).unwrap_err())))
    .collect();
    let record_pub = k.record.public().unwrap();
    let agree_pub = k.agree.public().unwrap();
    let key_ids: Vec<J> = [
        ("p256-signing", k.tenancy.public_key().as_bytes().to_vec()),
        ("p256-agreement", agree_pub.encoded().to_vec()),
        ("x25519-record", record_pub.encoded().to_vec()),
    ]
    .into_iter()
    .map(|(id, p)| json!({"id": id, "requirement": "WIRE-010", "public_key": hex(&p), "key_id": hex(key_id(&p).as_bytes())}))
    .collect();
    let instrument = cbor::encode(&map([("kind", text("instrument")), ("items", Value::Array(vec![]))])).unwrap();
    let fingerprints: Vec<J> = [("salt-a", seed("salt-a")), ("salt-b", seed("salt-b"))]
        .into_iter()
        .map(|(id, salt)| {
            let fp = instrument_fingerprint(&Salt::from(salt), &instrument);
            json!({"id": id, "requirement": "WIRE-185", "salt": hex(&salt), "canonical": hex(&instrument),
                   "fingerprint": hex(fp.as_bytes()), "short_form": fp.short_form()})
        })
        .collect();
    with(
        header("Content addresses (WIRE-011), key IDs (WIRE-010) and salted instrument fingerprints (WIRE-185..187). The two fingerprints share content and differ only by salt."),
        json!({"content_addresses": addresses, "invalid_content_addresses": invalid_addresses, "key_ids": key_ids, "fingerprints": fingerprints}),
    )
}

#[test]
fn wire_010_011_185_identifier_vectors() {
    let v = load("identifiers.json");
    for c in v["content_addresses"].as_array().unwrap() {
        let a = ContentAddress::of(&unhex(c["bytes"].as_str().unwrap()));
        assert_eq!(a.to_text(), c["address"].as_str().unwrap());
        assert_eq!(ContentAddress::parse_text(c["address"].as_str().unwrap()).unwrap(), a);
    }
    for c in v["invalid_content_addresses"].as_array().unwrap() {
        assert_eq!(ContentAddress::parse_text(c["text"].as_str().unwrap()).unwrap_err().code, code_of(c));
    }
    for c in v["key_ids"].as_array().unwrap() {
        assert_eq!(hex(key_id(&unhex(c["public_key"].as_str().unwrap())).as_bytes()), c["key_id"].as_str().unwrap());
    }
    let mut seen = Vec::new();
    for c in v["fingerprints"].as_array().unwrap() {
        let salt = Salt::from_bytes(&unhex(c["salt"].as_str().unwrap())).unwrap();
        let fp = instrument_fingerprint(&salt, &unhex(c["canonical"].as_str().unwrap()));
        assert_eq!(hex(fp.as_bytes()), c["fingerprint"].as_str().unwrap());
        assert_eq!(fp.short_form(), c["short_form"].as_str().unwrap());
        seen.push(fp);
    }
    assert_ne!(seen[0], seen[1], "same content, different salt, different fingerprint");
}

// ---------------------------------------------------------------------------------------
// signatures.json

/// The P-256 group order.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad,
    0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `n − s`, turning a low-s signature into its high-s twin.
fn high_s(sig: &Signature) -> Signature {
    let mut out = sig.0.clone();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(N[i]) - i16::from(sig.0[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        out[32 + i] = d.rem_euclid(256) as u8;
    }
    Signature(out)
}

fn signature_structures() -> Vec<(&'static str, &'static str, DomainTag, Value)> {
    vec![
        ("receipt", "WIRE-142", tags::RECEIPT, map([
            ("v", int(1)), ("tenancy", bytes(&seed("tenancy"))), ("last_seq", int(41)),
            ("hash_at", bytes(&seed("hash-at"))), ("received", int(1_767_225_600_000)),
            ("of", bytes(&seed("export"))), ("signer", bytes(&seed16("receipt-key"))),
        ])),
        ("publication-statement", "WIRE-190", tags::PUBLICATION, map([
            ("type", text("publish")), ("fingerprint", bytes(&seed("fingerprint"))), ("provenance", bytes(&seed("provenance"))),
        ])),
        ("empty-structure", "WIRE-021", tags::TIME_TOKEN, map([])),
    ]
}

fn gen_signatures() -> J {
    let key = &keys().signer;
    let public = key.public_key();
    let valid: Vec<J> = signature_structures()
        .into_iter()
        .map(|(id, req, tag, s)| {
            let sig = key.sign(&tag, &s).unwrap();
            json!({"id": id, "requirement": req, "tag": tag.as_str(), "structure": to_j(&s),
                   "message": hex(&signed_message(&tag, &s).unwrap()), "signature": hex(&sig.0)})
        })
        .collect();
    let (_, _, tag, s) = signature_structures().remove(0);
    let sig = key.sign(&tag, &s).unwrap();
    let mut flipped = sig.clone();
    flipped.0[10] ^= 1;
    let negatives: Vec<(&str, &str, &str, Signature)> = vec![
        ("high-s", "WIRE-022", tag.as_str(), high_s(&sig)),
        ("bit-flip", "WIRE-021", tag.as_str(), flipped),
        ("truncated", "WIRE-022", tag.as_str(), Signature(sig.0[..63].to_vec())),
        ("der-encoded", "WIRE-022", tag.as_str(), Signature([vec![0x30, 0x44, 0x02, 0x20], sig.0[..32].to_vec(), vec![0x02, 0x20], sig.0[32..].to_vec()].concat())),
        ("other-known-tag", "WIRE-020", tags::TIME_TOKEN.as_str(), sig.clone()),
        ("unknown-tag", "WIRE-020", "fieldseal.dev/receipt/v2", sig.clone()),
        ("seal-tag", "WIRE-020", tags::RECORD_SEAL.as_str(), sig.clone()),
    ];
    let invalid: Vec<J> = negatives
        .into_iter()
        .map(|(id, req, t, sig)| {
            let e = match DomainTag::known(t) {
                Ok(tag) => verify(&public, &tag, &s, &sig).unwrap_err(),
                Err(e) => e,
            };
            with(json!({"id": id, "requirement": req, "tag": t, "structure": to_j(&s), "signature": hex(&sig.0)}), err_j(&e))
        })
        .collect();
    with(
        header("Domain-tagged ECDSA P-256 signatures (WIRE-020..022). message = canonical CBOR [tag, structure]; signature = r || s, low s, RFC 6979 deterministic. The private key is SHA-256(\"fieldseal.dev/vectors/authority-signing-key\")."),
        json!({"private_key": hex(&seed("authority-signing-key")), "public_key": hex(public.as_bytes()), "valid": valid, "invalid": invalid}),
    )
}

// covers: WIRE-021
#[test]
fn wire_020_021_022_signature_vectors() {
    let v = load("signatures.json");
    let key = SigningKey::from_scalar(&unhex(v["private_key"].as_str().unwrap())).unwrap();
    let public = P256PublicKey::from_bytes(&unhex(v["public_key"].as_str().unwrap())).unwrap();
    assert_eq!(key.public_key(), public);
    for c in v["valid"].as_array().unwrap() {
        let tag = DomainTag::known(c["tag"].as_str().unwrap()).unwrap();
        let s = from_j(&c["structure"]);
        let sig = Signature(unhex(c["signature"].as_str().unwrap()));
        assert_eq!(hex(&signed_message(&tag, &s).unwrap()), c["message"].as_str().unwrap());
        verify(&public, &tag, &s, &sig).unwrap();
        assert_eq!(key.sign(&tag, &s).unwrap(), sig, "deterministic signing reproduces {}", c["id"]);
    }
    for c in v["invalid"].as_array().unwrap() {
        let s = from_j(&c["structure"]);
        let sig = Signature(unhex(c["signature"].as_str().unwrap()));
        let e = match DomainTag::known(c["tag"].as_str().unwrap()) {
            Ok(tag) => verify(&public, &tag, &s, &sig).unwrap_err(),
            Err(e) => e,
        };
        assert_eq!(e.code, code_of(c), "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// seals.json

fn gen_seals() -> J {
    let k = keys();
    let plaintext = cbor::encode(&map([("body", text("sealed payload")), ("n", int(7))])).unwrap();
    let cases: Vec<(&str, &str, &RecipientSecret, DomainTag)> = vec![
        ("fs1-x-record-seal", "WIRE-023", &k.record, tags::RECORD_SEAL),
        ("fs1-p-bundle-seal", "WIRE-023", &k.agree, tags::BUNDLE_SEAL),
    ];
    let mut sealed_boxes = Vec::new();
    let valid: Vec<J> = cases
        .iter()
        .map(|(id, req, secret, tag)| {
            let ikm = seed(&format!("ikm-e/{id}"));
            let public = secret.public().unwrap();
            let sealed = seal(&mut FixedRng(ikm.to_vec()), &public, tag, &plaintext).unwrap();
            sealed_boxes.push(sealed.clone());
            json!({"id": id, "requirement": req, "suite": sealed.suite.id(), "tag": tag.as_str(),
                   "recipient_private_key": hex(&seed(match secret.suite() { Suite::Fs1X => "authority-record-key", Suite::Fs1P => "device-agreement-key" })),
                   "recipient_public_key": hex(public.encoded()), "recipient_key_id": hex(public.key_id().as_bytes()),
                   "plaintext": hex(&plaintext), "ikm_e": hex(&ikm), "enc": hex(&sealed.enc), "ct": hex(&sealed.ct),
                   "sealed": hex(&sealed.encode())})
        })
        .collect();
    let x = &sealed_boxes[0];
    let p = &sealed_boxes[1];
    let mut tampered = x.clone();
    tampered.ct[0] ^= 1;
    let mut other_recipient = x.clone();
    other_recipient.recipient = key_id(b"someone else");
    let negatives: Vec<(&str, &str, &str, Vec<u8>)> = vec![
        ("suite-mismatch", "WIRE-024", tags::RECORD_SEAL.as_str(), p.encode()),
        ("other-recipient", "WIRE-024", tags::RECORD_SEAL.as_str(), other_recipient.encode()),
        ("tampered-ct", "WIRE-023", tags::RECORD_SEAL.as_str(), tampered.encode()),
        ("other-seal-tag", "WIRE-023", tags::EXPORT_MANIFEST_SEAL.as_str(), x.encode()),
        ("signature-tag", "WIRE-020", tags::RECORD.as_str(), x.encode()),
        ("unknown-suite", "WIRE-024", tags::RECORD_SEAL.as_str(),
            cbor::encode(&{ let mut v = x.to_value(); if let Value::Map(m) = &mut v { m.insert("suite".into(), text("fs2-x")); } v }).unwrap()),
        ("unknown-field", "WIRE-005", tags::RECORD_SEAL.as_str(),
            cbor::encode(&{ let mut v = x.to_value(); if let Value::Map(m) = &mut v { m.insert("aad".into(), bytes(&[])); } v }).unwrap()),
    ];
    let invalid: Vec<J> = negatives
        .into_iter()
        .map(|(id, req, tag, sealed)| {
            // Every negative is opened with the fs1-x record key.
            let e = open_case(&k.record, tag, &sealed).unwrap_err();
            with(json!({"id": id, "requirement": req, "recipient_private_key": hex(&seed("authority-record-key")), "suite_of_key": "fs1-x", "tag": tag, "sealed": hex(&sealed)}), err_j(&e))
        })
        .collect();
    with(
        header("HPKE seals (WIRE-023, WIRE-024): RFC 9180 base mode, info = the domain tag's UTF-8 bytes, empty AAD. ikm_e is the randomness the sender's random source yielded; the ephemeral key is DeriveKeyPair(ikm_e)."),
        json!({"valid": valid, "invalid": invalid}),
    )
}

fn open_case(secret: &RecipientSecret, tag: &str, sealed: &[u8]) -> Result<Vec<u8>, WireError> {
    let tag = DomainTag::known(tag)?;
    let sealed = SealedBox::decode(sealed)?;
    open(secret, &tag, &sealed).map(|p| p.to_vec())
}

// covers: WIRE-024
#[test]
fn wire_023_024_seal_vectors() {
    let v = load("seals.json");
    for c in v["valid"].as_array().unwrap() {
        let suite = Suite::parse(c["suite"].as_str().unwrap()).unwrap();
        let secret = RecipientSecret::from_bytes(suite, &unhex(c["recipient_private_key"].as_str().unwrap())).unwrap();
        let public = secret.public().unwrap();
        assert_eq!(hex(public.encoded()), c["recipient_public_key"].as_str().unwrap());
        assert_eq!(hex(public.key_id().as_bytes()), c["recipient_key_id"].as_str().unwrap());
        let tag = DomainTag::known(c["tag"].as_str().unwrap()).unwrap();
        let sealed_bytes = unhex(c["sealed"].as_str().unwrap());
        let sealed = SealedBox::decode(&sealed_bytes).unwrap();
        assert_eq!(hex(&sealed.enc), c["enc"].as_str().unwrap());
        assert_eq!(hex(&sealed.ct), c["ct"].as_str().unwrap());
        let plaintext = unhex(c["plaintext"].as_str().unwrap());
        assert_eq!(open(&secret, &tag, &sealed).unwrap().as_slice(), plaintext.as_slice());
        let resealed = seal(&mut FixedRng(unhex(c["ikm_e"].as_str().unwrap())), &public, &tag, &plaintext).unwrap();
        assert_eq!(resealed.encode(), sealed_bytes, "sealing with the recorded ikm_e reproduces {}", c["id"]);
    }
    for c in v["invalid"].as_array().unwrap() {
        let suite = Suite::parse(c["suite_of_key"].as_str().unwrap()).unwrap();
        let secret = RecipientSecret::from_bytes(suite, &unhex(c["recipient_private_key"].as_str().unwrap())).unwrap();
        let e = open_case(&secret, c["tag"].as_str().unwrap(), &unhex(c["sealed"].as_str().unwrap())).unwrap_err();
        assert_eq!(e.code, code_of(c), "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// frames.json

fn gen_frames() -> J {
    let crcs: Vec<J> = [b"".to_vec(), b"123456789".to_vec(), vec![0u8; 32], vec![0xff; 32], (0u8..32).collect()]
        .into_iter()
        .map(|b| json!({"requirement": "WIRE-031", "bytes": hex(&b), "crc32c": format!("{:08x}", crc32c(&b))}))
        .collect();
    let bodies: Vec<Vec<u8>> = vec![b"".to_vec(), b"one".to_vec(), cbor::encode(&map([("seq", int(1))])).unwrap()];
    let frames: Vec<J> = bodies.iter().map(|b| json!({"requirement": "WIRE-031", "body": hex(b), "frame": hex(&frame(b).unwrap())})).collect();
    let journal: Vec<u8> = [b"alpha".as_slice(), b"beta", b"gamma", b"delta"].iter().flat_map(|b| frame(b).unwrap()).collect();
    let offsets = [0usize, 19, 37, 56];
    let scans: Vec<(&str, &str, Vec<u8>)> = vec![
        ("intact", "WIRE-032", journal.clone()),
        ("crc-and-length-damage", "WIRE-032", {
            let mut j = journal.clone();
            j[offsets[1] + 14] ^= 0x01; // body bit flip: E_CRC
            j[offsets[2] + 6] = 0x7f; // impossible length: E_FRAME_LENGTH
            j
        }),
        ("garbage-between-frames", "WIRE-032", [&journal[..offsets[2]], b"\x00junk", &journal[offsets[2]..]].concat()),
        ("bad-version-and-flags", "WIRE-031", {
            let mut j = journal.clone();
            j[offsets[0] + 4] = 0x02;
            j[offsets[3] + 5] = 0x01;
            j
        }),
        ("truncated-tail", "WIRE-032", journal[..journal.len() - 2].to_vec()),
    ];
    let scans: Vec<J> = scans
        .into_iter()
        .map(|(id, req, j)| {
            let scan = read_frames(&j);
            json!({"id": id, "requirement": req, "journal": hex(&j),
                   "frames": scan.frames.iter().map(|f| json!({"offset": f.offset, "body": hex(f.body)})).collect::<Vec<_>>(),
                   "damage": scan.damage.iter().map(err_j).collect::<Vec<_>>()})
        })
        .collect();
    with(
        header("CRC-32C (RFC 3720 §B.4), journal frames (WIRE-031) and frame scanning with damage reports by offset (WIRE-032)."),
        json!({"crc32c": crcs, "frames": frames, "scans": scans}),
    )
}

#[test]
fn wire_031_032_frame_vectors() {
    let v = load("frames.json");
    for c in v["crc32c"].as_array().unwrap() {
        assert_eq!(format!("{:08x}", crc32c(&unhex(c["bytes"].as_str().unwrap()))), c["crc32c"].as_str().unwrap());
    }
    for c in v["frames"].as_array().unwrap() {
        assert_eq!(hex(&frame(&unhex(c["body"].as_str().unwrap())).unwrap()), c["frame"].as_str().unwrap());
    }
    for c in v["scans"].as_array().unwrap() {
        let j = unhex(c["journal"].as_str().unwrap());
        let scan = read_frames(&j);
        let frames: Vec<(u64, String)> = scan.frames.iter().map(|f| (f.offset as u64, hex(f.body))).collect();
        let expected: Vec<(u64, String)> = c["frames"].as_array().unwrap().iter()
            .map(|f| (f["offset"].as_u64().unwrap(), f["body"].as_str().unwrap().to_owned())).collect();
        assert_eq!(frames, expected, "{}", c["id"]);
        let damage: Vec<(ErrorCode, u64)> = scan.damage.iter().map(|e| (e.code, e.offset as u64)).collect();
        let expected: Vec<(ErrorCode, u64)> = c["damage"].as_array().unwrap().iter().map(|d| (code_of(d), d["offset"].as_u64().unwrap())).collect();
        assert_eq!(damage, expected, "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// records.json

struct Journal {
    payloads: Vec<Value>,
    bodies: Vec<Vec<u8>>,
    hashes: Vec<Digest>,
    bytes: Vec<u8>,
}

fn tick(slot: i128) -> Value {
    map([("anchor", bytes(&seed("build-anchor"))), ("slot", int(slot)), ("boot", int(1))])
}

fn make_record(k: &Keys, seq: u64, prev: Digest, payload: &Value) -> Record {
    let record_pub = k.record.public().unwrap();
    let sealed = seal_value(&mut FixedRng(seed(&format!("ikm-e/record-{seq}")).to_vec()), &record_pub, &tags::RECORD_SEAL, payload).unwrap();
    let header = RecordHeader {
        record_id: record_id_from_random(seed16(&format!("record-id-{seq}"))),
        seq,
        prev,
        key: 0,
        period: record_pub.key_id(),
    };
    Record::sign(&k.tenancy, header, sealed).unwrap()
}

fn build_journal(k: &Keys) -> Journal {
    let sign_pub = k.tenancy.public_key();
    let fingerprint = instrument_fingerprint(&Salt::from(seed("salt-a")), b"instrument");
    let mut payloads = vec![
        map([
            ("type", text("open")), ("tick", tick(0)), ("tenancy", bytes(sha256(sign_pub.as_bytes()).as_bytes())),
            ("sign_pub", bytes(sign_pub.as_bytes())), ("agree_pub", bytes(k.agree.public().unwrap().encoded())),
            ("evidence", Value::Array(vec![])), ("build_anchor", bytes(&seed("build-anchor"))),
        ]),
        map([
            ("type", text("items")), ("tick", tick(1500)), ("instrument", bytes(fingerprint.as_bytes())),
            ("layout", text("default")), ("lang", Value::Array(vec![text("en"), text("fr")])),
            ("subject", bytes(b"subject-1")), ("consent_ref", map([("roster", bytes(&seed("roster"))), ("version", int(3))])),
            ("mode", text("first")),
            ("values", map([
                ("body.height", dec(1523, -1)), ("body.weight", dec(4210, -2)), ("visit.agreed", Value::Bool(true)),
                ("diet.notes", map([("nr", text("refused"))])), ("visit.languages", Value::Array(vec![text("en")])),
            ])),
        ]),
    ];
    let mut bodies = Vec::new();
    let mut hashes = Vec::new();
    let mut prev = Digest::from([0; 32]);
    for (seq, payload) in payloads.iter().enumerate() {
        let body = make_record(k, seq as u64, prev, payload).encode().unwrap();
        prev = record_hash(&body);
        hashes.push(prev);
        bodies.push(body);
    }
    let closing = map([("type", text("closing")), ("tick", tick(3000)), ("last_seq", int(2)), ("prev_hash", bytes(prev.as_bytes())), ("reason", text("collector"))]);
    let body = make_record(k, 2, prev, &closing).encode().unwrap();
    hashes.push(record_hash(&body));
    bodies.push(body);
    payloads.push(closing);
    let bytes = bodies.iter().flat_map(|b| frame(b).unwrap()).collect();
    Journal { payloads, bodies, hashes, bytes }
}

fn journal_case(id: &str, req: &str, journal: &[u8], keys: &[P256PublicKey]) -> J {
    let report = read_journal(journal, keys, &[]);
    json!({"id": id, "requirement": req, "journal": hex(journal), "errors": report.errors.iter().map(err_j).collect::<Vec<_>>()})
}

fn gen_records() -> J {
    let k = keys();
    let j = build_journal(&k);
    let history = [k.tenancy.public_key()];
    let records: Vec<J> = j
        .bodies
        .iter()
        .zip(&j.hashes)
        .zip(&j.payloads)
        .map(|((body, hash), payload)| json!({"payload": to_j(payload), "body": hex(body), "hash": hex(hash.as_bytes())}))
        .collect();
    let frames: Vec<Vec<u8>> = j.bodies.iter().map(|b| frame(b).unwrap()).collect();
    let mut negatives = Vec::new();
    // seq gap: drop the record at seq 1.
    negatives.push(journal_case("seq-gap", "WIRE-030", &[frames[0].clone(), frames[2].clone()].concat(), &history));
    // duplicated frame.
    negatives.push(journal_case("duplicated-frame", "WIRE-030", &[frames[0].clone(), frames[1].clone(), frames[1].clone(), frames[2].clone()].concat(), &history));
    // reordered frames.
    negatives.push(journal_case("reordered-frames", "WIRE-030", &[frames[1].clone(), frames[0].clone(), frames[2].clone()].concat(), &history));
    // broken prev: a validly signed record at seq 1 whose prev is not the hash of seq 0.
    let forged = make_record(&k, 1, Digest::from(seed("not-the-hash")), &j.payloads[1]).encode().unwrap();
    negatives.push(journal_case("broken-prev", "WIRE-036", &[frames[0].clone(), frame(&forged).unwrap(), frames[2].clone()].concat(), &history));
    // bad signature: a bit flipped inside the signature, re-framed so the CRC passes.
    let mut bad_sig = j.bodies[1].clone();
    let n = bad_sig.len();
    bad_sig[n - 5] ^= 0x01;
    negatives.push(journal_case("bad-signature", "WIRE-037", &[frames[0].clone(), frame(&bad_sig).unwrap(), frames[2].clone()].concat(), &history));
    // signed by a key outside the history.
    negatives.push(journal_case("unknown-signer", "WIRE-040", &j.bytes, &[k.signer.public_key()]));
    // a header with a field WIRE-034 forbids.
    let mut extra = Record::decode(&j.bodies[0]).unwrap().to_value();
    if let Value::Map(m) = &mut extra
        && let Some(Value::Map(h)) = m.get_mut("header")
    {
        h.insert("type".into(), text("open"));
    }
    negatives.push(journal_case("header-extra-field", "WIRE-034", &frame(&cbor::encode(&extra).unwrap()).unwrap(), &history));
    // a CRC-damaged frame.
    let mut crc = j.bytes.clone();
    crc[frames[0].len() + 20] ^= 0x80;
    negatives.push(journal_case("crc-damage", "WIRE-032", &crc, &history));
    with(
        header("Records and the journal (WIRE-030..040): records signed by the tenancy key (private key SHA-256(\"fieldseal.dev/vectors/tenancy-signing-key\")), payloads sealed with fs1-x to the record key (SHA-256(\"fieldseal.dev/vectors/authority-record-key\")) using ikm_e = SHA-256(\"fieldseal.dev/vectors/ikm-e/record-<seq>\")."),
        json!({
            "tenancy_private_key": hex(&seed("tenancy-signing-key")),
            "tenancy_public_key": hex(k.tenancy.public_key().as_bytes()),
            "record_private_key": hex(&seed("authority-record-key")),
            "records": records,
            "journal": hex(&j.bytes),
            "invalid": negatives,
        }),
    )
}

// covers: WIRE-033, WIRE-037, WIRE-040
#[test]
fn wire_030_to_040_record_vectors() {
    let v = load("records.json");
    let public = P256PublicKey::from_bytes(&unhex(v["tenancy_public_key"].as_str().unwrap())).unwrap();
    let record_key = RecipientSecret::from_bytes(Suite::Fs1X, &unhex(v["record_private_key"].as_str().unwrap())).unwrap();
    let journal = unhex(v["journal"].as_str().unwrap());
    let report = read_journal(&journal, std::slice::from_ref(&public), &[]);
    assert!(report.is_clean(), "{:?}", report.errors);
    let records = v["records"].as_array().unwrap();
    assert_eq!(report.entries.len(), records.len());
    for (entry, c) in report.entries.iter().zip(records) {
        assert_eq!(hex(entry.hash.as_bytes()), c["hash"].as_str().unwrap());
        assert_eq!(hex(&entry.record.encode().unwrap()), c["body"].as_str().unwrap());
        assert!(fieldseal_kernel::record::is_uuid_v4(&entry.record.header.record_id));
        let payload = fieldseal_kernel::seal::open_value(&record_key, &tags::RECORD_SEAL, &entry.record.payload).unwrap();
        assert_eq!(payload, from_j(&c["payload"]));
        if payload.as_map().and_then(|m| m.get("type")).and_then(Value::as_text) == Some("items") {
            let typed = fieldseal_kernel::payload::ItemsPayload::from_value(payload.clone()).unwrap();
            assert_eq!(typed.to_value().unwrap(), payload, "typed items payload round-trips (WIRE-051)");
        }
    }
    for c in v["invalid"].as_array().unwrap() {
        let keys = if c["id"] == "unknown-signer" { vec![keys().signer.public_key()] } else { vec![public.clone()] };
        let report = read_journal(&unhex(c["journal"].as_str().unwrap()), &keys, &[]);
        let got: Vec<(ErrorCode, u64)> = report.errors.iter().map(|e| (e.code, e.offset as u64)).collect();
        let want: Vec<(ErrorCode, u64)> = c["errors"].as_array().unwrap().iter().map(|e| (code_of(e), e["offset"].as_u64().unwrap())).collect();
        assert!(!want.is_empty(), "{}", c["id"]);
        assert_eq!(got, want, "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// exports.json

fn build_export(k: &Keys, j: &Journal, parity: bool) -> (ExportHeader, Vec<u8>) {
    let header = ExportHeader { handle: TenancyHandle::from(seed16("export-handle")), parts: 1 };
    let sign_pub = k.tenancy.public_key();
    let manifest = map([
        ("tenancy", bytes(sha256(sign_pub.as_bytes()).as_bytes())),
        ("keys", Value::Array(vec![map([("index", int(0)), ("public_key", bytes(sign_pub.as_bytes())), ("evidence", bytes(&seed("evidence")))])])),
        ("records", int(3)), ("first_seq", int(0)), ("last_seq", int(2)),
        ("first_hash", bytes(j.hashes[0].as_bytes())), ("last_hash", bytes(j.hashes[2].as_bytes())),
        ("journal_sha256", bytes(sha256(&j.bytes).as_bytes())), ("end", bytes(j.hashes[2].as_bytes())),
        ("build_anchor", bytes(&seed("build-anchor"))), ("instruments", Value::Array(vec![bytes(&seed("fingerprint"))])),
        ("policy", bytes(&seed("policy"))),
    ]);
    let sealed = seal_value(&mut FixedRng(seed("ikm-e/export-manifest").to_vec()), &k.record.public().unwrap(), &tags::EXPORT_MANIFEST_SEAL, &manifest).unwrap();
    let part = ExportPart::sign(&header, sealed.encode(), j.bytes.clone(), &k.tenancy, 0).unwrap();
    let file = ExportFile { header: header.clone(), parts: vec![part] }.encode(parity).unwrap();
    (header, file)
}

/// File offsets of the first byte of each data shard, for damage injection.
fn shard_offsets(file: &[u8]) -> Vec<usize> {
    let parsed = ExportFile::decode(file).unwrap();
    let header_len = cbor::encode(&parsed.header.to_value()).unwrap().len();
    let part = &parsed.parts[0];
    let (h, m, jl) = (header_len, part.manifest.len(), part.journal.len());
    let size = part.parity.as_ref().unwrap().shard_size;
    (0..10)
        .map(|i| i * size)
        .filter(|&d| d < h + m + jl)
        .map(|d| if d < h { 4 + 9 + d } else if d < h + m { 4 + 9 + h + 9 + (d - h) } else { 4 + 9 + h + 9 + m + 9 + (d - h - m) })
        .collect()
}

fn raw_section(kind: u8, body: &[u8]) -> Vec<u8> {
    [vec![kind], (body.len() as u32).to_be_bytes().to_vec(), crc32c(body).to_be_bytes().to_vec(), body.to_vec()].concat()
}

fn gen_exports() -> J {
    let k = keys();
    let j = build_journal(&k);
    let (_, plain) = build_export(&k, &j, false);
    let (_, file) = build_export(&k, &j, true);
    let offsets = shard_offsets(&file);
    let repairs: Vec<J> = [("repair-1-shard", vec![0usize]), ("repair-4-shards", vec![0, 3, 6, 8]), ("fail-5-shards", vec![0, 2, 4, 6, 8])]
        .into_iter()
        .map(|(id, shards)| {
            let flips: Vec<usize> = shards.iter().map(|&s| offsets[s]).collect();
            let mut damaged = file.clone();
            for &f in &flips {
                damaged[f] ^= 0xff;
            }
            let outcome = match fieldseal_kernel::export::repair(&damaged) {
                Ok((repaired, n)) => {
                    assert_eq!(repaired, file);
                    json!({"repaired_shards": n})
                }
                Err(e) => with(err_j(&e), json!({"salvaged_frames": salvage_frames(&damaged).len()})),
            };
            with(json!({"id": id, "requirement": "WIRE-109", "damaged_shards": shards, "flip_offsets": flips}), outcome)
        })
        .collect();
    let parsed = ExportFile::decode(&plain).unwrap();
    let header_body = cbor::encode(&parsed.header.to_value()).unwrap();
    let part = &parsed.parts[0];
    let sig_body = cbor::encode(&part.signature.to_value()).unwrap();
    let mut bad_crc = plain.clone();
    bad_crc[4 + 9 + header_body.len() + 9 + 3] ^= 1;
    let unknown_format = cbor::encode(&{
        let mut v = parsed.header.to_value();
        if let Value::Map(m) = &mut v {
            m.insert("format".into(), text("fieldseal.dev/export/v2"));
        }
        v
    })
    .unwrap();
    let mut other_handle = parsed.header.clone();
    other_handle.handle = TenancyHandle::from([0u8; 16]);
    let negatives: Vec<(&str, &str, Vec<u8>)> = vec![
        ("bad-magic", "WIRE-100", [b"FSX2".as_slice(), &plain[4..]].concat()),
        ("section-crc", "WIRE-100", bad_crc),
        ("journal-before-manifest", "WIRE-101", [EXPORT_MAGIC.to_vec(), raw_section(1, &header_body), raw_section(3, &part.journal), raw_section(2, &part.manifest), raw_section(5, &sig_body)].concat()),
        ("missing-signature", "WIRE-101", [EXPORT_MAGIC.to_vec(), raw_section(1, &header_body), raw_section(2, &part.manifest), raw_section(3, &part.journal)].concat()),
        ("unknown-format", "WIRE-150", [EXPORT_MAGIC.to_vec(), raw_section(1, &unknown_format), raw_section(2, &part.manifest), raw_section(3, &part.journal), raw_section(5, &sig_body)].concat()),
        ("truncated", "WIRE-100", plain[..plain.len() - 1].to_vec()),
    ];
    let mut invalid: Vec<J> = negatives
        .into_iter()
        .map(|(id, req, f)| with(json!({"id": id, "requirement": req, "file": hex(&f)}), err_j(&ExportFile::decode(&f).unwrap_err())))
        .collect();
    // A header the signature doesn't cover: structurally valid, fails verification.
    let resigned = [EXPORT_MAGIC.to_vec(), raw_section(1, &cbor::encode(&other_handle.to_value()).unwrap()), raw_section(2, &part.manifest), raw_section(3, &part.journal), raw_section(5, &sig_body)].concat();
    let e = {
        let f = ExportFile::decode(&resigned).unwrap();
        f.parts[0].verify(&f.header, &k.tenancy.public_key()).unwrap_err()
    };
    invalid.push(with(json!({"id": "header-not-signed", "requirement": "WIRE-106", "file": hex(&resigned)}), err_j(&e)));
    with(
        header("Export files (WIRE-100..109) built from the records.json journal and the same keys. The manifest is sealed with fs1-x to the record key with ikm_e = SHA-256(\"fieldseal.dev/vectors/ikm-e/export-manifest\"). Repair vectors XOR 0xff into the first byte of each listed data shard."),
        json!({
            "tenancy_public_key": hex(k.tenancy.public_key().as_bytes()),
            "without_parity": hex(&plain),
            "with_parity": hex(&file),
            "repairs": repairs,
            "invalid": invalid,
        }),
    )
}

// covers: WIRE-105, WIRE-108
#[test]
fn wire_100_to_110_export_vectors() {
    let v = load("exports.json");
    let public = P256PublicKey::from_bytes(&unhex(v["tenancy_public_key"].as_str().unwrap())).unwrap();
    let plain = unhex(v["without_parity"].as_str().unwrap());
    let file = unhex(v["with_parity"].as_str().unwrap());
    for f in [&plain, &file] {
        let parsed = ExportFile::decode(f).unwrap();
        assert_eq!(parsed.parts.len() as u64, parsed.header.parts);
        parsed.parts[0].verify(&parsed.header, &public).unwrap();
        assert_eq!(&parsed.encode(parsed.parts[0].parity.is_some()).unwrap(), f, "re-encoding reproduces the file");
        assert!(read_journal(&parsed.parts[0].journal, std::slice::from_ref(&public), &[]).is_clean());
    }
    // Parity is not signed (WIRE-108): adding or stripping it leaves the signature valid.
    assert_eq!(ExportFile::decode(&plain).unwrap().parts[0].signature, ExportFile::decode(&file).unwrap().parts[0].signature);
    assert_eq!(ExportFile::decode(&plain).unwrap().encode(true).unwrap(), file);
    assert_eq!(ExportFile::decode(&file).unwrap().encode(false).unwrap(), plain);
    for c in v["repairs"].as_array().unwrap() {
        let mut damaged = file.clone();
        for off in c["flip_offsets"].as_array().unwrap() {
            damaged[off.as_u64().unwrap() as usize] ^= 0xff;
        }
        assert_eq!(ExportFile::decode(&damaged).unwrap_err().code, ErrorCode::Crc);
        match fieldseal_kernel::export::repair(&damaged) {
            Ok((repaired, n)) => {
                assert_eq!(n as u64, c["repaired_shards"].as_u64().unwrap(), "{}", c["id"]);
                assert_eq!(repaired, file, "{}", c["id"]);
                let parsed = ExportFile::decode(&repaired).unwrap();
                parsed.parts[0].verify(&parsed.header, &public).unwrap();
            }
            Err(e) => {
                assert_eq!(e.code, code_of(c), "{}", c["id"]);
                assert_eq!(salvage_frames(&damaged).len() as u64, c["salvaged_frames"].as_u64().unwrap());
            }
        }
    }
    for c in v["invalid"].as_array().unwrap() {
        let f = unhex(c["file"].as_str().unwrap());
        let e = match ExportFile::decode(&f) {
            Ok(parsed) => parsed.parts[0].verify(&parsed.header, &public).unwrap_err(),
            Err(e) => e,
        };
        assert_eq!(e.code, code_of(c), "{}", c["id"]);
        assert_eq!(e.offset as u64, c["offset"].as_u64().unwrap(), "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// local_records.json

fn local_inputs(label: &str) -> ([u8; 32], [u8; 32], TenancyId) {
    (seed(&format!("local/{label}/unwrapped-secret")), seed(&format!("local/{label}/pin-hash")), TenancyId::from(seed(&format!("local/{label}/tenancy"))))
}

/// An invalid entry, with the inputs the reader opens it under; the expected error comes
/// from the library.
fn local_invalid(id: &str, req: &str, entry: &[u8], open_under: &str, tenancy_under: &str) -> J {
    let (secret, _, _) = local_inputs("a");
    let pin = local_inputs(open_under).1;
    let tenancy = local_inputs(tenancy_under).2;
    let key = derive_session_key(&secret, &pin, &tenancy);
    let (stage, e) = match LocalEntry::decode(entry) {
        Err(e) => ("decode", e),
        Ok(parsed) => ("open", parsed.open(&key, &tenancy).unwrap_err()),
    };
    json!({"id": id, "requirement": req, "stage": stage, "cbor": hex(entry),
           "unwrapped_secret": hex(&secret), "pin_hash": hex(&pin), "tenancy": hex(tenancy.as_bytes()),
           "error": e.code.as_str(), "offset": e.offset})
}

fn gen_local_records() -> J {
    let plaintexts: Vec<(&str, &[u8])> = vec![
        ("empty-payload", b""),
        ("short-payload", b"payload"),
        ("canonical-cbor-payload", &[0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]),
    ];
    let (secret, pin, tenancy) = local_inputs("a");
    let key = derive_session_key(&secret, &pin, &tenancy);
    let valid: Vec<J> = plaintexts
        .iter()
        .enumerate()
        .map(|(i, (id, pt))| {
            let seq = [0u64, 7, 4_294_967_296][i];
            let nonce = seed16(&format!("local/nonce/{id}"))[..12].try_into().unwrap();
            let entry = LocalEntry::seal(&key, &tenancy, seq, nonce, pt);
            json!({"id": id, "requirement": "WIRE-080, WIRE-081", "seq": seq, "nonce": hex(&nonce), "plaintext": hex(pt),
                   "aad": hex(&local_record_aad(&tenancy, seq)), "cbor": hex(&entry.encode())})
        })
        .collect();
    let base = LocalEntry::seal(&key, &tenancy, 7, seed16("local/nonce/short-payload")[..12].try_into().unwrap(), b"payload");
    let mut flipped = base.clone();
    flipped.ct[0] ^= 1;
    let mut moved = base.clone();
    moved.seq = 8;
    let mut wrong_nonce = base.clone();
    wrong_nonce.nonce[0] ^= 1;
    let Value::Map(m) = base.to_value() else { unreachable!() };
    let with_field = |k: &str, v: Value| {
        let mut m = m.clone();
        m.insert(k.to_owned(), v);
        cbor::encode(&Value::Map(m)).unwrap()
    };
    let without = |k: &str| {
        let mut m = m.clone();
        m.remove(k);
        cbor::encode(&Value::Map(m)).unwrap()
    };
    let invalid = vec![
        local_invalid("wrong-pin", "WIRE-080", &base.encode(), "other", "a"),
        local_invalid("wrong-tenancy", "WIRE-081", &base.encode(), "a", "other"),
        local_invalid("seq-moved", "WIRE-081", &moved.encode(), "a", "a"),
        local_invalid("ciphertext-bit-flipped", "WIRE-080", &flipped.encode(), "a", "a"),
        local_invalid("nonce-bit-flipped", "WIRE-080", &wrong_nonce.encode(), "a", "a"),
        local_invalid("extra-field", "WIRE-080", &with_field("extra", int(1)), "a", "a"),
        local_invalid("nonce-11-bytes", "WIRE-080", &with_field("nonce", bytes(&[0; 11])), "a", "a"),
        local_invalid("missing-ct", "WIRE-080", &without("ct"), "a", "a"),
        local_invalid("seq-not-integer", "WIRE-080", &with_field("seq", text("7")), "a", "a"),
        local_invalid("trailing-byte", "WIRE-080", &[base.encode(), vec![0]].concat(), "a", "a"),
        local_invalid("empty-input", "WIRE-080", &[], "a", "a"),
    ];
    with(
        header("Local record entries {seq, nonce, ct} (WIRE-080..082): AES-256-GCM under the session key HKDF-SHA256(unwrapped_secret || pin_hash, info = \"fieldseal.dev/session-key/v1\" || tenancy), with additional data [\"fieldseal.dev/local-record/v1\", tenancy, seq]. Inputs are SHA-256(\"fieldseal.dev/vectors/local/a/...\"); nonces are fixed here and random in use."),
        json!({
            "unwrapped_secret": hex(&secret), "pin_hash": hex(&pin), "tenancy": hex(tenancy.as_bytes()),
            "max_encryptions": MAX_ENCRYPTIONS,
            "valid": valid, "invalid": invalid,
        }),
    )
}

#[test]
fn wire_080_081_082_local_record_vectors() {
    let v = load("local_records.json");
    assert_eq!(v["max_encryptions"].as_u64().unwrap(), MAX_ENCRYPTIONS, "WIRE-082");
    assert_eq!(MAX_ENCRYPTIONS, 1 << 32);
    let tenancy = TenancyId::from(<[u8; 32]>::try_from(unhex(v["tenancy"].as_str().unwrap())).unwrap());
    let key = derive_session_key(&unhex(v["unwrapped_secret"].as_str().unwrap()), &unhex(v["pin_hash"].as_str().unwrap()).try_into().unwrap(), &tenancy);
    for c in v["valid"].as_array().unwrap() {
        let seq = c["seq"].as_u64().unwrap();
        let nonce: [u8; 12] = unhex(c["nonce"].as_str().unwrap()).try_into().unwrap();
        let plaintext = unhex(c["plaintext"].as_str().unwrap());
        assert_eq!(hex(&local_record_aad(&tenancy, seq)), c["aad"].as_str().unwrap(), "{}", c["id"]);
        assert_eq!(hex(&LocalEntry::seal(&key, &tenancy, seq, nonce, &plaintext).encode()), c["cbor"].as_str().unwrap(), "{}", c["id"]);
        let entry = LocalEntry::decode(&unhex(c["cbor"].as_str().unwrap())).unwrap();
        assert_eq!((entry.seq, entry.nonce), (seq, nonce));
        assert_eq!(&entry.open(&key, &tenancy).unwrap()[..], &plaintext[..], "{}", c["id"]);
    }
    for c in v["invalid"].as_array().unwrap() {
        let cbor = unhex(c["cbor"].as_str().unwrap());
        let tenancy = TenancyId::from(<[u8; 32]>::try_from(unhex(c["tenancy"].as_str().unwrap())).unwrap());
        let key = derive_session_key(&unhex(c["unwrapped_secret"].as_str().unwrap()), &unhex(c["pin_hash"].as_str().unwrap()).try_into().unwrap(), &tenancy);
        let e = match (c["stage"].as_str().unwrap(), LocalEntry::decode(&cbor)) {
            ("decode", Err(e)) => e,
            ("open", Ok(entry)) => entry.open(&key, &tenancy).unwrap_err(),
            (stage, other) => panic!("{}: stage {stage} gave {other:?}", c["id"]),
        };
        assert_eq!(e.code, code_of(c), "{}", c["id"]);
        assert_eq!(e.offset as u64, c["offset"].as_u64().unwrap(), "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// qr_sequences.json

/// `n` deterministic bytes for the object labelled `label`.
fn stream(label: &str, n: usize) -> Vec<u8> {
    (0u32..).flat_map(|i| seed(&format!("qr/{label}/{i}"))).take(n).collect()
}

fn frame_error(f: &str) -> J {
    match Frame::parse(f) {
        Err(e) => err_j(&e),
        Ok(_) => panic!("frame {f} parsed"),
    }
}

/// Feeds `frames` to a fresh receiver and reports the first failure with the index of the
/// frame that caused it, or the object it completed.
fn feed(frames: &[String]) -> J {
    let mut r = Reassembler::new();
    for (i, f) in frames.iter().enumerate() {
        match r.push(f) {
            Err(e) => return with(err_j(&e), json!({"at_frame": i})),
            Ok(Some(o)) => return json!({"object": hex(&o), "at_frame": i}),
            Ok(None) => {}
        }
    }
    json!({"incomplete": true})
}

fn gen_qr_sequences() -> J {
    let sizes: [(&str, usize); 6] =
        [("one-byte", 1), ("one-frame", 100), ("exact-chunk", CHUNK_BYTES), ("two-frames", CHUNK_BYTES + 1), ("three-frames", 800), ("registration-sized", 5000)];
    let sequences: Vec<J> = sizes
        .iter()
        .map(|(id, n)| {
            let object = stream(id, *n);
            let frames = encode_sequence(&object).unwrap();
            json!({"id": id, "requirement": "WIRE-175, WIRE-176", "object": hex(&object), "message_id": hex(&message_id(&object)),
                   "message_id_text": crockford_base32(&message_id(&object)), "frames": frames})
        })
        .collect();

    let a = encode_sequence(&stream("three-frames", 800)).unwrap();
    let other = encode_sequence(&stream("other", 800)).unwrap();
    let orders: Vec<J> = [("reversed", vec![2, 1, 0]), ("repeats-and-shuffle", vec![1, 1, 2, 0, 0, 2]), ("looped-twice", vec![0, 1, 0, 1, 2])]
        .into_iter()
        .map(|(id, order)| {
            let frames: Vec<String> = order.iter().map(|i| a[*i].clone()).collect();
            json!({"id": id, "requirement": "WIRE-177", "frames": frames, "result": feed(&frames)})
        })
        .collect();
    let interleaved: Vec<String> = a.iter().zip(&other).flat_map(|(x, y)| [y.clone(), x.clone()]).collect();

    // Same ID, same total, last chunk replaced by another message's last chunk.
    let id_text = a[0].split(':').nth(2).unwrap();
    let forged_last = format!("FS1A:3/3:{id_text}:{}", other[2].split(':').nth(3).unwrap());
    let payload_of = |f: &str| f.split(':').nth(3).unwrap().to_owned();
    let reassembly_errors: Vec<(&str, &str, Vec<String>)> = vec![
        ("object-hash-mismatch", "WIRE-177", vec![a[0].clone(), a[1].clone(), forged_last]),
        ("total-disagrees", "WIRE-177", vec![a[0].clone(), format!("FS1A:2/4:{id_text}:{}", payload_of(&a[1]))]),
        ("repeated-seq-different-payload", "WIRE-177", vec![a[0].clone(), format!("FS1A:1/3:{id_text}:{}", payload_of(&other[0]))]),
    ];
    let reassembly_errors: Vec<J> =
        reassembly_errors.into_iter().map(|(id, req, frames)| json!({"id": id, "requirement": req, "result": feed(&frames), "frames": frames})).collect();

    let long = format!("{}{}", a[0], "0".repeat(MAX_FRAME_CHARS));
    let invalid_frames: Vec<(&str, &str, String)> = vec![
        ("over-600-characters", "WIRE-176", long),
        ("wrong-prefix", "WIRE-175", a[0].replace("FS1A", "FS1B")),
        ("leading-zero-seq", "WIRE-175", a[0].replace("1/3", "01/3")),
        ("seq-zero", "WIRE-175", a[0].replace("1/3", "0/3")),
        ("seq-beyond-total", "WIRE-175", a[0].replace("1/3", "4/3")),
        ("total-beyond-limit", "WIRE-175", a[0].replace("1/3", "1/1001")),
        ("no-position-slash", "WIRE-175", a[0].replace("1/3", "13")),
        ("short-message-id", "WIRE-175", a[0].replacen(id_text, &id_text[..12], 1)),
        ("bad-id-character", "WIRE-175", a[0].replacen(id_text, &format!("U{}", &id_text[1..]), 1)),
        ("missing-payload-field", "WIRE-175", format!("FS1A:1/3:{id_text}")),
        ("empty-payload", "WIRE-175", format!("FS1A:1/3:{id_text}:")),
        ("short-chunk-before-last", "WIRE-175", a[2].replace("3/3", "2/3")),
        ("non-ascii", "WIRE-175", a[0].replace("FS1A", "FS1\u{e4}")),
    ];
    let invalid_frames: Vec<J> =
        invalid_frames.into_iter().map(|(id, req, f)| json!({"id": id, "requirement": req, "frame": f, "result": frame_error(&f)})).collect();

    with(
        header("Animated QR sequences (WIRE-175..177): frames FS1A:<seq>/<total>:<message-id>:<payload> for objects of the stated size, built from SHA-256(\"fieldseal.dev/vectors/qr/<id>/<n>\") streams; the receiver's results for loops in other orders and for damaged or conflicting frames. In a result, `at_frame` is the index of the frame that completed the object or failed."),
        json!({
            "chunk_bytes": CHUNK_BYTES, "max_frame_chars": MAX_FRAME_CHARS, "max_frames": MAX_FRAMES,
            "sequences": sequences, "orders": orders,
            "interleaved": {"requirement": "WIRE-177", "frames": interleaved.clone(), "objects": [hex(&stream("other", 800)), hex(&stream("three-frames", 800))]},
            "reassembly_errors": reassembly_errors, "invalid_frames": invalid_frames,
        }),
    )
}

/// What a fresh receiver makes of `frames`, in the vectors' result form.
fn result_of(c: &J) -> J {
    let frames: Vec<String> = c["frames"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_owned()).collect();
    feed(&frames)
}

#[test]
fn wire_175_176_177_qr_sequence_vectors() {
    let v = load("qr_sequences.json");
    assert_eq!(v["chunk_bytes"].as_u64().unwrap() as usize, CHUNK_BYTES);
    assert_eq!(v["max_frame_chars"].as_u64().unwrap() as usize, MAX_FRAME_CHARS);
    assert_eq!(v["max_frames"].as_u64().unwrap() as usize, MAX_FRAMES);
    for c in v["sequences"].as_array().unwrap() {
        let object = unhex(c["object"].as_str().unwrap());
        let frames: Vec<String> = c["frames"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_owned()).collect();
        assert_eq!(hex(&message_id(&object)), c["message_id"].as_str().unwrap());
        assert_eq!(crockford_base32(&message_id(&object)), c["message_id_text"].as_str().unwrap());
        assert_eq!(encode_sequence(&object).unwrap(), frames, "{}", c["id"]);
        assert!(frames.iter().all(|f| f.len() <= MAX_FRAME_CHARS), "WIRE-176 {}", c["id"]);
        assert_eq!(feed(&frames), json!({"object": c["object"], "at_frame": frames.len() - 1}), "{}", c["id"]);
    }
    for c in v["orders"].as_array().unwrap().iter().chain(v["reassembly_errors"].as_array().unwrap()) {
        assert_eq!(result_of(c), c["result"], "{}", c["id"]);
    }
    let mixed = result_of(&v["interleaved"]);
    assert!(mixed.get("object").is_some(), "the first message completes");
    let mut r = Reassembler::new();
    let mut done = Vec::new();
    for f in v["interleaved"]["frames"].as_array().unwrap() {
        done.extend(r.push(f.as_str().unwrap()).unwrap().map(|o| hex(&o)));
    }
    let want: Vec<&str> = v["interleaved"]["objects"].as_array().unwrap().iter().map(|o| o.as_str().unwrap()).collect();
    assert_eq!(done.iter().map(String::as_str).collect::<Vec<_>>(), want);
    for c in v["invalid_frames"].as_array().unwrap() {
        let e = Frame::parse(c["frame"].as_str().unwrap()).unwrap_err();
        assert_eq!(e.code, code_of(&c["result"]), "{}", c["id"]);
        assert_eq!(e.offset as u64, c["result"]["offset"].as_u64().unwrap(), "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// pop_tokens.json

const POP_T0: u64 = 1_800_000_000_000;

fn pop_key() -> SigningKey {
    SigningKey::from_scalar(&seed("pop/device-signing-key")).unwrap()
}

fn pop_token() -> PopToken {
    let mut t = PopToken {
        tenancy: TenancyId::from(seed("pop/tenancy")),
        method: "POST".into(),
        url: "https://factory.example.org/v1/api-token".into(),
        iat: AuthorityTime(POP_T0),
        jti: seed16("pop/jti"),
        ath: Some(sha256(b"access-token")),
        signature: Signature(vec![]),
    };
    t.signature = pop_key().sign_message(&t.message());
    t
}

/// What a server does with a token before looking at the request: decode it (from CBOR or
/// from the header) and check its signature against `public`.
fn pop_check(form: &str, input: &str, public: &P256PublicKey) -> Result<PopToken, WireError> {
    let t = match form {
        "cbor" => PopToken::decode(&unhex(input))?,
        "header" => PopToken::from_header(input)?,
        other => panic!("unknown form {other}"),
    };
    t.verify_signature(public)?;
    Ok(t)
}

/// The token's map with `edit` applied, carrying `sig` (the real one unless `edit` replaces it).
fn pop_map(edit: impl FnOnce(&mut BTreeMap<String, Value>)) -> Vec<u8> {
    let t = pop_token();
    let Value::Map(mut m) = t.signed_structure() else { unreachable!() };
    m.insert("sig".into(), bytes(&t.signature.0));
    edit(&mut m);
    cbor::encode(&Value::Map(m)).unwrap()
}

fn pop_invalid(id: &str, req: &str, form: &str, input: String) -> J {
    let e = pop_check(form, &input, &pop_key().public_key()).unwrap_err();
    with(json!({"id": id, "requirement": req, "form": form, "input": input}), err_j(&e))
}

fn gen_pop_tokens() -> J {
    let t = pop_token();
    let no_ath = {
        let mut u = PopToken { ath: None, method: "GET".into(), url: "https://upload.example.org/v1/upload".into(), ..t.clone() };
        u.signature = pop_key().sign_message(&u.message());
        u
    };
    let valid: Vec<J> = [("with-access-token-hash", &t), ("without-access-token-hash", &no_ath)]
        .into_iter()
        .map(|(id, t)| {
            json!({"id": id, "requirement": "WIRE-170, WIRE-172", "cbor": hex(&t.encode()), "header": t.to_header(),
                   "message": hex(&t.message()), "signature": hex(&t.signature.0),
                   "tenancy": hex(t.tenancy.as_bytes()), "method": t.method, "url": t.url, "iat": t.iat.0, "jti": hex(&t.jti),
                   "ath": t.ath.as_ref().map(|a| hex(a.as_bytes()))})
        })
        .collect();
    let resign = |tag: &DomainTag, key: &SigningKey| {
        let mut u = t.clone();
        u.signature = key.sign(tag, &u.signed_structure()).unwrap();
        u.encode()
    };
    let mut tampered = t.clone();
    tampered.url = "https://factory.example.org/v1/other".into();
    let mut flipped = t.clone();
    flipped.signature.0[5] ^= 1;
    let mut high = t.clone();
    high.signature = high_s(&t.signature);
    let padded = format!("{}=", t.to_header());
    let invalid = vec![
        pop_invalid("version-2", "WIRE-150", "cbor", hex(&pop_map(|m| { m.insert("v".into(), int(2)); }))),
        pop_invalid("extra-field", "WIRE-170", "cbor", hex(&pop_map(|m| { m.insert("scope".into(), text("x")); }))),
        pop_invalid("missing-jti", "WIRE-170", "cbor", hex(&pop_map(|m| { m.remove("jti"); }))),
        pop_invalid("jti-15-bytes", "WIRE-170", "cbor", hex(&pop_map(|m| { m.insert("jti".into(), bytes(&[1; 15])); }))),
        pop_invalid("ath-31-bytes", "WIRE-170", "cbor", hex(&pop_map(|m| { m.insert("ath".into(), bytes(&[1; 31])); }))),
        pop_invalid("sig-63-bytes", "WIRE-170", "cbor", hex(&pop_map(|m| { m.insert("sig".into(), bytes(&[1; 63])); }))),
        pop_invalid("method-not-text", "WIRE-170", "cbor", hex(&pop_map(|m| { m.insert("method".into(), int(1)); }))),
        pop_invalid("iat-negative", "WIRE-170", "cbor", hex(&pop_map(|m| { m.insert("iat".into(), int(-1)); }))),
        pop_invalid("trailing-byte", "WIRE-170", "cbor", hex(&[t.encode(), vec![0]].concat())),
        pop_invalid("over-4-kib", "WIRE-160", "cbor", hex(&pop_map(|m| { m.insert("url".into(), text(&"u".repeat(5000))); }))),
        pop_invalid("header-with-padding", "WIRE-172", "header", padded),
        pop_invalid("header-standard-base64-character", "WIRE-172", "header", format!("+{}", &t.to_header()[1..])),
        pop_invalid("header-over-8-kib", "WIRE-160", "header", "A".repeat(8193)),
        pop_invalid("signature-bit-flipped", "WIRE-170", "cbor", hex(&flipped.encode())),
        pop_invalid("high-s-signature", "WIRE-022", "cbor", hex(&high.encode())),
        pop_invalid("url-changed-after-signing", "WIRE-170", "cbor", hex(&tampered.encode())),
        pop_invalid("signed-under-receipt-tag", "WIRE-170", "cbor", hex(&resign(&tags::RECEIPT, &pop_key()))),
        pop_invalid("signed-by-another-key", "WIRE-170", "cbor", hex(&resign(&tags::API_POP, &SigningKey::from_scalar(&seed("pop/other-key")).unwrap()))),
    ];
    with(
        header("Proof-of-possession API tokens (WIRE-170..172): the token is the canonical CBOR map without `sig`, signed over [\"fieldseal.dev/api-pop/v1\", structure] by the key SHA-256(\"fieldseal.dev/vectors/pop/device-signing-key\"); the `Fieldseal-PoP` header is its base64url. The registration vectors carry one more token (registration.json)."),
        json!({"device_public_key": hex(pop_key().public_key().as_bytes()), "max_token_bytes": MAX_POP_TOKEN, "valid": valid, "invalid": invalid}),
    )
}

#[test]
fn wire_170_171_172_pop_token_vectors() {
    let v = load("pop_tokens.json");
    assert_eq!(v["max_token_bytes"].as_u64().unwrap() as usize, MAX_POP_TOKEN);
    let public = P256PublicKey::from_bytes(&unhex(v["device_public_key"].as_str().unwrap())).unwrap();
    for c in v["valid"].as_array().unwrap() {
        let from_header = pop_check("header", c["header"].as_str().unwrap(), &public).unwrap();
        let from_cbor = pop_check("cbor", c["cbor"].as_str().unwrap(), &public).unwrap();
        assert_eq!(from_header, from_cbor, "{}", c["id"]);
        assert_eq!(hex(&from_cbor.encode()), c["cbor"].as_str().unwrap(), "re-encoding {}", c["id"]);
        assert_eq!(from_cbor.to_header(), c["header"].as_str().unwrap(), "{}", c["id"]);
        assert_eq!(hex(&from_cbor.message()), c["message"].as_str().unwrap(), "{}", c["id"]);
        assert_eq!(hex(&from_cbor.signature.0), c["signature"].as_str().unwrap(), "{}", c["id"]);
        assert_eq!(hex(from_cbor.tenancy.as_bytes()), c["tenancy"].as_str().unwrap());
        assert_eq!((from_cbor.method.as_str(), from_cbor.url.as_str(), from_cbor.iat.0), (c["method"].as_str().unwrap(), c["url"].as_str().unwrap(), c["iat"].as_u64().unwrap()));
        assert_eq!(c["ath"].as_str().map(str::to_owned), from_cbor.ath.as_ref().map(|a| hex(a.as_bytes())));
    }
    for c in v["invalid"].as_array().unwrap() {
        let e = pop_check(c["form"].as_str().unwrap(), c["input"].as_str().unwrap(), &public).unwrap_err();
        assert_eq!(e.code, code_of(c), "{}", c["id"]);
        assert_eq!(e.offset as u64, c["offset"].as_u64().unwrap(), "{}", c["id"]);
    }
}

// ---------------------------------------------------------------------------------------
// Regeneration.

fn generate() -> BTreeMap<&'static str, J> {
    BTreeMap::from([
        ("cbor.json", gen_cbor()),
        ("identifiers.json", gen_identifiers()),
        ("signatures.json", gen_signatures()),
        ("seals.json", gen_seals()),
        ("frames.json", gen_frames()),
        ("records.json", gen_records()),
        ("exports.json", gen_exports()),
        ("local_records.json", gen_local_records()),
        ("qr_sequences.json", gen_qr_sequences()),
        ("pop_tokens.json", gen_pop_tokens()),
    ])
}

fn render(j: &J) -> String {
    serde_json::to_string_pretty(j).unwrap() + "\n"
}

fn load(name: &str) -> J {
    let path = dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}; regenerate the vectors", path.display()));
    serde_json::from_str(&text).unwrap()
}

// covers: WIRE-151
#[test]
fn vectors_are_current() {
    let regenerate = std::env::var_os("FIELDSEAL_REGENERATE_VECTORS").is_some();
    let mut stale = Vec::new();
    for (name, j) in generate() {
        let path = dir().join(name);
        let fresh = render(&j);
        if regenerate {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, fresh).unwrap();
        } else if std::fs::read_to_string(&path).ok().as_deref() != Some(fresh.as_str()) {
            stale.push(name);
        }
    }
    assert!(stale.is_empty(), "vectors differ from the generator: {stale:?}; if the format change is intended (WIRE-151), regenerate them");
}
