//! Golden vectors for the registration request (WIRE-130..135): `tests/vectors/registration.json`.
//!
//! The decode tests check the stored request vectors against the library, independently of how
//! the file was made. `wire_130_the_vectors_are_current` rebuilds the request entries from
//! fixed seeds and fails if they differ from the file. The other entries of the file (tokens,
//! certificates, PoP token) are checked where they are built. To regenerate the request entries
//! after an intended format change (WIRE-151):
//!
//! ```text
//! FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-registration --test vectors
//! ```
//!
//! Every key is derived from a fixed label as `SHA-256("fieldseal.dev/vectors/<label>")`, as
//! `crates/kernel/tests/vectors.rs` derives its keys. Fixed keys exist only here.

use std::path::PathBuf;

use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::Nonce;
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_kernel::sign::SigningKey;
use fieldseal_kernel::{Value, cbor};
use fieldseal_registration::domain::wire::{RequestBody, decode_request};
use fieldseal_registration::domain::{
    FingerprintWords, KeyEvidence, NonceSource, ReportedProfile, ReportedVersion, TokenSecret,
};
use fieldseal_trust::domain::{AttestationEvidence, DeviceKeyKind};
use serde_json::{Value as J, json};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/registration.json")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn seed(label: &str) -> [u8; 32] {
    *sha256(format!("fieldseal.dev/vectors/{label}").as_bytes()).as_bytes()
}

fn device_signing() -> SigningKey {
    SigningKey::from_scalar(&seed("registration/device-signing")).expect("scalar")
}

fn device_agreement() -> P256PublicKey {
    let public = RecipientSecret::from_bytes(Suite::Fs1P, &seed("registration/device-agreement"))
        .expect("secret")
        .public()
        .expect("public");
    P256PublicKey::from_bytes(public.encoded()).expect("a P-256 key")
}

/// The body the vectors use, with or without a catalogue version.
fn body(catalogue: Option<&str>) -> RequestBody {
    RequestBody {
        token: TokenSecret::from_bytes([0x11; 16]),
        nonce: Nonce::from([0x22; 32]),
        nonce_source: NonceSource::Factory,
        sign_pub: device_signing().public_key(),
        agree_pub: device_agreement(),
        evidence: vec![
            KeyEvidence {
                kind: DeviceKeyKind::Signing,
                evidence: AttestationEvidence {
                    format: "software".into(),
                    data: vec![1, 2, 3],
                },
            },
            KeyEvidence {
                kind: DeviceKeyKind::Agreement,
                evidence: AttestationEvidence {
                    format: "software".into(),
                    data: vec![4, 5, 6],
                },
            },
        ],
        build: "fieldseal-simulator/0.1.0".into(),
        prev_closing: None,
        label: Some("blue".into()),
        profile: ReportedProfile {
            instrument_schema: ReportedVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            catalogue_reference: catalogue.map(str::to_owned),
        },
    }
}

const CATALOGUE: &str = "ui-reference-1.0";

/// The sealed plaintext `{body, pop}` for a body value, with the proof of possession of `real`.
fn plaintext(body: Value, pop: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::map([
        ("body", body),
        ("pop", Value::Bytes(pop.to_vec())),
    ]))
    .expect("encodable")
}

fn request_row(catalogue: Option<&str>) -> J {
    let b = body(catalogue);
    let pop = device_signing().sign_message(&b.pop_message());
    let digest = b.digest();
    let words = FingerprintWords::from_body_digest(&digest);
    json!({
        "body": lower_hex(&b.encode()),
        "body_sha256": lower_hex(digest.as_bytes()),
        "indices": words.indices(),
        "plaintext": lower_hex(&plaintext(b.to_value(), &pop.0)),
        "pop": lower_hex(&pop.0),
        "requirement": "WIRE-130..135, REG-020, REG-023",
        "words": words.joined(),
    })
}

/// The negative request rows: a tenancy that is not the hash of the key, no evidence, and no
/// schema version.
fn invalid_rows() -> Vec<J> {
    let real = body(Some(CATALOGUE));
    let pop = device_signing().sign_message(&real.pop_message());
    let row = |id: &str,
               error: &str,
               requirement: &str,
               edit: &dyn Fn(&mut std::collections::BTreeMap<String, Value>)| {
        let Value::Map(mut m) = body(None).to_value() else {
            unreachable!("a body is a map")
        };
        edit(&mut m);
        json!({
            "cbor": lower_hex(&plaintext(Value::Map(m), &pop.0)),
            "error": error,
            "id": id,
            "requirement": requirement,
            "structure": "request",
        })
    };
    vec![
        row("body-tenancy-mismatch", "E_HASH", "WIRE-131", &|m| {
            m.insert("tenancy".into(), Value::Bytes(vec![0; 32]));
        }),
        row("body-no-evidence", "E_UNKNOWN_FIELD", "WIRE-130", &|m| {
            m.insert("evidence".into(), Value::Array(vec![]));
        }),
        row("body-no-schema", "E_UNKNOWN_FIELD", "WIRE-130", &|m| {
            m.remove("schema");
        }),
    ]
}

fn load() -> J {
    let text =
        std::fs::read_to_string(path()).unwrap_or_else(|e| panic!("{}: {e}", path().display()));
    serde_json::from_str(&text).expect("the vectors are JSON")
}

fn invalid_requests(file: &J) -> Vec<J> {
    file["invalid"]
        .as_array()
        .expect("invalid rows")
        .iter()
        .filter(|r| r["structure"] == "request")
        .cloned()
        .collect()
}

// covers: WIRE-130
#[test]
fn wire_130_the_request_body_vectors_decode_with_schema_and_catalogue() {
    let file = load();
    for (name, catalogue) in [("request", Some(CATALOGUE)), ("request_no_catalogue", None)] {
        let row = &file[name];
        let request = decode_request(&unhex(row["plaintext"].as_str().expect("plaintext")))
            .expect("the request decodes");
        assert_eq!(
            request.profile.instrument_schema,
            ReportedVersion {
                major: 1,
                minor: 0,
                patch: 0
            },
            "{name}: schema"
        );
        assert_eq!(
            request.profile.catalogue_reference.as_deref(),
            catalogue,
            "{name}: catalogue"
        );
        assert_eq!(
            lower_hex(request.body_digest.as_bytes()),
            row["body_sha256"].as_str().expect("body_sha256"),
            "{name}: the digest covers both fields"
        );
        let direct = RequestBody::from_value(
            cbor::decode(&unhex(row["body"].as_str().expect("body"))).expect("canonical CBOR"),
        )
        .expect("the body decodes");
        assert_eq!(
            lower_hex(direct.digest().as_bytes()),
            row["body_sha256"].as_str().expect("body_sha256"),
            "{name}: digest of the body"
        );
        assert_eq!(
            direct.encode(),
            unhex(row["body"].as_str().expect("body")),
            "{name}: re-encoding gives the stored bytes"
        );
    }
}

// covers: WIRE-130
#[test]
fn wire_130_a_body_without_schema_is_refused() {
    let file = load();
    let rows = invalid_requests(&file);
    assert!(
        rows.iter().any(|r| r["id"] == "body-no-schema"),
        "the vectors have the missing-schema row"
    );
    for row in rows {
        let err = decode_request(&unhex(row["cbor"].as_str().expect("cbor")))
            .expect_err("an invalid request is refused");
        assert_eq!(
            err.code.as_str(),
            row["error"].as_str().expect("error"),
            "{}",
            row["id"]
        );
    }
}

// covers: WIRE-151
#[test]
fn wire_130_the_vectors_are_current() {
    let mut file = load();
    let fresh_invalid = invalid_rows();
    let mut current = true;
    current &= file["request"] == request_row(Some(CATALOGUE));
    current &= file["request_no_catalogue"] == request_row(None);
    current &= invalid_requests(&file) == fresh_invalid;
    if std::env::var_os("FIELDSEAL_REGENERATE_VECTORS").is_some() {
        file["request"] = request_row(Some(CATALOGUE));
        file["request_no_catalogue"] = request_row(None);
        let mut invalid: Vec<J> = file["invalid"]
            .as_array()
            .expect("invalid rows")
            .iter()
            .filter(|r| r["structure"] != "request")
            .cloned()
            .collect();
        invalid.extend(fresh_invalid);
        file["invalid"] = J::Array(invalid);
        std::fs::write(
            path(),
            serde_json::to_string_pretty(&file).expect("JSON") + "\n",
        )
        .expect("write the vectors");
    } else {
        assert!(
            current,
            "the request vectors differ from the generator; if the format change is intended (WIRE-151), run FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-registration --test vectors"
        );
    }
}
