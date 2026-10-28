//! The Publishing context's golden vectors (PUB §6), checked in-process.

use std::collections::BTreeMap;

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{P256PublicKey, tags};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::sign;
use fieldseal_kernel::ErrorCode;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::merkle::leaf_hash;
use fieldseal_publishing::domain::{
    LeafFormat, LogEntry, ProvenanceStatement, Publication, PublicationStatement, PublishingError, SignedCheckpoint, SignedProvenance,
    Withdrawal, hashedrekord_json,
};
use fieldseal_trust::domain::{LogPin, TrustBundle, TrustStore};
use serde_json::Value as J;

use super::harness::{Chk, Collector, ensure, label, requirement_ids, same, unhex};
use super::Unit;

const PROVENANCE: &str = include_str!("../../../../contexts/publishing/tests/vectors/provenance.json");
const LOG_ENTRIES: &str = include_str!("../../../../contexts/publishing/tests/vectors/log_entries.json");
const PUBLICATIONS: &str = include_str!("../../../../contexts/publishing/tests/vectors/publications.json");

/// The vector units of the `publishing` suite.
pub fn units() -> Vec<Unit> {
    vec![
        Unit::new("publishing:provenance", &["publishing"], provenance),
        Unit::new("publishing:log-entries", &["publishing", "transparency-log"], log_entries),
        Unit::new("publishing:publications", &["publishing"], publications),
    ]
}

fn s<'a>(j: &'a J, key: &str) -> Result<&'a str, String> {
    j[key].as_str().ok_or_else(|| format!("field `{key}` is missing"))
}

fn bytes(j: &J, key: &str) -> Result<Vec<u8>, String> {
    unhex(s(j, key)?)
}

fn list<'a>(j: &'a J, key: &str) -> &'a [J] {
    j[key].as_array().map_or(&[], Vec::as_slice)
}

fn code(j: &J) -> Result<ErrorCode, String> {
    ErrorCode::parse(s(j, "error")?).c()
}

fn reason(e: &PublishingError) -> &'static str {
    match e {
        PublishingError::BelowThreshold { .. } => "below-threshold",
        PublishingError::DuplicateSigner(_) => "duplicate-signer",
        PublishingError::SignerNotListed { .. } => "signer-not-listed",
        PublishingError::PublisherSignature { .. } => "publisher-signature",
        PublishingError::Inclusion => "inclusion",
        PublishingError::Checkpoint(_) => "checkpoint",
        PublishingError::LogEntryMismatch => "log-entry-mismatch",
        PublishingError::Withdrawn => "withdrawn",
        _ => "other",
    }
}

fn provenance(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(PROVENANCE) else { return c.case(&["PUB-030".into()], "load", || Err("provenance.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-030", "PUB-031"]), format!("valid {}", label(case, i)), || {
            let raw = bytes(case, "statement")?;
            let st = ProvenanceStatement::decode(&raw).c()?;
            same!(st.encode(), raw, "re-encoding");
            let p = SignedProvenance::from_value(cbor::decode(&bytes(case, "provenance")?).c()?).c()?;
            same!(p.statement_bytes(), raw.as_slice(), "statement bytes");
            same!(lower_hex(p.digest().as_bytes()), s(case, "provenance_sha256")?.to_owned(), "provenance digest");
            let key = P256PublicKey::from_bytes(&bytes(case, "builder_public_key")?).c()?;
            sign::verify(&key, &tags::PROVENANCE, &st.to_value(), p.signature()).c()?;
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_decode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-030"]), format!("invalid {}", label(case, i)), || {
            let Err(e) = ProvenanceStatement::decode(&bytes(case, "cbor")?) else { return Err("accepted".into()) };
            same!(e.code, code(case)?, "error code");
            Ok(())
        });
    }
}

fn log_entries(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(LOG_ENTRIES) else { return c.case(&["PUB-101".into()], "load", || Err("log_entries.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-101", "PUB-102"]), format!("valid {}", label(case, i)), || {
            let st = PublicationStatement::from_value(cbor::decode(&bytes(case, "statement")?).c()?).c()?;
            same!(lower_hex(st.digest().as_bytes()), s(case, "digest")?.to_owned(), "statement digest");
            let raw = bytes(case, "entry")?;
            let entry = LogEntry::decode(&raw).c()?;
            same!(entry.encode(), raw, "re-encoding");
            same!(entry.digest(), &st.digest(), "entry digest");
            let key = P256PublicKey::from_bytes(&bytes(case, "publisher_public_key")?).c()?;
            sign::verify(&key, &tags::PUBLICATION, &st.to_value(), entry.signature()).c()?;
            same!(hashedrekord_json(&entry), s(case, "hashedrekord")?.to_owned(), "hashedrekord body");
            for format in [LeafFormat::Fieldseal, LeafFormat::HashedRekord] {
                same!(lower_hex(leaf_hash(&format.leaf(&entry)).as_bytes()), s(&case["leaf_hash"], format.as_str())?.to_owned(), "leaf hash");
            }
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_decode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-104"]), format!("invalid {}", label(case, i)), || {
            let Err(e) = LogEntry::decode(&bytes(case, "cbor")?) else { return Err("accepted".into()) };
            same!(e.code, code(case)?, "error code");
            Ok(())
        });
    }
    let pin = (|| -> Result<LogPin, String> {
        Ok(LogPin {
            origin: s(&v["log_pin"], "origin")?.into(),
            public_key: bytes(&v["log_pin"], "public_key")?,
            format: s(&v["log_pin"], "format")?.into(),
        })
    })();
    for (i, case) in list(&v, "checkpoints").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-106"]), format!("checkpoint {}", label(case, i)), || {
            let pin = pin.clone()?;
            let cp = SignedCheckpoint::parse(s(case, "note")?.as_bytes()).c()?;
            same!(cp.verify(std::slice::from_ref(&pin), 0).is_ok(), case["error"].is_null(), "verdict against the pinned log key");
            Ok(())
        });
    }
}

fn publications(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(PUBLICATIONS) else { return c.case(&["PUB-060".into()], "load", || Err("publications.json does not parse".into())) };
    let setup = (|| -> Result<(TrustBundle, fieldseal_policy::domain::PublishingPolicy), String> {
        let bundle = TrustBundle::decode(&bytes(&v, "trust_bundle")?).c()?;
        let mut policy = fieldseal_policy::domain::Controls::defaults().publishing();
        policy.allowed_builders = list(&v, "allowed_builders").iter().filter_map(|b| b.as_str().map(Into::into)).collect();
        policy.allowed_sources = list(&v, "allowed_sources").iter().filter_map(|b| b.as_str().map(Into::into)).collect();
        Ok((bundle, policy))
    })();
    let Ok((bundle, policy)) = setup else { return c.case(&["PUB-060".into()], "setup", || Err("the vector trust bundle or policy does not load".into())) };
    let verifier = VerifyPublication::new(TrustStore::new(&bundle), &policy);
    let mut by_id = BTreeMap::new();
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-060", "PUB-061"]), format!("valid {}", label(case, i)), || {
            let raw = bytes(case, "cbor")?;
            let p = Publication::decode(&raw).c()?;
            same!(p.encode(), raw, "re-encoding");
            same!(p.address().to_text(), s(case, "address")?.to_owned(), "address");
            let verified = verifier.verify(&p, &[]).c()?;
            let mut got: Vec<String> = verified.signers.iter().map(|k| lower_hex(k.as_bytes())).collect();
            got.sort();
            let mut want: Vec<String> = list(case, "signers").iter().filter_map(|x| x.as_str().map(str::to_owned)).collect();
            want.sort();
            same!(got, want, "signers");
            by_id.insert(s(case, "id")?.to_owned(), p);
            Ok(())
        });
    }
    for (i, case) in list(&v, "withdrawals").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-080"]), format!("withdrawal {}", label(case, i)), || {
            let raw = bytes(case, "cbor")?;
            let w = Withdrawal::decode(&raw).c()?;
            same!(w.encode(), raw, "re-encoding");
            let p = by_id.get(s(case, "withdraws")?).c()?;
            same!(verifier.verify(p, &[w]).err(), Some(PublishingError::Withdrawn), "a withdrawn artefact is refused");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_decode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-021"]), format!("invalid decode {}", label(case, i)), || {
            let Err(e) = Publication::decode(&bytes(case, "cbor")?) else { return Err("accepted".into()) };
            same!(e.code(), Some(code(case)?), "error code");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_verify").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["PUB-040"]), format!("invalid verify {}", label(case, i)), || {
            let p = Publication::decode(&bytes(case, "cbor")?).c()?;
            let Err(e) = verifier.verify(&p, &[]) else { return Err("verified".into()) };
            same!(reason(&e).to_owned(), s(case, "error")?.to_owned(), "reason");
            same!(e.code().map(ErrorCode::as_str), case["code"].as_str(), "code");
            Ok(())
        });
    }
    c.case(&["PUB-040".into()], "the publication vectors are not empty", || {
        ensure!(!by_id.is_empty(), "no valid publication verified");
        Ok(())
    });
}
