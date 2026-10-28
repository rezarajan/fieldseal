//! The Trust context's golden vectors (TRU §6.4–6.6), checked in-process.

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::{DomainTag, Purpose, Signature};
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value};
use fieldseal_trust::domain::{
    AuthorityPublicKey, CertificateRequest, KeyCertificate, Revocation, TrustBundle, TrustError, TrustStore,
};
use serde_json::{Value as J, json};

use super::harness::{Chk, Collector, ensure, label, requirement_ids, same, unhex};
use super::Unit;

const CERTIFICATES: &str = include_str!("../../../../contexts/trust/tests/vectors/certificates.json");
const REVOCATIONS: &str = include_str!("../../../../contexts/trust/tests/vectors/revocations.json");
const TRUST_BUNDLES: &str = include_str!("../../../../contexts/trust/tests/vectors/trust_bundles.json");
const CHAINS: &str = include_str!("../../../../contexts/trust/tests/vectors/chains.json");

/// The vector units of the `trust` suite.
pub fn units() -> Vec<Unit> {
    vec![
        Unit::new("trust:certificates", &["trust"], certificates),
        Unit::new("trust:revocations", &["trust"], revocations),
        Unit::new("trust:trust-bundles", &["trust"], trust_bundles),
        Unit::new("trust:chains", &["trust"], chains),
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

fn offset(j: &J) -> Result<u64, String> {
    j["offset"].as_u64().ok_or_else(|| "field `offset` is missing".to_owned())
}

/// A stable name for a verification failure, so the vectors say why as well as which code.
fn reason(e: &TrustError) -> &'static str {
    match e {
        TrustError::Wire(_) => "malformed",
        TrustError::UnknownRoot(_) => "unknown-root",
        TrustError::ChainTooLong => "chain-too-long",
        TrustError::MissingCertificate(_) => "missing-certificate",
        TrustError::SignerMismatch => "signer-mismatch",
        TrustError::WrongPurpose { .. } => "wrong-purpose",
        TrustError::NotYetValid => "not-yet-valid",
        TrustError::Expired => "expired",
        TrustError::Revoked { .. } => "revoked",
        TrustError::BadSignature(_) => "bad-signature",
        TrustError::UntrustedTag(_) => "untrusted-tag",
        TrustError::BundleSigner => "bundle-signer",
        TrustError::InvalidRoots(_) => "invalid-roots",
        TrustError::InvalidBundleEntry(_) => "invalid-entry",
        TrustError::UntrustedEntry(_) => "untrusted-entry",
        TrustError::InvalidVersion => "invalid-version",
        TrustError::PossessionNotProved => "possession-not-proved",
        _ => "other",
    }
}

fn certificates(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(CERTIFICATES) else { return c.case(&["TRU-090".into()], "load", || Err("certificates.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-001"]), format!("valid {}", label(case, i)), || {
            let raw = bytes(case, "cbor")?;
            let cert = KeyCertificate::decode(&raw).c()?;
            same!(cert.encode().c()?, raw, "re-encoding");
            same!(lower_hex(cert.key_id().as_bytes()), s(case, "key_id")?.to_owned(), "key id");
            same!(cert.role().as_str().to_owned(), s(case, "purpose")?.to_owned(), "purpose");
            let issuer = AuthorityPublicKey::from_encoded(&bytes(case, "issuer_public_key")?).c()?;
            cert.verify_issued_by(issuer.as_p256().c()?).c()?;
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_decode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-090"]), format!("invalid decode {}", label(case, i)), || {
            let Err(e) = KeyCertificate::decode(&bytes(case, "cbor")?) else { return Err("accepted".into()) };
            same!(e.code, code(case)?, "error code");
            same!(e.offset as u64, offset(case)?, "error offset");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_signature").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-020"]), format!("invalid signature {}", label(case, i)), || {
            let cert = KeyCertificate::decode(&bytes(case, "cbor")?).c()?;
            let issuer = AuthorityPublicKey::from_encoded(&bytes(case, "issuer_public_key")?).c()?;
            let Err(e) = cert.verify_issued_by(issuer.as_p256().c()?) else { return Err("verified".into()) };
            same!(e.code(), Some(code(case)?), "error code");
            same!(reason(&e).to_owned(), s(case, "reason")?.to_owned(), "reason");
            Ok(())
        });
    }
    let requests = &v["requests"];
    for (i, case) in list(requests, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-016"]), format!("request {}", label(case, i)), || {
            let raw = bytes(case, "cbor")?;
            let r = CertificateRequest::decode(&raw).c()?;
            same!(r.encode().c()?, raw, "re-encoding");
            r.verify_possession().c()?;
            Ok(())
        });
    }
    for (i, case) in list(requests, "possession_rejected").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-016"]), format!("possession rejected {}", label(case, i)), || {
            let Err(e) = CertificateRequest::decode(&bytes(case, "cbor")?).c()?.verify_possession() else { return Err("accepted".into()) };
            same!(e.code(), Some(code(case)?), "error code");
            same!(reason(&e).to_owned(), s(case, "reason")?.to_owned(), "reason");
            Ok(())
        });
    }
    for (i, case) in list(requests, "invalid_decode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-016"]), format!("request invalid {}", label(case, i)), || {
            let Err(TrustError::Wire(e)) = CertificateRequest::decode(&bytes(case, "cbor")?) else { return Err("not a wire error".into()) };
            same!((e.code, e.offset as u64), (code(case)?, offset(case)?), "error");
            Ok(())
        });
    }
    for (i, case) in list(requests, "identity_rejected").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-091"]), format!("identity rejected {}", label(case, i)), || {
            let attrs: Vec<String> = list(case, "attributes").iter().filter_map(|a| a.as_str().map(str::to_owned)).collect();
            same!(CertificateRequest::decode(&bytes(case, "cbor")?), Err(TrustError::IdentityAttributes(attrs)), "a request naming a person is refused");
            Ok(())
        });
    }
}

fn revocations(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(REVOCATIONS) else { return c.case(&["TRU-040".into()], "load", || Err("revocations.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-040"]), format!("valid {}", label(case, i)), || {
            let raw = bytes(case, "cbor")?;
            let r = Revocation::decode(&raw).c()?;
            same!(r.encode().c()?, raw, "re-encoding");
            let root = AuthorityPublicKey::from_encoded(&bytes(case, "root_public_key")?).c()?;
            r.verify_issued_by(root.as_p256().c()?).c()?;
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_decode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-040"]), format!("invalid decode {}", label(case, i)), || {
            let Err(e) = Revocation::decode(&bytes(case, "cbor")?) else { return Err("accepted".into()) };
            same!((e.code, e.offset as u64), (code(case)?, offset(case)?), "error");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_signature").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-020"]), format!("invalid signature {}", label(case, i)), || {
            let r = Revocation::decode(&bytes(case, "cbor")?).c()?;
            let root = AuthorityPublicKey::from_encoded(&bytes(case, "root_public_key")?).c()?;
            let Err(e) = r.verify_issued_by(root.as_p256().c()?) else { return Err("verified".into()) };
            same!(e.code(), Some(code(case)?), "error code");
            Ok(())
        });
    }
}

fn trust_bundles(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(TRUST_BUNDLES) else { return c.case(&["TRU-030".into()], "load", || Err("trust_bundles.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-030"]), format!("valid {}", label(case, i)), || {
            let raw = bytes(case, "cbor")?;
            let b = TrustBundle::decode(&raw).c()?;
            same!(b.encode().c()?, raw, "re-encoding");
            same!(b.content_address().c()?.to_text(), s(case, "content_address")?.to_owned(), "content address");
            let roots: Vec<String> = b.roots().iter().map(|r| lower_hex(r.key_id().as_bytes())).collect();
            same!(json!(roots), case["roots"].clone(), "roots");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-031"]), format!("invalid {}", label(case, i)), || {
            let Err(e) = TrustBundle::decode(&bytes(case, "cbor")?) else { return Err("accepted".into()) };
            same!(e.code().map_or("none", |c| c.as_str()).to_owned(), s(case, "error")?.to_owned(), "error code");
            if let Some(off) = case.get("offset").and_then(J::as_u64) {
                let TrustError::Wire(w) = &e else { return Err("not a wire error".into()) };
                same!(w.offset as u64, off, "error offset");
            }
            Ok(())
        });
    }
}

fn chains(c: &mut Collector) {
    let Ok(v) = serde_json::from_str::<J>(CHAINS) else { return c.case(&["TRU-011".into()], "load", || Err("chains.json does not parse".into())) };
    let Ok(bundle) = bytes(&v, "bundle").and_then(|b| TrustBundle::decode(&b).c()) else {
        return c.case(&["TRU-011".into()], "bundle", || Err("the vector trust bundle does not decode".into()));
    };
    let store = TrustStore::new(&bundle);
    let outcome = |r: Result<&KeyCertificate, TrustError>| match r {
        Ok(_) => json!({"result": "ok"}),
        Err(e) => json!({"error": e.code().map_or("none", |c| c.as_str()), "reason": reason(&e)}),
    };
    let expected = |case: &J| {
        let mut e = case.clone();
        if let Some(o) = e.as_object_mut() {
            o.retain(|k, _| matches!(k.as_str(), "result" | "error" | "reason"));
        }
        e
    };
    for (i, case) in list(&v, "chains").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-011"]), format!("chain {}", label(case, i)), || {
            let signer = KeyId::from_bytes(&bytes(case, "signer")?).c()?;
            let chain: Vec<KeyCertificate> =
                list(case, "chain").iter().map(|h| KeyCertificate::decode(&unhex(h.as_str().c()?)?).c()).collect::<Result<_, String>>()?;
            let purpose = Purpose::parse(s(case, "purpose")?).c()?;
            let time = AuthorityTime(case["time"].as_u64().c()?);
            same!(outcome(store.verify_chain(&signer, &chain, purpose, time)), expected(case), "verdict");
            Ok(())
        });
    }
    for (i, case) in list(&v, "signatures").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["TRU-011"]), format!("signature {}", label(case, i)), || {
            let signer = KeyId::from_bytes(&bytes(case, "signer")?).c()?;
            let tag: &'static str = Box::leak(s(case, "tag")?.to_owned().into_boxed_str());
            let structure: Value = cbor::decode(&bytes(case, "structure")?).c()?;
            let sig = Signature(bytes(case, "sig")?);
            let time = AuthorityTime(case["time"].as_u64().c()?);
            same!(outcome(store.verify_signature(&signer, &[], &DomainTag::new(tag), &structure, &sig, time)), expected(case), "verdict");
            Ok(())
        });
    }
    ensure_nonempty(c, &v);
}

fn ensure_nonempty(c: &mut Collector, v: &J) {
    c.case(&["TRU-011".into()], "the chain vectors are not empty", || {
        ensure!(!list(v, "chains").is_empty() && !list(v, "signatures").is_empty(), "no chain vectors");
        Ok(())
    });
}
