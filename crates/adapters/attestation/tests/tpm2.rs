//! The `tpm2-quote` authority-evidence verifier, named by requirement (TRU-110, TRU-118,
//! TRU-063, TRU-062): the shared verifier contract, every way evidence fails, the registry's
//! refusal of formats with no adapter, and a recorded corpus (`tests/vectors/tpm2_certify.json`).
//!
//! Regenerate the corpus after an intended change with
//! `FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-adapters-attestation --test tpm2`.

use std::path::PathBuf;

use fieldseal_adapters_attestation::registry::{AUTHORITY_FORMATS, EvidenceVerifiers, VERIFIABLE_FORMATS};
use fieldseal_adapters_attestation::testing::{AT, Options, Pki, certificate, evidence, tpm_key, with_chain};
use fieldseal_adapters_attestation::tpm2::{FORMAT, Tpm2CertifyVerifier};
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::Nonce;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_trust::contract::{VerifierFixture, attestation_verifier_contract};
use fieldseal_trust::domain::{AttestationEvidence, DeviceKeyKind, RevocationStatus, SecurityLevel};
use fieldseal_trust::ports::{AttestationVerifier, RevocationSource, RevocationSourceError, VerificationError};
use serde_json::json;

struct Revoked(Vec<Vec<u8>>);

impl RevocationSource for Revoked {
    fn status(&self, id: &[u8]) -> Result<RevocationStatus, RevocationSourceError> {
        Ok(RevocationStatus { revoked: self.0.iter().any(|r| r == id), retrieved_at: AT })
    }
}

/// One recorded-evidence case: name, evidence, key, challenge, expected to verify, expected error.
type Case<'a> = (&'a str, AttestationEvidence, Vec<u8>, Nonce, bool, &'a str);

fn nonce() -> Nonce {
    Nonce::from([0x5a; 32])
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn tru_110_the_tpm2_verifier_meets_the_shared_verifier_contract() {
    let none = Revoked(vec![]);
    attestation_verifier_contract(|| {
        let pki = Pki::new("contract");
        let (ev, key) = evidence(&pki, "one", &nonce(), Options::default());
        let (other_key, _) = tpm_key("two", Options::default().attributes);
        VerifierFixture { verifier: Tpm2CertifyVerifier::new(AT, &none), evidence: ev, challenge: nonce(), key, other_key, roots: vec![pki.root.clone()] }
    });
}

#[test]
fn tru_110_valid_evidence_yields_only_verified_claims() {
    let none = Revoked(vec![]);
    let pki = Pki::new("claims");
    let (ev, key) = evidence(&pki, "k", &nonce(), Options::default());
    let claims = Tpm2CertifyVerifier::new(AT, &none).verify(&ev, &nonce(), &key, std::slice::from_ref(&pki.root)).expect("verifies");
    assert_eq!(claims.security_level, SecurityLevel::Tpm);
    assert!(claims.origin_generated);
    assert_eq!(claims.kind, DeviceKeyKind::Signing);
    assert_eq!(claims.challenge, nonce());
    // TRU-063 and TRU-118: the device-only facts a TPM does not attest are absent, not defaulted.
    assert_eq!(
        (claims.unlocked_required, claims.app_id, claims.app_version, claims.boot_state, claims.bootloader_locked, claims.os_patch_level, claims.device_serial),
        (None, None, None, None, None, None, None)
    );
}

#[test]
fn tru_110_evidence_that_does_not_hold_up_is_refused() {
    let none = Revoked(vec![]);
    let pki = Pki::new("negative");
    let roots = vec![pki.root.clone()];
    let v = Tpm2CertifyVerifier::new(AT, &none);
    let (good, key) = evidence(&pki, "k", &nonce(), Options::default());
    assert!(v.verify(&good, &nonce(), &key, &roots).is_ok());

    // Wrong challenge, wrong key.
    assert_eq!(v.verify(&good, &Nonce::from([1; 32]), &key, &roots).unwrap_err(), VerificationError::ChallengeMismatch);
    let (other, _) = tpm_key("other", Options::default().attributes);
    assert_eq!(v.verify(&good, &nonce(), &other, &roots).unwrap_err(), VerificationError::KeyMismatch);

    // A key that is not fixed to the TPM, or not generated inside it: a software-backed key.
    for attributes in [0u32, (1 << 18) | (1 << 5) | (1 << 4), (1 << 18) | (1 << 1) | (1 << 4)] {
        let (ev, k) = evidence(&pki, "soft", &nonce(), Options { attributes, ..Options::default() });
        assert!(matches!(v.verify(&ev, &nonce(), &k, &roots), Err(VerificationError::Invalid(_))), "attributes {attributes:#x}");
    }
    // A key that neither signs nor decrypts.
    let (ev, k) = evidence(&pki, "none", &nonce(), Options { attributes: (1 << 1) | (1 << 4) | (1 << 5), ..Options::default() });
    assert!(v.verify(&ev, &nonce(), &k, &roots).is_err());

    // Not a TPM attestation, or not a certification.
    for opts in [Options { magic: 0xdead_beef, ..Options::default() }, Options { attest_type: 0x8018, ..Options::default() }] {
        let (ev, k) = evidence(&pki, "k", &nonce(), opts);
        assert!(matches!(v.verify(&ev, &nonce(), &k, &roots), Err(VerificationError::Invalid(_))));
    }
    // Signed by a key that is not the certificate's.
    let (ev, k) = evidence(&pki, "k", &nonce(), Options { wrong_signer: true, ..Options::default() });
    assert!(matches!(v.verify(&ev, &nonce(), &k, &roots), Err(VerificationError::Invalid(_))));

    // A chain that does not reach a root the bundle lists.
    let stranger = Pki::new("stranger");
    assert!(matches!(v.verify(&good, &nonce(), &key, std::slice::from_ref(&stranger.root)), Err(VerificationError::Invalid(_))));
    // No roots at all.
    assert_eq!(v.verify(&good, &nonce(), &key, &[]).unwrap_err(), VerificationError::NoRoots(FORMAT.to_owned()));
    // A leaf that no root signed, presented under a root it merely shares a name with.
    let imposter = Pki::new("imposter");
    let mut forged_chain = evidence(&imposter, "k", &nonce(), Options::default()).0;
    forged_chain.format = FORMAT.to_owned();
    assert!(v.verify(&forged_chain, &nonce(), &key, &roots).is_err());
}

#[test]
fn tru_110_revoked_and_expired_chains_are_refused() {
    let pki = Pki::new("lifetime");
    let (good, key) = evidence(&pki, "k", &nonce(), Options::default());
    let roots = vec![pki.root.clone()];
    // The vendor's revocation source says the AK certificate is revoked (TRU-062).
    let revoked = Revoked(vec![pki.ak_serial.clone()]);
    assert_eq!(Tpm2CertifyVerifier::new(AT, &revoked).verify(&good, &nonce(), &key, &roots).unwrap_err(), VerificationError::Revoked);
    // Judged at a time before or after the certificates' validity.
    let none = Revoked(vec![]);
    for at in [AuthorityTime(1_000_000_000_000), AuthorityTime(2_300_000_000_000)] {
        assert!(Tpm2CertifyVerifier::new(at, &none).verify(&good, &nonce(), &key, &roots).is_err(), "{at:?}");
    }
    // A leaf whose own validity has ended.
    let Value::Map(m) = cbor::decode(&good.data).unwrap() else { unreachable!() };
    let (Some(Value::Bytes(attest)), Some(Value::Bytes(sig)), Some(Value::Bytes(public))) = (m.get("attest"), m.get("signature"), m.get("public")) else { panic!() };
    let expired = with_chain(attest, sig, public, &[pki.expired_ak()]);
    assert!(Tpm2CertifyVerifier::new(AT, &none).verify(&expired, &nonce(), &key, &roots).is_err());
}

#[test]
fn tru_110_evidence_is_strictly_decoded() {
    let none = Revoked(vec![]);
    let pki = Pki::new("strict");
    let roots = vec![pki.root.clone()];
    let v = Tpm2CertifyVerifier::new(AT, &none);
    let (good, key) = evidence(&pki, "k", &nonce(), Options::default());
    let Value::Map(map) = cbor::decode(&good.data).unwrap() else { unreachable!() };
    let refuse = |m: std::collections::BTreeMap<String, Value>| {
        let ev = AttestationEvidence { format: FORMAT.into(), data: cbor::encode(&Value::Map(m)).unwrap() };
        assert!(matches!(v.verify(&ev, &nonce(), &key, &roots), Err(VerificationError::Invalid(_))));
    };
    let mut extra = map.clone();
    extra.insert("holder".into(), Value::Text("Jane".into()));
    refuse(extra);
    for field in ["attest", "signature", "public", "chain", "v"] {
        let mut m = map.clone();
        m.remove(field);
        refuse(m);
    }
    let mut m = map.clone();
    m.insert("chain".into(), Value::Array(vec![]));
    refuse(m);
    let mut m = map.clone();
    m.insert("attest".into(), Value::Bytes(vec![0; 3]));
    refuse(m);
    // Trailing bytes after a structure, truncated structures and garbage are refused.
    let Some(Value::Bytes(attest)) = map.get("attest") else { panic!() };
    let mut longer = attest.clone();
    longer.push(0);
    let mut m = map.clone();
    m.insert("attest".into(), Value::Bytes(longer));
    refuse(m);
    assert!(v.verify(&AttestationEvidence { format: FORMAT.into(), data: vec![0xff, 0x00] }, &nonce(), &key, &roots).is_err());
    // A certificate that is not X.509 is refused as such.
    let Some(Value::Bytes(sig)) = map.get("signature") else { panic!() };
    let Some(Value::Bytes(public)) = map.get("public") else { panic!() };
    assert!(v.verify(&with_chain(attest, sig, public, &[b"not a certificate".to_vec()]), &nonce(), &key, &roots).is_err());
    // A certificate with an unsupported signature algorithm: signed with a key but labelled differently is untrusted.
    let k = pki.root.clone();
    let _ = certificate("x", "y", 9, 0, 1, &[4; 65], &p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap());
    assert!(v.verify(&with_chain(attest, sig, public, &[k]), &nonce(), &key, &roots).is_err(), "the root is not an attestation key");
}

#[test]
fn tru_062_evidence_in_another_format_is_refused() {
    let none = Revoked(vec![]);
    let pki = Pki::new("format");
    let (mut ev, key) = evidence(&pki, "k", &nonce(), Options::default());
    ev.format = "android-key-attestation".into();
    assert!(matches!(
        Tpm2CertifyVerifier::new(AT, &none).verify(&ev, &nonce(), &key, std::slice::from_ref(&pki.root)),
        Err(VerificationError::UnsupportedFormat(_))
    ));
}

#[test]
fn tru_110_formats_without_an_adapter_are_refused_not_trusted() {
    // The registry knows three authority-evidence formats and can verify one. The others fail
    // closed: the registry has no verifier for them, whatever the bundle lists.
    assert_eq!(AUTHORITY_FORMATS, ["tpm2-quote", "hsm-key-attestation", "cloud-kms-attestation"]);
    assert_eq!(VERIFIABLE_FORMATS, ["tpm2-quote"]);
    let none = Revoked(vec![]);
    let tpm = Tpm2CertifyVerifier::new(AT, &none);
    let registry = EvidenceVerifiers::new(vec![&tpm]);
    let pki = Pki::new("registry");
    let (_, key) = evidence(&pki, "k", &nonce(), Options::default());
    let bundle = fieldseal_trust::domain::TrustBundle::decode(&bundle_bytes(&pki)).expect("bundle");
    for format in ["hsm-key-attestation", "cloud-kms-attestation", "made-up"] {
        let ev = AttestationEvidence { format: format.into(), data: vec![1, 2, 3] };
        assert_eq!(registry.verify(&bundle, &ev, &nonce(), &key).unwrap_err(), VerificationError::UnsupportedFormat(format.to_owned()));
    }
    // A verifiable format with no roots in the bundle (TRU-062).
    let (ev, key) = evidence(&pki, "k", &nonce(), Options::default());
    let bundle_without = fieldseal_trust::domain::TrustBundle::decode(&bundle_bytes_with(&pki, false)).unwrap();
    assert_eq!(registry.verify(&bundle_without, &ev, &nonce(), &key).unwrap_err(), VerificationError::NoRoots(FORMAT.to_owned()));
    // With the roots listed, it verifies through the registry.
    assert!(registry.verify(&bundle, &ev, &nonce(), &key).is_ok());
}

fn bundle_bytes(pki: &Pki) -> Vec<u8> {
    bundle_bytes_with(pki, true)
}

/// A signed trust bundle that lists `pki`'s root under `tpm2-quote` (or no attestation roots).
fn bundle_bytes_with(pki: &Pki, with_roots: bool) -> Vec<u8> {
    use fieldseal_kernel::crypto::Purpose;
    use fieldseal_kernel::sign::SigningKey;
    use fieldseal_trust::application::Authority;
    use fieldseal_trust::domain::{AuthorityPublicKey, BundleVersion, Ceremony, KeyAlgorithm, KeyRole, Threshold, TrustBundleContents};
    let _ = (Purpose::Factory, SigningKey::from_scalar(&[1; 32]), KeyAlgorithm::P256, KeyRole::Root, AuthorityPublicKey::P256);
    let custody = test_custody::Custody::default();
    let t0 = AuthorityTime(1_800_000_000_000);
    let ceremony = Authority::new(&custody, "t")
        .init_root(Ceremony {
            authority: "a".into(),
            threshold: Threshold::DEFAULT,
            custodians: vec!["a".into(), "b".into(), "c".into()],
            witnesses: vec!["w".into()],
            held_at: t0,
            not_before: t0,
            not_after: AuthorityTime(t0.0 + 86_400_000 * 365),
        })
        .unwrap();
    let roots = if with_roots { std::collections::BTreeMap::from([(FORMAT.to_owned(), vec![pki.root.clone()])]) } else { Default::default() };
    let contents = TrustBundleContents {
        name: "a".into(),
        version: BundleVersion::parse("1.0.0").unwrap(),
        issued: t0,
        roots: vec![ceremony.root.clone()],
        certificates: vec![],
        publishers: Default::default(),
        attestation_roots: roots,
        runtime_builds: vec![],
        logs: vec![],
        revocations: vec![],
    };
    Authority::new(&custody, "t").build_bundle(contents, &[&ceremony.root], None).unwrap().encode().unwrap()
}

#[test]
fn tru_110_the_recorded_corpus_is_current_and_holds() {
    let pki = Pki::new("recorded");
    let none = Revoked(vec![]);
    let revoked = Revoked(vec![pki.ak_serial.clone()]);
    let roots = vec![pki.root.clone()];
    let (good, key) = evidence(&pki, "recorded-key", &nonce(), Options::default());
    let (other, _) = tpm_key("recorded-other", Options::default().attributes);
    let soft = evidence(&pki, "recorded-soft", &nonce(), Options { attributes: 1 << 18, ..Options::default() });
    let wrong_signer = evidence(&pki, "recorded-key", &nonce(), Options { wrong_signer: true, ..Options::default() });
    // (name, evidence, key, challenge, revoked?, expected)
    let cases: Vec<Case> = vec![
        ("valid", good.clone(), key.as_bytes().to_vec(), nonce(), false, "ok"),
        ("wrong challenge", good.clone(), key.as_bytes().to_vec(), Nonce::from([9; 32]), false, "challenge-mismatch"),
        ("wrong key", good.clone(), other.as_bytes().to_vec(), nonce(), false, "key-mismatch"),
        ("revoked chain", good.clone(), key.as_bytes().to_vec(), nonce(), true, "revoked"),
        ("software-backed key", soft.0, soft.1.as_bytes().to_vec(), nonce(), false, "invalid"),
        ("signed by another key", wrong_signer.0, wrong_signer.1.as_bytes().to_vec(), nonce(), false, "invalid"),
    ];
    let outcome = |e: &Result<_, VerificationError>| match e {
        Ok(_) => "ok",
        Err(VerificationError::ChallengeMismatch) => "challenge-mismatch",
        Err(VerificationError::KeyMismatch) => "key-mismatch",
        Err(VerificationError::Revoked) => "revoked",
        Err(VerificationError::Invalid(_)) => "invalid",
        Err(_) => "other",
    };
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/tpm2_certify.json");
    let doc = json!({
        "description": "TPM 2.0 key certification evidence for authority keys (TRU-110), built to the TCG TPMS_ATTEST/TPMT_SIGNATURE/TPMT_PUBLIC structures and X.509 DER by the crate's test builder; not captured from a physical TPM.",
        "spec": "docs/reference/spec/trust.md",
        "at_ms": AT.0,
        "root": hex(&pki.root),
        "ak_serial": hex(&pki.ak_serial),
        "regenerate": "FIELDSEAL_REGENERATE_VECTORS=1 cargo test -p fieldseal-adapters-attestation --test tpm2",
        "cases": cases.iter().map(|(name, ev, k, ch, rev, want)| json!({
            "name": name, "format": ev.format, "evidence": hex(&ev.data), "key": hex(k), "challenge": hex(ch.as_bytes()), "chain_revoked": rev, "expect": want,
        })).collect::<Vec<_>>(),
    });
    let text = format!("{}\n", serde_json::to_string_pretty(&doc).unwrap());
    if std::env::var_os("FIELDSEAL_REGENERATE_VECTORS").is_some() {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&file).expect("the corpus exists"), text, "the corpus is stale");

    // The stored bytes, not the freshly built ones, are what the verifier must judge.
    let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let root = unhex(stored["root"].as_str().unwrap());
    for c in stored["cases"].as_array().unwrap() {
        let ev = AttestationEvidence { format: c["format"].as_str().unwrap().into(), data: unhex(c["evidence"].as_str().unwrap()) };
        let k = fieldseal_kernel::crypto::P256PublicKey::from_bytes(&unhex(c["key"].as_str().unwrap())).unwrap();
        let ch = Nonce::from(<[u8; 32]>::try_from(unhex(c["challenge"].as_str().unwrap())).unwrap());
        let source: &dyn RevocationSource = if c["chain_revoked"].as_bool().unwrap() { &revoked } else { &none };
        let got = Tpm2CertifyVerifier::new(AuthorityTime(stored["at_ms"].as_u64().unwrap()), source).verify(&ev, &ch, &k, std::slice::from_ref(&root));
        assert_eq!(outcome(&got), c["expect"].as_str().unwrap(), "{}", c["name"]);
    }
    let _ = roots;
}

mod test_custody {
    //! A throwaway software custody for building a trust bundle in these tests.
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use fieldseal_kernel::Value;
    use fieldseal_kernel::crypto::{DomainTag, Purpose, Signature};
    use fieldseal_kernel::id::KeyId;
    use fieldseal_kernel::seal::SealedBox;
    use fieldseal_kernel::sign::SigningKey;
    use fieldseal_trust::domain::{AuthorityPublicKey, CustodyKey, KeyAlgorithm, KeyRole, KeyUse};
    use fieldseal_trust::ports::{CustodyError, KeyCustody};
    use zeroize::Zeroizing;

    #[derive(Default)]
    pub struct Custody(RefCell<BTreeMap<KeyId, (SigningKey, KeyRole)>>);

    impl KeyCustody for Custody {
        fn generate(&self, role: KeyRole, _: KeyAlgorithm) -> Result<CustodyKey, CustodyError> {
            let k = SigningKey::from_scalar(&[42u8; 32]).unwrap();
            let public_key = AuthorityPublicKey::P256(k.public_key());
            let key = CustodyKey { id: public_key.key_id(), public_key, role };
            self.0.borrow_mut().insert(key.id, (k, role));
            Ok(key)
        }

        fn sign(&self, key: &KeyId, _: KeyRole, tag: &DomainTag, structure: &Value, _: &str) -> Result<Signature, CustodyError> {
            self.0.borrow().get(key).ok_or(CustodyError::UnknownKey)?.0.sign(tag, structure).map_err(|e| CustodyError::Backend(e.to_string()))
        }

        fn open(&self, _: &KeyId, _: Purpose, _: &DomainTag, _: &SealedBox, _: &str) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
            Err(CustodyError::Unsupported)
        }

        fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError> {
            let b = self.0.borrow();
            let (k, role) = b.get(key).ok_or(CustodyError::UnknownKey)?;
            let public_key = AuthorityPublicKey::P256(k.public_key());
            Ok(CustodyKey { id: public_key.key_id(), public_key, role: *role })
        }

        fn usage_log(&self) -> Vec<KeyUse> {
            vec![]
        }
    }
}
