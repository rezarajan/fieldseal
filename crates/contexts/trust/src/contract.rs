//! Contract tests for adapters of the Trust context's driven ports (TRU §4, PLAT-033).
//!
//! Each function panics with a message naming the broken obligation. Adapter crates
//! call them from their own tests.

use fieldseal_kernel::crypto::{Purpose, tags};
use fieldseal_kernel::id::{KeyId, Nonce, ReviewerId};
use fieldseal_kernel::seal::{RecipientKey, seal};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{CryptoRng, Value, sign};

use crate::domain::{
    AccessContext, AttestationEvidence, HoldingBounds, AuthorityPublicKey, DeviceKeyKind, KeyAlgorithm, KeyHandle, KeyOperation,
    KeyProtection, KeyRole, PersonRef,
};
use crate::ports::{
    AttestationVerifier, Attestor, AttestorError, AuthorityClock, CustodyError, HolderRegistryError, KeyCustody,
    KeyHolderRegistry, KeyStoreError, RandomSource, RevocationSource, SecureKeyStore, VerificationError,
};

/// [`KeyCustody`]: one role per key, tags limited to the role (TRU-003, TRU-011), real
/// signatures over the kernel's signed message, opening only by the addressed record key,
/// every use logged, unknown keys refused, and no way to read a private key.
///
/// `rng` seals the test payload to a generated record key (the sender's side, outside
/// custody).
pub fn key_custody_contract<C: KeyCustody>(make: impl Fn() -> C, rng: &mut impl CryptoRng) {
    let custody = make();
    let structure = Value::Text("contract".into());
    let factory_role = KeyRole::Purpose(Purpose::Factory);

    let root = custody.generate(KeyRole::Root, KeyAlgorithm::P256).expect("generate a root key");
    assert_eq!(root.role, KeyRole::Root, "generated key must carry the requested role");
    assert_eq!(root.id, root.public_key.key_id(), "the key ID is the public key's WIRE-010 identifier");
    assert!(
        matches!(custody.generate(KeyRole::Root, KeyAlgorithm::X25519), Err(CustodyError::Unsupported)),
        "a role must refuse an algorithm it can't have"
    );

    let factory = custody.generate(factory_role, KeyAlgorithm::P256).expect("generate a factory key");
    assert_eq!(custody.public_key(&factory.id).expect("public key"), factory, "public_key must report the generated key");
    assert_ne!(root.id, factory.id, "keys must have distinct identifiers");

    let sig = custody.sign(&factory.id, factory_role, &tags::BUNDLE, &structure, "contract").expect("sign with the key's own role");
    let public = factory.public_key.as_p256().expect("factory keys are P-256");
    sign::verify(public, &tags::BUNDLE, &structure, &sig).expect("signatures must verify with the kernel over [tag, structure]");
    assert!(
        matches!(
            custody.sign(&factory.id, KeyRole::Purpose(Purpose::Receipt), &tags::RECEIPT, &structure, "contract"),
            Err(CustodyError::WrongPurpose { .. })
        ),
        "a key must refuse a role other than its own"
    );
    assert!(
        matches!(custody.sign(&factory.id, factory_role, &tags::RECEIPT, &structure, "contract"), Err(CustodyError::TagNotAllowed { .. })),
        "a key must refuse a tag its purpose does not sign (TRU-011)"
    );
    custody.sign(&root.id, KeyRole::Root, &tags::KEY_CERTIFICATE, &structure, "contract").expect("a root signs key certificates");
    let csr = custody.sign(&factory.id, factory_role, &tags::CSR, &structure, "contract").expect("a key signs its own request (TRU-016)");
    sign::verify(public, &tags::CSR, &structure, &csr).expect("the proof of possession must verify");
    assert!(
        matches!(custody.sign(&root.id, KeyRole::Root, &tags::BUNDLE, &structure, "contract"), Err(CustodyError::TagNotAllowed { .. })),
        "a root must sign only key certificates, trust bundles and revocations (TRU-003)"
    );

    let record_role = KeyRole::Purpose(Purpose::Record);
    let record = custody.generate(record_role, KeyAlgorithm::X25519).expect("generate a record key");
    let AuthorityPublicKey::X25519(record_pub) = record.public_key else { panic!("record keys are X25519") };
    let sealed = seal(rng, &RecipientKey::X25519(record_pub), &tags::RECORD_SEAL, b"payload").expect("seal");
    assert_eq!(
        &custody.open(&record.id, Purpose::Record, &tags::RECORD_SEAL, &sealed, "contract").expect("open")[..],
        b"payload",
        "the record key must open what is sealed to it"
    );
    assert!(
        matches!(custody.open(&record.id, Purpose::Record, &tags::BUNDLE_SEAL, &sealed, "contract"), Err(CustodyError::TagNotAllowed { .. })),
        "a record key must open only record and manifest seals"
    );
    assert!(
        matches!(custody.open(&record.id, Purpose::Record, &tags::EXPORT_MANIFEST_SEAL, &sealed, "contract"), Err(CustodyError::Open(_))),
        "a seal under another tag must fail to open"
    );
    assert!(
        matches!(custody.open(&factory.id, Purpose::Record, &tags::RECORD_SEAL, &sealed, "contract"), Err(CustodyError::WrongPurpose { .. })),
        "opening must check the key's purpose"
    );
    assert!(
        matches!(custody.sign(&record.id, record_role, &tags::BUNDLE, &structure, "contract"), Err(CustodyError::TagNotAllowed { .. } | CustodyError::Unsupported)),
        "a record key must not sign"
    );
    assert_eq!(
        custody.sign(&KeyId::from([0xEE; 16]), factory_role, &tags::BUNDLE, &structure, "contract"),
        Err(CustodyError::UnknownKey),
        "unknown keys must be refused"
    );

    let log = custody.usage_log();
    assert!(
        log.iter().any(|u| u.key == factory.id && u.role == factory_role && u.operation == KeyOperation::Sign && u.caller == "contract"),
        "every signature must be logged with key, role and caller"
    );
    assert!(
        log.iter().any(|u| u.key == record.id && u.operation == KeyOperation::Open && u.caller == "contract"),
        "every open must be logged"
    );
}

/// [`SecureKeyStore`]: kinds are enforced, wrap round-trips, deletion is final.
pub fn secure_key_store_contract<S: SecureKeyStore>(make: impl Fn() -> S) {
    let store = make();
    let unlocked = KeyProtection {
        unlocked_required: true,
    };

    let (sign, sign_pub) = store
        .generate(DeviceKeyKind::Signing, unlocked, None)
        .expect("generate signing key");
    assert!(
        sign_pub.is_some(),
        "a signing key must report its public key"
    );
    store.sign(&sign, b"m").expect("sign");
    assert!(
        matches!(store.wrap(&sign, b"x"), Err(KeyStoreError::WrongKind(_))),
        "a signing key must not wrap"
    );

    let (agree_a, pub_a) = store
        .generate(DeviceKeyKind::Agreement, unlocked, None)
        .expect("generate agreement key");
    let (agree_b, pub_b) = store
        .generate(DeviceKeyKind::Agreement, unlocked, None)
        .expect("generate agreement key");
    let pub_a = pub_a.expect("agreement public key");
    let pub_b = pub_b.expect("agreement public key");
    assert_eq!(
        store.agree(&agree_a, &pub_b).expect("agree"),
        store.agree(&agree_b, &pub_a).expect("agree"),
        "key agreement must give both sides the same secret"
    );
    assert!(
        matches!(store.sign(&agree_a, b"m"), Err(KeyStoreError::WrongKind(_))),
        "an agreement key must not sign"
    );

    let (wrap, wrap_pub) = store
        .generate(DeviceKeyKind::Wrapping, unlocked, None)
        .expect("generate wrapping key");
    assert!(wrap_pub.is_none(), "a wrapping key has no public key");
    let wrapped = store.wrap(&wrap, b"session secret").expect("wrap");
    assert_ne!(
        wrapped,
        b"session secret".to_vec(),
        "wrapped data must differ from the plaintext"
    );
    assert_eq!(
        store.unwrap(&wrap, &wrapped).expect("unwrap"),
        b"session secret".to_vec(),
        "unwrap must invert wrap"
    );
    let mut tampered = wrapped.clone();
    tampered[0] ^= 1;
    assert_eq!(
        store.unwrap(&wrap, &tampered),
        Err(KeyStoreError::Unwrap),
        "tampered data must fail to unwrap"
    );

    store.delete(&sign).expect("delete");
    assert!(!store.exists(&sign), "a deleted key must not exist");
    assert_eq!(
        store.sign(&sign, b"m"),
        Err(KeyStoreError::UnknownKey),
        "a deleted key must be unusable"
    );
}

/// [`Attestor`]: evidence for a known key; unknown keys refused.
pub fn attestor_contract<A: Attestor>(make: impl Fn() -> (A, KeyHandle)) {
    let (attestor, key) = make();
    let evidence = attestor.evidence(&key).expect("evidence for a known key");
    assert!(!evidence.format.is_empty(), "evidence must name its format");
    assert_eq!(
        attestor.evidence(&KeyHandle("no-such-key".into())),
        Err(AttestorError::UnknownKey),
        "unknown keys must be refused"
    );
}

/// What a test needs to exercise an [`AttestationVerifier`]: valid evidence for a key.
pub struct VerifierFixture<V> {
    /// The verifier under test.
    pub verifier: V,
    /// Evidence the verifier must accept.
    pub evidence: AttestationEvidence,
    /// The challenge bound into it.
    pub challenge: Nonce,
    /// The key it attests.
    pub key: fieldseal_kernel::crypto::P256PublicKey,
    /// A different key it does not attest.
    pub other_key: fieldseal_kernel::crypto::P256PublicKey,
    /// The attestation roots to verify against (the trust bundle's, for the format).
    pub roots: Vec<Vec<u8>>,
}

/// [`AttestationVerifier`]: verifies good evidence; never returns claims for bad evidence.
pub fn attestation_verifier_contract<V: AttestationVerifier>(
    make: impl Fn() -> VerifierFixture<V>,
) {
    let f = make();
    let claims = f
        .verifier
        .verify(&f.evidence, &f.challenge, &f.key, &f.roots)
        .expect("valid evidence must verify");
    assert_eq!(
        claims.challenge, f.challenge,
        "claims must report the bound challenge"
    );

    let wrong = Nonce::from([0xAB; 32]);
    assert!(
        f.verifier.verify(&f.evidence, &wrong, &f.key, &f.roots).is_err(),
        "a wrong challenge must be refused"
    );
    assert!(
        f.verifier
            .verify(&f.evidence, &f.challenge, &f.other_key, &f.roots)
            .is_err(),
        "evidence for another key must be refused"
    );

    let mut tampered = f.evidence.clone();
    if let Some(b) = tampered.data.last_mut() {
        *b ^= 1;
    } else {
        tampered.data.push(1);
    }
    assert!(
        f.verifier.verify(&tampered, &f.challenge, &f.key, &f.roots).is_err(),
        "tampered evidence must be refused"
    );

    let foreign = AttestationEvidence {
        format: format!("{}-other", f.verifier.format()),
        data: f.evidence.data.clone(),
    };
    assert!(
        matches!(
            f.verifier.verify(&foreign, &f.challenge, &f.key, &f.roots),
            Err(VerificationError::UnsupportedFormat(_))
        ),
        "evidence in another format must be refused"
    );
}

/// [`RevocationSource`]: answers with a retrieval time, consistently.
pub fn revocation_source_contract<R: RevocationSource>(make: impl Fn() -> R) {
    let source = make();
    let a = source.status(b"cert-1").expect("status");
    let b = source.status(b"cert-1").expect("status");
    assert_eq!(
        a.revoked, b.revoked,
        "the same certificate must have a stable status"
    );
}

/// [`AuthorityClock`]: never goes backwards.
pub fn authority_clock_contract<C: AuthorityClock>(make: impl Fn() -> C) {
    let clock = make();
    let t1 = clock.now();
    let t2 = clock.now();
    assert!(t2 >= t1, "authority time must not decrease");
}

/// [`RandomSource`]: successive outputs differ.
pub fn random_source_contract<R: RandomSource>(make: impl Fn() -> R) {
    let random = make();
    assert_ne!(
        random.nonce(),
        random.nonce(),
        "successive nonces must differ"
    );
}

/// [`KeyHolderRegistry`]: access-controlled, no duplicates, holdings bounded in time,
/// listable per holder and endable (TRU-092, TRU-094).
pub fn key_holder_registry_contract<K: KeyHolderRegistry>(make: impl Fn() -> K) {
    let registry = make();
    let custodian = AccessContext {
        caller: "custodian".into(),
        may_resolve_holders: true,
    };
    let outsider = AccessContext {
        caller: "outsider".into(),
        may_resolve_holders: false,
    };
    let key = KeyId::from([7; 16]);
    let key2 = KeyId::from([9; 16]);
    let reviewer = ReviewerId::new("r-1").expect("reviewer id");
    let p1 = PersonRef("p-1".into());
    let t = AuthorityTime;
    let open = HoldingBounds::default();

    registry
        .register_key_holder(&key, p1.clone(), open, &custodian)
        .expect("register key holder");
    assert_eq!(
        registry.register_key_holder(&key, PersonRef("p-2".into()), open, &custodian),
        Err(HolderRegistryError::AlreadyRegistered),
        "a key's holder must not be silently replaced"
    );
    assert_eq!(
        registry.register_key_holder(&key2, p1.clone(), open, &outsider),
        Err(HolderRegistryError::Denied),
        "others must not register holders"
    );
    assert_eq!(
        registry.key_holder(&key, t(5), &custodian),
        Ok(p1.clone()),
        "an authorised caller resolves holders"
    );
    assert_eq!(
        registry.key_holder(&key, t(5), &outsider),
        Err(HolderRegistryError::Denied),
        "others must be denied"
    );
    assert_eq!(
        registry.key_holder(&KeyId::from([8; 16]), t(5), &custodian),
        Err(HolderRegistryError::NotFound),
        "unknown keys are not found"
    );

    // Validity bounds: in force on [not_before, not_after).
    let bad = HoldingBounds { not_before: Some(t(10)), not_after: Some(t(10)) };
    assert_eq!(
        registry.register_key_holder(&key2, p1.clone(), bad, &custodian),
        Err(HolderRegistryError::InvalidBounds),
        "a holding must end after it starts"
    );
    let bounded = HoldingBounds { not_before: Some(t(10)), not_after: Some(t(20)) };
    registry
        .register_key_holder(&key2, p1.clone(), bounded, &custodian)
        .expect("register bounded holding");
    assert_eq!(registry.key_holder(&key2, t(9), &custodian), Err(HolderRegistryError::NotFound));
    assert_eq!(registry.key_holder(&key2, t(10), &custodian), Ok(p1.clone()));
    assert_eq!(registry.key_holder(&key2, t(20), &custodian), Err(HolderRegistryError::NotFound));

    // Listing a holder's keys.
    let mut listed = registry.holder_keys(&p1, &custodian).expect("list");
    listed.sort_by_key(|h| h.key);
    assert_eq!(listed.len(), 2, "both of the holder's keys are listed");
    assert_eq!(listed[0].key, key);
    assert_eq!(listed[1].bounds, bounded);
    assert_eq!(
        registry.holder_keys(&PersonRef("nobody".into()), &custodian),
        Ok(vec![]),
        "a holder with no keys lists empty"
    );
    assert_eq!(
        registry.holder_keys(&p1, &outsider),
        Err(HolderRegistryError::Denied),
        "others must be denied"
    );

    // Ending a holding.
    assert_eq!(registry.end_holding(&key, t(30), &outsider), Err(HolderRegistryError::Denied));
    registry.end_holding(&key, t(30), &custodian).expect("end holding");
    assert_eq!(registry.key_holder(&key, t(29), &custodian), Ok(p1.clone()), "in force before the end");
    assert_eq!(
        registry.key_holder(&key, t(30), &custodian),
        Err(HolderRegistryError::NotFound),
        "not in force at the end"
    );
    assert_eq!(
        registry.end_holding(&key, t(40), &custodian),
        Err(HolderRegistryError::NotFound),
        "an ended holding can't be ended again"
    );
    assert_eq!(
        registry.end_holding(&KeyId::from([8; 16]), t(40), &custodian),
        Err(HolderRegistryError::NotFound)
    );
    let ended = registry.holder_keys(&p1, &custodian).expect("list").into_iter().find(|h| h.key == key).expect("kept");
    assert_eq!(ended.bounds.not_after, Some(t(30)), "the ended holding stays listed with its end");

    registry
        .register_reviewer(&reviewer, PersonRef("p-3".into()), &custodian)
        .expect("register reviewer");
    assert_eq!(
        registry.reviewer(&reviewer, &outsider),
        Err(HolderRegistryError::Denied),
        "others must be denied"
    );
}
