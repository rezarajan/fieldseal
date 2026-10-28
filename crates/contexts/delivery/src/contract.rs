//! Contract tests for adapters of the Delivery context's driven ports.

use fieldseal_collection::ports::ReceiptCheck;
use fieldseal_kernel::id::{Digest, Nonce, TenancyHandle, TenancyId};
use fieldseal_kernel::{Value, cbor};

use crate::domain::{AddressHint, AuthorisedDestination, ExportId, HintSource, ReceiverChallenge, UploadRequest};
use crate::ports::{
    FileAccess, ManifestAttachments, PrivateStorage, QrScanner, ReceiverCheck, RegistrationRecords, ShareOutcome, ShareTarget,
    UploadTransport,
};

/// An address hint, as a test uses it.
pub fn hint(address: &str) -> AddressHint {
    AddressHint { address: address.into(), source: HintSource::CollectorEntry }
}

/// A challenge with a nonce of `n` repeated.
pub fn challenge(n: u8, handle: TenancyHandle) -> ReceiverChallenge {
    ReceiverChallenge::new(Nonce::from([n; 32]), handle)
}

/// [`UploadTransport`] for an authorised destination: the answer passes `check` at any
/// address and doesn't depend on the address (WIRE-182), uploads are idempotent
/// (DEL-008) and receipts pass `receipts`. `addresses` are two addresses of the same
/// destination; `request` makes a valid upload for `tenancy` each time it is called (a
/// fresh token every time: a token is good once).
pub fn upload_transport_contract<T: UploadTransport>(
    transport: &T,
    check: &impl ReceiverCheck,
    receipts: &impl ReceiptCheck,
    addresses: [&str; 2],
    handle: TenancyHandle,
    tenancy: TenancyId,
    request: &dyn Fn() -> UploadRequest,
) {
    let c = challenge(1, handle);
    let a = transport.challenge(&hint(addresses[0]), &c).expect("answers");
    let b = transport.challenge(&hint(addresses[1]), &c).expect("answers");
    assert_eq!(a, b, "the answer doesn't depend on the address (WIRE-182)");
    let destination = AuthorisedDestination::authorise(hint(addresses[0]), &c, &a, check).expect("authorised");
    let first = transport.upload(&destination, &request()).expect("upload");
    let again = transport.upload(&destination, &request()).expect("re-upload");
    let mine = |v: &[fieldseal_collection::domain::ReceiptClaim]| v.iter().find(|r| r.tenancy == tenancy).cloned().expect("a receipt for the tenancy");
    let (first, again) = (mine(&first), mine(&again));
    assert_eq!(first.last_seq, again.last_seq, "uploads are idempotent");
    assert_eq!(first.journal_hash, again.journal_hash, "uploads are idempotent");
    receipts.verify(&first).expect("the receipt verifies against the trust root (DEL-064)");
}

/// [`UploadTransport`] for an unauthorised destination: whatever it answers, it can't
/// become an [`AuthorisedDestination`] (DEL-062).
pub fn unauthorised_destination_contract<T: UploadTransport>(transport: &T, check: &impl ReceiverCheck, handle: TenancyHandle) {
    let c = challenge(2, handle);
    if let Ok(proof) = transport.challenge(&hint("https://spoofed.example"), &c) {
        assert!(
            AuthorisedDestination::authorise(hint("https://spoofed.example"), &c, &proof, check).is_err(),
            "an unauthorised destination never passes the challenge"
        );
    }
}

/// [`ReceiverCheck`]: a proof for one challenge doesn't pass for another.
pub fn receiver_check_contract<T: UploadTransport, C: ReceiverCheck>(transport: &T, check: &C, handle: TenancyHandle) {
    let proof = transport.challenge(&hint("https://a.example"), &challenge(3, handle)).expect("answers");
    check.verify(&challenge(3, handle), &proof).expect("verifies");
    assert!(check.verify(&challenge(4, handle), &proof).is_err(), "a proof is bound to its challenge");
}

/// [`FileAccess`]: write, sync and read back through the destination; report its class.
pub fn file_access_contract<F: FileAccess>(make: impl Fn() -> F) {
    let files = make();
    let h = files.pick_destination().expect("pick");
    files.write(&h, b"export").expect("write");
    files.sync(&h).expect("sync");
    assert_eq!(files.read_back(&h).expect("read back"), b"export".to_vec());
    assert!(!files.report(&h).provider.is_empty(), "the provider is named");
    files.write(&h, b"second").expect("rewrite");
    assert_eq!(files.read_back(&h).expect("read back"), b"second".to_vec(), "a write replaces the file");
}

/// [`ShareTarget`]: reports an outcome.
pub fn share_target_contract<S: ShareTarget>(make: impl Fn() -> S) {
    let target = make();
    let outcome = target.share(b"export", &["mail".into()]);
    assert!(matches!(outcome, ShareOutcome::Shared | ShareOutcome::Cancelled | ShareOutcome::Failed));
}

/// [`PrivateStorage`]: returns what was stored until deleted; markers replace on write.
pub fn private_storage_contract<P: PrivateStorage>(make: impl Fn() -> P) {
    let store = make();
    let id = ExportId(Digest::from([1; 32]));
    store.put(&id, b"x").expect("put");
    assert_eq!(store.get(&id), Ok(Some(b"x".to_vec())));
    store.delete(&id).expect("delete");
    assert_eq!(store.get(&id), Ok(None));
    assert_eq!(store.get_marker("m"), Ok(None));
    store.put_marker("m", b"1").expect("marker");
    store.put_marker("m", b"2").expect("marker");
    assert_eq!(store.get_marker("m"), Ok(Some(b"2".to_vec())), "a marker is replaced");
}

/// [`QrScanner`]: returns decoded bytes.
pub fn qr_scanner_contract<Q: QrScanner>(make: impl Fn() -> Q) {
    assert!(!make().scan().expect("scan").is_empty());
}

/// [`RegistrationRecords`]: the same documents for the same tenancy; nothing for a tenancy
/// it doesn't know.
pub fn registration_records_contract<R: RegistrationRecords>(records: &R, known: TenancyId) {
    let a = records.attachments(&known);
    assert_eq!(a, records.attachments(&known), "stable");
    assert!(a.certificate.is_some() || a.registration.is_some(), "a known tenancy has documents");
    assert_eq!(records.attachments(&TenancyId::from([0xee; 32])), ManifestAttachments::default());
    // Whatever it returns must be encodable.
    for v in [a.certificate, a.registration].into_iter().flatten() {
        assert!(cbor::encode(&v).is_ok() && matches!(v, Value::Map(_)));
    }
}
