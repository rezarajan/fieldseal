//! Contract tests for adapters of the Collection context's platform ports.

use fieldseal_kernel::id::Seq;

use crate::domain::{
    CaptureConstraints, HashParams, ManagementMode, ReceiptClaim, Restriction, RestrictionState,
    RuntimePin, StorageClass, StorageName, WindowId,
};
use crate::ports::{
    BundleOpener, Camera, DevicePolicy, DevicePolicyError, ElapsedClock, FileAccess, MemoryHardHash,
    ReceiptCheck, SecureDisplay, SecureStorage, WallClock, CloseCertificateCheck,
};
use fieldseal_kernel::sign::verify_message;
use fieldseal_trust::domain::{DeviceKeyKind, KeyProtection};
use fieldseal_trust::ports::{KeyStoreError, SecureKeyStore};

/// [`ElapsedClock`]: within one boot count, readings never decrease.
pub fn elapsed_clock_contract<C: ElapsedClock>(make: impl Fn() -> C) {
    let clock = make();
    let a = clock.now();
    let b = clock.now();
    if a.boot_count == b.boot_count {
        assert!(b.elapsed_ms >= a.elapsed_ms, "elapsed time never decreases within a boot");
    } else {
        assert!(b.boot_count > a.boot_count, "the boot count only increases");
    }
}

/// [`SecureStorage`]: atomic replace, separate classes, delete, listing.
pub fn secure_storage_contract<S: SecureStorage>(make: impl Fn() -> S) {
    let store = make();
    let name = StorageName("journal".into());
    assert_eq!(store.read(StorageClass::DeviceEncrypted, &name), Ok(None));
    store.write(StorageClass::DeviceEncrypted, &name, b"one").expect("write");
    store.write(StorageClass::DeviceEncrypted, &name, b"two").expect("replace");
    assert_eq!(
        store.read(StorageClass::DeviceEncrypted, &name),
        Ok(Some(b"two".to_vec())),
        "a write fully replaces the object"
    );
    assert_eq!(
        store.read(StorageClass::SessionEncrypted, &name),
        Ok(None),
        "classes are separate namespaces"
    );
    assert_eq!(store.names(StorageClass::DeviceEncrypted), Ok(vec![name.clone()]));
    store.delete(StorageClass::DeviceEncrypted, &name).expect("delete");
    assert_eq!(store.read(StorageClass::DeviceEncrypted, &name), Ok(None));

    let log = StorageName("log".into());
    store.append(StorageClass::DeviceEncrypted, &log, b"ab").expect("append creates");
    store.append(StorageClass::DeviceEncrypted, &log, b"cd").expect("append");
    assert_eq!(
        store.read(StorageClass::DeviceEncrypted, &log),
        Ok(Some(b"abcd".to_vec())),
        "appends add to the end"
    );
    assert_eq!(store.read(StorageClass::SessionEncrypted, &log), Ok(None), "appends respect classes");
}

/// A [`SecureKeyStore`] the runtime can record with (PLAT-010, PLAT-011, WIRE-022): keys
/// that require an unlocked device refuse to work while it is locked, and signing keys make
/// real ECDSA P-256 signatures over the message, so journal records verify with the
/// format core. `set_locked` simulates the device lock.
pub fn record_signing_key_store_contract<S: SecureKeyStore>(make: impl Fn() -> S, set_locked: impl Fn(&S, bool)) {
    let store = make();
    let unlocked = KeyProtection { unlocked_required: true };
    let (sign, public) = store.generate(DeviceKeyKind::Signing, unlocked, None).expect("generate");
    let public = public.expect("a signing key reports its public key");
    let message = b"fieldseal contract message";
    let sig = store.sign(&sign, message).expect("sign");
    verify_message(&public, message, &sig).expect("a signature verifies with the format core");
    let (wrap, _) = store.generate(DeviceKeyKind::Wrapping, unlocked, None).expect("generate");
    let wrapped = store.wrap(&wrap, b"secret").expect("wrap");
    set_locked(&store, true);
    assert_eq!(store.sign(&sign, message), Err(KeyStoreError::Locked), "unlock-bound keys refuse while locked");
    assert_eq!(store.unwrap(&wrap, &wrapped), Err(KeyStoreError::Locked), "unlock-bound keys refuse while locked");
    set_locked(&store, false);
    assert_eq!(store.unwrap(&wrap, &wrapped).expect("unwrap"), b"secret".to_vec());
    store.delete(&wrap).expect("delete");
    assert!(store.unwrap(&wrap, &wrapped).is_err(), "deletion is a crypto-erase: what it wrapped is gone");
}

/// [`WallClock`]: any reading is only a hint; a known time is in milliseconds since the
/// epoch, so after 2001.
pub fn wall_clock_contract<W: WallClock>(make: impl Fn() -> W) {
    if let Some(ms) = make().now_ms() {
        assert!(ms > 1_000_000_000_000, "milliseconds since the Unix epoch");
    }
}

/// [`FileAccess`]: returns exactly the bytes of the file picked.
pub fn file_access_contract<F: FileAccess>(make: impl Fn(&[u8]) -> F) {
    let f = make(b"FSB1 picked file");
    assert_eq!(f.pick_source().expect("pick"), b"FSB1 picked file".to_vec());
}

/// [`BundleOpener`]: opens `ours` the same way every time; refuses `foreign` (sealed to
/// another device or tampered with).
pub fn bundle_opener_contract<B: BundleOpener>(make: impl Fn() -> B, ours: &[u8], foreign: &[u8]) {
    let opener = make();
    let a = opener.open(ours).expect("our bundle opens");
    assert_eq!(opener.open(ours).expect("again"), a, "the same bytes open to the same contents");
    assert!(opener.open(foreign).is_err(), "a foreign bundle is refused");
}

/// [`SecureDisplay`]: a protected window reports protected; others don't.
pub fn secure_display_contract<D: SecureDisplay>(make: impl Fn() -> D) {
    let display = make();
    let w = WindowId("review".into());
    assert!(!display.is_protected(&WindowId("other".into())));
    display.protect(&w).expect("protect");
    assert!(display.is_protected(&w));
}

/// [`DevicePolicy`], self-managed: applied restrictions are in force, and a restriction
/// removed behind the adapter's back is reported `Missing` (PLAT-033, PLAT-042).
pub fn device_policy_self_managed_contract<D: DevicePolicy>(
    make: impl Fn() -> D,
    remove_out_of_band: impl Fn(&D, Restriction),
) {
    let policy = make();
    assert_eq!(policy.mode(), ManagementMode::SelfManaged);
    policy.apply(&Restriction::ALL).expect("apply");
    let effective = policy.effective_restrictions();
    for r in Restriction::ALL {
        assert_eq!(effective.get(&r), Some(&RestrictionState::InForce), "{} applied", r.name());
    }
    remove_out_of_band(&policy, Restriction::ClearDataBlocked);
    assert_eq!(
        policy.effective_restrictions().get(&Restriction::ClearDataBlocked),
        Some(&RestrictionState::Missing),
        "state is read live, not remembered from apply"
    );
}

/// [`DevicePolicy`], EMM-managed: can't apply; reports only what it reads.
pub fn device_policy_emm_contract<D: DevicePolicy>(
    make: impl Fn() -> D,
    remove_out_of_band: impl Fn(&D, Restriction),
) {
    let policy = make();
    assert_eq!(policy.mode(), ManagementMode::EmmManaged);
    assert_eq!(policy.apply(&Restriction::ALL), Err(DevicePolicyError::NotDeviceOwner));
    remove_out_of_band(&policy, Restriction::DebuggingDisabled);
    assert_ne!(
        policy.effective_restrictions().get(&Restriction::DebuggingDisabled),
        Some(&RestrictionState::InForce),
        "a removed restriction is never reported in force"
    );
}

/// [`Camera`]: an image arrives in memory.
pub fn camera_contract<C: Camera>(make: impl Fn() -> C) {
    let camera = make();
    let image = camera.capture(CaptureConstraints { max_edge: 2000 }).expect("capture");
    assert!(!image.0.is_empty());
}

/// [`MemoryHardHash`]: deterministic, input-sensitive, floor enforced.
pub fn memory_hard_hash_contract<H: MemoryHardHash>(make: impl Fn() -> H) {
    let h = make();
    let a = RuntimePin::new("123456").expect("pin");
    let b = RuntimePin::new("654321").expect("pin");
    let p = HashParams::FLOOR;
    let x = h.hash(&a, &[1; 16], p).expect("hash");
    assert_eq!(Some(x), h.hash(&a, &[1; 16], p), "deterministic");
    assert_ne!(Some(x), h.hash(&b, &[1; 16], p), "PIN-sensitive");
    assert_ne!(Some(x), h.hash(&a, &[2; 16], p), "salt-sensitive");
    let weak = HashParams { memory_kib: 1024, ..p };
    assert_eq!(h.hash(&a, &[1; 16], weak), None, "parameters below the floor are refused");
}

/// [`ReceiptCheck`]: accepts `valid`, refuses `forged` (bad signature) and
/// `untrusted` (signed by a key outside the trust root).
pub fn receipt_check_contract<R: ReceiptCheck>(
    make: impl Fn() -> R,
    valid: ReceiptClaim,
    forged: ReceiptClaim,
    untrusted: ReceiptClaim,
) {
    let check = make();
    check.verify(&valid).expect("a valid receipt verifies");
    assert!(check.verify(&forged).is_err(), "a forged receipt is refused");
    assert!(check.verify(&untrusted).is_err(), "a receipt from an untrusted key is refused");
    let mut tampered = valid.clone();
    tampered.last_seq = Seq(valid.last_seq.0 + 1);
    tampered.statement.push(0);
    assert!(check.verify(&tampered).is_err(), "changing the statement breaks the signature");
}

/// [`CloseCertificateCheck`] (COL-007): accepts a genuine certificate and states what it
/// closes; refuses a certificate with any byte changed, a truncated one and an empty one;
/// needs nothing but the certificate (no PIN, no tenancy key).
pub fn close_certificate_check_contract<C: CloseCertificateCheck>(check: &C, genuine: &[u8], tenancy: fieldseal_kernel::id::TenancyId, cutoff: Seq) {
    let stated = check.verify(genuine).expect("a genuine certificate verifies");
    assert_eq!(stated.tenancy, tenancy, "it states the tenancy it closes");
    assert_eq!(stated.cutoff_seq, cutoff, "it states the cutoff");
    assert_eq!(stated.bytes, genuine.to_vec(), "it returns the bytes to attach to the outbox");
    assert_eq!(check.verify(genuine), Ok(stated), "the same bytes always give the same answer");
    for i in [0, genuine.len() / 2, genuine.len() - 1] {
        let mut forged = genuine.to_vec();
        forged[i] ^= 1;
        assert!(check.verify(&forged).is_err(), "a certificate with byte {i} changed is refused");
    }
    assert!(check.verify(&genuine[..genuine.len() - 1]).is_err(), "a truncated certificate is refused");
    assert!(check.verify(&[]).is_err(), "an empty certificate is refused");
}
