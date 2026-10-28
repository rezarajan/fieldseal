//! Driven ports owned by the Trust context (`docs/reference/spec/trust.md` §4).

use std::convert::Infallible;

use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::{DomainTag, P256PublicKey, Purpose, Signature};
use fieldseal_kernel::id::{KeyId, Nonce, ReviewerId};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::time::AuthorityTime;
use zeroize::Zeroizing;

use crate::domain::{
    AccessContext, AttestationClaims, HoldingBounds, KeyHolding, AttestationEvidence, CustodyKey, DeviceKeyKind, KeyAlgorithm,
    KeyHandle, KeyProtection, KeyRole, KeyUse, PersonRef, RevocationStatus,
};

/// Errors from [`KeyCustody`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    /// No such key in custody.
    #[error("unknown key")]
    UnknownKey,
    /// The key was asked to act outside its single role.
    #[error("key is held for {held}, not {requested}")]
    WrongPurpose {
        /// The key's role.
        held: KeyRole,
        /// The role requested.
        requested: KeyRole,
    },
    /// The key's role does not sign, or open, under this domain tag (TRU-003, TRU-011).
    #[error("a {role} key does not use tag {tag}")]
    TagNotAllowed {
        /// The key's role.
        role: KeyRole,
        /// The tag refused.
        tag: &'static str,
    },
    /// The operation isn't available for this key type (for example opening with a signing
    /// key, or a key algorithm the role can't have).
    #[error("operation not supported by this key")]
    Unsupported,
    /// The sealed input couldn't be opened (with the WIRE code of the failure).
    #[error("open failed: {0}")]
    Open(fieldseal_kernel::WireError),
    /// The custody backend failed.
    #[error("custody backend: {0}")]
    Backend(String),
}

/// Authority keys inside a hardware boundary: an HSM, a KMS, or the offline signer that
/// holds the root (TRU-001, TRU-013, TRU-022).
///
/// Contract (checked by [`crate::contract::key_custody_contract`]):
/// - keys are generated inside custody, for exactly one role, and private parts are never
///   exported; the port has no operation that could return one;
/// - a key refuses any role other than its own, and any tag its role does not sign or open
///   ([`crate::domain::may_sign`], [`crate::domain::may_open`]): a root signs only key
///   certificates, trust bundles and revocations (TRU-003), and any P-256 key may sign its
///   own certificate request (`fieldseal.dev/csr/v1`, TRU-016);
/// - signatures are over the kernel's signed message `[tag, structure]` (WIRE-021), so they
///   verify with [`fieldseal_kernel::sign::verify`];
/// - every use is logged with the key ID, role and caller identity.
pub trait KeyCustody {
    /// Generates a key for exactly one role, with `algorithm` (which the role must allow).
    fn generate(&self, role: KeyRole, algorithm: KeyAlgorithm) -> Result<CustodyKey, CustodyError>;

    /// Signs `structure` under `tag` with `key`, which must be held for `role`.
    fn sign(
        &self,
        key: &KeyId,
        role: KeyRole,
        tag: &DomainTag,
        structure: &Value,
        caller: &str,
    ) -> Result<Signature, CustodyError>;

    /// Opens a seal addressed to `key` under `tag` (WIRE-023..026); the key must be held for
    /// `purpose` (`record` or `registration`), which must open under `tag`. The plaintext is
    /// zeroised when dropped.
    fn open(
        &self,
        key: &KeyId,
        purpose: Purpose,
        tag: &DomainTag,
        sealed: &SealedBox,
        caller: &str,
    ) -> Result<Zeroizing<Vec<u8>>, CustodyError>;

    /// The public part of a key in custody.
    fn public_key(&self, key: &KeyId) -> Result<CustodyKey, CustodyError>;

    /// Every recorded use, oldest first.
    fn usage_log(&self) -> Vec<KeyUse>;
}

/// Errors from [`SecureKeyStore`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyStoreError {
    /// No such key, or it was deleted.
    #[error("unknown or deleted key")]
    UnknownKey,
    /// The key's kind doesn't allow this operation.
    #[error("key kind {0:?} does not allow this operation")]
    WrongKind(DeviceKeyKind),
    /// The key requires an unlocked device.
    #[error("device is locked")]
    Locked,
    /// Unwrapping failed authentication.
    #[error("unwrap failed")]
    Unwrap,
    /// The platform store failed.
    #[error("key store: {0}")]
    Backend(String),
}

/// A device's secure key store.
///
/// Contract: keys are generated inside the store and never exported; signing, key
/// agreement and unwrapping happen only inside it; `unlocked_required` keys fail while
/// the device is locked; deleted keys are unrecoverable.
pub trait SecureKeyStore {
    /// Generates a key of `kind`, binding `challenge` into its attestation where supported.
    fn generate(
        &self,
        kind: DeviceKeyKind,
        protection: KeyProtection,
        challenge: Option<Nonce>,
    ) -> Result<(KeyHandle, Option<P256PublicKey>), KeyStoreError>;

    /// Signs with a signing key.
    fn sign(&self, key: &KeyHandle, message: &[u8]) -> Result<Signature, KeyStoreError>;

    /// Performs P-256 key agreement with an agreement key; the shared secret is returned to the caller,
    /// which must wipe it after use.
    fn agree(&self, key: &KeyHandle, peer: &P256PublicKey) -> Result<Vec<u8>, KeyStoreError>;

    /// Wraps data with a wrapping key.
    fn wrap(&self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, KeyStoreError>;

    /// Unwraps data wrapped by [`SecureKeyStore::wrap`] with the same key.
    fn unwrap(&self, key: &KeyHandle, wrapped: &[u8]) -> Result<Vec<u8>, KeyStoreError>;

    /// Deletes a key irrecoverably.
    fn delete(&self, key: &KeyHandle) -> Result<(), KeyStoreError>;

    /// Whether the key exists.
    fn exists(&self, key: &KeyHandle) -> bool;
}

/// Errors from [`Attestor`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestorError {
    /// No such key.
    #[error("unknown key")]
    UnknownKey,
    /// The platform can't attest this key.
    #[error("attestation unavailable: {0}")]
    Unavailable(String),
}

/// Produces attestation evidence for a device key at creation.
pub trait Attestor {
    /// Evidence for `key`, binding the challenge given when it was generated.
    fn evidence(&self, key: &KeyHandle) -> Result<AttestationEvidence, AttestorError>;
}

/// Errors from [`AttestationVerifier`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerificationError {
    /// The evidence is in a format this verifier doesn't handle.
    #[error("unsupported evidence format {0}")]
    UnsupportedFormat(String),
    /// The evidence didn't verify against the platform roots.
    #[error("evidence invalid: {0}")]
    Invalid(String),
    /// The challenge bound into the evidence isn't the expected one.
    #[error("challenge mismatch")]
    ChallengeMismatch,
    /// The evidence is for a different key.
    #[error("evidence is for a different key")]
    KeyMismatch,
    /// A certificate in the chain is revoked.
    #[error("revoked")]
    Revoked,
    /// The trust bundle lists no attestation roots for the format (TRU-062).
    #[error("no attestation roots for format {0}")]
    NoRoots(String),
}

/// Verifies one evidence format and returns platform-neutral claims (TRU-060..065).
///
/// Contract (checked by [`crate::contract::attestation_verifier_contract`]): verifies the
/// evidence chain to one of `roots` (the trust bundle's attestation roots for its format,
/// TRU-062), checks vendor revocation, that the attested key is `key` and the attested
/// challenge is `expected_challenge`; returns only facts it verified, never defaults
/// (TRU-063); decides nothing about sufficiency (TRU-065).
pub trait AttestationVerifier {
    /// The evidence format this verifier handles (TRU §6.2).
    fn format(&self) -> &str;

    /// Verifies `evidence` for `key` with `expected_challenge`, against `roots`.
    fn verify(
        &self,
        evidence: &AttestationEvidence,
        expected_challenge: &Nonce,
        key: &P256PublicKey,
        roots: &[Vec<u8>],
    ) -> Result<AttestationClaims, VerificationError>;
}

/// Errors from [`RevocationSource`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationSourceError {
    /// The status list couldn't be retrieved.
    #[error("revocation source unavailable: {0}")]
    Unavailable(String),
}

/// The platform vendor's revocation status for attestation certificates.
pub trait RevocationSource {
    /// Status of the certificate identified by `certificate_id` (format-specific, for example a serial).
    fn status(&self, certificate_id: &[u8]) -> Result<RevocationStatus, RevocationSourceError>;
}

/// Trusted authority time, for authority-side components only.
pub trait AuthorityClock {
    /// The current authority time.
    fn now(&self) -> AuthorityTime;
}

/// Cryptographically secure randomness.
pub trait RandomSource {
    /// Fills `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]);

    /// A fresh nonce.
    fn nonce(&self) -> Nonce {
        let mut bytes = [0u8; Nonce::LEN];
        self.fill(&mut bytes);
        Nonce::from(bytes)
    }
}

/// A [`RandomSource`] as the kernel's [`fieldseal_kernel::CryptoRng`], so the kernel's key
/// generation and sealing draw from the port: `SigningKey::generate(&mut SourceRng(&random))`.
///
/// It is only as random as the source; adapters must back `RandomSource` with the
/// platform's cryptographically secure generator.
pub struct SourceRng<'a, R: RandomSource + ?Sized>(pub &'a R);

impl<R: RandomSource + ?Sized> rand_core::TryRng for SourceRng<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0; 4];
        self.0.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0; 8];
        self.0.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill(dst);
        Ok(())
    }
}

impl<R: RandomSource + ?Sized> rand_core::TryCryptoRng for SourceRng<'_, R> {}

/// Errors from [`KeyHolderRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HolderRegistryError {
    /// The caller may not resolve holders.
    #[error("access denied")]
    Denied,
    /// No holder is recorded for the identifier.
    #[error("not found")]
    NotFound,
    /// The identifier already has a holder.
    #[error("already registered")]
    AlreadyRegistered,
    /// The holding would end before it starts.
    #[error("holding ends before it starts")]
    InvalidBounds,
}

/// The private mapping from key IDs and reviewer IDs to people (TRU-092).
///
/// Contract: access-controlled. It lists only one holder's keys, with no way to dump the
/// whole mapping, so it can't be copied into bundles, trust bundles, provenance or logs.
/// Only the authority's tooling reads it (TRU-094).
pub trait KeyHolderRegistry {
    /// Records who holds `key`, optionally between `bounds`. A key has one holding.
    fn register_key_holder(
        &self,
        key: &KeyId,
        holder: PersonRef,
        bounds: HoldingBounds,
        ctx: &AccessContext,
    ) -> Result<(), HolderRegistryError>;

    /// Records who a reviewer ID stands for.
    fn register_reviewer(
        &self,
        reviewer: &ReviewerId,
        person: PersonRef,
        ctx: &AccessContext,
    ) -> Result<(), HolderRegistryError>;

    /// Resolves who holds `key` at `at`; only for callers allowed to resolve holders.
    /// A key whose holding is not in force at `at` is [`HolderRegistryError::NotFound`].
    fn key_holder(
        &self,
        key: &KeyId,
        at: AuthorityTime,
        ctx: &AccessContext,
    ) -> Result<PersonRef, HolderRegistryError>;

    /// Lists every holding recorded for `holder`, ended or not; only for callers allowed to
    /// resolve holders. A holder with none yields an empty list.
    fn holder_keys(
        &self,
        holder: &PersonRef,
        ctx: &AccessContext,
    ) -> Result<Vec<KeyHolding>, HolderRegistryError>;

    /// Ends `key`'s holding at `at`. A key with no holding, or one already ended at or
    /// before `at`, is [`HolderRegistryError::NotFound`].
    fn end_holding(
        &self,
        key: &KeyId,
        at: AuthorityTime,
        ctx: &AccessContext,
    ) -> Result<(), HolderRegistryError>;

    /// Resolves a reviewer; only for callers allowed to resolve holders.
    fn reviewer(
        &self,
        reviewer: &ReviewerId,
        ctx: &AccessContext,
    ) -> Result<PersonRef, HolderRegistryError>;
}
