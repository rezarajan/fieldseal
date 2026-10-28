//! Why a Trust operation was refused.

use fieldseal_kernel::id::KeyId;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, WireError};

use super::purpose::KeyRole;

/// A refusal from the Trust domain: a request it won't certify, a structure that isn't
/// valid, or a signature or chain it won't trust.
///
/// Verification failures map to a WIRE §6.8 code through [`TrustError::code`]: every
/// "signer not trusted" case is `E_SIG` (TRU-011, TRU-012, TRU-034, TRU-042), a tag no
/// authority key signs is `E_TAG` (WIRE-020), and a decoding failure keeps its own code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The bytes or value are not a valid structure, or a kernel check failed.
    #[error(transparent)]
    Wire(#[from] WireError),

    // --- Requests and issuance -----------------------------------------------------
    /// A certificate request carried identity attributes (TRU-091).
    #[error("certificate requests must not carry identity attributes: {0:?}")]
    IdentityAttributes(Vec<String>),
    /// The request asked for one purpose and the issuer was asked to certify another.
    #[error("the request asks for {requested}, not {issued}")]
    PurposeMismatch {
        /// What the request asked for.
        requested: KeyRole,
        /// What the issuer was asked to certify.
        issued: KeyRole,
    },
    /// A collection period is required for, and only allowed on, `record` keys (TRU-020).
    #[error("a collection period is required for, and only allowed on, record keys")]
    PeriodMismatch,
    /// The public key's type can't be certified for this role (TRU-001, TRU-020, WIRE-009).
    #[error("a {0} key can't have this key type")]
    KeyTypeMismatch(KeyRole),
    /// The validity period is empty or inverted.
    #[error("validity must end after it starts")]
    EmptyValidity,
    /// The validity period exceeds the role's limit (TRU-004, TRU-012, TRU §6.1).
    #[error("validity of {role} keys must not exceed {max_ms} ms")]
    ValidityTooLong {
        /// The role being certified.
        role: KeyRole,
        /// The limit, in milliseconds.
        max_ms: u64,
    },
    /// A certificate would be valid outside its issuing root's validity.
    #[error("a certificate must lie within its root's validity")]
    OutsideIssuerValidity,
    /// Only a root issues certificates, and only for purpose keys (TRU-003, TRU-014).
    #[error("only a root issues key certificates, and only for purpose keys")]
    NotAnIssuer,
    /// A P-256 certificate request has no valid proof of possession (TRU-016, `E_SIG`).
    #[error("the request does not prove possession of its key")]
    PossessionNotProved,
    /// A ceremony's custodian threshold is not a threshold (TRU-002).
    #[error("invalid custodian threshold: {0}")]
    InvalidCeremony(&'static str),
    /// A record key may not be destroyed yet (TRU-023).
    #[error("the record key must be kept until {until:?}")]
    RecordKeyRetained {
        /// The earliest time it may be destroyed, if no sealed data remains.
        until: AuthorityTime,
    },

    // --- Chain verification ----------------------------------------------------------
    /// The issuer is not a root in the trust bundle (TRU-034).
    #[error("issuer {0:?} is not a root in the trust bundle")]
    UnknownRoot(KeyId),
    /// The chain is longer than root → purpose key (TRU-014).
    #[error("certificate chains must have depth 1")]
    ChainTooLong,
    /// No certificate for the signer was presented or pinned.
    #[error("no certificate for key {0:?}")]
    MissingCertificate(KeyId),
    /// The certificate presented is for another key.
    #[error("the certificate is for another key")]
    SignerMismatch,
    /// The key is certified for another purpose than the signature needs (TRU-011).
    #[error("key is certified for {certified}, not {required}")]
    WrongPurpose {
        /// What the certificate says.
        certified: KeyRole,
        /// What the tag or caller requires.
        required: KeyRole,
    },
    /// The signing time is before the certificate's (or root's) validity (TRU-012).
    #[error("not yet valid at the signing time")]
    NotYetValid,
    /// The signing time is after the certificate's (or root's) validity (TRU-012).
    #[error("expired at the signing time")]
    Expired,
    /// The certificate was revoked at or before the signing time (TRU-042).
    #[error("revoked with effect from {effective:?}")]
    Revoked {
        /// The revocation's effective time.
        effective: AuthorityTime,
    },
    /// A signature does not verify (`E_SIG`), or its tag is wrong (`E_TAG`).
    #[error("bad signature: {0}")]
    BadSignature(WireError),
    /// The tag is not one an authority key signs (WIRE-020).
    #[error("tag {0} is not signed by an authority key")]
    UntrustedTag(&'static str),

    // --- Trust bundles -----------------------------------------------------------------
    /// A trust bundle lists no root, or a "root" entry isn't a self-issued root certificate.
    #[error("trust bundle roots are invalid: {0}")]
    InvalidRoots(&'static str),
    /// A certificate or revocation in a trust bundle is not issued by one of its roots
    /// (TRU-034, `E_SIG`: its signer is not trusted).
    #[error("trust bundle entry is not issued by a listed root: {0}")]
    UntrustedEntry(&'static str),
    /// An entry in a trust bundle is listed twice or refers to something the bundle lacks.
    #[error("trust bundle entry is invalid: {0}")]
    InvalidBundleEntry(&'static str),
    /// A trust bundle carries no signature, or a signature by a key that isn't one of its roots (TRU-031).
    #[error("trust bundle must be signed by its own roots")]
    BundleSigner,
    /// A newer trust bundle isn't signed by a root of the current one (TRU-033).
    #[error("trust bundle update is not signed by a current root")]
    UpdateSigner,
    /// A newer trust bundle adds a root that did not sign it (TRU-004).
    #[error("new root {0:?} must also sign the trust bundle")]
    NewRootUnsigned(KeyId),
    /// A newer trust bundle's version is not higher (TRU-033), or it is for another authority.
    #[error("trust bundle update must be for the same authority with a higher version")]
    UpdateNotNewer,
    /// A version string is not `MAJOR.MINOR.PATCH` (`E_UNKNOWN_FIELD`: the field is not of
    /// the form its structure defines).
    #[error("trust bundle versions are MAJOR.MINOR.PATCH")]
    InvalidVersion,
    /// The transparency log is not pinned, or the checkpoint key isn't its pinned key (TRU-093).
    #[error("transparency log {0} is not pinned with this key")]
    LogNotPinned(String),
    /// The trust bundle lists no attestation roots for an evidence format (TRU-062).
    #[error("no attestation roots for evidence format {0}")]
    NoAttestationRoots(String),

    // --- Custody (TRU §5.10) -------------------------------------------------------------
    /// A `development` key was offered to a root that certifies for production (TRU-109, INV-15).
    #[error("a development key cannot be certified by a production root")]
    DevelopmentKeyInProduction,
    /// The key was certified as `development` before; promotion is a new key (TRU-114).
    #[error("key {0:?} was issued as a development key and cannot be promoted; generate a new key")]
    PromotionRefused(KeyId),
    /// The request shows none of the means that establish an assurance (TRU-108).
    #[error("the request shows no custody: not from a software custody, a bound custody generation or verified evidence")]
    NoCustodyMeans,
    /// A custody the policy minimum does not allow (TRU-112, POL-065).
    #[error("{what} {actual} is below the policy minimum {minimum}")]
    BelowMinimum {
        /// `assurance` or `mode`.
        what: &'static str,
        /// What the key has.
        actual: &'static str,
        /// What policy requires.
        minimum: &'static str,
    },
    /// A hot key's validity exceeds the policy maximum (TRU-113, POL-066).
    #[error("a hot key's validity must not exceed {max_ms} ms")]
    HotKeyTooLong {
        /// The limit, in milliseconds.
        max_ms: u64,
    },
    /// A rotation would lower the key's assurance (TRU-113).
    #[error("a successor must not have a lower assurance than its predecessor")]
    RotationLowersAssurance,
    /// A custody issuance record is not valid text (TRU-111).
    #[error("issuance record: {0}")]
    BadIssuanceRecord(&'static str),
}

impl TrustError {
    /// The WIRE §6.8 code for this failure, where it is a wire-level one: `E_SIG` for any
    /// untrusted signer or invalid signature, `E_TAG` for a tag no authority key signs, and
    /// the decoder's own code for malformed input. `None` for refusals to issue or build.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            TrustError::Wire(e) | TrustError::BadSignature(e) => Some(e.code),
            TrustError::UntrustedTag(_) => Some(ErrorCode::Tag),
            TrustError::InvalidVersion => Some(ErrorCode::UnknownField),
            TrustError::UnknownRoot(_)
            | TrustError::ChainTooLong
            | TrustError::MissingCertificate(_)
            | TrustError::SignerMismatch
            | TrustError::WrongPurpose { .. }
            | TrustError::NotYetValid
            | TrustError::Expired
            | TrustError::Revoked { .. }
            | TrustError::BundleSigner
            | TrustError::UpdateSigner
            | TrustError::NewRootUnsigned(_)
            | TrustError::LogNotPinned(_)
            | TrustError::UntrustedEntry(_)
            | TrustError::PossessionNotProved => Some(ErrorCode::Sig),
            _ => None,
        }
    }
}
