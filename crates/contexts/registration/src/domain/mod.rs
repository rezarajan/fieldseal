//! Entities, value objects and invariants of the Registration context
//! (`docs/reference/spec/registration.md` §2).
//!
//! - this module: accounts, devices, tokens, tenancies and their states;
//! - [`auth`]: authentication strength at the portal (REG-002, REG-002a);
//! - [`wire`]: the byte forms of tokens, requests, certificates, PoP tokens and posture
//!   reports (WIRE §5.9–§5.13), with the device-side builders;
//! - [`checks`]: pure verification rules (attestation sufficiency, runtime build
//!   acceptance, posture gaps).

use std::collections::BTreeMap;

use fieldseal_kernel::KernelError;
use fieldseal_kernel::crypto::{P256PublicKey, Signature};
use fieldseal_kernel::id::{
    CohortId, ContentAddress, Digest, Generation, KeyId, Nonce, Seq, TenancyHandle, TenancyId,
};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::words;
use fieldseal_trust::domain::{AttestationClaims, AttestationEvidence, DeviceKeyKind};

pub mod auth;
pub mod checks;
pub mod wire;

pub use auth::{AuthRecord, AuthenticatedPerson, AuthenticationMethods, MethodAssurance};

/// The identity provider's stable subject identifier for a person.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AccountId(pub String);

/// A role held by an account at the portal.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Role {
    /// Collects data on devices.
    Collector,
    /// Prepares devices and handles exceptions.
    Operator,
}

impl Role {
    /// The role's name, as identity providers and policy (`batchTokens.roles`) write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Collector => "collector",
            Role::Operator => "operator",
        }
    }

    /// Parses a role name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "collector" => Some(Role::Collector),
            "operator" => Some(Role::Operator),
            _ => None,
        }
    }
}

/// An account as the factory knows it (REG §2 `Account`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Account {
    /// The identity provider's subject.
    pub id: AccountId,
    /// The opaque collector reference written into tenancy certificates. Random, issued
    /// at the account's first registration, never derived from the subject.
    pub collector: [u8; 16],
    /// Roles last reported by the identity provider.
    pub roles: Vec<Role>,
}

/// The route a registration takes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RegistrationRoute {
    /// The device reaches the factory itself.
    Online,
    /// Every message travels as a QR code or a file.
    AirGapped,
}

impl RegistrationRoute {
    /// The wire name (`mode`, WIRE-120).
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationRoute::Online => "online",
            RegistrationRoute::AirGapped => "air-gapped",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "online" => Some(Self::Online),
            "air-gapped" => Some(Self::AirGapped),
            _ => None,
        }
    }
}

/// The secret part of a registration token: what makes it single-use.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TokenSecret([u8; 16]);

impl TokenSecret {
    /// Wraps 16 bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TokenSecret(<redacted>)")
    }
}

/// A registration token as the portal shows it and the device reads it (WIRE-120): signed
/// by the factory's registration key. Its expiry is not in the bytes; only the factory
/// evaluates it (REG-006, WIRE-124).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistrationToken {
    /// Where the device can reach the factory: an `https` URL, a hint only (ADR 0021).
    pub factory: String,
    /// SHA-256 of the root public key the device must already trust (REG-010).
    pub trust_root: Digest,
    /// The single-use secret.
    pub secret: TokenSecret,
    /// The factory nonce, used as the attestation challenge (REG-011).
    pub nonce: Nonce,
    /// The route this token was issued for.
    pub route: RegistrationRoute,
    /// When it was issued, by authority time.
    pub issued_at: AuthorityTime,
    /// The registration key that signed it.
    pub signer: KeyId,
    /// The signature over tag `fieldseal.dev/registration-token/v1`.
    pub signature: Signature,
}

/// A token as the factory stores it: bound to one account, with its expiry and uses.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssuedToken {
    /// The token handed to the collector.
    pub token: RegistrationToken,
    /// The account it is bound to (REG-003).
    pub account: AccountId,
    /// When it stops being accepted, by the factory's clock (REG-006).
    pub expires_at: AuthorityTime,
    /// How many devices it may register: 1, or more for an operator's batch token (REG-044).
    pub max_uses: u32,
    /// How the account authenticated when it was issued (REG-002a).
    pub authentication: AuthRecord,
}

impl IssuedToken {
    /// Whether this is a batch token.
    pub fn is_batch(&self) -> bool {
        self.max_uses > 1
    }
}

/// Four words, each an index into the fixed 2048-word list, derived from a request body
/// (WIRE-135, REG-020). The list is format-core data ([`fieldseal_kernel::words`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FingerprintWords([u16; 4]);

impl FingerprintWords {
    /// Size of the word list.
    pub const LIST_LEN: u16 = 2048;

    /// Wraps four indices, each below [`Self::LIST_LEN`].
    pub fn from_indices(indices: [u16; 4]) -> Result<Self, KernelError> {
        if indices.iter().any(|i| *i >= Self::LIST_LEN) {
            return Err(KernelError::Malformed { kind: "FingerprintWords", reason: "index outside the 2048-word list" });
        }
        Ok(Self(indices))
    }

    /// The words for a request-body digest: its first 44 bits as four 11-bit indices.
    pub fn from_body_digest(digest: &Digest) -> Self {
        Self(words::indices_of_digest(digest))
    }

    /// The four indices (shown beside the words, REG-023).
    pub fn indices(&self) -> [u16; 4] {
        self.0
    }

    /// The four words.
    pub fn words(&self) -> [&'static str; 4] {
        self.0.map(|i| words::word(i).expect("index below 2048"))
    }

    /// The words joined by ` · ` (WIRE-135).
    pub fn joined(&self) -> String {
        words::join(self.0)
    }
}

/// Where the nonce in a request came from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NonceSource {
    /// The factory, inside the token: proves freshness.
    Factory,
    /// The device, for keys that already existed (REG-011): flagged by policy
    /// (`registration.deviceNonceRegistrations`).
    Device,
}

impl NonceSource {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            NonceSource::Factory => "factory",
            NonceSource::Device => "device",
        }
    }
}

/// Attestation evidence for one of a tenancy's keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyEvidence {
    /// Which key it is for.
    pub kind: DeviceKeyKind,
    /// The platform evidence.
    pub evidence: AttestationEvidence,
}

/// The current key's endorsement of a key roll (REG-060): which tenancy is rolled, and the
/// current signing key's signature over the same `{nonce, body_sha256}` as the new key's
/// proof of possession.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RollProof {
    /// The tenancy whose keys are rolled.
    pub tenancy: TenancyId,
    /// The current signing key's signature.
    pub signature: Signature,
}

/// A device's request to register a tenancy, after the factory has unsealed and decoded it
/// (WIRE-130..134). The body has been checked for structure only, not yet verified.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistrationRequest {
    /// The token secret it claims.
    pub token: TokenSecret,
    /// The nonce it signed.
    pub nonce: Nonce,
    /// Where the nonce came from.
    pub nonce_source: NonceSource,
    /// The tenancy's identifier: SHA-256 of `sign_pub` (WIRE-131).
    pub tenancy: TenancyId,
    /// The signing public key.
    pub sign_pub: P256PublicKey,
    /// The agreement public key.
    pub agree_pub: P256PublicKey,
    /// Evidence for each key.
    pub evidence: Vec<KeyEvidence>,
    /// The runtime build identity.
    pub build: String,
    /// The previous tenancy's closing hash on this device, if any.
    pub prev_closing: Option<Digest>,
    /// The collector's nickname for the device, if given.
    pub label: Option<String>,
    /// SHA-256 of the canonical request body.
    pub body_digest: Digest,
    /// Proof of possession: the signing key's signature over `{nonce, body_sha256}`.
    pub proof_of_possession: Signature,
    /// Present on a key roll.
    pub roll: Option<RollProof>,
}

impl RegistrationRequest {
    /// The fingerprint words the device and the portal both show.
    pub fn fingerprint_words(&self) -> FingerprintWords {
        FingerprintWords::from_body_digest(&self.body_digest)
    }
}

/// The state of a tenancy at the factory (REG §2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TenancyState {
    /// Received, waiting for the collector to confirm the fingerprint words.
    Pending,
    /// A policy check failed with `hold`; waiting for an operator.
    Held,
    /// Refused: a policy check failed with `deny`, an operator rejected it, or it was not
    /// confirmed in time (REG-022, REG-031). Its reasons are kept for the portal.
    Rejected,
    /// Registered and eligible for bundles.
    Registered,
    /// A posture or anomaly finding; bundle releases paused (REG-081).
    Flagged,
    /// Reported lost; deny-listed above its cutoff.
    Lost,
    /// A close certificate has been issued.
    Closing,
    /// Closed.
    Closed,
    /// Retired at the end of a device's loan.
    Retired,
}

impl TenancyState {
    /// The state's name, for the portal and the status API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Registered => "registered",
            Self::Flagged => "flagged",
            Self::Lost => "lost",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Retired => "retired",
        }
    }

    /// Whether the tenancy counts towards its account's device limit (REG-041): it is
    /// registered, flagged, or held for an operator. A pending request doesn't count until
    /// it is confirmed, when the limit is checked again.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Held | Self::Registered | Self::Flagged)
    }

    /// Whether the runtime may authenticate to factory APIs as this tenancy (REG-070).
    pub fn may_call_api(self) -> bool {
        matches!(self, Self::Registered | Self::Flagged)
    }
}

/// The state of one registered key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KeyState {
    /// In use.
    Active,
    /// Replaced by a newer key; signatures made before the roll stay valid (REG-061).
    Rolled,
    /// Revoked.
    Revoked,
}

/// A key in a tenancy's history. Keys are never removed from history.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredKey {
    /// Its index in the tenancy's key history (records name keys by index, WIRE-034).
    pub index: u32,
    /// Signing or agreement.
    pub kind: DeviceKeyKind,
    /// The public key.
    pub public_key: P256PublicKey,
    /// The evidence submitted for it.
    pub evidence: AttestationEvidence,
    /// What the attestation verifier established (TRU-064).
    pub claims: Option<AttestationClaims>,
    /// Its state.
    pub state: KeyState,
}

/// A tenancy's time window (ADR 0020).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Window {
    /// Earliest authority time records are expected.
    pub not_before: AuthorityTime,
    /// Latest authority time records are expected.
    pub not_after: AuthorityTime,
    /// Milliseconds after `not_after` during which deliveries aren't flagged late.
    pub grace_ms: u64,
}

/// A cohort assigned to a tenancy, with its generation for ordering.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CohortAssignment {
    /// The cohort.
    pub cohort: CohortId,
    /// This tenancy's generation for the cohort.
    pub generation: Generation,
}

/// What a new tenancy is registered for: the collection period's record key, the window
/// and any cohorts assigned at registration. Supplied to the factory by its deployment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenancyTerms {
    /// The record key of the collection period (the certificate's `period`).
    pub record_key: KeyId,
    /// The window.
    pub window: Window,
    /// Cohorts assigned at registration (more are assigned by Distribution).
    pub cohorts: Vec<CohortAssignment>,
}

/// A device's identifier at the factory.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DeviceId(pub String);

/// A device as the factory knows it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredDevice {
    /// Its identifier.
    pub id: DeviceId,
    /// The owning account.
    pub account: AccountId,
    /// The collector's nickname for it.
    pub nickname: String,
    /// Fingerprint words of its latest registration.
    pub words: FingerprintWords,
    /// The attested hardware identity, if any (optional by policy).
    pub hardware_id: Option<String>,
    /// Its tenancies, oldest first.
    pub tenancies: Vec<TenancyId>,
}

/// A tenancy at the factory: one collector, one device, one window.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenancyRecord {
    /// Its identifier.
    pub id: TenancyId,
    /// The opaque handle used outside sealed parts of exports (random, WIRE-102).
    pub handle: TenancyHandle,
    /// The account it belongs to.
    pub account: AccountId,
    /// The device it runs on.
    pub device: DeviceId,
    /// Its state.
    pub state: TenancyState,
    /// Its keys, with history.
    pub keys: Vec<RegisteredKey>,
    /// Its window.
    pub window: Window,
    /// The collection period's record key.
    pub record_key: KeyId,
    /// Assigned cohorts.
    pub cohorts: Vec<CohortAssignment>,
    /// The deny-list or close cutoff, if set (REG-062).
    pub cutoff: Option<Seq>,
    /// The fingerprint words of its (latest) request.
    pub words: FingerprintWords,
    /// The token it was registered with.
    pub token: TokenSecret,
    /// Whether that was a batch token (confirmations are listed together, REG-044).
    pub batch: bool,
    /// When a pending request lapses unconfirmed (REG-022): the token's expiry.
    pub pending_until: AuthorityTime,
    /// Where the request's nonce came from.
    pub nonce_source: NonceSource,
    /// The runtime build it registered with.
    pub build: String,
    /// How the token's account authenticated (REG-002a: an `asserted` method is recorded).
    pub authentication: AuthRecord,
    /// Policy reasons for its current state (`hold`, `deny`, `flag`), shown on the portal.
    pub reasons: Vec<String>,
    /// The current tenancy certificate, once registered.
    pub certificate: Option<wire::TenancyCertificate>,
    /// The last time the runtime called the factory.
    pub last_seen: Option<AuthorityTime>,
}

impl TenancyRecord {
    /// Whether `next` keeps every key this record has (keys are never deleted).
    pub fn keeps_key_history(&self, next: &TenancyRecord) -> bool {
        self.keys.iter().all(|k| next.keys.iter().any(|n| n.public_key == k.public_key && n.index == k.index))
    }

    /// Whether the tenancy may receive bundles (REG-072, REG-081).
    pub fn eligible_for_release(&self) -> bool {
        self.state == TenancyState::Registered
    }

    /// The active key of `kind`.
    pub fn active_key(&self, kind: DeviceKeyKind) -> Option<&RegisteredKey> {
        self.keys.iter().rev().find(|k| k.kind == kind && k.state == KeyState::Active)
    }

    /// Whether every active key is hardware-attested (INV-10, for `bundle.release`).
    pub fn keys_attested(&self) -> bool {
        self.keys
            .iter()
            .filter(|k| k.state == KeyState::Active)
            .all(|k| k.claims.as_ref().is_some_and(AttestationClaims::is_attested))
    }
}

/// Why a tenancy is being closed by the authority.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CloseReason {
    /// The collector is absent.
    Absent,
    /// The collector forgot the runtime PIN (a reset certificate, REG-065).
    ForgottenPin,
    /// The device was returned.
    Returned,
    /// The device was reported lost.
    Lost,
    /// Any other reason, recorded by the operator.
    Other,
}

impl CloseReason {
    /// The wire name (REG §2).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::ForgottenPin => "forgotten-pin",
            Self::Returned => "returned",
            Self::Lost => "lost",
            Self::Other => "other",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Absent, Self::ForgottenPin, Self::Returned, Self::Lost, Self::Other].into_iter().find(|r| r.as_str() == text)
    }

    /// Whether the certificate is a reset certificate (WIRE-141).
    pub fn is_reset(self) -> bool {
        self == Self::ForgottenPin
    }
}

/// How a device's lock-down is managed, as reported (ADR 0031).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ManagementMode {
    /// The runtime is device owner.
    SelfManaged,
    /// An EMM is device owner.
    EmmManaged,
}

impl ManagementMode {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfManaged => "self-managed",
            Self::EmmManaged => "emm-managed",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "self-managed" => Some(Self::SelfManaged),
            "emm-managed" => Some(Self::EmmManaged),
            _ => None,
        }
    }
}

/// The state of one restriction, as a device reports it (PLAT-042).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ReportedRestriction {
    /// Read from live platform state and in force.
    InForce,
    /// Read from live platform state and not in force.
    Missing,
    /// Couldn't be read.
    Unknown,
}

impl ReportedRestriction {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InForce => "in-force",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "in-force" => Some(Self::InForce),
            "missing" => Some(Self::Missing),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Fresh evidence from a registered device (REG-080), decoded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PostureReport {
    /// The tenancy reporting.
    pub tenancy: TenancyId,
    /// The factory nonce it answers.
    pub nonce: Nonce,
    /// How the device is managed.
    pub mode: ManagementMode,
    /// Each restriction, by name, with its reported state.
    pub restrictions: BTreeMap<String, ReportedRestriction>,
    /// Fresh attestation evidence for the signing key over the nonce, if the platform can
    /// produce it; otherwise the claims stored at registration stand.
    pub evidence: Option<AttestationEvidence>,
    /// SHA-256 of the canonical report body.
    pub body_digest: Digest,
    /// The signing key's signature over `{nonce, body_sha256}`.
    pub proof_of_possession: Signature,
}

impl PostureReport {
    /// Restrictions that would flag the tenancy (REG-081): `missing` always, `unknown` when
    /// policy says to flag them, and any `required` restriction the report leaves out
    /// (treated as `unknown`).
    pub fn gaps(&self, required: &[String], flag_unknown: bool) -> Vec<String> {
        let mut out: Vec<String> = self
            .restrictions
            .iter()
            .filter(|(_, s)| match s {
                ReportedRestriction::Missing => true,
                ReportedRestriction::Unknown => flag_unknown,
                ReportedRestriction::InForce => false,
            })
            .map(|(n, _)| n.clone())
            .collect();
        if flag_unknown {
            out.extend(required.iter().filter(|r| !self.restrictions.contains_key(*r)).cloned());
        }
        out.sort();
        out.dedup();
        out
    }
}

/// A short-lived access token bound to a tenancy's signing key (REG-070, `IssueApiToken`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessToken {
    /// The bearer value (32 random bytes).
    pub value: [u8; 32],
    /// The tenancy it is bound to.
    pub tenancy: TenancyId,
    /// The signing key it is bound to.
    pub key: KeyId,
    /// When it stops being accepted.
    pub expires_at: AuthorityTime,
}

/// A content address of the policy that approved a registration (the effective policy's
/// innermost layer), recorded in the certificate.
pub fn policy_address(sources: &[ContentAddress]) -> ContentAddress {
    sources.last().copied().unwrap_or(ContentAddress::from([0; 32]))
}
