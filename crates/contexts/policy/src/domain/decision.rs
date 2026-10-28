//! Decision points, decisions and the records written to the decision log (POL §6.2,
//! POL-033, POL-034, POL-040, POL-041).
//!
//! # Input facts
//!
//! A decision point is evaluated against a [`Facts`] map. The names and meanings below are the
//! vocabulary every [`PolicyEngine`](crate::ports::PolicyEngine) adapter must understand. A
//! missing or mistyped required fact is an engine error, which the caller turns into `hold` or
//! `flag` (POL-034), never `allow`. Durations are given in whole seconds, sizes in bytes.
//!
//! | Point | Facts |
//! |---|---|
//! | `registration.token.issue` | `batch` bool, `airGapped` bool, `requestedTtlSeconds` int, `role` text, `phishingResistantAuth` bool |
//! | `registration.approve` | `fingerprintConfirmed` bool, `serialStatus` text (`matched`, `unmatched`, `absent`), `nonceOnly` bool |
//! | `device.add` | `activeDevices` int |
//! | `key.roll` | `postureOk` bool |
//! | `bundle.release` | `tenancyRegistered` bool, `containsRoster` bool, `keyAttested` bool, `unattestedAllowed` bool, `activeTenanciesInCohort` int, `paused` bool |
//! | `posture.recheck` | `verifiedBoot` bool, `bootloaderLocked` bool, `securityLevel` text, `osPatchLevel` text (date), `unknownRestriction` bool |
//! | `artefact.publish` | `kind` text, `approvals` int, `authorIsApprover` bool, `publisherSignatures` int, `builder` text, `source` text, `inclusionProof` bool, `witnessCosignatures` int |
//! | `intake.accept` | `sizeBytes` int, `qualityFailures` int |
//! | `consent.decide` | `hasEvidence` bool, `heuristicHits` list of text, `sampleDraw` decimal in [0, 1) |
//! | `tenancy.late` | `lateSeconds` int, `provablyLate` bool, `fastRunning` bool |
//!
//! `sampleDraw` is supplied by the caller because policy evaluation draws no randomness
//! (POL-032).

use std::collections::BTreeMap;

use fieldseal_kernel::id::{ContentAddress, Digest, RecordId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use sha2::{Digest as _, Sha256};

/// The named places where a context asks for a decision (POL §6.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum DecisionPoint {
    /// `registration.token.issue`
    RegistrationTokenIssue,
    /// `registration.approve`
    RegistrationApprove,
    /// `device.add`
    DeviceAdd,
    /// `key.roll`
    KeyRoll,
    /// `bundle.release`
    BundleRelease,
    /// `posture.recheck`
    PostureRecheck,
    /// `artefact.publish`
    ArtefactPublish,
    /// `intake.accept`
    IntakeAccept,
    /// `consent.decide`
    ConsentDecide,
    /// `tenancy.late`
    TenancyLate,
    /// `key.issue` (TRU-108, POL-067)
    KeyIssue,
}

impl DecisionPoint {
    /// Every decision point.
    pub const ALL: [DecisionPoint; 11] = [
        Self::RegistrationTokenIssue,
        Self::RegistrationApprove,
        Self::DeviceAdd,
        Self::KeyRoll,
        Self::BundleRelease,
        Self::PostureRecheck,
        Self::ArtefactPublish,
        Self::IntakeAccept,
        Self::ConsentDecide,
        Self::TenancyLate,
        Self::KeyIssue,
    ];

    /// The decision point's name as written in policy files.
    pub fn name(self) -> &'static str {
        match self {
            Self::RegistrationTokenIssue => "registration.token.issue",
            Self::RegistrationApprove => "registration.approve",
            Self::DeviceAdd => "device.add",
            Self::KeyRoll => "key.roll",
            Self::BundleRelease => "bundle.release",
            Self::PostureRecheck => "posture.recheck",
            Self::ArtefactPublish => "artefact.publish",
            Self::IntakeAccept => "intake.accept",
            Self::ConsentDecide => "consent.decide",
            Self::TenancyLate => "tenancy.late",
            Self::KeyIssue => "key.issue",
        }
    }

    /// The decision point written as `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// What to decide when the engine fails or times out (POL-034): `Flag` for decisions on
    /// data that has already been collected (`intake.accept`, `consent.decide`,
    /// `tenancy.late`), `Hold` for every decision that releases anything. Never `Allow`.
    pub fn failure_verdict(self) -> Verdict {
        match self {
            Self::IntakeAccept | Self::ConsentDecide | Self::TenancyLate => Verdict::Flag,
            _ => Verdict::Hold,
        }
    }
}

/// The outcome of a decision (POL-033).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Verdict {
    /// Go ahead.
    Allow,
    /// Refuse.
    Deny,
    /// Wait for a person to decide.
    Hold,
    /// Go ahead, but mark for review.
    Flag,
}

impl Verdict {
    /// The outcome's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Hold => "hold",
            Self::Flag => "flag",
        }
    }
}

/// Something the caller must do alongside the outcome (POL-033).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Obligation {
    /// Sample this item for review.
    SampleForReview,
    /// Pause bundle release to the device.
    PauseRelease,
    /// Set the submission aside.
    Quarantine,
}

/// Input facts for one decision, by name.
pub type Facts = BTreeMap<String, Value>;

/// One evaluation's outcome. Every decision names the policy that produced it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decision {
    /// Where the decision was made.
    pub point: DecisionPoint,
    /// The outcome.
    pub verdict: Verdict,
    /// Machine-readable reasons (kebab-case codes), required for every outcome other than `Allow`.
    pub reasons: Vec<String>,
    /// What the caller must do alongside.
    pub obligations: Vec<Obligation>,
    /// The content addresses of the effective policy's layers (POL-023).
    pub policy: Vec<ContentAddress>,
}

/// What a decision is about. Opaque identifiers only (POL-041).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Subject {
    /// A tenancy.
    Tenancy(TenancyId),
    /// A registration, by its identifier.
    Registration(String),
    /// A record.
    Record(RecordId),
}

/// An entry in the decision log (POL-040). It holds no personal data: inputs are referenced by
/// hash and the subject by identifier (POL-041).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecisionRecord {
    /// The decision: point, outcome, reasons, obligations and the policy's layer addresses.
    pub decision: Decision,
    /// SHA-256 of the input facts.
    pub input_digest: Digest,
    /// The subject of the decision.
    pub subject: Subject,
    /// Authority time of the decision.
    pub at: AuthorityTime,
    /// The log index of the held decision this one resolves (POL-042).
    pub resolves: Option<u64>,
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

fn encode_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(i) => {
            out.push(b'I');
            out.extend_from_slice(&i.to_be_bytes());
        }
        Value::Decimal(d) => {
            out.push(b'D');
            out.extend_from_slice(&d.mantissa.to_be_bytes());
            out.extend_from_slice(&d.exponent.to_be_bytes());
        }
        Value::Bytes(b) => {
            out.push(b'B');
            put_len(out, b.len());
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            out.push(b'T');
            put_len(out, t.len());
            out.extend_from_slice(t.as_bytes());
        }
        Value::Bool(b) => out.push(if *b { b't' } else { b'f' }),
        Value::Array(items) => {
            out.push(b'A');
            put_len(out, items.len());
            for item in items {
                encode_value(item, out);
            }
        }
        Value::Map(entries) => {
            out.push(b'M');
            put_len(out, entries.len());
            for (key, item) in entries {
                put_len(out, key.len());
                out.extend_from_slice(key.as_bytes());
                encode_value(item, out);
            }
        }
    }
}

/// The SHA-256 of the input facts for a decision at `point` (POL-040): a length-prefixed,
/// key-sorted encoding under a domain-separation prefix, so equal facts at the same point
/// always hash alike and facts at different points never collide.
pub fn facts_digest(point: DecisionPoint, facts: &Facts) -> Digest {
    let mut bytes = b"fieldseal.policy.facts.v1\0".to_vec();
    put_len(&mut bytes, point.name().len());
    bytes.extend_from_slice(point.name().as_bytes());
    encode_value(&Value::Map(facts.clone()), &mut bytes);
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    Digest::from(hash)
}
