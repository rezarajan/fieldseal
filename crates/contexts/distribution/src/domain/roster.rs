//! Rosters (`docs/reference/spec/distribution.md` §2, DIS-013, DIS-014; WIRE-095).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::cbor;
use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::{CohortId, Generation, SubjectId};
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::value::Value;

/// A subject's consent state on a roster (ADR 0022).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConsentState {
    /// Consent is on record.
    Granted,
    /// Consent was refused: no record of any kind may be made.
    Refused,
    /// No consent on record: the collector may attest it.
    Unknown,
}

impl ConsentState {
    /// The wire name (WIRE-095).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Refused => "refused",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Granted, Self::Refused, Self::Unknown].into_iter().find(|c| c.as_str() == text)
    }
}

/// One subject on a roster.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RosterEntry {
    /// The subject's position on the roster; strictly increasing along a roster.
    pub ordinal: u32,
    /// The pseudonymous subject ID.
    pub subject: SubjectId,
    /// The text the collector sees when choosing the subject.
    pub display: String,
    /// Roster fields by name. A roster from a [`crate::ports::RosterSource`] may carry every
    /// column the source has; a roster in a bundle carries only the fields an instrument
    /// references (DIS-013).
    pub attributes: BTreeMap<String, Value>,
    /// The consent state.
    pub consent: ConsentState,
    /// Status carried over from a predecessor tenancy, if any (DIS-051).
    pub prior_status: Option<String>,
}

/// A cohort's roster at one version, for one tenancy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Roster {
    /// The cohort.
    pub cohort: CohortId,
    /// The roster version; monotonic per cohort (DIS-014).
    pub version: u64,
    /// This tenancy's generation for the cohort (DIS-014).
    pub generation: Generation,
    /// The subjects.
    pub entries: Vec<RosterEntry>,
}

/// Why a roster can't follow the one a tenancy already holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    /// It is for a different cohort.
    #[error("different cohort")]
    DifferentCohort,
    /// Its version is lower than the one held (roster versions never decrease).
    #[error("roster version {offered} is older than {held}")]
    Older {
        /// The version held.
        held: u64,
        /// The version offered.
        offered: u64,
    },
    /// Its generation is lower than the one held.
    #[error("roster generation {offered} is older than {held}")]
    OlderGeneration {
        /// The generation held.
        held: u32,
        /// The generation offered.
        offered: u32,
    },
}

impl Roster {
    /// Checks that `next` may replace `self` in a later bundle: same cohort, and neither the
    /// version nor the generation goes down.
    pub fn may_be_followed_by(&self, next: &Roster) -> Result<(), RosterError> {
        if next.cohort != self.cohort {
            return Err(RosterError::DifferentCohort);
        }
        if next.generation < self.generation {
            return Err(RosterError::OlderGeneration { held: self.generation.0, offered: next.generation.0 });
        }
        if next.generation == self.generation && next.version < self.version {
            return Err(RosterError::Older { held: self.version, offered: next.version });
        }
        Ok(())
    }

    /// The roster field names any entry carries.
    pub fn field_names(&self) -> BTreeSet<&str> {
        self.entries.iter().flat_map(|e| e.attributes.keys().map(String::as_str)).collect()
    }

    /// This roster with every attribute not in `allowed` removed (DIS-013).
    pub fn restricted_to(&self, allowed: &BTreeSet<String>) -> Roster {
        let mut r = self.clone();
        for e in &mut r.entries {
            e.attributes.retain(|k, _| allowed.contains(k));
        }
        r
    }

    /// The wire form (WIRE-095).
    pub fn to_value(&self) -> Value {
        let subjects = self
            .entries
            .iter()
            .map(|e| {
                let mut fields = vec![
                    ("ordinal", Value::Int(i128::from(e.ordinal))),
                    ("subject", Value::Bytes(e.subject.as_str().as_bytes().to_vec())),
                    ("display", Value::Text(e.display.clone())),
                    ("attributes", Value::Map(e.attributes.clone())),
                    ("consent", Value::Text(e.consent.as_str().to_owned())),
                ];
                if let Some(p) = &e.prior_status {
                    fields.push(("prior_status", Value::Text(p.clone())));
                }
                cbor::map(fields)
            })
            .collect();
        cbor::map([
            ("cohort", Value::Text(self.cohort.as_str().to_owned())),
            ("version", Value::Int(i128::from(self.version))),
            ("generation", Value::Int(i128::from(self.generation.0))),
            ("subjects", Value::Array(subjects)),
        ])
    }

    /// Canonical CBOR of the roster.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a roster is encodable")
    }

    /// Strictly reads a roster: unknown keys, repeated or unordered ordinals, repeated
    /// subjects and unknown consent states are refused.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let bad = |detail| WireError::new(ErrorCode::UnknownField, 0, detail);
        let mut f = Fields::new(value)?;
        let cohort = CohortId::new(f.text("cohort")?).map_err(|_| bad("empty cohort"))?;
        let version = f.uint("version")?;
        let generation = Generation(u32::try_from(f.uint("generation")?).map_err(|_| bad("generation out of range"))?);
        let mut entries: Vec<RosterEntry> = Vec::new();
        let mut seen = BTreeSet::new();
        for s in f.array("subjects")? {
            let mut sf = Fields::new(s)?;
            let ordinal = u32::try_from(sf.uint("ordinal")?).map_err(|_| bad("ordinal out of range"))?;
            let subject = String::from_utf8(sf.bytes("subject")?).map_err(|_| bad("subject is not UTF-8"))?;
            let subject = SubjectId::new(subject).map_err(|_| bad("empty subject"))?;
            let display = sf.text("display")?;
            let attributes = match sf.take("attributes")? {
                Value::Map(m) => m,
                _ => return Err(bad("attributes is not a map")),
            };
            let consent = ConsentState::parse(&sf.text("consent")?).ok_or_else(|| bad("unknown consent state"))?;
            let prior_status = match sf.take_opt("prior_status") {
                None => None,
                Some(Value::Text(t)) => Some(t),
                Some(_) => return Err(bad("prior_status is not text")),
            };
            sf.finish()?;
            if entries.last().is_some_and(|l| l.ordinal >= ordinal) {
                return Err(bad("ordinals are not strictly increasing"));
            }
            if !seen.insert(subject.clone()) {
                return Err(bad("a subject appears twice"));
            }
            entries.push(RosterEntry { ordinal, subject, display, attributes, consent, prior_status });
        }
        f.finish()?;
        Ok(Self { cohort, version, generation, entries })
    }
}
