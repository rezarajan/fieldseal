//! Descriptive metadata, languages, consent, media, tables, derived values and atomic groups
//! (INS §5.7, §5.9, §5.11, §5.19, INS-031, INS-043, INS-045).

use std::collections::BTreeMap;

use super::element::DataSpec;
use super::language::LanguageTag;
use super::rules::Val;
use super::text::{LocalisedText, NameText};

/// Who answers (INS-110).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Administration {
    /// A collector asks and records.
    Interviewer,
    /// The subject answers on the device.
    SelfAdministered,
    /// Either.
    Both,
}

/// A copyright notice and licence (INS-112).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Copyright {
    /// The notice.
    pub notice: NameText,
    /// The licence identifier, SPDX where one exists.
    pub licence: String,
}

/// A source instrument this one derives from (INS-112).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Derivation {
    /// The source's title.
    pub title: String,
    /// The source's version.
    pub version: Option<String>,
    /// How to cite it.
    pub citation: String,
    /// Where to find it.
    pub url: Option<String>,
}

/// Descriptive metadata (INS-110–INS-113).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstrumentMetadata {
    /// The title.
    pub title: LocalisedText,
    /// A description.
    pub description: Option<LocalisedText>,
    /// Its purpose.
    pub purpose: Option<LocalisedText>,
    /// The authority's name as subjects should see it.
    pub publisher: Option<NameText>,
    /// Copyright notice and licence.
    pub copyright: Option<Copyright>,
    /// Sources it derives from.
    pub derived_from: Vec<Derivation>,
    /// Who answers.
    pub administration: Administration,
}

/// How a language was translated (INS-083).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TranslationMethod {
    /// By people.
    Human,
    /// Machine-assisted, then reviewed.
    MachineAssisted,
}

/// A translation declaration (INS-083).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Translation {
    /// How it was made.
    pub method: TranslationMethod,
    /// How many people reviewed it.
    pub reviewed_by: u32,
    /// Notes.
    pub notes: Option<String>,
}

/// The instrument's languages (INS-080, INS-083).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Languages {
    /// Every declared language, in document order.
    pub languages: Vec<LanguageTag>,
    /// The default language.
    pub default: LanguageTag,
    /// Translation declarations of every non-default language.
    pub translations: BTreeMap<LanguageTag, Translation>,
}

/// Whether consent evidence may or must be captured (INS-061).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EvidencePolicy {
    /// None.
    None,
    /// Optional.
    Optional,
    /// Required.
    Required,
}

/// A consent basis a collector may attest (INS-061).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsentBasis {
    /// The code recorded.
    pub code: String,
    /// Its label.
    pub label: LocalisedText,
}

/// The versioned consent statement (INS-061).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsentStatement {
    /// Its version.
    pub version: u32,
    /// Its text.
    pub text: LocalisedText,
}

/// The consent requirement (INS-060–INS-062).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConsentRequirement {
    /// No consent step; records reference `consent_basis: not-required`.
    NotRequired,
    /// Consent is required.
    Required {
        /// The bases a collector may attest.
        bases: Vec<ConsentBasis>,
        /// The statement.
        statement: ConsentStatement,
        /// Whether evidence may or must be captured.
        evidence: EvidencePolicy,
    },
}

impl ConsentRequirement {
    /// Whether evidence may be captured (so `photo-evidence` may be used).
    pub fn allows_evidence(&self) -> bool {
        matches!(self, ConsentRequirement::Required { evidence: EvidencePolicy::Optional | EvidencePolicy::Required, .. })
    }
}

/// An embedded image (INS-180).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MediaAsset {
    /// `image/png`, `image/webp` or `image/svg+xml`.
    pub media_type: String,
    /// The SHA-256 of `bytes`, lowercase hex.
    pub sha256: String,
    /// The image.
    pub bytes: Vec<u8>,
    /// Alternative text (INS-181).
    pub alt: LocalisedText,
}

/// A lookup table (INS-043): `rows: [{key, value}]` with unique keys of one type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LookupTable {
    /// The rows, in document order.
    pub rows: Vec<(Val, Val)>,
}

impl LookupTable {
    /// The value for `key`, if present. Numeric keys match numerically.
    pub fn get(&self, key: &Val) -> Option<&Val> {
        self.rows.iter().find(|(k, _)| match (k, key) {
            (Val::Num(a), Val::Num(b)) => a == b,
            (a, b) => a == b,
        }).map(|(_, v)| v)
    }
}

/// A derived value's declaration (INS-045).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DerivedDef {
    /// Its item path.
    pub path: String,
    /// Its label.
    pub label: LocalisedText,
    /// Its data specification.
    pub data: DataSpec,
    /// Whether it is written to records.
    pub record: bool,
    /// Where it is in the document.
    pub doc_path: String,
}

/// A declared atomic group (INS-031).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AtomicGroup {
    /// Its id.
    pub id: String,
    /// The item paths written together.
    pub paths: Vec<String>,
}
