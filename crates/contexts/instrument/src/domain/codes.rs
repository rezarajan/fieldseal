//! Code lists, codes and the vocabulary shared with them: concepts, nonresponse and media
//! references (INS-131–INS-143, INS-170, INS-180–INS-183).

use std::collections::BTreeMap;

use fieldseal_kernel::Decimal;

use super::language::LanguageTag;
use super::text::LocalisedText;

/// A code in an external terminology (INS-170). Carried into the data contract; never
/// changes validation, rendering or records (INS-171).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Concept {
    /// The terminology's URI, for example `http://loinc.org`.
    pub system: String,
    /// The code in that terminology.
    pub code: String,
    /// The terminology's display text, if given.
    pub display: Option<String>,
}

/// A reference to embedded media (INS-180, INS-086): one id, or one id per language.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MediaRef {
    /// The same media in every language.
    Same(String),
    /// Media that varies by language, for example images containing words.
    PerLanguage(BTreeMap<LanguageTag, String>),
}

impl MediaRef {
    /// Every media id referenced.
    pub fn ids(&self) -> Vec<&str> {
        match self {
            MediaRef::Same(id) => vec![id.as_str()],
            MediaRef::PerLanguage(m) => m.values().map(String::as_str).collect(),
        }
    }
}

/// One code of a code list (INS-131).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Code {
    /// The stable code recorded (INS-136).
    pub code: String,
    /// Its label.
    pub label: LocalisedText,
    /// A longer description, also an instance's description in a repeat (INS-127).
    pub description: Option<LocalisedText>,
    /// Its numeric meaning for analysis (INS-132).
    pub value: Option<Decimal>,
    /// Whether selecting it deselects every other code (INS-133).
    pub exclusive: bool,
    /// Embedded media.
    pub media: Option<MediaRef>,
    /// A single emoji shown as an icon (INS-183).
    pub icon: Option<String>,
    /// External terminology codes (INS-170).
    pub concept: Vec<Concept>,
}

/// A code list's "other, specify" code (INS-134).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OtherCode {
    /// The code that asks for text; it is also one of the list's codes.
    pub code: String,
    /// The label of the text answer.
    pub label: LocalisedText,
    /// The longest text accepted, in characters.
    pub max_length: u32,
}

/// A named, reusable list of codes (INS-131), or the inline options of one control.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CodeList {
    /// Whether the codes have an order (required for a `scale`, INS-135).
    pub ordered: bool,
    /// The codes, in order.
    pub codes: Vec<Code>,
    /// The "other, specify" code, if any.
    pub other: Option<OtherCode>,
}

impl CodeList {
    /// The code `code`, if present.
    pub fn code(&self, code: &str) -> Option<&Code> {
        self.codes.iter().find(|c| c.code == code)
    }

    /// Whether `code` is one of the list's codes.
    pub fn contains(&self, code: &str) -> bool {
        self.code(code).is_some()
    }

    /// The "other" code, if the list declares one.
    pub fn other_code(&self) -> Option<&str> {
        self.other.as_ref().map(|o| o.code.as_str())
    }
}

/// A nonresponse a collector may enter (INS-140). `not-applicable` is derived, never
/// entered (INS-142), so it is not a variant.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Nonresponse {
    /// The subject doesn't know.
    DontKnow,
    /// The subject refused to answer.
    Refused,
}

impl Nonresponse {
    /// The code as recorded in `{"nr": …}` (WIRE-052).
    pub fn code(self) -> &'static str {
        match self {
            Nonresponse::DontKnow => "dont-know",
            Nonresponse::Refused => "refused",
        }
    }

    /// The nonresponse for a recorded code.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "dont-know" => Some(Nonresponse::DontKnow),
            "refused" => Some(Nonresponse::Refused),
            _ => None,
        }
    }
}
