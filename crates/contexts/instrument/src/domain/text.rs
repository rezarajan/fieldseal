//! Localised text (INS-080–INS-086).

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_kernel::Value;

use super::language::LanguageTag;

/// A map of language tag to text (INS-080). In a validated instrument every text has every
/// declared language (INS-082), is plain text (INS-085), and uses the same message variables
/// in every language (INS-084).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct LocalisedText {
    texts: BTreeMap<LanguageTag, String>,
    variables: BTreeSet<String>,
}

impl LocalisedText {
    /// Builds a text from checked parts; validation does the checking.
    pub(crate) fn from_parts(texts: BTreeMap<LanguageTag, String>, variables: BTreeSet<String>) -> Self {
        Self { texts, variables }
    }

    /// The text in `language`, if present.
    pub fn get(&self, language: &LanguageTag) -> Option<&str> {
        self.texts.get(language).map(String::as_str)
    }

    /// The text in the language whose tag is `tag`.
    pub fn get_str(&self, tag: &str) -> Option<&str> {
        self.texts.iter().find(|(k, _)| k.as_str() == tag).map(|(_, v)| v.as_str())
    }

    /// Every language and text, ordered by tag.
    pub fn iter(&self) -> impl Iterator<Item = (&LanguageTag, &str)> {
        self.texts.iter().map(|(k, v)| (k, v.as_str()))
    }

    /// The message variables the text references (`roster.<field>` or item paths).
    pub fn variables(&self) -> &BTreeSet<String> {
        &self.variables
    }

    /// The text as authored: a map of language tag to text.
    pub fn to_value(&self) -> Value {
        Value::Map(self.texts.iter().map(|(k, v)| (k.as_str().to_owned(), Value::Text(v.clone()))).collect())
    }
}

/// Text that is either a single plain string (a proper name, a licence notice) or a
/// [`LocalisedText`]. Used only where the specification's own example writes plain strings
/// (`publisher`, `copyright.notice`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NameText {
    /// The same in every language.
    Plain(String),
    /// Translated.
    Localised(LocalisedText),
}
