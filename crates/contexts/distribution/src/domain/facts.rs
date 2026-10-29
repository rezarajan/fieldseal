//! What a bundle needs to know about the artefacts it carries, read from their canonical
//! bytes: an instrument's schema range and the roster fields it references (DIS-012,
//! DIS-013), a layout's instrument and window class (DIS-016), a localisation's reference
//! version (DIS-017). Publishing has already validated each kind; these readers take only
//! what bundle composition depends on, and refuse anything they cannot read.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_instrument::domain::{Compatibility, SchemaRange, SchemaVersion, check_compatibility};
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{ContentAddress, Fingerprint};
use fieldseal_kernel::value::Value;
use fieldseal_publishing::domain::{Artefact, ArtefactKind};

use super::error::CompositionError;

/// What the factory knows about a tenancy's runtime from registration (DIS-012, DIS-017).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimeProfile {
    /// The instrument-schema version the runtime build implements (INS-092).
    pub instrument_schema: SchemaVersion,
    /// The reference-catalogue version of the runtime build's UI messages, which a
    /// `Localisation` artefact must name (PLAT-053). `None`: the build reported none, so no
    /// localisation is included.
    pub localisation_reference: Option<String>,
}

/// An instrument's facts for composing a bundle.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstrumentFacts {
    /// The instrument's fingerprint (its address).
    pub address: ContentAddress,
    /// The schema range it needs (INS-091).
    pub schema: SchemaRange,
    /// The roster fields it references (`roster.<field>` in rules, messages and items).
    pub roster_fields: BTreeSet<String>,
}

/// A layout's facts for composing a bundle.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LayoutFacts {
    /// The layout's address.
    pub address: ContentAddress,
    /// The fingerprint of the one instrument it is bound to (INS-200).
    pub instrument: Fingerprint,
    /// Its window class, if it declares one (INS-207).
    pub window_class: Option<String>,
}

/// The artefacts of a list of publications.
pub fn artefacts_of(publications: &[fieldseal_publishing::domain::Publication]) -> Vec<&Artefact> {
    publications.iter().map(|p| &p.artefact).collect()
}

fn decode(artefact: &Artefact, kind: ArtefactKind) -> Result<Value, CompositionError> {
    if artefact.kind() != kind {
        return Err(CompositionError::WrongKind { address: *artefact.address(), expected: kind, found: artefact.kind() });
    }
    cbor::decode(artefact.canonical_bytes()).map_err(|_| CompositionError::Unreadable { address: *artefact.address() })
}

fn spec(value: &Value) -> Option<&BTreeMap<String, Value>> {
    value.as_map()?.get("spec")?.as_map()
}

/// Reads an instrument's schema range and roster references.
pub fn instrument_facts(artefact: &Artefact) -> Result<InstrumentFacts, CompositionError> {
    let address = *artefact.address();
    let value = decode(artefact, ArtefactKind::Instrument)?;
    let schema = spec(&value)
        .and_then(|s| s.get("schema"))
        .and_then(Value::as_text)
        .and_then(|t| SchemaRange::parse(t).ok())
        .ok_or(CompositionError::Unreadable { address })?;
    let mut roster_fields = BTreeSet::new();
    collect_roster_fields(&value, &mut roster_fields);
    Ok(InstrumentFacts { address, schema, roster_fields })
}

/// Every `roster.<field>` mentioned in any text of the document: `from: roster.<field>` items,
/// `roster.<field>` in rule expressions, and `$roster.<field>` in messages (INS-013, INS-042,
/// INS-084). Reading all text keeps the set a safe over-approximation of what the instrument
/// uses, and never misses a place the format allows a reference.
pub fn collect_roster_fields(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Text(t) => scan_text(t, out),
        Value::Array(a) => a.iter().for_each(|v| collect_roster_fields(v, out)),
        Value::Map(m) => m.values().for_each(|v| collect_roster_fields(v, out)),
        _ => {}
    }
}

fn scan_text(text: &str, out: &mut BTreeSet<String>) {
    const KEY: &str = "roster.";
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let mut from = 0;
    while let Some(at) = text[from..].find(KEY) {
        let start = from + at;
        let before_ok = text[..start].chars().next_back().is_none_or(|c| !is_ident(c) && c != '.');
        let name_start = start + KEY.len();
        let name: String = text[name_start..].chars().take_while(|c| is_ident(*c)).collect();
        if before_ok && !name.is_empty() {
            out.insert(name.clone());
        }
        from = name_start + name.len();
    }
}

/// Reads a layout's instrument binding and window class.
pub fn layout_facts(artefact: &Artefact) -> Result<LayoutFacts, CompositionError> {
    let address = *artefact.address();
    let value = decode(artefact, ArtefactKind::Layout)?;
    let spec = spec(&value).ok_or(CompositionError::Unreadable { address })?;
    let instrument = match spec.get("instrument") {
        Some(Value::Bytes(b)) => Fingerprint::from_bytes(b).map_err(|_| CompositionError::Unreadable { address })?,
        _ => return Err(CompositionError::Unreadable { address }),
    };
    let window_class = match spec.get("windowClass") {
        None => None,
        Some(Value::Text(t)) => Some(t.clone()),
        Some(_) => return Err(CompositionError::Unreadable { address }),
    };
    Ok(LayoutFacts { address, instrument, window_class })
}

/// Reads a localisation's reference-catalogue version (`spec.reference`).
pub fn localisation_reference(artefact: &Artefact) -> Result<String, CompositionError> {
    let address = *artefact.address();
    let value = decode(artefact, ArtefactKind::Localisation)?;
    spec(&value)
        .and_then(|s| s.get("reference"))
        .and_then(Value::as_text)
        .map(str::to_owned)
        .ok_or(CompositionError::Unreadable { address })
}

/// Checks the pieces of a bundle against each other and the runtime (DIS-012, DIS-016,
/// DIS-017): every instrument fits the runtime's schema; every layout is bound to an
/// instrument in the bundle, at most one per window class for each; every localisation
/// names the runtime's reference version. Returns the roster fields the instruments
/// reference, which bound what a roster may carry (DIS-013).
pub fn check_composition(
    instruments: &[&Artefact],
    layouts: &[&Artefact],
    localisations: &[&Artefact],
    profile: &RuntimeProfile,
) -> Result<BTreeSet<String>, CompositionError> {
    let mut referenced = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for a in instruments {
        let facts = instrument_facts(a)?;
        if let Compatibility::Incompatible(reason) = check_compatibility(facts.schema, profile.instrument_schema) {
            return Err(CompositionError::IncompatibleSchema { address: facts.address, reason });
        }
        fingerprints.insert(Fingerprint::from(*facts.address.as_bytes()));
        referenced.extend(facts.roster_fields);
    }
    let mut classes: BTreeSet<(Fingerprint, Option<String>)> = BTreeSet::new();
    for a in layouts {
        let facts = layout_facts(a)?;
        if !fingerprints.contains(&facts.instrument) {
            return Err(CompositionError::LayoutNotBound { layout: facts.address });
        }
        if !classes.insert((facts.instrument, facts.window_class.clone())) {
            return Err(CompositionError::DuplicateLayoutClass { layout: facts.address });
        }
    }
    for a in localisations {
        let reference = localisation_reference(a)?;
        if profile.localisation_reference.as_deref() != Some(reference.as_str()) {
            return Err(CompositionError::LocalisationReference { address: *a.address() });
        }
    }
    Ok(referenced)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(t: &str) -> Value {
        Value::Text(t.to_owned())
    }

    #[test]
    fn dis_013_roster_fields_read_through_message_variables_and_roster_items_are_found() {
        let doc = Value::Map(BTreeMap::from([
            ("welcome".to_owned(), text("Questions about the household of {$roster.head_name}.")),
            ("source".to_owned(), Value::Map(BTreeMap::from([("from".to_owned(), text("roster.village_code"))]))),
            ("rule".to_owned(), Value::Array(vec![text("roster.members > 3"), text("not-roster.ignored"), text("a.roster.ignored_too")])),
        ]));
        let mut found = BTreeSet::new();
        collect_roster_fields(&doc, &mut found);
        assert_eq!(found, BTreeSet::from(["head_name".to_owned(), "members".to_owned(), "village_code".to_owned()]));
    }
}
