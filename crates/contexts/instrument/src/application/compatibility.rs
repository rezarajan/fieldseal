//! `CheckCompatibility` (INS-025, INS-089, INS-092).

use crate::domain::{Compatibility, ControlPresentation, ControlType, Instrument, LanguageTag, SchemaRange, check_compatibility};
use crate::ports::ControlCatalogue;

/// Whether this runtime can open an instrument needing `required` (INS-092).
pub fn check_against_catalogue(catalogue: &dyn ControlCatalogue, required: SchemaRange) -> Compatibility {
    check_compatibility(required, catalogue.schema_version())
}

/// The full compatibility of one instrument with one runtime.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompatibilityReport {
    /// The schema-range check (INS-092).
    pub schema: Compatibility,
    /// Control types the instrument uses that the runtime doesn't render (INS-025).
    pub unsupported_controls: Vec<ControlType>,
    /// Fixed presentations the instrument uses that the runtime doesn't render (INS-025).
    pub unsupported_presentations: Vec<ControlPresentation>,
    /// Each declared language and whether the runtime can render it (INS-089).
    pub languages: Vec<(LanguageTag, bool)>,
}

impl CompatibilityReport {
    /// Compatible: the schema matches, every control is supported, and at least one
    /// declared language can be rendered (INS-089).
    pub fn is_compatible(&self) -> bool {
        self.schema == Compatibility::Compatible && self.unsupported_controls.is_empty() && self.unsupported_presentations.is_empty() && self.languages.iter().any(|(_, ok)| *ok)
    }

    /// The languages a runtime may offer (INS-089).
    pub fn offered_languages(&self) -> Vec<&LanguageTag> {
        self.languages.iter().filter(|(_, ok)| *ok).map(|(l, _)| l).collect()
    }
}

/// `CheckCompatibility` for a validated instrument.
pub fn check_instrument(catalogue: &dyn ControlCatalogue, instrument: &Instrument) -> CompatibilityReport {
    let mut used: Vec<ControlType> = instrument
        .compiled()
        .questions()
        .filter_map(|(_, q)| q.control.as_ref().map(|c| c.control_type()))
        .collect();
    if !matches!(instrument.definition().consent, crate::domain::metadata::ConsentRequirement::NotRequired) {
        used.push(ControlType::ConsentAttestation);
    }
    used.sort();
    used.dedup();
    let mut presentations: Vec<ControlPresentation> =
        instrument.compiled().questions().filter_map(|(_, q)| q.control.as_ref().and_then(|c| c.presentation())).collect();
    presentations.sort();
    presentations.dedup();
    CompatibilityReport {
        schema: check_against_catalogue(catalogue, instrument.definition().schema),
        unsupported_controls: used.into_iter().filter(|c| !catalogue.supports(*c)).collect(),
        unsupported_presentations: presentations.into_iter().filter(|p| !catalogue.supports_presentation(*p)).collect(),
        languages: instrument.definition().languages.languages.iter().map(|l| (l.clone(), catalogue.renders_language(l))).collect(),
    }
}
