//! Driven ports owned by the Instrument context (`docs/reference/spec/instrument.md` §4).
//!
//! Canonical encoding and hashing are format-core functions (issue #42), not ports.

use crate::domain::{ControlPresentation, ControlType, LanguageTag, SchemaVersion};

/// The controls and languages a runtime can render, and the schema version it implements.
///
/// Contract: never advertises a control or language it can't render under the interaction
/// rules; `supports` agrees with `controls`.
pub trait ControlCatalogue {
    /// The instrument-schema version the runtime implements.
    fn schema_version(&self) -> SchemaVersion;

    /// The control types it renders.
    fn controls(&self) -> Vec<ControlType>;

    /// Whether it renders `control`.
    fn supports(&self, control: ControlType) -> bool {
        self.controls().contains(&control)
    }

    /// The presentations it renders (INS-025). The default is every catalogue v1
    /// presentation of each control in [`controls`](Self::controls).
    fn presentations(&self) -> Vec<ControlPresentation> {
        let controls = self.controls();
        ControlPresentation::V1.into_iter().filter(|p| controls.contains(&p.control_type())).collect()
    }

    /// Whether it renders `presentation` (a control whose type it does not support renders
    /// no presentation of it).
    fn supports_presentation(&self, presentation: ControlPresentation) -> bool {
        self.presentations().contains(&presentation)
    }

    /// Whether it can render text in `language`: its script, a font and its direction
    /// (INS-089). The default claims every language, which suits headless catalogues only;
    /// a platform catalogue must override it.
    fn renders_language(&self, language: &LanguageTag) -> bool {
        let _ = language;
        true
    }
}
