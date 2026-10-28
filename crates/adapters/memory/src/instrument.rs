//! In-memory adapters for the Instrument context's driven ports.

use fieldseal_instrument::domain::{ControlType, SchemaVersion};
use fieldseal_instrument::ports::ControlCatalogue;

/// A [`ControlCatalogue`] for headless use (the CLI's `instrument preview` and the device
/// simulator): it advertises every catalogue v1 control at schema 1.0.0.
#[derive(Default)]
pub struct FullCatalogue;

impl ControlCatalogue for FullCatalogue {
    fn schema_version(&self) -> SchemaVersion {
        SchemaVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn controls(&self) -> Vec<ControlType> {
        ControlType::V1.to_vec()
    }
}
