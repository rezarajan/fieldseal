//! UniFFI bindings for platform runtimes. An interface adapter (ADR 0028): it only
//! converts types and errors; every rule lives in the context crates. Use cases are
//! exposed here as each context is implemented.

uniffi::setup_scaffolding!();

/// The version of the Fieldseal core these bindings were built from.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// What a native runtime reports about itself in its registration request (WIRE-130).
#[derive(uniffi::Record)]
pub struct RuntimeProfile {
    /// The instrument-schema version the core implements, as `major.minor.patch`.
    pub instrument_schema: String,
    /// The UI reference-catalogue version of the app build. The core has none; the native app
    /// puts its own here when its build has one.
    pub catalogue_reference: Option<String>,
}

/// The profile of the core these bindings were built from, for the registration request the
/// native app builds. The app fills `catalogue_reference` from its own catalogue.
#[uniffi::export]
pub fn runtime_profile() -> RuntimeProfile {
    RuntimeProfile {
        instrument_schema: fieldseal_instrument::domain::IMPLEMENTED_SCHEMA.to_string(),
        catalogue_reference: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // covers: WIRE-130
    #[test]
    fn the_runtime_profile_names_the_schema_the_core_implements() {
        let profile = runtime_profile();
        assert_eq!(profile.instrument_schema, "1.0.0");
        assert_eq!(profile.catalogue_reference, None);
    }
}
