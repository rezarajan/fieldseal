//! UniFFI bindings for platform runtimes. An interface adapter (ADR 0028): it only
//! converts types and errors; every rule lives in the context crates. Use cases are
//! exposed here as each context is implemented.

uniffi::setup_scaffolding!();

/// The version of the Fieldseal core these bindings were built from.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
