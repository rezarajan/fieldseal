//! Contract tests for adapters of the Instrument context's driven ports.

use crate::domain::ControlType;
use crate::ports::ControlCatalogue;

/// [`ControlCatalogue`]: `supports` agrees with `controls`; schema version 1 or later.
pub fn control_catalogue_contract<C: ControlCatalogue>(make: impl Fn() -> C) {
    let catalogue = make();
    assert!(
        catalogue.schema_version().major >= 1,
        "the catalogue must implement a released schema"
    );
    let listed = catalogue.controls();
    for control in ControlType::V1 {
        assert_eq!(
            catalogue.supports(control),
            listed.contains(&control),
            "supports() must agree with controls()"
        );
    }
}
