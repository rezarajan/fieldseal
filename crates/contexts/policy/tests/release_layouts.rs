//! `factory.release.layouts` (POL-068): which layouts a bundle carries.

use fieldseal_policy::domain::{Controls, LayoutAssignment, decode_document, describe, has_errors, merge_layers};
use fieldseal_policy::fixtures::{DocBuilder, text};

const PATH: &str = "factory.release.layouts";

fn decoded(builder: DocBuilder) -> fieldseal_policy::domain::Decoded {
    decode_document(&builder.build())
}

fn deployment(value: Option<&str>) -> fieldseal_policy::domain::PolicyDocument {
    let mut b = DocBuilder::deployment("authority-baseline", "1.0.0");
    if let Some(v) = value {
        b = b.set(PATH, text(v));
    }
    decoded(b).document.expect("a valid deployment document")
}

#[test]
fn pol_068_the_default_is_bound() {
    assert_eq!(Controls::defaults().factory().release_layouts, LayoutAssignment::Bound);
    let (controls, findings) = merge_layers(&[&deployment(None)]);
    assert!(!has_errors(&findings));
    assert_eq!(controls.factory().release_layouts, LayoutAssignment::Bound);
}

#[test]
fn pol_068_none_is_accepted() {
    let (controls, findings) = merge_layers(&[&deployment(Some("none"))]);
    assert!(!has_errors(&findings), "{findings:?}");
    assert_eq!(controls.factory().release_layouts, LayoutAssignment::None);
}

#[test]
fn pol_068_an_unknown_value_is_refused() {
    let decoded = decoded(DocBuilder::deployment("authority-baseline", "1.0.0").set(PATH, text("all")));
    assert!(has_errors(&decoded.findings), "{:?}", decoded.findings);
    assert!(decoded.document.is_none());
}

#[test]
fn pol_068_a_tighter_layer_can_set_none_but_a_looser_layer_cannot_restore_bound() {
    let programme = |value| decoded(DocBuilder::programme("programme-2026", "1.0.0", "wash").set(PATH, text(value))).document.expect("a valid programme document");
    let (controls, findings) = merge_layers(&[&deployment(None), &programme("none")]);
    assert!(!has_errors(&findings), "{findings:?}");
    assert_eq!(controls.factory().release_layouts, LayoutAssignment::None);

    let (_, findings) = merge_layers(&[&deployment(Some("none")), &programme("bound")]);
    assert!(has_errors(&findings), "a later layer must not loosen `none` to `bound`");
    assert!(findings.iter().any(|f| f.requirement == "POL-021" && f.path == PATH), "{findings:?}");
}

#[test]
fn pol_068_the_typed_section_exposes_the_layout_choice() {
    for (written, expected) in [("bound", LayoutAssignment::Bound), ("none", LayoutAssignment::None)] {
        let (controls, _) = merge_layers(&[&deployment(Some(written))]);
        assert_eq!(controls.factory().release_layouts, expected);
        assert_eq!(expected.as_str(), written);
        assert_eq!(LayoutAssignment::parse(written), Some(expected));
    }
    assert_eq!(LayoutAssignment::NAMES, ["bound", "none"]);
}

/// The defaults snapshot (`tests/vectors/defaults.json`): every control with a default, as the
/// schema fills it in. A change to any of them is a change of policy meaning, so it needs a
/// deliberate edit of the snapshot, as this row had.
#[test]
fn pol_068_the_other_control_defaults_are_unchanged() {
    let snapshot: serde_json::Value = serde_json::from_str(include_str!("vectors/defaults.json")).expect("defaults.json");
    let expected = snapshot["controls"].as_object().expect("controls");
    let defaults = Controls::defaults();
    let actual: std::collections::BTreeMap<&str, String> = defaults.iter().map(|(path, value)| (path.as_str(), describe(value))).collect();
    assert_eq!(actual.len(), expected.len(), "the set of controls with a default changed");
    for (path, value) in expected {
        assert_eq!(actual.get(path.as_str()), value.as_str().map(str::to_owned).as_ref(), "the default of {path} changed");
    }
    assert_eq!(expected["factory.release.layouts"], "bound");
}
