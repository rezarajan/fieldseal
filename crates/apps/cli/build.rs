//! Embeds the example surveys and scenarios for `device simulate` and the conformance suite.
//!
//! The survey folders are read through the resolver's own tree walk, so the shape of a survey
//! folder is written in one place. The generated table holds (survey, file role, name, bytes):
//! role `instrument`, `layout` (name is the window class) or `catalogue` (name is the language).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::survey::SurveyTree;

fn main() {
    let examples = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets the manifest directory")).join("../../../examples");
    let surveys = examples.join("surveys");
    println!("cargo:rerun-if-changed={}", examples.display());

    let mut out = String::from("/// Each file of each example survey: (survey, role, name, bytes).\nstatic SURVEY_FILES: &[(&str, &str, &str, &[u8])] = &[\n");
    let tree = SurveyTree::open(&surveys).unwrap_or_else(|e| panic!("{e}"));
    for name in tree.names() {
        let survey = tree.survey(name).unwrap_or_else(|e| panic!("{e}"));
        let mut row = |role: &str, file_name: &str, path: &Path| {
            writeln!(out, "    ({name:?}, {role:?}, {file_name:?}, include_bytes!({:?})),", path.display().to_string()).expect("writes to a string");
        };
        row("instrument", "", &survey.instrument);
        for l in &survey.layouts {
            row("layout", &l.window, &l.path);
        }
        for c in &survey.catalogues {
            row("catalogue", &c.language, &c.path);
        }
    }
    out.push_str("];\n\n/// Each scenario: (name, text).\nstatic SCENARIO_FILES: &[(&str, &str)] = &[\n");
    let mut scenarios: Vec<PathBuf> = std::fs::read_dir(examples.join("scenarios")).expect("examples/scenarios").map(|e| e.expect("entry").path()).filter(|p| p.extension().is_some_and(|e| e == "yaml")).collect();
    scenarios.sort();
    for path in scenarios {
        let stem = path.file_stem().and_then(|s| s.to_str()).expect("a scenario name");
        writeln!(out, "    ({stem:?}, include_str!({:?})),", path.display().to_string()).expect("writes to a string");
    }
    out.push_str("];\n");
    std::fs::write(PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets the output directory")).join("embedded_surveys.rs"), out).expect("writes the table");
}
