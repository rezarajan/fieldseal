//! WEB-120: the page the server draws is byte-for-byte what `fieldseal instrument preview
//! --format html` prints, built here from the library functions the CLI calls and not through
//! the app's workbench.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::survey::SurveyTree;
use fieldseal_adapters_html::{Page, render_html};
use fieldseal_instrument::application::{
    LayoutBinding, LayoutOptions, PlanLayout, PlanRequest, ValidationOptions, compile_render_plan, select_layout, validate_instrument_with, validate_layout_with,
};
use fieldseal_instrument::domain::{InstrumentReference, Layout, WindowClass};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{ContentAddress, Fingerprint};
use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
}


/// What `fieldseal instrument preview <instrument> [--layout <file>]... --lang --window` prints.
fn cli_html(instrument: &Path, layout_files: &[PathBuf], lang: &str, window: WindowClass) -> String {
    let doc = fieldseal_adapters_authoring::decode_path(instrument).unwrap();
    let digest = |b: &[u8]| *sha256(b).as_bytes();
    let validated = validate_instrument_with(&doc, ValidationOptions { media_digest: Some(&digest) }).unwrap();
    let canonical = fieldseal_kernel::cbor::encode(&validated.instrument.to_value()).unwrap();
    let identity = Fingerprint::from(*ContentAddress::of(&canonical).as_bytes());
    let mut layouts: Vec<(Layout, ContentAddress)> = Vec::new();
    for path in layout_files {
        let ldoc = fieldseal_adapters_authoring::decode_path(path).unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        let resolve = |r: &InstrumentReference| -> Option<Fingerprint> {
            let InstrumentReference::Source(source) = r else { return None };
            let file = dir.join(source);
            // Resolved as the CLI does: the reference must name this instrument's file.
            (file.canonicalize().ok()? == instrument.canonicalize().ok()?).then_some(identity)
        };
        let binding = LayoutBinding { expected: identity, resolve: &resolve };
        let layout = validate_layout_with(&ldoc, &validated.instrument, LayoutOptions { binding: Some(binding) }).unwrap();
        let bytes = fieldseal_kernel::cbor::encode(&layout.to_value()).unwrap();
        layouts.push((layout, ContentAddress::of(&bytes)));
    }
    let refs: Vec<&Layout> = layouts.iter().map(|(l, _)| l).collect();
    let plan_layout = match select_layout(&refs, window) {
        Some(l) => {
            let address = layouts.iter().find(|(x, _)| std::ptr::eq(x, l)).map(|(_, a)| *a).unwrap();
            PlanLayout::Layout { layout: l, address }
        }
        None => PlanLayout::Default,
    };
    let plan = compile_render_plan(&validated.instrument, plan_layout, PlanRequest { languages: &[lang], window_class: window }).unwrap();
    let empty = BTreeMap::new();
    render_html(&Page { plan: &plan, instrument: &validated.instrument, visibility: None, values: &empty, roster: &empty, fingerprint: None })
}

#[test]
fn web_120_instrument_page_matches_preview() {
    let state = AppState { examples_dir: examples(), ..AppState::default() };
    let mut compared = 0;
    for stem in ["school-meals-baseline", "household-water-access"] {
        let survey = SurveyTree::open(&examples().join("surveys")).unwrap().survey(stem).unwrap();
        let instrument = survey.instrument.clone();
        let layout_files: Vec<PathBuf> = survey.layouts.iter().map(|l| l.path.clone()).collect();
        assert!(!layout_files.is_empty());
        let languages: Vec<String> = {
            let page = dispatch(&state, &Request::get(&format!("/instruments/{stem}"))).body_text();
            let start = page.find("name=\"lang\"").unwrap();
            let select = &page[start..page[start..].find("</select>").unwrap() + start];
            select.split("value=\"").skip(1).map(|s| s.split('"').next().unwrap().to_owned()).collect()
        };
        assert!(!languages.is_empty());
        // The layout selections: all (by window class), the default layout, each one alone.
        let mut selections: Vec<(Option<String>, Vec<PathBuf>)> = vec![(None, layout_files.clone()), (Some("default".into()), vec![])];
        selections.extend(layout_files.iter().enumerate().map(|(i, p)| (Some(i.to_string()), vec![p.clone()])));
        for (param, files) in &selections {
            for lang in &languages {
                for window in WindowClass::ALL {
                    let mut target = format!("/instruments/{stem}/render?lang={lang}&window={}", window.name());
                    if let Some(p) = param {
                        target.push_str(&format!("&layout={p}"));
                    }
                    let served = dispatch(&state, &Request::get(&target));
                    assert_eq!(served.status, 200, "{target}");
                    assert_eq!(served.header("content-security-policy"), None, "the frame page carries its own policy");
                    assert_eq!(served.body_text(), cli_html(&instrument, files, lang, window), "{target}");
                    compared += 1;
                }
            }
        }
    }
    assert!(compared >= 30, "compared {compared}");
}
