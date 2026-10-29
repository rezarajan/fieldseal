//! INS-025, INS-027, INS-133 in a real browser: the instrument pages the web app serves are
//! opened in headless Chromium and driven like a collector (tick a fifth option, type 100 into
//! a field that stops at 20, press "+" past the maximum). The checks are in
//! `tools/browser-tests/constraints.py`.
//!
//! Skipped (with a note) unless `FIELDSEAL_BROWSER_TESTS=1`. When it runs:
//!
//! * by default it uses `nix shell` to get Chromium and a Python with `websockets`;
//! * with `FIELDSEAL_CHROMIUM_PYTHON=<command>` it runs `<command> constraints.py FOOD WATER`
//!   instead (for example `python3`, with `chromium` on the PATH and `websockets` importable).
//!
//! ```text
//! FIELDSEAL_BROWSER_TESTS=1 cargo test -p fieldseal-web --test browser_constraints -- --nocapture
//! ```
#![allow(missing_docs)]

use std::path::PathBuf;
use std::process::Command;

use fieldseal_web::http::Request;
use fieldseal_web::routes::dispatch;
use fieldseal_web::state::AppState;

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
}

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tools/browser-tests/constraints.py")
}

/// The page the server serves for `target`, written to a file the browser can open.
fn page(state: &AppState, target: &str, dir: &std::path::Path, name: &str) -> PathBuf {
    let served = dispatch(state, &Request::get(target));
    assert_eq!(served.status, 200, "{target}");
    let file = dir.join(name);
    std::fs::write(&file, served.body_text()).unwrap();
    file
}

// covers: INS-025, INS-027, INS-133
#[test]
fn ins_025_the_page_stops_a_fifth_option_and_out_of_range_values_in_a_real_browser() {
    if std::env::var("FIELDSEAL_BROWSER_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set FIELDSEAL_BROWSER_TESTS=1 to drive headless Chromium (see this file's doc comment)");
        return;
    }
    let state = AppState { examples_dir: examples(), ..AppState::default() };
    let dir = std::env::temp_dir().join(format!("fieldseal-browser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let meals = page(&state, "/instruments/school-meals-baseline/render?lang=en&window=compact", &dir, "meals.html");
    let water = page(&state, "/instruments/household-water-access/render?lang=en&window=expanded", &dir, "water.html");

    let mut cmd = match std::env::var("FIELDSEAL_CHROMIUM_PYTHON") {
        Ok(python) if !python.trim().is_empty() => {
            let mut words = python.split_whitespace();
            let mut c = Command::new(words.next().unwrap());
            c.args(words);
            c
        }
        _ => {
            let mut c = Command::new("nix");
            c.args([
                "shell",
                "--impure",
                "--expr",
                "let p = (builtins.getFlake \"nixpkgs\").legacyPackages.${builtins.currentSystem}; in p.buildEnv { name = \"fieldseal-browser-test\"; paths = [ p.chromium (p.python3.withPackages (ps: [ ps.websockets ])) ]; }",
                "--command",
                "python3",
            ]);
            c
        }
    };
    let out = cmd.arg(script()).arg(&meals).arg(&water).output().expect("the browser test starts");
    let text = String::from_utf8_lossy(&out.stdout);
    let _ = std::fs::remove_dir_all(&dir);
    println!("{text}");
    assert!(out.status.success(), "browser checks failed:\n{text}\n{}", String::from_utf8_lossy(&out.stderr));
}

// covers: WEB-186
