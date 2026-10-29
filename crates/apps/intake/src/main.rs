//! `fieldseal-intake`: the intake app's composition root (ADR 0028). Configuration is read
//! from the environment only; `fieldseal deployment render` writes it from the manifest
//! (DEP-012). See `crates/apps/intake/README.md` for the variables.
//!
//! Exit codes: `2` for unusable configuration or an invalid export key, `1` for a start-up
//! or runtime failure, including a stored submission that failed replay.

use fieldseal_intake_app::config::Config;
use fieldseal_intake_app::{AppError, IntakeApp};

fn run() -> Result<(), AppError> {
    let config = Config::from_lookup(|k| std::env::var(k).ok()).map_err(AppError::Config)?;
    let app = IntakeApp::build(config)?;
    let live = app.listen()?;
    app.serve(&live);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("fieldseal-intake: {e}");
        std::process::exit(i32::from(e.exit_code()));
    }
}
