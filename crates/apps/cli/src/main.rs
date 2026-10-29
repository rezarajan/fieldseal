//! `fieldseal`: the CLI and its composition root (ADR 0006, ADR 0028).
//!
//! The command tree is `fieldseal <noun> <verb> [arguments]` (docs/reference/spec/cli.md).
//! This entry point reads configuration from the environment (ADR 0025), wires adapters
//! through the composition root, and dispatches. Results go to stdout (`--json` for one
//! machine-readable document), structured events to stderr.
//!
//! Built so far: `instrument validate|lint|compile|hash|preview|i18n`, `layout
//! validate|lint|compile`, `localisation validate`, `policy`, `trust`, `keys generate`,
//! `artefact`, `log prove|key`, `registration`, `bundle`, `export`, `deployment`, `docs`, `device simulate`, `intake`, `new survey`, `survey check|list`, `roster check|diff|list`, `schema export|check` and `adapters`. The rest
//! of the tree is built by the buildout issues.

mod args;
mod artefact_cmd;
mod artefact_kinds;
mod bundle_cmd;
mod bundle_stack;
mod clients;
mod commands;
mod conformance_cmd;
mod composition;
mod deployment_cmd;
mod device;
mod embedded;
mod device_dir;
mod device_export;
mod device_delivery;
mod export_cmd;
mod custody;
mod device_keys;
mod log_cmd;
mod receipt_cmd;
mod intake_cmd;
mod i18n_cmd;
mod json;
mod messages;
mod new_cmd;
mod keys_cmd;
mod outcome;
mod policy_cmd;
mod registration_cmd;
mod registration_remote;
mod registry_cmd;
mod roster_check;
mod roster_cmd;
mod schema_cmd;
mod stores;
mod survey_cmd;
mod support;
mod transport;
mod upload_cmd;
mod trust_cmd;

use std::process::ExitCode;

use composition::{AdapterSet, AuthoringTools, Config, MemoryAdapters, authoring_bindings, memory_bindings};
use messages::msg;
use outcome::{Outcome, exit};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let config = match Config::from_lookup(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fieldseal: {e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    // The noun and verb are the first two arguments that aren't flags; everything else
    // belongs to the command.
    let at: Vec<usize> = args.iter().enumerate().filter(|(_, a)| !a.starts_with('-')).map(|(i, _)| i).take(2).collect();
    let words: Vec<&str> = at.iter().map(|i| args[*i].as_str()).collect();
    let rest: Vec<String> = args.iter().enumerate().filter(|(i, _)| !at.contains(i)).map(|(_, a)| a.clone()).collect();

    let code = match words.as_slice() {
        [] if args.iter().any(|a| a == "--version") => {
            println!("fieldseal {}", env!("CARGO_PKG_VERSION"));
            exit::OK
        }
        [] if args.iter().any(|a| a == "--help") => {
            println!("{}", msg("usage", &[]));
            exit::OK
        }
        ["adapters", ..] => adapters(&config, json),
        ["device", "export"] => device_export::run(&rest),
        ["export", "upload"] => upload_cmd::run(&rest),
        // The device simulator parses its own arguments (docs/reference/spec/cli.md, `device simulate`).
        ["device", ..] => return device::run(&args, json),
        ["conformance", ..] => return conformance_cmd::run(&args),
        ["bundle", ..] => return bundle_cmd::run(&args),
        ["intake", ..] => return intake_cmd::run(&args),
        ["trust", verb] => match trust_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("trust {verb}"))]), json),
        },
        ["keys", verb] => match keys_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("keys {verb}"))]), json),
        },
        ["registry", verb] => match registry_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("registry {verb}"))]), json),
        },
        ["receipt", verb] => match receipt_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("receipt {verb}"))]), json),
        },
        ["artefact", verb] => match artefact_cmd::run_artefact(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("artefact {verb}"))]), json),
        },
        ["log", verb] => match artefact_cmd::run_log(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("log {verb}"))]), json),
        },
        ["registration", verb] => match registration_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("registration {verb}"))]), json),
        },
        ["instrument", "i18n"] => match rest.split_first() {
            Some((verb, tail)) => match i18n_cmd::run_i18n(verb, tail) {
                Some(code) => code,
                None => usage_error(&msg("unknown-command", &[("command", &format!("instrument i18n {verb}"))]), json),
            },
            None => usage_error(&msg("usage", &[]), json),
        },
        ["localisation", verb] => match i18n_cmd::run_localisation(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("localisation {verb}"))]), json),
        },
        ["new", noun] => match new_cmd::run(noun, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("new {noun}"))]), json),
        },
        ["survey", verb] => match survey_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("survey {verb}"))]), json),
        },
        ["roster", verb] => match roster_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("roster {verb}"))]), json),
        },
        ["schema", verb] => match schema_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("schema {verb}"))]), json),
        },
        ["policy", verb] => match policy_cmd::run(verb, &rest) {
            Some(code) => code,
            None => usage_error(&msg("unknown-command", &[("command", &format!("policy {verb}"))]), json),
        },
        ["deployment", ..] | ["docs", ..] => return deployment_cmd::run(&args),
        ["export", ..] => return export_cmd::run(&args, json),
        [noun, verb] => {
            let ctx = commands::Ctx { tools: AuthoringTools, log_format: config.log_format };
            match commands::run(&ctx, noun, verb, &rest) {
                Some((outcome, as_json)) => outcome.emit(as_json),
                None => usage_error(&msg("unknown-command", &[("command", &format!("{noun} {verb}"))]), json),
            }
        }
        _ => usage_error(&msg("usage", &[]), json),
    };
    ExitCode::from(code)
}

fn usage_error(message: &str, json: bool) -> u8 {
    let mut o = Outcome::new("usage");
    o.error(exit::USAGE, message.to_owned());
    o.emit(json)
}

fn adapters(config: &Config, json: bool) -> u8 {
    let mut bindings = match config.adapters {
        AdapterSet::Memory | AdapterSet::Files => {
            let _wired = MemoryAdapters::wire();
            memory_bindings()
        }
    };
    bindings.extend(authoring_bindings());
    if json {
        let rows: Vec<String> = bindings
            .iter()
            .map(|b| format!(r#"{{"context":"{}","port":"{}","adapter":"{}"}}"#, b.context, b.port, b.adapter))
            .collect();
        println!(r#"{{"set":"memory","bindings":[{}]}}"#, rows.join(","));
    } else {
        for b in &bindings {
            println!("{:<13} {:<20} {}", b.context, b.port, b.adapter);
        }
    }
    exit::OK
}
