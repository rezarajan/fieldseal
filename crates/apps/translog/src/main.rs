//! `fieldseal-translog`: the transparency-log server's composition root. See the library
//! documentation for the configuration.

use std::process::ExitCode;
use std::sync::Arc;

use fieldseal_adapters_translog::FileLogStore;
use fieldseal_deployment::events::development_adapters_event;
use fieldseal_translog::config::{Config, check_names, load_key};
use fieldseal_translog::http::Server;

/// Exit status for unusable configuration.
const EXIT_CONFIG: u8 = 78;
/// Exit status for a failure to open the log or bind the address.
const EXIT_UNAVAILABLE: u8 = 69;

fn fail(code: u8, what: &str, e: impl std::fmt::Display) -> ExitCode {
    eprintln!("fieldseal-translog event=error what={what} detail={:?}", e.to_string());
    ExitCode::from(code)
}

fn main() -> ExitCode {
    if let Err(e) = check_names(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok())) {
        return fail(EXIT_CONFIG, "config", e);
    }
    let config = match Config::from_lookup(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => return fail(EXIT_CONFIG, "config", e),
    };
    let key = match load_key(&config.key_file, config.generate_key, |buf| {
        getrandom::getrandom(buf).expect("the operating system's random source");
    }) {
        Ok(k) => k,
        Err(e) => return fail(EXIT_CONFIG, "key", e),
    };
    let store = match FileLogStore::open(&config.dir, &config.origin, key) {
        Ok(s) => Arc::new(s),
        Err(e) => return fail(EXIT_UNAVAILABLE, "open", e),
    };
    let server = match Server::bind(&config.bind, store.clone(), config.max_body) {
        Ok(s) => s,
        Err(e) => return fail(EXIT_UNAVAILABLE, "bind", e),
    };
    // The signing key is a file the operator provides (or this process makes once): a development adapter for the log's signer (DEP-051).
    eprintln!("{}", development_adapters_event("fieldseal-translog", &[("Signer", "file-dev")]));
    let pin = store.pin();
    eprintln!(
        "fieldseal-translog event=started origin={} public_key={} format={} bind={} size={}",
        pin.origin,
        fieldseal_kernel::digest::lower_hex(&pin.public_key),
        pin.format,
        server.local_addr().map_or_else(|_| config.bind.clone(), |a| a.to_string()),
        store.size(),
    );
    server.run();
    ExitCode::SUCCESS
}
