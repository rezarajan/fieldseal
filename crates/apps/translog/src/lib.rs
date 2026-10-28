//! The Fieldseal transparency-log server (issue #82): a self-hosted, append-only RFC 9162
//! Merkle log behind a small HTTP/1.1 API. The log itself and its API are documented in
//! [`fieldseal_adapters_translog`]; this crate adds the configuration ([`config`]) and the
//! blocking server ([`http`]) that the `fieldseal-translog` binary wires together.
//!
//! # Configuration (environment only)
//!
//! | Variable | Meaning |
//! |---|---|
//! | `FIELDSEAL_TRANSLOG_DIR` | The data directory (required) |
//! | `FIELDSEAL_TRANSLOG_ORIGIN` | The log's origin line, with no whitespace (required) |
//! | `FIELDSEAL_TRANSLOG_KEY_FILE` | A file with the 32-byte P-256 private scalar as hex (required) |
//! | `FIELDSEAL_TRANSLOG_GENERATE_KEY` | `1` creates the key file once, from OS randomness, if it doesn't exist |
//! | `FIELDSEAL_TRANSLOG_BIND` | The listen address (default `127.0.0.1:8080`) |
//! | `FIELDSEAL_TRANSLOG_MAX_BODY` | The largest request body in bytes (default 4096, at most 1 MiB) |
//!
//! The server never derives its key: without a key file (and without the generate switch)
//! it refuses to start. At startup it prints the log's pin (origin, public key, format) to
//! stderr as one structured line, for the operator to put in trust bundles.
//!
//! The server speaks plain HTTP. Put a TLS-terminating proxy in front of it to serve over
//! the network; checkpoints are signed, so clients verify them offline against the pin
//! regardless of the channel.
//!
//! SIGTERM is not handled (that needs signal handling outside `std`, and `unsafe` is
//! forbidden): the process terminates immediately. This is safe, because every append is
//! `fsync`ed before it is acknowledged and an interrupted append is cut off on the next
//! start. [`http::ShutdownHandle`] stops a server cleanly in-process.

pub mod config;
pub mod http;
