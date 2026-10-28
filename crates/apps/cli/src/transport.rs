//! A log transport that sends nothing: for the local logs, which have no network side. The
//! transmission is still built (so the minimal-disclosure contract applies to local logs
//! unchanged, ADR 0030) but goes nowhere.

use fieldseal_publishing::ports::{LogError, LogTransport, Transmission};

/// Sends nothing and answers with an empty body.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullTransport;

impl LogTransport for NullTransport {
    fn send(&self, _transmission: &Transmission) -> Result<Vec<u8>, LogError> {
        Ok(Vec::new())
    }
}
