//! Start-up replay (INT-013a): every stored submission goes through the gate again, in the
//! original order and at the original times, before the upload listener accepts a connection.
//! The published directory is treated as append-only: a withdrawal made later does not apply.

use fieldseal_intake::domain::SubmissionSource;
use fieldseal_intake::gate::IntakeService;
use fieldseal_kernel::time::AuthorityTime;

/// What replay did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReplaySummary {
    /// Submissions run through the gate again.
    pub replayed: usize,
    /// Records they landed.
    pub landed: usize,
    /// Submissions the gate could not take (`replay-failed`).
    pub failed: usize,
    /// How long replay took, in milliseconds.
    pub millis: u128,
}

/// Runs `stored` (arrival milliseconds, bytes) through `gate`. Every failure is logged as a
/// `replay-failed` event; the caller stops start-up if there was any.
pub fn run(gate: &IntakeService<'_>, stored: &[(u64, Vec<u8>)]) -> ReplaySummary {
    let started = std::time::Instant::now();
    let mut s = ReplaySummary::default();
    for (ms, bytes) in stored {
        match gate.ingest(bytes, SubmissionSource::Upload, AuthorityTime(*ms)) {
            Ok(r) => {
                s.replayed += 1;
                s.landed += r.summary.landed;
                eprintln!("{{\"event\":\"replayed\",\"state\":\"{:?}\",\"landed\":{},\"duplicates\":{}}}", r.submission.state(), r.summary.landed, r.summary.duplicates);
            }
            Err(e) => {
                s.failed += 1;
                eprintln!("{{\"event\":\"replay-failed\",\"detail\":{:?}}}", e.to_string());
            }
        }
    }
    s.millis = started.elapsed().as_millis();
    eprintln!("{{\"event\":\"replay-finished\",\"submissions\":{},\"landed\":{},\"failed\":{},\"millis\":{}}}", s.replayed + s.failed, s.landed, s.failed, s.millis);
    s
}
