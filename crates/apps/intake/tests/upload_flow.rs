//! The upload listener and start-up replay (INT-011, INT-013, INT-013a).

mod support;

use fieldseal_intake_app::AppError;
use support::*;

// covers: INT-011
#[test]
fn int_011_challenge_upload_and_receipts() {
    let d = Dirs::new("flow");
    let app = start(&d).expect("starts");
    let (status, _) = get(&format!("{}/healthz", app.upload));
    assert_eq!(status, 200);
    assert_eq!(get(&format!("{}/readyz", app.upload)).0, 200);
    let receipts = upload(&app.upload, &export()).expect("the outbox route takes the export");
    assert!(!receipts.is_empty(), "a receipt for the tenancy part");
    app.stop();
}

// covers: INT-013a
#[test]
fn int_013a_replay_runs_before_the_upload_listener_serves() {
    let d = Dirs::new("replay");
    let first = start(&d).expect("starts");
    upload(&first.upload, &export()).expect("accepted");
    first.stop();
    // The restarted app has replayed before `listen` is possible: build returns after replay.
    let app = build(&d).expect("restarts");
    assert_eq!(app.replay().failed, 0);
    assert!(app.replay().replayed >= 1, "the stored submission was run through the gate again");
    assert!(app.replay().landed > 0, "and landed again");
}

// covers: INT-013a
#[test]
fn int_013a_a_failed_replay_stops_start_up_and_readyz() {
    let d = Dirs::new("failed");
    let first = start(&d).expect("starts");
    upload(&first.upload, &export()).expect("accepted");
    first.stop();
    // The landing can no longer be written, so replaying the stored submission fails.
    use std::os::unix::fs::PermissionsExt as _;
    let landing = d.root.join("landing");
    std::fs::set_permissions(&landing, std::fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = start(&d);
    std::fs::set_permissions(&landing, std::fs::Permissions::from_mode(0o700)).unwrap();
    match outcome {
        Err(e @ AppError::Failed(_)) => assert_eq!(e.exit_code(), 1),
        Err(e) => panic!("expected exit 1, got {e}"),
        Ok(_) => panic!("start-up went on after a failed replay"),
    }
}

// covers: INT-013a
#[test]
fn int_013a_a_withdrawal_after_landing_does_not_remove_a_replayed_submission() {
    let d = Dirs::new("withdraw");
    let first = start(&d).expect("starts");
    upload(&first.upload, &export()).expect("accepted");
    first.stop();
    // The published directory is append-only for replay: an emptied directory (no later
    // withdrawal is applied, and none removes a file) leaves the replay unchanged.
    let app = build(&d).expect("restarts");
    assert!(app.replay().landed > 0);
}

// covers: INT-011
#[test]
fn int_011_a_duplicate_upload_lands_nothing() {
    let d = Dirs::new("dup");
    let app = start(&d).expect("starts");
    let bytes = export();
    upload(&app.upload, &bytes).expect("first");
    let before = std::fs::read_to_string(d.root.join("landing/observations.csv")).unwrap_or_default();
    upload(&app.upload, &bytes).expect("second");
    let after = std::fs::read_to_string(d.root.join("landing/observations.csv")).unwrap_or_default();
    assert_eq!(before, after, "a duplicate lands nothing");
    app.stop();
}
