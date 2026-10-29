//! The server's start-up event (DEP-051, DEP-076): the real binary, started with a generated key.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

// covers: DEP-051
#[test]
fn dep_051_the_translog_server_writes_one_development_adapters_event() {
    let dir = std::env::temp_dir().join(format!("fieldseal-translog-event-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let mut child = Command::new(env!("CARGO_BIN_EXE_fieldseal-translog"))
        .env_clear()
        .env("FIELDSEAL_TRANSLOG_DIR", dir.join("log"))
        .env("FIELDSEAL_TRANSLOG_ORIGIN", "test.example/log")
        .env("FIELDSEAL_TRANSLOG_KEY_FILE", dir.join("translog.key"))
        .env("FIELDSEAL_TRANSLOG_GENERATE_KEY", "1")
        .env("FIELDSEAL_TRANSLOG_BIND", "127.0.0.1:0")
        .stderr(Stdio::piped())
        .spawn()
        .expect("the server starts");
    // The pin line follows the event, so reading up to it sees every start-up line.
    let mut lines = Vec::new();
    for line in BufReader::new(child.stderr.take().expect("stderr")).lines() {
        let line = line.expect("a line");
        let started = line.contains("event=started");
        lines.push(line);
        if started {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let events: Vec<&String> = lines.iter().filter(|l| l.contains("\"event\":\"development-adapters\"")).collect();
    assert_eq!(events.len(), 1, "{lines:?}");
    assert_eq!(events[0], "{\"event\":\"development-adapters\",\"service\":\"fieldseal-translog\",\"adapters\":[{\"port\":\"Signer\",\"adapter\":\"file-dev\"}]}");
}
