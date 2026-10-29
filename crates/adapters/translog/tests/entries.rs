//! `GET /entries/{from}/{to}`: the log lists what it stores (PUB-110, WIRE-199).

use std::path::PathBuf;
use std::sync::Arc;

use fieldseal_adapters_translog::{FileLogStore, HandlerTransport, HttpTranslog, MAX_ENTRIES, handle};
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::sign::SigningKey;
use fieldseal_publishing::domain::{LogEntry, LogEntryType};

fn open(name: &str) -> FileLogStore {
    let dir: PathBuf = std::env::temp_dir().join(format!("fieldseal-translog-entries-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    FileLogStore::open(&dir, "entries.example/log", SigningKey::from_scalar(&[5; 32]).expect("key")).expect("open")
}

fn entry(n: u32) -> LogEntry {
    let mut digest = [0u8; 32];
    digest[..4].copy_from_slice(&n.to_be_bytes());
    LogEntry::new(LogEntryType::Publish, Digest::from(digest), Signature(vec![7; 64]), SigningKey::from_scalar(&[6; 32]).expect("key").public_key())
}

fn filled(name: &str, count: u32) -> FileLogStore {
    let store = open(name);
    for n in 0..count {
        store.append_entry(&entry(n)).expect("append");
    }
    store
}

fn get(store: &FileLogStore, path: &str) -> fieldseal_adapters_translog::Response {
    handle(store, "GET", path, b"", 4096)
}

#[test]
fn pub_110_get_entries_returns_the_canonical_entries_in_order() {
    let store = filled("order", 5);
    let r = get(&store, "/entries/1/4");
    assert_eq!(r.status, 200);
    let mut expected = Vec::new();
    for n in 1..4 {
        let bytes = entry(n).encode();
        expected.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(&bytes);
    }
    assert_eq!(r.body, expected, "each entry is a 4-byte length and the canonical bytes");
    // A `to` past the end is clipped to the size of the log.
    let r = get(&store, "/entries/3/99");
    assert_eq!(r.status, 200);
    assert_eq!(fieldseal_adapters_translog::decode_entries(&r.body).expect("decode"), vec![entry(3), entry(4)]);
}

#[test]
fn pub_110_get_entries_stops_at_256_entries() {
    let store = filled("cap", MAX_ENTRIES as u32 + 4);
    let first = fieldseal_adapters_translog::decode_entries(&get(&store, "/entries/0/1000").body).expect("decode");
    assert_eq!(first.len(), 256);
    let rest = fieldseal_adapters_translog::decode_entries(&get(&store, "/entries/256/1000").body).expect("decode");
    assert_eq!(rest, (256..260).map(entry).collect::<Vec<_>>(), "a reader asks again from the next index");
}

#[test]
fn pub_110_get_entries_past_the_end_is_404() {
    let store = filled("past", 2);
    assert_eq!(get(&store, "/entries/2/3").status, 404);
    assert_eq!(get(&store, "/entries/50/60").status, 404);
    assert_eq!(get(&open("empty"), "/entries/0/1").status, 404);
}

#[test]
fn pub_110_get_entries_with_a_bad_range_is_400() {
    let store = filled("bad", 3);
    for path in ["/entries/2/1", "/entries/a/2", "/entries/0/-1", "/entries/01/2", "/entries/0/"] {
        assert_eq!(get(&store, path).status, 400, "{path}");
    }
}

#[test]
fn pub_110_get_entries_with_a_body_or_another_method_is_refused() {
    let store = filled("refused", 3);
    assert_eq!(handle(&store, "GET", "/entries/0/2", b"x", 4096).status, 400);
    assert_eq!(handle(&store, "POST", "/entries/0/2", b"", 4096).status, 405);
    assert_eq!(handle(&store, "DELETE", "/entries/0/2", b"", 4096).status, 405);
}

#[test]
fn pub_110_the_client_reads_back_what_the_server_stores() {
    let store = Arc::new(filled("client", 4));
    let client = HttpTranslog::new(HandlerTransport::new(store));
    assert_eq!(client.entries(0, 4).expect("entries"), (0..4).map(entry).collect::<Vec<_>>());
    assert_eq!(client.entries(2, 3).expect("entries"), vec![entry(2)]);
    assert!(client.entries(4, 5).is_err(), "past the end");
}
