//! `FileSubmissionStore` against the `SubmissionStore` contract (INT-013).

use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_adapters_file::submissions::FileSubmissionStore;

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn int_013_the_file_submission_store_satisfies_the_contract() {
    let root = std::env::temp_dir().join(format!("fieldseal-submissions-{}", std::process::id()));
    fieldseal_intake::contract::submission_store_contract(|| {
        let dir = root.join(NEXT.fetch_add(1, Ordering::Relaxed).to_string());
        FileSubmissionStore::open(dir, || 0).expect("a fresh directory")
    });
    let _ = std::fs::remove_dir_all(root);
}
