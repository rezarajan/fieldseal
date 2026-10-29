//! A restart on the same directories gives the same results export (INT-013a, Technical
//! Plan 6): replay refills the landing, and the export is built from it.

mod support;

use std::collections::BTreeSet;
use std::path::Path;

use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_landing_files::export::reader::{Published, export_table};
use fieldseal_adapters_landing_files::export::{ExportKey, ExportOptions, Format, KeyedSubject, write_export};
use support::*;

fn results(d: &Dirs, out: &Path) {
    let app = build(d).expect("builds");
    let published = Published::read(&d.root.join("published"), app.trust_bundle(), &d.config(&[]).publishing_policy()).expect("published");
    let snapshot = FileDataPlatform::open_read_only(d.root.join("landing")).expect("snapshot");
    let key = ExportKey::load(&d.root.join("export-key")).expect("key");
    let table = export_table(&snapshot, &published, &KeyedSubject::new(key.clone())).expect("table");
    write_export(&table, &ExportOptions { formats: BTreeSet::from([Format::Jsonl, Format::Csv]), subject: Box::new(KeyedSubject::new(key)) }, out).expect("export");
}

fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            if e.path().is_dir() {
                walk(base, &e.path(), out);
            } else {
                out.push((e.path().strip_prefix(base).unwrap().display().to_string(), std::fs::read(e.path()).unwrap()));
            }
        }
    }
    let mut v = vec![];
    walk(dir, dir, &mut v);
    v.sort();
    v
}

// covers: INT-013a
#[test]
fn int_013a_the_export_is_byte_identical_after_a_restart_on_the_same_directories() {
    let d = Dirs::new("restart");
    let first = start(&d).expect("starts");
    upload(&first.upload, &export()).expect("accepted");
    first.stop();
    let (a, b) = (scratch("restart-a"), scratch("restart-b"));
    results(&d, &a);
    // `results` built the app again, which replayed the stored submission.
    results(&d, &b);
    let (fa, fb) = (files(&a), files(&b));
    assert!(fa.iter().any(|(n, _)| n == "manifest.json"));
    assert_eq!(fa, fb, "every file, including the manifest digests, is the same");
}
