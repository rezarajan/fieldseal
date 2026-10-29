//! The results export as the reader shows and serves it (INT-085 to INT-092).

mod support;

use std::collections::BTreeSet;

use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_landing_files::export::reader::{Published, export_table};
use fieldseal_adapters_landing_files::export::{ExportKey, ExportOptions, Format, KeyedSubject, write_export};
use fieldseal_kernel::digest::lower_hex;
use support::*;

/// Signs in, opens the page (which builds and holds the export) and returns the cookie and mark.
fn open(h: &fieldseal_adapters_results_http::ResultsHttp<'_>, w: &World) -> (String, u64) {
    let cookie = sign_in(h, w, "reader");
    let page = text(&h.handle(&get("/results", Some(&cookie))));
    let mark = page.split("/results/exports/").nth(1).and_then(|r| r.split('/').next()).and_then(|m| m.parse().ok()).expect("a link with a mark");
    (cookie, mark)
}

fn dl(h: &fieldseal_adapters_results_http::ResultsHttp<'_>, cookie: &str, mark: u64, file: &str) -> fieldseal_adapters_portal::Response {
    h.handle(&get(&format!("/results/exports/{mark}/{file}"), Some(cookie)))
}

/// What `fieldseal intake results` writes: the same functions, written to a directory.
fn cli_output(w: &World, name: &str) -> std::path::PathBuf {
    let out = scratch(name);
    let published = Published::read(&w.published, &w.world.trust, &w.world.publishing).expect("published");
    let snapshot = FileDataPlatform::open_read_only(&w.landing).expect("snapshot");
    let key = ExportKey::load_file(&w.key_file).expect("key");
    let table = export_table(&snapshot, &published, &KeyedSubject::new(key.clone())).expect("table");
    write_export(&table, &ExportOptions { formats: BTreeSet::from([Format::Jsonl, Format::Csv]), subject: Box::new(KeyedSubject::new(key)) }, &out).expect("export");
    out
}

// covers: INT-085
#[test]
fn int_085_results_csv_download_is_the_results_export_of_the_shared_table() {
    let w = world("csv");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    assert_eq!(mark, 3);
    let r = dl(&h, &cookie, mark, "results.csv");
    assert_eq!(r.status, 200);
    let body = text(&r);
    assert!(body.starts_with("record_id,") || body.contains("item_path"), "{body}");
    assert_eq!(header(&r, "Content-Disposition"), Some("attachment; filename=\"results.csv\""));
    assert_eq!(header(&r, "X-Content-Type-Options"), Some("nosniff"));
    assert_eq!(header(&r, "Cache-Control"), Some("no-store"));
}

// covers: INT-085
#[test]
fn int_085_every_download_equals_the_cli_output_byte_for_byte_for_the_same_landing_and_key() {
    let w = world("same");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let out = cli_output(&w, "same-cli");
    let contract = format!("contracts/{}.json", lower_hex(w.fingerprint.as_bytes()));
    for file in ["results.csv", "results.jsonl", "free_text.csv", "free_text.jsonl", "codebook.csv", "manifest.json", contract.as_str()] {
        let r = dl(&h, &cookie, mark, file);
        assert_eq!(r.status, 200, "{file}");
        assert_eq!(r.body, std::fs::read(out.join(file)).expect("cli file"), "{file}");
    }
}

// covers: INT-085
#[test]
fn int_085_the_results_reader_writes_nothing_to_disk() {
    let w = world("nowrite");
    let snapshot = |d: &std::path::Path| -> Vec<(String, u64)> {
        fn walk(d: &std::path::Path, out: &mut Vec<(String, u64)>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let m = e.metadata().unwrap();
                if m.is_dir() {
                    walk(&e.path(), out);
                } else {
                    out.push((e.path().display().to_string(), m.len()));
                }
            }
        }
        let mut v = vec![];
        walk(d, &mut v);
        v.sort();
        v
    };
    let before = snapshot(&w.dir);
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    for f in ["results.csv", "manifest.json", "codebook.csv"] {
        assert_eq!(dl(&h, &cookie, mark, f).status, 200);
    }
    assert_eq!(snapshot(&w.dir), before, "no file under the landing, the published directory or the key directory changed or appeared");
    assert!(!std::env::temp_dir().join("fieldseal-export-scratch").exists());
}

// covers: INT-085
#[test]
fn int_085_a_held_mark_does_not_change_when_a_submission_lands() {
    let w = world("held");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let before = dl(&h, &cookie, mark, "results.jsonl").body;
    land(&w.landing, w.fingerprint, 5);
    assert_eq!(dl(&h, &cookie, mark, "results.jsonl").body, before, "the held copy is served");
    let (_, newer) = open(&h, &w);
    assert_eq!(newer, 5);
    assert_ne!(dl(&h, &cookie, newer, "results.jsonl").body, before);
    assert_eq!(dl(&h, &cookie, mark, "results.jsonl").body, before, "the earlier mark is still held");
}

// covers: INT-085
#[test]
fn int_085_an_unknown_or_evicted_mark_is_404() {
    let w = world("evict");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let r = dl(&h, &cookie, 999, "results.csv");
    assert_eq!(r.status, 404);
    assert!(text(&r).contains("unknown-mark"));
    assert_eq!(dl(&h, &cookie, mark, "results.csv").status, 200);
    // Five more marks push the first out; only the last four are held.
    for n in 4..=8 {
        land(&w.landing, w.fingerprint, n);
        open(&h, &w);
    }
    let r = dl(&h, &cookie, mark, "results.csv");
    assert_eq!(r.status, 404);
    assert!(text(&r).contains("unknown-mark"));
    assert_eq!(fieldseal_adapters_results_http::HELD_MARKS, 4);
}

// covers: INT-085
#[test]
fn int_085_a_path_outside_the_fixed_list_is_404() {
    let w = world("paths");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    for bad in ["../observations.csv", "observations.csv", "findings.csv", "contracts/../../export.key", "results.csv/", "RESULTS.CSV", "%2e%2e/export.key", "contracts", "contracts/"] {
        let r = dl(&h, &cookie, mark, bad);
        assert_eq!(r.status, 404, "{bad}");
        assert!(text(&r).contains("not-found"), "{bad}");
    }
}

// covers: INT-085
#[test]
fn int_085_a_contract_name_that_is_not_64_lower_case_hex_digits_is_404() {
    let w = world("hex");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let good = lower_hex(w.fingerprint.as_bytes());
    for bad in [good.to_uppercase(), good[..63].to_owned(), format!("{good}0"), "g".repeat(64), String::new()] {
        assert_eq!(dl(&h, &cookie, mark, &format!("contracts/{bad}.json")).status, 404, "{bad}");
    }
    assert_eq!(dl(&h, &cookie, mark, &format!("contracts/{good}.json")).status, 200);
}

// covers: INT-085
#[test]
fn int_085_a_fingerprint_absent_from_the_manifest_is_404() {
    let w = world("absent");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let other = "ab".repeat(32);
    assert_eq!(dl(&h, &cookie, mark, &format!("contracts/{other}.json")).status, 404);
}

// covers: INT-090
#[test]
fn int_090_the_page_shows_the_replay_gap_count() {
    let w = world("gap");
    let mut cfg = config(&w);
    cfg.replay_gap = 2;
    cfg.development_adapters = vec![("SubmissionStore".into(), "file-dev".into())];
    let h = reader(&w, cfg);
    let cookie = sign_in(&h, &w, "reader");
    let page = text(&h.handle(&get("/results", Some(&cookie))));
    assert!(page.contains("could not land: 2."), "{page}");
    assert!(page.contains("Development adapters in use") && page.contains("file-dev"));
}

// covers: INT-088
#[test]
fn int_088_free_text_csv_matches_the_free_text_file() {
    let w = world("free");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let out = cli_output(&w, "free-cli");
    assert_eq!(dl(&h, &cookie, mark, "free_text.csv").body, std::fs::read(out.join("free_text.csv")).unwrap());
    assert_eq!(dl(&h, &cookie, mark, "free_text.jsonl").body, std::fs::read(out.join("free_text.jsonl")).unwrap());
}

// covers: INT-086
#[test]
fn int_086_excluded_rows_never_appear_in_the_results_reader() {
    let w = world("excl");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let rec1 = lower_hex(fieldseal_kernel::id::RecordId::from([1; 16]).as_bytes());
    for f in ["results.csv", "results.jsonl"] {
        assert!(!text(&dl(&h, &cookie, mark, f)).contains(&rec1), "{f}");
    }
    assert!(text(&dl(&h, &cookie, mark, "manifest.json")).contains("\"rows_omitted_excluded\":1"));
    assert!(!text(&h.handle(&get("/results", Some(&cookie)))).contains(&format!("<td>{rec1}</td>")));
}

// covers: INT-087
#[test]
fn int_087_subjects_in_the_results_reader_are_keyed_hashes() {
    let w = world("subj");
    let h = reader(&w, config(&w));
    let (cookie, mark) = open(&h, &w);
    let hex_of_subject = "hh-0001".bytes().map(|b| format!("{b:02x}")).collect::<String>();
    for f in ["results.csv", "results.jsonl", "free_text.csv", "codebook.csv", "manifest.json"] {
        let body = text(&dl(&h, &cookie, mark, f));
        assert!(!body.contains("hh-0001") && !body.contains(&hex_of_subject), "{f}");
    }
    let page = text(&h.handle(&get("/results", Some(&cookie))));
    assert!(!page.contains("hh-0001") && !page.contains(&hex_of_subject));
}

// covers: INT-092
#[test]
fn int_092_the_page_computes_nothing_from_the_answers() {
    // The page code reads the held export's files and nothing else: no sums, means or
    // per-question counts. The numbers it shows are the landing mark, the manifest's row
    // counts and the page arithmetic.
    let src = include_str!("../src/pages.rs");
    for word in ["sum(", ".sum::<", "mean", "average", "percent", "histogram", "group_by"] {
        assert!(!src.contains(word), "pages.rs mentions {word}");
    }
}

// covers: INT-085
#[test]
fn int_085_a_page_number_past_the_end_is_the_last_page_and_never_overflows() {
    let w = world("paging");
    land(&w.landing, w.fingerprint, 120);
    let h = reader(&w, config(&w));
    let cookie = sign_in(&h, &w, "reader");
    for (query, shown) in [("999999999999999999", "Page 3 of 3"), ("18446744073709551615", "Page 3 of 3"), ("99999999999999999999999", "Page 1 of 3"), ("0", "Page 1 of 3"), ("-5", "Page 1 of 3"), ("2", "Page 2 of 3")] {
        let r = h.handle(&get(&format!("/results?page={query}"), Some(&cookie)));
        assert_eq!(r.status, 200, "{query}");
        assert!(text(&r).contains(shown), "{query}: {}", shown);
    }
    // The last page links back and has no next page.
    let last = text(&h.handle(&get("/results?page=999999999999999999", Some(&cookie))));
    assert!(last.contains("/results?page=2\">Previous") && !last.contains(">Next<"));
}

// covers: INT-085
#[test]
fn int_085_the_reader_holds_built_exports_within_a_byte_budget() {
    let w = world("budget");
    let h = reader(&w, config(&w)).with_held_bytes(1);
    let (cookie, first) = open(&h, &w);
    land(&w.landing, w.fingerprint, 4);
    let (_, second) = open(&h, &w);
    assert_ne!(first, second);
    // Over budget, the oldest mark goes at once; the newest is always kept.
    assert_eq!(dl(&h, &cookie, first, "results.csv").status, 404);
    assert_eq!(dl(&h, &cookie, second, "results.csv").status, 200);
    assert_eq!(fieldseal_adapters_results_http::HELD_BYTES, 256 * 1024 * 1024);
}
