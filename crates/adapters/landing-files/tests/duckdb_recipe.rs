//! The documented DuckDB command turns the export into Parquet with the manifest's row count
//! (INT-085). The test is skipped, by name, when `duckdb` is not on `PATH`.

mod support;

use std::process::Command;

use support::*;

// covers: INT-085
#[test]
fn int_085_duckdb_converts_jsonl_and_csv_to_parquet_with_the_manifest_row_count() {
    if Command::new("duckdb").arg("--version").output().is_err() {
        eprintln!("skipped: duckdb not on PATH");
        return;
    }
    let dir = export("duckdb", table_rows("s-1"));
    let manifest = parse_json(&read(&dir, "manifest.json"));
    let J::Arr(files) = manifest.get("files") else { panic!("files") };
    let rows = files.iter().find(|f| f.get("name") == &J::Str("results.jsonl".into())).expect("results.jsonl").get("rows").cell();
    let run = |sql: &str| {
        let o = Command::new("duckdb").args(["-csv", "-noheader", "-c", sql]).current_dir(&dir).output().expect("duckdb runs");
        assert!(o.status.success(), "{sql}\n{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    };
    run("COPY (SELECT * REPLACE (CAST(value_number AS DECIMAL(38,9)) AS value_number) FROM read_json_auto('results.jsonl')) TO 'results.parquet' (FORMAT PARQUET)");
    assert_eq!(run("SELECT count(*) FROM 'results.parquet'"), rows, "the Parquet file has the manifest's row count");
    assert_eq!(run("SELECT count(*) FROM read_csv('results.csv')"), rows, "and so has the CSV");
    let _ = std::fs::remove_dir_all(dir);
}
