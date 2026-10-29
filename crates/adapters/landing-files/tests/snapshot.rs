//! A landing directory opened as a snapshot reads back what was landed (INT-085, INT-091).

mod support;

use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_intake::contract::sample_observation;
use fieldseal_intake::domain::{ObservedValue, Reading};
use fieldseal_intake::ports::{DataPlatform, LandingBatch};
use fieldseal_kernel::id::{Fingerprint, RecordId};
use support::*;

fn landed(dir: &std::path::Path) -> FileDataPlatform {
    let platform = FileDataPlatform::new(dir).expect("landing directory");
    let mut observations: Vec<_> = table_rows("s-1").into_iter().map(|r| r.observation).collect();
    observations.push(sample_observation(2, 1));
    // A text value with every character CSV quotes.
    observations[3].reading = Reading::Value(ObservedValue::Text("a \"quoted\", multi\nline\r\nanswer".into()));
    platform.land(&LandingBatch { observations, exclusions: vec![(RecordId::from([4; 16]), "consent pending".into())], ..LandingBatch::default() }).expect("land");
    platform
}

// covers: INT-085
#[test]
fn int_085_a_snapshot_reads_back_what_was_landed() {
    let dir = scratch("snapshot");
    let live = landed(&dir);
    let snapshot = FileDataPlatform::open_read_only(&dir).expect("snapshot");
    assert_eq!(snapshot.instruments().expect("instruments"), live.instruments().expect("instruments"));
    assert_eq!(snapshot.instruments().expect("instruments").len(), 2);
    for fp in snapshot.instruments().expect("instruments") {
        assert_eq!(snapshot.observations(&fp).expect("snapshot rows"), live.observations(&fp).expect("live rows"));
    }
    assert!(snapshot.observations(&fingerprint()).expect("rows").iter().any(|r| r.excluded.as_deref() == Some("consent pending")), "exclusions come back");
    assert_eq!(snapshot.landing_mark().expect("mark"), 16, "the mark counts every row, excluded included");
    assert_eq!(live.landing_mark().expect("mark"), 16);
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-085
#[test]
fn int_085_a_snapshot_never_writes() {
    let dir = scratch("snapshot-ro");
    let _ = landed(&dir);
    let before = std::fs::read(dir.join("observations.csv")).expect("file");
    let snapshot = FileDataPlatform::open_read_only(&dir).expect("snapshot");
    assert!(snapshot.land(&LandingBatch::default()).is_err());
    assert!(snapshot.exclude(&[RecordId::from([1; 16])], "x").is_err());
    assert!(snapshot.reinstate(&[RecordId::from([1; 16])]).is_err());
    assert!(snapshot.findings().is_err(), "a snapshot holds observations only");
    assert_eq!(std::fs::read(dir.join("observations.csv")).expect("file"), before);
    assert!(FileDataPlatform::open_read_only(dir.join("missing")).is_err(), "a missing directory is an error, not an empty landing");
    assert!(!dir.join("missing").exists(), "and is not created");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-072
#[test]
fn int_072_a_snapshot_refuses_a_row_that_does_not_fit_its_column() {
    let dir = scratch("snapshot-strict");
    let _ = landed(&dir);
    let good = std::fs::read_to_string(dir.join("observations.csv")).expect("file");
    for (from, to, why) in [
        (",integer,", ",integr,", "an unknown value type"),
        (",false,,", ",maybe,,", "a retracted flag that is not a boolean"),
        ("body.weight", "body weight", "an item path with a space"),
    ] {
        assert!(good.contains(from), "{why}: the fixture holds {from}");
        std::fs::write(dir.join("observations.csv"), good.replacen(from, to, 1)).expect("write");
        assert!(FileDataPlatform::open_read_only(&dir).is_err(), "{why}");
    }
    std::fs::write(dir.join("observations.csv"), good.replacen("instrument,", "instrumen,", 1)).expect("write");
    assert!(FileDataPlatform::open_read_only(&dir).is_err(), "a header that is not the long format");
    std::fs::write(dir.join("observations.csv"), good.trim_end()).expect("write");
    assert!(FileDataPlatform::open_read_only(&dir).is_err(), "a last line with no line end");
    let _ = std::fs::remove_dir_all(dir);
}

// covers: INT-011
#[test]
fn int_011_the_file_platform_satisfies_the_data_platform_contract() {
    let root = scratch("contract");
    let n = std::sync::atomic::AtomicU64::new(0);
    fieldseal_intake::contract::data_platform_contract(|| FileDataPlatform::new(root.join(n.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_string())).expect("directory"));
    let _ = (std::fs::remove_dir_all(root), Fingerprint::from([0; 32]));
}

// covers: INT-085
#[test]
fn int_085_the_landing_files_keep_their_bytes() {
    let dir = scratch("bytes");
    let platform = FileDataPlatform::new(&dir).expect("landing directory");
    platform.land(&LandingBatch { observations: vec![sample_observation(1, 1)], ..LandingBatch::default() }).expect("land");
    let header = fieldseal_adapters_landing_files::long_header();
    let line = fieldseal_adapters_landing_files::long_row(&sample_observation(1, 1).into_landed());
    assert_eq!(std::fs::read_to_string(dir.join("observations.csv")).expect("file"), format!("{header}\n{line}\n"));
    assert_eq!(std::fs::read_to_string(dir.join("findings.csv")).expect("file"), "submission,kind,rule,detail\n");
    assert_eq!(std::fs::read_to_string(dir.join("losses.csv")).expect("file"), "tenancy,from_seq,through_seq,reason\n");
    assert!(std::fs::read_dir(&dir).expect("dir").all(|e| !e.expect("entry").file_name().to_string_lossy().ends_with(".tmp")), "no temporary file remains");
    let _ = std::fs::remove_dir_all(dir);
}

trait IntoLanded {
    fn into_landed(self) -> fieldseal_intake::domain::LandedObservation;
}

impl IntoLanded for fieldseal_intake::domain::Observation {
    fn into_landed(self) -> fieldseal_intake::domain::LandedObservation {
        fieldseal_intake::domain::LandedObservation { observation: self, excluded: None }
    }
}
