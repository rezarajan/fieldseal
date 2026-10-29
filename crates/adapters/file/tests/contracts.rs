//! The file adapters against the port contract suites (PUB-060, DIS-080, DIS-015, DIS-012), and
//! the behaviour of each that the shared contracts do not cover.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_adapters_file::bundles::FileBundleStore;
use fieldseal_adapters_file::profiles::FileRuntimeProfiles;
use fieldseal_adapters_file::registry::FileRegistry;
use fieldseal_adapters_file::roster_store::{
    FileRosterSource, IssueOutcome, RosterStore, RosterStoreError,
};
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_distribution::contract::{
    bundle_store_contract, roster_source_contract, runtime_profiles_contract, sample_bundle,
};
use fieldseal_distribution::domain::{
    BundleSeq, ConsentState, Roster, RosterEntry, RuntimeProfile,
};
use fieldseal_distribution::ports::{BundleStore, BundleStoreError, RosterSource, RuntimeProfiles};
use fieldseal_instrument::domain::SchemaVersion;
use fieldseal_kernel::id::{CohortId, Generation, SubjectId, TenancyId};
use fieldseal_kernel::value::Value;
use fieldseal_publishing::contract::artefact_registry_contract;
use fieldseal_registration::contract::sample_tenancy;
use fieldseal_registration::domain::{
    CohortAssignment, ReportedProfile, ReportedVersion, TenancyRecord, TenancyState,
};
use fieldseal_registration::ports::RegistryStore;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fieldseal-file-contracts-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn version(major: u32, minor: u32, patch: u32) -> ReportedVersion {
    ReportedVersion {
        major,
        minor,
        patch,
    }
}

/// A registered tenancy reporting `profile`, assigned `cohorts`.
fn tenancy(
    id: u8,
    account: &str,
    profile: ReportedProfile,
    cohorts: &[(&str, u32)],
) -> TenancyRecord {
    let mut t = sample_tenancy(id, account);
    t.state = TenancyState::Registered;
    t.profile = profile;
    t.cohorts = cohorts
        .iter()
        .map(|(c, g)| CohortAssignment {
            cohort: CohortId::new(*c).expect("cohort"),
            generation: Generation(*g),
        })
        .collect();
    t
}

fn plain(major: u32, minor: u32, patch: u32) -> ReportedProfile {
    ReportedProfile {
        instrument_schema: version(major, minor, patch),
        catalogue_reference: None,
    }
}

/// Puts `records` in a tenancy registry journal in `dir`.
fn journal(dir: &Path, records: &[TenancyRecord]) {
    let store = FileRegistryStore::open(dir).expect("journal");
    for r in records {
        store.put_tenancy(r).expect("put tenancy");
    }
}

fn roster(cohort: &str, version: u64, display: &str) -> Roster {
    Roster {
        cohort: CohortId::new(cohort).expect("cohort"),
        version,
        generation: Generation(1),
        entries: vec![RosterEntry {
            ordinal: 1,
            subject: SubjectId::new("subject-1").expect("subject"),
            display: display.into(),
            attributes: [("grade".to_owned(), Value::Text("3".into()))]
                .into_iter()
                .collect(),
            consent: ConsentState::Granted,
            prior_status: None,
        }],
    }
}

// covers: PUB-060
#[test]
fn pub_060_the_file_registry_satisfies_the_artefact_registry_contract() {
    let root = Scratch::new();
    artefact_registry_contract(|| {
        FileRegistry::new(root.join(&NEXT.fetch_add(1, Ordering::Relaxed).to_string()))
    });
}

// covers: DIS-080
#[test]
fn dis_080_the_file_roster_source_satisfies_the_roster_source_contract() {
    let root = Scratch::new();
    let tenancy_id = TenancyId::from([1; 32]);
    roster_source_contract(
        || {
            let dir = root.join(&NEXT.fetch_add(1, Ordering::Relaxed).to_string());
            let journal_dir = dir.join("tenancies");
            journal(
                &journal_dir,
                &[
                    tenancy(1, "acct-a", plain(1, 0, 0), &[("north", 1)]),
                    tenancy(2, "acct-b", plain(1, 0, 0), &[("north", 2)]),
                    // A pending request is not an active tenancy.
                    {
                        let mut pending = tenancy(3, "acct-c", plain(1, 0, 0), &[("north", 1)]);
                        pending.state = TenancyState::Pending;
                        pending
                    },
                ],
            );
            let store = RosterStore::open(dir.join("rosters")).expect("store");
            store.issue(&roster("north", 1, "Ada")).expect("issue");
            FileRosterSource::new(store, journal_dir)
        },
        tenancy_id,
    );
}

// covers: DIS-015
#[test]
fn dis_015_the_file_bundle_store_satisfies_the_bundle_store_contract() {
    let root = Scratch::new();
    bundle_store_contract(|| {
        FileBundleStore::new(root.join(&NEXT.fetch_add(1, Ordering::Relaxed).to_string()))
    });
}

// covers: DIS-012
#[test]
fn dis_012_the_file_runtime_profiles_satisfy_the_runtime_profiles_contract() {
    let root = Scratch::new();
    runtime_profiles_contract(
        || {
            let dir = root.join(&NEXT.fetch_add(1, Ordering::Relaxed).to_string());
            journal(
                &dir,
                &[tenancy(
                    1,
                    "acct-a",
                    ReportedProfile {
                        instrument_schema: version(1, 2, 3),
                        catalogue_reference: Some("ui-reference-4".into()),
                    },
                    &[],
                )],
            );
            FileRuntimeProfiles::new(dir)
        },
        TenancyId::from([1; 32]),
        RuntimeProfile {
            instrument_schema: SchemaVersion {
                major: 1,
                minor: 2,
                patch: 3,
            },
            localisation_reference: Some("ui-reference-4".into()),
        },
    );
}

// covers: DIS-012
#[test]
fn dis_012_a_tenancy_that_reported_an_older_schema_reports_that_schema_back() {
    let root = Scratch::new();
    journal(
        root.path(),
        &[
            tenancy(1, "acct-a", plain(1, 0, 0), &[]),
            tenancy(2, "acct-b", plain(1, 3, 0), &[]),
        ],
    );
    let profiles = FileRuntimeProfiles::new(root.path());
    let old = profiles
        .profile(&TenancyId::from([1; 32]))
        .expect("profile")
        .expect("known");
    let new = profiles
        .profile(&TenancyId::from([2; 32]))
        .expect("profile")
        .expect("known");
    assert_eq!(
        old.instrument_schema,
        SchemaVersion {
            major: 1,
            minor: 0,
            patch: 0
        }
    );
    assert_eq!(
        new.instrument_schema,
        SchemaVersion {
            major: 1,
            minor: 3,
            patch: 0
        }
    );
    assert_eq!(
        old.localisation_reference, None,
        "a build that reported no catalogue is given no localisation"
    );
}

// covers: DIS-012
#[test]
fn dis_012_the_profile_survives_a_restart_of_the_journal() {
    let root = Scratch::new();
    journal(
        root.path(),
        &[tenancy(
            1,
            "acct-a",
            ReportedProfile {
                instrument_schema: version(2, 0, 1),
                catalogue_reference: Some("ui-reference-9".into()),
            },
            &[],
        )],
    );
    // A second open replays the journal from disk.
    let reopened = FileRegistryStore::open(root.path()).expect("reopen");
    let profile = reopened
        .tenancy(&TenancyId::from([1; 32]))
        .expect("store")
        .expect("known")
        .profile;
    assert_eq!(
        profile,
        ReportedProfile {
            instrument_schema: version(2, 0, 1),
            catalogue_reference: Some("ui-reference-9".into())
        }
    );
}

// covers: DIS-080
#[test]
fn dis_080_a_roster_version_once_issued_does_not_change() {
    let root = Scratch::new();
    let store = RosterStore::open(root.join("rosters")).expect("store");
    assert_eq!(
        store.issue(&roster("north", 1, "Ada")),
        Ok(IssueOutcome::Stored)
    );
    assert_eq!(
        store.issue(&roster("north", 1, "Ada")),
        Ok(IssueOutcome::Unchanged),
        "the same content again changes nothing"
    );
    assert_eq!(
        store.issue(&roster("north", 1, "Grace")),
        Err(RosterStoreError::VersionTaken {
            cohort: "north".into(),
            version: 1
        }),
        "different content at an issued version is refused"
    );
    let held = store
        .get(&CohortId::new("north").expect("cohort"), 1)
        .expect("get")
        .expect("stored");
    assert_eq!(
        held,
        roster("north", 1, "Ada"),
        "the issued roster is unchanged"
    );
}

// covers: DIS-080
#[test]
fn dis_080_a_lower_version_is_refused() {
    let root = Scratch::new();
    let store = RosterStore::open(root.join("rosters")).expect("store");
    let north = CohortId::new("north").expect("cohort");
    store.issue(&roster("north", 2, "Ada")).expect("v2");
    assert_eq!(
        store.issue(&roster("north", 1, "Ada")),
        Err(RosterStoreError::NotNewer {
            held: 2,
            offered: 1
        })
    );
    store.issue(&roster("north", 3, "Ada")).expect("v3");
    assert_eq!(
        store
            .latest(&north)
            .expect("latest")
            .expect("stored")
            .version,
        3,
        "the highest version issued is the latest"
    );
    assert_eq!(store.cohorts().expect("cohorts"), vec![north]);
}

// covers: DIS-080
#[test]
fn dis_080_a_cohort_name_cannot_escape_the_store_directory() {
    let root = Scratch::new();
    let store = RosterStore::open(root.join("rosters")).expect("store");
    for name in ["../outside", "a/b", ".hidden", "..", "with space"] {
        assert_eq!(
            store.issue(&roster(name, 1, "Ada")),
            Err(RosterStoreError::Cohort(name.into())),
            "{name}"
        );
    }
    assert!(!root.join("outside").exists());
}

// covers: DIS-080
#[test]
fn dis_080_a_roster_that_no_longer_matches_its_checksum_is_not_served() {
    let root = Scratch::new();
    let store = RosterStore::open(root.join("rosters")).expect("store");
    store.issue(&roster("north", 1, "Ada")).expect("issue");
    let sum = root.join("rosters").join("north").join("v1.sha256");
    std::fs::write(&sum, format!("{}\n", "0".repeat(64))).expect("tamper");
    assert!(matches!(
        store.get(&CohortId::new("north").expect("cohort"), 1),
        Err(RosterStoreError::Backend(_))
    ));
}

// covers: DIS-080
#[cfg(unix)]
#[test]
fn dis_080_roster_files_are_readable_only_by_their_owner() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = Scratch::new();
    let store = RosterStore::open(root.join("rosters")).expect("store");
    store.issue(&roster("north", 1, "Ada")).expect("issue");
    let mode = |p: PathBuf| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(root.join("rosters")), 0o700);
    assert_eq!(mode(root.join("rosters").join("north")), 0o700);
    assert_eq!(
        mode(root.join("rosters").join("north").join("v1.roster")),
        0o600
    );
    assert_eq!(
        mode(root.join("rosters").join("north").join("v1.sha256")),
        0o600
    );
}

// covers: DIS-080
#[test]
fn dis_080_a_source_serves_the_latest_roster_at_the_tenancys_generation() {
    let root = Scratch::new();
    journal(
        root.path(),
        &[tenancy(1, "acct-a", plain(1, 0, 0), &[("north", 4)])],
    );
    let store = RosterStore::open(root.join("rosters")).expect("store");
    store.issue(&roster("north", 1, "Ada")).expect("v1");
    store.issue(&roster("north", 2, "Ada")).expect("v2");
    let source = FileRosterSource::new(store, root.path());
    let served = source
        .current_rosters(&TenancyId::from([1; 32]))
        .expect("rosters");
    assert_eq!(
        (served.len(), served[0].version, served[0].generation),
        (1, 2, Generation(4))
    );
}

// covers: DIS-023
#[test]
fn dis_023_bundle_files_carry_the_dated_name() {
    let root = Scratch::new();
    let store = FileBundleStore::new(root.path());
    store.put(&sample_bundle(1, 1)).expect("put");
    store.put(&sample_bundle(1, 2)).expect("put");
    let dir = root.path().join("01".repeat(32));
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("tenancy directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".fsb"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "fieldseal-bundle-20270115-1.fsb",
            "fieldseal-bundle-20270115-2.fsb"
        ]
    );
    assert_eq!(
        std::fs::read(dir.join(&names[1])).expect("bytes"),
        sample_bundle(1, 2).bytes,
        "the file holds the bundle bytes exactly"
    );
}

// covers: DIS-015
#[test]
fn dis_015_a_second_bundle_with_an_old_sequence_is_refused() {
    let root = Scratch::new();
    let store = FileBundleStore::new(root.path());
    store.put(&sample_bundle(1, 5)).expect("put");
    assert_eq!(
        store.put(&sample_bundle(1, 3)),
        Err(BundleStoreError::NotNewer {
            held: BundleSeq(5),
            offered: BundleSeq(3)
        })
    );
    assert_eq!(
        store.latest(&TenancyId::from([1; 32])),
        Ok(Some(sample_bundle(1, 5))),
        "the refused bundle changed nothing"
    );
    // A fresh store over the same directory sees the same bundles.
    assert_eq!(
        FileBundleStore::new(root.path()).latest(&TenancyId::from([1; 32])),
        Ok(Some(sample_bundle(1, 5)))
    );
}

// covers: DIS-015
#[test]
fn dis_015_a_bundle_whose_write_was_interrupted_is_not_served() {
    let root = Scratch::new();
    let store = FileBundleStore::new(root.path());
    store.put(&sample_bundle(1, 1)).expect("put");
    // The bundle file of sequence 2 was renamed into place but its metadata never was.
    let dir = root.path().join("01".repeat(32));
    std::fs::write(dir.join("fieldseal-bundle-20270115-2.fsb"), b"half").expect("partial bundle");
    assert_eq!(
        store.latest(&TenancyId::from([1; 32])),
        Ok(Some(sample_bundle(1, 1)))
    );
    store
        .put(&sample_bundle(1, 2))
        .expect("the sequence can be retried");
    assert_eq!(
        store.latest(&TenancyId::from([1; 32])),
        Ok(Some(sample_bundle(1, 2)))
    );
}

// covers: DIS-080
#[test]
fn dis_080_two_writers_racing_for_one_version_store_exactly_one() {
    let root = Scratch::new();
    let dir = root.join("rosters");
    let a = RosterStore::open(&dir).expect("store");
    let b = RosterStore::open(&dir).expect("store");
    for round in 1..=20u64 {
        let barrier = std::sync::Barrier::new(2);
        let (ra, rb) = std::thread::scope(|s| {
            let ha = s.spawn(|| {
                barrier.wait();
                a.issue(&roster("north", round, "Ada"))
            });
            let hb = s.spawn(|| {
                barrier.wait();
                b.issue(&roster("north", round, "Grace"))
            });
            (ha.join().expect("a"), hb.join().expect("b"))
        });
        let taken = Err(RosterStoreError::VersionTaken {
            cohort: "north".into(),
            version: round,
        });
        let stored = Ok(IssueOutcome::Stored);
        assert!(
            (ra == stored && rb == taken) || (ra == taken && rb == stored),
            "round {round}: exactly one writer stores the version and the other gets VersionTaken, got {ra:?} and {rb:?}"
        );
        // Whoever won, the stored roster reads back whole against its checksum.
        let held = a
            .get(&CohortId::new("north").expect("cohort"), round)
            .expect("get")
            .expect("stored");
        assert!(held == roster("north", round, "Ada") || held == roster("north", round, "Grace"));
    }
}

// covers: DIS-080
#[test]
fn dis_080_two_writers_racing_with_identical_content_both_succeed() {
    let root = Scratch::new();
    let dir = root.join("rosters");
    let a = RosterStore::open(&dir).expect("store");
    let b = RosterStore::open(&dir).expect("store");
    let barrier = std::sync::Barrier::new(2);
    let (ra, rb) = std::thread::scope(|s| {
        let ha = s.spawn(|| {
            barrier.wait();
            a.issue(&roster("north", 1, "Ada"))
        });
        let hb = s.spawn(|| {
            barrier.wait();
            b.issue(&roster("north", 1, "Ada"))
        });
        (ha.join().expect("a"), hb.join().expect("b"))
    });
    assert!(ra.is_ok() && rb.is_ok(), "{ra:?} {rb:?}");
    assert!(ra == Ok(IssueOutcome::Stored) || rb == Ok(IssueOutcome::Stored));
}

// covers: DIS-080
#[cfg(unix)]
#[test]
fn dis_080_a_store_directory_wider_than_owner_only_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = Scratch::new();
    let dir = root.join("rosters");
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert!(
        matches!(RosterStore::open(&dir), Err(RosterStoreError::Backend(_))),
        "a root open to others is refused"
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let store = RosterStore::open(&dir).expect("store");
    let cohort = dir.join("north");
    std::fs::create_dir(&cohort).expect("cohort");
    std::fs::set_permissions(&cohort, std::fs::Permissions::from_mode(0o750)).expect("chmod");
    assert!(
        matches!(
            store.issue(&roster("north", 1, "Ada")),
            Err(RosterStoreError::Backend(_))
        ),
        "a cohort directory open to a group is refused"
    );
}

fn withdrawal_of(
    p: &fieldseal_publishing::domain::Publication,
    reason: &str,
) -> fieldseal_publishing::domain::Withdrawal {
    fieldseal_publishing::domain::Withdrawal {
        statement: fieldseal_publishing::domain::WithdrawalStatement::of(
            p,
            reason,
            fieldseal_kernel::time::AuthorityTime(2),
        ),
        signatures: p.signatures.clone(),
        log: p.log.clone(),
        checkpoint: p.checkpoint.clone(),
    }
}

// covers: PUB-062
#[test]
fn pub_062_a_withdrawal_is_stored_once_under_a_name_from_its_content() {
    use fieldseal_publishing::ports::ArtefactRegistry as _;
    let root = Scratch::new();
    let registry = FileRegistry::new(root.path());
    let p = fieldseal_publishing::contract::sample_publication("health-check", "1.0.0", b"bytes");
    let (one, two) = (
        withdrawal_of(&p, "superseded"),
        withdrawal_of(&p, "recalled"),
    );
    registry.withdraw(&one).expect("first");
    registry.withdraw(&one).expect("again");
    registry.withdraw(&two).expect("second");
    let names: Vec<String> = std::fs::read_dir(root.join("withdrawals"))
        .expect("dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "the same withdrawal is one file: {names:?}");
    assert!(
        names
            .iter()
            .all(|n| n.len() == 64 + ".withdrawal".len() && n.ends_with(".withdrawal")),
        "{names:?}"
    );
    // A file named by count, as older versions wrote it, is still read.
    std::fs::write(
        root.join("withdrawals").join("00000000.withdrawal"),
        withdrawal_of(&p, "old").encode(),
    )
    .expect("old file");
    assert_eq!(registry.withdrawals().expect("read").len(), 3);
}

// covers: PUB-062
#[cfg(unix)]
#[test]
fn pub_062_a_registry_directory_that_cannot_be_read_is_an_error_not_an_empty_registry() {
    use fieldseal_publishing::ports::{ArtefactRegistry as _, RegistryError};
    use std::os::unix::fs::PermissionsExt as _;
    let root = Scratch::new();
    let dir = root.join("registry");
    let registry = FileRegistry::new(&dir);
    assert_eq!(
        registry.withdrawals(),
        Ok(vec![]),
        "a registry not yet created is empty"
    );
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let readable_anyway = std::fs::read_dir(&dir).is_ok(); // running as root
    let result = registry.list(fieldseal_publishing::domain::ArtefactKind::Instrument, "x");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
    if !readable_anyway {
        assert!(
            matches!(result, Err(RegistryError::Backend(_))),
            "{result:?}"
        );
    }
}
