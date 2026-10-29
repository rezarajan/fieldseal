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
use fieldseal_kernel::cbor;
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
        consent_covers: vec!["survey-a".to_owned()],
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

#[test]
fn reg_046_the_file_registry_store_satisfies_the_registry_store_contract() {
    let scratch = Scratch::new();
    let n = AtomicU64::new(0);
    fieldseal_registration::contract::registry_store_contract(|| {
        FileRegistryStore::open(scratch.join(&format!("store-{}", n.fetch_add(1, Ordering::Relaxed)))).expect("store")
    });
}

#[test]
fn reg_046_assignments_and_roster_issues_survive_a_restart_of_the_journal() {
    use fieldseal_registration::contract::sample_assignment;
    use fieldseal_registration::domain::RosterIssue;
    let scratch = Scratch::new();
    let issue = RosterIssue {
        seq: fieldseal_kernel::id::Seq(0),
        cohort: CohortId::new("cohort-a").expect("cohort"),
        version: 2,
        digest: fieldseal_kernel::id::Digest::from([5; 32]),
        by: fieldseal_registration::domain::AccountId("operator".into()),
        roles: vec!["operator".into()],
        methods: vec!["hwk".into(), "phr".into()],
        at: fieldseal_kernel::time::AuthorityTime(77),
    };
    let (assignments, issues) = {
        let store = FileRegistryStore::open(scratch.path()).expect("store");
        store.put_assignment(&sample_assignment("acct-a", "survey-a", "cohort-a")).expect("put");
        store.put_assignment(&sample_assignment("acct-b", "survey-b", "cohort-b")).expect("put");
        store.put_roster_issue(&issue).expect("put");
        (store.assignments().expect("assignments"), store.roster_issues().expect("issues"))
    };
    assert_eq!(assignments.len(), 2);
    let reopened = FileRegistryStore::open(scratch.path()).expect("reopen");
    assert_eq!(reopened.assignments(), Ok(assignments), "oldest first, with the same seq");
    assert_eq!(reopened.roster_issues(), Ok(issues));
    // A new record continues the numbering.
    reopened.put_assignment(&sample_assignment("acct-c", "survey-a", "cohort-b")).expect("put");
    assert_eq!(reopened.assignments().expect("assignments").last().map(|a| a.seq), Some(fieldseal_kernel::id::Seq(3)));
    // The read-only snapshot another process takes sees them too.
    assert_eq!(FileRegistryStore::snapshot(scratch.path()).expect("snapshot").assignments().expect("assignments").len(), 3);
}

#[test]
fn reg_046_a_journal_record_that_does_not_decode_is_refused_not_skipped() {
    use std::io::Write as _;
    let scratch = Scratch::new();
    drop(FileRegistryStore::open(scratch.path()).expect("store"));
    // An assignment record (operation 10) whose cohort is empty.
    let mut payload = vec![10u8];
    for text in ["acct", "survey", ""] {
        payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
        payload.extend_from_slice(text.as_bytes());
    }
    let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&payload);
    std::fs::OpenOptions::new().append(true).open(scratch.path().join("registry.journal")).expect("journal").write_all(&framed).expect("write");
    assert!(FileRegistryStore::open(scratch.path()).is_err());
}

#[test]
fn reg_046_a_corrupt_assignment_record_makes_the_store_refuse_to_open() {
    use fieldseal_registration::contract::sample_assignment;
    let journal_after = |assignment| {
        let scratch = Scratch::new();
        FileRegistryStore::open(scratch.path()).expect("store").put_assignment(&assignment).expect("put");
        scratch
    };
    // A good record opens.
    let good = journal_after(sample_assignment("acct", "survey", "cohort-a"));
    assert!(FileRegistryStore::open(good.path()).is_ok());
    // A byte after the record's last field, inside its frame.
    let trailing = journal_after(sample_assignment("acct", "survey", "cohort-a"));
    let path = trailing.path().join("registry.journal");
    let mut bytes = std::fs::read(&path).expect("journal");
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) + 1;
    bytes[..4].copy_from_slice(&len.to_be_bytes());
    bytes.push(0);
    std::fs::write(&path, bytes).expect("write");
    assert!(FileRegistryStore::open(trailing.path()).is_err(), "a trailing byte");
    // Empty account, survey and `by`; generation 0.
    let mut empty_by = sample_assignment("acct", "survey", "cohort-a");
    empty_by.by.0.clear();
    let mut generation_0 = sample_assignment("acct", "survey", "cohort-a");
    generation_0.generation = Generation(0);
    for (why, bad) in [
        ("an empty account", sample_assignment("", "survey", "cohort-a")),
        ("an empty survey", sample_assignment("acct", "", "cohort-a")),
        ("an empty by", empty_by),
        ("generation 0", generation_0),
    ] {
        let dir = journal_after(bad);
        assert!(FileRegistryStore::open(dir.path()).is_err(), "{why}");
    }
}

#[test]
fn reg_046_the_survey_and_cohort_directories_answer_from_the_registry_and_the_roster_store() {
    use fieldseal_adapters_file::directories::{PublishedSurveys, StoredCohorts};
    use fieldseal_registration::ports::{CohortDirectory, SurveyDirectory};
    let scratch = Scratch::new();
    let surveys = PublishedSurveys(FileRegistry::new(scratch.join("registry")));
    assert!(!surveys.exists("school-meals-baseline"), "an empty registry publishes nothing");
    let store = RosterStore::open(scratch.join("rosters")).expect("store");
    let cohorts = StoredCohorts(RosterStore::open(scratch.join("rosters")).expect("store"));
    let cohort = CohortId::new("village-a").expect("cohort");
    assert!(!cohorts.exists(&cohort));
    store.issue(&roster("village-a", 1, "Bo")).expect("issue");
    assert!(cohorts.exists(&cohort));
    assert!(!cohorts.exists(&CohortId::new("village-b").expect("cohort")));
    assert!(!cohorts.exists(&CohortId::new("../escape").expect("cohort")), "a name that can't be stored is not a cohort");
}

#[test]
fn reg_047_the_file_roster_issuer_checks_before_it_writes_and_maps_the_store_outcomes() {
    use fieldseal_adapters_file::roster_issuer::FileRosterIssuer;
    use fieldseal_registration::ports::{IssueOutcome as Out, RosterIssuer};
    let scratch = Scratch::new();
    let issuer = FileRosterIssuer::new(RosterStore::open(scratch.join("rosters")).expect("store"));
    let cohort = CohortId::new("village-a").expect("cohort");
    let body = |version: i128, display: &str| {
        let subject = cbor::map([("subject", Value::Text("s-1".into())), ("display", Value::Text(display.into()))]);
        cbor::encode(&cbor::map([
            ("cohort", Value::Text("village-a".into())),
            ("version", Value::Int(version)),
            ("subjects", Value::Array(vec![subject])),
        ]))
        .expect("encodable")
    };
    let Out::Issued { version: 2, digest } = issuer.issue(&cohort, &body(2, "Bo"), &[]) else { panic!("issued") };
    assert_eq!(issuer.issue(&cohort, &body(2, "Bo"), &[]), Out::AlreadyIssued { version: 2, digest });
    assert_eq!(issuer.issue(&cohort, &body(2, "Other"), &[]), Out::VersionTaken);
    assert_eq!(issuer.issue(&cohort, &body(1, "Bo"), &[]), Out::NotNewer);
    assert!(matches!(issuer.issue(&CohortId::new("village-b").expect("cohort"), &body(3, "Bo"), &[]), Out::Invalid(_)), "the roster names another cohort");
    assert!(matches!(issuer.issue(&cohort, b"not cbor", &[]), Out::Invalid(_)));
    // Bytes that decode but are not in canonical form (a map with keys in the wrong order).
    assert!(matches!(issuer.issue(&cohort, b"\xa2\x61b\x01\x61a\x02", &[]), Out::Invalid(_)));
    assert_eq!(issuer.store().versions(&cohort).expect("versions"), vec![2], "nothing else was written");
    // The stored digest is the checksum the store keeps and `roster list` prints.
    assert_eq!(digest, fieldseal_kernel::digest::sha256(&issuer.store().get(&cohort, 2).expect("get").expect("stored").encode()));
}

#[test]
fn reg_047_the_file_roster_issuer_satisfies_the_roster_issuer_contract() {
    use fieldseal_adapters_file::roster_issuer::FileRosterIssuer;
    let scratch = Scratch::new();
    let issuer = FileRosterIssuer::new(RosterStore::open(scratch.join("rosters")).expect("store"));
    let cohort = CohortId::new("village-a").expect("cohort");
    fieldseal_registration::contract::roster_issuer_contract(&issuer, &cohort, |cohort, version, display| {
        let subject = cbor::map([("subject", Value::Text("s-1".into())), ("display", Value::Text(display.into()))]);
        cbor::encode(&cbor::map([
            ("cohort", Value::Text(cohort.as_str().into())),
            ("version", Value::Int(i128::from(version))),
            ("subjects", Value::Array(vec![subject])),
        ]))
        .expect("encodable")
    });
}

#[test]
fn reg_046_the_file_directories_satisfy_the_directory_contracts() {
    use fieldseal_adapters_file::directories::StoredCohorts;
    let scratch = Scratch::new();
    let store = RosterStore::open(scratch.join("rosters")).expect("store");
    store.issue(&roster("village-a", 1, "Bo")).expect("issue");
    fieldseal_registration::contract::cohort_directory_contract(&StoredCohorts(store), &CohortId::new("village-a").expect("cohort"));
}

#[test]
fn reg_046_the_published_surveys_satisfy_the_survey_directory_contract() {
    use fieldseal_adapters_file::directories::PublishedSurveys;
    use fieldseal_publishing::contract::sample_publication;
    use fieldseal_publishing::ports::ArtefactRegistry;
    let scratch = Scratch::new();
    let registry = FileRegistry::new(scratch.join("registry"));
    registry.put(&sample_publication("school-meals-baseline", "1.0.0", b"instrument bytes")).expect("put");
    fieldseal_registration::contract::survey_directory_contract(&PublishedSurveys(registry), "school-meals-baseline");
}
