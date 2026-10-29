//! The file adapters of Intake's ports satisfy the shared contracts (INT-006, INT-040,
//! INT-070). Each case uses a fresh temporary directory per call.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fieldseal_adapters_file::instruments::PublishedInstruments;
use fieldseal_adapters_file::rosters::{FileRosterHistory, record_issued};
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_file::tenancy::FileTenancyRegistry;
use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{CohortId, Digest, SubjectId, TenancyId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_registration::contract::sample_tenancy;
use fieldseal_registration::domain::TenancyState;
use fieldseal_registration::ports::RegistryStore;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("fieldseal-intake-ports-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// covers: INT-006
#[test]
fn int_006_the_file_tenancy_registry_satisfies_the_contract() {
    let s = Scratch::new();
    let mut t = sample_tenancy(1, "account-1");
    t.state = TenancyState::Registered;
    FileRegistryStore::open(s.path()).expect("journal").put_tenancy(&t).expect("tenancy");
    fieldseal_intake::contract::tenancy_registry_contract(|| FileTenancyRegistry::new(s.path()), (t.id, t.handle));
}

// covers: INT-040
#[test]
fn int_040_the_file_roster_history_satisfies_the_contract() {
    let tenancy = TenancyId::from([1; 32]);
    let s = Scratch::new();
    // `record_issued` makes its own owner-only directory.
    let issued = s.path().join("issued");
    for (cohort, version) in [("village-a", 1), ("cohort-a", 2), ("cohort-a", 1)] {
        let roster = IssuedRoster {
            cohort: CohortId::new(cohort).expect("cohort"),
            version,
            address: Digest::from([version as u8; 32]),
            issued_at: AuthorityTime(1_000),
            consent: [(SubjectId::new("s-1").expect("subject"), IssuedConsent::Granted)].into_iter().collect(),
        };
        record_issued(&issued, &tenancy, &roster).expect("recorded");
    }
    fieldseal_intake::contract::roster_history_contract(|| FileRosterHistory::new(&issued), tenancy);
}

// covers: INT-070
#[test]
fn int_070_the_published_instruments_reader_satisfies_the_contract() {
    let s = Scratch::new();
    let world = DemoWorld::new(7, AuthorityTime(1_800_000_000_000)).expect("a demo world");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let doc = fieldseal_adapters_authoring::decode_path(&repo.join("examples/surveys/household-water-access")).expect("the survey decodes");
    let publication =
        world.publish(ArtefactKind::Instrument, "household-water-access", "1.0.0", cbor::encode(&doc).expect("encodes"), Some(DemoWorld::salt_for("household-water-access"))).expect("published");
    std::fs::write(s.path().join("water.published"), publication.encode()).expect("write");
    let fingerprint = publication.artefact.fingerprint().expect("an instrument has a fingerprint");
    fieldseal_intake::contract::instrument_source_contract(|| PublishedInstruments::new(s.path(), world.trust.clone(), world.publishing.clone()), fingerprint);
}
