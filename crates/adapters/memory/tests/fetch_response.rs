//! `FetchBundle` and `DownloadBundle` (DIS-040, DIS-041) over the in-memory tenancy registry
//! and bundle store. A context's own tests cannot use an adapter (`architecture.toml`), so
//! the Distribution use cases run here.

use std::collections::BTreeMap;

use fieldseal_adapters_memory::demo::{DEMO_SCHEMA, DemoDevice, DemoWorld};
use fieldseal_distribution::application::{BundleDelivery, BundleFetchResponse, DownloadBundle, FetchBundle};
use fieldseal_distribution::application::BuildRequest;
use fieldseal_distribution::domain::{BundleSeq, ConsentState, DistributionError, Roster, RosterEntry, RuntimeProfile, file_name};
use fieldseal_kernel::id::{CohortId, Generation, Salt, SubjectId};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_kernel::cbor;
use fieldseal_publishing::domain::{ArtefactKind, Publication};
use fieldseal_registration::domain::TenancyState;

const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn instrument_bytes() -> Vec<u8> {
    let doc = cbor::map([
        ("apiVersion", text("fieldseal.dev/v1alpha1")),
        ("kind", text("Instrument")),
        ("metadata", cbor::map([("name", text("health-check")), ("version", text("1.0.0"))])),
        (
            "spec",
            cbor::map([
                ("schema", text("^1.0")),
                ("items", Value::Array(vec![cbor::map([("label", text("Age {$roster.age}")), ("from", text("roster.age"))])])),
            ]),
        ),
    ]);
    cbor::encode(&doc).expect("encodes")
}

fn roster() -> Roster {
    Roster {
        cohort: CohortId::new("cohort-a").expect("id"),
        version: 1,
        generation: Generation(1),
        entries: vec![RosterEntry {
            ordinal: 1,
            subject: SubjectId::new("s-001").expect("id"),
            display: "Subject 1".into(),
            attributes: BTreeMap::from([("age".to_owned(), Value::Int(9))]),
            consent: ConsentState::Unknown,
            prior_status: None,
        }],
    }
}

struct Env {
    world: DemoWorld,
    device: DemoDevice,
    instrument: Publication,
}

impl Env {
    fn new() -> Self {
        let world = DemoWorld::new(1, T0).expect("world");
        let instrument = world.publish(ArtefactKind::Instrument, "health-check", "1.0.0", instrument_bytes(), Some(Salt::from([0x5a; 32]))).expect("publishes");
        let device = world
            .register("device-a", &[("cohort-a", 1)], true, RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None })
            .expect("registers");
        world.assign_rosters(&device, vec![roster()]);
        Env { world, device, instrument }
    }

    fn build(&self) -> BundleSeq {
        let request = BuildRequest::new(self.device.tenancy, vec![*self.instrument.address()]);
        self.world.build(&self.world.built_in_policy(), &request).expect("builds").sealed.seq
    }

    fn delivery(&self) -> BundleDelivery<'_> {
        BundleDelivery::new(&self.world.registry, &self.world.bundles)
    }
}

#[test]
fn dis_040_fetch_reports_no_bundle_when_nothing_is_stored() {
    let env = Env::new();
    assert_eq!(env.delivery().fetch(&env.device.tenancy, None), Ok(BundleFetchResponse::NoBundle));
    assert_eq!(env.delivery().fetch(&env.device.tenancy, Some(BundleSeq(3))), Ok(BundleFetchResponse::NoBundle), "what the device holds does not matter when nothing is stored");
}

#[test]
fn dis_040_fetch_reports_current_when_held_is_the_latest() {
    let env = Env::new();
    let seq = env.build();
    assert_eq!(env.delivery().fetch(&env.device.tenancy, Some(seq)), Ok(BundleFetchResponse::Current));
    // A device that claims to hold more than exists is also told it is current: it never gets an older bundle.
    assert_eq!(env.delivery().fetch(&env.device.tenancy, Some(BundleSeq(seq.0 + 5))), Ok(BundleFetchResponse::Current));
}

#[test]
fn dis_040_fetch_returns_the_bundle_when_held_is_older() {
    let env = Env::new();
    let first = env.build();
    let second = env.build();
    assert_eq!((first, second), (BundleSeq(1), BundleSeq(2)));
    for held in [None, Some(BundleSeq(0)), Some(first)] {
        match env.delivery().fetch(&env.device.tenancy, held) {
            Ok(BundleFetchResponse::Bundle(b)) => assert_eq!((b.tenancy, b.seq), (env.device.tenancy, second)),
            other => panic!("expected the latest bundle for held {held:?}, got {other:?}"),
        }
    }
}

#[test]
fn dis_040_fetch_refuses_an_ineligible_tenancy_before_it_reads_the_store() {
    let env = Env::new();
    env.build();
    for (state, expected) in [
        (TenancyState::Flagged, DistributionError::Withheld(vec!["tenancy-flagged".into()])),
        (TenancyState::Lost, DistributionError::Withheld(vec!["tenancy-lost".into()])),
        (TenancyState::Retired, DistributionError::Withheld(vec!["tenancy-retired".into()])),
        (TenancyState::Pending, DistributionError::NotRegistered),
    ] {
        env.world.set_state(&env.device.tenancy, state).expect("state");
        // A bundle is stored, so an answer from the store would be `Bundle`.
        assert_eq!(env.delivery().fetch(&env.device.tenancy, None), Err(expected), "{state:?}");
    }
    let unknown = fieldseal_kernel::id::TenancyId::from([9; 32]);
    assert_eq!(env.delivery().fetch(&unknown, None), Err(DistributionError::NotRegistered));
}

#[test]
fn dis_041_download_reports_withheld_no_bundle_built_when_nothing_is_stored() {
    let env = Env::new();
    assert_eq!(env.delivery().download(&env.device.device), Err(DistributionError::Withheld(vec!["no-bundle-built".into()])));
    env.build();
    let (name, bundle) = env.delivery().download(&env.device.device).expect("the stored bundle");
    assert_eq!(name, file_name(bundle.issued.0, bundle.seq.0));
}
