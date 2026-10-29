//! Fixtures for the intake tests: a practice authority, practice devices, the two sample
//! instruments, in-memory adapters, and a builder for exports whose every rule can be broken
//! on purpose.

#![allow(dead_code, missing_docs, unused_imports)]

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_adapters_memory::intake::practice::{
    ExportSpec, JournalBuilder, PracticeAuthority, PracticeDevice, Written, at, manifest_for, tick,
};
use fieldseal_adapters_memory::intake::{
    MemoryDataPlatform, MemoryInstrumentSource, MemoryRosterHistory, MemorySubmissionStore, MemoryTenancyRegistry,
};
use fieldseal_adapters_memory::policy::BuiltInPolicyEngine;
use fieldseal_adapters_memory::trust::SeededRandom;
use fieldseal_instrument::application::validate_instrument;
use fieldseal_instrument::domain::Instrument;
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster, SubmissionSource, TenancyView};
use fieldseal_intake::gate::{IngestReport, IntakeService};
use fieldseal_intake::wire::{CertWindow, ExportManifest, Payload};
use fieldseal_kernel::digest::{instrument_fingerprint, lower_hex, sha256};
use fieldseal_kernel::id::{CohortId, Digest, Fingerprint, ItemPath, RecordId, Salt, SubjectId};
use fieldseal_kernel::payload::{ConsentRef, ItemsPayload, Layout, Mode, Tick};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Decimal, Value, cbor};
use fieldseal_policy::domain::EffectivePolicy;
use fieldseal_policy::fixtures::{DocBuilder, effective, effective_default};

pub const COHORT: &str = "cohort-a";
/// A digest of 32 copies of `b`.
pub fn d(b: u8) -> Digest {
    Digest::from([b; 32])
}

pub fn roster() -> Digest {
    d(0x11)
}

pub fn roster_v2() -> Digest {
    d(0x12)
}

pub fn build_anchor() -> Digest {
    sha256(b"practice build")
}

pub fn anchor1() -> Digest {
    sha256(b"anchor 1")
}

pub fn sid(bytes: &[u8]) -> SubjectId {
    SubjectId::new(lower_hex(bytes)).expect("subject id")
}

pub const S_GRANTED: &[u8] = b"subject-granted";
pub const S_UNKNOWN: &[u8] = b"subject-unknown";
pub const S_REFUSED: &[u8] = b"subject-refused";

pub fn int(n: i128) -> Value {
    Value::Int(n)
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

pub fn dec(s: &str) -> Value {
    Value::Decimal(Decimal::parse(s).expect("decimal"))
}

pub fn arr(items: &[Value]) -> Value {
    Value::Array(items.to_vec())
}

pub fn nr(code: &str) -> Value {
    cbor::map([("nr", text(code))])
}

pub fn load(name: &str) -> Instrument {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/surveys");
    let loaded = fieldseal_adapters_authoring::SurveyTree::open(&root).and_then(|tree| tree.survey(name)).expect("the survey folder").load().expect("resolves");
    validate_instrument(&loaded.instrument).expect("valid").instrument
}

pub fn fingerprint_of(i: &Instrument) -> Fingerprint {
    instrument_fingerprint(&Salt::from([5; 32]), &cbor::encode(&i.to_value()).expect("encodes"))
}

pub struct World {
    pub authority: PracticeAuthority,
    pub devices: Vec<PracticeDevice>,
    pub store: MemorySubmissionStore,
    pub registry: MemoryTenancyRegistry,
    pub rosters: MemoryRosterHistory,
    pub instruments: MemoryInstrumentSource,
    pub platform: MemoryDataPlatform,
    pub engine: BuiltInPolicyEngine,
    pub effective: EffectivePolicy,
    pub random: SeededRandom,
    pub water: Instrument,
    pub water_fp: Fingerprint,
    pub meals: Instrument,
    pub meals_fp: Fingerprint,
}

impl World {
    pub fn new() -> Self {
        Self::with(|_| {}, effective_default())
    }

    pub fn with_policy(effective: EffectivePolicy) -> Self {
        Self::with(|_| {}, effective)
    }

    pub fn with_views(f: impl FnOnce(&mut Vec<TenancyView>)) -> Self {
        Self::with(f, effective_default())
    }

    pub fn with(f: impl FnOnce(&mut Vec<TenancyView>), effective: EffectivePolicy) -> Self {
        let authority = PracticeAuthority::new(7);
        let devices = vec![PracticeDevice::new("device-a"), PracticeDevice::new("device-b")];
        let mut views: Vec<TenancyView> = devices.iter().map(|d| TenancyView::new(d.tenancy, d.handle, vec![d.public_key()])).collect();
        f(&mut views);
        let water = load("household-water-access");
        let meals = load("school-meals-baseline");
        let (water_fp, meals_fp) = (fingerprint_of(&water), fingerprint_of(&meals));
        let instruments = MemoryInstrumentSource::new();
        instruments.add(water_fp, water.clone());
        instruments.add(meals_fp, meals.clone());
        let rosters = MemoryRosterHistory::new();
        for dev in &devices {
            rosters.record(
                dev.tenancy,
                IssuedRoster {
                    cohort: CohortId::new(COHORT).expect("id"),
                    version: 1,
                    address: roster(),
                    issued_at: at(1),
                    consent: BTreeMap::from([
                        (sid(S_GRANTED), IssuedConsent::Granted),
                        (sid(S_UNKNOWN), IssuedConsent::Unknown),
                        (sid(S_REFUSED), IssuedConsent::Refused),
                    ]),
                },
            );
        }
        Self {
            authority,
            devices,
            store: MemorySubmissionStore::new(),
            registry: MemoryTenancyRegistry::new(views),
            rosters,
            instruments,
            platform: MemoryDataPlatform::new(),
            engine: BuiltInPolicyEngine,
            effective,
            random: SeededRandom::new(99),
            water,
            water_fp,
            meals,
            meals_fp,
        }
    }

    pub fn service(&self) -> IntakeService<'_> {
        IntakeService {
            store: &self.store,
            registry: &self.registry,
            rosters: &self.rosters,
            instruments: &self.instruments,
            platform: &self.platform,
            custody: &self.authority.custody,
            policy: &self.engine,
            effective: &self.effective,
            random: &self.random,
            trust: &self.authority.bundle,
            revocations: vec![],
            receipt_key: self.authority.receipt_key,
            caller: "intake-test",
        }
    }

    pub fn now() -> AuthorityTime {
        at(20)
    }

    pub fn ingest(&self, bytes: &[u8]) -> IngestReport {
        self.service().ingest(bytes, SubmissionSource::File, Self::now()).expect("no backend failure")
    }

    pub fn device(&self) -> &PracticeDevice {
        &self.devices[0]
    }

    pub fn window() -> CertWindow {
        CertWindow { not_before: at(0), not_after: at(100), grace: 30 * AuthorityTime::DAY }
    }
}

/// The ticks of the standard journal: `open` at slot 1, `import` at 2, an anchor at 3, and
/// items from slot 10 on under the anchor.
pub fn t(slot: u64) -> Tick {
    tick(anchor1(), slot)
}

pub fn items(instrument: Fingerprint, subject: &[u8], consent: ConsentRef, values: &[(&str, Value)], tick: Tick, flags: Option<Vec<String>>) -> Payload {
    Payload::Items(Box::new(ItemsPayload {
        tick,
        instrument,
        layout: Layout::Default,
        lang: vec!["en".into()],
        subject: subject.to_vec(),
        consent_ref: consent,
        mode: Mode::First,
        values: values.iter().map(|(k, v)| (ItemPath::new(*k).expect("path"), v.clone())).collect(),
        overrides: None,
        flags,
    }))
}

pub fn roster_ref() -> ConsentRef {
    ConsentRef::Roster { roster: roster(), version: 1 }
}

/// A journal built up to the point where items can be added, with the manifest and
/// certificate to go with it.
pub struct Draft<'w> {
    pub world: &'w World,
    pub device: &'w PracticeDevice,
    pub records: Vec<Written>,
    pub journal: Vec<u8>,
    pub manifest: ExportManifest,
    pub parity: bool,
}

impl<'w> Draft<'w> {
    /// `open`, `import`, an anchor, then whatever `f` adds.
    pub fn standard(world: &'w World, device: &'w PracticeDevice, f: impl FnOnce(&mut JournalBuilder<'_>)) -> Self {
        let mut jb = device.journal(world.authority.record_recipient(), world.authority.record_key.id);
        jb.push(&jb.open_payload(tick(build_anchor(), 1), build_anchor()));
        jb.push(&Payload::Import {
            tick: tick(build_anchor(), 2),
            bundle: d(0x21),
            artefacts: vec![],
            rosters: vec![fieldseal_intake::wire::ImportedRoster { cohort: COHORT.into(), version: 1, address: roster() }],
        });
        jb.push(&Payload::Anchor {
            tick: tick(build_anchor(), 3),
            kind: fieldseal_intake::wire::AnchorKind::TimeToken,
            address: anchor1(),
            authority_time: at(5),
        });
        f(&mut jb);
        Self::finish(world, device, jb)
    }

    /// Finishes a journal builder into a draft with a valid manifest and certificate.
    pub fn finish(world: &'w World, device: &'w PracticeDevice, jb: JournalBuilder<'_>) -> Self {
        let journal = jb.journal();
        let records = jb.records().to_vec();
        let mut manifest = manifest_for(device, &records, &journal, build_anchor());
        manifest.certificate = Some(world.authority.tenancy_certificate(device, World::window(), &[(COHORT, 3)]));
        Self { world, device, records, journal, manifest, parity: false }
    }

    pub fn spec(&self) -> ExportSpec<'_> {
        ExportSpec {
            device: self.device,
            manifest: self.manifest.clone(),
            journal: self.journal.clone(),
            seal_to: self.world.authority.record_recipient(),
            key_index: 0,
            parity: self.parity,
        }
    }

    pub fn export(&self) -> Vec<u8> {
        self.spec().build().expect("builds")
    }
}

/// Observation rows of the landed instrument, as `(item, reading)` pairs for readability.
pub fn rows(world: &World, fp: &Fingerprint) -> Vec<fieldseal_intake::domain::LandedObservation> {
    use fieldseal_intake::ports::DataPlatform;
    world.platform.observations(fp).expect("read")
}

pub fn find<'a>(rows: &'a [fieldseal_intake::domain::LandedObservation], item: &str) -> Vec<&'a fieldseal_intake::domain::LandedObservation> {
    rows.iter().filter(|r| r.observation.item.as_str() == item).collect()
}

pub fn flags(r: &fieldseal_intake::domain::LandedObservation) -> BTreeSet<String> {
    r.observation.flags.clone()
}

pub fn record_id_of(w: &Written) -> RecordId {
    w.id
}

/// Splits an export file into `(type, body)` sections.
pub fn sections(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 4;
    while pos < bytes.len() {
        let len = u32::from_be_bytes([bytes[pos + 1], bytes[pos + 2], bytes[pos + 3], bytes[pos + 4]]) as usize;
        out.push((bytes[pos], bytes[pos + 9..pos + 9 + len].to_vec()));
        pos += 9 + len;
    }
    out
}

/// Joins sections into an export file with correct lengths and CRCs.
pub fn assemble(sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"FSX1".to_vec();
    for (kind, body) in sections {
        out.push(*kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&fieldseal_kernel::crc::crc32c(body).to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Rewrites one section body and keeps every CRC valid, so that only the signature or the
/// hashes notice.
pub fn tamper(bytes: &[u8], kind: u8, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut s = sections(bytes);
    let body = &mut s.iter_mut().find(|(k, _)| *k == kind).expect("section").1;
    f(body);
    assemble(&s)
}

/// Whether nothing at all landed for the tenancy: no envelope, row, case, loss or finding.
pub fn nothing_landed(w: &World, device: &PracticeDevice) -> bool {
    use fieldseal_intake::ports::DataPlatform;
    w.platform.envelopes(&device.tenancy).expect("read").is_empty()
        && w.platform.observations(&w.water_fp).expect("read").is_empty()
        && w.platform.observations(&w.meals_fp).expect("read").is_empty()
        && w.platform.consent_cases().expect("read").is_empty()
        && w.platform.losses().expect("read").is_empty()
        && w.platform.findings().expect("read").is_empty()
}

/// A simple water-instrument record for the granted subject.
pub fn simple(w: &World, slot: u64) -> Payload {
    items(w.water_fp, S_GRANTED, roster_ref(), &[("household.members", int(3))], t(slot), None)
}
