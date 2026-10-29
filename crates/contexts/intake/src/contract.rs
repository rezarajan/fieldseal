//! Contract tests for adapters of the Intake context's driven ports.

use std::collections::BTreeSet;

use fieldseal_kernel::id::{Digest, Fingerprint, Generation, ItemPath, RecordId, Seq, SubjectId, TenancyHandle, TenancyId};
use fieldseal_kernel::payload::Layout;
use fieldseal_kernel::time::AuthorityTime;

use crate::domain::{
    ConsentBasis, ConsentCase, ConsentDecision, Finding, FindingKind, LandedEnvelope, LossLedgerEntry, Observation,
    ObservedValue, Reading, SubmissionId,
};
use crate::ports::{DataPlatform, InstrumentSource, LandingBatch, PopLedger, RosterHistory, SubmissionStore, TenancyRegistry};

/// An observation fixture.
pub fn sample_observation(instrument: u8, record: u8) -> Observation {
    Observation {
        instrument: Fingerprint::from([instrument; 32]),
        layout: Layout::Default,
        lang: vec!["en".into()],
        subject: SubjectId::new("s-1").expect("id"),
        item: ItemPath::new("body.weight").expect("path"),
        reading: Reading::Value(ObservedValue::Decimal("41.2".into())),
        value_type: "decimal",
        unit: Some("kg".into()),
        source: RecordId::from([record; 16]),
        tenancy: TenancyId::from([7; 32]),
        generation: Generation(1),
        seq: Seq(u64::from(record)),
        not_before: Some(AuthorityTime(10)),
        not_after: AuthorityTime(20),
        consent_basis: "not-required".into(),
        flags: BTreeSet::new(),
    }
}

/// [`SubmissionStore`]: content-addressed and write-once.
pub fn submission_store_contract<S: SubmissionStore>(make: impl Fn() -> S) {
    let store = make();
    let a = store.put(b"export-a").expect("put");
    assert_eq!(store.put(b"export-a"), Ok(a), "the same bytes have the same identifier");
    let b = store.put(b"export-b").expect("put");
    assert_ne!(a, b, "different bytes have different identifiers");
    assert_eq!(store.get(&a), Ok(Some(b"export-a".to_vec())), "stored bytes are unchanged");
    assert_eq!(store.get(&SubmissionId(Digest::from([0xee; 32]))), Ok(None), "an unknown identifier has no bytes");
}

/// [`TenancyRegistry`]: `known` is found by ID and handle consistently; unknown is `None`.
pub fn tenancy_registry_contract<R: TenancyRegistry>(make: impl Fn() -> R, known: (TenancyId, TenancyHandle)) {
    let registry = make();
    let by_id = registry.by_id(&known.0).expect("lookup").expect("known tenancy");
    let by_handle = registry.by_handle(&known.1).expect("lookup").expect("known handle");
    assert_eq!(by_id, by_handle, "the same view by ID and by handle");
    assert_eq!(registry.by_id(&TenancyId::from([0xee; 32])), Ok(None));
    assert_eq!(registry.by_handle(&TenancyHandle::from([0xee; 16])), Ok(None));
}

/// [`RosterHistory`]: ordered by cohort, then ascending version.
pub fn roster_history_contract<H: RosterHistory>(make: impl Fn() -> H, tenancy: TenancyId) {
    let history = make();
    let issued = history.issued(&tenancy).expect("history");
    assert!(!issued.is_empty(), "the fixture tenancy must have rosters");
    for pair in issued.windows(2) {
        let ordered = pair[0].cohort < pair[1].cohort || (pair[0].cohort == pair[1].cohort && pair[0].version < pair[1].version);
        assert!(ordered, "versions are ordered by cohort, then ascending");
    }
    assert!(history.issued(&TenancyId::from([0xee; 32])).expect("history").is_empty(), "an unknown tenancy has none");
}

/// [`InstrumentSource`]: `known` is returned, any other fingerprint is `None`.
pub fn instrument_source_contract<S: InstrumentSource>(make: impl Fn() -> S, known: Fingerprint) {
    let source = make();
    assert!(source.instrument(&known).expect("lookup").is_some(), "the fixture instrument is held");
    assert!(source.instrument(&Fingerprint::from([0xee; 32])).expect("lookup").is_none());
}

fn envelope(record: u8, tenancy: u8, seq: u64) -> LandedEnvelope {
    LandedEnvelope {
        record: RecordId::from([record; 16]),
        tenancy: TenancyId::from([tenancy; 32]),
        seq: Seq(seq),
        hash: Digest::from([record; 32]),
        body: vec![record; 8],
        evidence: (record == 3).then_some(([record; 16], Digest::from([0x33; 32]))),
    }
}

/// [`DataPlatform`]: atomic and append-only; keyed by fingerprint; exclusion flags and never
/// deletes; consent cases are replaced by key; envelopes, evidence and losses are readable.
pub fn data_platform_contract<D: DataPlatform>(make: impl Fn() -> D) {
    let platform = make();
    let case = |decision| ConsentCase {
        tenancy: TenancyId::from([7; 32]),
        subject: SubjectId::new("s-1").expect("id"),
        instrument: Fingerprint::from([1; 32]),
        basis: ConsentBasis::NotRequired,
        decision,
        sampled: false,
        evidence: vec![],
        records: vec![RecordId::from([1; 16])],
        history: vec![],
    };
    let batch = LandingBatch {
        submission: Some(SubmissionId(Digest::from([9; 32]))),
        envelopes: vec![envelope(2, 7, 2), envelope(1, 7, 1), envelope(3, 8, 0)],
        observations: vec![sample_observation(1, 1), sample_observation(2, 2)],
        findings: vec![Finding::new(FindingKind::Flag, "INT-011", "late")],
        consent: vec![case(ConsentDecision::Pending)],
        losses: vec![LossLedgerEntry { tenancy: TenancyId::from([7; 32]), from: Seq(5), through: Seq(6), reason: "gap".into() }],
        exclusions: vec![(RecordId::from([2; 16]), "consent-pending".into())],
    };
    platform.land(&batch).expect("land");

    assert_eq!(
        platform.instruments().expect("instruments"),
        vec![Fingerprint::from([1; 32]), Fingerprint::from([2; 32])],
        "an instrument is listed once, ascending, after a landing that has an observation for it"
    );
    let first = platform.observations(&Fingerprint::from([1; 32])).expect("read");
    assert_eq!(first.len(), 1, "observations are keyed by instrument fingerprint");
    assert_eq!(first[0].excluded, None);
    let second = platform.observations(&Fingerprint::from([2; 32])).expect("read");
    assert_eq!(second[0].excluded.as_deref(), Some("consent-pending"), "landing can exclude by record");

    platform.exclude(&[RecordId::from([1; 16])], "consent rejected").expect("exclude");
    let after = platform.observations(&Fingerprint::from([1; 32])).expect("read");
    assert_eq!(after.len(), 1, "exclusion never deletes");
    assert_eq!(after[0].excluded.as_deref(), Some("consent rejected"));
    assert_eq!(platform.observations(&Fingerprint::from([2; 32])).expect("read")[0].excluded.as_deref(), Some("consent-pending"), "exclusion affects only the named sources");
    platform.reinstate(&[RecordId::from([1; 16])]).expect("reinstate");
    assert_eq!(platform.observations(&Fingerprint::from([1; 32])).expect("read")[0].excluded, None, "a reversed exclusion is lifted, not deleted");

    let seven = platform.envelopes(&TenancyId::from([7; 32])).expect("envelopes");
    assert_eq!(seven.iter().map(|e| e.seq.0).collect::<Vec<_>>(), vec![1, 2], "envelopes are per tenancy, by ascending seq");
    assert_eq!(seven[0].body, vec![1; 8], "the raw envelope is kept unchanged");
    assert_eq!(platform.evidence(&[3; 16]).expect("evidence"), Some(Digest::from([0x33; 32])));
    assert_eq!(platform.evidence(&[4; 16]).expect("evidence"), None);

    platform.land(&LandingBatch { consent: vec![case(ConsentDecision::Accepted)], ..LandingBatch::default() }).expect("land");
    assert_eq!(platform.instruments().expect("instruments").len(), 2, "a landing with no observation lists no instrument");
    let key = (TenancyId::from([7; 32]), SubjectId::new("s-1").expect("id"), Fingerprint::from([1; 32]));
    assert_eq!(platform.consent_case(&key.0, &key.1, &key.2).expect("case").map(|c| c.decision), Some(ConsentDecision::Accepted), "the latest decision replaces the earlier one");
    assert_eq!(platform.consent_cases().expect("cases").len(), 1);
    assert_eq!(platform.losses().expect("losses").len(), 1);
    assert_eq!(platform.findings().expect("findings").len(), 1);
}

/// [`PopLedger`]: a token identifier is accepted once within its window, per tenancy, and
/// may be forgotten after it.
pub fn pop_ledger_contract<L: PopLedger>(make: impl Fn() -> L) {
    let ledger = make();
    let (a, b) = (TenancyId::from([1; 32]), TenancyId::from([2; 32]));
    let jti = [9u8; 16];
    let (now, until) = (AuthorityTime(1_000), AuthorityTime(301_000));
    assert_eq!(ledger.first_use(&a, &jti, now, until), Ok(true), "the first use is accepted");
    assert_eq!(ledger.first_use(&a, &jti, now, until), Ok(false), "a replay within the window is refused");
    assert_eq!(ledger.first_use(&b, &jti, now, until), Ok(true), "identifiers are per tenancy");
    assert_eq!(ledger.first_use(&a, &[8u8; 16], now, until), Ok(true), "another identifier is a fresh token");
    assert_eq!(ledger.first_use(&a, &jti, AuthorityTime(400_000), AuthorityTime(700_000)), Ok(true), "forgotten once the window has passed");
}
