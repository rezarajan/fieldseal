//! `BundleContent` (WIRE-094, WIRE-095), the plaintext inside the seal, and the
//! `BundleManifest` that summarises it (distribution §2, §6).

use std::collections::BTreeMap;

use fieldseal_kernel::cbor;
use fieldseal_kernel::error::{ErrorCode, WireError};
use fieldseal_kernel::id::{CohortId, ContentAddress, Generation, TenancyId};
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::value::Value;
use fieldseal_publishing::domain::{Publication, Withdrawal};
use fieldseal_registration::domain::wire::TenancyCertificate;

use super::roster::Roster;
use super::time_token::TimeToken;

/// A bundle's sequence number for one tenancy; strictly increasing, one at a time (DIS-015).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct BundleSeq(pub u64);

/// One survey the factory assigned to the tenancy's account: the survey, the instrument that
/// carries it, and the cohort and generation to visit. It links an instrument to a roster, which
/// the two separate lists of a bundle do not (WIRE-094).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BundleAssignment {
    /// The survey, by the instrument's name.
    pub survey: String,
    /// The content address of the instrument in this bundle.
    pub instrument: ContentAddress,
    /// The cohort to visit.
    pub cohort: CohortId,
    /// The cohort's generation on this tenancy (DIS-014).
    pub generation: Generation,
}

impl BundleAssignment {
    fn to_value(&self) -> Value {
        cbor::map([
            ("survey", Value::Text(self.survey.clone())),
            ("instrument", Value::Bytes(self.instrument.as_bytes().to_vec())),
            ("cohort", Value::Text(self.cohort.as_str().to_owned())),
            ("generation", Value::Int(i128::from(self.generation.0))),
        ])
    }

    fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let survey = f.text("survey")?;
        if survey.is_empty() {
            return Err(unknown("an assignment names no survey"));
        }
        let instrument = ContentAddress::from(f.bytes_n::<32>("instrument")?);
        let cohort = CohortId::new(f.text("cohort")?).map_err(|_| unknown("empty cohort"))?;
        let generation = Generation(u32::try_from(f.uint("generation")?).map_err(|_| unknown("generation out of range"))?);
        f.finish()?;
        Ok(Self { survey, instrument, cohort, generation })
    }
}

/// The plaintext of a bundle (WIRE-094).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BundleContent {
    /// The tenancy the bundle is for.
    pub tenancy: TenancyId,
    /// The bundle sequence number (DIS-015).
    pub seq: BundleSeq,
    /// The factory's issue time.
    pub issued: AuthorityTime,
    /// The tenancy certificate. Present exactly when the bundle carries rosters; a practice
    /// bundle for a tenancy that is not registered has none (DIS-004).
    pub certificate: Option<TenancyCertificate>,
    /// The fresh anchor (DIS-010).
    pub time_token: TimeToken,
    /// The instruments, each a `Publication`.
    pub instruments: Vec<Publication>,
    /// Layouts the factory assigns (DIS-016).
    pub layouts: Vec<Publication>,
    /// Runtime UI localisations (DIS-017).
    pub localisations: Vec<Publication>,
    /// The runtime policy, one `Publication` per contributing layer, outermost first (POL-050).
    pub policy: Vec<Publication>,
    /// The rosters for the tenancy's cohorts.
    pub rosters: Vec<Roster>,
    /// The surveys assigned to the tenancy's account, each linking an instrument to a cohort.
    pub assignments: Vec<BundleAssignment>,
    /// Newer trust bundles, as `TrustBundle` publications.
    pub trust_updates: Vec<Publication>,
    /// The current withdrawal list (DIS-010).
    pub withdrawals: Vec<Withdrawal>,
}

/// What a bundle contains, for display and the journal (distribution §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BundleManifest {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The sequence number.
    pub seq: BundleSeq,
    /// When it was issued.
    pub issued: AuthorityTime,
    /// Each instrument: address, name and version.
    pub instruments: Vec<(ContentAddress, String, String)>,
    /// Each layout's address.
    pub layouts: Vec<ContentAddress>,
    /// Each localisation's address.
    pub localisations: Vec<ContentAddress>,
    /// Each policy layer's address.
    pub policy: Vec<ContentAddress>,
    /// Each roster: cohort, version, generation and subject count.
    pub rosters: Vec<(CohortId, u64, Generation, usize)>,
    /// Each assigned survey with its instrument, cohort and generation.
    pub assignments: Vec<BundleAssignment>,
    /// The number of withdrawals listed.
    pub withdrawals: usize,
    /// The number of trust updates.
    pub trust_updates: usize,
}

fn pub_value(p: &Publication) -> Value {
    cbor::decode(&p.encode()).expect("a publication is canonical CBOR")
}

fn withdrawal_value(w: &Withdrawal) -> Value {
    cbor::decode(&w.encode()).expect("a withdrawal is canonical CBOR")
}

fn unknown(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

fn publication(v: Value) -> Result<Publication, WireError> {
    Publication::decode(&cbor::encode(&v)?).map_err(|_| unknown("not a publication"))
}

fn withdrawal(v: Value) -> Result<Withdrawal, WireError> {
    Withdrawal::decode(&cbor::encode(&v)?).map_err(|_| unknown("not a withdrawal"))
}

/// A bundle carries at most one roster per cohort (DIS-014).
fn unique_cohorts(rosters: &[Roster]) -> Result<(), WireError> {
    let mut seen = std::collections::BTreeSet::new();
    if rosters.iter().all(|r| seen.insert(r.cohort.as_str())) {
        Ok(())
    } else {
        Err(unknown("two rosters name the same cohort"))
    }
}

/// A bundle carries one version of a survey, so no two instruments share a name. An assignment
/// names an instrument of the bundle by address and name, and a cohort whose roster the bundle
/// carries at the same generation; one survey is assigned to a cohort once.
pub(crate) fn consistent_assignments(instruments: &[Publication], rosters: &[Roster], assignments: &[BundleAssignment]) -> Result<(), WireError> {
    let named: Vec<(ContentAddress, &str)> = instruments.iter().map(|p| (*p.address(), p.artefact.name())).collect();
    consistent(&named, rosters, assignments)
}

/// [`consistent_assignments`] over the instruments' addresses and names.
fn consistent(instruments: &[(ContentAddress, &str)], rosters: &[Roster], assignments: &[BundleAssignment]) -> Result<(), WireError> {
    let mut names = std::collections::BTreeSet::new();
    if !instruments.iter().all(|(_, name)| names.insert(*name)) {
        return Err(unknown("two instruments carry the same survey name"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for a in assignments {
        let instrument = instruments.iter().find(|(address, _)| *address == a.instrument);
        if instrument.is_none_or(|(_, name)| *name != a.survey) {
            return Err(unknown("an assignment names an instrument the bundle doesn't carry"));
        }
        if !rosters.iter().any(|r| r.cohort == a.cohort && r.generation == a.generation) {
            return Err(unknown("an assignment names a cohort the bundle carries no roster for"));
        }
        if !seen.insert((a.survey.as_str(), a.cohort.as_str())) {
            return Err(unknown("a survey is assigned to one cohort twice"));
        }
    }
    Ok(())
}

fn list<T>(f: &mut Fields, key: &'static str, required: bool, read: impl Fn(Value) -> Result<T, WireError>) -> Result<Vec<T>, WireError> {
    let values = match f.take_opt(key) {
        None if required => return Err(unknown("required list missing")),
        None => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(unknown("field is not an array")),
    };
    if values.is_empty() && !required {
        return Err(unknown("an optional list is omitted when empty"));
    }
    values.into_iter().map(read).collect()
}

impl BundleContent {
    /// The value tree. Optional lists are left out when empty, so each content has one
    /// canonical form.
    pub fn to_value(&self) -> Value {
        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        let mut put = |k: &str, v: Value| {
            m.insert(k.to_owned(), v);
        };
        put("v", Value::Int(1));
        put("tenancy", Value::Bytes(self.tenancy.as_bytes().to_vec()));
        put("seq", Value::Int(i128::from(self.seq.0)));
        put("issued", Value::Int(i128::from(self.issued.0)));
        if let Some(c) = &self.certificate {
            put("certificate", c.to_value());
        }
        put("time_token", self.time_token.to_value());
        put("instruments", Value::Array(self.instruments.iter().map(pub_value).collect()));
        put("policy", Value::Array(self.policy.iter().map(pub_value).collect()));
        put("rosters", Value::Array(self.rosters.iter().map(Roster::to_value).collect()));
        if !self.assignments.is_empty() {
            put("assignments", Value::Array(self.assignments.iter().map(BundleAssignment::to_value).collect()));
        }
        let optional = [
            ("layouts", &self.layouts),
            ("localisations", &self.localisations),
            ("trust_updates", &self.trust_updates),
        ];
        for (k, v) in optional {
            if !v.is_empty() {
                put(k, Value::Array(v.iter().map(pub_value).collect()));
            }
        }
        if !self.withdrawals.is_empty() {
            put("withdrawals", Value::Array(self.withdrawals.iter().map(withdrawal_value).collect()));
        }
        Value::Map(m)
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// Strictly reads the plaintext of a bundle: version 1, no unknown keys, canonical form,
    /// and at least one policy publication and one instrument (or, when every assignment was
    /// dropped, one roster).
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut f = Fields::new(cbor::decode(bytes)?)?;
        f.version("v", &Value::Int(1))?;
        let tenancy = TenancyId::from(f.bytes_n::<32>("tenancy")?);
        let seq = BundleSeq(f.uint("seq")?);
        let issued = AuthorityTime(f.uint("issued")?);
        let certificate = f.take_opt("certificate").map(TenancyCertificate::from_value).transpose()?;
        let time_token = TimeToken::from_value(f.take("time_token")?)?;
        let instruments = list(&mut f, "instruments", true, publication)?;
        let layouts = list(&mut f, "layouts", false, publication)?;
        let localisations = list(&mut f, "localisations", false, publication)?;
        let policy = list(&mut f, "policy", true, publication)?;
        let rosters = list(&mut f, "rosters", true, Roster::from_value)?;
        let assignments = list(&mut f, "assignments", false, BundleAssignment::from_value)?;
        let trust_updates = list(&mut f, "trust_updates", false, publication)?;
        let withdrawals = list(&mut f, "withdrawals", false, withdrawal)?;
        f.finish()?;
        // A bundle for assignments none of which survived carries rosters and no instrument.
        if (instruments.is_empty() && rosters.is_empty()) || policy.is_empty() {
            return Err(unknown("a bundle needs an instrument (or a roster) and a policy"));
        }
        unique_cohorts(&rosters)?;
        consistent_assignments(&instruments, &rosters, &assignments)?;
        for list in [&instruments, &layouts, &localisations, &policy, &trust_updates] {
            let mut seen = std::collections::BTreeSet::new();
            if !list.iter().all(|p| seen.insert(*p.address())) {
                return Err(unknown("a publication is listed twice in one list"));
            }
        }
        Ok(Self { tenancy, seq, issued, certificate, time_token, instruments, layouts, localisations, policy, rosters, assignments, trust_updates, withdrawals })
    }

    /// The summary of the contents.
    pub fn manifest(&self) -> BundleManifest {
        let addr = |ps: &[Publication]| ps.iter().map(|p| *p.address()).collect();
        BundleManifest {
            tenancy: self.tenancy,
            seq: self.seq,
            issued: self.issued,
            instruments: self
                .instruments
                .iter()
                .map(|p| (*p.address(), p.artefact.name().to_owned(), p.artefact.version().to_owned()))
                .collect(),
            layouts: addr(&self.layouts),
            localisations: addr(&self.localisations),
            policy: addr(&self.policy),
            rosters: self.rosters.iter().map(|r| (r.cohort.clone(), r.version, r.generation, r.entries.len())).collect(),
            assignments: self.assignments.clone(),
            withdrawals: self.withdrawals.len(),
            trust_updates: self.trust_updates.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(n: u8) -> ContentAddress {
        ContentAddress::from([n; 32])
    }

    fn assignment(survey: &str, instrument: ContentAddress, cohort: &str, generation: u32) -> BundleAssignment {
        BundleAssignment { survey: survey.into(), instrument, cohort: CohortId::new(cohort).unwrap(), generation: Generation(generation) }
    }

    fn roster(cohort: &str, generation: u32) -> Roster {
        Roster { cohort: CohortId::new(cohort).unwrap(), version: 1, generation: Generation(generation), entries: vec![], consent_covers: vec![] }
    }

    fn named() -> [(ContentAddress, &'static str); 2] {
        [(address(1), "water"), (address(2), "meals")]
    }

    fn read(entries: Vec<(&str, Value)>) -> Result<BundleAssignment, WireError> {
        BundleAssignment::from_value(cbor::map(entries))
    }

    fn fields() -> Vec<(&'static str, Value)> {
        vec![
            ("survey", Value::Text("water".into())),
            ("instrument", Value::Bytes(vec![1; 32])),
            ("cohort", Value::Text("village-a".into())),
            ("generation", Value::Int(1)),
        ]
    }

    #[test]
    fn wire_096_an_assignment_round_trips() {
        let a = assignment("water", address(1), "village-a", 1);
        assert_eq!(BundleAssignment::from_value(a.to_value()).unwrap(), a);
        assert_eq!(read(fields()).unwrap(), a);
    }

    #[test]
    fn wire_096_an_assignment_with_an_unknown_key_is_refused() {
        let mut f = fields();
        f.push(("note", Value::Text("extra".into())));
        assert!(read(f).is_err());
    }

    #[test]
    fn wire_096_an_assignment_with_a_wrong_type_or_a_missing_field_is_refused() {
        let with = |key: &str, value: Value| fields().into_iter().map(|(k, v)| if k == key { (k, value.clone()) } else { (k, v) }).collect::<Vec<_>>();
        assert!(read(with("survey", Value::Int(1))).is_err());
        assert!(read(with("survey", Value::Text(String::new()))).is_err(), "a survey is named");
        assert!(read(with("instrument", Value::Bytes(vec![1; 31]))).is_err(), "an address is 32 bytes");
        assert!(read(with("cohort", Value::Int(1))).is_err());
        assert!(read(with("cohort", Value::Text(String::new()))).is_err());
        assert!(read(with("generation", Value::Text("1".into()))).is_err());
        assert!(read(fields().into_iter().filter(|(k, _)| *k != "generation").collect()).is_err());
    }

    #[test]
    fn wire_096_a_survey_assigned_to_two_cohorts_is_consistent_but_not_twice_to_one() {
        let rosters = [roster("village-a", 1), roster("village-b", 1)];
        let two = [assignment("water", address(1), "village-a", 1), assignment("water", address(1), "village-b", 1)];
        assert!(consistent(&named(), &rosters, &two).is_ok());
        let twice = [assignment("water", address(1), "village-a", 1), assignment("water", address(1), "village-a", 1)];
        assert!(consistent(&named(), &rosters, &twice).is_err(), "one survey, one cohort, once");
    }

    #[test]
    fn wire_096_an_assignment_must_name_an_instrument_of_the_bundle_under_its_own_name() {
        let rosters = [roster("village-a", 1)];
        assert!(consistent(&named(), &rosters, &[assignment("meals", address(1), "village-a", 1)]).is_err(), "the name is not the instrument's");
        assert!(consistent(&named(), &rosters, &[assignment("water", address(9), "village-a", 1)]).is_err(), "no such instrument");
    }

    #[test]
    fn wire_096_two_instruments_of_one_name_are_refused() {
        let two = [(address(1), "water"), (address(2), "water")];
        assert!(consistent(&two, &[], &[]).is_err(), "a bundle carries one version of a survey");
        assert!(consistent(&named(), &[], &[]).is_ok());
    }

    #[test]
    fn wire_096_an_assignment_must_match_a_roster_of_the_bundle_by_cohort_and_generation() {
        let rosters = [roster("village-a", 2)];
        assert!(consistent(&named(), &rosters, &[assignment("water", address(1), "village-a", 2)]).is_ok());
        assert!(consistent(&named(), &rosters, &[assignment("water", address(1), "village-a", 1)]).is_err(), "another generation");
        assert!(consistent(&named(), &rosters, &[assignment("water", address(1), "village-b", 2)]).is_err(), "no roster for the cohort");
    }

    #[test]
    fn wire_094_an_empty_assignment_list_is_omitted_and_never_present() {
        let omitted = cbor::map([("x", Value::Int(1))]);
        let mut f = Fields::new(omitted).unwrap();
        assert_eq!(list(&mut f, "assignments", false, BundleAssignment::from_value).unwrap(), vec![]);
        let present = cbor::map([("assignments", Value::Array(vec![]))]);
        let mut f = Fields::new(present).unwrap();
        assert!(list(&mut f, "assignments", false, BundleAssignment::from_value).is_err(), "an optional list is left out when empty");
    }
}
