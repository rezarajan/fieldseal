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
    /// and at least one instrument and one policy publication.
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
        let trust_updates = list(&mut f, "trust_updates", false, publication)?;
        let withdrawals = list(&mut f, "withdrawals", false, withdrawal)?;
        f.finish()?;
        if instruments.is_empty() || policy.is_empty() {
            return Err(unknown("a bundle needs an instrument and a policy"));
        }
        unique_cohorts(&rosters)?;
        for list in [&instruments, &layouts, &localisations, &policy, &trust_updates] {
            let mut seen = std::collections::BTreeSet::new();
            if !list.iter().all(|p| seen.insert(*p.address())) {
                return Err(unknown("a publication is listed twice in one list"));
            }
        }
        Ok(Self { tenancy, seq, issued, certificate, time_token, instruments, layouts, localisations, policy, rosters, trust_updates, withdrawals })
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
            withdrawals: self.withdrawals.len(),
            trust_updates: self.trust_updates.len(),
        }
    }
}
