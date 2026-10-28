//! The root aggregate: the root certificate, its custodians and the ceremony record
//! (TRU-001..004).
//!
//! The custodian threshold is represented as data. Splitting or reconstructing the root
//! key (HSM quorum cards, backup shares) is the job of the offline signer behind
//! `KeyCustody`, not of this domain.

use std::collections::BTreeSet;

use fieldseal_kernel::cbor;
use fieldseal_kernel::id::ContentAddress;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{Value, WireError};

use super::certificate::KeyCertificate;
use super::error::TrustError;
use super::wire::{self, V1, not_defined};

/// How many custodians must be present for a root operation, out of how many (TRU-002).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Threshold {
    m: u32,
    n: u32,
}

impl Threshold {
    /// The default, 2 of 3 (TRU-002).
    pub const DEFAULT: Threshold = Threshold { m: 2, n: 3 };

    /// `m` of `n`. A threshold needs at least two custodians to act together and no more than
    /// there are: 2 ≤ m ≤ n.
    pub fn new(m: u32, n: u32) -> Result<Self, TrustError> {
        if m < 2 {
            return Err(TrustError::InvalidCeremony("a root operation needs at least 2 custodians"));
        }
        if m > n {
            return Err(TrustError::InvalidCeremony("the threshold exceeds the number of custodians"));
        }
        Ok(Self { m, n })
    }

    /// Custodians required.
    pub fn m(&self) -> u32 {
        self.m
    }

    /// Custodians in total.
    pub fn n(&self) -> u32 {
        self.n
    }
}

/// The parameters of a root ceremony (`ceremony.yaml` in the operator guide).
///
/// Custodians and witnesses are named by opaque references; the mapping to people stays in
/// the authority's private records ([`crate::ports::KeyHolderRegistry`], TRU-092).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ceremony {
    /// The authority's name for its root.
    pub authority: String,
    /// The custodian threshold.
    pub threshold: Threshold,
    /// One reference per custodian; exactly `threshold.n()`, all distinct.
    pub custodians: Vec<String>,
    /// At least one witness, none of them a custodian.
    pub witnesses: Vec<String>,
    /// When the ceremony is held.
    pub held_at: AuthorityTime,
    /// The root's validity, at most 10 years (TRU-004).
    pub not_before: AuthorityTime,
    /// End of the root's validity.
    pub not_after: AuthorityTime,
}

impl Ceremony {
    /// Checks the people: `n` distinct custodians, at least one witness, nobody holding two
    /// roles.
    pub fn check(&self) -> Result<(), TrustError> {
        if self.authority.is_empty() {
            return Err(TrustError::InvalidCeremony("the authority is unnamed"));
        }
        let custodians: BTreeSet<_> = self.custodians.iter().collect();
        if custodians.len() != self.custodians.len() || self.custodians.iter().any(String::is_empty) {
            return Err(TrustError::InvalidCeremony("custodians must be distinct and named"));
        }
        if self.custodians.len() as u64 != u64::from(self.threshold.n()) {
            return Err(TrustError::InvalidCeremony("the number of custodians must equal n"));
        }
        if self.witnesses.is_empty() || self.witnesses.iter().any(String::is_empty) {
            return Err(TrustError::InvalidCeremony("a ceremony needs at least one witness"));
        }
        if self.witnesses.iter().any(|w| custodians.contains(w)) {
            return Err(TrustError::InvalidCeremony("a witness must not be a custodian"));
        }
        Ok(())
    }
}

/// The record of a root ceremony (TRU-002): the root certificate it produced, the threshold,
/// the custodians and witnesses, and when it was held.
///
/// The root does not sign it: TRU-003 lets the root sign only key certificates, trust bundles
/// and revocations. The participants sign the record's [content address](Self::content_address)
/// in the ceremony log; the root certificate inside it is the root's own signed statement.
///
/// Wire form (`ceremony-record`, TRU §6.6): `{"v": 1, "authority": tstr, "root":
/// key-certificate, "threshold": {"m": uint, "n": uint}, "custodians": [+ tstr],
/// "witnesses": [+ tstr], "held": ms-time}`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CeremonyRecord {
    /// The ceremony's parameters.
    pub ceremony: Ceremony,
    /// The root certificate it produced.
    pub root: KeyCertificate,
}

impl CeremonyRecord {
    /// Records `ceremony` and the root certificate it produced. The root certificate's validity
    /// must be the ceremony's.
    pub fn new(ceremony: Ceremony, root: KeyCertificate) -> Result<Self, TrustError> {
        ceremony.check()?;
        if !root.is_root() || root.not_before() != ceremony.not_before || root.not_after() != ceremony.not_after {
            return Err(TrustError::InvalidCeremony("the root certificate does not match the ceremony"));
        }
        Ok(Self { ceremony, root })
    }

    /// The record as a value.
    pub fn to_value(&self) -> Value {
        let c = &self.ceremony;
        let list = |v: &[String]| Value::Array(v.iter().map(|s| wire::text(s)).collect());
        cbor::map([
            ("v", V1),
            ("authority", wire::text(&c.authority)),
            ("root", self.root.to_value()),
            ("threshold", cbor::map([("m", wire::uint(c.threshold.m.into())), ("n", wire::uint(c.threshold.n.into()))])),
            ("custodians", list(&c.custodians)),
            ("witnesses", list(&c.witnesses)),
            ("held", wire::time(c.held_at)),
        ])
    }

    /// The canonical CBOR of the record.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        cbor::encode(&self.to_value())
    }

    /// The content address the participants sign in the ceremony log.
    pub fn content_address(&self) -> Result<ContentAddress, WireError> {
        Ok(ContentAddress::of(&self.encode()?))
    }

    /// Reads a record and checks it, including the root certificate's self-signature.
    pub fn from_value(value: Value) -> Result<Self, TrustError> {
        let mut f = Fields::new(value)?;
        f.version("v", &V1)?;
        let authority = f.text("authority")?;
        let root = KeyCertificate::from_value(f.take("root")?)?;
        let mut t = Fields::new(f.take("threshold")?)?;
        let small = |n: u64| u32::try_from(n).map_err(|_| not_defined("threshold out of range"));
        let threshold = Threshold::new(small(t.uint("m")?)?, small(t.uint("n")?)?)?;
        t.finish()?;
        let texts = |f: &mut Fields, key: &str| -> Result<Vec<String>, WireError> {
            f.array(key)?.into_iter().map(wire::text_value).collect()
        };
        let custodians = texts(&mut f, "custodians")?;
        let witnesses = texts(&mut f, "witnesses")?;
        let held_at = wire::auth_time(&mut f, "held")?;
        f.finish()?;
        let key = root.public_key().as_p256().ok_or(TrustError::InvalidRoots("roots are P-256"))?.clone();
        root.verify_issued_by(&key)?;
        let ceremony = Ceremony {
            authority,
            threshold,
            custodians,
            witnesses,
            held_at,
            not_before: root.not_before(),
            not_after: root.not_after(),
        };
        Self::new(ceremony, root)
    }

    /// Decodes a record from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}
