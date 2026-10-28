//! Importing a bundle and holding its contents for a session (COL-003, COL-005, COL-082,
//! COL-090, PUB-073).
//!
//! The bundle file is stored as received (sealed to the device agreement key). At import
//! and at every unlock, Distribution's [`crate::ports::BundleOpener`] verifies the envelope
//! and opens it; then every publication it carries is verified with Publishing's
//! `VerifyPublication` (a runtime checks only that the provenance describes the artefact,
//! PUB-073), the instrument and layouts are validated by the format core, and the rosters
//! are held only in memory for the session.

use fieldseal_distribution::domain::{AnchorKind, check_publication_tree_head_age};
use fieldseal_instrument::application::{LayoutBinding, LayoutOptions, validate_instrument, validate_layout_with};
use fieldseal_instrument::domain::{Instrument, Layout as InstrumentLayout};
use fieldseal_kernel::cbor;
use fieldseal_kernel::structure::Fields;
use fieldseal_kernel::id::{ContentAddress, Digest, Fingerprint, SubjectId};
use fieldseal_kernel::value::Value;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_policy::domain::{AppliedVersions, InstrumentRef, Layer, PolicyDocument, RuntimeEvaluator, Version, decode_document};
use fieldseal_publishing::application::{ProvenanceCheck, VerifyPublication};
use fieldseal_publishing::domain::{ArtefactKind, Publication, Withdrawal};
use fieldseal_trust::domain::TrustStore;

use super::{CollectionError, Runtime, names};
use crate::domain::TenancyState;
use crate::domain::bundle::{HeldRoster, OpenedBundle, RosterSubject, TimeAnchor};
use crate::domain::payload::{ImportedRoster, Payload};

/// A verified bundle's contents, held in memory for one session (COL-090).
#[derive(Clone, Debug)]
pub struct Held {
    /// The bundle content's address.
    pub address: Digest,
    /// The instrument.
    pub instrument: Instrument,
    /// Its fingerprint (WIRE-186).
    pub fingerprint: Fingerprint,
    /// Validated layouts, with their content addresses.
    pub layouts: Vec<(InstrumentLayout, ContentAddress)>,
    /// The rosters.
    pub rosters: Vec<HeldRoster>,
    /// The runtime policy layers' content addresses, outermost first; empty when the bundle
    /// carried none.
    pub policy: Vec<ContentAddress>,
}

impl Held {
    /// Whether this is a practice bundle: one without rosters (COL-003).
    pub fn is_practice(&self) -> bool {
        self.rosters.is_empty()
    }

    /// The roster entry for a subject, and its roster.
    pub fn subject(&self, subject: &SubjectId) -> Option<(&HeldRoster, &RosterSubject)> {
        self.rosters.iter().find_map(|r| r.subjects.iter().find(|s| &s.subject == subject).map(|s| (r, s)))
    }
}

struct Verified {
    held: Held,
    policy: Option<RuntimeEvaluator>,
    /// The applied policy versions once this bundle's layers are admitted (POL-052).
    applied: Option<AppliedVersions>,
}

/// Encodes the applied policy versions: an array of `{layer, key, name, version}` maps.
fn encode_applied(applied: &AppliedVersions) -> Vec<u8> {
    let entries = applied
        .entries()
        .map(|(layer, name, version)| {
            let (kind, key) = match layer {
                Layer::Deployment => ("deployment", Value::Text(String::new())),
                Layer::Programme(n) => ("programme", Value::Text(n.clone())),
                Layer::Instrument(InstrumentRef::Name(n)) => ("instrument-name", Value::Text(n.clone())),
                Layer::Instrument(InstrumentRef::Address(a)) => ("instrument-address", Value::Bytes(a.as_bytes().to_vec())),
            };
            cbor::map([
                ("layer", Value::Text(kind.to_owned())),
                ("key", key),
                ("name", Value::Text(name.to_owned())),
                ("version", Value::Text(version.to_string())),
            ])
        })
        .collect();
    cbor::encode(&Value::Array(entries)).expect("applied versions are plain values")
}

fn decode_applied(bytes: &[u8]) -> Option<AppliedVersions> {
    let value = cbor::decode(bytes).ok()?;
    let mut applied = AppliedVersions::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in value.as_array()? {
        let mut f = Fields::new(entry.clone()).ok()?;
        let kind = f.text("layer").ok()?;
        let key = f.take("key").ok()?;
        let name = f.text("name").ok()?;
        let version = Version::parse(&f.text("version").ok()?).ok()?;
        f.finish().ok()?;
        let key_dbg = format!("{key:?}");
        let layer = match kind.as_str() {
            "deployment" if key.as_text() == Some("") => Layer::Deployment,
            "programme" => Layer::Programme(key.as_text()?.to_owned()),
            "instrument-name" => Layer::Instrument(InstrumentRef::Name(key.as_text()?.to_owned())),
            "instrument-address" => match key {
                Value::Bytes(b) => Layer::Instrument(InstrumentRef::Address(ContentAddress::from(<[u8; 32]>::try_from(b.as_slice()).ok()?))),
                _ => return None,
            },
            _ => return None,
        };
        if !seen.insert((kind, key_dbg, name.clone())) {
            return None;
        }
        applied.restore(layer, name, version);
    }
    Some(applied)
}

fn rejected(what: &str, e: impl std::fmt::Display) -> CollectionError {
    CollectionError::BundleRejected(format!("{what}: {e}"))
}

impl Runtime<'_> {
    fn verify_publication(&self, p: &Publication, kind: ArtefactKind, withdrawals: &[Withdrawal]) -> Result<(), CollectionError> {
        if p.artefact.kind() != kind {
            return Err(rejected("publication", format!("expected {}, found {}", kind.as_str(), p.artefact.kind().as_str())));
        }
        VerifyPublication::new(TrustStore::new(self.prov.trust), self.prov.publishing)
            .with_provenance_check(ProvenanceCheck::DescribesOnly)
            .verify(p, withdrawals)
            .map_err(|e| rejected(kind.as_str(), e))?;
        Ok(())
    }

    fn verify_bundle(&self, opened: &OpenedBundle) -> Result<Verified, CollectionError> {
        if opened.tenancy != self.meta()?.tenancy {
            return Err(rejected("bundle", "for another tenancy"));
        }
        self.verify_publication(&opened.instrument, ArtefactKind::Instrument, &opened.withdrawals)?;
        let fingerprint = opened.instrument.artefact.fingerprint().ok_or_else(|| rejected("instrument", "no fingerprint"))?;
        let document = cbor::decode(opened.instrument.artefact.canonical_bytes()).map_err(|e| rejected("instrument", e))?;
        let instrument = validate_instrument(&document)
            .map_err(|f| rejected("instrument", format!("{} validation findings", f.len())))?
            .instrument;
        let mut layouts = Vec::new();
        for p in &opened.layouts {
            self.verify_publication(p, ArtefactKind::Layout, &opened.withdrawals)?;
            let doc = cbor::decode(p.artefact.canonical_bytes()).map_err(|e| rejected("layout", e))?;
            // INS-200: a bundled layout names the instrument by its fingerprint.
            let binding = LayoutBinding { expected: fingerprint, resolve: &|_| None };
            let layout = validate_layout_with(&doc, &instrument, LayoutOptions { binding: Some(binding) })
                .map_err(|f| rejected("layout", format!("{} validation findings", f.len())))?;
            layouts.push((layout, *p.address()));
        }
        let mut policy = None;
        let mut applied = None;
        if !opened.policy.is_empty() {
            let mut documents = Vec::new();
            for p in &opened.policy {
                self.verify_publication(p, ArtefactKind::Policy, &opened.withdrawals)?;
                let doc = cbor::decode(p.artefact.canonical_bytes()).map_err(|e| rejected("policy", e))?;
                let decoded = decode_document(&doc);
                documents.push(decoded.document.ok_or_else(|| rejected("policy", "not a policy document"))?);
            }
            applied = Some(self.admit_policies(&documents)?);
            let layers: Vec<_> = documents.iter().collect();
            policy = Some(RuntimeEvaluator::from_bundle(&layers).map_err(|f| rejected("policy", format!("{} findings", f.len())))?);
        }
        // PUB-072: each tree head's age, from the time token that accompanied it to the bundle's
        // issue time, must be within the runtime policy's `maxTreeHeadAge`.
        let defaults;
        let evaluator = match &policy {
            Some(p) => p,
            None => {
                defaults = super::session::default_policy();
                &defaults
            }
        };
        let max_age_ms = evaluator.policy().max_tree_head_age.as_secs().saturating_mul(AuthorityTime::SECOND);
        let store = TrustStore::new(self.prov.trust);
        let all = std::iter::once(&opened.instrument).chain(&opened.layouts).chain(&opened.policy);
        for p in all {
            check_publication_tree_head_age(p, opened.issued, &store, max_age_ms).map_err(|e| rejected(p.artefact.kind().as_str(), e))?;
        }
        Ok(Verified {
            held: Held {
                address: opened.address,
                instrument,
                fingerprint,
                layouts,
                rosters: opened.rosters.clone(),
                policy: opened.policy.iter().map(|p| *p.address()).collect(),
            },
            policy,
            applied,
        })
    }

    /// The policy versions this device has applied (POL-052); empty when none were recorded.
    /// A record that cannot be read counts as nothing applied, which is the safe direction
    /// only because the next import writes it afresh from a verified bundle.
    pub fn applied_policies(&self) -> Result<AppliedVersions, CollectionError> {
        Ok(self.p.storage.read(names::DEVICE, &names::applied_policies())?.and_then(|b| decode_applied(&b)).unwrap_or_default())
    }

    /// Feeds the applied versions to the check of a bundle's policy layers: no layer may go
    /// back to a version lower than one already applied for the same layer and name
    /// (POL-052). Returns the versions after admitting these layers.
    fn admit_policies(&self, documents: &[PolicyDocument]) -> Result<AppliedVersions, CollectionError> {
        let mut applied = self.applied_policies()?;
        for d in documents {
            applied.admit(d).map_err(|f| rejected("policy", f.message))?;
        }
        Ok(applied)
    }

    /// Imports a bundle file (from any route): verifies and opens it, verifies every
    /// publication, installs the tenancy certificate's grant (COL-005), chains the bundle's
    /// anchors (COL-082), seals an `import` record (WIRE-058), and holds the contents for
    /// the session. Replaces any bundle held before.
    pub fn import_bundle(&mut self, file: &[u8]) -> Result<(), CollectionError> {
        self.active()?;
        if self.capture.is_some() {
            return Err(CollectionError::CaptureOpen);
        }
        let state = self.meta()?.state;
        if !matches!(state, TenancyState::Local | TenancyState::Registered) {
            return Err(CollectionError::WrongState(state));
        }
        let opened = self.p.bundles.open(file).map_err(|e| rejected("bundle", e))?;
        let verified = self.verify_bundle(&opened)?;
        self.check_not_older(&opened)?;
        self.p.storage.write(names::DEVICE, &names::bundle(), file)?;
        if let Some(grant) = &opened.registration {
            if let Some(m) = self.meta.as_mut() {
                m.state = TenancyState::Registered;
                m.record_key = grant.record_key;
                m.period = grant.period;
                m.handle = grant.handle;
                m.certificate = Some(grant.certificate);
                m.window = Some((grant.not_before.0, grant.not_after.0));
            }
            if let Some(document) = &grant.document {
                self.p.storage.write(names::DEVICE, &names::registration(), &fieldseal_kernel::cbor::encode(document)?)?;
            }
            self.save_meta()?;
        }
        if let Some(applied) = &verified.applied {
            // Recorded only now that the whole bundle verified (POL-052).
            self.p.storage.write(names::DEVICE, &names::applied_policies(), &encode_applied(applied))?;
        }
        if let Some(policy) = &verified.policy {
            let pin = &policy.policy().pin;
            if let Some(m) = self.meta.as_mut() {
                m.failures_before_lockout = pin.failures_before_lockout;
                m.lockout_steps_ms = pin.lockout_steps.iter().map(|d| d.as_secs() * 1000).collect();
                m.policy = verified.held.policy.last().map(|a| Digest::from(*a.as_bytes()));
            }
            self.save_meta()?;
        }
        self.chain_anchor(TimeAnchor { kind: AnchorKind::Bundle, address: opened.address, authority_time: opened.issued })?;
        for t in &opened.time_tokens {
            self.chain_anchor(*t)?;
        }
        let held = &verified.held;
        let mut artefacts = vec![Digest::from(*held.fingerprint.as_bytes())];
        artefacts.extend(held.layouts.iter().map(|(_, a)| Digest::from(*a.as_bytes())));
        artefacts.extend(held.policy.iter().map(|a| Digest::from(*a.as_bytes())));
        let rosters: Vec<ImportedRoster> =
            held.rosters.iter().map(|r| ImportedRoster { cohort: r.cohort.as_str().to_owned(), version: r.version, address: r.address }).collect();
        let bundle = opened.address;
        self.seal_record(|tick| Payload::Import { tick, bundle, artefacts, rosters }, None)?;
        self.hold(verified)
    }

    /// The bundle must be newer than the one held, and no roster may go back in version or
    /// generation (DIS-030 steps 6 and 9, DIS-031). A held bundle that can't be opened any
    /// more (sealed to a rolled agreement key, DIS-050) doesn't count.
    fn check_not_older(&self, opened: &OpenedBundle) -> Result<(), CollectionError> {
        let Some(old) = self.p.storage.read(names::DEVICE, &names::bundle())? else {
            return Ok(());
        };
        let Ok(held) = self.p.bundles.open(&old) else {
            return Ok(());
        };
        if held.tenancy == opened.tenancy && opened.seq <= held.seq {
            return Err(rejected("bundle", format!("sequence {} is not newer than {}", opened.seq, held.seq)));
        }
        for r in &opened.rosters {
            if let Some(h) = held.rosters.iter().find(|h| h.cohort == r.cohort)
                && (r.generation < h.generation || (r.generation == h.generation && r.version < h.version))
            {
                return Err(rejected("roster", format!("{} version {} is older than the one held", r.cohort.as_str(), r.version)));
            }
        }
        Ok(())
    }

    fn hold(&mut self, verified: Verified) -> Result<(), CollectionError> {
        let fp = verified.held.fingerprint;
        if let Some(m) = self.meta.as_mut()
            && !m.instruments.contains(&fp)
        {
            m.instruments.push(fp);
        }
        let session = self.session.as_mut().ok_or(CollectionError::Locked)?;
        if let Some(policy) = verified.policy {
            session.policy = policy;
        }
        session.held = Some(verified.held);
        Ok(())
    }

    /// Opens the stored bundle again at unlock. Returns whether one is held.
    pub(crate) fn load_held_bundle(&mut self) -> Result<bool, CollectionError> {
        let Some(file) = self.p.storage.read(names::DEVICE, &names::bundle())? else {
            return Ok(false);
        };
        let opened = self.p.bundles.open(&file).map_err(|e| rejected("held bundle", e))?;
        let verified = self.verify_bundle(&opened)?;
        self.hold(verified)?;
        Ok(true)
    }

    /// The held bundle, if any.
    pub fn held(&self) -> Option<&Held> {
        self.session.as_ref().and_then(|s| s.held.as_ref())
    }

    /// A subject's display fields (names), for the shell to show during the session only
    /// (COL-090). Never written anywhere by the runtime.
    pub fn display_fields(&self, subject: &SubjectId) -> Option<std::collections::BTreeMap<String, String>> {
        self.held().and_then(|h| h.subject(subject)).map(|(_, s)| s.display.clone())
    }

    /// A time token or other anchor seen outside a bundle (COL-082).
    pub fn see_anchor(&mut self, kind: AnchorKind, address: Digest, authority_time: AuthorityTime) -> Result<bool, CollectionError> {
        self.chain_anchor(TimeAnchor { kind, address, authority_time })
    }
}
