//! What one tenancy's bundle is built from (Technical Plan section 7.3).
//!
//! [`BuildInputs::collect`] reads the inputs through ports only: the instrument version each
//! assigned survey selects, the layouts bound to it, the withdrawals, the current roster of
//! each assigned cohort, the tenancy's certificate and agreement key, the runtime profile it
//! reported, and the release policy. [`BuildInputs::digest`] covers exactly these, so the
//! reconciler builds when the digest differs from the one stored beside the last bundle and
//! at no other time. [`BuildInputs::request_for`] is the `BuildRequest` for them.
//!
//! The bundle format is not touched: the digest lives in a file beside the bundle, never in
//! the signed manifest.

use std::collections::{BTreeMap, BTreeSet};

use fieldseal_distribution::application::BuildRequest;
use fieldseal_distribution::domain::{BundleAssignment, Roster, RuntimeProfile, instrument_facts, layout_facts};
use fieldseal_distribution::ports::{RosterSource, RuntimeProfiles};
use fieldseal_instrument::domain::{Compatibility, SemVer, WindowClass, check_compatibility};
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{CohortId, ContentAddress, Fingerprint, Generation, KeyId, TenancyId};
use fieldseal_kernel::value::Value;
use fieldseal_policy::domain::LayoutAssignment;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::{ArtefactKind, Publication, PublishingError, Withdrawal};
use fieldseal_publishing::ports::ArtefactRegistry;
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::DeviceKeyKind;

/// The ports the inputs are read through.
#[derive(Clone, Copy)]
pub struct InputPorts<'a> {
    /// Tenancies and the assignment journal.
    pub registry: &'a dyn RegistryStore,
    /// Published artefacts and withdrawals.
    pub artefacts: &'a dyn ArtefactRegistry,
    /// The current roster of each cohort.
    pub rosters: &'a dyn RosterSource,
    /// What each runtime reported at registration.
    pub profiles: &'a dyn RuntimeProfiles,
    /// Verifies a publication before it is selected, and a withdrawal before it counts. It is
    /// built over the trusted publishing policy, the one the builder verifies under.
    pub verifier: &'a VerifyPublication<'a>,
}

/// What signs the bundle, which the digest covers: a key roll or a new trust bundle rebuilds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SigningInputs {
    /// The factory key that signs bundles.
    pub signer: KeyId,
    /// SHA-256 of the encoded trust bundle the factory verifies under.
    pub trust: [u8; 32],
}

/// A published version that was passed over because it did not verify.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Skipped {
    /// The artefact kind.
    pub kind: ArtefactKind,
    /// The artefact name.
    pub name: String,
    /// The version label.
    pub version: String,
    /// A code for why (never the error text).
    pub code: &'static str,
}

/// A code for a publication that failed verification.
pub fn verify_code(e: &PublishingError) -> &'static str {
    match e {
        PublishingError::Withdrawn => "withdrawn",
        PublishingError::BuilderNotAllowed(_) => "builder-not-allowed",
        PublishingError::SourceNotAllowed(_) => "source-not-allowed",
        PublishingError::ProvenanceMismatch | PublishingError::ProvenanceSignature(_) => "provenance",
        PublishingError::Wire(_) | PublishingError::InvalidArtefact(_) | PublishingError::Validation(_) => "invalid",
        _ => "unverified",
    }
}

/// The effective release policy values a build reads.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReleaseInputs {
    /// The published policy layers behind the release decision (POL-023).
    pub sources: Vec<ContentAddress>,
    /// `factory.release.layouts` (POL-068).
    pub layouts: LayoutAssignment,
}

/// Why the inputs of a tenancy could not be read.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum InputsError {
    /// The registry has no such tenancy, or it has no active agreement key.
    #[error("the tenancy is not registered")]
    NotRegistered,
    /// The runtime reported no profile (DIS-012 cannot be decided; never a default).
    #[error("the tenancy has no runtime profile")]
    ProfileUnknown,
    /// A port failed.
    #[error("{port}: {reason}")]
    Port {
        /// Which port.
        port: &'static str,
        /// What it said.
        reason: String,
    },
}

fn port<E: std::fmt::Display>(name: &'static str) -> impl FnOnce(E) -> InputsError {
    move |e| InputsError::Port { port: name, reason: e.to_string() }
}

/// Why an assigned survey has no instrument in the bundle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeftOut {
    /// Versions exist but none satisfies DIS-012 for the tenancy's reported schema.
    Incompatible,
    /// Every published version is withdrawn, or none is readable.
    Unavailable,
}

impl LeftOut {
    /// The reason the reconciler records (`bundle-withheld(<reason>)`).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Incompatible => "instrument-incompatible",
            Self::Unavailable => "instrument-unavailable",
        }
    }
}

/// Everything a tenancy's next bundle is built from.
#[derive(Clone, Debug)]
pub struct BuildInputs {
    /// The tenancy.
    pub tenancy: TenancyId,
    /// The latest assignment of each survey to the tenancy's account: survey, cohort, generation.
    pub assignments: Vec<(String, CohortId, Generation)>,
    /// The instrument each assigned survey selects: survey, fingerprint.
    pub instruments: Vec<(String, ContentAddress)>,
    /// The assigned surveys that have no instrument, and why.
    pub left_out: Vec<(String, LeftOut)>,
    /// The layouts the policy assigns to those instruments.
    pub layouts: Vec<ContentAddress>,
    /// The digest of every recorded withdrawal (a bundle carries them all).
    pub withdrawals: Vec<[u8; 32]>,
    /// The current roster of each assigned cohort, as the source returns it (every column).
    pub rosters: Vec<Roster>,
    /// The roster fields the selected instruments read (DIS-013).
    pub roster_fields: BTreeSet<String>,
    /// The address of the tenancy's current certificate. Its serial is not a field of the
    /// certificate; the signed bytes stand for it, since a reissue changes them.
    pub certificate: Option<ContentAddress>,
    /// The tenancy's active agreement key, which the bundle is sealed to.
    pub agreement_key: Vec<u8>,
    /// What the runtime reported at registration.
    pub profile: RuntimeProfile,
    /// The release policy values.
    pub release: ReleaseInputs,
    /// What signs the bundle.
    pub signing: SigningInputs,
    /// Versions passed over because they did not verify. They do not change the bundle.
    pub skipped: Vec<Skipped>,
}

/// The precedence of a version label: the core, then a release above its pre-releases.
fn precedence(v: &SemVer) -> (fieldseal_instrument::domain::SchemaVersion, bool, String) {
    (v.core, v.pre.is_none(), v.pre.clone().unwrap_or_default())
}

/// The published versions of `kind` named `name` that are not withdrawn and whose label is a
/// semantic version, highest first.
fn live_versions(artefacts: &dyn ArtefactRegistry, kind: ArtefactKind, name: &str, withdrawn: &BTreeSet<ContentAddress>) -> Result<Vec<(String, SemVer, ContentAddress)>, InputsError> {
    let mut all: Vec<(String, SemVer, ContentAddress)> = artefacts
        .list(kind, name)
        .map_err(port("ArtefactRegistry"))?
        .into_iter()
        .filter(|(_, address)| !withdrawn.contains(address))
        .filter_map(|(label, address)| Some((label.clone(), SemVer::parse(&label).ok()?, address)))
        .collect();
    all.sort_by_key(|v| std::cmp::Reverse(precedence(&v.1)));
    Ok(all)
}

/// The publication at `address`, if it is stored and verifies in full (PUB-073). One that does
/// not is recorded in `skipped` and the caller moves to the next version, so a forged
/// higher version cannot block every build.
fn verified(ports: &InputPorts<'_>, address: &ContentAddress, withdrawals: &[Withdrawal], what: (ArtefactKind, &str, &str), skipped: &mut Vec<Skipped>) -> Result<Option<Publication>, InputsError> {
    let Some(p) = ports.artefacts.get(address).map_err(port("ArtefactRegistry"))? else { return Ok(None) };
    match ports.verifier.verify(&p, withdrawals) {
        Ok(_) => Ok(Some(p)),
        Err(e) => {
            skipped.push(Skipped { kind: what.0, name: what.1.to_owned(), version: what.2.to_owned(), code: verify_code(&e) });
            Ok(None)
        }
    }
}

impl BuildInputs {
    /// Reads the inputs of `tenancy`. It builds nothing and writes nothing.
    pub fn collect(tenancy: &TenancyId, ports: InputPorts<'_>, release: ReleaseInputs, signing: SigningInputs) -> Result<Self, InputsError> {
        let record = ports.registry.tenancy(tenancy).map_err(port("RegistryStore"))?.ok_or(InputsError::NotRegistered)?;
        let agreement_key = record.active_key(DeviceKeyKind::Agreement).ok_or(InputsError::NotRegistered)?.public_key.as_bytes().to_vec();
        let profile = ports.profiles.profile(tenancy).map_err(port("RuntimeProfiles"))?.ok_or(InputsError::ProfileUnknown)?;

        // The latest assignment of each survey to each cohort for this account (the journal is
        // oldest first). One survey may go to several cohorts, so both key the assignment.
        let mut latest: BTreeMap<(String, CohortId), Generation> = BTreeMap::new();
        for a in ports.registry.assignments().map_err(port("RegistryStore"))?.into_iter().filter(|a| a.account == record.account) {
            latest.insert((a.survey, a.cohort), a.generation);
        }
        let assignments: Vec<(String, CohortId, Generation)> = latest.into_iter().map(|((survey, cohort), generation)| (survey, cohort, generation)).collect();

        let recorded = ports.artefacts.withdrawals().map_err(port("ArtefactRegistry"))?;
        // A withdrawal counts only when it verifies against the publication it names, under
        // the trusted publishing policy: a forged one denies nothing. (The bundle carries every
        // recorded withdrawal and the device checks them again.)
        let mut withdrawn: BTreeSet<ContentAddress> = BTreeSet::new();
        for w in &recorded {
            if let Some(p) = ports.artefacts.get(w.address()).map_err(port("ArtefactRegistry"))?
                && ports.verifier.verify_withdrawal(w, &p).is_ok()
            {
                withdrawn.insert(*w.address());
            }
        }
        let withdrawals = recorded.iter().map(|w| *sha256(&w.encode()).as_bytes()).collect::<BTreeSet<_>>().into_iter().collect();
        let mut skipped = Vec::new();

        // For each survey: the highest non-withdrawn semver that satisfies DIS-012 (DIS-012).
        let mut instruments = Vec::new();
        let mut left_out = Vec::new();
        let mut roster_fields = BTreeSet::new();
        for (survey, _, _) in &assignments {
            let versions = live_versions(ports.artefacts, ArtefactKind::Instrument, survey, &withdrawn)?;
            let mut readable = false;
            for (label, _, address) in &versions {
                let Some(p) = verified(&ports, address, &recorded, (ArtefactKind::Instrument, survey, label), &mut skipped)? else { continue };
                let Ok(facts) = instrument_facts(&p.artefact) else { continue };
                readable = true;
                match check_compatibility(facts.schema, profile.instrument_schema) {
                    Compatibility::Compatible => {
                        instruments.push((survey.clone(), facts.address));
                        roster_fields.extend(facts.roster_fields);
                        break;
                    }
                    Compatibility::Incompatible(_) => {}
                }
            }
            if !instruments.iter().any(|(s, _)| s == survey) {
                left_out.push((survey.clone(), if readable { LeftOut::Incompatible } else { LeftOut::Unavailable }));
            }
        }

        // Layouts: found by the name `<survey>-<window>` (the registry lists by kind and name
        // only; a name holds lower-case words and hyphens, so the design's `<survey>.<window>`
        // cannot be one, and the example layouts are named this way), kept when bound to the selected instrument's fingerprint (INS-200), the newest
        // of each window class (INS-207).
        let mut layouts = Vec::new();
        if release.layouts == LayoutAssignment::Bound {
            for (survey, instrument) in &instruments {
                let fingerprint = Fingerprint::from(*instrument.as_bytes());
                for window in WindowClass::ALL {
                    let name = format!("{survey}-{}", window.name());
                    for (label, _, address) in live_versions(ports.artefacts, ArtefactKind::Layout, &name, &withdrawn)? {
                        let Some(p) = verified(&ports, &address, &recorded, (ArtefactKind::Layout, &name, &label), &mut skipped)? else { continue };
                        if layout_facts(&p.artefact).is_ok_and(|f| f.instrument == fingerprint) {
                            layouts.push(address);
                            break;
                        }
                    }
                }
            }
        }

        let rosters = match ports.rosters.current_rosters(tenancy) {
            Ok(r) => r,
            Err(e) => return Err(port("RosterSource")(e)),
        };
        Ok(Self {
            tenancy: *tenancy,
            assignments,
            instruments,
            left_out,
            layouts,
            withdrawals,
            rosters,
            roster_fields,
            certificate: record.certificate.as_ref().map(|c| ContentAddress::of(&c.encode())),
            agreement_key,
            profile,
            release,
            signing,
            skipped,
        })
    }

    /// The digest of the inputs: SHA-256 of their canonical CBOR. It covers exactly what the
    /// bundle is built from, so it differs when the next bundle would.
    pub fn digest(&self) -> [u8; 32] {
        let text = |s: &str| Value::Text(s.to_owned());
        let int = |n: u64| Value::Int(i128::from(n));
        let bytes = |b: &[u8]| Value::Bytes(b.to_vec());
        let list = |items: Vec<Value>| Value::Array(items);
        let value = cbor::map([
            ("v", int(1)),
            ("tenancy", bytes(self.tenancy.as_bytes())),
            ("assignments", list(self.assignments.iter().map(|(s, c, g)| list(vec![text(s), text(c.as_str()), int(u64::from(g.0))])).collect())),
            ("instruments", list(self.instruments.iter().map(|(s, a)| list(vec![text(s), bytes(a.as_bytes())])).collect())),
            ("layouts", list(self.layouts.iter().map(|a| bytes(a.as_bytes())).collect())),
            ("withdrawals", list(self.withdrawals.iter().map(|d| bytes(d)).collect())),
            (
                "rosters",
                list(self.rosters.iter().map(|r| list(vec![text(r.cohort.as_str()), int(r.version), int(u64::from(r.generation.0)), bytes(sha256(&r.encode()).as_bytes())])).collect()),
            ),
            ("certificate", list(self.certificate.iter().map(|c| bytes(c.as_bytes())).collect())),
            ("agreement", bytes(&self.agreement_key)),
            (
                "profile",
                list(vec![
                    int(u64::from(self.profile.instrument_schema.major)),
                    int(u64::from(self.profile.instrument_schema.minor)),
                    int(u64::from(self.profile.instrument_schema.patch)),
                    list(self.profile.localisation_reference.iter().map(|r| text(r)).collect()),
                ]),
            ),
            ("policy", list(self.release.sources.iter().map(|a| bytes(a.as_bytes())).collect())),
            ("layoutPolicy", text(self.release.layouts.as_str())),
            ("signer", bytes(self.signing.signer.as_bytes())),
            ("trust", bytes(&self.signing.trust)),
        ]);
        *sha256(&cbor::encode(&value).expect("the inputs always encode")).as_bytes()
    }

    /// The request that builds a bundle from these inputs.
    pub fn request_for(&self) -> BuildRequest {
        let mut request = BuildRequest::new(self.tenancy, self.instruments.iter().map(|(_, a)| *a).collect());
        request.layouts.clone_from(&self.layouts);
        request.assignments = self
            .assignments
            .iter()
            .filter_map(|(survey, cohort, generation)| {
                let (_, instrument) = self.instruments.iter().find(|(s, _)| s == survey)?;
                Some(BundleAssignment { survey: survey.clone(), instrument: *instrument, cohort: cohort.clone(), generation: *generation })
            })
            .collect();
        request
    }
}
