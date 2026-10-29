//! Publishing the example content: surveys (instruments and their layouts) and the rosters that
//! belong with them.

use std::collections::BTreeMap;
use std::path::Path;

use fieldseal_adapters_authoring::survey::{RosterSet, SurveyTree};
use fieldseal_adapters_authoring::LoadedSurvey;
use fieldseal_adapters_memory::demo::DemoWorld;
use fieldseal_distribution::domain::{ConsentState, Roster, RosterEntry};
use fieldseal_instrument::application::validate_instrument;
use fieldseal_instrument::domain::Instrument;
use fieldseal_kernel::Value;
use fieldseal_kernel::cbor;
use fieldseal_kernel::id::{CohortId, ContentAddress, Fingerprint, Generation, SubjectId};
use fieldseal_publishing::domain::{ArtefactKind, Publication};

/// A published instrument and what is known about it.
#[derive(Clone, Debug)]
pub(crate) struct PublishedInstrument {
    pub(crate) name: String,
    /// The survey folder the instrument was loaded from, which names its roster's cohort.
    pub(crate) stem: String,
    pub(crate) publication: Publication,
    pub(crate) model: Instrument,
    pub(crate) fingerprint: Fingerprint,
}

/// A published layout and the instrument it is for.
#[derive(Clone, Debug)]
pub(crate) struct PublishedLayout {
    pub(crate) publication: Publication,
    pub(crate) instrument: ContentAddress,
}

/// Everything published from the examples directory.
#[derive(Default)]
pub(crate) struct Content {
    pub(crate) instruments: Vec<PublishedInstrument>,
    pub(crate) layouts: Vec<PublishedLayout>,
    /// Rosters by the survey folder they were loaded for.
    pub(crate) rosters: Vec<(String, Roster)>,
    pub(crate) warnings: Vec<String>,
}

/// The cohort whose roster each example survey uses. This crate is removed with the demo it
/// serves, so the map is fixed here instead of read from configuration.
const COHORTS: &[(&str, &str)] = &[("school-meals-baseline", "cohort-a"), ("household-water-access", "village-a")];

fn load(path: &Path) -> Result<Value, String> {
    fieldseal_adapters_authoring::decode_path(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn meta(doc: &Value, key: &str) -> Option<String> {
    doc.as_map().and_then(|m| m.get("metadata")).and_then(Value::as_map).and_then(|m| m.get(key)).and_then(Value::as_text).map(str::to_owned)
}

impl Content {
    /// Publishes every valid survey under `dir/surveys` (its instrument and its layouts), and
    /// loads the roster of each survey's cohort from `dir/rosters`. Anything that fails is
    /// skipped with a warning.
    pub(crate) fn publish(world: &DemoWorld, dir: &Path) -> Self {
        let mut c = Self::default();
        let tree = match SurveyTree::open(&dir.join("surveys")) {
            Ok(tree) => tree,
            Err(e) => {
                c.warnings.push(e.to_string());
                return c;
            }
        };
        for name in tree.names() {
            match tree.survey(name).map_err(|e| e.to_string()).and_then(|s| s.load().map_err(|errors| errors.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))) {
                Ok(loaded) => {
                    if let Err(e) = c.survey(world, name, loaded) {
                        c.warnings.push(format!("survey {name} skipped: {e}"));
                    }
                }
                Err(e) => c.warnings.push(format!("survey {name} skipped: {e}")),
            }
        }
        let rosters = match RosterSet::open(&dir.join("rosters")) {
            Ok(rosters) => rosters,
            Err(errors) => {
                c.warnings.extend(errors.iter().map(ToString::to_string));
                return c;
            }
        };
        let names: Vec<String> = c.instruments.iter().map(|i| i.stem.clone()).collect();
        for s in names {
            let Some(cohort) = COHORTS.iter().find(|(survey, _)| *survey == s).map(|(_, cohort)| *cohort) else {
                c.warnings.push(format!("no roster cohort for {s}"));
                continue;
            };
            let Some(file) = rosters.latest(cohort) else {
                c.warnings.push(format!("no roster file for {s}"));
                continue;
            };
            match load(&file.path).and_then(|doc| roster(&doc)) {
                Ok(r) if c.rosters.iter().any(|(_, x)| x.cohort == r.cohort) => c.warnings.push(format!("roster {}: the cohort {} is already taken", file.path.display(), r.cohort.as_str())),
                Ok(r) => c.rosters.push((s, r)),
                Err(e) => c.warnings.push(format!("roster {} skipped: {e}", file.path.display())),
            }
        }
        c
    }

    fn survey(&mut self, world: &DemoWorld, stem: &str, loaded: LoadedSurvey) -> Result<(), String> {
        let doc = loaded.instrument;
        let valid = validate_instrument(&doc).map_err(|f| format!("the instrument is invalid ({} finding(s))", f.iter().count()))?;
        let name = meta(&doc, "name").ok_or("no metadata.name")?;
        let version = meta(&doc, "version").ok_or("no metadata.version")?;
        let publication = world.publish(ArtefactKind::Instrument, &name, &version, cbor::encode(&doc).map_err(|e| e.to_string())?, Some(DemoWorld::salt_for(&name)))?;
        let fingerprint = Fingerprint::from(*publication.address().as_bytes());
        let address = *publication.address();
        self.instruments.push(PublishedInstrument { name, stem: stem.to_owned(), publication, model: valid.instrument, fingerprint });
        for (window, layout) in loaded.layouts {
            if let Err(e) = self.layout(world, layout, address) {
                self.warnings.push(format!("layout {stem}/{window} skipped: {e}"));
            }
        }
        Ok(())
    }

    fn layout(&mut self, world: &DemoWorld, mut doc: Value, address: ContentAddress) -> Result<(), String> {
        let name = meta(&doc, "name").ok_or("no metadata.name")?;
        let version = meta(&doc, "version").ok_or("no metadata.version")?;
        // A layout names its instrument by fingerprint once canonicalised (INS-200).
        if let Value::Map(root) = &mut doc
            && let Some(Value::Map(spec)) = root.get_mut("spec")
        {
            spec.insert("instrument".into(), Value::Bytes(address.as_bytes().to_vec()));
        }
        let publication = world.publish(ArtefactKind::Layout, &name, &version, cbor::encode(&doc).map_err(|e| e.to_string())?, None)?;
        self.layouts.push(PublishedLayout { publication, instrument: address });
        Ok(())
    }
}

/// A roster from the examples' roster file format: `cohort`, `version` and `subjects`.
pub(crate) fn roster(doc: &Value) -> Result<Roster, String> {
    let map = doc.as_map().ok_or("a roster is a map")?;
    let cohort = map.get("cohort").and_then(Value::as_text).ok_or("a roster needs `cohort`")?;
    let version = match map.get("version") {
        Some(Value::Int(v)) => u64::try_from(*v).map_err(|_| "version out of range")?,
        _ => 1,
    };
    let Some(Value::Array(subjects)) = map.get("subjects") else { return Err("a roster needs `subjects`".into()) };
    let mut entries = Vec::new();
    for (i, s) in subjects.iter().enumerate() {
        let s = s.as_map().ok_or("a subject is a map")?;
        let id = s.get("subject").and_then(Value::as_text).ok_or("a subject needs `subject`")?;
        let consent = match s.get("consent").and_then(Value::as_text).unwrap_or("unknown") {
            "granted" => ConsentState::Granted,
            "refused" => ConsentState::Refused,
            "unknown" => ConsentState::Unknown,
            other => return Err(format!("unknown consent state {other}")),
        };
        let attributes: BTreeMap<String, Value> = match s.get("fields") {
            Some(Value::Map(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            _ => BTreeMap::new(),
        };
        entries.push(RosterEntry {
            ordinal: u32::try_from(i + 1).map_err(|_| "too many subjects")?,
            subject: SubjectId::new(id).map_err(|e| e.to_string())?,
            display: s.get("display").and_then(Value::as_text).unwrap_or(id).to_owned(),
            attributes,
            consent,
            prior_status: s.get("prior_status").and_then(Value::as_text).map(str::to_owned),
        });
    }
    Ok(Roster { cohort: CohortId::new(cohort).map_err(|e| e.to_string())?, version, generation: Generation(1), entries })
}
