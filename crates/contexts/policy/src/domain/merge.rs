//! Layers, the effective-policy merge and policy diffs (POL-020 to POL-023).

use fieldseal_kernel::id::ContentAddress;

use super::control::{ControlValue, Kind, Merge, SetItems, Tightness, compare};
use super::document::{Layer, PolicyDocument};
use super::finding::{Finding, has_errors};
use super::invariant::check_floors;
use super::schema::{control_spec, schema};
use super::sections::{
    Controls, FactoryPolicy, IntakePolicy, PublishingPolicy, RuntimePolicy,
};

/// A policy document that passed publishing verification, with the content address it was
/// published under (POL-004, POL-023).
#[derive(Clone, PartialEq, Debug)]
pub struct PublishedPolicy {
    /// The content address of the published policy.
    pub address: ContentAddress,
    /// The decoded document.
    pub document: PolicyDocument,
}

/// The result of merging the layers that apply to one decision (POL §2).
#[derive(Clone, PartialEq, Debug)]
pub struct EffectivePolicy {
    /// Content addresses of the layers it came from, outermost first (POL-023). Never empty.
    pub sources: Vec<ContentAddress>,
    /// The merged controls.
    pub controls: Controls,
}

impl EffectivePolicy {
    /// The typed `factory` section.
    pub fn factory(&self) -> FactoryPolicy {
        self.controls.factory()
    }

    /// The typed `runtime` section.
    pub fn runtime(&self) -> RuntimePolicy {
        self.controls.runtime()
    }

    /// The typed `intake` section.
    pub fn intake(&self) -> IntakePolicy {
        self.controls.intake()
    }

    /// The typed `publishing` section.
    pub fn publishing(&self) -> PublishingPolicy {
        self.controls.publishing()
    }
}

/// Renders a control value for messages.
pub fn describe(value: &ControlValue) -> String {
    match value {
        ControlValue::Bool(b) => b.to_string(),
        ControlValue::Int(i) => i.to_string(),
        ControlValue::Ratio(d) => d.to_string(),
        ControlValue::Duration(d) => d.to_string(),
        ControlValue::Size(s) => s.to_string(),
        ControlValue::Date(d) => d.to_string(),
        ControlValue::Choice(t) | ControlValue::Text(t) => t.clone(),
        ControlValue::Durations(ds) => {
            format!("[{}]", ds.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
        }
        ControlValue::Set(items) => format!("[{}]", items.join(", ")),
        ControlValue::Argon2(a) => {
            format!("{{memory: {}, iterations: {}, parallelism: {}}}", a.memory, a.iterations, a.parallelism)
        }
        ControlValue::Threshold(t) => format!("{{m: {}, n: {}}}", t.m, t.n),
    }
}

fn is_range_set(kind: Kind) -> bool {
    matches!(kind, Kind::Set(SetItems::Range))
}

/// Merges layers outermost first. Each control merges by the rule its schema entry declares:
/// the deployment layer sets controls freely (subject to the floors); later layers may only
/// tighten `tighten` controls, narrow `intersect` controls and widen `union` controls
/// (POL-020). An attempt to loosen is an error naming the key and the layer (POL-021).
/// Missing controls take the schema default (POL-022). The effective set is checked against
/// the floors again (POL-010).
///
/// Ranges (`acceptedRuntimeVersions`) intersect as a conjunction: a version must satisfy the
/// range of every layer.
pub fn merge_layers(layers: &[&PolicyDocument]) -> (Controls, Vec<Finding>) {
    let mut findings = Vec::new();
    match layers.first() {
        None => findings.push(Finding::error("POL-020", "layers", "no policy layers to merge")),
        Some(first) if first.layer != Layer::Deployment => findings.push(Finding::error(
            "POL-020",
            "layers",
            "the first layer must be the deployment layer",
        )),
        _ => {}
    }
    for pair in layers.windows(2) {
        if pair[1].layer.rank() <= pair[0].layer.rank() {
            findings.push(Finding::error(
                "POL-020",
                "layers",
                format!(
                    "layers must be applied deployment, programme, instrument, once each; {} follows {}",
                    pair[1].layer.label(),
                    pair[0].layer.label()
                ),
            ));
        }
    }
    let mut acc = Controls::defaults().as_map().clone();
    for doc in layers {
        let label = doc.layer.label();
        let first = doc.layer == Layer::Deployment;
        for (path, new) in &doc.controls {
            let Some(spec) = control_spec(path) else {
                findings.push(Finding::error("POL-002", path.clone(), "unknown control").in_layer(label.clone()));
                continue;
            };
            let old = acc.get(path).cloned();
            match (spec.merge, old) {
                (Merge::Override, _) => {
                    acc.insert(path.clone(), new.clone());
                }
                (Merge::Tighten(_), Some(old))
                    if !first && compare(spec.kind, spec.merge, &old, new) == Tightness::Looser =>
                {
                    findings.push(
                        Finding::error(
                            "POL-021",
                            path.clone(),
                            format!(
                                "loosens {path}: {} would replace {}; a later layer may only tighten",
                                describe(new),
                                describe(&old)
                            ),
                        )
                        .in_layer(label.clone()),
                    );
                }
                (Merge::Intersect, Some(ControlValue::Set(old))) if !first => {
                    let ControlValue::Set(new_items) = new else { continue };
                    let merged: Vec<String> = if is_range_set(spec.kind) {
                        let mut all = old.clone();
                        for item in new_items {
                            if !all.contains(item) {
                                all.push(item.clone());
                            }
                        }
                        all.sort();
                        all
                    } else {
                        let dropped: Vec<&String> = new_items.iter().filter(|i| !old.contains(i)).collect();
                        if !dropped.is_empty() {
                            findings.push(
                                Finding::warning(
                                    "POL-020",
                                    path.clone(),
                                    format!(
                                        "values not allowed by an earlier layer are dropped: {}",
                                        dropped.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                                    ),
                                )
                                .in_layer(label.clone()),
                            );
                        }
                        old.iter().filter(|i| new_items.contains(i)).cloned().collect()
                    };
                    if merged.is_empty() {
                        findings.push(
                            Finding::warning("POL-020", path.clone(), "the layers allow nothing in common")
                                .in_layer(label.clone()),
                        );
                    }
                    acc.insert(path.clone(), ControlValue::Set(merged));
                }
                (Merge::Union, Some(ControlValue::Set(old))) if !first => {
                    let ControlValue::Set(new_items) = new else { continue };
                    let mut all = old;
                    for item in new_items {
                        if !all.contains(item) {
                            all.push(item.clone());
                        }
                    }
                    all.sort();
                    acc.insert(path.clone(), ControlValue::Set(all));
                }
                _ => {
                    acc.insert(path.clone(), new.clone());
                }
            }
        }
        findings.extend(check_floors(&doc.controls, "").into_iter().map(|f| f.in_layer(label.clone())));
    }
    let effective = Controls::from_map(acc);
    if !has_errors(&findings) {
        findings.extend(check_floors(effective.as_map(), ""));
    }
    (effective, findings)
}

/// How one control changed between two policies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeDirection {
    /// Stricter.
    Tighter,
    /// Weaker, or not comparable (the safest reading).
    Looser,
    /// An operational control changed; strictness does not apply.
    Changed,
}

/// One control-by-control change (`DiffPolicies`).
#[derive(Clone, PartialEq, Debug)]
pub struct ControlChange {
    /// The control path.
    pub path: String,
    /// The value before: set, or the schema default; `None` when unset.
    pub before: Option<ControlValue>,
    /// The value after.
    pub after: Option<ControlValue>,
    /// Tighter, looser or merely changed.
    pub direction: ChangeDirection,
}

/// Lists the controls whose effective value differs between `before` and `after`, each marked
/// tighter or looser by the control's merge rule. Controls a document does not set count at
/// their schema default.
pub fn diff_documents(before: &PolicyDocument, after: &PolicyDocument) -> Vec<ControlChange> {
    let mut out = Vec::new();
    for spec in schema() {
        let value = |d: &PolicyDocument| d.controls.get(&spec.path).or(spec.default.as_ref()).cloned();
        let (b, a) = (value(before), value(after));
        let direction = match (&b, &a) {
            (Some(x), Some(y)) if x.same_as(y) => continue,
            (None, None) => continue,
            (Some(x), Some(y)) => match spec.merge {
                Merge::Override => ChangeDirection::Changed,
                _ => match compare(spec.kind, spec.merge, x, y) {
                    Tightness::Tighter => ChangeDirection::Tighter,
                    Tightness::Same => continue,
                    Tightness::Looser => ChangeDirection::Looser,
                },
            },
            (None, Some(_)) => match spec.merge {
                Merge::Tighten(_) | Merge::Intersect => ChangeDirection::Tighter,
                _ => ChangeDirection::Changed,
            },
            (Some(_), None) => match spec.merge {
                Merge::Tighten(_) | Merge::Intersect => ChangeDirection::Looser,
                _ => ChangeDirection::Changed,
            },
        };
        out.push(ControlChange { path: spec.path.clone(), before: b, after: a, direction });
    }
    out
}
