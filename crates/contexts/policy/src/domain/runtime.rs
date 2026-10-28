//! The typed runtime evaluator (POL-031, POL-051, POL-052).
//!
//! The runtime does not use [`PolicyEngine`](crate::ports::PolicyEngine). It builds a
//! [`RuntimeEvaluator`] from the policy layers in the bundle it is running and answers its
//! questions by direct, deterministic code. Nothing else feeds it: no environment, no
//! network, no clock. The invariant floors are re-checked when it is built, so a bundle
//! cannot configure a weaker runtime than the code allows.

use std::collections::BTreeMap;

use super::choice::{ExportDestination, Restriction, Toggle};
use super::document::{Layer, PolicyDocument};
use super::finding::{Finding, has_errors};
use super::invariant::check_floors;
use super::merge::{EffectivePolicy, merge_layers};
use super::sections::{Controls, RuntimePolicy};
use super::units::{Duration, Version};

/// What can lock a session besides idleness.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockTrigger {
    /// The app moved to the background.
    Background,
    /// The screen turned off.
    ScreenOff,
}

/// Answers the runtime's policy questions from its effective `runtime` section.
#[derive(Clone, PartialEq, Debug)]
pub struct RuntimeEvaluator {
    policy: RuntimePolicy,
}

impl RuntimeEvaluator {
    /// Builds the evaluator from an effective policy, checking the invariant floors first
    /// (POL-051, POL-010).
    pub fn from_effective(effective: &EffectivePolicy) -> Result<Self, Vec<Finding>> {
        Self::from_controls(&effective.controls)
    }

    fn from_controls(controls: &Controls) -> Result<Self, Vec<Finding>> {
        let findings = check_floors(controls.as_map(), "");
        if has_errors(&findings) {
            return Err(findings);
        }
        Ok(Self { policy: controls.runtime() })
    }

    /// Builds the evaluator from the policy layers carried in a bundle, outermost first.
    /// The layers are merged by the same rules as everywhere else (a looser later layer is an
    /// error) and the floors are checked (POL-031, POL-051).
    pub fn from_bundle(layers: &[&PolicyDocument]) -> Result<Self, Vec<Finding>> {
        let (controls, findings) = merge_layers(layers);
        if has_errors(&findings) {
            return Err(findings);
        }
        Self::from_controls(&controls)
    }

    /// The effective `runtime` section.
    pub fn policy(&self) -> &RuntimePolicy {
        &self.policy
    }

    /// Whether a PIN of `length` digits is long enough (INV-4).
    pub fn pin_length_acceptable(&self, length: u64) -> bool {
        length >= self.policy.pin.min_length
    }

    /// The lockout after `failures` consecutive wrong PINs: none until
    /// `failuresBeforeLockout`, then each further failure moves one step up the escalating
    /// delays, staying at the last (INV-5).
    pub fn lockout_delay(&self, failures: u64) -> Option<Duration> {
        let threshold = self.policy.pin.failures_before_lockout;
        if failures < threshold {
            return None;
        }
        let steps = &self.policy.pin.lockout_steps;
        let index = usize::try_from(failures - threshold).unwrap_or(usize::MAX);
        steps.get(index).or_else(|| steps.last()).copied()
    }

    /// Whether a session idle for `idle` must lock (INV-6).
    pub fn session_expired(&self, idle: Duration) -> bool {
        idle >= self.policy.session.idle_lock
    }

    /// Whether `trigger` locks the session.
    pub fn locks_on(&self, trigger: LockTrigger) -> bool {
        match trigger {
            LockTrigger::Background => self.policy.session.lock_on_background,
            LockTrigger::ScreenOff => self.policy.session.lock_on_screen_off,
        }
    }

    /// Whether exports may go to `destination`.
    pub fn export_allowed(&self, destination: ExportDestination) -> bool {
        self.policy.export.destinations.contains(&destination)
    }

    /// Whether parity starts on.
    pub fn parity_default_on(&self) -> bool {
        self.policy.export.parity_default == Toggle::On
    }

    /// Whether the collector may turn parity off.
    pub fn may_turn_parity_off(&self) -> bool {
        self.policy.export.allow_parity_off
    }

    /// The wait before upload retry number `attempt` (counting from 0), staying at the last
    /// step.
    pub fn retry_delay(&self, attempt: usize) -> Duration {
        let steps = &self.policy.upload.retry_backoff;
        steps
            .get(attempt)
            .or_else(|| steps.last())
            .copied()
            .unwrap_or(Duration::from_mins(1))
    }

    /// Whether to offer clearing the device when a receipt arrives.
    pub fn offer_clear_on_receipt(&self) -> bool {
        self.policy.retention.offer_clear_on_receipt
    }

    /// Whether to remind about uncleared data that has waited `waited`.
    pub fn reminder_due(&self, waited: Duration) -> bool {
        waited >= self.policy.retention.remind_after
    }

    /// Whether a tree head of age `age` is too old to trust.
    pub fn tree_head_stale(&self, age: Duration) -> bool {
        age > self.policy.max_tree_head_age
    }

    /// The required restrictions missing from `present`.
    pub fn missing_restrictions(&self, present: &[Restriction]) -> Vec<Restriction> {
        self.policy
            .device
            .required_restrictions
            .iter()
            .filter(|r| !present.contains(r))
            .copied()
            .collect()
    }

    /// Whether an image edge of `pixels` is within the limit.
    pub fn image_edge_allowed(&self, pixels: u64) -> bool {
        pixels <= self.policy.max_image_edge
    }
}

/// Remembers the highest policy version applied per layer and name, so a runtime refuses to go
/// back to an older one (POL-052).
#[derive(Clone, Default, Debug)]
pub struct AppliedVersions {
    applied: BTreeMap<(Layer, String), Version>,
}

impl AppliedVersions {
    /// A runtime that has applied nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every layer and name applied so far, with the highest version, in a stable order. A
    /// runtime that persists what it applied writes these out.
    pub fn entries(&self) -> impl Iterator<Item = (&Layer, &str, Version)> {
        self.applied.iter().map(|((layer, name), version)| (layer, name.as_str(), *version))
    }

    /// Restores one persisted entry, keeping the higher version if the layer and name are
    /// already present. It is not an admission check: use [`AppliedVersions::admit`] for a
    /// document being offered.
    pub fn restore(&mut self, layer: Layer, name: String, version: Version) {
        let slot = self.applied.entry((layer, name)).or_insert(version);
        if *slot < version {
            *slot = version;
        }
    }

    /// Whether `document` would be admitted, without recording it (POL-052).
    pub fn check(&self, document: &PolicyDocument) -> Result<(), Finding> {
        self.clone().admit(document)
    }

    /// Admits `document` unless an older version of the same layer and name is being offered
    /// after a newer one (POL-052), and records it. Re-applying the same version is allowed.
    pub fn admit(&mut self, document: &PolicyDocument) -> Result<(), Finding> {
        let key = (document.layer.clone(), document.metadata.name.clone());
        let offered = document.metadata.version;
        match self.applied.get(&key) {
            Some(current) if offered < *current => Err(Finding::error(
                "POL-052",
                "metadata.version",
                format!(
                    "version {offered} is lower than the {current} already applied for {} `{}`",
                    document.layer.label(),
                    document.metadata.name
                ),
            )),
            _ => {
                self.applied.insert(key, offered);
                Ok(())
            }
        }
    }
}
