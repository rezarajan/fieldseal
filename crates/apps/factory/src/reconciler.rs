//! The reconciler (Technical Plan section 7.3): the factory component that compares each
//! tenancy's build inputs with those of its last build and calls `BuildBundle` when they
//! differ, or when the anchor of the stored bundle is too old (DIS-010).
//!
//! It runs on its own thread ([`Reconciler::spawn`]) so a build never holds up a request:
//! the HTTP adapter only tells it which tenancy changed ([`Spawned::notify`]), and the thread
//! also scans the artefact registry at an interval, because the file adapters have no change
//! events. It reads tenancies and never changes them; the use cases do that.
//!
//! **Write order.** For each build: (1) the rosters issued to the tenancy are recorded for
//! intake and flushed; (2) the bundle is built and stored (the store renames it into place
//! and writes its metadata last); (3) the digest of the inputs is written beside the bundle.
//! The digest is last, so it never names inputs for which no bundle is stored. A crash
//! between two steps leaves the previous bundle in place and the next pass rebuilds. After
//! each step the reconciler calls a [`BuildWriteHook`], which the crash tests use to stop
//! the build at that point.
//!
//! A build that fails keeps the previous bundle. A tenancy whose build failed is retried when
//! its input digest changes, or after a backoff that doubles up to five minutes, so a failure
//! that persists is not signed again every pass. Events carry no subject data (DEP-051): a
//! tenancy is named by the first 16 hex digits of its identifier, a failure by a code.
//!
//! **Trust.** The release policy is a publication, so it is never verified under the policy
//! it carries (a publisher key could publish a policy that lowers its own threshold).
//! [`PolicyTrust`] says what it is verified against: outside development the one content
//! address the operator pinned, in development the schema defaults with configured builders
//! and sources. Only then are the other artefact kinds verified under the policy's own
//! publishing section. Artefacts are verified when they are selected, so a forged higher
//! version is skipped (with an event) instead of blocking every build, and a withdrawal counts
//! only when it verifies.
//!
//! **One view per pass.** The tenancy record and the assignment journal of a pass are read from
//! one snapshot of the registry journal. The reconciler does not take the registry's cohort
//! lock: the builder re-reads the record and fails closed if it changed. A pass is skipped
//! for a tenancy while the watched directories and the journal are unchanged and its anchor is
//! fresh.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fieldseal_adapters_factory_http::{BUNDLE_LIMIT, ReconcileNotify};
use fieldseal_adapters_file::atomic::write_atomic;
use fieldseal_adapters_file::rosters::{FileRosterHistory, record_issued};
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_memory::distribution::ClockAnchorSource;
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog, MemoryPolicySource};
use fieldseal_distribution::application::{BuildBundle, BundleBuilder, FactoryIdentity, FactoryPorts, check_state, decide_release, release_facts};
use fieldseal_distribution::domain::{BundleSeq, ConsentState, DistributionError, Roster};
use fieldseal_distribution::ports::{BundleStore, RosterSource, RosterSourceError, RuntimeProfiles};
use fieldseal_instrument::domain::SemVer;
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
use fieldseal_intake::ports::RosterHistory;
use fieldseal_kernel::cbor;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{CohortId, ContentAddress, Digest, KeyId, TenancyId};
use fieldseal_policy::application::{ComputeEffectivePolicy, PolicyService};
use fieldseal_policy::domain::{Controls, LayerSelector, PublishedPolicy, PublishingPolicy, decode_document};
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::ArtefactKind;
use fieldseal_publishing::ports::ArtefactRegistry;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::{TrustBundle, TrustStore};
use fieldseal_trust::ports::{AuthorityClock, KeyCustody, RandomSource};

use crate::config::PolicyTrust;
use crate::inputs::{BuildInputs, InputPorts, InputsError, ReleaseInputs, SigningInputs, Skipped, verify_code};

/// The artefact name of the deployment policy the factory reads its release policy from.
pub const DEPLOYMENT_POLICY: &str = "deployment-policy";

/// The three writes of one build, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WriteStep {
    /// The issued rosters are recorded for intake and flushed.
    IssuedRosters,
    /// The bundle is stored.
    Bundle,
    /// The digest of the inputs is stored.
    Digest,
}

/// Called after each write step of a build. An error stops the build as a crash would: nothing
/// later is written.
pub trait BuildWriteHook: Send + Sync {
    /// `step` has been written for `tenancy`. The default does nothing.
    fn after(&self, _tenancy: &TenancyId, _step: WriteStep) -> Result<(), String> {
        Ok(())
    }
}

/// The hook that does nothing.
pub struct NoHook;

impl BuildWriteHook for NoHook {}

/// What the reconciler tells the factory's event log. None of it is subject data (DEP-051).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReconcileEvent {
    /// A bundle was built and stored (`bundle-built`).
    Built {
        /// The tenancy.
        tenancy: TenancyId,
        /// The sequence number.
        seq: u64,
        /// The bundle's content address.
        address: ContentAddress,
        /// Instruments in the bundle.
        instruments: usize,
        /// Layouts in the bundle.
        layouts: usize,
        /// Rosters in the bundle.
        rosters: usize,
    },
    /// Nothing was built, and why (`bundle-withheld`).
    Withheld {
        /// The tenancy.
        tenancy: TenancyId,
        /// The reason: `no-policy`, `instrument-incompatible`, `tenancy-lost`, ...
        reason: String,
        /// The survey the reason is about, for an instrument.
        survey: Option<String>,
    },
    /// A build failed and the previous bundle stays (`bundle-failed`).
    Failed {
        /// The tenancy.
        tenancy: TenancyId,
        /// A code for the failure.
        reason: String,
    },
    /// A published version did not verify and was passed over (`artefact-skipped`). It is told
    /// once per version and code.
    Skipped {
        /// The artefact kind.
        kind: String,
        /// The artefact name.
        name: String,
        /// The version label.
        version: String,
        /// A code for why.
        reason: String,
    },
    /// A pass could not read its inputs (`reconcile-failed`).
    PassFailed {
        /// A code for the failure.
        reason: String,
    },
}

/// Receives the [`ReconcileEvent`]s.
pub type ReconcileEvents = Arc<dyn Fn(&ReconcileEvent) + Send + Sync>;

/// What one reconciliation of one tenancy did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// A bundle with this sequence number was stored.
    Built(BundleSeq),
    /// The inputs are unchanged and the anchor is fresh: nothing was built.
    Unchanged,
    /// Nothing was built, with the reason.
    Withheld(String),
    /// The build failed with this code; the previous bundle stays.
    Failed(String),
    /// The write hook stopped the build after this step.
    Stopped(WriteStep),
}

/// The ports the reconciler drives. They are shared with the HTTP thread, so each is `Sync`.
#[derive(Clone, Copy)]
pub struct ReconcilerPorts<'a> {
    /// Tenancies and the assignment journal (read only here).
    pub registry: &'a (dyn RegistryStore + Sync),
    /// Published artefacts and withdrawals.
    pub artefacts: &'a (dyn ArtefactRegistry + Sync),
    /// The roster store.
    pub rosters: &'a (dyn RosterSource + Sync),
    /// What each runtime reported at registration.
    pub profiles: &'a (dyn RuntimeProfiles + Sync),
    /// The stored bundles.
    pub bundles: &'a (dyn BundleStore + Sync),
    /// The `factory` and `receipt` keys.
    pub custody: &'a (dyn KeyCustody + Sync),
    /// Randomness for sealing.
    pub random: &'a (dyn RandomSource + Sync),
    /// The factory's clock.
    pub clock: &'a (dyn AuthorityClock + Sync),
}

/// The reconciler's settings.
#[derive(Clone, Debug)]
pub struct ReconcilerConfig {
    /// The trust bundle bundles and artefacts are verified against.
    pub trust: TrustBundle,
    /// The factory's signing identity.
    pub identity: FactoryIdentity,
    /// The `receipt` key that signs the anchor.
    pub receipt: KeyId,
    /// The bundle directory; the digest of a tenancy is `<dir>/<tenancy hex>/inputs.sha256`.
    pub bundle_dir: PathBuf,
    /// Where the issued rosters are recorded for intake.
    pub issued_rosters_dir: PathBuf,
    /// A stored bundle whose anchor is older than this is rebuilt, in milliseconds.
    pub max_anchor_age_ms: u64,
    /// What the release policy is verified against.
    pub policy_trust: PolicyTrust,
    /// The registry state directory, whose journal a pass reads as one snapshot. When none is
    /// named the pass reads the registry port directly.
    pub state_dir: Option<PathBuf>,
    /// Files and directories whose modification times say that an input may have changed (the
    /// artefact registry and its `withdrawals/`, the roster store, the state directory and its
    /// journal). While none changed, a tenancy that was up to date is not read again. When
    /// empty, every pass reads everything.
    pub watch: Vec<PathBuf>,
}

/// The release policy, as published.
struct LoadedPolicy {
    service: PolicyService<MemoryPolicySource, BuiltInPolicyEngine, MemoryDecisionLog>,
    inputs: ReleaseInputs,
    publishing: PublishingPolicy,
}

/// The modification times of the watched paths. Taken before a pass reads anything, so a change
/// during the pass shows at the next one.
type Stamp = Vec<Option<SystemTime>>;

/// A tenancy that was up to date: nothing it reads has changed while the stamp is the same and
/// the bundle's anchor is fresh.
struct Quiet {
    stamp: Stamp,
    issued_ms: u64,
}

/// A build that failed for these inputs: not tried again before `retry_at` unless the digest
/// changes.
struct FailureMemo {
    digest: [u8; 32],
    code: String,
    attempts: u32,
    retry_at: u64,
}

/// The wait before a failed build is tried again the first time, and the longest wait.
const BASE_BACKOFF_MS: u64 = 5_000;
const MAX_BACKOFF_MS: u64 = 300_000;

/// Why no release policy could be read.
enum PolicyFault {
    /// None is published: nothing is built.
    NoPolicy,
    /// One is published and is unusable (a code).
    Invalid(&'static str),
}

/// A [`RosterSource`] that returns the rosters the reconciler already read, so the rosters it
/// records for intake are exactly the ones the bundle carries.
struct SnapshotRosters<'a> {
    rosters: Vec<Roster>,
    inner: &'a dyn RosterSource,
}

impl RosterSource for SnapshotRosters<'_> {
    fn current_rosters(&self, _: &TenancyId) -> Result<Vec<Roster>, RosterSourceError> {
        Ok(self.rosters.clone())
    }

    fn active_tenancies(&self, cohort: &CohortId, except: &TenancyId) -> Result<u64, RosterSourceError> {
        self.inner.active_tenancies(cohort, except)
    }
}

/// The reconciler.
pub struct Reconciler<'a> {
    ports: ReconcilerPorts<'a>,
    config: ReconcilerConfig,
    hook: Box<dyn BuildWriteHook>,
    events: ReconcileEvents,
    /// One build at a time, whichever thread asks.
    building: Mutex<()>,
    /// The last event reason per tenancy, so a reason that persists is told once.
    last: Mutex<BTreeMap<TenancyId, String>>,
    /// Skipped versions already told.
    told_skipped: Mutex<BTreeSet<String>>,
    /// Tenancies found up to date, with the stamp they were found at.
    quiet: Mutex<BTreeMap<TenancyId, Quiet>>,
    /// Builds that failed, per tenancy.
    failures: Mutex<BTreeMap<TenancyId, FailureMemo>>,
    /// SHA-256 of the encoded trust bundle, part of every input digest.
    trust_digest: [u8; 32],
}

/// A code for a failed build: never the error text, which can hold paths.
fn failure_code(e: &DistributionError) -> String {
    match e {
        DistributionError::NotRegistered => "not-registered".into(),
        DistributionError::Withheld(_) => "withheld".into(),
        DistributionError::ArtefactNotPublished { .. } => "artefact-not-published".into(),
        DistributionError::IncompatibleSchema(_) => "incompatible-schema".into(),
        DistributionError::Composition(_) => "composition".into(),
        DistributionError::Roster { .. } => "roster".into(),
        DistributionError::TooLarge { .. } => "too-large".into(),
        DistributionError::Port { port, .. } => format!("port-{port}"),
        DistributionError::Wire(_) => "wire".into(),
        DistributionError::Rejected(_) => "rejected".into(),
    }
}

impl<'a> Reconciler<'a> {
    /// A reconciler over `ports` that tells `events` what it does.
    pub fn new(ports: ReconcilerPorts<'a>, config: ReconcilerConfig, events: ReconcileEvents) -> Self {
        let trust_digest = *sha256(&config.trust.encode().unwrap_or_default()).as_bytes();
        Self {
            ports,
            config,
            hook: Box::new(NoHook),
            events,
            building: Mutex::new(()),
            last: Mutex::new(BTreeMap::new()),
            told_skipped: Mutex::new(BTreeSet::new()),
            quiet: Mutex::new(BTreeMap::new()),
            failures: Mutex::new(BTreeMap::new()),
            trust_digest,
        }
    }

    /// Changes what the release policy is verified against.
    pub fn set_policy_trust(&mut self, trust: PolicyTrust) {
        self.config.policy_trust = trust;
    }

    /// Installs a hook called after each write step.
    #[must_use]
    pub fn with_hook(mut self, hook: Box<dyn BuildWriteHook>) -> Self {
        self.hook = hook;
        self
    }

    fn digest_path(&self, tenancy: &TenancyId) -> PathBuf {
        self.config.bundle_dir.join(lower_hex(tenancy.as_bytes())).join("inputs.sha256")
    }

    fn stored_digest(&self, tenancy: &TenancyId) -> Option<[u8; 32]> {
        let text = std::fs::read_to_string(self.digest_path(tenancy)).ok()?;
        let text = text.trim();
        if text.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(out)
    }

    /// Tells `event` unless it repeats the last reason told for the tenancy.
    fn tell(&self, tenancy: &TenancyId, key: String, event: ReconcileEvent) {
        let mut last = self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.get(tenancy) != Some(&key) {
            last.insert(*tenancy, key);
            drop(last);
            (self.events)(&event);
        }
    }

    fn withheld(&self, tenancy: &TenancyId, reason: &str, survey: Option<&str>) -> Outcome {
        let key = format!("withheld:{reason}:{}", survey.unwrap_or_default());
        self.tell(tenancy, key, ReconcileEvent::Withheld { tenancy: *tenancy, reason: reason.to_owned(), survey: survey.map(str::to_owned) });
        Outcome::Withheld(reason.to_owned())
    }

    fn failed(&self, tenancy: &TenancyId, code: &str) -> Outcome {
        self.tell(tenancy, format!("failed:{code}"), ReconcileEvent::Failed { tenancy: *tenancy, reason: code.to_owned() });
        Outcome::Failed(code.to_owned())
    }

    /// Writes (or clears) the marker that stops the stored bundle being delivered while policy
    /// holds the tenancy back (SR2-M2). A marker that cannot be written leaves the bundle
    /// deliverable, so it is told as a failure.
    fn set_withheld(&self, tenancy: &TenancyId, reasons: Option<&[String]>) {
        if self.ports.bundles.set_withheld(tenancy, reasons).is_err() {
            self.failed(tenancy, "port-BundleStore");
        }
    }

    /// Tells a version that was passed over, once per version and code.
    fn tell_skipped(&self, s: &Skipped) {
        let key = format!("{}:{}:{}:{}", s.kind, s.name, s.version, s.code);
        if self.told_skipped.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key) {
            (self.events)(&ReconcileEvent::Skipped { kind: s.kind.to_string(), name: s.name.clone(), version: s.version.clone(), reason: s.code.to_owned() });
        }
    }

    /// The release policy, verified against what the factory trusts ([`PolicyTrust`]) before any
    /// value is read from it.
    fn load_policy(&self) -> Result<LoadedPolicy, PolicyFault> {
        let artefacts = self.ports.artefacts;
        let fault = |_: fieldseal_publishing::ports::RegistryError| PolicyFault::Invalid("registry");
        let withdrawals = artefacts.withdrawals().map_err(fault)?;
        let publication = match &self.config.policy_trust {
            PolicyTrust::Pinned(address) => {
                let p = artefacts.get(address).map_err(fault)?.ok_or(PolicyFault::NoPolicy)?;
                if p.artefact.kind() != ArtefactKind::Policy || p.artefact.name() != DEPLOYMENT_POLICY || p.address() != address {
                    return Err(PolicyFault::Invalid("policy-mismatch"));
                }
                p
            }
            PolicyTrust::Allowlists { builders, sources } => {
                // The defaults with the configured allow-lists: nothing here comes from a
                // candidate.
                let mut trusted = Controls::defaults().publishing();
                trusted.allowed_builders.clone_from(builders);
                trusted.allowed_sources.clone_from(sources);
                let verifier = VerifyPublication::new(TrustStore::new(&self.config.trust), &trusted);
                let mut versions: Vec<(String, SemVer, ContentAddress)> = artefacts
                    .list(ArtefactKind::Policy, DEPLOYMENT_POLICY)
                    .map_err(fault)?
                    .into_iter()
                    .filter_map(|(label, a)| Some((label.clone(), SemVer::parse(&label).ok()?, a)))
                    .collect();
                versions.sort_by(|a, b| (b.1.core, b.1.pre.is_none(), &b.1.pre).cmp(&(a.1.core, a.1.pre.is_none(), &a.1.pre)));
                let mut only_withdrawn = true;
                let mut chosen = None;
                for (label, _, address) in versions {
                    let Some(p) = artefacts.get(&address).map_err(fault)? else {
                        only_withdrawn = false;
                        continue;
                    };
                    match verifier.verify(&p, &withdrawals) {
                        Ok(_) => {
                            chosen = Some(p);
                            break;
                        }
                        Err(e) => {
                            let code = verify_code(&e);
                            if code != "withdrawn" {
                                only_withdrawn = false;
                                self.tell_skipped(&Skipped { kind: ArtefactKind::Policy, name: DEPLOYMENT_POLICY.into(), version: label, code });
                            }
                        }
                    }
                }
                match chosen {
                    Some(p) => p,
                    None if only_withdrawn => return Err(PolicyFault::NoPolicy),
                    None => return Err(PolicyFault::Invalid("policy-unverified")),
                }
            }
        };
        let address = *publication.address();
        let value = cbor::decode(publication.artefact.canonical_bytes()).map_err(|_| PolicyFault::Invalid("policy-invalid"))?;
        let document = decode_document(&value).document.ok_or(PolicyFault::Invalid("policy-invalid"))?;
        let service = PolicyService::new(MemoryPolicySource::new(vec![PublishedPolicy { address, document }]), BuiltInPolicyEngine, MemoryDecisionLog::new());
        let effective = service.compute(&LayerSelector::default()).map_err(|_| PolicyFault::Invalid("policy-invalid"))?;
        let publishing = effective.publishing();
        if matches!(self.config.policy_trust, PolicyTrust::Pinned(_)) {
            // The pinned policy is trusted, so its own thresholds say whether a withdrawal of it is valid.
            let verifier = VerifyPublication::new(TrustStore::new(&self.config.trust), &publishing);
            if withdrawals.iter().any(|w| w.address() == &address && verifier.verify_withdrawal(w, &publication).is_ok()) {
                return Err(PolicyFault::Invalid("policy-withdrawn"));
            }
        }
        let inputs = ReleaseInputs { sources: effective.sources.clone(), layouts: effective.factory().release_layouts };
        Ok(LoadedPolicy { service, inputs, publishing })
    }

    /// The modification times of the watched paths, or none when nothing is watched.
    fn stamp(&self) -> Stamp {
        self.config.watch.iter().map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()).collect()
    }

    /// One snapshot of the registry journal for a pass, when a state directory is named.
    fn snapshot(&self) -> Result<Option<fieldseal_adapters_memory::registration::MemoryRegistryStore>, ()> {
        let Some(dir) = &self.config.state_dir else { return Ok(None) };
        FileRegistryStore::snapshot(dir).map(Some).map_err(|_| ())
    }

    /// Whether `tenancy` was up to date at `stamp` and its bundle's anchor is still fresh.
    fn is_quiet(&self, tenancy: &TenancyId, stamp: &Stamp) -> bool {
        if stamp.is_empty() {
            return false;
        }
        let now = self.ports.clock.now();
        self.quiet
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tenancy)
            .is_some_and(|q| &q.stamp == stamp && now.0.saturating_sub(q.issued_ms) <= self.config.max_anchor_age_ms)
    }

    /// One pass over every tenancy of an account that has an assignment (a tenancy with none
    /// has nothing to receive). It returns what happened to each.
    pub fn run_once(&self) -> Vec<(TenancyId, Outcome)> {
        self.pass(None)
    }

    /// Reconciles `tenancies` now: what a notification asks for.
    pub fn reconcile_all(&self, tenancies: &[TenancyId]) -> Vec<(TenancyId, Outcome)> {
        self.pass(Some(tenancies))
    }

    fn pass(&self, only: Option<&[TenancyId]>) -> Vec<(TenancyId, Outcome)> {
        // The stamp first, so a change during the pass shows at the next one.
        let stamp = self.stamp();
        let snapshot = match self.snapshot() {
            Ok(s) => s,
            Err(()) => {
                self.pass_failed("registry-snapshot");
                return Vec::new();
            }
        };
        let registry: &dyn RegistryStore = match &snapshot {
            Some(s) => s,
            None => self.ports.registry,
        };
        let tenancies: Vec<TenancyId> = match only {
            Some(t) => t.to_vec(),
            None => {
                let assignments = match registry.assignments() {
                    Ok(a) => a,
                    Err(_) => {
                        self.pass_failed("assignments");
                        return Vec::new();
                    }
                };
                let mut accounts: Vec<_> = assignments.into_iter().map(|a| a.account).collect();
                accounts.sort();
                accounts.dedup();
                let mut tenancies: Vec<TenancyId> = accounts.iter().filter_map(|a| registry.tenancies_of(a).ok()).flatten().map(|t| t.id).collect();
                tenancies.sort();
                tenancies.dedup();
                tenancies
            }
        };
        let mut policy: Option<Result<LoadedPolicy, PolicyFault>> = None;
        let mut done = Vec::new();
        for tenancy in &tenancies {
            if self.is_quiet(tenancy, &stamp) {
                done.push((*tenancy, Outcome::Unchanged));
                continue;
            }
            let outcome = match policy.get_or_insert_with(|| self.load_policy()) {
                Ok(policy) => self.reconcile(tenancy, policy, registry, &stamp),
                // A fault in the policy itself holds every tenancy the pass covers: the stored
                // bundle stops being delivered until a policy can be read again (fail closed).
                Err(PolicyFault::NoPolicy) => {
                    self.set_withheld(tenancy, Some(&["no-policy".to_owned()]));
                    self.withheld(tenancy, "no-policy", None)
                }
                Err(PolicyFault::Invalid(code)) => {
                    self.set_withheld(tenancy, Some(&[(*code).to_owned()]));
                    self.failed(tenancy, code)
                }
            };
            let stopped = matches!(outcome, Outcome::Stopped(_));
            done.push((*tenancy, outcome));
            if stopped {
                break;
            }
        }
        done
    }

    /// Tells a pass-level failure once until it clears.
    fn pass_failed(&self, code: &str) {
        let mut told = self.told_skipped.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if told.insert(format!("pass:{code}")) {
            drop(told);
            (self.events)(&ReconcileEvent::PassFailed { reason: code.to_owned() });
        }
    }

    /// Records a failed build of these inputs, with a backoff that doubles to five minutes, and
    /// tells it.
    fn build_failed(&self, tenancy: &TenancyId, digest: [u8; 32], now: AuthorityTime, code: &str) -> Outcome {
        let mut failures = self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let attempts = failures.get(tenancy).filter(|m| m.digest == digest).map_or(0, |m| m.attempts) + 1;
        let wait = (BASE_BACKOFF_MS << (attempts - 1).min(16)).min(MAX_BACKOFF_MS);
        failures.insert(*tenancy, FailureMemo { digest, code: code.to_owned(), attempts, retry_at: now.0 + wait });
        drop(failures);
        self.failed(tenancy, code)
    }

    fn reconcile(&self, tenancy: &TenancyId, policy: &LoadedPolicy, registry: &dyn RegistryStore, stamp: &Stamp) -> Outcome {
        let _one_at_a_time = self.building.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let p = &self.ports;
        self.quiet.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(tenancy);
        let record = match registry.tenancy(tenancy) {
            Ok(Some(r)) => r,
            Ok(None) => return Outcome::Unchanged,
            Err(_) => return self.failed(tenancy, "port-RegistryStore"),
        };
        // Not eligible (DIS-001, DIS-003, REG-081): no build.
        if let Err(e) = check_state(record.state, false) {
            return match e {
                DistributionError::Withheld(reasons) => self.withheld(tenancy, &reasons.join(","), None),
                _ => self.withheld(tenancy, &format!("tenancy-{}", record.state.as_str()), None),
            };
        }
        // Artefacts are verified as they are selected, under the same policy the builder uses.
        let verifier = VerifyPublication::new(TrustStore::new(&self.config.trust), &policy.publishing);
        let ports = InputPorts { registry, artefacts: p.artefacts, rosters: p.rosters, profiles: p.profiles, verifier: &verifier };
        let signing = SigningInputs { signer: self.config.identity.signer, trust: self.trust_digest };
        let inputs = match BuildInputs::collect(tenancy, ports, policy.inputs.clone(), signing) {
            Ok(i) => i,
            Err(InputsError::ProfileUnknown) => return self.withheld(tenancy, "runtime-profile-unknown", None),
            Err(InputsError::NotRegistered) => return self.withheld(tenancy, "not-registered", None),
            Err(InputsError::Port { port, .. }) => return self.failed(tenancy, &format!("port-{port}")),
        };
        for s in &inputs.skipped {
            self.tell_skipped(s);
        }
        if inputs.instruments.is_empty() {
            return match inputs.left_out.first() {
                Some((survey, why)) => self.withheld(tenancy, why.reason(), Some(survey)),
                None => self.withheld(tenancy, "no-assignments", None),
            };
        }
        // A survey with no usable instrument is left out; the others are built.
        for (survey, why) in &inputs.left_out {
            self.withheld(tenancy, why.reason(), Some(survey));
        }

        let digest = inputs.digest();
        let latest = match p.bundles.latest(tenancy) {
            Ok(l) => l,
            Err(_) => return self.failed(tenancy, "port-BundleStore"),
        };
        let now = p.clock.now();
        // Does policy release it? Asked on every pass, before the unchanged shortcut: the facts
        // it reads (cohort activity, key attestation) are not in the input digest, so a hold
        // that appears later must still stop the stored bundle being delivered (SR2-M2). Asked
        // before anything is recorded, so a bundle that is withheld leaves no roster recorded
        // as issued (DIS-002, DIS-003). Only a withhold goes on to the marker; any other error
        // is a failed build.
        let mut active = 0;
        for c in &record.cohorts {
            match p.rosters.active_tenancies(&c.cohort, tenancy) {
                Ok(n) => active = active.max(n),
                Err(_) => return self.failed(tenancy, "port-RosterSource"),
            }
        }
        let facts = release_facts(&record, !inputs.rosters.is_empty(), active, self.config.identity.unattested == UnattestedKeys::AllowNonProduction);
        match decide_release(&policy.service, &LayerSelector::default(), *tenancy, facts, now) {
            Ok(_) => {}
            Err(DistributionError::Withheld(reasons)) => {
                self.set_withheld(tenancy, Some(&reasons));
                return self.withheld(tenancy, &reasons.join(","), None);
            }
            Err(e) => return self.failed(tenancy, &failure_code(&e)),
        }

        // The anchor of a bundle is its issue time; a bundle with a stale anchor is rebuilt
        // even when nothing else changed (DIS-010).
        let stale = latest.as_ref().is_some_and(|b| now.0.saturating_sub(b.issued.0) > self.config.max_anchor_age_ms);
        // A tenancy held back by policy is not unchanged even when its inputs match the last
        // build: the hold is lifted by a build.
        let held = p.bundles.withheld(tenancy).map_or(true, |m| m.is_some());
        if let Some(latest) = latest.as_ref().filter(|_| self.stored_digest(tenancy) == Some(digest) && !stale && !held) {
            self.quiet.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(*tenancy, Quiet { stamp: stamp.clone(), issued_ms: latest.issued.0 });
            return Outcome::Unchanged;
        }
        // A build that failed for these very inputs waits for its backoff.
        if let Some(m) = self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(tenancy).filter(|m| m.digest == digest && now.0 < m.retry_at) {
            return Outcome::Failed(m.code.clone());
        }

        // 1. The rosters issued to the tenancy, for intake's consent checks.
        if self.record_issued(&inputs, now).is_err() {
            return self.build_failed(tenancy, digest, now, "issued-rosters");
        }
        if let Err(step) = self.stop_after(tenancy, WriteStep::IssuedRosters) {
            return step;
        }

        // 2. The bundle, built over the rosters just recorded and stored by the builder.
        let snapshot = SnapshotRosters { rosters: inputs.rosters.clone(), inner: p.rosters };
        let anchors = ClockAnchorSource::new(p.clock, p.custody, self.config.receipt);
        let builder = BundleBuilder::new(
            FactoryPorts {
                registry: p.registry,
                artefacts: p.artefacts,
                rosters: &snapshot,
                profiles: p.profiles,
                policy: &policy.service,
                anchors: &anchors,
                custody: p.custody,
                random: p.random,
                bundles: p.bundles,
            },
            &verifier,
            self.config.identity.clone(),
        )
        .with_max_size(BUNDLE_LIMIT);
        let built = match builder.build(&inputs.request_for()) {
            Ok(b) => b,
            Err(DistributionError::Withheld(reasons)) => {
                self.set_withheld(tenancy, Some(&reasons));
                return self.withheld(tenancy, &reasons.join(","), None);
            }
            Err(e) => return self.build_failed(tenancy, digest, now, &failure_code(&e)),
        };
        if let Err(step) = self.stop_after(tenancy, WriteStep::Bundle) {
            return step;
        }

        // 3. The digest, last, so it never names inputs without a stored bundle.
        let path = self.digest_path(tenancy);
        let written = std::fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new("."))).and_then(|()| write_atomic(&path, format!("{}\n", lower_hex(&digest)).as_bytes()));
        if written.is_err() {
            return self.build_failed(tenancy, digest, now, "digest");
        }
        if let Err(step) = self.stop_after(tenancy, WriteStep::Digest) {
            return step;
        }

        self.failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(tenancy);
        self.set_withheld(tenancy, None);
        self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(tenancy);
        (self.events)(&ReconcileEvent::Built {
            tenancy: *tenancy,
            seq: built.sealed.seq.0,
            address: built.sealed.address,
            instruments: built.manifest.instruments.len(),
            layouts: built.manifest.layouts.len(),
            rosters: built.manifest.rosters.len(),
        });
        Outcome::Built(built.sealed.seq)
    }

    /// Calls the hook; an error is a stopped build, reported as a value.
    fn stop_after(&self, tenancy: &TenancyId, step: WriteStep) -> Result<(), Outcome> {
        self.hook.after(tenancy, step).map_err(|_| Outcome::Stopped(step))
    }

    /// Records each roster of `inputs` as issued to the tenancy, restricted to the fields the
    /// instruments read (DIS-013), unless the same version is already recorded.
    fn record_issued(&self, inputs: &BuildInputs, now: AuthorityTime) -> std::io::Result<()> {
        let dir = &self.config.issued_rosters_dir;
        let known = FileRosterHistory::new(dir).issued(&inputs.tenancy).map_err(|e| std::io::Error::other(e.to_string()))?;
        for roster in &inputs.rosters {
            let held = roster.restricted_to(&inputs.roster_fields);
            let address = Digest::from(*ContentAddress::of(&held.encode()).as_bytes());
            if known.iter().any(|k| k.cohort == held.cohort && k.version == held.version && k.address == address) {
                continue;
            }
            let consent = held
                .entries
                .iter()
                .map(|e| {
                    (
                        e.subject.clone(),
                        match e.consent {
                            ConsentState::Granted => IssuedConsent::Granted,
                            ConsentState::Refused => IssuedConsent::Refused,
                            ConsentState::Unknown => IssuedConsent::Unknown,
                        },
                    )
                })
                .collect();
            record_issued(dir, &inputs.tenancy, &IssuedRoster { cohort: held.cohort.clone(), version: held.version, address, issued_at: now, consent })?;
        }
        Ok(())
    }

    /// Runs the reconciler on a thread of `scope`: a pass at once, then a pass at every
    /// `interval` (the scan for publications the CLI wrote) and a reconciliation of the
    /// tenancies [`Spawned::notify`] names as soon as it hears of them.
    pub fn spawn<'scope, 'env>(&'scope self, scope: &'scope std::thread::Scope<'scope, 'env>, interval: Duration) -> Spawned
    where
        'a: 'scope,
        Self: Sync,
    {
        let (tx, rx) = mpsc::channel::<TenancyId>();
        scope.spawn(move || {
            self.run_once();
            loop {
                match rx.recv_timeout(interval) {
                    Ok(first) => {
                        let mut ids = vec![first];
                        ids.extend(rx.try_iter());
                        ids.sort();
                        ids.dedup();
                        self.reconcile_all(&ids);
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        self.run_once();
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        Spawned { tx }
    }
}

/// A reconciler thread. Dropping every [`ReconcileNotify`] and this value stops it.
pub struct Spawned {
    tx: mpsc::Sender<TenancyId>,
}

impl Spawned {
    /// The callback that tells the thread to reconcile a tenancy now. It only sends a message.
    pub fn notify(&self) -> ReconcileNotify {
        let tx = self.tx.clone();
        Arc::new(move |tenancy| {
            let _ = tx.send(tenancy);
        })
    }
}
