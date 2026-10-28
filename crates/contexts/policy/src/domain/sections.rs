//! Typed views of an effective policy's sections: `factory`, `runtime`, `intake` and
//! `publishing`. They are built from the merged controls, which always hold every
//! defaulted control (POL-022), so reading them cannot fail.

use std::collections::BTreeMap;

use super::choice::*;
use super::control::{Argon2Params, ControlValue, Threshold};
use super::schema::{control_spec, schema};
use super::units::{ByteSize, Date, Duration};
use fieldseal_kernel::value::Decimal;

/// The merged controls of an effective policy, by path from `spec`, with every control that
/// has a default filled in.
#[derive(Clone, PartialEq, Debug)]
pub struct Controls {
    map: BTreeMap<String, ControlValue>,
}

impl Controls {
    /// The schema defaults alone (POL-022).
    pub fn defaults() -> Self {
        Self::from_map(BTreeMap::new())
    }

    /// `set` over the schema defaults.
    pub fn from_map(set: BTreeMap<String, ControlValue>) -> Self {
        let mut map: BTreeMap<String, ControlValue> = schema()
            .iter()
            .filter_map(|s| s.default.clone().map(|d| (s.path.clone(), d)))
            .collect();
        map.extend(set);
        Self { map }
    }

    /// The control at `path`, if it is set or has a default.
    pub fn get(&self, path: &str) -> Option<&ControlValue> {
        self.map.get(path)
    }

    /// Every set control, by path.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ControlValue)> {
        self.map.iter()
    }

    /// The underlying map.
    pub fn as_map(&self) -> &BTreeMap<String, ControlValue> {
        &self.map
    }

    fn need(&self, path: &str) -> &ControlValue {
        match self.map.get(path) {
            Some(v) => v,
            None => panic!("typed view reads `{path}`, which has no value and no default in the schema"),
        }
    }

    fn bool_(&self, path: &str) -> bool {
        match self.need(path) {
            ControlValue::Bool(b) => *b,
            other => panic!("`{path}` is {other:?}, not a boolean"),
        }
    }

    fn int(&self, path: &str) -> u64 {
        match self.need(path) {
            ControlValue::Int(i) => *i,
            other => panic!("`{path}` is {other:?}, not an integer"),
        }
    }

    fn dur(&self, path: &str) -> Duration {
        match self.need(path) {
            ControlValue::Duration(d) => *d,
            other => panic!("`{path}` is {other:?}, not a duration"),
        }
    }

    fn durs(&self, path: &str) -> Vec<Duration> {
        match self.need(path) {
            ControlValue::Durations(d) => d.clone(),
            other => panic!("`{path}` is {other:?}, not a duration list"),
        }
    }

    fn size(&self, path: &str) -> ByteSize {
        match self.need(path) {
            ControlValue::Size(s) => *s,
            other => panic!("`{path}` is {other:?}, not a size"),
        }
    }

    fn text(&self, path: &str) -> String {
        match self.need(path) {
            ControlValue::Text(t) => t.clone(),
            other => panic!("`{path}` is {other:?}, not text"),
        }
    }

    fn words(&self, path: &str) -> Vec<String> {
        match self.need(path) {
            ControlValue::Set(s) => s.clone(),
            other => panic!("`{path}` is {other:?}, not a set"),
        }
    }

    fn opt_words(&self, path: &str) -> Option<Vec<String>> {
        self.map.get(path).map(|_| self.words(path))
    }

    fn opt_date(&self, path: &str) -> Option<Date> {
        match self.map.get(path) {
            Some(ControlValue::Date(d)) => Some(*d),
            _ => None,
        }
    }

    fn choice<T: Copy>(&self, path: &str, parse: fn(&str) -> Option<T>) -> T {
        match self.need(path) {
            ControlValue::Choice(w) => match parse(w) {
                Some(v) => v,
                None => panic!("`{path}` holds `{w}`, which the schema does not list"),
            },
            other => panic!("`{path}` is {other:?}, not a choice"),
        }
    }

    fn enums<T: Copy + Ord>(&self, path: &str, parse: fn(&str) -> Option<T>) -> Vec<T> {
        let mut out: Vec<T> = self.words(path).iter().filter_map(|w| parse(w)).collect();
        out.sort();
        out
    }

    fn threshold(&self, path: &str) -> Option<Threshold> {
        match self.map.get(path) {
            Some(ControlValue::Threshold(t)) => Some(*t),
            _ => None,
        }
    }
}

/// Batch token controls (`factory.registration.batchTokens`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BatchTokenPolicy {
    /// Whether batch tokens may be issued.
    pub allowed: bool,
    /// Operator roles that may receive them.
    pub roles: Vec<String>,
    /// Devices one batch token may register.
    pub max_uses: u64,
    /// How long a batch token lasts.
    pub ttl: Duration,
}

/// `factory.registration`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistrationPolicy {
    /// Devices one account may have.
    pub max_devices_per_account: u64,
    /// Registration token lifetime.
    pub token_ttl: Duration,
    /// Registration token lifetime for air-gapped devices.
    pub air_gapped_token_ttl: Duration,
    /// Whether fingerprint words must be confirmed.
    pub require_fingerprint_confirmation: bool,
    /// Serial number check.
    pub serial_check: SerialCheck,
    /// Whether phishing-resistant authentication is required.
    pub require_phishing_resistant_auth: bool,
    /// Whether authentication methods the identity adapter could only report as
    /// `asserted` (REG-002a) may be relied on.
    pub accept_asserted_auth_methods: bool,
    /// What to do with registrations that carry only a device nonce.
    pub device_nonce_registrations: Disposition,
    /// Batch tokens.
    pub batch_tokens: BatchTokenPolicy,
}

/// `factory.attestation`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttestationPolicy {
    /// Accepted attestation formats; never includes software keys (INV-10).
    pub accepted_formats: Vec<String>,
    /// Weakest accepted hardware security level.
    pub min_security_level: SecurityLevel,
    /// Oldest accepted OS patch level, if constrained.
    pub min_os_patch_level: Option<Date>,
    /// Whether verified boot is required.
    pub require_verified_boot: bool,
    /// Whether a locked bootloader is required.
    pub require_bootloader_locked: bool,
    /// Runtime version ranges, all of which must hold; `None` means no constraint.
    pub accepted_runtime_versions: Option<Vec<String>>,
}

/// `factory.custody` (POL-065, POL-066)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CustodyPolicy {
    /// The least assurance for each authority purpose, by purpose name.
    pub min_assurance: BTreeMap<String, Assurance>,
    /// The least mode for each authority purpose, by purpose name.
    pub min_mode: BTreeMap<String, CustodyMode>,
    /// The longest validity of a hot key's certificate.
    pub hot_key_max_validity: Duration,
    /// How long before expiry a hot key must be rotated.
    pub hot_key_rotate_before: Duration,
}

/// `factory.posture`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PosturePolicy {
    /// How often posture is rechecked.
    pub recheck_interval: Duration,
    /// What a failed recheck does.
    pub on_failure: PostureFailure,
    /// What an unknown restriction does.
    pub unknown_restriction: UnknownRestriction,
}

/// `spec.factory`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FactoryPolicy {
    /// Registration controls.
    pub registration: RegistrationPolicy,
    /// Attestation controls.
    pub attestation: AttestationPolicy,
    /// Most active tenancies per cohort.
    pub max_active_tenancies_per_cohort: u64,
    /// Posture controls.
    pub posture: PosturePolicy,
    /// Authority key custody minimums.
    pub custody: CustodyPolicy,
    /// Whether bundles go only to registered tenancies (always true).
    pub require_registered_tenancy: bool,
}

/// `runtime.pin`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PinPolicy {
    /// Shortest PIN.
    pub min_length: u64,
    /// Escalating lockout delays.
    pub lockout_steps: Vec<Duration>,
    /// Failures before the first lockout.
    pub failures_before_lockout: u64,
    /// Argon2id parameters for the session key.
    pub argon2: Argon2Params,
}

/// `runtime.session`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionPolicy {
    /// Idle time before the session locks.
    pub idle_lock: Duration,
    /// Lock when the app goes to the background.
    pub lock_on_background: bool,
    /// Lock when the screen turns off.
    pub lock_on_screen_off: bool,
}

/// `runtime.export`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportPolicy {
    /// Whether parity is on by default.
    pub parity_default: Toggle,
    /// Whether the collector may turn parity off.
    pub allow_parity_off: bool,
    /// Permitted destinations.
    pub destinations: Vec<ExportDestination>,
    /// File name prefix.
    pub file_prefix: String,
    /// File name extension.
    pub file_extension: String,
}

/// `runtime.upload`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UploadPolicy {
    /// Whether to upload in the background.
    pub background: bool,
    /// Delays between retries.
    pub retry_backoff: Vec<Duration>,
}

/// `runtime.retention`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RetentionPolicy {
    /// Whether to offer clearing once a receipt arrives.
    pub offer_clear_on_receipt: bool,
    /// When to remind about uncleared data.
    pub remind_after: Duration,
}

/// `runtime.device`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DevicePolicy {
    /// Whether the runtime is the device's only app.
    pub kiosk: bool,
    /// Restrictions the device must carry.
    pub required_restrictions: Vec<Restriction>,
}

/// `spec.runtime`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimePolicy {
    /// PIN controls.
    pub pin: PinPolicy,
    /// Session controls.
    pub session: SessionPolicy,
    /// Export controls.
    pub export: ExportPolicy,
    /// Upload controls.
    pub upload: UploadPolicy,
    /// Retention controls.
    pub retention: RetentionPolicy,
    /// Whether to warn when the device clock is outside the collection window.
    pub warn_outside_window: bool,
    /// Device controls.
    pub device: DevicePolicy,
    /// Oldest transparency-log tree head the runtime accepts.
    pub max_tree_head_age: Duration,
    /// Longest image edge, in pixels.
    pub max_image_edge: u64,
}

/// `intake.consent`
#[derive(Clone, PartialEq, Debug)]
pub struct ConsentPolicy {
    /// Accept consent that comes with evidence without review.
    pub auto_accept_with_evidence: bool,
    /// Fraction of auto-accepted consents sampled for review.
    pub sample_rate: Decimal,
    /// What to do with consent that lacks evidence.
    pub without_evidence: ConsentWithoutEvidence,
    /// Named heuristics that send consent to review.
    pub heuristics: Vec<String>,
    /// Whether pending consent is left out of analysis.
    pub exclude_pending_from_analysis: bool,
}

/// `spec.intake`
#[derive(Clone, PartialEq, Debug)]
pub struct IntakePolicy {
    /// Consent controls.
    pub consent: ConsentPolicy,
    /// Grace period for late tenancies.
    pub time_grace: Duration,
    /// What a provably late record does.
    pub provably_late: Escalation,
    /// What a fast-running clock does.
    pub fast_running: Escalation,
    /// Whether intake repairs damaged exports using parity.
    pub parity_repair: bool,
    /// Deny-list cutoff mode.
    pub cutoff_mode: CutoffMode,
    /// Largest accepted submission.
    pub max_submission_size: ByteSize,
    /// What a data quality failure does.
    pub data_quality_on_failure: QualityFailure,
}

/// Choice-load lint thresholds (INS-210 to INS-213).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LayoutLintPolicy {
    /// Most unanswered questions shown at once (INS-210).
    pub max_decisions_per_screen: u64,
    /// Most visible options without grouping (INS-211).
    pub max_visible_options: u64,
    /// Scale steps from which a compact layout warns (INS-212).
    pub max_scale_steps_compact: u64,
    /// Lints publishing treats as blocking.
    pub blocking: Vec<LayoutLint>,
}

/// Signature and approval controls for one artefact kind.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KindPolicy {
    /// Approving reviews needed.
    pub required_approvals: u64,
    /// Publisher signatures needed.
    pub publisher_threshold: Threshold,
    /// Signatures needed to withdraw (the publisher threshold when not set).
    pub withdrawal_threshold: Threshold,
}

/// `spec.publishing`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublishingPolicy {
    /// Per artefact kind (see [`ARTEFACT_KINDS`]).
    pub kinds: BTreeMap<String, KindPolicy>,
    /// Whether the author counts as a reviewer.
    pub author_may_approve: bool,
    /// Builder identities whose provenance is accepted. Empty means none.
    pub allowed_builders: Vec<String>,
    /// Source repositories whose revisions may be published. Empty means none.
    pub allowed_sources: Vec<String>,
    /// Whether transparency-log inclusion is required (always true).
    pub require_transparency_log: bool,
    /// Witness cosignatures a checkpoint needs.
    pub required_witness_cosignatures: u64,
    /// Layout lint thresholds.
    pub layout_lint: LayoutLintPolicy,
}

impl Controls {
    /// The typed `factory` section.
    pub fn factory(&self) -> FactoryPolicy {
        let p = |s: &str| format!("factory.{s}");
        FactoryPolicy {
            registration: RegistrationPolicy {
                max_devices_per_account: self.int(&p("registration.maxDevicesPerAccount")),
                token_ttl: self.dur(&p("registration.tokenTtl")),
                air_gapped_token_ttl: self.dur(&p("registration.airGappedTokenTtl")),
                require_fingerprint_confirmation: self.bool_(&p("registration.requireFingerprintConfirmation")),
                serial_check: self.choice(&p("registration.serialCheck"), SerialCheck::parse),
                require_phishing_resistant_auth: self.bool_(&p("registration.requirePhishingResistantAuth")),
                accept_asserted_auth_methods: self.bool_(&p("registration.acceptAssertedAuthMethods")),
                device_nonce_registrations: self.choice(&p("registration.deviceNonceRegistrations"), Disposition::parse),
                batch_tokens: BatchTokenPolicy {
                    allowed: self.bool_(&p("registration.batchTokens.allowed")),
                    roles: self.words(&p("registration.batchTokens.roles")),
                    max_uses: self.int(&p("registration.batchTokens.maxUses")),
                    ttl: self.dur(&p("registration.batchTokens.ttl")),
                },
            },
            attestation: AttestationPolicy {
                accepted_formats: self.words(&p("attestation.acceptedFormats")),
                min_security_level: self.choice(&p("attestation.minSecurityLevel"), SecurityLevel::parse),
                min_os_patch_level: self.opt_date(&p("attestation.minOsPatchLevel")),
                require_verified_boot: self.bool_(&p("attestation.requireVerifiedBoot")),
                require_bootloader_locked: self.bool_(&p("attestation.requireBootloaderLocked")),
                accepted_runtime_versions: self.opt_words(&p("attestation.acceptedRuntimeVersions")),
            },
            max_active_tenancies_per_cohort: self.int(&p("cohorts.maxActiveTenanciesPerCohort")),
            posture: PosturePolicy {
                recheck_interval: self.dur(&p("posture.recheckInterval")),
                on_failure: self.choice(&p("posture.onFailure"), PostureFailure::parse),
                unknown_restriction: self.choice(&p("posture.unknownRestriction"), UnknownRestriction::parse),
            },
            custody: CustodyPolicy {
                min_assurance: super::schema::CUSTODY_PURPOSES
                    .iter()
                    .map(|n| ((*n).to_owned(), self.choice(&p(&format!("custody.minAssurance.{n}")), Assurance::parse)))
                    .collect(),
                min_mode: super::schema::CUSTODY_PURPOSES
                    .iter()
                    .map(|n| ((*n).to_owned(), self.choice(&p(&format!("custody.minMode.{n}")), CustodyMode::parse)))
                    .collect(),
                hot_key_max_validity: self.dur(&p("custody.hotKey.maxValidity")),
                hot_key_rotate_before: self.dur(&p("custody.hotKey.rotateBefore")),
            },
            require_registered_tenancy: self.bool_(&p("release.requireRegisteredTenancy")),
        }
    }

    /// The typed `runtime` section.
    pub fn runtime(&self) -> RuntimePolicy {
        let p = |s: &str| format!("runtime.{s}");
        let argon2 = match self.need(&p("pin.argon2")) {
            ControlValue::Argon2(a) => *a,
            other => panic!("`runtime.pin.argon2` is {other:?}"),
        };
        RuntimePolicy {
            pin: PinPolicy {
                min_length: self.int(&p("pin.minLength")),
                lockout_steps: self.durs(&p("pin.lockoutSteps")),
                failures_before_lockout: self.int(&p("pin.failuresBeforeLockout")),
                argon2,
            },
            session: SessionPolicy {
                idle_lock: self.dur(&p("session.idleLock")),
                lock_on_background: self.bool_(&p("session.lockOnBackground")),
                lock_on_screen_off: self.bool_(&p("session.lockOnScreenOff")),
            },
            export: ExportPolicy {
                parity_default: self.choice(&p("export.parityDefault"), Toggle::parse),
                allow_parity_off: self.bool_(&p("export.allowParityOff")),
                destinations: self.enums(&p("export.destinations"), ExportDestination::parse),
                file_prefix: self.text(&p("export.filePrefix")),
                file_extension: self.text(&p("export.fileExtension")),
            },
            upload: UploadPolicy {
                background: self.bool_(&p("upload.background")),
                retry_backoff: self.durs(&p("upload.retryBackoff")),
            },
            retention: RetentionPolicy {
                offer_clear_on_receipt: self.bool_(&p("retention.offerClearOnReceipt")),
                remind_after: self.dur(&p("retention.remindAfter")),
            },
            warn_outside_window: self.bool_(&p("time.warnOutsideWindow")),
            device: DevicePolicy {
                kiosk: self.bool_(&p("device.kiosk")),
                required_restrictions: self.enums(&p("device.requiredRestrictions"), Restriction::parse),
            },
            max_tree_head_age: self.dur(&p("publishing.maxTreeHeadAge")),
            max_image_edge: self.int(&p("evidence.maxImageEdge")),
        }
    }

    /// The typed `intake` section.
    pub fn intake(&self) -> IntakePolicy {
        let p = |s: &str| format!("intake.{s}");
        let sample_rate = match self.need(&p("consent.sampleRate")) {
            ControlValue::Ratio(d) => *d,
            other => panic!("`intake.consent.sampleRate` is {other:?}"),
        };
        IntakePolicy {
            consent: ConsentPolicy {
                auto_accept_with_evidence: self.bool_(&p("consent.autoAcceptWithEvidence")),
                sample_rate,
                without_evidence: self.choice(&p("consent.withoutEvidence"), ConsentWithoutEvidence::parse),
                heuristics: self.words(&p("consent.heuristics")),
                exclude_pending_from_analysis: self.bool_(&p("consent.excludePendingFromAnalysis")),
            },
            time_grace: self.dur(&p("time.grace")),
            provably_late: self.choice(&p("time.provablyLate"), Escalation::parse),
            fast_running: self.choice(&p("ticks.fastRunning"), Escalation::parse),
            parity_repair: self.bool_(&p("parity.repair")),
            cutoff_mode: self.choice(&p("denyList.cutoffMode"), CutoffMode::parse),
            max_submission_size: self.size(&p("limits.maxSubmissionSize")),
            data_quality_on_failure: self.choice(&p("dataQuality.onFailure"), QualityFailure::parse),
        }
    }

    /// The typed `publishing` section.
    pub fn publishing(&self) -> PublishingPolicy {
        let p = |s: &str| format!("publishing.{s}");
        let mut kinds = BTreeMap::new();
        for kind in ARTEFACT_KINDS {
            let publisher = self
                .threshold(&p(&format!("publisherThreshold.{kind}")))
                .unwrap_or(Threshold { m: 2, n: 3 });
            kinds.insert(
                (*kind).to_owned(),
                KindPolicy {
                    required_approvals: self.int(&p(&format!("requiredApprovals.{kind}"))),
                    publisher_threshold: publisher,
                    withdrawal_threshold: self
                        .threshold(&p(&format!("withdrawalThreshold.{kind}")))
                        .unwrap_or(publisher),
                },
            );
        }
        PublishingPolicy {
            kinds,
            author_may_approve: self.bool_(&p("authorMayApprove")),
            allowed_builders: self.words(&p("allowedBuilders")),
            allowed_sources: self.words(&p("allowedSources")),
            require_transparency_log: self.bool_(&p("requireTransparencyLog")),
            required_witness_cosignatures: self.int(&p("requiredWitnessCosignatures")),
            layout_lint: LayoutLintPolicy {
                max_decisions_per_screen: self.int(&p("layoutLint.maxDecisionsPerScreen")),
                max_visible_options: self.int(&p("layoutLint.maxVisibleOptions")),
                max_scale_steps_compact: self.int(&p("layoutLint.maxScaleStepsCompact")),
                blocking: self.enums(&p("layoutLint.blocking"), LayoutLint::parse),
            },
        }
    }

    /// Whether `path` is a control in the schema.
    pub fn is_control(path: &str) -> bool {
        control_spec(path).is_some()
    }
}
