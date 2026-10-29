//! Enumerated control values. Variants are declared loosest first, so the derived order
//! is the order of strictness the `tighten` rule uses (POL-020).

/// Defines a choice enum with its written forms.
macro_rules! choice {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
        pub enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            /// Every written form, loosest first.
            pub const NAMES: &'static [&'static str] = &[$($text),+];
            /// Every variant, loosest first.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The written form.
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            /// The variant written as `text`.
            pub fn parse(text: &str) -> Option<Self> {
                match text { $($text => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

choice!(
    /// `registration.serialCheck`
    SerialCheck {
        /// No serial check.
        Off = "off",
        /// Check when a serial is available.
        Optional = "optional",
        /// A matching serial is required.
        Required = "required",
    }
);

choice!(
    /// A three-way disposition: `allow`, `flag` or `deny`.
    Disposition {
        /// Proceed.
        Allow = "allow",
        /// Proceed and mark for review.
        Flag = "flag",
        /// Refuse.
        Deny = "deny",
    }
);

choice!(
    /// `attestation.minSecurityLevel`, weakest first.
    SecurityLevel {
        /// Trusted execution environment.
        Tee = "tee",
        /// Dedicated secure processor (StrongBox).
        Strongbox = "strongbox",
        /// Secure element.
        SecureElement = "secure-element",
        /// Trusted platform module.
        Tpm = "tpm",
    }
);

choice!(
    /// `custody.minAssurance.<purpose>`, weakest first (TRU §6.7).
    Assurance {
        /// A software key; never accepted in production (INV-15).
        Development = "development",
        /// Generated inside a hardware custody the deployment binds to the purpose.
        CustodyBound = "custody-bound",
        /// Custody-bound, with verified key-attestation evidence.
        Attested = "attested",
    }
);

choice!(
    /// `custody.minMode.<purpose>`, loosest first (TRU §6.7).
    CustodyMode {
        /// Used online by a running service.
        Hot = "hot",
        /// Used only offline, in a recorded ceremony.
        Cold = "cold",
    }
);

choice!(
    /// `posture.onFailure`
    PostureFailure {
        /// Record a finding only.
        Flag = "flag",
        /// Pause bundle release to the device.
        PauseRelease = "pause-release",
    }
);

choice!(
    /// `release.layouts`, loosest first
    LayoutAssignment {
        /// Every published layout bound to an instrument accompanies it.
        Bound = "bound",
        /// No layout.
        None = "none",
    }
);

choice!(
    /// `posture.unknownRestriction`
    UnknownRestriction {
        /// Accept restrictions the policy does not know.
        Accept = "accept",
        /// Flag them.
        Flag = "flag",
    }
);

choice!(
    /// `export.parityDefault`
    Toggle {
        /// Off.
        Off = "off",
        /// On.
        On = "on",
    }
);

choice!(
    /// `consent.withoutEvidence`
    ConsentWithoutEvidence {
        /// Accept without review.
        Accept = "accept",
        /// Hold for review.
        Review = "review",
        /// Refuse.
        Deny = "deny",
    }
);

choice!(
    /// `time.provablyLate` and `ticks.fastRunning`
    Escalation {
        /// Flag and proceed.
        Flag = "flag",
        /// Refuse.
        Deny = "deny",
    }
);

choice!(
    /// `denyList.cutoffMode`
    CutoffMode {
        /// Cut off at the highest sequence number received.
        HighestReceived = "highest-received",
    }
);

choice!(
    /// `dataQuality.onFailure`
    QualityFailure {
        /// Record a finding and accept.
        Finding = "finding",
        /// Set the submission aside.
        Quarantine = "quarantine",
    }
);

choice!(
    /// `export.destinations`
    ExportDestination {
        /// Upload to the authority.
        Upload = "upload",
        /// Save on the device.
        Local = "local",
        /// Write to removable media.
        Removable = "removable",
        /// Send to a cloud store.
        Cloud = "cloud",
        /// Hand to the platform share sheet.
        Share = "share",
    }
);

choice!(
    /// `device.requiredRestrictions`
    Restriction {
        /// The runtime cannot be uninstalled.
        UninstallBlocked = "uninstall-blocked",
        /// Its data cannot be cleared outside the app.
        ClearDataBlocked = "clear-data-blocked",
        /// Debugging is disabled.
        DebuggingDisabled = "debugging-disabled",
        /// Safe boot is disabled.
        SafeBootDisabled = "safe-boot-disabled",
        /// Factory reset is disabled.
        FactoryResetDisabled = "factory-reset-disabled",
        /// Backup is disabled.
        BackupDisabled = "backup-disabled",
        /// Content capture is disabled.
        ContentCaptureDisabled = "content-capture-disabled",
        /// Input methods are allow-listed.
        InputMethodsAllowListed = "input-methods-allow-listed",
        /// Accessibility services are allow-listed.
        AccessibilityAllowListed = "accessibility-allow-listed",
    }
);

choice!(
    /// The layout lints that publishing policy may make blocking (INS-210 to INS-213).
    LayoutLint {
        /// Too many decisions on one screen.
        Ins210 = "INS-210",
        /// Too many visible options.
        Ins211 = "INS-211",
        /// A long scale on a compact layout.
        Ins212 = "INS-212",
        /// A dependent question placed before what it depends on.
        Ins213 = "INS-213",
    }
);

/// The artefact kinds that publishing thresholds are set for (PUB-002).
pub const ARTEFACT_KINDS: &[&str] = &[
    "Instrument",
    "Layout",
    "Localisation",
    "Policy",
    "TrustBundle",
    "Deployment",
];
