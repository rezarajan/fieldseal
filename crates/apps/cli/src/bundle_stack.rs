//! `fieldseal bundle build --stack` (CLI §5 `bundle`, DIS-001–DIS-030): a bundle built by the
//! local stack's own authority for a device that registered with its factory.
//!
//! Unlike the in-process demo world of plain `bundle build`, everything here is the stack's:
//! the instrument is the one published through the stack's transparency log (the artefact
//! registry `artefact publish` filled), the tenancy is the factory's (read from its journal),
//! the bundle is signed by the authority's `factory` key in the key directory and sealed to the
//! device's own agreement key, and the roster issued to the device is recorded in a directory
//! the intake endpoint reads, so its gate can check consent. Development only: software keys,
//! unattested devices (CLI-007, TRU-061); the release policy is the built-in default, and a
//! roster reaches an unattested key only with `--allow-unattested`, the development factory's
//! non-production allowance (REG-017), released with a flag. Production never grants it.

use std::path::Path;

use fieldseal_adapters_file::custody::DirCustody;
use fieldseal_adapters_file::store::FileRegistryStore;
use fieldseal_adapters_memory::distribution::{MemoryAnchorSource, MemoryBundleStore, MemoryRosterSource, MemoryRuntimeProfiles};
use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog, MemoryPolicySource};
use fieldseal_adapters_memory::distribution::SoftwareAgreementKey;
use fieldseal_distribution::application::{BuildBundle, BuildRequest, BundleBuilder, FactoryIdentity, FactoryPorts, HeldState, ImportState, VerifyBundle};
use fieldseal_distribution::domain::ConsentState;
use fieldseal_intake::domain::{IssuedConsent, IssuedRoster};
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_distribution::domain::{RuntimeProfile, file_name};
use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::checks::UnattestedKeys;
use fieldseal_policy::application::PolicyService;
use fieldseal_policy::domain::{Controls, PublishedPolicy, decode_document};
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::Publication;
use fieldseal_registration::ports::RegistryStore;
use fieldseal_trust::domain::{TrustBundle, TrustStore};

use crate::args::Args;
use crate::custody::OsRandom;
use crate::device_dir::DeviceDir;

/// The builder and source the stack's publishing policy allows (`tools/stack-demo.sh`).
pub const BUILDER: &str = "https://ci.example.org/builders/fieldseal-publish";
/// See [`BUILDER`].
pub const SOURCE: &str = "https://git.example.org/authority/artefacts";

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn required<'a>(args: &'a Args, flag: &str) -> Result<&'a str, String> {
    args.value(flag).ok_or_else(|| format!("bundle build --stack needs {flag}"))
}

/// The publishing policy thresholds of the stack: the defaults with the stack's builder and source.
pub fn publishing_policy() -> fieldseal_policy::domain::PublishingPolicy {
    let mut p = Controls::defaults().publishing();
    p.allowed_builders = vec![BUILDER.into()];
    p.allowed_sources = vec![SOURCE.into()];
    p
}

/// Runs `bundle build --stack`.
pub fn build(args: &Args, parse_roster: impl Fn(&str) -> Result<fieldseal_distribution::domain::Roster, String>) -> Result<u8, String> {
    // The device: a CLI device's key directory (`--device-dir`), or only a registered tenancy
    // (`--tenancy`, a browser device whose keys never leave it; the factory holds its public keys).
    let (agree, tenancy_hex) = match (args.value("--device-dir"), args.value("--tenancy")) {
        (Some(d), None) => {
            let dir = DeviceDir::new(d);
            let (_, agree) = dir.keys().ok_or("the device directory has no keys (run `registration request --device-dir`)")?;
            (Some(agree), dir.tenancy().ok_or("the device directory has no tenancy")?)
        }
        (None, Some(t)) => (None, t.to_owned()),
        _ => return Err("give exactly one of --device-dir or --tenancy".into()),
    };
    let trust = TrustBundle::decode(&std::fs::read(required(args, "--trust-bundle")?).map_err(err)?).map_err(err)?;
    let custody = DirCustody::new(required(args, "--custody")?);
    let publication = Publication::decode(&std::fs::read(required(args, "--publication")?).map_err(err)?).map_err(err)?;
    // One roster per cohort the tenancy is assigned (`--roster` repeats): every bundle carries them all.
    if args.values("--roster").is_empty() {
        return Err("give --roster (once per assigned cohort)".into());
    }
    let parsed = args.values("--roster").iter().map(|r| parse_roster(r)).collect::<Result<Vec<_>, _>>()?;
    let out_dir = required(args, "--out-dir")?;
    let now = AuthorityTime(args.value("--time").map_or_else(|| Ok(system_millis()), |v| v.parse::<u64>().map_err(|_| "--time is milliseconds".to_owned()))?);

    // The factory's view of the tenancy, from its journal (read only).
    let registry = FileRegistryStore::snapshot(required(args, "--tenancy-dir")?).map_err(err)?;
    let tenancy = fieldseal_kernel::id::TenancyId::from(<[u8; 32]>::try_from(crate::support::unhex(&tenancy_hex).ok_or("bad tenancy")?).map_err(|_| "bad tenancy")?);
    let record = registry.tenancy(&tenancy).map_err(err)?.ok_or("the factory does not know this tenancy")?;
    let factory_cert = trust.certificates().iter().find(|c| c.purpose() == Some(Purpose::Factory)).cloned().ok_or("the trust bundle has no factory key certificate")?;
    let receipt = trust.certificates().iter().find(|c| c.purpose() == Some(Purpose::Receipt)).map(|c| *c.key_id()).ok_or("the trust bundle has no receipt key certificate")?;
    let identity = FactoryIdentity { signer: *factory_cert.key_id(), chain: vec![factory_cert], caller: "fieldseal-cli".into(), unattested: if args.has("--allow-unattested") { UnattestedKeys::AllowNonProduction } else { UnattestedKeys::Refuse } };

    let artefacts = fieldseal_adapters_file::registry::FileRegistry::new(
        Path::new(required(args, "--state")?).join("registry"),
    );
    let rosters = MemoryRosterSource::new();
    let issued_all: Vec<fieldseal_distribution::domain::Roster> = parsed
        .into_iter()
        .map(|roster| fieldseal_distribution::domain::Roster { generation: fieldseal_kernel::id::Generation(record.cohorts.iter().find(|c| c.cohort == roster.cohort).map_or(1, |c| c.generation.0)), ..roster })
        .collect();
    rosters.assign(tenancy, issued_all.clone());
    let profiles = MemoryRuntimeProfiles::new();
    profiles.record(tenancy, RuntimeProfile { instrument_schema: fieldseal_adapters_memory::demo::DEMO_SCHEMA, localisation_reference: None });
    // The release policy is the deployment policy published through the stack's log.
    let policy_publication = Publication::decode(&std::fs::read(required(args, "--policy-publication")?).map_err(err)?).map_err(err)?;
    let value = cbor::decode(policy_publication.artefact.canonical_bytes()).map_err(err)?;
    let document = decode_document(&value).document.ok_or("the published policy document is invalid")?;
    let policy = PolicyService::new(MemoryPolicySource::new(vec![PublishedPolicy { address: *policy_publication.address(), document }]), BuiltInPolicyEngine, MemoryDecisionLog::new());
    let anchors = MemoryAnchorSource::new(now, &custody, receipt);
    let bundles = MemoryBundleStore::new();
    let ports = FactoryPorts {
        registry: &registry,
        artefacts: &artefacts,
        rosters: &rosters,
        profiles: &profiles,
        policy: &policy,
        anchors: &anchors,
        custody: &custody,
        random: &OsRandom,
        bundles: &bundles,
    };
    let publishing = publishing_policy();
    let verifier = VerifyPublication::new(TrustStore::new(&trust), &publishing);
    let mut request = BuildRequest::new(tenancy, vec![*publication.address()]);
    request.layouts = Vec::new();
    let built = BundleBuilder::new(ports, &verifier, identity).build(&request).map_err(|e| format!("the bundle was not released: {e}"))?;

    let out = Path::new(out_dir);
    std::fs::create_dir_all(out).map_err(err)?;
    let name = file_name(built.sealed.issued.0, built.sealed.seq.0);
    std::fs::write(out.join(&name), &built.sealed.bytes).map_err(err)?;
    std::fs::write(out.join("trust-bundle.cbor"), trust.encode().map_err(err)?).map_err(err)?;
    let Some(agree) = agree else {
        // A browser device opens and verifies the bundle itself. What it will hold is the roster
        // as the builder restricts it (DIS-013), so that is what the gate is told was issued.
        if let Some(issued_dir) = args.value("--issued-dir") {
            let fields = fieldseal_distribution::domain::instrument_facts(&publication.artefact).map_err(err)?.roster_fields;
            for issued in &issued_all {
                let held = issued.restricted_to(&fields);
                let consent = held
                    .entries
                    .iter()
                    .map(|e| (e.subject.clone(), match e.consent { ConsentState::Granted => IssuedConsent::Granted, ConsentState::Refused => IssuedConsent::Refused, ConsentState::Unknown => IssuedConsent::Unknown }))
                    .collect();
                let address = fieldseal_kernel::id::Digest::from(*fieldseal_kernel::id::ContentAddress::of(&held.encode()).as_bytes());
                let record = IssuedRoster { cohort: held.cohort.clone(), version: held.version, address, issued_at: built.sealed.issued, consent };
                fieldseal_adapters_file::rosters::record_issued(Path::new(issued_dir), &tenancy, &record).map_err(err)?;
            }
        }
        println!("built {} (sequence {}, {} bytes) with the stack's authority for tenancy {}", out.join(&name).display(), built.manifest.seq.0, built.sealed.bytes.len(), &tenancy_hex[..16]);
        return Ok(0);
    };
    let secret = hex(agree.secret_bytes());
    std::fs::write(out.join("device.txt"), format!("# The registered device (software keys; not for production).\ntenancy = {tenancy_hex}\nagreement-key = {secret}\ninstrument-schema = {}\nissued-ms = {}\n", fieldseal_adapters_memory::demo::DEMO_SCHEMA, built.sealed.issued.0)).map_err(err)?;
    // Open the bundle as the device will, so that what the gate is told was issued is exactly
    // what the runtime holds: the roster as sealed (only the fields the instrument reads) and
    // its content address (what records and imports name).
    let key = SoftwareAgreementKey::new(RecipientSecret::from_bytes(Suite::Fs1P, agree.secret_bytes()).map_err(err)?).map_err(err)?;
    let profile = RuntimeProfile { instrument_schema: fieldseal_adapters_memory::demo::DEMO_SCHEMA, localisation_reference: None };
    let state = ImportState { tenancy, now: built.sealed.issued, held: HeldState::default() };
    let verified = VerifyBundle::new(&trust, &publishing, &key, profile).verify(&built.sealed.bytes, &state).map_err(|r| format!("the bundle does not verify as the device would: {r}"))?;
    if let Some(issued_dir) = args.value("--issued-dir") {
        for r in &verified.content.rosters {
            let consent = r
                .entries
                .iter()
                .map(|e| (e.subject.clone(), match e.consent { ConsentState::Granted => IssuedConsent::Granted, ConsentState::Refused => IssuedConsent::Refused, ConsentState::Unknown => IssuedConsent::Unknown }))
                .collect();
            let address = fieldseal_kernel::id::Digest::from(*fieldseal_kernel::id::ContentAddress::of(&r.encode()).as_bytes());
            let issued_roster = IssuedRoster { cohort: r.cohort.clone(), version: r.version, address, issued_at: built.sealed.issued, consent };
            fieldseal_adapters_file::rosters::record_issued(Path::new(issued_dir), &tenancy, &issued_roster).map_err(err)?;
        }
    }
    println!("built {} (sequence {}, {} bytes) with the stack's authority for tenancy {}", out.join(&name).display(), built.manifest.seq.0, built.sealed.bytes.len(), &tenancy_hex[..16]);
    println!("{} instrument(s), {} roster(s) with {} subject(s) issued", built.manifest.instruments.len(), built.manifest.rosters.len(), issued_all.iter().map(|r| r.entries.len()).sum::<usize>());
    println!("verify it with: fieldseal bundle verify {} --trust {} --device-file {}", out.join(&name).display(), out.join("trust-bundle.cbor").display(), out.join("device.txt").display());
    println!("note: software keys, unattested{}; development custody (CLI-007, CLI-019)", if args.has("--allow-unattested") { ", roster released under the development allowance (REG-017)" } else { "" });
    Ok(0)
}

fn hex(b: &[u8]) -> String {
    crate::support::hex(b)
}

fn system_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}
