//! The bundle file's golden vector (WIRE-090..095, DIS-020..023, DIS-030), checked in-process
//! with a verifier built from nothing but the vector's recorded inputs.

use fieldseal_adapters_memory::demo::DEMO_SCHEMA;
use fieldseal_adapters_memory::distribution::SoftwareAgreementKey;
use fieldseal_distribution::application::{HeldState, ImportState, VerifiedBundle, VerifyBundle};
use fieldseal_distribution::domain::{BundleFile, BundleRejection, RuntimeProfile, VerifyStep};
use fieldseal_kernel::cbor;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_kernel::id::TenancyId;
use fieldseal_kernel::seal::{RecipientSecret, Suite};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::Value;
use fieldseal_policy::domain::Controls;
use fieldseal_trust::domain::TrustBundle;
use serde_json::Value as J;

use super::harness::{Chk, Collector, ensure, label, same, unhex};
use super::Unit;

const BUNDLE: &str = include_str!("../../../../adapters/memory/tests/vectors/bundle.json");
const T0: AuthorityTime = AuthorityTime(1_800_000_000_000);
const BUILDER: &str = "https://ci.example.org/builders/fieldseal-demo";
const SOURCE: &str = "https://git.example.org/authority/artefacts";

/// The vector units of the `distribution` suite.
pub fn units() -> Vec<Unit> {
    vec![Unit::new("distribution:bundle", &["distribution", "dis-verify"], bundle)]
}

fn s<'a>(j: &'a J, key: &str) -> Result<&'a str, String> {
    j[key].as_str().ok_or_else(|| format!("field `{key}` is missing"))
}

fn step_name(s: VerifyStep) -> &'static str {
    match s {
        VerifyStep::Envelope => "envelope",
        VerifyStep::Signature => "signature",
        VerifyStep::Open => "open",
        VerifyStep::Content => "content",
        VerifyStep::Sequence => "sequence",
        VerifyStep::Artefacts => "artefacts",
        VerifyStep::Compatibility => "compatibility",
        VerifyStep::Rosters => "rosters",
    }
}

fn verify(trust: &TrustBundle, secret: &[u8], tenancy: TenancyId, max_size: usize, file: &[u8]) -> Result<Result<VerifiedBundle, BundleRejection>, String> {
    let key = SoftwareAgreementKey::new(RecipientSecret::from_bytes(Suite::Fs1P, secret).c()?).c()?;
    let mut publishing = Controls::defaults().publishing();
    publishing.allowed_builders = vec![BUILDER.into()];
    publishing.allowed_sources = vec![SOURCE.into()];
    let profile = RuntimeProfile { instrument_schema: DEMO_SCHEMA, localisation_reference: None };
    Ok(VerifyBundle::new(trust, &publishing, &key, profile)
        .with_max_size(max_size)
        .verify(file, &ImportState { tenancy, now: AuthorityTime(T0.0 + 2 * AuthorityTime::DAY), held: HeldState::default() }))
}

fn bundle(c: &mut Collector) {
    let Ok(j) = serde_json::from_str::<J>(BUNDLE) else { return c.case(&["WIRE-090".into()], "load", || Err("bundle.json does not parse".into())) };
    let v = &j["valid"];
    let Ok(trust) = unhex(s(v, "trust_bundle").unwrap_or("")).and_then(|b| TrustBundle::decode(&b).c()) else {
        return c.case(&["WIRE-090".into()], "trust bundle", || Err("the vector trust bundle does not decode".into()));
    };
    c.case(&["WIRE-090".into(), "WIRE-091".into(), "DIS-022".into()], "the bundle file has the FSB1 envelope with exactly the four outer fields", || {
        let file = unhex(s(v, "file")?)?;
        same!(&file[..4], b"FSB1".as_slice(), "magic");
        let Value::Map(outer) = cbor::decode(&file[4..]).c()? else { return Err("the envelope is not a map".into()) };
        same!(outer.keys().map(String::as_str).collect::<Vec<_>>(), ["chain", "sealed", "sig", "signer"], "outer fields");
        let parsed = BundleFile::decode(&file, usize::MAX).c()?;
        same!(parsed.sealed.suite.id(), "fs1-p", "suite");
        same!(parsed.encode(), file, "decode then encode");
        Ok(())
    });
    c.case(&["DIS-023".into()], "the file name carries only a date and a counter", || {
        let name = fieldseal_distribution::domain::file_name(1_800_086_401_000, v["sequence"].as_u64().c()?);
        same!(name.clone(), "fieldseal-bundle-20270116-1.fsb".to_owned(), "file name");
        same!(name, s(v, "file_name")?.to_owned(), "recorded file name");
        Ok(())
    });
    c.case(&["WIRE-092".into(), "DIS-030".into()], "the valid vector verifies and opens to the recorded contents", || {
        let tenancy = TenancyId::from_bytes(&unhex(s(v, "tenancy")?)?).c()?;
        let verified = verify(&trust, &unhex(s(v, "agreement_secret")?)?, tenancy, usize::MAX, &unhex(s(v, "file")?)?)?
            .map_err(|r| format!("rejected: {r:?}"))?;
        same!(lower_hex(verified.address.as_bytes()), s(v, "address")?.to_owned(), "address");
        same!(verified.content.seq.0, v["sequence"].as_u64().c()?, "sequence");
        let r = verified.content.rosters.first().c()?;
        same!((r.cohort.as_str().to_owned(), r.version, r.entries.len()), ("cohort-a".to_owned(), 4, 2), "roster");
        same!(r.field_names().into_iter().collect::<Vec<_>>(), ["age"], "roster fields (DIS-013)");
        Ok(())
    });
    for (i, case) in j["invalid"].as_array().map_or(&[][..], Vec::as_slice).iter().enumerate() {
        c.case(&["DIS-030".into(), "DIS-031".into()], format!("damaged: {}", label(case, i)), || {
            let tenancy = TenancyId::from_bytes(&unhex(s(case, "tenancy")?)?).c()?;
            let max = case["max_size"].as_u64().c()?.min(usize::MAX as u64) as usize;
            let outcome = verify(&trust, &unhex(s(case, "agreement_secret")?)?, tenancy, max, &unhex(s(case, "file")?)?)?;
            let Err(r) = outcome else { return Err("the damaged bundle was accepted".into()) };
            same!(step_name(r.step()).to_owned(), s(case, "step")?.to_owned(), "failing step");
            same!(r.code().map(|c| c.as_str().to_owned()), case["error"].as_str().map(str::to_owned), "error code");
            Ok(())
        });
    }
    c.case(&["DIS-031".into()], "the damaged-bundle vectors are not empty", || {
        ensure!(j["invalid"].as_array().is_some_and(|a| a.len() >= 3), "too few damaged bundles");
        Ok(())
    });
}
