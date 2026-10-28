//! `fieldseal deployment validate|render|release` and `fieldseal docs build` (CLI §5,
//! DEP-001–006, DEP-010–012, DEP-020, DEP-030–033).
//!
//! Reading files is this module's job; the Deployment context sees decoded values. Nothing
//! here reads a secret: manifests hold references, and rendering writes references.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use fieldseal_deployment::application::{DeploymentTools, ManifestFinding, RenderEnvironment, ValidateManifest};
use fieldseal_deployment::docs::{CheckDoc, DocsInput, InstrumentDoc, ItemDoc, PolicyRow, TrustRow, build_documentation};
use fieldseal_deployment::domain::{Component, EnvironmentName, StoredBuild};
use fieldseal_deployment::manifest::{ArtefactRef, Manifest, decode_manifest};
use fieldseal_deployment::release::{build_signing_message, create_release};
use fieldseal_deployment::render::env_file;
use fieldseal_deployment::validate::check_policy_layers;
use fieldseal_instrument::application::validate_instrument;
use fieldseal_intake::data_contract::generate_data_contract;
use fieldseal_kernel::crypto::{P256PublicKey, Signature};
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::id::{ContentAddress, Digest, Salt};
use fieldseal_kernel::sign::{SigningKey, verify_message};
use fieldseal_kernel::{Value, cbor};
use fieldseal_policy::domain::merge::describe;
use fieldseal_policy::domain::{PolicyDocument, decode_document, merge_layers};
use fieldseal_trust::domain::TrustBundle;

use crate::args::Args;
use crate::json;
use crate::outcome::{Outcome, exit};

fn read_value(path: &str) -> Result<Value, String> {
    fieldseal_adapters_authoring::decode_path(std::path::Path::new(path)).map_err(|e| format!("{path}: {e}"))
}

fn address_of(v: &Value) -> Result<ContentAddress, String> {
    Ok(ContentAddress::of(&cbor::encode(v).map_err(|e| e.to_string())?))
}

fn finding(o: &mut Outcome, file: &str, f: &ManifestFinding) {
    let path = f.message().split_once(": ").map_or("", |(p, _)| p);
    o.raw_finding(f.requirement(), "error", file, path, &format!("{}: {}", f.kind(), f.message()));
}

fn short(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn event(name: &str, fields: &[(&str, &str)]) {
    let mut m = BTreeMap::from([("event".to_owned(), Value::Text(name.to_owned())), ("component".to_owned(), Value::Text("cli".into()))]);
    for (k, v) in fields {
        m.insert((*k).to_owned(), Value::Text((*v).to_owned()));
    }
    eprintln!("{}", json::compact(&Value::Map(m)));
}

/// Runs `fieldseal deployment …` and `fieldseal docs …`; `args` start at the noun.
pub fn run(args: &[String]) -> ExitCode {
    let command: &'static str = match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
        (Some("deployment"), Some("validate")) => "deployment validate",
        (Some("deployment"), Some("render")) => "deployment render",
        (Some("deployment"), Some("release")) => "deployment release",
        (Some("docs"), Some("build")) => "docs build",
        _ => {
            eprintln!(
                "usage: fieldseal deployment validate <manifest> [--policy <file>]...\n\
                 \x20      fieldseal deployment render <manifest> --environment <e> [--out <dir>]\n\
                 \x20      fieldseal deployment release <manifest> --publication <sha256:…> --build <component>=<file>... (--signing-key-file <file> | --practice) [--environment <e>] [--out <file>]\n\
                 \x20      fieldseal docs build <manifest> --environment <e> --release <sha256:…> -o <dir> [--instrument <file>]... [--policy <file>]... [--trust-bundle <file>]"
            );
            return ExitCode::from(exit::USAGE);
        }
    };
    let (valued, switches): (&[&str], &[&str]) = match command {
        "deployment validate" => (&["--policy"], &[]),
        "deployment render" => (&["--environment", "--out"], &[]),
        "deployment release" => (&["--publication", "--build", "--signing-key-file", "--out", "--environment"], &["--practice"]),
        _ => (&["--environment", "--release", "-o", "--instrument", "--policy", "--trust-bundle"], &[]),
    };
    let json = args.iter().any(|a| a == "--json");
    let mut o = Outcome::new(command);
    match Args::parse(command, &args[2..], valued, switches) {
        Err(e) => o.error(exit::USAGE, e.0),
        Ok(a) => {
            if let Err((code, message)) = execute(command, &a, &mut o) {
                o.error(code, format!("fieldseal: {message}"));
            }
        }
    }
    ExitCode::from(o.emit(json))
}

type Failure = (u8, String);

fn execute(command: &str, a: &Args, o: &mut Outcome) -> Result<(), Failure> {
    let file = a.file(command).map_err(|e| (exit::USAGE, e.0))?.to_owned();
    let value = read_value(&file).map_err(|e| (exit::NOT_FOUND, e))?;
    let internal = |e: String| (exit::INTERNAL, e);
    let address = address_of(&value).map_err(internal)?;
    o.set("address", Value::Text(address.to_text()));
    let findings = DeploymentTools.validate(&value);
    for f in &findings {
        finding(o, &file, f);
    }
    let manifest = decode_manifest(&value).ok();
    match command {
        "deployment validate" => {
            if manifest.is_some() {
                let docs = a.values("--policy").iter().map(|p| load_policy(p)).collect::<Result<Vec<_>, _>>()?;
                if !docs.is_empty() {
                    let refs = docs.iter().collect::<Vec<_>>();
                    for f in check_policy_layers(&refs) {
                        finding(o, "policy", &f);
                    }
                    // DEP-074: with the policy in hand, every authority purpose must be bound,
                    // and bound at or above the policy's custody minimums.
                    if let Some(m) = manifest.as_ref() {
                        let (controls, _) = merge_layers(&refs);
                        let minimums = controls.factory().custody;
                        for env in m.environments.keys() {
                            for f in fieldseal_deployment::custody::check_custody(m, env, Some(&minimums)) {
                                if !findings.contains(&f) {
                                    finding(o, &file, &f);
                                }
                            }
                        }
                    }
                }
            }
            o.lines.push(format!("{file}: {} finding(s)", o.findings.len()));
            Ok(())
        }
        "deployment render" => {
            let Some(m) = manifest.filter(|_| findings.is_empty()) else { return Ok(()) };
            let env = a.required(command, "--environment").map_err(|e| (exit::USAGE, e.0))?;
            let rendered = DeploymentTools.render(&value, &EnvironmentName(env.to_owned())).map_err(|e| (exit::FAILED, format!("MissingReference: {}", e.join("; "))))?;
            let provisioning = json::pretty(&rendered.provisioning);
            let envs: BTreeMap<String, Value> = rendered
                .environments
                .iter()
                .map(|(c, vars)| (c.name().to_owned(), Value::Map(vars.iter().map(|(k, v)| (k.clone(), Value::Text(v.clone()))).collect())))
                .collect();
            o.set("environments", Value::Map(envs));
            o.set("provisioning", rendered.provisioning.clone());
            if let Some(dir) = a.value("--out") {
                std::fs::create_dir_all(dir).map_err(|e| (exit::CONFIG, format!("{dir}: {e}")))?;
                for (c, vars) in &rendered.environments {
                    write(&Path::new(dir).join(format!("{}.env", c.name())), env_file(vars).as_bytes())?;
                }
                write(&Path::new(dir).join("provisioning.json"), provisioning.as_bytes())?;
                o.lines.push(format!("rendered {} component(s) to {dir}", rendered.environments.len()));
            } else {
                let mut body = String::new();
                for (c, vars) in &rendered.environments {
                    body.push_str(&format!("# {}\n{}\n", c.name(), env_file(vars)));
                }
                body.push_str(&format!("# provisioning\n{provisioning}\n"));
                o.body = Some(body);
            }
            event("EnvironmentRendered", &[("deployment", &m.name), ("environment", env)]);
            Ok(())
        }
        "deployment release" => {
            if !findings.is_empty() {
                return Ok(());
            }
            let m = manifest.ok_or((exit::FAILED, "the manifest is invalid".to_owned()))?;
            release(a, o, &m, address)
        }
        _ => {
            let Some(m) = manifest.filter(|_| findings.is_empty()) else { return Ok(()) };
            docs_build(a, o, &m)
        }
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    std::fs::write(path, bytes).map_err(|e| (exit::CONFIG, format!("{}: {e}", path.display())))
}

fn load_policy(path: &str) -> Result<PolicyDocument, Failure> {
    let v = read_value(path).map_err(|e| (exit::NOT_FOUND, e))?;
    let decoded = decode_document(&v);
    decoded.document.ok_or_else(|| (exit::FAILED, format!("{path}: the policy is invalid: {}", decoded.findings.first().map(|f| format!("{} {}", f.path, f.message)).unwrap_or_default())))
}

/// Decodes exactly 64 lowercase hexadecimal digits; anything else (odd length, a sign, upper
/// case, other characters) is refused.
fn strict_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != 64 || text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    crate::support::unhex(text)
}

fn practice_key() -> SigningKey {
    SigningKey::from_scalar(sha256(b"fieldseal practice build key").as_bytes()).expect("a SHA-256 is a valid scalar")
}

fn release(a: &Args, o: &mut Outcome, m: &Manifest, manifest: ContentAddress) -> Result<(), Failure> {
    let command = "deployment release";
    let publication = a.required(command, "--publication").map_err(|e| (exit::USAGE, e.0))?;
    let published = ContentAddress::parse_text(publication).map_err(|_| (exit::USAGE, "--publication: expected sha256: and 64 hex digits".to_owned()))? == manifest;
    if a.value("--signing-key-file").is_some() && a.has("--practice") {
        return Err((exit::USAGE, "--practice and --signing-key-file are exclusive".to_owned()));
    }
    let (key, signing) = match a.value("--signing-key-file") {
        Some(f) => {
            let hex = std::fs::read_to_string(f).map_err(|e| (exit::NOT_FOUND, format!("{f}: {e}")))?;
            let hex = hex.trim();
            let bytes = strict_hex(hex).ok_or_else(|| (exit::USAGE, format!("{f}: expected 64 lowercase hexadecimal digits (a 32-byte P-256 scalar)")))?;
            (SigningKey::from_scalar(&bytes).map_err(|_| (exit::USAGE, format!("{f}: expected a 32-byte P-256 scalar in hex")))?, "key-file")
        }
        None if a.has("--practice") => {
            let production = a.value("--environment") == Some("production") || m.environments.contains_key("production");
            if production {
                o.raw_finding("DEP-023", "error", "deployment release", "", "PolicyFloorViolation: --practice signing is not allowed for production (DEP-023)");
                return Ok(());
            }
            (practice_key(), "practice")
        }
        None => return Err((exit::USAGE, "deployment release needs --signing-key-file <f>, or --practice for development builds".to_owned())),
    };
    let public: P256PublicKey = key.public_key();
    let mut builds = vec![];
    for spec in a.values("--build") {
        let (name, path) = spec.split_once('=').ok_or((exit::USAGE, format!("--build {spec}: expected <component>=<file>")))?;
        let component = Component::parse(name).ok_or((exit::USAGE, format!("--build {spec}: unknown component")))?;
        let bytes = std::fs::read(path).map_err(|e| (exit::NOT_FOUND, format!("{path}: {e}")))?;
        let digest = Digest::from(*sha256(&bytes).as_bytes());
        let signature = key.sign_message(&build_signing_message(component, &ContentAddress::from(*digest.as_bytes())));
        builds.push(StoredBuild { component, digest, signature, bytes });
    }
    let required: Vec<Component> = m.components.keys().copied().collect();
    let verify = |b: &StoredBuild| verify_message(&public, &build_signing_message(b.component, &ContentAddress::from(*b.digest.as_bytes())), &Signature(b.signature.0.clone())).is_ok();
    let release = create_release(manifest, published, &builds, &required, &verify).map_err(|e| (exit::FAILED, e.to_string()))?;
    o.set("release", Value::Text(release.address.to_text()));
    o.set("signing", Value::Text(signing.into()));
    o.set("record", release.to_value());
    o.lines.push(format!("release {}", release.address.to_text()));
    if signing == "practice" {
        o.lines.push("builds were signed with the practice key (development only); pass --signing-key-file for a real one".into());
    }
    if let Some(out) = a.value("--out") {
        write(Path::new(out), json::pretty(&release.to_value()).as_bytes())?;
    }
    event("ReleaseCreated", &[("release", &release.address.to_text())]);
    Ok(())
}

fn docs_build(a: &Args, o: &mut Outcome, m: &Manifest) -> Result<(), Failure> {
    let command = "docs build";
    let env = a.required(command, "--environment").map_err(|e| (exit::USAGE, e.0))?;
    let release = ContentAddress::parse_text(a.required(command, "--release").map_err(|e| (exit::USAGE, e.0))?).map_err(|_| (exit::USAGE, "--release: expected sha256: and 64 hex digits".to_owned()))?;
    let out = a.required(command, "-o").map_err(|e| (exit::USAGE, e.0))?;
    let resolved = m.resolve(env).map_err(|f| (exit::FAILED, f.iter().map(|x| x.message().to_owned()).collect::<Vec<_>>().join("; ")))?;

    // Instruments, by name, each checked against a pinned digest.
    let mut supplied = BTreeMap::new();
    for p in a.values("--instrument") {
        let doc = read_value(p).map_err(|e| (exit::NOT_FOUND, e))?;
        let inst = validate_instrument(&doc).map_err(|_| (exit::FAILED, format!("{p}: the instrument is invalid; run `instrument validate`")))?.instrument;
        supplied.insert(inst.definition().name.clone(), inst);
    }
    let mut instruments = vec![];
    for r in &resolved.instruments {
        let inst = supplied.get(short(&r.name)).ok_or((exit::NOT_FOUND, format!("UnresolvableArtefact: instrument `{}` was not supplied (--instrument)", r.name)))?;
        let addr = address_of(&inst.to_value()).map_err(|e| (exit::INTERNAL, e))?;
        pinned(r, &addr)?;
        instruments.push(instrument_doc(&r.name, inst, addr));
    }

    // Policy layers, in manifest order.
    let mut by_name = BTreeMap::new();
    for p in a.values("--policy") {
        let v = read_value(p).map_err(|e| (exit::NOT_FOUND, e))?;
        let doc = load_policy(p)?;
        by_name.insert(doc.metadata.name.clone(), (doc, address_of(&v).map_err(|e| (exit::INTERNAL, e))?));
    }
    let mut layers = vec![];
    let mut layer_labels = BTreeMap::new();
    for r in &resolved.policy_layers {
        let (doc, addr) = by_name.get(short(&r.name)).ok_or((exit::NOT_FOUND, format!("UnresolvableArtefact: policy layer `{}` was not supplied (--policy)", r.name)))?;
        pinned(r, addr)?;
        layer_labels.insert(r.name.clone(), doc.layer.label());
        layers.push(doc);
    }
    let (controls, _) = merge_layers(&layers);
    for f in check_policy_layers(&layers) {
        finding(o, "policy", &f);
    }
    let policy: Vec<PolicyRow> = controls
        .as_map()
        .iter()
        .map(|(path, v)| PolicyRow {
            control: path.clone(),
            value: describe(v),
            layer: layers.iter().rev().find(|d| d.controls.contains_key(path)).map_or_else(|| "schema default".to_owned(), |d| d.layer.label()),
        })
        .collect();
    if o.exit != exit::OK {
        return Ok(());
    }

    let trust = match a.value("--trust-bundle") {
        None => vec![],
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| (exit::NOT_FOUND, format!("{p}: {e}")))?;
            if m.trust_bundle.digest.is_some_and(|d| d != ContentAddress::of(&bytes)) {
                return Err((exit::FAILED, format!("UnresolvableArtefact: {p} does not match the trust bundle digest in the manifest")));
            }
            let bundle = TrustBundle::decode(&bytes).map_err(|e| (exit::FAILED, format!("{p}: {e}")))?;
            let c = bundle.contents();
            let validity = |from: u64, to: u64| format!("{from} to {to} (authority ms)");
            let mut rows: Vec<TrustRow> = c.roots.iter().map(|r| TrustRow { kind: "root".into(), key: lower_hex(r.key_id().as_bytes()), validity: validity(r.not_before().0, r.not_after().0) }).collect();
            rows.extend(c.certificates.iter().map(|r| TrustRow {
                kind: r.purpose().map_or("key", |p| p.as_str()).to_owned(),
                key: lower_hex(r.key_id().as_bytes()),
                validity: validity(r.not_before().0, r.not_after().0),
            }));
            for (kind, keys) in &c.publishers {
                rows.extend(keys.iter().map(|k| TrustRow { kind: format!("publisher ({kind})"), key: lower_hex(k.as_bytes()), validity: "see its certificate".into() }));
            }
            rows
        }
    };

    let bundle = build_documentation(&DocsInput { manifest: m, environment: env, release, instruments, policy_layers: layer_labels, policy, trust }).map_err(|e| (exit::FAILED, e))?;
    std::fs::create_dir_all(out).map_err(|e| (exit::CONFIG, format!("{out}: {e}")))?;
    for (name, bytes) in &bundle.files {
        write(&Path::new(out).join(name), bytes)?;
    }
    o.set("release", Value::Text(release.to_text()));
    o.set("files", Value::Array(bundle.files.keys().map(|k| Value::Text(k.clone())).collect()));
    o.lines.push(format!("wrote {} documentation file(s) to {out} for release {}", bundle.files.len(), release.to_text()));
    event("DocumentationBuilt", &[("release", &release.to_text())]);
    Ok(())
}

fn pinned(r: &ArtefactRef, actual: &ContentAddress) -> Result<(), Failure> {
    match &r.digest {
        Some(d) if d != actual => Err((exit::FAILED, format!("UnresolvableArtefact: `{}` has content address {}, not the pinned {}", r.name, actual.to_text(), d.to_text()))),
        _ => Ok(()),
    }
}

fn instrument_doc(reference: &str, inst: &fieldseal_instrument::domain::Instrument, address: ContentAddress) -> InstrumentDoc {
    let fp = fieldseal_kernel::digest::instrument_fingerprint(&Salt::from([0; 32]), &cbor::encode(&inst.to_value()).unwrap_or_default());
    let contract = generate_data_contract(fp, inst);
    let codes: BTreeMap<&str, String> = contract.code_lists.iter().map(|l| (l.id.as_str(), l.codes.iter().map(|c| c.code.clone()).collect::<Vec<_>>().join(", "))).collect();
    let items = contract
        .items
        .iter()
        .map(|i| ItemDoc {
            path: i.path.clone(),
            value_type: i.value_type.to_owned(),
            unit: i.unit.clone().or_else(|| i.currency.clone()).unwrap_or_default(),
            required: i.required,
            allowed: match (&i.code_list, &i.min, &i.max) {
                (Some(l), ..) => codes.get(l.as_str()).cloned().unwrap_or_default(),
                (None, Some(lo), Some(hi)) => format!("{lo} to {hi}"),
                (None, Some(lo), None) => format!("at least {lo}"),
                (None, None, Some(hi)) => format!("at most {hi}"),
                _ => String::new(),
            },
            nonresponse: i.nonresponse.join(", "),
        })
        .collect();
    let checks = contract
        .expectations
        .iter()
        .map(|e| CheckDoc { id: e.id.clone(), kind: e.kind.clone(), severity: format!("{:?}", e.severity).to_lowercase(), items: e.items.join(", ") })
        .collect();
    let consent = inst
        .to_value()
        .as_map()
        .and_then(|m| m.get("spec"))
        .and_then(Value::as_map)
        .and_then(|s| s.get("consent"))
        .and_then(Value::as_map)
        .map(|c| c.iter().filter_map(|(k, v)| scalar(v).map(|t| format!("{k}: {t}"))).collect())
        .unwrap_or_default();
    InstrumentDoc {
        reference: reference.to_owned(),
        title: inst.definition().name.clone(),
        address: address.to_text(),
        languages: contract.languages.clone(),
        items,
        checks,
        consent,
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::Text(t) => Some(t.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Int(i) => Some(i.to_string()),
        _ => None,
    }
}
