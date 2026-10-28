//! `fieldseal registry list|show|fetch` (CLI §5 `registry`, PUB-060–PUB-062, PUB-100): browse the
//! stack's register of published artefacts, and download one, verified.
//!
//! The register is the directory the publishers' `*.published` files are kept in (the stack's
//! `published` volume). Every publication is verified as a device verifies it: threshold of
//! publisher signatures, provenance, and inclusion of each signature's log entry in the checkpoint
//! it carries, against the log pinned by the trust bundle. With a log address the log's own latest
//! checkpoint is shown too, and checked against the pinned key.

use std::path::{Path, PathBuf};

use fieldseal_kernel::Value;
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::Publication;
use fieldseal_trust::domain::TrustStore;

use crate::args::Args;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, hex, run_command, setting};
use crate::trust_cmd::load_bundle;

/// Runs `registry <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    let common = ["--dir", "--trust-bundle", "--log-url"];
    Some(match verb {
        "list" => run_command("registry list", raw, &common, &[], list),
        "show" => run_command("registry show", raw, &common, &[], show),
        "fetch" => run_command("registry fetch", raw, &["--dir", "--trust-bundle", "--log-url", "--out", "-o", "--document"], &[], fetch),
        _ => return None,
    })
}

struct Entry {
    file: PathBuf,
    publication: Publication,
    verdict: Result<Vec<String>, String>,
}

fn load(args: &Args, out: &mut Outcome) -> Option<Vec<Entry>> {
    let dir = PathBuf::from(setting(args, "--dir", "FIELDSEAL_REGISTRY_DIR").unwrap_or_else(|| "published".into()));
    let bundle = load_bundle(args, out)?;
    let Ok(rd) = std::fs::read_dir(&dir) else {
        fail(out, exit::NOT_FOUND, "not-found", &[("file", &dir.to_string_lossy()), ("reason", "no such register directory")]);
        return None;
    };
    let policy = crate::bundle_stack::publishing_policy();
    let verifier = VerifyPublication::new(TrustStore::new(&bundle), &policy);
    let mut files: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "published")).collect();
    files.sort();
    let mut entries = Vec::new();
    for file in files {
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) => {
                fail(out, exit::NOT_FOUND, "not-found", &[("file", &file.to_string_lossy()), ("reason", &e.to_string())]);
                return None;
            }
        };
        match Publication::decode(&bytes) {
            Ok(publication) => {
                let verdict = verifier.verify(&publication, &[]).map(|v| v.signers.iter().map(|k| hex(k.as_bytes())).collect()).map_err(|e| e.to_string());
                entries.push(Entry { file, publication, verdict });
            }
            Err(e) => out.raw_finding("PUB", "error", &file.to_string_lossy(), "", &e.to_string()),
        }
    }
    entries.sort_by_key(|e| e.publication.log.iter().map(|r| r.inclusion.leaf_index).min().unwrap_or(u64::MAX));
    Some(entries)
}

fn describe(e: &Entry) -> Vec<String> {
    let p = &e.publication;
    let a = &p.artefact;
    let mut lines = vec![format!("{} {} {}", a.kind().as_str(), a.name(), a.version()), format!("  address    {}", p.address().to_text())];
    match &e.verdict {
        Ok(signers) => {
            lines.push(format!("  signatures {} of the threshold, by {}", signers.len(), signers.iter().map(|s| s[..8].to_owned()).collect::<Vec<_>>().join(", ")));
            let idx: Vec<String> = p.log.iter().map(|r| r.inclusion.leaf_index.to_string()).collect();
            lines.push(format!("  log        leaf {} of a tree of {} (checkpoint root {})", idx.join(" and "), p.checkpoint.size(), &hex(p.checkpoint.root().as_bytes())[..16]));
            lines.push("  verified   yes: signatures, provenance and log inclusion against the trust bundle".into());
        }
        Err(why) => lines.push(format!("  verified   NO: {why}")),
    }
    lines
}

fn log_line(args: &Args, out: &mut Outcome) {
    let Some(url) = setting(args, "--log-url", "FIELDSEAL_TRANSLOG_URL") else { return };
    match crate::stores::translog_at(&url).and_then(|l| l.checkpoint().map_err(|e| e.to_string())) {
        Ok(c) => {
            out.lines.push(format!("log {} at {url}: {} entries, root {}", c.origin(), c.size(), &hex(c.root().as_bytes())[..16]));
            out.set("logSize", Value::Int(i128::from(c.size())));
        }
        Err(e) => out.raw_finding("PUB-100", "error", &url, "", &e),
    }
}

fn list(args: &Args, out: &mut Outcome) -> Res {
    let Some(entries) = load(args, out) else { return Ok(()) };
    log_line(args, out);
    out.lines.push(format!("{} published artefact(s)", entries.len()));
    let mut rows = Vec::new();
    for e in &entries {
        out.lines.extend(describe(e));
        if let Err(why) = &e.verdict {
            out.raw_finding("PUB", "error", &e.file.to_string_lossy(), "", why);
        }
        let a = &e.publication.artefact;
        rows.push(Value::Map(
            [
                ("kind".to_owned(), Value::Text(a.kind().as_str().into())),
                ("name".to_owned(), Value::Text(a.name().into())),
                ("version".to_owned(), Value::Text(a.version().into())),
                ("address".to_owned(), Value::Text(e.publication.address().to_text())),
                ("verified".to_owned(), Value::Bool(e.verdict.is_ok())),
            ]
            .into(),
        ));
    }
    out.set("artefacts", Value::Array(rows));
    Ok(())
}

fn find<'e>(entries: &'e [Entry], wanted: &str, out: &mut Outcome) -> Option<&'e Entry> {
    let matches: Vec<&Entry> = entries.iter().filter(|e| e.publication.address().to_text().starts_with(wanted) || e.publication.artefact.name() == wanted).collect();
    match matches.as_slice() {
        [one] => Some(one),
        [] => {
            fail(out, exit::NOT_FOUND, "not-found", &[("file", wanted), ("reason", "no such artefact in the register (give an address, a prefix of one, or a name)")]);
            None
        }
        many => {
            // Names are not unique (versions, kinds): list the candidates so the caller can
            // choose one by its address.
            for e in many {
                let a = &e.publication.artefact;
                out.lines.push(format!("  {} {} {}  {}", a.kind().as_str(), a.name(), a.version(), e.publication.address().to_text()));
            }
            fail(out, exit::USAGE, "not-found", &[("file", wanted), ("reason", "more than one artefact matches: give its address (sha256:…) instead")]);
            None
        }
    }
}

fn show(args: &Args, out: &mut Outcome) -> Res {
    let wanted = args.file("registry show")?;
    let Some(entries) = load(args, out) else { return Ok(()) };
    let Some(e) = find(&entries, wanted, out) else { return Ok(()) };
    out.lines.extend(describe(e));
    let p = &e.publication;
    for (i, r) in p.log.iter().enumerate() {
        out.lines.push(format!("  log entry {i}: {:?} signed by {}, leaf {}, proof path of {} hash(es)", r.entry.entry_type(), &hex(fieldseal_kernel::digest::key_id(r.entry.public_key().as_bytes()).as_bytes())[..8], r.inclusion.leaf_index, r.inclusion.path.len()));
    }
    out.lines.push(format!("  artefact   {} bytes of canonical CBOR in {}", p.artefact.canonical_bytes().len(), e.file.display()));
    if let Err(why) = &e.verdict {
        out.raw_finding("PUB", "error", &e.file.to_string_lossy(), "", why);
    }
    Ok(())
}

fn fetch(args: &Args, out: &mut Outcome) -> Res {
    let wanted = args.file("registry fetch")?;
    let Some(entries) = load(args, out) else { return Ok(()) };
    let Some(e) = find(&entries, wanted, out) else { return Ok(()) };
    if let Err(why) = &e.verdict {
        // Never hand out what does not verify.
        out.raw_finding("PUB", "error", &e.file.to_string_lossy(), "", why);
        return Ok(());
    }
    let name = format!("{}-{}.published", e.publication.artefact.name(), e.publication.artefact.version());
    let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| Path::new(&name).to_path_buf(), PathBuf::from);
    let bytes = match std::fs::read(&e.file) {
        Ok(b) => b,
        Err(err) => {
            fail(out, exit::NOT_FOUND, "not-found", &[("file", &e.file.to_string_lossy()), ("reason", &err.to_string())]);
            return Ok(());
        }
    };
    if crate::support::write(&path, &bytes, false, out) {
        out.lines.push(msg("fetched", &[("address", &e.publication.address().to_text()), ("file", &path.to_string_lossy())]));
        out.set("file", Value::Text(path.to_string_lossy().into_owned()));
        out.set("address", Value::Text(e.publication.address().to_text()));
        out.set("kind", Value::Text(e.publication.artefact.kind().as_str().into()));
        out.set("name", Value::Text(e.publication.artefact.name().into()));
        out.set("version", Value::Text(e.publication.artefact.version().into()));
        // `--document <file.json>`: the artefact's document itself (an instrument, say), for
        // `instrument preview` and the other authoring commands.
        if let Some(doc) = args.value("--document") {
            match fieldseal_kernel::cbor::decode(e.publication.artefact.canonical_bytes()) {
                Ok(v) => {
                    if crate::support::write(Path::new(doc), crate::json::pretty(&v).as_bytes(), false, out) {
                        out.lines.push(format!("wrote the {} document to {doc}", e.publication.artefact.kind().as_str().to_lowercase()));
                        out.set("document", Value::Text(doc.into()));
                    }
                }
                Err(err) => out.raw_finding("WIRE", "error", doc, "", &err.to_string()),
            }
        }
    }
    Ok(())
}
