//! `fieldseal log append|verify` (CLI §5 `log`, PUB-051–PUB-055, PUB-103): append a signed
//! entry to the transparency log and get its inclusion proof, and check a proof offline.
//!
//! A *log proof* file is canonical CBOR `{v, entry, leaf, leaf_index, tree_size, path,
//! checkpoint}`: the entry, how the log hashed it, the RFC 9162 audit path and the C2SP
//! checkpoint note it reaches. `log verify` also accepts the publication file `log prove --out`
//! writes, and checks each of its log records.

use std::path::Path;

use fieldseal_kernel::cbor;
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::Value;
use fieldseal_kernel::crypto::Purpose;
use fieldseal_kernel::structure::{Fields, expect_bytes_n};
use fieldseal_publishing::domain::merkle::{MAX_PATH, leaf_hash, verify_inclusion};
use fieldseal_publishing::domain::{InclusionProof, LeafFormat, LogEntry, Publication, SignedCheckpoint, TreeHeadTracker};
use fieldseal_trust::domain::TrustStore;

use crate::args::Args;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, hex, now, read, write};
use crate::trust_cmd::load_bundle;

fn encode_proof(entry: &LogEntry, leaf: LeafFormat, inclusion: &InclusionProof, checkpoint: &SignedCheckpoint) -> Option<Vec<u8>> {
    cbor::encode(&cbor::map([
        ("v", Value::Int(1)),
        ("entry", Value::Bytes(entry.encode())),
        ("leaf", Value::Text(leaf.as_str().into())),
        ("leaf_index", Value::Int(i128::from(inclusion.leaf_index))),
        ("tree_size", Value::Int(i128::from(inclusion.tree_size))),
        ("path", Value::Array(inclusion.path.iter().map(|d| Value::Bytes(d.as_bytes().to_vec())).collect())),
        ("checkpoint", Value::Bytes(checkpoint.note().to_vec())),
    ]))
    .ok()
}

struct Proof {
    entry: LogEntry,
    leaf: LeafFormat,
    inclusion: InclusionProof,
    checkpoint: SignedCheckpoint,
}

/// Reads a log proof file strictly: version 1, exactly the documented fields, each of its
/// exact type, a path of at most [`MAX_PATH`] 32-byte hashes, and nothing after the map.
fn decode_proof(bytes: &[u8]) -> Result<Proof, String> {
    let wire = |e: fieldseal_kernel::WireError| format!("{}: {}", e.code.as_str(), e.detail);
    let mut f = Fields::new(cbor::decode(bytes).map_err(wire)?).map_err(wire)?;
    f.version("v", &Value::Int(1)).map_err(wire)?;
    let entry = LogEntry::decode(&f.bytes("entry").map_err(wire)?).map_err(wire)?;
    let leaf = LeafFormat::parse(&f.text("leaf").map_err(wire)?).ok_or("unknown leaf format")?;
    let leaf_index = f.uint("leaf_index").map_err(wire)?;
    let tree_size = f.uint("tree_size").map_err(wire)?;
    let path = f.array("path").map_err(wire)?;
    if path.len() > MAX_PATH {
        return Err("the audit path is too long".into());
    }
    let path = path.into_iter().map(|d| expect_bytes_n::<32>(d).map(Digest::from)).collect::<Result<Vec<_>, _>>().map_err(wire)?;
    let checkpoint = SignedCheckpoint::parse(&f.bytes("checkpoint").map_err(wire)?).map_err(|e| e.to_string())?;
    f.finish().map_err(wire)?;
    Ok(Proof { entry, leaf, inclusion: InclusionProof { leaf_index, tree_size, path }, checkpoint })
}

/// Whether the file is a log proof (a map with a `v` field) rather than a publication.
fn is_proof(bytes: &[u8]) -> bool {
    matches!(cbor::decode(bytes), Ok(Value::Map(m)) if m.contains_key("v"))
}

/// `log append <entry>`: appends a signed entry (canonical CBOR, WIRE-191) and writes its proof.
/// The entry's key must be a current `publisher` key of the trust bundle (PUB-101); the
/// signature itself is over a statement the entry does not carry, so `artefact verify`
/// is what checks it against the publication.
pub fn append(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("log append")?;
    let at = now(args)?;
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let Some(bytes) = read(file, out) else { return Ok(()) };
    let entry = match LogEntry::decode(&bytes) {
        Ok(e) => e,
        Err(e) => {
            out.raw_finding("WIRE-191", "error", file, "", e.detail);
            return Ok(());
        }
    };
    let store = TrustStore::new(&bundle);
    let key = entry.key_id();
    let trusted = bundle.certificates_for(&key).any(|c| c.purpose() == Some(Purpose::Publisher) && store.verify_certificate(c, at).is_ok());
    if !trusted {
        out.raw_finding("PUB-101", "error", file, "", "the entry's key is not a current publisher key of the trust bundle");
        return Ok(());
    }
    let Some(s) = crate::artefact_cmd::stores(args, out) else { return Ok(()) };
    match s.log.append(&entry) {
        Ok(logged) => {
            let path = args.value("--out").or_else(|| args.value("-o")).map_or_else(|| Path::new(file).with_extension("logproof"), Into::into);
            let Some(body) = encode_proof(&logged.entry, logged.leaf, &logged.inclusion, &logged.checkpoint) else {
                fail(out, exit::INTERNAL, "encode-failed", &[]);
                return Ok(());
            };
            if write(&path, &body, false, out) {
                out.lines.push(msg("log-appended", &[("index", &logged.inclusion.leaf_index.to_string()), ("size", &logged.checkpoint.size().to_string()), ("file", &path.to_string_lossy())]));
                out.set("leafIndex", Value::Int(i128::from(logged.inclusion.leaf_index)));
                out.set("treeSize", Value::Int(i128::from(logged.checkpoint.size())));
                out.set("rootHash", Value::Text(hex(logged.checkpoint.root().as_bytes())));
                out.set("file", Value::Text(path.to_string_lossy().into_owned()));
            }
        }
        Err(e) => out.error(exit::CONFIG, format!("fieldseal: {e}")),
    }
    Ok(())
}

fn check(out: &mut Outcome, file: &str, p: &Proof, bundle: &fieldseal_trust::domain::TrustBundle) -> bool {
    let mut ok = true;
    if let Err(e) = p.checkpoint.verify(&bundle.contents().logs, 0) {
        ok = false;
        out.raw_finding("PUB-054", "error", file, "checkpoint", &e.to_string());
    }
    if p.inclusion.tree_size != p.checkpoint.size() || !verify_inclusion(&leaf_hash(&p.leaf.leaf(&p.entry)), &p.inclusion, p.checkpoint.root()) {
        ok = false;
        out.raw_finding("PUB-051", "error", file, &format!("leaf {}", p.inclusion.leaf_index), "the inclusion proof does not reach the checkpoint's root");
    }
    ok
}

/// `log verify <proof>`: checks the checkpoint is signed by a pinned log and the proof
/// reaches its root; with `--known-tree-head <note>`, also that the checkpoint extends that
/// tree head (PUB-055), taking the consistency proof from the configured log.
pub fn verify(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("log verify")?;
    let Some(bundle) = load_bundle(args, out) else { return Ok(()) };
    let Some(bytes) = read(file, out) else { return Ok(()) };
    let proofs: Vec<Proof> = if is_proof(&bytes) {
        match decode_proof(&bytes) {
            Ok(p) => vec![p],
            Err(e) => {
                out.raw_finding("WIRE", "error", file, "", &format!("not a valid log proof: {e}"));
                return Ok(());
            }
        }
    } else {
        match Publication::decode(&bytes) {
            Ok(p) => p.log.iter().map(|r| Proof { entry: r.entry.clone(), leaf: r.leaf, inclusion: r.inclusion.clone(), checkpoint: p.checkpoint.clone() }).collect(),
            Err(e) => {
                out.raw_finding("WIRE", "error", file, "", &format!("not a log proof or a publication: {e}"));
                return Ok(());
            }
        }
    };
    if proofs.is_empty() {
        out.raw_finding("PUB-103", "error", file, "", "the file carries no log record");
        return Ok(());
    }
    let mut ok = true;
    for p in &proofs {
        ok &= check(out, file, p, &bundle);
    }
    let head = &proofs[0].checkpoint;
    if let Some(known_path) = args.value("--known-tree-head") {
        let Some(known_bytes) = read(known_path, out) else { return Ok(()) };
        match SignedCheckpoint::parse(&known_bytes) {
            Ok(known) => {
                if let Err(e) = known.verify(&bundle.contents().logs, 0) {
                    ok = false;
                    out.raw_finding("PUB-055", "error", known_path, "", &e.to_string());
                } else if known.size() == head.size() {
                    if known.root() != head.root() {
                        ok = false;
                        out.raw_finding("PUB-055", "error", known_path, "", "same size, different root: the log forked");
                    }
                } else {
                    let (old, new) = if known.size() < head.size() { (&known, head) } else { (head, &known) };
                    let consistency = crate::artefact_cmd::stores(args, out).map(|s| s.log.prove_consistency(old.size(), new));
                    match consistency {
                        Some(Ok(proof)) => {
                            if TreeHeadTracker::new(old).advance(new, &proof).is_err() {
                                ok = false;
                                out.raw_finding("PUB-055", "error", known_path, "", "the tree heads are not consistent");
                            }
                        }
                        Some(Err(e)) => {
                            ok = false;
                            out.raw_finding("PUB-055", "error", known_path, "", &format!("no consistency proof from the log: {e}"));
                        }
                        None => return Ok(()),
                    }
                }
            }
            Err(e) => {
                ok = false;
                out.raw_finding("PUB-055", "error", known_path, "", &e.to_string());
            }
        }
    }
    out.set("treeSize", Value::Int(i128::from(head.size())));
    out.set("rootHash", Value::Text(hex(head.root().as_bytes())));
    out.set("records", Value::Int(proofs.len() as i128));
    out.set("verified", Value::Bool(ok));
    if ok {
        out.lines.push(msg("log-verified", &[("file", file), ("size", &head.size().to_string())]));
    }
    Ok(())
}

/// `log key --key-file <file> [--generate]` (CLI §5 `log`): the self-hosted log's signing key
/// file (`fieldseal-translog` reads the same file) and its public key, which a trust bundle
/// pins with `trust bundle --log <origin>=<key>` (TRU-093). `--generate` creates the file
/// once, from the operating system's randomness, if it doesn't exist; an existing key is never
/// replaced. Development convenience: a production log key lives in an HSM.
pub fn key(args: &crate::args::Args, out: &mut crate::outcome::Outcome) -> crate::support::Res {
    use crate::support::{fail, hex, unhex};
    use fieldseal_kernel::sign::SigningKey;
    use fieldseal_trust::ports::RandomSource;
    let path = std::path::PathBuf::from(args.required("log key", "--key-file")?);
    if !path.exists() {
        if !args.has("--generate") {
            fail(out, crate::outcome::exit::NOT_FOUND, "not-found", &[("file", &path.to_string_lossy()), ("reason", "no such key file (use --generate to create it)")]);
            return Ok(());
        }
        let scalar = loop {
            let mut b = [0u8; 32];
            crate::custody::OsRandom.fill(&mut b);
            if SigningKey::from_scalar(&b).is_ok() {
                break b;
            }
        };
        // Readable by the log service's own user, which is not always the one that generated it.
        if !crate::support::write(&path, format!("{}\n", hex(&scalar)).as_bytes(), false, out) {
            return Ok(());
        }
    }
    let text = std::fs::read_to_string(&path).map_err(|e| crate::support::usage("not-found", &[("file", &path.to_string_lossy()), ("reason", &e.to_string())]))?;
    let Some(key) = unhex(text.trim()).and_then(|b| SigningKey::from_scalar(&b).ok()) else {
        fail(out, crate::outcome::exit::FAILED, "not-found", &[("file", &path.to_string_lossy()), ("reason", "not 64 hexadecimal digits of a valid P-256 scalar")]);
        return Ok(());
    };
    let public = hex(key.public_key().as_bytes());
    out.lines.push(format!("public_key={public}"));
    out.set("publicKey", fieldseal_kernel::Value::Text(public));
    out.set("keyFile", fieldseal_kernel::Value::Text(path.to_string_lossy().into_owned()));
    Ok(())
}
