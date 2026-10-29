//! The Publishing page (WEB-140, WEB-141): the transparency log's checkpoint and entries and
//! one section per published artefact. The page reads the log (`FIELDSEAL_LOG_URL`) and the
//! published files on the server, and verifies every verdict here, with the publishing
//! context against the stack's trust bundle and the publishing policy, never on the log's own
//! word. Without a trust bundle it shows what the log says and says what is not verified.

use std::collections::BTreeSet;
use std::time::Duration;

use fieldseal_adapters_translog::{HttpLogTransport, HttpTranslog, decode_checkpoint, decode_inclusion};
use fieldseal_kernel::crypto::tags;
use fieldseal_kernel::digest::lower_hex;
use fieldseal_policy::domain::{Controls, PublishingPolicy};
use fieldseal_publishing::application::VerifyPublication;
use fieldseal_publishing::domain::merkle::{leaf_hash, verify_inclusion};
use fieldseal_publishing::domain::{Publication, SignedCheckpoint};
use fieldseal_publishing::ports::{LogRequest, LogTransport, Transmission};
use fieldseal_trust::domain::{TrustBundle, TrustStore};

use crate::http::{Request, Response};
use crate::reports::{BuildReport, CheckpointReport, InclusionReport, PublicationReport, ReviewerReport, SignatureReport, ThresholdReport};
use crate::state::AppState;
use crate::ui::{self, escape};

/// How long the page waits for the log.
const LOG_TIMEOUT: Duration = Duration::from_secs(10);

/// The most log entries the page lists: the newest (the log serves at most this many a call).
const ENTRIES_SHOWN: u64 = 256;

/// Handles the routes of this page.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    if req.method != "GET" || req.path != "/publishing" {
        return None;
    }
    let body = match &state.log_url {
        Some(url) => log_body(state, url),
        None => format!("{}<p>No transparency log is configured: set FIELDSEAL_LOG_URL.</p>", head("")),
    };
    Some(ui::page("Publishing", "/publishing", &body, &[]))
}

/// The page head: the title and the one filled action, a refresh of this snapshot.
fn head(lede: &str) -> String {
    let lede = if lede.is_empty() { String::new() } else { format!("\n<p class=\"lede\">{lede}</p>") };
    format!("<div class=\"page-head\"><div><h1>Publishing</h1>{lede}</div>\n<div class=\"head-actions\"><a class=\"btn btn-primary\" href=\"/publishing\">Refresh</a></div></div>\n")
}

fn verdict(ok: bool) -> String {
    if ok { "<span class=\"ok\">yes</span>".into() } else { "<span class=\"bad\">NO</span>".into() }
}

fn short(hex: &str) -> String {
    format!("<code class=\"hash\" title=\"{0}\">{0}</code>", escape(hex))
}

/// The trust bundle of the stack, when the app runs as a service of it. `Ok(None)` outside
/// stack mode, where the app holds none.
fn trust_bundle(state: &AppState) -> Result<Option<TrustBundle>, String> {
    if !state.stack {
        return Ok(None);
    }
    let path = state.authority().join("trust-bundle.bundle");
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    TrustBundle::decode(&bytes).map(Some).map_err(|e| format!("{}: {e}", path.display()))
}

/// The publishing policy the device accepts: the defaults with the allow-lists of the stack.
fn policy(state: &AppState) -> PublishingPolicy {
    let mut p = Controls::defaults().publishing();
    p.allowed_builders.clone_from(&state.allowed_builders);
    p.allowed_sources.clone_from(&state.allowed_sources);
    p
}

/// What the log answers now: its latest checkpoint and the way to ask it more.
struct Live {
    transport: HttpLogTransport,
    checkpoint: SignedCheckpoint,
}

impl Live {
    fn read(url: &str) -> Result<Self, String> {
        let transport = HttpLogTransport::with_timeout(url, LOG_TIMEOUT).map_err(|e| e.to_string())?;
        let bytes = transport.send(&Transmission { request: LogRequest::Checkpoint, fields: Vec::new() }).map_err(|e| e.to_string())?;
        let checkpoint = decode_checkpoint(&bytes).map_err(|e| e.to_string())?;
        Ok(Self { transport, checkpoint })
    }

    /// Whether the log proves, now, that the leaf is in the tree of its latest checkpoint.
    fn holds(&self, leaf_index: u64, leaf: &fieldseal_kernel::id::Digest) -> Option<bool> {
        let size = self.checkpoint.size();
        let bytes = self.transport.send(&Transmission { request: LogRequest::Inclusion { leaf_index, tree_size: size }, fields: Vec::new() }).ok()?;
        let proof = decode_inclusion(&bytes).ok()?;
        Some(proof.leaf_index == leaf_index && proof.tree_size == size && verify_inclusion(leaf, &proof, self.checkpoint.root()))
    }
}

/// The publications on the server's disk: the CLI's registry (`*.publication`) and, in stack
/// mode, the published directory (`*.published`), each artefact once. Files that cannot be
/// read are named separately.
fn publications(state: &AppState) -> (Vec<Publication>, Vec<String>) {
    let mut dirs: Vec<(std::path::PathBuf, &str)> = Vec::new();
    if let Some(dir) = &state.registry_dir {
        dirs.push((dir.clone(), "publication"));
    }
    if state.stack {
        dirs.push((state.published(), "published"));
    }
    let (mut found, mut unreadable, mut seen) = (Vec::new(), Vec::new(), BTreeSet::new());
    for (dir, extension) in dirs {
        let mut files: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == extension)).collect();
        files.sort();
        for path in files {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            match std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| Publication::decode(&b).map_err(|e| e.to_string())) {
                Ok(p) => {
                    if seen.insert(p.address().to_text()) {
                        found.push(p);
                    }
                }
                Err(_) => unreadable.push(name),
            }
        }
    }
    found.sort_by_key(|p| (p.log.first().map(|l| l.inclusion.leaf_index), p.artefact.name().to_owned()));
    (found, unreadable)
}

/// The published artefacts as the Publishing page verifies them, for the guided demo: each
/// report is made in the server by the publishing context against the trust bundle, and the log
/// is asked for its inclusion proofs now. `log_size` is the size of the log's latest checkpoint
/// when it verifies against the log key the bundle pins.
pub struct Verified {
    /// The size of the log's latest checkpoint, if the log answers and the checkpoint verifies.
    pub log_size: Option<u64>,
    /// One report for each published artefact.
    pub reports: Vec<PublicationReport>,
}

/// Verifies the published artefacts like the Publishing page does. An error says what could not be
/// read: no log, no trust bundle (outside the stack) or an unreadable bundle.
pub fn verified(state: &AppState) -> Result<Verified, String> {
    let url = state.log_url.as_deref().ok_or("no transparency log is configured: set FIELDSEAL_LOG_URL")?;
    let bundle = trust_bundle(state)?.ok_or("this app holds no trust bundle, so nothing can be verified")?;
    let live = Live::read(url);
    let (found, _) = publications(state);
    let policy = policy(state);
    let reports = found.iter().map(|p| publication_report(&bundle, &policy, p, live.as_ref().ok())).collect();
    let log_size = live.ok().filter(|l| l.checkpoint.verify(&bundle.contents().logs, 0).is_ok()).map(|l| l.checkpoint.size());
    Ok(Verified { log_size, reports })
}

fn log_body(state: &AppState, url: &str) -> String {
    let bundle = trust_bundle(state);
    let live = Live::read(url);
    let (found, unreadable) = publications(state);
    let mut out = match &bundle {
        Ok(Some(_)) => head("Verified here, in the server, by the real publishing context against the stack's trust bundle and publishing policy. Nothing below is taken on the log's word. Development keys."),
        _ => head(""),
    };
    out.push_str(&format!("<p>Transparency log: <code>{}</code></p>\n", escape(url)));
    match &bundle {
        Err(e) => out.push_str(&format!("<p class=\"error\">The trust bundle could not be read, so nothing is verified: {}</p>\n", escape(e))),
        Ok(None) => out.push_str("<p class=\"note\"><strong>Not verified.</strong> This app holds no trust bundle for that log (it is not running as a service of the stack), so it cannot check signatures, thresholds or inclusion proofs. What is shown is only what the log and the files say about themselves.</p>\n"),
        Ok(Some(_)) => {}
    }
    let trusted = bundle.as_ref().ok().and_then(Option::as_ref);
    match &live {
        Ok(l) => out.push_str(&checkpoint_section(trusted, &l.checkpoint)),
        Err(e) => out.push_str(&format!("<p class=\"error\">The log could not be read at {}/checkpoint: {}</p>\n", escape(url.trim_end_matches('/')), escape(e))),
    }
    out.push_str(&surveys_section(state));
    out.push_str("<section id=\"artefacts\">\n<h2>Published artefacts</h2>\n");
    if found.is_empty() && unreadable.is_empty() {
        out.push_str("<p>No artefact has been published yet. <code>just publish &lt;survey&gt;</code> publishes one.</p>\n");
    }
    let policy = policy(state);
    out.push_str("<div class=\"stack\">\n");
    for p in &found {
        match trusted {
            Some(b) => out.push_str(&publication_section(&publication_report(b, &policy, p, live.as_ref().ok()))),
            None => out.push_str(&unverified_row(p)),
        }
    }
    out.push_str("</div>\n");
    for name in &unreadable {
        out.push_str(&format!("<p class=\"bad\">{} is unreadable</p>\n", escape(name)));
    }
    out.push_str("</section>\n");
    if let Ok(l) = &live {
        out.push_str(&entries_section(url, l, &found));
    }
    out.push_str("<p class=\"note\">This page is a snapshot; reload to refresh.</p>\n");
    out
}

/// The latest checkpoint, with whether it verifies against the log key the bundle pins.
fn checkpoint_section(bundle: Option<&TrustBundle>, c: &SignedCheckpoint) -> String {
    let verified = match bundle {
        Some(b) => verdict(c.verify(&b.contents().logs, 0).is_ok()),
        None => "<span class=\"muted\">not checked: no trust bundle</span>".to_owned(),
    };
    format!(
        "<section id=\"checkpoint\" class=\"card\">\n<h2>Log checkpoint</h2>\n<dl class=\"facts\">\n<div><dt>Origin</dt><dd>{}</dd></div>\n<div><dt>Size</dt><dd>{}</dd></div>\n<div><dt>Root hash</dt><dd>{}</dd></div>\n<div><dt>Signature verified against the pinned log key</dt><dd>{verified}</dd></div>\n</dl>\n</section>\n",
        escape(c.origin()),
        c.size(),
        short(&lower_hex(c.root().as_bytes()))
    )
}

/// The surveys the log vouches for (`stack::surveys`): the ones the device's bundle may name.
fn surveys_section(state: &AppState) -> String {
    if !state.stack {
        return String::new();
    }
    let names = crate::stack::surveys(state);
    if names.is_empty() {
        return "<p id=\"surveys\">The log vouches for no survey yet.</p>\n".to_owned();
    }
    let list: Vec<String> = names.iter().map(|n| format!("<code>{}</code>", escape(n))).collect();
    format!("<p id=\"surveys\">The log vouches for these surveys: {}.</p>\n", list.join(", "))
}

/// A publication the app cannot verify: what its own file says.
fn unverified_row(p: &Publication) -> String {
    let index = p.log.first().map_or_else(|| "none".to_owned(), |l| l.inclusion.leaf_index.to_string());
    format!(
        "<div class=\"card\"><span class=\"kind\">{}</span> <strong>{} {}</strong> {} <span class=\"muted\">log index {index}, not verified</span></div>\n",
        escape(p.artefact.kind().as_str()),
        escape(p.artefact.name()),
        escape(p.artefact.version()),
        short(&p.address().to_text())
    )
}

/// The log's newest entries, read with `GET /entries/{from}/{to}`. An entry holds digests, not
/// names (WIRE-191), so a name appears when a publication on disk has a record at that index.
fn entries_section(url: &str, live: &Live, found: &[Publication]) -> String {
    let size = live.checkpoint.size();
    let from = size.saturating_sub(ENTRIES_SHOWN);
    let transport = match HttpLogTransport::with_timeout(url, LOG_TIMEOUT) {
        Ok(t) => t,
        Err(e) => return format!("<p class=\"error\">The log's entries could not be read: {}</p>\n", escape(&e.to_string())),
    };
    let entries = match HttpTranslog::new(transport).entries(from, size) {
        Ok(e) => e,
        Err(e) => return format!("<p class=\"error\">The log's entries could not be read: {}</p>\n", escape(&e.to_string())),
    };
    let named = |index: u64| {
        found.iter().find(|p| p.log.iter().any(|l| l.inclusion.leaf_index == index)).map_or_else(String::new, |p| format!("{} {}", escape(p.artefact.name()), escape(p.artefact.version())))
    };
    let mut out = format!(
        "<details id=\"entries\" class=\"card disclosure\">\n<summary>Log entries ({size})</summary>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Index</th><th>Kind</th><th>Artefact</th><th>Statement digest</th><th>Signer key</th></tr>\n"
    );
    for (offset, e) in entries.iter().enumerate() {
        let index = from + offset as u64;
        out.push_str(&format!(
            "<tr><td>{index}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape(e.entry_type().as_str()),
            named(index),
            short(&lower_hex(e.digest().as_bytes())),
            short(&lower_hex(e.key_id().as_bytes()))
        ));
    }
    out.push_str("</table></div>\n</details>\n");
    out
}

/// Verifies `p` against the bundle and the policy and describes it. `live` is the log as it
/// answers now: with it, each inclusion proof is also asked of the log.
fn publication_report(bundle: &TrustBundle, policy: &PublishingPolicy, p: &Publication, live: Option<&Live>) -> PublicationReport {
    let verifier = VerifyPublication::new(TrustStore::new(bundle), policy);
    let verified = verifier.verify(p, &[]).map(|_| ()).map_err(|e| e.to_string());
    let statement = p.provenance.statement();
    let store = TrustStore::new(bundle);
    let kind = p.artefact.kind();
    let signatures: Vec<SignatureReport> = p
        .signatures
        .iter()
        .map(|s| {
            let certificate = bundle.certificates_for(&s.signer).next().map(|c| format!("{:?} certificate, serial {}", c.role(), c.serial()));
            let valid = store.verify_signature(&s.signer, &[], &tags::ARTEFACT, &p.signed_structure(), &s.sig, statement.finished).is_ok();
            SignatureReport { key_id: lower_hex(s.signer.as_bytes()), signer_certificate: certificate, valid }
        })
        .collect();
    let required = policy.kinds.get(kind.as_str()).map_or(1, |k| k.publisher_threshold.m.max(1));
    let threshold = ThresholdReport { required, available: bundle.publishers_for(kind.as_str()).len() as u64, valid_signatures: signatures.iter().filter(|s| s.valid).count() as u64 };
    let reviewers = statement.reviewers.iter().map(|r| ReviewerReport { id: r.as_str().to_owned(), decision: "approve".into() }).collect();
    let log_entries = p
        .log
        .iter()
        .map(|r| {
            let leaf = leaf_hash(&r.leaf.leaf(&r.entry));
            InclusionReport {
                log_origin: p.checkpoint.origin().to_owned(),
                signer_key_id: lower_hex(r.entry.key_id().as_bytes()),
                leaf_index: r.inclusion.leaf_index,
                leaf_hash: lower_hex(leaf.as_bytes()),
                tree_size: r.inclusion.tree_size,
                root_hash: lower_hex(p.checkpoint.root().as_bytes()),
                verified: r.inclusion.tree_size == p.checkpoint.size() && verify_inclusion(&leaf, &r.inclusion, p.checkpoint.root()),
                held_by_log: live.and_then(|l| l.holds(r.inclusion.leaf_index, &leaf)),
            }
        })
        .collect();
    PublicationReport {
        kind: kind.as_str().to_owned(),
        name: p.artefact.name().to_owned(),
        version: p.artefact.version().to_owned(),
        address: lower_hex(p.address().as_bytes()),
        verified,
        signatures,
        threshold,
        reviewers,
        log_entries,
        build: BuildReport {
            builder: statement.builder.0.clone(),
            source: statement.source.uri.clone(),
            revision: statement.source.revision.0.clone(),
            finished_ms: statement.finished.0,
        },
        checkpoint: CheckpointReport {
            origin: p.checkpoint.origin().to_owned(),
            size: p.checkpoint.size(),
            root_hash: lower_hex(p.checkpoint.root().as_bytes()),
            signature_verified: p.checkpoint.verify(&bundle.contents().logs, 0).is_ok(),
        },
    }
}

fn publication_section(p: &PublicationReport) -> String {
    let overall = match &p.verified {
        Ok(()) => "<span class=\"ok\">verified</span>".to_owned(),
        Err(e) => format!("<span class=\"bad\">not verified: {}</span>", escape(e)),
    };
    let mut s = format!(
        "<details class=\"publication card disclosure\">\n<summary><span class=\"kind\">{}</span> <strong>{} {}</strong> <span class=\"verdict\">{}</span></summary>\n<table>\n<tr><th>Kind</th><td>{}</td></tr>\n<tr><th>Content address</th><td>{}</td></tr>\n<tr><th>Verdict</th><td>{}</td></tr>\n",
        escape(&p.kind),
        escape(&p.name),
        escape(&p.version),
        overall,
        escape(&p.kind),
        short(&p.address),
        overall
    );
    s.push_str(&format!(
        "<tr><th>Signature threshold</th><td>{} of {} publishers required; {} valid signatures</td></tr>\n</table>\n",
        p.threshold.required, p.threshold.available, p.threshold.valid_signatures
    ));
    s.push_str("<h3>Signatures</h3>\n<table>\n<tr><th>Signer key</th><th>Certificate</th><th>Valid</th></tr>\n");
    for g in &p.signatures {
        s.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n", short(&g.key_id), escape(g.signer_certificate.as_deref().unwrap_or("none in the trust bundle")), verdict(g.valid)));
    }
    s.push_str("</table>\n<h3>Reviewers</h3>\n<table>\n<tr><th>Reviewer</th><th>Decision</th></tr>\n");
    for r in &p.reviewers {
        s.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", escape(&r.id), escape(&r.decision)));
    }
    s.push_str("</table>\n<h3>Log inclusion proofs</h3>\n<div class=\"scroll\" tabindex=\"0\" role=\"region\" aria-label=\"Table, scrolls sideways\"><table>\n<tr><th>Leaf index</th><th>Tree size</th><th>Root</th><th>Leaf hash</th><th>Verified</th><th>In the log now</th></tr>\n");
    for l in &p.log_entries {
        let now = l.held_by_log.map_or_else(|| "<span class=\"muted\">not asked</span>".to_owned(), verdict);
        s.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{now}</td></tr>\n", l.leaf_index, l.tree_size, short(&l.root_hash), short(&l.leaf_hash), verdict(l.verified)));
    }
    s.push_str(&format!(
        "</table></div>\n<h3>Provenance</h3>\n<table>\n<tr><th>Builder</th><td>{}</td></tr>\n<tr><th>Source</th><td>{}</td></tr>\n<tr><th>Revision</th><td>{}</td></tr>\n</table>\n</details>\n",
        escape(&p.build.builder),
        escape(&p.build.source),
        escape(&p.build.revision)
    ));
    s
}
