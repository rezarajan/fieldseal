//! Building the export for a landing mark, holding it in memory, and serving one file of it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fieldseal_adapters_landing_files::FileDataPlatform;
use fieldseal_adapters_landing_files::export::reader::{Published, export_table};
use fieldseal_adapters_landing_files::export::{ExportOptions, ExportTable, Format, KeyedSubject, render_export};
use fieldseal_adapters_portal::Response;
use serde_json::json;

use crate::{Held, ResultsHttp};

/// How many landing marks the reader keeps built.
pub const HELD_MARKS: usize = 4;

/// How many bytes of built exports the reader keeps in all (256 MiB): past it the oldest
/// marks are dropped, except the newest.
pub const HELD_BYTES: usize = 256 * 1024 * 1024;

/// The files of every export, by fixed name; `contracts/<fingerprint>.json` is the other kind.
const FIXED: [&str; 6] = ["results.csv", "results.jsonl", "free_text.csv", "free_text.jsonl", "codebook.csv", "manifest.json"];

/// Whether `s` is exactly 64 lower-case hex digits.
fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        Some("csv") => "text/csv; charset=utf-8",
        Some("jsonl") => "application/x-ndjson",
        _ => "application/json",
    }
}

impl ResultsHttp<'_> {
    /// The export of the landing as it stands, built once for its landing mark and then held.
    pub(crate) fn current(&self) -> Result<Arc<Held>, String> {
        let mapper = KeyedSubject::new(self.key.clone());
        let table = if self.cfg.landing_dir.join("observations.csv").exists() {
            let snapshot = FileDataPlatform::open_read_only(&self.cfg.landing_dir).map_err(|e| e.to_string())?;
            let published = Published::read(&self.cfg.published_dir, &self.cfg.trust, &self.cfg.policy).map_err(|e| e.to_string())?;
            export_table(&snapshot, &published, &mapper).map_err(|e| e.to_string())?
        } else {
            // Nothing has landed yet.
            ExportTable::from_observations(vec![], BTreeMap::new(), &mapper).map_err(|e| e.to_string())?
        };
        let mark = table.landing_mark();
        let mut held = self.held.lock().expect("lock");
        if let Some(h) = held.iter().find(|h| h.mark == mark) {
            return Ok(h.clone());
        }
        let options = ExportOptions { formats: BTreeSet::from([Format::Jsonl, Format::Csv]), subject: Box::new(mapper) };
        let export = render_export(&table, &options).map_err(|e| e.to_string())?;
        let built = Arc::new(Held { mark, export });
        held.push_back(built.clone());
        let size = |h: &Arc<Held>| h.export.files.iter().map(|(_, b)| b.len()).sum::<usize>();
        while held.len() > HELD_MARKS || (held.len() > 1 && held.iter().map(size).sum::<usize>() > self.held_bytes) {
            held.pop_front();
        }
        Ok(built)
    }

    /// `GET /results/exports/{mark}/{path}`, with `rest` being `{mark}/{path}`. Any path outside
    /// the fixed list, or a contract not in the export, is `404 not-found`; a mark that is not
    /// held is `404 unknown-mark`. Serving writes nothing to disk.
    pub(crate) fn download(&self, rest: &str) -> Response {
        let Some((mark, path)) = rest.split_once('/') else { return Response::json(404, json!({ "error": "not-found" })) };
        let mark = (!mark.is_empty() && mark.len() <= 20 && mark.bytes().all(|b| b.is_ascii_digit())).then(|| mark.parse::<u64>().ok()).flatten();
        let allowed = FIXED.contains(&path) || path.strip_prefix("contracts/").and_then(|n| n.strip_suffix(".json")).is_some_and(hex64);
        if !allowed {
            return Response::json(404, json!({ "error": "not-found" }));
        }
        let held = mark.and_then(|m| self.held.lock().expect("lock").iter().find(|h| h.mark == m).cloned());
        let Some(held) = held else {
            let current = self.current().map(|h| h.mark.to_string()).unwrap_or_default();
            return Response::json(404, json!({ "error": "unknown-mark", "current": current }));
        };
        // A contract is served only if the manifest's export has it.
        let Some((_, bytes)) = held.export.files.iter().find(|(n, _)| n == path) else { return Response::json(404, json!({ "error": "not-found" })) };
        eprintln!("{{\"event\":\"results-download\",\"mark\":{},\"file\":{:?}}}", held.mark, path);
        let base = path.rsplit('/').next().unwrap_or(path);
        Response::new(200, content_type(path), bytes.clone())
            .with("Content-Disposition", format!("attachment; filename=\"{base}\""))
            .with("X-Content-Type-Options", "nosniff".into())
            .with("Cache-Control", "no-store".into())
    }
}
