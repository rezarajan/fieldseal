//! `fieldseal schema export|check` (CLI §5, CLI-041): the closed JSON Schema of the authoring
//! documents, the same schema the decoder checks them against, and a check of one file.

use std::path::Path;

use fieldseal_adapters_authoring::{Format, decode_with_spans};
use fieldseal_kernel::Value;
use fieldseal_kernel::digest::{lower_hex, sha256};
use fieldseal_kernel::schema::{self, DocKind};

use crate::json;
use crate::messages::msg;
use crate::outcome::Outcome;
use crate::support::{Res, read, run_command, usage, write};

/// The version of the authoring schemas.
const SCHEMA_VERSION: &str = "1.0.0";

/// Runs `schema <verb>`; `None` if the verb is not one of these.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    Some(match verb {
        "export" => run_command("schema export", raw, &["--kind", "--out", "--version"], &[], export),
        "check" => run_command("schema check", raw, &[], &[], check),
        _ => return None,
    })
}

/// The kind named by `--kind`: the authoring kinds `survey` and `layout`.
pub fn kind_of(name: &str) -> Option<DocKind> {
    [DocKind::Survey, DocKind::Layout].into_iter().find(|k| k.name() == name)
}

/// The schema of `kind` as `schema export --out` writes it: sorted keys, two-space indent and one
/// final newline. Its bytes are what the content address covers (WIRE-209, CLI-041).
pub fn schema_text(kind: DocKind) -> String {
    let mut text = json::pretty(&schema::json_schema(kind));
    text.push('\n');
    text
}

/// `sha256:` and the lowercase hexadecimal SHA-256 of exactly the bytes of `text`.
pub fn address_of(text: &str) -> String {
    format!("sha256:{}", lower_hex(sha256(text.as_bytes()).as_bytes()))
}

/// `schema export --kind survey|layout [--out <path>] [--version <v>]`.
fn export(args: &crate::args::Args, out: &mut Outcome) -> Res {
    let name = args.required("schema export", "--kind")?;
    let kind = kind_of(name).ok_or_else(|| usage("bad-kind", &[("value", name)]))?;
    if let Some(v) = args.value("--version").filter(|v| *v != SCHEMA_VERSION) {
        return Err(usage("bad-schema-version", &[("value", v), ("have", SCHEMA_VERSION)]));
    }
    let text = schema_text(kind);
    let address = address_of(&text);
    out.set("kind", Value::Text(name.to_owned()));
    out.set("address", Value::Text(address.clone()));
    match args.value("--out") {
        Some(path) => {
            if write(Path::new(path), text.as_bytes(), false, out) {
                out.lines.push(msg("schema-written", &[("file", path), ("address", &address)]));
            }
        }
        None => {
            out.set("schema", schema::json_schema(kind));
            out.body = Some(format!("{text}address: {address}\n"));
        }
    }
    Ok(())
}

/// `schema check <file>`: validates one authoring document against the schema of its kind.
fn check(args: &crate::args::Args, out: &mut Outcome) -> Res {
    let file = args.file("schema check")?;
    let Some(bytes) = read(file, out) else { return Ok(()) };
    let ext = Path::new(file).extension().and_then(|e| e.to_str()).unwrap_or("");
    let format = Format::from_extension(ext).ok_or_else(|| usage("bad-extension", &[("file", file)]))?;
    let Ok(text) = std::str::from_utf8(&bytes) else {
        out.located_finding("WIRE-211", "error", file, (1, 1), "", "the file is not valid UTF-8");
        return Ok(());
    };
    let (doc, spans) = match decode_with_spans(text, format) {
        Ok(d) => d,
        Err(e) => {
            out.located_finding("INS-002", "error", file, (e.line, e.column), "", &e.message);
            return Ok(());
        }
    };
    let Some(kind) = DocKind::detect(&doc) else {
        out.located_finding("WIRE-211", "error", file, (1, 1), "", &msg("not-authoring-document", &[]));
        return Ok(());
    };
    let errors = schema::check(&doc, kind);
    for e in &errors {
        let at = spans.nearest(&e.pointer);
        out.located_finding("WIRE-211", "error", file, (at.line, at.column), &e.pointer, &format!("{}: {}", e.kind.name(), e.message));
    }
    out.set("kind", Value::Text(kind.name().to_owned()));
    out.lines.insert(0, if errors.is_empty() { msg("schema-valid", &[("file", file), ("kind", kind.name())]) } else { msg("schema-invalid", &[("file", file), ("kind", kind.name()), ("errors", &errors.len().to_string())]) });
    Ok(())
}
