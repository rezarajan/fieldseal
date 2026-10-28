//! Helpers for the command-family tests: a scratch directory per test, running the binary
//! with a clean `FIELDSEAL_*` environment, reading its one `--json` document, and building a
//! small authority (root, keys, certificates, trust bundle) with the commands themselves.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fieldseal_adapters_authoring::{Format, decode};
use fieldseal_kernel::Value;

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A scratch directory and the environment commands run in.
pub struct Sandbox {
    pub dir: PathBuf,
    pub env: Vec<(String, String)>,
}

impl Sandbox {
    /// A fresh, empty directory named for the test.
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fieldseal-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self { dir, env: Vec::new() }
    }

    pub fn path(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }

    pub fn write(&self, name: &str, content: &str) -> String {
        let p = self.dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    pub fn set_env(&mut self, key: &str, value: &str) {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.into(), value.into()));
    }

    /// Runs `fieldseal args…` in the scratch directory with `extra` environment variables.
    pub fn run_with(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_fieldseal"));
        c.args(args).current_dir(&self.dir);
        for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("FIELDSEAL_")) {
            c.env_remove(k);
        }
        for (k, v) in self.env.iter() {
            c.env(k, v);
        }
        for (k, v) in extra {
            c.env(k, v);
        }
        c.output().expect("fieldseal runs")
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    /// Runs with `--json`; checks stdout is exactly one outcome document (CLI-003) and returns
    /// the exit code and the document.
    pub fn json_with(&self, args: &[&str], extra: &[(&str, &str)]) -> (i32, Value) {
        let mut all = args.to_vec();
        all.push("--json");
        let o = self.run_with(&all, extra);
        let code = o.status.code().expect("exit code");
        let doc = decode(&o.stdout, Format::Json)
            .unwrap_or_else(|e| panic!("{args:?}: stdout is not one JSON document: {e}\n{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)));
        let m = doc.as_map().expect("an object");
        assert_eq!(m.get("exitCode").and_then(Value::as_int), Some(i128::from(code)), "{args:?}");
        assert_eq!(m.get("ok").and_then(Value::as_bool), Some(code == 0), "{args:?}");
        assert!(m.get("command").and_then(Value::as_text).is_some());
        assert!(m.get("findings").and_then(Value::as_array).is_some());
        (code, doc)
    }

    pub fn json(&self, args: &[&str]) -> (i32, Value) {
        self.json_with(args, &[])
    }

    /// Runs and requires exit 0.
    pub fn ok(&self, args: &[&str], extra: &[(&str, &str)]) -> Value {
        let (code, doc) = self.json_with(args, extra);
        assert_eq!(code, 0, "{args:?}: {doc:?}");
        doc
    }
}

pub fn field<'a>(doc: &'a Value, key: &str) -> &'a Value {
    doc.as_map().and_then(|m| m.get(key)).unwrap_or_else(|| panic!("no `{key}` in {doc:?}"))
}

pub fn text(doc: &Value, key: &str) -> String {
    field(doc, key).as_text().unwrap_or_else(|| panic!("`{key}` is not text")).to_owned()
}

pub fn finding_ids(doc: &Value) -> Vec<String> {
    field(doc, "findings").as_array().unwrap().iter().map(|f| f.as_map().unwrap()["id"].as_text().unwrap().to_owned()).collect()
}

const CEREMONY: &str = "authority: example-authority
threshold: 2-of-3
custodians: [custodian-a, custodian-b, custodian-c]
witnesses: [witness-1]
held: 2026-01-15T08:00:00Z
validity: 3650d
";

/// The commands' time for issuing certificates.
pub const ISSUED: &str = "2026-01-16";

/// Creates the offline root in `root/`.
pub fn root_init(sb: &Sandbox) {
    sb.write("ceremony.yaml", CEREMONY);
    sb.ok(&["trust", "root-init", "--ceremony", "ceremony.yaml", "--out", "root"], &[]);
}

/// Generates a key for `purpose` in the custody `dir` and certifies it under the root:
/// `certs/<name>.crt`. Returns the key's ID.
pub fn certify(sb: &Sandbox, dir: &str, purpose: &str, name: &str, extra: &[&str]) -> String {
    let csr = format!("csr/{name}.csr");
    let g = sb.ok(&["keys", "generate", "--purpose", purpose, "--custody", dir, "--csr", &csr], &[]);
    let mut args = vec!["trust", "issue", "--purpose", purpose, "--csr", &csr, "--out", "certs", "--at", ISSUED];
    if purpose != "record" {
        // Publisher keys may live 2 years, every other purpose 1 (TRU §6.1).
        args.extend(["--validity", if purpose == "publisher" { "730d" } else { "365d" }]);
    }
    args.extend(extra);
    sb.ok(&args, &[("FIELDSEAL_SIGNER", "soft:root")]);
    text(&g, "keyId")
}

/// A root, three publisher keys (`pub-alice|bob|carol`), a builder key and a trust bundle
/// `trust-bundle.bundle` pinning the local log.
pub fn publishing_authority(sb: &Sandbox) -> Vec<String> {
    root_init(sb);
    let ids: Vec<String> = ["alice", "bob", "carol"].iter().map(|p| certify(sb, &format!("pub-{p}"), "publisher", &format!("publisher-{p}"), &[])).collect();
    certify(sb, "builder", "builder", "builder", &[]);
    sb.ok(
        &["trust", "bundle", "--roots", "root/root.crt", "--pins", "certs", "--log-origin", "fieldseal-local-log", "--out", "trust-bundle.bundle", "--at", ISSUED],
        &[("FIELDSEAL_SIGNER", "soft:root")],
    );
    ids
}

/// The publishing policy of docs/how-to/set-up-publishing-signatures.md §2.
pub const PUBLISHING_POLICY: &str = r#"apiVersion: fieldseal.dev/v1alpha1
kind: Policy
metadata: { name: authority-publishing, version: 1.0.0 }
spec:
  schemaVersion: 1.0.0
  layer: { scope: deployment }
  publishing:
    requiredApprovals: { Instrument: 2, Policy: 2, TrustBundle: 2, Deployment: 2 }
    authorMayApprove: false
    publisherThreshold: { m: 2, n: 3 }
    allowedBuilders: [ "https://ci.example.org/builders/fieldseal-publish" ]
    allowedSources: [ "https://git.example.org/authority/artefacts" ]
    requireTransparencyLog: true
"#;
