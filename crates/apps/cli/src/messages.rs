//! The CLI's own messages (CLI-011b): one catalogue, keyed by stable message IDs, each a
//! MessageFormat 2 simple message whose only placeholders are `{$name}` variables.
//!
//! Only English exists so far. Machine-readable output (`--json`) never uses this catalogue:
//! it carries IDs, codes and values only, so it is the same in every locale. Findings keep the
//! message text the contexts give them.

/// The catalogue: message ID → English MessageFormat 2 message.
const EN: &[(&str, &str)] = &[
    ("usage", "usage: fieldseal <noun> <verb> [arguments] [--json]\n\ncommands:\n  instrument validate <file>\n  instrument lint <file>\n  instrument compile <file>\n  instrument hash <file> [--salt <hex32>]\n  instrument preview <file> [--layout <file>]... [--lang <tag>]... [--window compact|medium|expanded]\n                     [--answers <file>] [--roster <file>] [--format html|plan] [-o <out>]\n  layout validate <file> --instrument <file> [--salt <hex32>]\n  layout lint <file> --instrument <file> [--policy <file>] [--salt <hex32>]\n  layout compile [<file>] --instrument <file> [--lang <tag>]... [--window <class>] [--salt <hex32>]\n  instrument i18n extract <file> [--lang <tag>]... [--out <dir>]\n  instrument i18n merge <file> <xlf>... [--out <file>]\n  localisation validate <file> --reference <file>\n  policy validate <file>...\n  policy evaluate --decision <name> --input <json> [<file>...]\n  policy diff <a> <b>\n  policy effective [<file>...]\n  trust root-init --ceremony <file> --out <dir>\n  trust issue --purpose <p> --validity <d> --csr <file> --out <dir> [--period <id> --period-start <t> --period-end <t> --retention <d>]\n  trust bundle --roots <f> --pins <f> [--attestation-roots <d>] [--runtime-builds <f>] --out <file>\n  trust verify <cert>... [--trust-bundle <file>]\n  trust revoke <cert> --reason <r> [--effective <t>]\n  keys generate --purpose <p> --csr <file> [--algorithm p256|x25519]\n  keys generate --purpose sign|agree [--out <file>]\n  keys roll <handle> [--sign-key <handle>] [--out <file>]\n  artefact provenance <file> --source <rev> --reviewers <id[:lang+lang]>,... [--instrument <file> (Layout)]\n  artefact sign|verify <file>\n  artefact publish <file> (--time-token <file> | --custody <dir> with a receipt key)\n  artefact withdraw <address> --reason <text>\n  log prove <address>\n  log append <entry>\n  log verify <proof> [--known-tree-head <file>]\n  log key --key-file <file> [--generate]\n  registry list|show|fetch [<address>] --dir <published> --trust-bundle <file> [--log-url <url>]\n  trust show --trust-bundle <file> [--custody <dir>]\n  receipt issue --tenancy <hex> --last-seq <n> --journal-hash <hex> [--of <hex>] [--out <file>] [--qr <svg>]\n  receipt verify <file> [--tenancy <hex>] [--journal-hash <hex>]\n  bundle build|inspect|verify|open (open: <file> --key <handle> --trust <file> [--reveal --out <file>])\n  registration token --account <id> [--batch N]\n  registration request --token <t> [--device-dir <dir>]\n  registration submit <request> [--factory-url <url>]\n  registration status|wait [<tenancy>] [--factory-url <url>] [--device-dir <dir>] [--timeout <s>]\n  registration inspect|approve <request>\n  device simulate --script <file>\n  device export --device-dir <dir> --trust-bundle <file> --out <file>\n  intake run|replay [--reveal]|contract\n  export build|inspect|verify|repair\n  export upload <file> --to <url> --trust-bundle <file> [--receipts-dir <dir>]\n  deployment validate|render|release\n  docs build\n  conformance run|list|matrix [--suite <name>]\n  adapters\n\nsigner: --custody <dir> or FIELDSEAL_SIGNER=soft:<dir> (development custody; production uses an HSM adapter)\nexit codes: 0 success, 1 validation failed, 2 usage, 3 configuration, 4 not found, 5 policy denied, 6 internal"),
    ("transport-not-built", "fieldseal: {$url}: `{$scheme}://` is not built into this binary yet (ADR 0035); use an http:// or https:// address"),
    ("bad-scheme", "fieldseal: {$url}: expected an http(s):// address (or grpc(s)://, which is not built yet)"),
    ("service-unreachable", "fieldseal: {$url}: {$reason}"),
    ("service-refused", "fieldseal: {$url} refused it: HTTP {$status} {$code}"),
    ("service-malformed", "fieldseal: {$url} answered something unexpected: {$reason}"),
    ("no-intake-url", "fieldseal: no upload address: give `--to <url>` or set FIELDSEAL_INTAKE_URL"),
    ("registration-submitted", "submitted {$file} to {$url}: tenancy {$tenancy} is {$state}; fingerprint words: {$words}"),
    ("registration-state", "tenancy {$tenancy}: {$state}"),
    ("registration-waited", "tenancy {$tenancy} is {$state}; certificate saved in {$file}"),
    ("registration-timeout", "fieldseal: tenancy {$tenancy} is still {$state} after {$seconds} s"),
    ("registration-ended", "fieldseal: tenancy {$tenancy} is {$state}; it will not become registered"),
    ("bad-tenancy", "fieldseal: `{$value}`: expected a tenancy of 64 hexadecimal digits"),
    ("device-dir-new", "device keys created in {$dir} (software keys, unattested: CLI-007)"),
    ("device-not-registered", "fieldseal: {$dir}: no registered device: run `registration request --device-dir` and `registration wait --device-dir` first"),
    ("device-exported", "wrote {$file}: export of tenancy {$tenancy} with {$records} records, sealed to the record key {$period}"),
    ("export-uploaded", "uploaded {$file} to {$url}: {$count} receipt(s), all verified, stored in {$dir}"),
    ("export-no-receipts", "fieldseal: {$url} accepted the upload but returned no receipts"),
    ("export-bad-receipt", "fieldseal: receipt {$index} from {$url} does not verify: {$reason}"),
    ("log-key", "log key {$file}: public key {$key}"),
    ("fetched", "fetched {$address}, verified against the trust bundle, into {$file}"),
    ("unattested-key", "note: a software key in a file, unattested (CLI-007); it is not hardware-protected."),
    ("no-receipt-key", "fieldseal: the custody holds no single `receipt` key; give `--key <id>`"),
    ("bad-hex32", "fieldseal: `{$flag} {$value}`: expected 64 hexadecimal digits (32 bytes)"),
    ("receipt-issued", "issued a receipt for tenancy {$tenancy} through seq {$seq} in {$file}"),
    ("receipt-verified", "{$file}: receipt verified (through seq {$seq})"),
    ("log-appended", "appended at leaf {$index} (tree size {$size}); proof in {$file}"),
    ("log-verified", "{$file}: log proof verified (tree size {$size})"),
    ("publish-needs-time-token", "fieldseal: `artefact publish` needs `--time-token <file>`, or a `receipt` key in the custody (`--custody` or FIELDSEAL_SIGNER) to issue one: devices refuse a tree head with no authority time token (PUB-072)"),
    ("device-key-generated", "generated {$purpose} key {$key} in {$handle}"),
    ("key-rolled", "rolled {$old}: successor key in {$handle}, roll request in {$file}"),
    ("roll-needs-sign-key", "fieldseal: rolling an agreement key needs `--sign-key <handle>`, the current signing key that endorses it (REG-060)"),
    ("roll-sign-key-purpose", "fieldseal: {$file}: `--sign-key` must be a signing key"),
    ("unknown-command", "fieldseal: unknown command `{$command}`; run `fieldseal --help`"),
    ("unknown-flag", "fieldseal: `{$command}` doesn't take `{$flag}`"),
    ("missing-value", "fieldseal: `{$flag}` needs a value"),
    ("duplicate-flag", "fieldseal: `{$flag}` was given more than once"),
    ("flag-as-value", "fieldseal: `{$flag}` needs a value, not the flag `{$value}` (write `{$flag}={$value}` to pass it literally)"),
    ("missing-file", "fieldseal: `{$command}` needs a file"),
    ("extra-argument", "fieldseal: unexpected argument `{$argument}`"),
    ("missing-flag", "fieldseal: `{$command}` needs `{$flag}`"),
    ("bad-window", "fieldseal: `--window {$value}`: expected compact, medium or expanded"),
    ("bad-format", "fieldseal: `--format {$value}`: expected html or plan"),
    ("bad-salt", "fieldseal: `--salt`: expected 64 hexadecimal digits (32 bytes)"),
    ("bad-extension", "fieldseal: {$file}: expected a .yaml, .yml or .json file"),
    ("not-found", "fieldseal: {$file}: {$reason}"),
    ("write-failed", "fieldseal: {$file}: {$reason}"),
    ("roster-needs-output", "fieldseal: `--roster` writes roster contents into the page, so it needs `-o <file>` (CLI-008)"),
    ("not-a-map", "fieldseal: {$file}: expected a map of {$what}"),
    ("valid", "{$file}: valid"),
    ("invalid", "{$file}: invalid ({$errors} errors)"),
    ("findings", "{$file}: {$count} findings"),
    ("no-findings", "{$file}: no findings"),
    ("instrument-invalid", "{$file}: the instrument is invalid; fix it first"),
    ("policy-invalid", "{$file}: the policy is invalid"),
    ("layout-mismatch", "{$file}: the layout was validated against a different instrument"),
    ("layout-default", "no layout fits window class {$window}; using the default layout (INS-207)"),
    ("wrote", "wrote {$file} ({$nodes} plan nodes, {$language}, {$window}, layout {$layout})"),
    ("verdicts", "rules: {$hard} hard and {$soft} soft fired; {$problems} value problems; {$unanswered} unanswered"),
    ("evaluation-limit", "fieldseal: rule evaluation exceeded its bounds"),
    ("bad-time", "fieldseal: `{$value}`: expected milliseconds, an RFC 3339 UTC time or a date"),
    ("unknown-decision", "fieldseal: `--decision {$value}` is not a decision point"),
    ("bad-input", "fieldseal: `--input`: {$reason}"),
    ("decision", "{$decision}: {$verdict}"),
    ("decision-reason", "  reason: {$reason}"),
    ("engine-failed", "fieldseal: the policy engine failed: {$reason}"),
    ("diff-needs-two", "fieldseal: `policy diff` needs two policy sets (files, or layers joined with commas)"),
    ("policy-change", "{$path}: {$before} -> {$after} ({$direction})"),
    ("policy-same", "the two policy sets have the same effective controls"),
    ("no-signer", "fieldseal: no signer: give `--custody <dir>` or set FIELDSEAL_SIGNER=soft:<dir>"),
    ("unknown-signer", "fieldseal: FIELDSEAL_SIGNER `{$kind}:`: only `soft:` (development custody) is built in; production custody is an HSM adapter"),
    ("dev-custody", "note: development custody. The keys are software keys in a local directory, unattested (CLI-007). A production authority uses an HSM adapter."),
    ("no-trust-bundle", "fieldseal: no trust bundle: give `--trust-bundle <file>` or set FIELDSEAL_TRUST_BUNDLE"),
    ("no-root-in-custody", "fieldseal: no listed root is held in this custody; the offline signer must hold a root to sign a trust bundle"),
    ("encode-failed", "fieldseal: could not encode the result"),
    ("bad-ceremony", "fieldseal: {$file}: missing or invalid `{$field}`"),
    ("root-exists", "fieldseal: {$dir} already holds a root; a root is created once"),
    ("root-created", "created root {$key} in {$dir}"),
    ("unknown-purpose", "fieldseal: `{$value}` is not a key purpose"),
    ("unknown-reason", "fieldseal: `--reason {$value}`: expected compromised, superseded, holder-left or retired"),
    ("record-needs-period", "fieldseal: a record key needs `--period`, `--period-start`, `--period-end` and `--retention`"),
    ("bad-period", "fieldseal: invalid collection period: {$value}"),
    ("bad-validity", "fieldseal: `--validity {$value}`: expected a duration such as 365d"),
    ("bad-build", "fieldseal: {$file}: each runtime build needs `platform`, `appId` and `signingDigests`"),
    ("bad-log-pin", "fieldseal: `--log {$value}`: expected <origin>=<public key hex>"),
    ("bad-version", "fieldseal: `--version {$value}`: expected MAJOR.MINOR.PATCH"),
    ("issued", "issued {$purpose} certificate for {$key}: {$file}"),
    ("bundle-built", "wrote trust bundle {$file} (version {$version}, {$address})"),
    ("chain-valid", "{$file}: valid {$purpose} chain"),
    ("revoked", "revoked {$key}: {$file}"),
    ("key-generated", "generated {$purpose} key {$key}; request written to {$file}"),
    ("device-keys-not-built", "fieldseal: `keys generate --purpose {$purpose}` (device-style keys) is not built yet"),
    ("bad-address", "fieldseal: `{$value}` is not an artefact address (sha256:<64 hex> or 64 hex digits)"),
    ("bad-digest", "fieldseal: `{$value}`: expected 64 hexadecimal digits"),
    ("bad-key-id", "fieldseal: `{$value}` is not a key ID (32 hexadecimal digits)"),
    ("bad-reviewer", "fieldseal: `{$value}` is not a valid reviewer ID"),
    ("key-ambiguous", "fieldseal: the custody doesn't hold exactly one {$role} key; choose one with `--key <id>`"),
    ("no-policy", "fieldseal: no publishing policy: give `--policy <file>` or set FIELDSEAL_POLICY"),
    ("no-randomness", "fieldseal: no operating-system randomness is available; give `--salt <hex32>`"),
    ("no-source-or-builder", "fieldseal: no source or builder: give `--source-uri` and `--builder`, or list them in the publishing policy"),
    ("not-a-draft", "{$file}: expected a publication draft (from `artefact provenance`)"),
    ("unknown-kind", "fieldseal: {$file}: `kind` must be one of Instrument, Layout, Localisation, Policy, TrustBundle, Deployment, with the metadata that kind needs"),
    ("instrument-flag-layout-only", "fieldseal: `--instrument` names the instrument a Layout is validated against; it applies to a Layout artefact only"),
    ("bad-policy-list", "fieldseal: policy paths must not be empty (check `--policy` and the comma-separated `FIELDSEAL_POLICY`)"),
    ("not-an-artefact", "{$file}: expected `kind`, `metadata.name` and `metadata.version`"),
    ("provenance-written", "wrote {$file} ({$address})"),
    ("signed", "signed as {$key}: {$have} of {$need} publisher signatures"),
    ("draft-verified", "{$file}: provenance and {$have} of {$need} signatures verified"),
    ("publication-verified", "{$file}: verified ({$signers} publisher signatures, log inclusion)"),
    ("published", "published {$address}: {$file}"),
    ("already-published", "{$address} is already published; nothing logged again"),
    ("withdrawal-pending", "withdrawal has {$have} of {$need} signatures; draft written to {$file}"),
    ("withdrawn", "withdrew {$address}"),
    ("proved", "{$address} is in the log (tree size {$size}, root {$root})"),
    ("no-such-publication", "fieldseal: no publication {$address} in the registry"),
    ("no-factory-url", "fieldseal: no factory URL: give `--factory-url <https URL>` or set FIELDSEAL_FACTORY_URL"),
    ("no-registration-keys", "fieldseal: the custody holds no registration signing (P-256) and sealing (X25519) keys"),
    ("no-record-key", "fieldseal: the trust bundle certifies no single record key; give `--record-key <id>`"),
    ("no-such-token", "fieldseal: the request's token was not issued by this factory (or its state directory differs)"),
    ("bad-number", "fieldseal: `{$flag} {$value}`: expected a number"),
    ("bad-route", "fieldseal: `--route {$value}`: expected online or air-gapped"),
    ("qr-failed", "fieldseal: the token does not fit in a QR code"),
    ("token-issued", "issued a registration token for {$account} ({$uses} uses): {$file}"),
    ("request-written", "wrote {$file}; fingerprint words: {$words}"),
    ("unattested-keys", "note: the request's keys are software keys and unattested (CLI-007); production policy refuses them (CLI-013)"),
    ("request-inspected", "{$file}: fingerprint words {$words}"),
    ("tenancy-approved", "approved tenancy {$tenancy}: {$file}"),
    ("tenancy-not-approved", "the tenancy was not approved (state: {$state})"),
    ("words-not-confirmed", "fingerprint words not confirmed: pass `--words \"{$words}\"` once the collector reads them back (REG-021)"),
    ("bad-algorithm", "fieldseal: `--algorithm {$value}`: expected p256 or x25519"),
    ("no-languages", "fieldseal: {$file}: expected `spec.languages` and `spec.defaultLanguage`"),
    ("no-target-languages", "fieldseal: {$file} declares no language besides the default; give `--lang <tag>`"),
    ("merge-needs-xliff", "fieldseal: `instrument i18n merge` needs one or more .xlf files after the instrument"),
    ("xliff-written", "wrote {$file} ({$units} texts for {$lang})"),
    ("merged", "merged {$count} translations; wrote {$file}"),
    ("merge-incomplete", "{$file}: not merged; fix the findings first"),
    ("catalogue-valid", "{$file}: valid {$lang} catalogue ({$count} messages)"),
    ("decode-error", "{$file}:{$line}:{$column}: {$message}"),
];

/// The message `id` with its `{$name}` variables replaced. An unknown ID is an internal error
/// in the CLI; it is shown as the ID itself so it is noticed.
pub fn msg(id: &str, args: &[(&str, &str)]) -> String {
    let template = EN.iter().find(|(k, _)| *k == id).map_or(id, |(_, v)| *v);
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{$") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match args.iter().find(|(k, _)| *k == name) {
                    Some((_, v)) => out.push_str(v),
                    None => {
                        out.push_str("{$");
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}
