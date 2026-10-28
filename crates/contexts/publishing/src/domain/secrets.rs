//! The secrets check every artefact passes before review (PUB-004): recognisable key
//! material and credentials are refused. Embedded rosters are kind-specific and are the
//! kind validator's to find.
//!
//! The check reads the canonical bytes as text (lossily) and looks for well-known markers
//! only, so it has no false positives on ordinary prose; it is a floor, not a scanner.

use super::error::Diagnostic;

const MARKERS: &[(&str, &str)] = &[
    ("PRIVATE KEY-----", "a PEM private key"),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "a PGP private key"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "an OpenSSH private key"),
    ("PuTTY-User-Key-File-", "a PuTTY private key"),
    ("xoxb-", "a Slack bot token"),
    ("xoxp-", "a Slack user token"),
];

fn token_after(text: &str, prefix: &str, len: usize, allowed: impl Fn(u8) -> bool) -> bool {
    text.match_indices(prefix).any(|(i, _)| {
        let rest = &text.as_bytes()[i + prefix.len()..];
        rest.len() >= len && rest[..len].iter().all(|&b| allowed(b))
    })
}

/// Findings for any recognisable secret in `canonical`; empty if none. Every finding
/// blocks. Messages never quote the secret.
pub fn find_secrets(canonical: &[u8]) -> Vec<Diagnostic> {
    let text = String::from_utf8_lossy(canonical);
    let mut out: Vec<Diagnostic> = MARKERS
        .iter()
        .filter(|(marker, _)| text.contains(marker))
        .map(|(_, what)| Diagnostic { code: "PUB-004".into(), message: format!("contains {what}"), blocking: true })
        .collect();
    let upper_or_digit = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    if token_after(&text, "AKIA", 16, upper_or_digit) || token_after(&text, "ASIA", 16, upper_or_digit) {
        out.push(Diagnostic { code: "PUB-004".into(), message: "contains an AWS access key ID".into(), blocking: true });
    }
    for prefix in ["ghp_", "gho_", "ghs_", "ghu_", "github_pat_"] {
        if token_after(&text, prefix, 36, |b| b.is_ascii_alphanumeric() || b == b'_') {
            out.push(Diagnostic { code: "PUB-004".into(), message: "contains a GitHub token".into(), blocking: true });
            break;
        }
    }
    out
}
