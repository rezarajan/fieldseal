//! Every decoder that reads untrusted bytes, as `(name, fn)` pairs shared by the seeded
//! property tests and the `cargo fuzz` harness under `fuzz/`.

use fieldseal_adapters_authoring::{Format, decode as authoring_decode};
use fieldseal_kernel::export::{ExportFile, repair, salvage_frames};
use fieldseal_kernel::local_record::LocalEntry;
use fieldseal_kernel::record::{Record, read_journal};
use fieldseal_kernel::seal::SealedBox;
use fieldseal_kernel::{cbor, frame, text};

/// A decoder under test: returns the re-encoding when it accepted the input.
pub type Target = (&'static str, fn(&[u8]) -> Option<Vec<u8>>);

/// All decoders under test.
pub fn targets() -> Vec<Target> {
    use fieldseal_collection::domain::local::LocalNote;
    use fieldseal_collection::domain::meta::{Marker, TenancyMeta};
    use fieldseal_collection::domain::pin::PinAttempts;
    use fieldseal_delivery::domain::{ReceiverChallenge, ReceiverProof};
    use fieldseal_distribution::domain::{BundleContent, BundleFile, TimeToken};
    use fieldseal_publishing::domain::{LogEntry, ProvenanceStatement, Publication, PublicationDraft, Withdrawal, WithdrawalDraft};
    use fieldseal_registration::domain::RegistrationToken;
    use fieldseal_registration::domain::wire::{CloseCertificate, PopToken, TenancyCertificate, decode_posture, decode_request_file};
    use fieldseal_trust::domain::{CertificateRequest, KeyCertificate, Revocation, TrustBundle};
    vec![
        ("kernel::cbor::decode", |b| cbor::decode(b).ok().map(|v| cbor::encode(&v).expect("re-encodes"))),
        ("kernel::cbor::decode_limited", |b| cbor::decode_limited(b, 1024).ok().map(|v| cbor::encode(&v).expect("re-encodes"))),
        ("kernel::frame::read_frames", |b| {
            let scan = frame::read_frames(b);
            let _ = format!("{:?}", scan.frames.len());
            None
        }),
        ("kernel::record::read_journal", |b| {
            let _ = read_journal(b, &[], &[]);
            None
        }),
        ("kernel::record::Record", |b| Record::decode(b).ok().map(|r| r.encode().expect("re-encodes"))),
        ("kernel::seal::SealedBox", |b| SealedBox::decode(b).ok().map(|s| s.encode())),
        ("kernel::local_record::LocalEntry", |b| LocalEntry::decode(b).ok().map(|e| e.encode())),
        ("kernel::export::ExportFile", |b| {
            let f = ExportFile::decode(b).ok()?;
            // Parity presence is per part, so re-encode with parity iff every part has it.
            let with = f.parts.iter().all(|p| p.parity.is_some());
            f.encode(with).ok()
        }),
        ("kernel::export::repair", |b| {
            let _ = repair(b);
            None
        }),
        ("kernel::export::salvage_frames", |b| {
            let _ = salvage_frames(b);
            None
        }),
        ("kernel::text::decode(FS1T)", |b| {
            let s = String::from_utf8_lossy(b);
            let _ = text::decode("FS1T", &s);
            let _ = text::crockford_base32_decode(&s);
            None
        }),
        ("delivery::export::verify", |b| {
            let _ = fieldseal_delivery::export::verify(b, &[]);
            None
        }),
        ("delivery::ReceiverChallenge", |b| ReceiverChallenge::decode(b).ok().map(|c| c.encode())),
        ("delivery::ReceiverProof", |b| ReceiverProof::decode(b).ok().map(|c| c.encode())),
        ("distribution::BundleFile", |b| BundleFile::decode(b, 1 << 20).ok().map(|f| f.encode())),
        ("distribution::BundleContent", |b| BundleContent::decode(b).ok().and_then(|c| c.encode().ok())),
        ("distribution::TimeToken", |b| TimeToken::decode(b).ok().map(|t| t.encode())),
        ("registration::RegistrationToken", |b| RegistrationToken::decode(b).ok().and_then(|t| t.encode().ok())),
        ("registration::RegistrationToken(text)", |b| {
            let _ = RegistrationToken::from_text(&String::from_utf8_lossy(b));
            None
        }),
        // The online route sends the bare box; a file adds `FSRQ`. Canonical either way.
        ("registration::request_file", |b| {
            let sealed = decode_request_file(b).ok()?;
            Some(if b.starts_with(b"FSRQ") { fieldseal_registration::domain::wire::encode_request_file(&sealed) } else { sealed.encode() })
        }),
        ("registration::TenancyCertificate", |b| TenancyCertificate::decode(b).ok().map(|c| c.encode())),
        ("registration::CloseCertificate", |b| CloseCertificate::decode(b).ok().and_then(|c| c.encode().ok())),
        ("registration::PopToken(bytes)", |b| PopToken::decode(b).ok().map(|t| t.encode())),
        ("registration::PopToken(text)", |b| {
            let _ = PopToken::from_header(&String::from_utf8_lossy(b));
            None
        }),
        ("registration::posture", |b| {
            let _ = decode_posture(b);
            None
        }),
        ("trust::TrustBundle", |b| TrustBundle::decode(b).ok().and_then(|t| t.encode().ok())),
        ("trust::KeyCertificate", |b| KeyCertificate::decode(b).ok().and_then(|t| t.encode().ok())),
        ("trust::CertificateRequest", |b| CertificateRequest::decode(b).ok().and_then(|t| t.encode().ok())),
        ("trust::Revocation", |b| Revocation::decode(b).ok().and_then(|t| t.encode().ok())),
        ("publishing::PublicationDraft", |b| PublicationDraft::decode(b).ok().map(|t| t.encode())),
        ("publishing::Publication", |b| Publication::decode(b).ok().map(|t| t.encode())),
        ("publishing::WithdrawalDraft", |b| WithdrawalDraft::decode(b).ok().map(|t| t.encode())),
        ("publishing::Withdrawal", |b| Withdrawal::decode(b).ok().map(|t| t.encode())),
        ("publishing::ProvenanceStatement", |b| ProvenanceStatement::decode(b).ok().map(|t| t.encode())),
        ("publishing::LogEntry", |b| LogEntry::decode(b).ok().map(|t| t.encode())),
        ("publishing::checkpoint", |b| {
            let _ = fieldseal_publishing::domain::checkpoint::SignedCheckpoint::parse(b);
            None
        }),
        ("intake::Receipt", |b| fieldseal_intake::wire::Receipt::decode(b).ok().and_then(|t| t.encode().ok())),
        ("intake::Payload", |b| {
            let _ = fieldseal_intake::wire::Payload::decode(b);
            None
        }),
        ("collection::Payload", |b| fieldseal_collection::domain::payload::Payload::decode(b).ok().and_then(|t| t.encode().ok())),
        ("collection::PinAttempts", |b| PinAttempts::decode(b).ok().map(|t| t.encode())),
        ("collection::TenancyMeta", |b| TenancyMeta::decode(b).ok().map(|t| t.encode())),
        ("collection::Marker", |b| Marker::decode(b).ok().map(|t| t.encode())),
        ("collection::LocalNote", |b| LocalNote::decode(b).ok().map(|t| t.encode())),
        ("authoring::yaml", |b| {
            let _ = authoring_decode(b, Format::Yaml);
            None
        }),
        ("authoring::json", |b| {
            let _ = authoring_decode(b, Format::Json);
            None
        }),
    ]
}

