//! Signed checkpoints in the C2SP `tlog-checkpoint` signed-note format (WIRE-192), verified
//! against the log key pinned in the trust bundle (PUB-106, TRU-093), and the tree-head
//! tracking every consumer keeps (PUB-055).
//!
//! A checkpoint note is:
//!
//! ```text
//! <origin>\n
//! <tree size, decimal>\n
//! <root hash, base64>\n
//! [<extension line>\n ...]
//! \n
//! — <key name> <base64(key hash ‖ signature)>\n   (one or more)
//! ```
//!
//! The signed message is the body: everything before the blank line, including the root
//! line's newline. Log keys are ECDSA P-256 (the form Rekor uses): the 4-byte key hash is
//! the first four bytes of SHA-256 over the key's DER `SubjectPublicKeyInfo`, and the
//! signature is ASN.1 DER over the body with SHA-256. A pinned key is the 65-byte
//! uncompressed point (WIRE-009) with format [`CHECKPOINT_FORMAT`].

use fieldseal_kernel::crypto::{P256PublicKey, Signature};
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::Digest;
use fieldseal_kernel::sign::{self, SigningKey};
use fieldseal_trust::domain::LogPin;

use super::encoding::{base64_decode, base64_encode, ecdsa_der_from_raw, ecdsa_raw_from_der, normalize_s, p256_spki_der};
use super::merkle::{ConsistencyProof, verify_consistency};

/// The checkpoint format a pinned log signs (the `format` of a trust bundle's log pin).
pub const CHECKPOINT_FORMAT: &str = "c2sp-tlog-checkpoint";

/// The largest checkpoint note accepted, in bytes.
pub const MAX_NOTE: usize = 16 * 1024;

/// The most signature lines a note may carry.
pub const MAX_NOTE_SIGNATURES: usize = 32;

/// Why a checkpoint was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    /// The note is not a well-formed C2SP checkpoint (or is too large).
    #[error("malformed checkpoint: {0}")]
    Malformed(&'static str),
    /// No log is pinned for the checkpoint's origin with format [`CHECKPOINT_FORMAT`]
    /// (TRU-093).
    #[error("transparency log {0} is not pinned")]
    NotPinned(String),
    /// No signature by the pinned key verifies over the body (PUB-106).
    #[error("the checkpoint is not signed by the pinned log key")]
    BadSignature,
    /// Fewer witness cosignatures than policy requires (PUB-109). The trust bundle pins no
    /// witness keys, so any required cosignature is unverifiable and refused.
    #[error("{need} witness cosignatures required; none can be verified")]
    WitnessCosignatures {
        /// Cosignatures required by policy.
        need: u64,
    },
    /// A later tree head does not extend the latest verified one (PUB-055).
    #[error("tree heads are inconsistent: the log has forked or rewritten history")]
    Inconsistent,
    /// The log was marked untrusted after an inconsistency (PUB-055).
    #[error("this log was stopped after an inconsistency")]
    Stopped,
}

/// One signature line of a note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteSignature {
    /// The signer's key name.
    pub name: String,
    /// The first four bytes of the signer's key hash.
    pub key_hash: [u8; 4],
    /// The signature bytes (for ECDSA keys, ASN.1 DER).
    pub signature: Vec<u8>,
}

/// The signed part of a checkpoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckpointBody {
    /// The log's origin line.
    pub origin: String,
    /// The tree size.
    pub size: u64,
    /// The tree's root hash.
    pub root: Digest,
    /// Extension lines, in order, without their newlines.
    pub extensions: Vec<String>,
}

impl CheckpointBody {
    /// The exact signed text.
    pub fn text(&self) -> String {
        let mut s = format!("{}\n{}\n{}\n", self.origin, self.size, base64_encode(self.root.as_bytes()));
        for e in &self.extensions {
            s.push_str(e);
            s.push('\n');
        }
        s
    }
}

/// A log's signed tree head: the note as received, and its parsed parts. Two checkpoints
/// are equal when their notes are byte-for-byte equal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedCheckpoint {
    note: Vec<u8>,
    body: CheckpointBody,
    signatures: Vec<NoteSignature>,
}

fn malformed(why: &'static str) -> CheckpointError {
    CheckpointError::Malformed(why)
}

fn line_ok(line: &str) -> bool {
    !line.is_empty() && !line.chars().any(char::is_control)
}

impl SignedCheckpoint {
    /// Parses a C2SP checkpoint note.
    pub fn parse(note: &[u8]) -> Result<Self, CheckpointError> {
        if note.len() > MAX_NOTE {
            return Err(malformed("note too large"));
        }
        let text = core::str::from_utf8(note).map_err(|_| malformed("not UTF-8"))?;
        let split = text.find("\n\n").ok_or(malformed("no blank line before the signatures"))?;
        let (body_text, sig_text) = (&text[..=split], &text[split + 2..]);

        let mut lines = body_text.strip_suffix('\n').unwrap_or(body_text).split('\n');
        let origin = lines.next().filter(|l| line_ok(l)).ok_or(malformed("origin line"))?;
        let size_line = lines.next().ok_or(malformed("size line"))?;
        if size_line.is_empty()
            || !size_line.bytes().all(|b| b.is_ascii_digit())
            || (size_line.len() > 1 && size_line.starts_with('0'))
        {
            return Err(malformed("size is not a decimal number"));
        }
        let size: u64 = size_line.parse().map_err(|_| malformed("size out of range"))?;
        let root_line = lines.next().ok_or(malformed("root line"))?;
        let root = base64_decode(root_line)
            .and_then(|b| Digest::from_bytes(&b).ok())
            .ok_or(malformed("root is not a base64 32-byte hash"))?;
        let extensions = lines
            .map(|l| if line_ok(l) { Ok(l.to_owned()) } else { Err(malformed("extension line")) })
            .collect::<Result<Vec<_>, _>>()?;

        let sig_lines = sig_text.strip_suffix('\n').ok_or(malformed("signatures must end in a newline"))?;
        let mut signatures = Vec::new();
        for line in sig_lines.split('\n') {
            let rest = line.strip_prefix("\u{2014} ").ok_or(malformed("signature line"))?;
            let (name, b64) = rest.split_once(' ').ok_or(malformed("signature line"))?;
            if !line_ok(name) || b64.contains(' ') {
                return Err(malformed("signature line"));
            }
            let raw = base64_decode(b64).ok_or(malformed("signature is not base64"))?;
            if raw.len() < 5 {
                return Err(malformed("signature too short"));
            }
            let mut key_hash = [0u8; 4];
            key_hash.copy_from_slice(&raw[..4]);
            signatures.push(NoteSignature { name: name.to_owned(), key_hash, signature: raw[4..].to_vec() });
        }
        if signatures.is_empty() || signatures.len() > MAX_NOTE_SIGNATURES {
            return Err(malformed("number of signatures"));
        }
        Ok(Self {
            note: note.to_vec(),
            body: CheckpointBody { origin: origin.to_owned(), size, root, extensions },
            signatures,
        })
    }

    /// Signs `body` with an ECDSA P-256 log key named `name`. For in-memory logs and tests;
    /// a public log signs its own checkpoints.
    pub fn sign(body: CheckpointBody, name: &str, key: &SigningKey) -> Self {
        let text = body.text();
        let raw: [u8; 64] = key.sign_message(text.as_bytes()).0.try_into().expect("64-byte signature");
        let mut sig = key_hash(&key.public_key()).to_vec();
        sig.extend_from_slice(&ecdsa_der_from_raw(&raw));
        let note = format!("{text}\n\u{2014} {name} {}\n", base64_encode(&sig));
        Self::parse(note.as_bytes()).expect("a note this function wrote parses")
    }

    /// The note bytes as received.
    pub fn note(&self) -> &[u8] {
        &self.note
    }

    /// The signed body.
    pub fn body(&self) -> &CheckpointBody {
        &self.body
    }

    /// The log's origin.
    pub fn origin(&self) -> &str {
        &self.body.origin
    }

    /// The tree size.
    pub fn size(&self) -> u64 {
        self.body.size
    }

    /// The root hash.
    pub fn root(&self) -> &Digest {
        &self.body.root
    }

    /// Every signature line.
    pub fn signatures(&self) -> &[NoteSignature] {
        &self.signatures
    }

    /// Verifies the checkpoint against the pinned logs (PUB-106, TRU-093): a log must be
    /// pinned for this origin with format [`CHECKPOINT_FORMAT`], and a signature line whose
    /// key hash is the pinned key's must verify over the body. Returns the pin used.
    ///
    /// `required_cosignatures` is `publishing.requiredWitnessCosignatures` (PUB-109): the
    /// trust bundle pins no witness keys, so any requirement above zero is refused.
    pub fn verify<'p>(&self, pins: &'p [LogPin], required_cosignatures: u64) -> Result<&'p LogPin, CheckpointError> {
        let candidates: Vec<&LogPin> =
            pins.iter().filter(|p| p.origin == self.body.origin && p.format == CHECKPOINT_FORMAT).collect();
        if candidates.is_empty() {
            return Err(CheckpointError::NotPinned(self.body.origin.clone()));
        }
        let text = self.body.text();
        for pin in candidates {
            let Ok(key) = P256PublicKey::from_bytes(&pin.public_key) else { continue };
            let hash = key_hash(&key);
            for s in self.signatures.iter().filter(|s| s.key_hash == hash) {
                let Some(raw) = ecdsa_raw_from_der(&s.signature) else { continue };
                let sig = Signature(normalize_s(raw).to_vec());
                if sign::verify_message(&key, text.as_bytes(), &sig).is_ok() {
                    if required_cosignatures > 0 {
                        return Err(CheckpointError::WitnessCosignatures { need: required_cosignatures });
                    }
                    return Ok(pin);
                }
            }
        }
        Err(CheckpointError::BadSignature)
    }
}

/// The 4-byte key hash a note names an ECDSA P-256 key by: the first four bytes of
/// SHA-256 over its DER `SubjectPublicKeyInfo`.
pub fn key_hash(key: &P256PublicKey) -> [u8; 4] {
    let d = sha256(&p256_spki_der(key));
    let mut out = [0u8; 4];
    out.copy_from_slice(&d.as_bytes()[..4]);
    out
}

/// The latest tree head a component has verified for one log, and whether it has stopped
/// trusting that log (PUB-055).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TreeHeadTracker {
    origin: String,
    size: u64,
    root: Digest,
    stopped: bool,
}

impl TreeHeadTracker {
    /// Starts from a verified checkpoint.
    pub fn new(checkpoint: &SignedCheckpoint) -> Self {
        Self { origin: checkpoint.origin().to_owned(), size: checkpoint.size(), root: *checkpoint.root(), stopped: false }
    }

    /// The latest accepted size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The latest accepted root.
    pub fn root(&self) -> &Digest {
        &self.root
    }

    /// Whether the log has been stopped after an inconsistency.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// Accepts a later (already signature-verified) checkpoint from the same log if `proof`
    /// shows it extends the latest one. An inconsistency is a security event: the tracker
    /// stops, and refuses every later checkpoint (PUB-055). An older checkpoint is accepted
    /// without changing the latest if it is consistent with it.
    pub fn advance(&mut self, checkpoint: &SignedCheckpoint, proof: &ConsistencyProof) -> Result<(), CheckpointError> {
        if self.stopped {
            return Err(CheckpointError::Stopped);
        }
        if checkpoint.origin() != self.origin {
            return Err(CheckpointError::NotPinned(checkpoint.origin().to_owned()));
        }
        let consistent = if checkpoint.size() >= self.size {
            proof.old_size == self.size
                && proof.new_size == checkpoint.size()
                && verify_consistency(proof, &self.root, checkpoint.root())
        } else {
            proof.old_size == checkpoint.size()
                && proof.new_size == self.size
                && verify_consistency(proof, checkpoint.root(), &self.root)
        };
        if !consistent {
            self.stopped = true;
            return Err(CheckpointError::Inconsistent);
        }
        if checkpoint.size() >= self.size {
            self.size = checkpoint.size();
            self.root = *checkpoint.root();
        }
        Ok(())
    }
}
