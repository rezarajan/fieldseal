//! The client adapter: a [`TransparencyLog`] that sends every request through a
//! [`LogTransport`], as the in-memory log does, so the contract suite's recorded
//! transmissions see everything that leaves.

use fieldseal_publishing::domain::merkle::{leaf_hash, verify_inclusion};
use fieldseal_publishing::domain::{ConsistencyProof, InclusionProof, LeafFormat, LogEntry, SignedCheckpoint};
use fieldseal_publishing::ports::{LogError, LogRequest, LogTransport, LoggedEntry, Transmission, TransparencyLog};
use fieldseal_trust::domain::LogPin;

use crate::wire::{decode_append, decode_checkpoint, decode_consistency, decode_inclusion};

/// A [`TransparencyLog`] client for a log served by [`crate::handle`] (or the
/// `fieldseal-translog` server), over any [`LogTransport`].
///
/// An append transmits exactly the entry's four fields (`type`, `digest`, `signature`,
/// `publicKey`); lookups transmit only sizes and indices. Responses are parsed strictly and
/// cross-checked against the request: the proof must verify against the returned
/// checkpoint, and sizes must be those asked for. With a pin ([`Self::pinned`]) checkpoints
/// must also verify under the log's key.
pub struct HttpTranslog<T: LogTransport> {
    transport: T,
    pin: Option<LogPin>,
}

impl<T: LogTransport> HttpTranslog<T> {
    /// A client sending through `transport`.
    pub fn new(transport: T) -> Self {
        Self { transport, pin: None }
    }

    /// Also requires every checkpoint received to verify against `pin`.
    pub fn pinned(mut self, pin: LogPin) -> Self {
        self.pin = Some(pin);
        self
    }

    fn send(&self, request: LogRequest, fields: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, LogError> {
        self.transport.send(&Transmission { request, fields })
    }

    fn checked(&self, checkpoint: SignedCheckpoint) -> Result<SignedCheckpoint, LogError> {
        if let Some(pin) = &self.pin {
            checkpoint
                .verify(std::slice::from_ref(pin), 0)
                .map_err(|e| LogError::Malformed(format!("checkpoint does not verify under the pinned key: {e}")))?;
        }
        Ok(checkpoint)
    }
}

impl<T: LogTransport> TransparencyLog for HttpTranslog<T> {
    fn append(&self, entry: &LogEntry) -> Result<LoggedEntry, LogError> {
        let body = self.send(
            LogRequest::Append,
            vec![
                ("type".into(), entry.entry_type().as_str().as_bytes().to_vec()),
                ("digest".into(), entry.digest().as_bytes().to_vec()),
                ("signature".into(), entry.signature().0.clone()),
                ("publicKey".into(), entry.public_key().as_bytes().to_vec()),
            ],
        )?;
        let (checkpoint, inclusion) = decode_append(&body)?;
        let checkpoint = self.checked(checkpoint)?;
        if inclusion.tree_size != checkpoint.size() || inclusion.leaf_index >= inclusion.tree_size {
            return Err(LogError::Malformed("the proof is not against the returned checkpoint".into()));
        }
        let leaf = leaf_hash(&LeafFormat::Fieldseal.leaf(entry));
        if !verify_inclusion(&leaf, &inclusion, checkpoint.root()) {
            return Err(LogError::Malformed("the inclusion proof does not verify".into()));
        }
        Ok(LoggedEntry { entry: entry.clone(), leaf: LeafFormat::Fieldseal, inclusion, checkpoint })
    }

    fn checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        self.checked(decode_checkpoint(&self.send(LogRequest::Checkpoint, Vec::new())?)?)
    }

    fn prove_inclusion(&self, leaf_index: u64, checkpoint: &SignedCheckpoint) -> Result<InclusionProof, LogError> {
        let tree_size = checkpoint.size();
        let proof = decode_inclusion(&self.send(LogRequest::Inclusion { leaf_index, tree_size }, Vec::new())?)?;
        if (proof.leaf_index, proof.tree_size) != (leaf_index, tree_size) {
            return Err(LogError::Malformed("the proof is not for the requested entry and size".into()));
        }
        Ok(proof)
    }

    fn prove_consistency(&self, old_size: u64, checkpoint: &SignedCheckpoint) -> Result<ConsistencyProof, LogError> {
        let new_size = checkpoint.size();
        let proof = decode_consistency(&self.send(LogRequest::Consistency { old_size, new_size }, Vec::new())?)?;
        if (proof.old_size, proof.new_size) != (old_size, new_size) {
            return Err(LogError::Malformed("the proof is not for the requested sizes".into()));
        }
        Ok(proof)
    }
}
