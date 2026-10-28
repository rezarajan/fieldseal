//! Build provenance: an in-toto Statement v1 with an SLSA Provenance v1 predicate,
//! canonical CBOR, signed by a `builder` key over `fieldseal.dev/provenance/v1`
//! (PUB-030–033, PUB-091, PUB-107).
//!
//! ```cddl
//! provenance-statement = {
//!   "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [{ "name": tstr,                                   ; metadata.name
//!                 "digest": { "sha256": hash,                     ; of the canonical bytes
//!                             ? "fieldseal-fingerprint": hash } }],   ; instruments
//!   "predicateType": "https://slsa.dev/provenance/v1",
//!   "predicate": {
//!     "buildDefinition": {
//!       "buildType": "https://fieldseal.dev/build/v1",
//!       "externalParameters": {
//!         "artefact": { "kind": tstr, "name": tstr, "version": tstr, ? "salt": bstr .size 32 },
//!         "source": { "uri": tstr, "revision": tstr },
//!         "reviewers": [* tstr]                                   ; ReviewerIds (PUB-107)
//!       },
//!       "internalParameters": { "definition": { "sha256": hash } }
//!     },
//!     "runDetails": { "builder": { "id": tstr }, "metadata": { "finishedOn": ms-time } }
//!   }
//! }
//! provenance = { "statement": bstr, "signer": key-id, "sig": signature }
//! ; "sig" is over tag fieldseal.dev/provenance/v1 and the decoded statement (WIRE-021).
//! ```

use fieldseal_kernel::cbor;
use fieldseal_kernel::crypto::Signature;
use fieldseal_kernel::digest::sha256;
use fieldseal_kernel::id::{ContentAddress, Digest, Fingerprint, KeyId, ReviewerId, Salt};
use fieldseal_kernel::structure::{Fields, expect_bytes_n, expect_uint};
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_kernel::{ErrorCode, Value, WireError};

use super::artefact::{Artefact, ArtefactKind, is_valid_name, is_valid_version};
use super::review::RevisionId;

/// The in-toto statement type.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The SLSA provenance predicate type.
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
/// Fieldseal's build type: canonicalisation by the format core.
pub const BUILD_TYPE: &str = "https://fieldseal.dev/build/v1";
/// The subject digest name for an instrument's fingerprint.
pub const FINGERPRINT_DIGEST: &str = "fieldseal-fingerprint";

/// A builder's attested identity, for example a CI workload identity URI.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BuilderId(pub String);

/// Where an artefact's source came from: a repository and an immutable revision.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceRef {
    /// The repository URI (matched against `publishing.allowedSources`).
    pub uri: String,
    /// The revision built.
    pub revision: RevisionId,
}

/// What the builder attests about one build (PUB-030, PUB-031).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvenanceStatement {
    /// The artefact's kind.
    pub kind: ArtefactKind,
    /// The artefact's name (the in-toto subject name).
    pub name: String,
    /// The artefact's version.
    pub version: String,
    /// SHA-256 of the canonical bytes.
    pub sha256: Digest,
    /// The fingerprint, for instruments (PUB-092).
    pub fingerprint: Option<Fingerprint>,
    /// The instrument salt, for instruments (PUB-091).
    pub salt: Option<Salt>,
    /// The source repository and revision.
    pub source: SourceRef,
    /// The approving reviewers, by pseudonymous ID (PUB-031, PUB-107).
    pub reviewers: Vec<ReviewerId>,
    /// Digest of the pinned build definition.
    pub definition: Digest,
    /// The builder's identity.
    pub builder: BuilderId,
    /// When the build finished, in authority time. Certificates are checked at this time.
    pub finished: AuthorityTime,
}

fn unknown(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::UnknownField, 0, detail)
}

fn constant(f: &mut Fields, key: &str, expected: &str) -> Result<(), WireError> {
    if f.text(key)? == expected { Ok(()) } else { Err(unknown("unexpected constant")) }
}

fn sha256_map(f: &mut Fields, key: &str) -> Result<Digest, WireError> {
    let mut d = Fields::new(f.take(key)?)?;
    let digest = Digest::from(d.bytes_n::<32>("sha256")?);
    d.finish()?;
    Ok(digest)
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

impl ProvenanceStatement {
    /// The statement for building `artefact` from `source`.
    pub fn for_artefact(
        artefact: &Artefact,
        source: SourceRef,
        reviewers: Vec<ReviewerId>,
        definition: Digest,
        builder: BuilderId,
        finished: AuthorityTime,
    ) -> Self {
        Self {
            kind: artefact.kind(),
            name: artefact.name().to_owned(),
            version: artefact.version().to_owned(),
            sha256: artefact.sha256(),
            fingerprint: artefact.fingerprint(),
            salt: artefact.salt().copied(),
            source,
            reviewers,
            definition,
            builder,
            finished,
        }
    }

    /// The artefact identity the statement names: the fingerprint for an instrument, else
    /// the SHA-256 content address.
    pub fn address(&self) -> ContentAddress {
        match self.fingerprint {
            Some(f) => ContentAddress::from(*f.as_bytes()),
            None => ContentAddress::from(*self.sha256.as_bytes()),
        }
    }

    /// Whether the statement describes exactly `artefact`: kind, name, version, digest,
    /// fingerprint and salt.
    pub fn describes(&self, artefact: &Artefact) -> bool {
        self.kind == artefact.kind()
            && self.name == artefact.name()
            && self.version == artefact.version()
            && self.sha256 == artefact.sha256()
            && self.fingerprint == artefact.fingerprint()
            && self.salt.as_ref() == artefact.salt()
    }

    /// The canonical structure.
    pub fn to_value(&self) -> Value {
        let mut digest = vec![("sha256", bytes(self.sha256.as_bytes()))];
        if let Some(f) = &self.fingerprint {
            digest.push((FINGERPRINT_DIGEST, bytes(f.as_bytes())));
        }
        let mut artefact =
            vec![("kind", text(self.kind.as_str())), ("name", text(&self.name)), ("version", text(&self.version))];
        if let Some(s) = &self.salt {
            artefact.push(("salt", bytes(s.as_bytes())));
        }
        cbor::map([
            ("_type", text(STATEMENT_TYPE)),
            ("subject", Value::Array(vec![cbor::map([("name", text(&self.name)), ("digest", cbor::map(digest))])])),
            ("predicateType", text(PREDICATE_TYPE)),
            (
                "predicate",
                cbor::map([
                    (
                        "buildDefinition",
                        cbor::map([
                            ("buildType", text(BUILD_TYPE)),
                            (
                                "externalParameters",
                                cbor::map([
                                    ("artefact", cbor::map(artefact)),
                                    (
                                        "source",
                                        cbor::map([("uri", text(&self.source.uri)), ("revision", text(&self.source.revision.0))]),
                                    ),
                                    ("reviewers", Value::Array(self.reviewers.iter().map(|r| text(r.as_str())).collect())),
                                ]),
                            ),
                            (
                                "internalParameters",
                                cbor::map([("definition", cbor::map([("sha256", bytes(self.definition.as_bytes()))]))]),
                            ),
                        ]),
                    ),
                    (
                        "runDetails",
                        cbor::map([
                            ("builder", cbor::map([("id", text(&self.builder.0))])),
                            ("metadata", cbor::map([("finishedOn", Value::Int(i128::from(self.finished.0)))])),
                        ]),
                    ),
                ]),
            ),
        ])
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a provenance statement always encodes")
    }

    /// Reads the structure, refusing unknown keys at every level (WIRE-005), a subject
    /// that disagrees with the artefact parameters, and a salt without a fingerprint.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut top = Fields::new(value)?;
        constant(&mut top, "_type", STATEMENT_TYPE)?;
        constant(&mut top, "predicateType", PREDICATE_TYPE)?;
        let subjects = top.array("subject")?;
        let [subject] = <[Value; 1]>::try_from(subjects).map_err(|_| unknown("exactly one subject"))?;
        let mut predicate = Fields::new(top.take("predicate")?)?;
        top.finish()?;

        let mut subject = Fields::new(subject)?;
        let subject_name = subject.text("name")?;
        let mut digest = Fields::new(subject.take("digest")?)?;
        subject.finish()?;
        let sha256 = Digest::from(digest.bytes_n::<32>("sha256")?);
        let fingerprint = digest.take_opt(FINGERPRINT_DIGEST).map(expect_bytes_n::<32>).transpose()?.map(Fingerprint::from);
        digest.finish()?;

        let mut definition = Fields::new(predicate.take("buildDefinition")?)?;
        let mut run = Fields::new(predicate.take("runDetails")?)?;
        predicate.finish()?;

        constant(&mut definition, "buildType", BUILD_TYPE)?;
        let mut external = Fields::new(definition.take("externalParameters")?)?;
        let mut internal = Fields::new(definition.take("internalParameters")?)?;
        definition.finish()?;
        let definition_digest = sha256_map(&mut internal, "definition")?;
        internal.finish()?;

        let mut artefact = Fields::new(external.take("artefact")?)?;
        let kind = ArtefactKind::parse(&artefact.text("kind")?).ok_or(unknown("unknown artefact kind"))?;
        let name = artefact.text("name")?;
        let version = artefact.text("version")?;
        let salt = artefact.take_opt("salt").map(expect_bytes_n::<32>).transpose()?.map(Salt::from);
        artefact.finish()?;
        let mut src = Fields::new(external.take("source")?)?;
        let source = SourceRef { uri: src.text("uri")?, revision: RevisionId(src.text("revision")?) };
        src.finish()?;
        let reviewers = external
            .array("reviewers")?
            .into_iter()
            .map(|v| match v {
                Value::Text(t) => ReviewerId::new(t).map_err(|_| unknown("empty reviewer ID")),
                _ => Err(unknown("reviewer is not text")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        external.finish()?;

        let mut builder = Fields::new(run.take("builder")?)?;
        let builder_id = BuilderId(builder.text("id")?);
        builder.finish()?;
        let mut metadata = Fields::new(run.take("metadata")?)?;
        let finished = AuthorityTime(expect_uint(metadata.take("finishedOn")?)?);
        metadata.finish()?;
        run.finish()?;

        if !is_valid_name(&name) || !is_valid_version(&version) {
            return Err(unknown("artefact name or version is not valid (PUB-001)"));
        }
        if source.uri.is_empty() || source.revision.0.is_empty() || builder_id.0.is_empty() {
            return Err(unknown("source URI, revision and builder ID are not empty"));
        }
        if reviewers.iter().collect::<std::collections::BTreeSet<_>>().len() != reviewers.len() {
            return Err(unknown("a reviewer is listed twice"));
        }
        if subject_name != name || salt.is_some() != fingerprint.is_some() || salt.is_some() != (kind == ArtefactKind::Instrument) {
            return Err(unknown("subject disagrees with the artefact parameters"));
        }
        Ok(Self {
            kind,
            name,
            version,
            sha256,
            fingerprint,
            salt,
            source,
            reviewers,
            definition: definition_digest,
            builder: builder_id,
            finished,
        })
    }

    /// Decodes canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(cbor::decode(bytes)?)
    }
}

/// A provenance statement with the builder's signature (PUB-032). The statement bytes are
/// kept as received, so the digest publishers sign is over exactly them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedProvenance {
    statement: ProvenanceStatement,
    bytes: Vec<u8>,
    signer: KeyId,
    signature: Signature,
}

impl SignedProvenance {
    /// Attaches the builder key's signature to a statement.
    pub fn new(statement: ProvenanceStatement, signer: KeyId, signature: Signature) -> Self {
        let bytes = statement.encode();
        Self { statement, bytes, signer, signature }
    }

    /// Reads `{statement, signer, sig}` (PUB §6.1). The statement must be canonical.
    pub fn from_value(value: Value) -> Result<Self, WireError> {
        let mut f = Fields::new(value)?;
        let bytes = f.bytes("statement")?;
        let signer = KeyId::from(f.bytes_n::<16>("signer")?);
        let signature = Signature(f.bytes_n::<64>("sig")?.to_vec());
        f.finish()?;
        let statement = ProvenanceStatement::decode(&bytes)?;
        Ok(Self { statement, bytes, signer, signature })
    }

    /// `{statement, signer, sig}`.
    pub fn to_value(&self) -> Value {
        cbor::map([
            ("statement", Value::Bytes(self.bytes.clone())),
            ("signer", Value::Bytes(self.signer.as_bytes().to_vec())),
            ("sig", Value::Bytes(self.signature.0.clone())),
        ])
    }

    /// The statement.
    pub fn statement(&self) -> &ProvenanceStatement {
        &self.statement
    }

    /// The canonical statement bytes.
    pub fn statement_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The builder key's identifier.
    pub fn signer(&self) -> &KeyId {
        &self.signer
    }

    /// The builder key's signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// `provenance_sha256`: SHA-256 of the statement bytes, the digest publishers sign
    /// (PUB-041) and the log statement commits to (WIRE-190).
    pub fn digest(&self) -> Digest {
        sha256(&self.bytes)
    }
}
