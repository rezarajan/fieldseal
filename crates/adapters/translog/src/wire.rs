//! The log's HTTP API as pure functions: how a [`Transmission`] becomes a request
//! ([`render`]), how the server answers one ([`handle`]), and how responses are read back
//! ([`interpret`], the proof codecs). Nothing here touches a socket.

use fieldseal_kernel::crypto::P256PublicKey;
use fieldseal_kernel::id::Digest;
use fieldseal_publishing::domain::merkle::MAX_PATH;
use fieldseal_publishing::domain::{ConsistencyProof, InclusionProof, LogEntry, LogEntryType, SignedCheckpoint};
use fieldseal_publishing::ports::{LogError, LogRequest, Transmission};

use crate::store::{FileLogStore, MAX_ENTRIES};

/// The largest response body a client accepts: 1 MiB (a checkpoint note is at most 16 KiB
/// and a proof at most 128 hashes).
pub const MAX_RESPONSE: usize = 1024 * 1024;

/// The default largest request body the server accepts.
pub const DEFAULT_MAX_BODY: usize = 4096;

/// One HTTP request, as rendered from a [`Transmission`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpRequest {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// The path, starting with `/`.
    pub path: String,
    /// The body (empty for `GET`).
    pub body: Vec<u8>,
}

/// One HTTP response.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }

    fn error(status: u16, text: &str) -> Self {
        Self { status, body: text.as_bytes().to_vec() }
    }
}

/// Renders a transmission to exactly one HTTP request, adding nothing but fixed protocol
/// constants (PUB-104). An append becomes `POST /append` whose body is the canonical CBOR
/// [`LogEntry`] built from the four fields; a lookup carries no body.
pub fn render(t: &Transmission) -> Result<HttpRequest, LogError> {
    Ok(match &t.request {
        LogRequest::Append => HttpRequest { method: "POST", path: "/append".into(), body: entry_from_fields(&t.fields)?.encode() },
        LogRequest::Checkpoint => HttpRequest { method: "GET", path: "/checkpoint".into(), body: Vec::new() },
        LogRequest::Inclusion { leaf_index, tree_size } => {
            HttpRequest { method: "GET", path: format!("/inclusion/{leaf_index}/{tree_size}"), body: Vec::new() }
        }
        LogRequest::Consistency { old_size, new_size } => {
            HttpRequest { method: "GET", path: format!("/consistency/{old_size}/{new_size}"), body: Vec::new() }
        }
        LogRequest::Entries { from, to } => HttpRequest { method: "GET", path: format!("/entries/{from}/{to}"), body: Vec::new() },
    })
}

fn bad(why: &str) -> LogError {
    LogError::Malformed(why.to_owned())
}

fn entry_from_fields(fields: &[(String, Vec<u8>)]) -> Result<LogEntry, LogError> {
    let get = |name: &str| -> Result<&Vec<u8>, LogError> {
        let mut found = fields.iter().filter(|(n, _)| n == name);
        let value = found.next().ok_or_else(|| bad("append is missing a field"))?;
        if found.next().is_some() {
            return Err(bad("append repeats a field"));
        }
        Ok(&value.1)
    };
    if fields.len() != 4 {
        return Err(bad("an append carries exactly the four entry fields"));
    }
    let entry_type = std::str::from_utf8(get("type")?).ok().and_then(LogEntryType::parse).ok_or_else(|| bad("unknown entry type"))?;
    let digest = Digest::from_bytes(get("digest")?).map_err(|_| bad("digest is not 32 bytes"))?;
    let key = P256PublicKey::from_bytes(get("publicKey")?).map_err(|_| bad("not an uncompressed P-256 key"))?;
    let entry = LogEntry::new(entry_type, digest, fieldseal_kernel::crypto::Signature(get("signature")?.clone()), key);
    // A signature of the wrong length would be rejected by the server; refuse it here.
    LogEntry::decode(&entry.encode()).map_err(|_| bad("signature is not 64 bytes"))
}

/// Turns a response into its body: `200` is the body, `404` is [`LogError::OutOfRange`],
/// anything else is [`LogError::Unavailable`] naming the status. Oversized bodies are
/// refused ([`LogError::Oversized`]).
pub fn interpret(status: u16, body: Vec<u8>) -> Result<Vec<u8>, LogError> {
    if body.len() > MAX_RESPONSE {
        return Err(LogError::Oversized);
    }
    match status {
        200 => Ok(body),
        404 => Err(LogError::OutOfRange),
        other => Err(LogError::Unavailable(format!("HTTP {other}: {}", String::from_utf8_lossy(&body[..body.len().min(200)])))),
    }
}

/// A decimal `u64` without sign, spaces or leading zeros.
fn number(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// Answers one request against `store`: the server side of the API.
///
/// | Request | Success body |
/// |---|---|
/// | `POST /append`, body: canonical CBOR `LogEntry` | `u32` note length, the checkpoint note, then an inclusion proof |
/// | `GET /checkpoint` | the signed checkpoint note |
/// | `GET /inclusion/<leaf>/<size>` | an inclusion proof |
/// | `GET /consistency/<old>/<new>` | a consistency proof |
/// | `GET /entries/<from>/<to>` | per entry, a `u32` length and the canonical `LogEntry` bytes; at most 256 entries |
///
/// Failures are `400` (malformed request), `404` (index or size the log doesn't have),
/// `405` (wrong method), `413` (body over `max_body`) and `500`. A lookup with a body is `400`. Error bodies are short text.
pub fn handle(store: &FileLogStore, method: &str, path: &str, body: &[u8], max_body: usize) -> Response {
    if body.len() > max_body {
        return Response::error(413, "request body too large");
    }
    let parts: Vec<&str> = path.strip_prefix('/').unwrap_or("\0").split('/').collect();
    let allowed = |want: &str| {
        if method != want {
            Some(Response::error(405, "method not allowed"))
        } else if want == "GET" && !body.is_empty() {
            Some(Response::error(400, "a lookup carries no body"))
        } else {
            None
        }
    };
    match parts.as_slice() {
        ["append"] => {
            if let Some(r) = allowed("POST") {
                return r;
            }
            let Ok(entry) = LogEntry::decode(body) else { return Response::error(400, "not a canonical log entry") };
            if entry.encode() != body {
                return Response::error(400, "not a canonical log entry");
            }
            match store.append_entry(&entry) {
                Ok(l) => {
                    let note = l.checkpoint.note();
                    let mut out = (note.len() as u32).to_be_bytes().to_vec();
                    out.extend_from_slice(note);
                    out.extend(encode_inclusion(&l.inclusion));
                    Response::ok(out)
                }
                Err(e) => Response::error(500, &e.to_string()),
            }
        }
        ["checkpoint"] => allowed("GET").unwrap_or_else(|| Response::ok(store.latest_checkpoint().note().to_vec())),
        ["inclusion", leaf, size] => allowed("GET").unwrap_or_else(|| match (number(leaf), number(size)) {
            (Some(l), Some(s)) => match store.inclusion_at(l, s) {
                Ok(p) => Response::ok(encode_inclusion(&p)),
                Err(LogError::OutOfRange) => Response::error(404, "no such entry or tree size"),
                Err(e) => Response::error(500, &e.to_string()),
            },
            _ => Response::error(400, "indices are decimal numbers"),
        }),
        ["consistency", old, new] => allowed("GET").unwrap_or_else(|| match (number(old), number(new)) {
            (Some(o), Some(n)) => match store.consistency_between(o, n) {
                Ok(p) => Response::ok(encode_consistency(&p)),
                Err(LogError::OutOfRange) => Response::error(404, "no such tree size"),
                Err(e) => Response::error(500, &e.to_string()),
            },
            _ => Response::error(400, "sizes are decimal numbers"),
        }),
        ["entries", from, to] => allowed("GET").unwrap_or_else(|| match (number(from), number(to)) {
            (Some(f), Some(t)) if t >= f => match store.entries(f, t) {
                Ok(entries) => Response::ok(encode_entries(&entries)),
                Err(LogError::OutOfRange) => Response::error(404, "no such entry"),
                Err(e) => Response::error(500, &e.to_string()),
            },
            _ => Response::error(400, "indices are decimal numbers and `to` is not below `from`"),
        }),
        _ => Response::error(404, "no such route"),
    }
}

/// Each entry as a 4-byte big-endian length and its canonical bytes (WIRE-199).
fn encode_entries(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.extend_from_slice(&(e.len() as u32).to_be_bytes());
        out.extend_from_slice(e);
    }
    out
}

/// Reads an entries answer back, strictly: every entry canonical, no trailing bytes, at most
/// 256 entries.
pub fn decode_entries(bytes: &[u8]) -> Result<Vec<LogEntry>, LogError> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if out.len() == MAX_ENTRIES {
            return Err(bad("more entries than one answer holds"));
        }
        let len = u32::from_be_bytes(rest.get(..4).ok_or_else(|| bad("entry length cut short"))?.try_into().expect("4 bytes")) as usize;
        let entry = rest.get(4..4usize.saturating_add(len)).ok_or_else(|| bad("entry cut short"))?;
        let decoded = LogEntry::decode(entry).map_err(|e| LogError::Malformed(e.to_string()))?;
        if decoded.encode() != entry {
            return Err(bad("entry is not canonical"));
        }
        out.push(decoded);
        rest = &rest[4 + len..];
    }
    Ok(out)
}

fn encode_proof(a: u64, b: u64, path: &[Digest]) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + 32 * path.len());
    out.extend_from_slice(&a.to_be_bytes());
    out.extend_from_slice(&b.to_be_bytes());
    out.extend_from_slice(&(path.len() as u16).to_be_bytes());
    for h in path {
        out.extend_from_slice(h.as_bytes());
    }
    out
}

/// `leaf_index: u64 | tree_size: u64 | n: u16 | n x 32-byte hash`, big-endian.
pub fn encode_inclusion(p: &InclusionProof) -> Vec<u8> {
    encode_proof(p.leaf_index, p.tree_size, &p.path)
}

/// `old_size: u64 | new_size: u64 | n: u16 | n x 32-byte hash`, big-endian.
pub fn encode_consistency(p: &ConsistencyProof) -> Vec<u8> {
    encode_proof(p.old_size, p.new_size, &p.path)
}

/// Reads exactly one proof (two numbers and a bounded path), refusing trailing bytes.
fn decode_proof(bytes: &[u8]) -> Result<(u64, u64, Vec<Digest>), LogError> {
    if bytes.len() < 18 {
        return Err(bad("proof too short"));
    }
    let a = u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"));
    let b = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let n = u16::from_be_bytes(bytes[16..18].try_into().expect("2 bytes")) as usize;
    if n > MAX_PATH {
        return Err(bad("proof path too long"));
    }
    if bytes.len() != 18 + 32 * n {
        return Err(bad("proof length does not match its path count"));
    }
    let path = bytes[18..].chunks_exact(32).map(|c| Digest::from_bytes(c).expect("32 bytes")).collect();
    Ok((a, b, path))
}

/// Parses an inclusion proof, strictly.
pub fn decode_inclusion(bytes: &[u8]) -> Result<InclusionProof, LogError> {
    let (leaf_index, tree_size, path) = decode_proof(bytes)?;
    Ok(InclusionProof { leaf_index, tree_size, path })
}

/// Parses a consistency proof, strictly.
pub fn decode_consistency(bytes: &[u8]) -> Result<ConsistencyProof, LogError> {
    let (old_size, new_size, path) = decode_proof(bytes)?;
    Ok(ConsistencyProof { old_size, new_size, path })
}

/// Parses a checkpoint note.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<SignedCheckpoint, LogError> {
    SignedCheckpoint::parse(bytes).map_err(|e| LogError::Malformed(e.to_string()))
}

/// Parses an append response into the checkpoint and the inclusion proof.
pub fn decode_append(bytes: &[u8]) -> Result<(SignedCheckpoint, InclusionProof), LogError> {
    let len = bytes.get(..4).ok_or_else(|| bad("append response too short"))?;
    let note_len = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
    let note = bytes.get(4..4usize.saturating_add(note_len)).ok_or_else(|| bad("append response cut short"))?;
    Ok((decode_checkpoint(note)?, decode_inclusion(&bytes[4 + note_len..])?))
}
