//! Fingerprint words (WIRE-135, REG-020, REG-023): the first 44 bits of SHA-256 over a
//! registration request's canonical body, read as four 11-bit indices into the BIP-39
//! English word list, joined by ` · `.
//!
//! The list is fixed by the format, whatever the display language (ADR 0034): runtime and
//! portal show the same four words, and each word's index (0–2047) beside it. The list is
//! committed as data (`data/bip39-english.txt`, 2048 lines) and pinned by its SHA-256 in
//! the tests.

use std::sync::LazyLock;

use crate::digest::sha256;
use crate::id::Digest;

/// The number of words in the list.
pub const LIST_LEN: usize = 2048;

/// The separator between words in the joined form (WIRE-135).
pub const SEPARATOR: &str = " · ";

const RAW: &str = include_str!("../data/bip39-english.txt");

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let words: Vec<&'static str> = RAW.lines().collect();
    assert_eq!(words.len(), LIST_LEN, "the word list has 2048 entries");
    words
});

/// The word at `index`, or `None` if `index` is 2048 or more.
pub fn word(index: u16) -> Option<&'static str> {
    WORDS.get(usize::from(index)).copied()
}

/// The index of `word` in the list (exact, lower-case match).
pub fn index_of(word: &str) -> Option<u16> {
    WORDS.binary_search(&word).ok().map(|i| i as u16)
}

/// The four indices for a request-body digest: its first 44 bits, most significant first.
pub fn indices_of_digest(digest: &Digest) -> [u16; 4] {
    let b = digest.as_bytes();
    let bits = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], 0, 0]) >> 20;
    let idx = |shift: u32| ((bits >> shift) & 0x7ff) as u16;
    [idx(33), idx(22), idx(11), idx(0)]
}

/// The four indices for a canonical request body.
pub fn indices(canonical_body: &[u8]) -> [u16; 4] {
    indices_of_digest(&sha256(canonical_body))
}

/// The joined words for four indices, for example `abandon · ability · able · about`.
/// Indices must be below 2048.
pub fn join(indices: [u16; 4]) -> String {
    indices.map(|i| word(i).expect("index below 2048")).join(SEPARATOR)
}
