//! A self-hosted transparency log for the Publishing context's [`TransparencyLog`] port
//! (ADR 0030, PUB-100–106, issue #82).
//!
//! * [`FileLogStore`] is a file-backed, append-only RFC 9162 Merkle log. It logs the
//!   [`LeafFormat::Fieldseal`] leaf of every entry, signs C2SP checkpoints with a P-256 key
//!   the caller supplies, and gives inclusion and consistency proofs. Appends are `fsync`ed
//!   before they are acknowledged, a torn tail is cut off on open, tampered data makes open
//!   fail, and a lock admits one writer at a time. It implements [`TransparencyLog`]
//!   directly, for in-process use.
//! * [`HttpTranslog`] is the same port as a client of a log server. It sends every request
//!   through a [`LogTransport`], so the contract suite can record exactly what leaves
//!   (`fieldseal_publishing::contract`). [`HttpLogTransport`] carries transmissions over
//!   HTTP(S); [`HandlerTransport`] calls the server handler in-process.
//! * [`handle`] is the server side as a function over a store, testable without sockets;
//!   the `fieldseal-translog` binary wraps it in a small HTTP/1.1 server.
//!
//! # HTTP API
//!
//! | Request | Success (`200`) body |
//! |---|---|
//! | `POST /append`, body: the entry's canonical CBOR (`{"type","digest","sig","pub"}`, WIRE-191) | `u32` note length, the checkpoint note, an inclusion proof |
//! | `GET /checkpoint` | the signed C2SP checkpoint note |
//! | `GET /inclusion/<leaf_index>/<tree_size>` | an inclusion proof |
//! | `GET /consistency/<old_size>/<new_size>` | a consistency proof |
//! | `GET /entries/<from>/<to>` | per entry a `u32` length and the canonical entry bytes, at most 256 entries (WIRE-199) |
//!
//! A proof is `size-or-index: u64 | size: u64 | count: u16 | count x 32-byte hash`, all
//! big-endian ([`encode_inclusion`], [`encode_consistency`]). Numbers in paths are plain
//! decimals. `404` means an entry or size the log doesn't have ([`LogError::OutOfRange`]),
//! `400` a malformed request, `413` an oversized body. Clients refuse bodies over 1 MiB
//! ([`LogError::Oversized`]), proofs whose length disagrees with their header, paths over
//! 128 hashes and notes that don't parse ([`LogError::Malformed`]).
//!
//! The server cannot check an entry's signature (it receives the statement's digest, not
//! the statement), so it logs what it is given: the log is a record, and consumers verify
//! the publisher signatures. It keeps the leaf hashes in memory and recomputes the root per
//! checkpoint, which is linear in the log's size.
//!
//! [`LeafFormat::Fieldseal`]: fieldseal_publishing::domain::LeafFormat::Fieldseal
//! [`LogTransport`]: fieldseal_publishing::ports::LogTransport
//! [`TransparencyLog`]: fieldseal_publishing::ports::TransparencyLog
//! [`LogError::OutOfRange`]: fieldseal_publishing::ports::LogError::OutOfRange
//! [`LogError::Oversized`]: fieldseal_publishing::ports::LogError::Oversized
//! [`LogError::Malformed`]: fieldseal_publishing::ports::LogError::Malformed

mod client;
mod http;
mod store;
mod wire;


pub use client::HttpTranslog;
pub use http::{HandlerTransport, HttpLogTransport};
pub use store::{FileLogStore, MAX_ENTRIES, StoreError};
pub use wire::{
    DEFAULT_MAX_BODY, HttpRequest, MAX_RESPONSE, Response, decode_append, decode_checkpoint, decode_consistency, decode_entries,
    decode_inclusion, encode_consistency, encode_inclusion, handle, interpret, render,
};
